//! The self-service portal SESSION, at the store (issue #140).
//!
//! # What these pin
//!
//! #140 requires that "a portal session for org A cannot read or mutate any org B state" and
//! that "an `sso` link cannot reach SCIM or domain-verification surfaces", both "verified
//! adversarially". A session's entire authority is the organization and the intent this file
//! puts on the row and hands back, so both properties are decided here and enforced by whatever
//! reads them. What is provable at this layer is that the two values arrive from the LINK rather
//! than from the caller, that a session stops authenticating when it should, and that redeeming
//! and opening happen together or not at all.
#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewPortalLink, NewPortalSession, OrganizationId, PortalLinkId, PortalSessionId,
    Scope, StoreError,
};

/// SHA-256 of a bearer value, which is what every row here stores.
fn digest(token: &str) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Create an organization to bind links to.
async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, 1_000_000, "Globex", None)
        .await
        .expect("create organization");
    id
}

/// Mint a link, returning its id.
async fn mint_link(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    intent: &str,
    token: &str,
) -> PortalLinkId {
    let id = PortalLinkId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .portal_links()
        .mint(
            env,
            NewPortalLink {
                id: &id,
                organization_id: organization,
                intent,
                token_digest: &digest(token),
            },
            1_000_000,
            300_000_000,
        )
        .await
        .expect("mint the link");
    id
}

#[tokio::test]
async fn redeeming_opens_a_session_carrying_the_links_organization_and_intent() {
    // THE WHOLE POINT OF THE SESSION IN ONE TEST. Its organization and intent ARE its authority,
    // and they must come from the LINK rather than from anything the redeeming request said --
    // otherwise a browser could ask for a session over an organization the vendor never granted.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let link = mint_link(&db, &env, scope, &organization, "scim", "tok-a").await;

    let session_id = PortalSessionId::generate(&env, &scope);
    let redeemed = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("tok-a"),
            NewPortalSession {
                id: &session_id,
                token_digest: &digest("cookie-a"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await
        .expect("a live link redeems into a session");
    assert_eq!(redeemed.organization_id, organization);
    assert_eq!(redeemed.intent, "scim");

    // AND THE COOKIE AUTHENTICATES TO THE SAME TWO VALUES. The redemption's answer and the
    // session's answer are read from different rows by different statements, so a change that
    // let them disagree would leave the handler trusting one and the fence honouring the other.
    let session = db
        .store()
        .scoped(scope)
        .portal_sessions()
        .authenticate(&digest("cookie-a"), 3_000_000)
        .await
        .expect("the cookie authenticates");
    assert_eq!(session.id, session_id);
    assert_eq!(session.organization_id, organization);
    assert_eq!(session.intent, "scim");
}

#[tokio::test]
async fn a_link_redeemed_into_a_session_cannot_be_redeemed_again() {
    // SINGLE-USE SURVIVES THE SECOND WRITE. The consume and the session insert are one
    // transaction, so the interesting failure is a second redemption finding the link already
    // spent -- and answering the SAME not-found an unknown link answers, because telling them
    // apart would tell somebody replaying a captured link whether their first attempt worked.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let link = mint_link(&db, &env, scope, &organization, "sso", "tok-b").await;

    let first = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("tok-b"),
            NewPortalSession {
                id: &PortalSessionId::generate(&env, &scope),
                token_digest: &digest("cookie-b1"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await;
    assert!(first.is_ok(), "the first redemption: {first:?}");

    let again = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("tok-b"),
            NewPortalSession {
                id: &PortalSessionId::generate(&env, &scope),
                token_digest: &digest("cookie-b2"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await;
    assert!(
        matches!(again, Err(StoreError::NotFound)),
        "one link opened two sessions: {again:?}"
    );

    // AND THE SECOND COOKIE AUTHENTICATES NOTHING, which is the half that matters: a refusal
    // that had already written the session row would leave a live credential behind.
    let orphan = db
        .store()
        .scoped(scope)
        .portal_sessions()
        .authenticate(&digest("cookie-b2"), 3_000_000)
        .await;
    assert!(
        matches!(orphan, Err(StoreError::NotFound)),
        "the refused redemption left a live session behind: {orphan:?}"
    );
}

#[tokio::test]
async fn a_failed_redemption_opens_no_session() {
    // A WRONG TOKEN MUST CONSUME NOTHING AND OPEN NOTHING. What provides that is the control
    // flow -- the `Some(row)` guard returns before the insert is reached -- and NOT the shared
    // transaction, which an earlier version of this comment credited. A two-transaction
    // implementation keeping the same guard passes every assertion here.
    //
    // The transaction is measured by `a_link_whose_session_cannot_be_inserted_is_not_spent`,
    // which forces the insert to fail AFTER the update has run. That is the only input on which
    // the two implementations differ.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let link = mint_link(&db, &env, scope, &organization, "sso", "tok-c").await;

    let refused = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("not-the-token"),
            NewPortalSession {
                id: &PortalSessionId::generate(&env, &scope),
                token_digest: &digest("cookie-c"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "a wrong token redeemed: {refused:?}"
    );
    let orphan = db
        .store()
        .scoped(scope)
        .portal_sessions()
        .authenticate(&digest("cookie-c"), 3_000_000)
        .await;
    assert!(
        matches!(orphan, Err(StoreError::NotFound)),
        "a wrong token opened a session anyway: {orphan:?}"
    );

    // AND THE LINK IS STILL LIVE for its rightful holder, so a failed guess is not a denial of
    // service anybody holding the (non-secret) id could mount.
    assert!(
        db.store()
            .scoped(scope)
            .portal_links()
            .redeem_into_session(
                &link,
                &digest("tok-c"),
                NewPortalSession {
                    id: &PortalSessionId::generate(&env, &scope),
                    token_digest: &digest("cookie-c2"),
                    expires_at_unix_micros: 600_000_000,
                },
                2_000_000,
            )
            .await
            .is_ok(),
        "a wrong-token attempt burned the link for its rightful holder"
    );
}

#[tokio::test]
async fn concurrent_redemptions_of_one_link_open_exactly_one_session() {
    // THE RACE THE UNIQUE CONSTRAINT AND THE CONDITIONAL UPDATE BOTH ADDRESS. Two browsers
    // presenting one link must produce one session, and the loser must not be able to tell that
    // from a link that never existed.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let link = mint_link(&db, &env, scope, &organization, "sso", "tok-d").await;

    let store = db.store();
    let token = digest("tok-d");
    let left_scope = store.scoped(scope);
    let right_scope = store.scoped(scope);
    let left = left_scope.portal_links();
    let right = right_scope.portal_links();
    let left_id = PortalSessionId::generate(&env, &scope);
    let right_id = PortalSessionId::generate(&env, &scope);
    // BOUND FIRST, like the scoped handles above: built inline inside `join!` each digest is a
    // temporary whose lifetime ends at the semicolon, which the borrow checker refuses.
    let left_cookie = digest("cookie-d1");
    let right_cookie = digest("cookie-d2");
    let (first, second) = tokio::join!(
        left.redeem_into_session(
            &link,
            &token,
            NewPortalSession {
                id: &left_id,
                token_digest: &left_cookie,
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        ),
        right.redeem_into_session(
            &link,
            &token,
            NewPortalSession {
                id: &right_id,
                token_digest: &right_cookie,
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        ),
    );
    let winners = usize::from(first.is_ok()) + usize::from(second.is_ok());
    assert_eq!(
        winners, 1,
        "two concurrent redemptions of one link: {first:?} {second:?}"
    );

    // EXACTLY ONE LIVE COOKIE, counted rather than inferred from the statuses above: a losing
    // call that still committed its insert would leave a second working credential.
    let live = usize::from(
        db.store()
            .scoped(scope)
            .portal_sessions()
            .authenticate(&digest("cookie-d1"), 3_000_000)
            .await
            .is_ok(),
    ) + usize::from(
        db.store()
            .scoped(scope)
            .portal_sessions()
            .authenticate(&digest("cookie-d2"), 3_000_000)
            .await
            .is_ok(),
    );
    assert_eq!(live, 1, "one link produced {live} live session cookies");
}

#[tokio::test]
async fn a_session_past_its_expiry_authenticates_no_longer() {
    // THE SESSION'S OWN HORIZON, which is a different and longer one than the link's: the link
    // bounds how long somebody has to START, this bounds how long they may CONTINUE. Enforced at
    // authentication rather than merely recorded, so the clock is the caller's and driven here.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let link = mint_link(&db, &env, scope, &organization, "sso", "tok-e").await;

    db.store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("tok-e"),
            NewPortalSession {
                id: &PortalSessionId::generate(&env, &scope),
                token_digest: &digest("cookie-e"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await
        .expect("redeem");

    let expired = db
        .store()
        .scoped(scope)
        .portal_sessions()
        .authenticate(&digest("cookie-e"), 600_000_001)
        .await;
    assert!(
        matches!(expired, Err(StoreError::NotFound)),
        "a session authenticated one microsecond past its expiry: {expired:?}"
    );
    // AND IT IS THE EXPIRY DOING IT: one microsecond earlier works. Without this the test would
    // pass against an authenticate that refused everything.
    assert!(
        db.store()
            .scoped(scope)
            .portal_sessions()
            .authenticate(&digest("cookie-e"), 599_999_999)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_revoked_session_authenticates_no_longer() {
    // ENDING A SESSION HAS TO BE POSSIBLE BEFORE ITS TTL. An admin who finishes, or an operator
    // who sees a session they did not expect, needs the cookie to stop working now rather than
    // in an hour.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let link = mint_link(&db, &env, scope, &organization, "sso", "tok-f").await;
    let session_id = PortalSessionId::generate(&env, &scope);

    db.store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("tok-f"),
            NewPortalSession {
                id: &session_id,
                token_digest: &digest("cookie-f"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await
        .expect("redeem");
    // IT WORKS FIRST, so the refusal below is the revocation rather than the session never
    // having authenticated at all.
    assert!(
        db.store()
            .scoped(scope)
            .portal_sessions()
            .authenticate(&digest("cookie-f"), 3_000_000)
            .await
            .is_ok()
    );

    db.store()
        .scoped(scope)
        .portal_sessions()
        .revoke(&session_id, 4_000_000)
        .await
        .expect("revoke");

    let after = db
        .store()
        .scoped(scope)
        .portal_sessions()
        .authenticate(&digest("cookie-f"), 5_000_000)
        .await;
    assert!(
        matches!(after, Err(StoreError::NotFound)),
        "a revoked session still authenticates: {after:?}"
    );
}

#[tokio::test]
async fn one_environments_session_cookie_is_inert_in_another() {
    // THE SCOPE FENCE, which is the outermost of the three a portal request passes (scope, then
    // organization, then intent). A cookie minted in one environment must find nothing in
    // another even though the digest is the same bytes.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let ours = db.seed_scope(&env).await;
    let theirs = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, ours).await;
    let link = mint_link(&db, &env, ours, &organization, "sso", "tok-g").await;

    db.store()
        .scoped(ours)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("tok-g"),
            NewPortalSession {
                id: &PortalSessionId::generate(&env, &ours),
                token_digest: &digest("cookie-g"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await
        .expect("redeem");

    let crossed = db
        .store()
        .scoped(theirs)
        .portal_sessions()
        .authenticate(&digest("cookie-g"), 3_000_000)
        .await;
    assert!(
        matches!(crossed, Err(StoreError::NotFound)),
        "one environment authenticated another's portal session cookie: {crossed:?}"
    );
}

#[tokio::test]
async fn a_link_whose_session_cannot_be_inserted_is_not_spent() {
    // THE ATOMICITY, MEASURED. Every other test here passes just as well against a
    // `redeem_into_session` written as two sequential transactions -- commit the consume, then
    // open the session -- because nothing forces the second half to fail. This one does.
    //
    // The forcing move is a session id that is already taken. The INSERT then violates the
    // primary key AFTER the conditional UPDATE has run, so the two implementations diverge:
    // one transaction rolls the consume back and the link stays redeemable, two transactions
    // leave the link spent with no session behind it -- the admin followed a working single-use
    // link and is looking at a dead page, which is the state the doc says this shape prevents.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;

    // A session id that exists, taken by redeeming a first link normally.
    let taken = PortalSessionId::generate(&env, &scope);
    let first_link = mint_link(&db, &env, scope, &organization, "sso", "tok-x1").await;
    db.store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &first_link,
            &digest("tok-x1"),
            NewPortalSession {
                id: &taken,
                token_digest: &digest("cookie-x1"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await
        .expect("the first redemption");

    // NOW THE SECOND LINK, redeemed with the SAME session id. The consume succeeds and the
    // insert cannot.
    let second_link = mint_link(&db, &env, scope, &organization, "sso", "tok-x2").await;
    let collided = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &second_link,
            &digest("tok-x2"),
            NewPortalSession {
                id: &taken,
                token_digest: &digest("cookie-x2"),
                expires_at_unix_micros: 600_000_000,
            },
            3_000_000,
        )
        .await;
    assert!(
        collided.is_err(),
        "an id collision was not reported: {collided:?}"
    );

    // THE ASSERTION THAT SEPARATES THE TWO IMPLEMENTATIONS. The second link must still be
    // redeemable, because its consume was rolled back with the failed insert.
    let retried = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &second_link,
            &digest("tok-x2"),
            NewPortalSession {
                id: &PortalSessionId::generate(&env, &scope),
                token_digest: &digest("cookie-x3"),
                expires_at_unix_micros: 600_000_000,
            },
            4_000_000,
        )
        .await;
    assert!(
        retried.is_ok(),
        "the failed redemption SPENT the link, so the consume and the insert did not commit \
         together: the admin is left with a used link and no session and no way to recover. \
         {retried:?}"
    );

    // AND THE COOKIE FROM THE FAILED ATTEMPT AUTHENTICATES NOTHING, which is the other half:
    // a rollback that left the session row behind would be a live credential nobody holds.
    let orphan = db
        .store()
        .scoped(scope)
        .portal_sessions()
        .authenticate(&digest("cookie-x2"), 5_000_000)
        .await;
    assert!(
        matches!(orphan, Err(StoreError::NotFound)),
        "the failed redemption left a live session behind: {orphan:?}"
    );
}

#[tokio::test]
async fn a_link_for_an_organization_deleted_after_minting_opens_no_session() {
    // THE WINDOW BETWEEN MINT AND REDEEM. The mint refuses a soft-deleted organization, but a
    // link lives up to an hour and an organization can be deleted inside that window: the vendor
    // mints, the organization is deleted ten minutes later, and the admin -- who already has the
    // link in a ticket -- would otherwise open a session over something an operator believes is
    // gone, with every later portal surface operating on a deleted organization.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let link = mint_link(&db, &env, scope, &organization, "sso", "tok-y").await;

    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete(&env, &organization)
        .await
        .expect("soft-delete the organization");

    let refused = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("tok-y"),
            NewPortalSession {
                id: &PortalSessionId::generate(&env, &scope),
                token_digest: &digest("cookie-y"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "a session opened over a soft-deleted organization: {refused:?}"
    );

    // AND NO SESSION EXISTS, which is what the check is for: a refusal reported after the insert
    // would leave a live credential over a deleted organization.
    let orphan = db
        .store()
        .scoped(scope)
        .portal_sessions()
        .authenticate(&digest("cookie-y"), 3_000_000)
        .await;
    assert!(
        matches!(orphan, Err(StoreError::NotFound)),
        "the refusal left a live session behind: {orphan:?}"
    );
}

#[tokio::test]
async fn a_live_session_stops_authenticating_when_its_organization_is_deleted() {
    // THE DOOR THE ROUND-1 FIX LEFT OPEN. That fix checked liveness at REDEMPTION only, and a
    // session lasts thirty minutes: an admin who redeemed while the organization was live kept a
    // working portal session over an organization an operator believes is gone, for the rest of
    // the window, with nothing in the product able to cut it short.
    //
    // A mint-time or redeem-time check cannot see the end of that window. Only re-reading on
    // every request can, which is what the join in `authenticate` does.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let link = mint_link(&db, &env, scope, &organization, "sso", "tok-z").await;

    db.store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("tok-z"),
            NewPortalSession {
                id: &PortalSessionId::generate(&env, &scope),
                token_digest: &digest("cookie-z"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await
        .expect("redeem while the organization is live");

    // IT WORKS FIRST, so the refusal below is the delete rather than the session never having
    // authenticated at all.
    assert!(
        db.store()
            .scoped(scope)
            .portal_sessions()
            .authenticate(&digest("cookie-z"), 3_000_000)
            .await
            .is_ok()
    );

    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete(&env, &organization)
        .await
        .expect("soft-delete the organization");

    let after = db
        .store()
        .scoped(scope)
        .portal_sessions()
        .authenticate(&digest("cookie-z"), 4_000_000)
        .await;
    assert!(
        matches!(after, Err(StoreError::NotFound)),
        "a portal session kept authenticating over a DELETED organization, and nothing in the \
         product can end it: {after:?}"
    );
}

#[tokio::test]
async fn a_live_session_stops_authenticating_when_its_organization_is_disabled() {
    // `state = 'active'` AS WELL AS `deleted_at IS NULL`. A disabled organization is one an
    // operator has switched off, and serving its configuration surface is the same mistake as
    // serving a deleted one. The analogue this join copies -- `ScimConnectionRepo::authenticate`
    // -- carries both conjuncts for exactly this reason, and checking only `deleted_at` would
    // pass the test above while leaving the disabled case open.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let link = mint_link(&db, &env, scope, &organization, "sso", "tok-w").await;

    db.store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("tok-w"),
            NewPortalSession {
                id: &PortalSessionId::generate(&env, &scope),
                token_digest: &digest("cookie-w"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await
        .expect("redeem while the organization is active");
    assert!(
        db.store()
            .scoped(scope)
            .portal_sessions()
            .authenticate(&digest("cookie-w"), 3_000_000)
            .await
            .is_ok()
    );

    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .set_state(
            &env,
            &organization,
            ironauth_store::OrganizationState::Disabled,
            None,
        )
        .await
        .expect("disable the organization");

    let after = db
        .store()
        .scoped(scope)
        .portal_sessions()
        .authenticate(&digest("cookie-w"), 4_000_000)
        .await;
    assert!(
        matches!(after, Err(StoreError::NotFound)),
        "a portal session kept authenticating over a DISABLED organization: {after:?}"
    );
}

/// Disable an organization through the management path.
async fn disable_org(db: &TestDatabase, env: &Env, scope: Scope, id: &OrganizationId) {
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .set_state(env, id, ironauth_store::OrganizationState::Disabled, None)
        .await
        .expect("disable the organization");
}

#[tokio::test]
async fn a_link_is_not_redeemed_into_a_session_for_a_disabled_organization() {
    // THE ONE INPUT ON WHICH THE TWO DOORS USED TO DISAGREE. `authenticate` requires
    // `state = 'active'`; the redemption's own check required only `deleted_at IS NULL`. So a
    // disabled organization redeemed SUCCESSFULLY -- consuming the single-use link and opening a
    // session -- and the 303 the handler itself issues was then refused, leaving the admin with
    // a spent link and a dead page. The courtesy check was weaker than the fence it anticipates,
    // which is the only way a courtesy can do harm.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let link = mint_link(&db, &env, scope, &organization, "sso", "tok-dis").await;

    disable_org(&db, &env, scope, &organization).await;

    let refused = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("tok-dis"),
            NewPortalSession {
                id: &PortalSessionId::generate(&env, &scope),
                token_digest: &digest("cookie-dis"),
                expires_at_unix_micros: 600_000_000,
            },
            2_000_000,
        )
        .await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "a link redeemed into a session for a DISABLED organization: {refused:?}"
    );

    // AND THE LINK IS NOT SPENT. This is the half that distinguishes the fix from merely moving
    // the refusal later: a refusal that consumed the link anyway leaves the admin exactly where
    // the defect left them, and an operator who re-enables the organization has not also
    // destroyed the link they were about to use.
    disable_org_undo(&db, &env, scope, &organization).await;
    let retried = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &digest("tok-dis"),
            NewPortalSession {
                id: &PortalSessionId::generate(&env, &scope),
                token_digest: &digest("cookie-dis2"),
                expires_at_unix_micros: 600_000_000,
            },
            3_000_000,
        )
        .await;
    assert!(
        retried.is_ok(),
        "the refusal spent the link, so re-enabling the organization does not recover it: \
         {retried:?}"
    );
}

/// Re-enable an organization, so a test can show the link survived the refusal.
async fn disable_org_undo(db: &TestDatabase, env: &Env, scope: Scope, id: &OrganizationId) {
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .set_state(env, id, ironauth_store::OrganizationState::Active, None)
        .await
        .expect("re-enable the organization");
}

#[tokio::test]
async fn a_link_is_never_minted_for_a_disabled_organization() {
    // THE EARLIEST DOOR HAS NO BUSINESS BEING THE MOST PERMISSIVE. The mint checked only
    // `deleted_at`, so a vendor could mint a link over an organization an operator had switched
    // off, and learn it was useless only when their customer's IT admin followed it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    disable_org(&db, &env, scope, &organization).await;

    let refused = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .portal_links()
        .mint(
            &env,
            NewPortalLink {
                id: &PortalLinkId::generate(&env, &scope),
                organization_id: &organization,
                intent: "sso",
                token_digest: &digest("tok-dis3"),
            },
            1_000_000,
            300_000_000,
        )
        .await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "a portal link was minted for a DISABLED organization: {refused:?}"
    );
}
