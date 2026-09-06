//! The self-service portal entry link, at the store (issue #140).
//!
//! # What these pin
//!
//! #140 states three properties of a link and asks for them "verified adversarially": it is
//! SINGLE-USE, it EXPIRES at its TTL, and it is INTENT-SCOPED and ORG-SCOPED. The first two are
//! decided entirely by the conditional UPDATE this file drives; the last two are decided by what
//! that UPDATE hands back, because the handler above has nothing else to go on. So this is where
//! all four boundaries either hold or do not.
#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewPortalLink, OrganizationId, PortalLinkId, Scope, StoreError,
};

/// SHA-256 of a link's bearer value, which is what the row stores.
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
async fn mint(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    intent: &str,
    token: &str,
    expires_at_micros: i64,
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
            expires_at_micros,
        )
        .await
        .expect("mint the link");
    id
}

#[tokio::test]
async fn a_link_redeems_once_and_answers_its_organization_and_intent() {
    // THE HAPPY PATH AND THE TWO BOUNDARIES IN ONE GO. What the redemption hands back IS the
    // portal session's authority -- the handler has nothing else -- so a redemption that
    // answered the wrong organization or the wrong intent would be the whole product's boundary
    // failing silently.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let id = mint(&db, &env, scope, &organization, "sso", "tok-a", 300_000_000).await;

    let redeemed = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem(&id, &digest("tok-a"), 2_000_000)
        .await
        .expect("a live link redeems");
    assert_eq!(redeemed.organization_id, organization);
    assert_eq!(redeemed.intent, "sso");

    // SINGLE-USE. The second redemption is refused, and refused as the SAME not-found an unknown
    // link answers -- telling them apart would tell somebody replaying a captured link whether
    // their first attempt worked.
    let again = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem(&id, &digest("tok-a"), 2_000_000)
        .await;
    assert!(
        matches!(again, Err(StoreError::NotFound)),
        "a portal link redeemed twice: {again:?}"
    );
}

#[tokio::test]
async fn a_link_past_its_ttl_redeems_no_longer() {
    // #140 ASKS FOR A FIVE-MINUTE DEFAULT, and the column holds whatever the caller asked for --
    // so what has to hold here is that the horizon is ENFORCED at redemption rather than merely
    // recorded. The clock is the caller's, so this drives it directly instead of sleeping.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let id = mint(
        &db,
        &env,
        scope,
        &organization,
        "scim",
        "tok-b",
        300_000_000,
    )
    .await;

    let expired = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem(&id, &digest("tok-b"), 300_000_001)
        .await;
    assert!(
        matches!(expired, Err(StoreError::NotFound)),
        "a link redeemed one microsecond past its expiry: {expired:?}"
    );

    // AND IT IS THE EXPIRY DOING IT, not the link being broken: one microsecond earlier works.
    // Without this the test would pass against a redemption that refused everything.
    assert!(
        db.store()
            .scoped(scope)
            .portal_links()
            .redeem(&id, &digest("tok-b"), 299_999_999)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn the_id_alone_redeems_nothing() {
    // THE ID IS NOT SECRET. It appears in audit rows, logs and error pages by design, and the
    // authority is the token whose digest the row holds. So holding the id must buy nothing --
    // which is why the digest is in the UPDATE's `WHERE` rather than compared after a read: a
    // wrong token leaves the row untouched, so it neither redeems NOR burns the link for its
    // rightful holder.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let id = mint(&db, &env, scope, &organization, "sso", "tok-c", 300_000_000).await;

    let guessed = db
        .store()
        .scoped(scope)
        .portal_links()
        .redeem(&id, &digest("not-the-token"), 2_000_000)
        .await;
    assert!(
        matches!(guessed, Err(StoreError::NotFound)),
        "a link redeemed with the wrong token: {guessed:?}"
    );

    // AND THE LINK IS STILL LIVE, which is the half that matters to the person holding it: a
    // failed guess that consumed the row would be a denial of service anybody with the id could
    // mount, and the id is not secret.
    assert!(
        db.store()
            .scoped(scope)
            .portal_links()
            .redeem(&id, &digest("tok-c"), 2_000_000)
            .await
            .is_ok(),
        "a wrong-token attempt burned the link for its rightful holder"
    );
}

#[tokio::test]
async fn one_environments_link_cannot_be_redeemed_in_another() {
    // #140: "a portal session for org A cannot read or mutate any org B state". The first fence
    // is the SCOPE: a link minted in one environment must be inert in another, and the id embeds
    // its scope so the mismatch is refusable before any row is read.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let ours = db.seed_scope(&env).await;
    let theirs = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, ours).await;
    let id = mint(&db, &env, ours, &organization, "sso", "tok-d", 300_000_000).await;

    let crossed = db
        .store()
        .scoped(theirs)
        .portal_links()
        .redeem(&id, &digest("tok-d"), 2_000_000)
        .await;
    assert!(
        matches!(crossed, Err(StoreError::NotFound)),
        "one environment redeemed another's portal link: {crossed:?}"
    );
}

#[tokio::test]
async fn a_link_for_an_organization_that_does_not_exist_is_never_minted() {
    // A LINK POINTING AT NOTHING would fail at REDEMPTION, which is the customer's screen rather
    // than the vendor's API call -- so the vendor would learn their integration is wrong only
    // after handing a broken link to somebody else's IT admin. The organization is checked in the
    // insert statement instead.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let absent = OrganizationId::generate(&env, &scope);

    let refused = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .portal_links()
        .mint(
            &env,
            NewPortalLink {
                id: &PortalLinkId::generate(&env, &scope),
                organization_id: &absent,
                intent: "sso",
                token_digest: &digest("tok-e"),
            },
            1_000_000,
            300_000_000,
        )
        .await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "a link was minted for an organization that does not exist: {refused:?}"
    );
}

#[tokio::test]
async fn an_unknown_intent_can_never_be_written() {
    // THE INTENT SET IS CLOSED IN THE SCHEMA, so a handler matching on it has no arm to guess at
    // and a new portal surface cannot be reached until somebody has written down that it exists.
    // A typo in a vendor's integration is a refusal at the API rather than a session scoped to a
    // surface nothing implements.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;

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
                intent: "everything",
                token_digest: &digest("tok-f"),
            },
            1_000_000,
            300_000_000,
        )
        .await;
    assert!(
        refused.is_err(),
        "an unknown intent was written: {refused:?}"
    );
}

#[tokio::test]
async fn concurrent_redemptions_of_one_link_admit_exactly_one() {
    // SINGLE-USE UNDER CONCURRENCY, which is the property a read-then-write in the handler would
    // not have: two requests presenting one link would both see `consumed_at IS NULL` and both
    // open a session. The conditional UPDATE is what makes exactly one win, and the loser cannot
    // tell that from a link that never existed.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;
    let id = mint(&db, &env, scope, &organization, "sso", "tok-g", 300_000_000).await;

    let store = db.store();
    let token = digest("tok-g");
    // THE SCOPED HANDLES ARE BOUND FIRST: building them inline inside `join!` makes each a
    // temporary whose lifetime ends at the semicolon, which the borrow checker refuses.
    let left = store.scoped(scope);
    let right = store.scoped(scope);
    let left_links = left.portal_links();
    let right_links = right.portal_links();
    let (first, second) = tokio::join!(
        left_links.redeem(&id, &token, 2_000_000),
        right_links.redeem(&id, &token, 2_000_000),
    );
    let winners = usize::from(first.is_ok()) + usize::from(second.is_ok());
    assert_eq!(
        winners, 1,
        "two concurrent redemptions of one link: {first:?} {second:?}"
    );
}

#[tokio::test]
async fn the_mint_announces_the_link_on_the_event_stream() {
    // THE ANNOUNCEMENT WAS UNMEASURED. Every other test in this file mints through the `mint`
    // helper, which forwards `None`, so the arm that enqueues the event was never once
    // executed -- and no admin test drains the feed after a mint either. Passing `None` at the
    // handler would have left this whole file green while every link went out unannounced,
    // which is the state an integrator cannot detect: the redemption happens in a browser the
    // management API never sees, so by the time anything observable occurs the grant is made.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;

    let id = PortalLinkId::generate(&env, &scope);
    let envelope = ironauth_store::event_catalog::envelope(
        "evt_portal_probe",
        "portal_link.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1_000,
        &serde_json::json!({
            "portal_link_id": id.to_string(),
            "organization_id": organization.to_string(),
            "intent": "sso",
            "expires_at_unix_ms": 300,
        }),
    )
    .expect("portal_link.created is registered");
    let subject = id.to_string();

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .portal_links()
        .mint_with_event(
            &env,
            NewPortalLink {
                id: &id,
                organization_id: &organization,
                intent: "sso",
                token_digest: &digest("tok-h"),
            },
            1_000_000,
            300_000_000,
            Some(&ironauth_store::DomainEvent {
                id: "evt_portal_probe",
                subject: &subject,
                envelope: &envelope,
            }),
        )
        .await
        .expect("mint with an event");

    // POLLED, NOT READ ONCE. The feed withholds an event until the cluster-wide snapshot
    // watermark has passed every writer that was in flight, so a single read is flaky under
    // concurrent tests rather than wrong.
    let outbox = db.store().scoped(scope).outbox();
    let mut seen = false;
    for _ in 0..100 {
        let messages = outbox.events_after(0, 200).await.expect("read the feed");
        seen = messages
            .iter()
            .any(|message| message.payload["id"].as_str() == Some("evt_portal_probe"));
        if seen {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        seen,
        "the mint committed the link and announced nothing, so a consumer watching the stream \
         never learns that configuration authority over an organization was handed out"
    );
}

#[tokio::test]
async fn a_link_for_a_soft_deleted_organization_is_never_minted() {
    // THE `deleted_at IS NULL` HALF OF THE INSERT'S GUARD, which nothing exercised. The
    // absent-organization test above uses an id that was never created, so the first three
    // conjuncts of the EXISTS already return zero and the liveness conjunct is satisfied
    // vacuously: deleting `AND deleted_at IS NULL` from the statement left every test green.
    //
    // The distinction is not academic. A soft-deleted organization is a row that still
    // matches on id, so this is the ONLY shape that can tell the two halves apart, and a link
    // minted for one would hand out authority over something an operator believes is gone.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = seed_org(&db, &env, scope).await;

    // THE CONTROL, and it runs first: the same mint against the same organization while it is
    // LIVE. Without it a refusal below could equally be the organization never having been
    // reachable, and the test would pass against a mint that refused everything.
    mint(
        &db,
        &env,
        scope,
        &organization,
        "sso",
        "tok-live",
        300_000_000,
    )
    .await;

    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete(&env, &organization)
        .await
        .expect("soft-delete the organization");

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
                token_digest: &digest("tok-i"),
            },
            1_000_000,
            300_000_000,
        )
        .await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "a portal link was minted for a SOFT-DELETED organization, handing configuration \
         authority over something an operator believes is gone: {refused:?}"
    );
}
