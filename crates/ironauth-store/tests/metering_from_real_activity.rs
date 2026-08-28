// SPDX-License-Identifier: MIT OR Apache-2.0
//! Metering counts what the system ACTUALLY DID, not what a fixture handed it (issue #107
//! criterion 4).
//!
//! The criterion asks that "metering matches seeded activity exactly (MAU, token issuance,
//! connections per tenant)", and names its own verification: "seeded metering fixture: generate
//! known activity, assert exported counters match to the unit."
//!
//! `metering_matches_seeded_activity_exactly` asserts the second half. It appends synthetic
//! envelopes through `OutboxRepo::append_event` and folds them, so what it proves is that
//! `UsageTally` adds up -- a real and useful property, and not the one the criterion names.
//! GENERATING KNOWN ACTIVITY is the part it skips, and skipping it is how the defect that
//! motivated all of this happened in the first place: `UsageTally` counted monthly actives off
//! `user.signed_in`, nothing produced that event, and the fold read a feed that never contained
//! it while reporting zero for every tenant. A test that appends the event itself cannot see
//! that.
//!
//! So this file performs the activity and then reads the meter. It writes no envelopes.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, EventCursor, EventPage, GrantId, IssueCode,
    IssuedTokenId, IssuedTokenRecord, NewSession, Scope, SessionId, StoredClientId, TokenKind,
    UsageTally,
};

const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// A real sign-in: the same call the authentication path makes.
async fn sign_in(db: &TestDatabase, env: &Env, scope: Scope, subject: &'static str) {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .rotate(
            env,
            &SessionId::generate(env, &scope),
            None,
            NewSession {
                impersonation: None,
                subject,
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: FAR_FUTURE_MICROS,
                absolute_expires_micros: FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("the sign-in commits");
}

/// A real authorization-code redemption issuing one token, through the shipped `redeem`.
async fn redeem_one_token(db: &TestDatabase, env: &Env, scope: Scope, subject: &str) {
    let code_id = AuthorizationCodeId::generate(env, &scope);
    let grant_id = GrantId::generate(env, &scope);
    let client_id = ClientId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .authorization()
        .issue(
            env,
            IssueCode {
                code_id: &code_id,
                grant_id: &grant_id,
                client_id: StoredClientId::Registered(&client_id),
                redirect_uri: "https://client.test/cb",
                browserless: false,
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                subject,
                oauth_scope: Some("openid"),
                auth_methods: "pwd",
                auth_time_micros: None,
                session_ref: None,
                org_id: None,
                consent_ref: None,
                claims_request: None,
                granted_resources: &[],
                dpop_jkt: None,
                expires_at_micros: FAR_FUTURE_MICROS,
                created_at_micros: 0,
            },
        )
        .await
        .expect("issue code");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .authorization()
        .redeem(
            env,
            &code_id,
            &grant_id,
            &[IssuedTokenRecord {
                id: IssuedTokenId::generate(env, &scope),
                kind: TokenKind::Access,
            }],
            None,
            std::time::Duration::from_secs(30),
        )
        .await
        .expect("the redemption commits");
}

/// Fold the whole feed for a scope, waiting out the cluster-wide visibility watermark.
///
/// Polled, not read once: `events_page_after` withholds a row until every transaction open
/// anywhere on the instance has finished, so a single read can legitimately see less than was
/// written. The loop waits for a STABLE count rather than for a number this test predicts,
/// so it cannot pass by asserting what it waited for.
async fn meter(db: &TestDatabase, scope: Scope) -> UsageTally {
    let outbox_scope = db.store().scoped(scope);
    let mut previous = usize::MAX;
    let mut stable = 0;
    let mut tally = UsageTally::new();
    for _ in 0..100 {
        if let EventPage::Page(events) = outbox_scope
            .outbox()
            .events_page_after(EventCursor::beginning(), 200)
            .await
            .expect("read the feed")
        {
            if events.len() == previous && !events.is_empty() {
                stable += 1;
                if stable >= 2 {
                    tally = UsageTally::new();
                    tally.absorb(&events);
                    return tally;
                }
            } else {
                stable = 0;
                previous = events.len();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    tally
}

/// CRITERION 4's ACTIVITY HALF: perform known activity, then read the meter.
///
/// Three sign-ins by two distinct subjects and two token redemptions. The numbers are chosen so
/// that a fold which confused the two counters, or counted sign-ins instead of subjects, gets a
/// different answer: 3 sign-ins but 2 actives, and 2 tokens.
#[tokio::test]
async fn metering_counts_activity_the_system_actually_performed() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    sign_in(&db, &env, scope, "usr_alice").await;
    sign_in(&db, &env, scope, "usr_bob").await;
    // Alice AGAIN, so monthly actives is a count of SUBJECTS and not of sign-ins. Without a
    // repeat, 3 sign-ins and 3 actives are the same number and the distinction is unmeasured.
    sign_in(&db, &env, scope, "usr_alice").await;

    redeem_one_token(&db, &env, scope, "usr_alice").await;
    redeem_one_token(&db, &env, scope, "usr_bob").await;

    let tally = meter(&db, scope).await;

    assert_eq!(
        tally.monthly_active_users(),
        2,
        "two DISTINCT subjects signed in, three times between them. This is the number that \
         read zero for every tenant while `user.signed_in` had no producer at all -- a defect \
         no test that appends the event itself can see"
    );
    assert_eq!(
        tally.tokens_issued(),
        2,
        "two redemptions issued one token each, through the shipped `redeem`"
    );
    // AND NOT CONFUSED WITH EACH OTHER. Without this, a fold that added sign-ins into
    // `tokens_issued` would still satisfy one of the assertions above by coincidence.
    assert_eq!(
        tally.connections(),
        0,
        "nothing opened a connection, so that counter must be untouched by either activity"
    );
}

/// A tenant that did nothing meters zero, and that is a DIFFERENT answer from a broken fold.
///
/// The control for the test above: every assertion there is a positive number, and a fold that
/// invented events would satisfy them as readily as one that counted correctly.
#[tokio::test]
async fn a_scope_with_no_activity_meters_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let tally = meter(&db, scope).await;
    assert_eq!(tally.monthly_active_users(), 0);
    assert_eq!(tally.tokens_issued(), 0);
    assert_eq!(tally.connections(), 0);
}

/// ACTIVITY IN ONE SCOPE IS NOT METERED IN ANOTHER, which is what "per tenant" means.
///
/// The criterion says "connections per tenant", and every counter here is per tenant for the
/// same reason: metering feeds billing, so a fold that crossed scopes would put one customer's
/// usage on another's invoice.
#[tokio::test]
async fn activity_is_metered_to_the_scope_that_performed_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let busy = db.seed_scope(&env).await;
    let quiet = db.seed_scope(&env).await;

    sign_in(&db, &env, busy, "usr_alice").await;
    redeem_one_token(&db, &env, busy, "usr_alice").await;

    let busy_tally = meter(&db, busy).await;
    assert_eq!(busy_tally.monthly_active_users(), 1);
    assert_eq!(busy_tally.tokens_issued(), 1);

    let quiet_tally = meter(&db, quiet).await;
    assert_eq!(
        quiet_tally.monthly_active_users(),
        0,
        "the other scope's sign-in must not appear here"
    );
    assert_eq!(quiet_tally.tokens_issued(), 0, "nor its token");
}
