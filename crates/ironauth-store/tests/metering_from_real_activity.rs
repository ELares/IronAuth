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

/// The event types this file's activity produces, and the ones `UsageTally` folds.
///
/// The wait below counts these rather than every row on the feed, so a producer that starts
/// emitting some unrelated envelope cannot satisfy the wait on this test's behalf.
const METERABLE: &[&str] = &["user.signed_in", "token.issued", "connection.opened"];

/// Fold the whole feed for a scope, waiting for the events this test's own activity produced.
///
/// Polled, not read once: `events_page_after` withholds a row until every transaction open
/// anywhere on the instance has finished, so a single read can legitimately see less than was
/// written.
///
/// IT WAITS FOR THIS TEST'S OWN WRITES, NOT FOR THE NUMBER TO STOP MOVING, and an earlier
/// version got that exactly backwards: it waited for three equal non-empty reads and called
/// that settled. A stalled watermark is PRECISELY what makes the count stable -- the withheld
/// rows are what holds it steady -- so the hazard this poll exists to survive satisfied the
/// criterion for having survived it. Review reproduced the consequence: one unrelated
/// transaction holding an xid across the writes (`events_cursor_ordering.rs`'s
/// `an_unrelated_open_transaction_stalls_the_whole_feed` opens exactly one, in this crate,
/// under the same one-cluster `cargo test --workspace`) leaves the sign-ins visible and the
/// token rows withheld, the count is stable at 3, and the fold returns `tokens_issued() == 0`
/// as though it had measured something.
///
/// `want_meterable` is what this test performed, so waiting for it cannot pass the test by
/// itself: the WAIT counts meterable ROWS ON THE FEED, while the assertions are on the fold's
/// three counters. A fold that counted sign-ins instead of subjects, crossed the two counters,
/// or crossed scopes converges the wait and then fails the assertion. A missing producer -- the
/// defect this whole file exists to catch -- never converges and panics naming the watermark,
/// which is a loud failure rather than a wrong number.
async fn meter(db: &TestDatabase, scope: Scope, want_meterable: usize) -> UsageTally {
    let outbox_scope = db.store().scoped(scope);
    for _ in 0..100 {
        if let EventPage::Page(events) = outbox_scope
            .outbox()
            .events_page_after(EventCursor::beginning(), 200)
            .await
            .expect("read the feed")
        {
            let meterable = events
                .iter()
                .filter(|message| {
                    message
                        .payload
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|kind| METERABLE.contains(&kind))
                })
                .count();
            if meterable >= want_meterable {
                let mut tally = UsageTally::new();
                tally.absorb(&events);
                return tally;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!(
        "the feed never carried the {want_meterable} meterable events this test performed. \
         Either a producer is missing -- which is the defect this file exists to catch -- or \
         the cluster-wide visibility watermark never advanced past them"
    );
}

/// Fold a scope's feed as it stands, for a scope that is expected to have written nothing.
///
/// NOT `meter(db, scope, 0)`, and the difference is what makes this a control. A scope that
/// never wrote has nothing to wait for -- the watermark can withhold rows, never invent them --
/// so one read is the whole truth, and the fold has to actually RUN for the three zero
/// assertions to be about the fold rather than about `UsageTally::new()`. The earlier version
/// of this file called `meter` here, whose settle criterion an empty feed can never meet, so it
/// spent 100 reads falling through to the default tally: review replaced the body of
/// `UsageTally::absorb` with a `panic!` and both quiet sites stayed green.
async fn meter_quiet(db: &TestDatabase, scope: Scope) -> UsageTally {
    let EventPage::Page(events) = db
        .store()
        .scoped(scope)
        .outbox()
        .events_page_after(EventCursor::beginning(), 200)
        .await
        .expect("read the feed")
    else {
        panic!("the feed was pruned out from under a scope that never wrote to it")
    };
    let mut tally = UsageTally::new();
    tally.absorb(&events);
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

    // 5 meterable rows: three `user.signed_in` and two `token.issued`.
    let tally = meter(&db, scope, 5).await;

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
    // THE THIRD COUNTER, PINNED AT ZERO, and being exact about what it catches has already
    // cost two wrong versions of this comment, one in each direction. It does NOT catch a
    // fold that confuses this test's two event types with each other's counters: either
    // confusion moves a number the `monthly_active_users` or `tokens_issued` assertion above
    // checks, the test dies up there, and this line never runs. What dies HERE and nowhere
    // else is a fold that touches `connections` while leaving both counters above correct --
    // `token.issued` incrementing tokens AND connections, or a repeat sign-in counted here
    // rather than deduplicated. Both of those were run against this test, and so were the two
    // confusions; neither confusion reached this line.
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

    let tally = meter_quiet(&db, scope).await;
    assert_eq!(tally.monthly_active_users(), 0);
    assert_eq!(tally.tokens_issued(), 0);
    assert_eq!(tally.connections(), 0);
}

/// ACTIVITY IN ONE SCOPE IS NOT METERED IN ANOTHER, which is what "per tenant" means.
///
/// The criterion says "connections per tenant", and every counter here is per tenant for the
/// same reason: metering feeds billing, so a fold that crossed scopes would put one customer's
/// usage on another's invoice.
///
/// WHAT ENFORCES THAT IS POSTGRES, not the fold, and it enforces it TWICE. `outbox_messages`
/// carries `FORCE ROW LEVEL SECURITY` with a tenant-and-environment policy
/// (`migrations/0099_outbox_messages.sql`) and `begin_scoped` sets both settings on every read,
/// so the read this test performs cannot return the other scope's rows whatever the metering
/// query says. The query says it too: both halves of the feed read carry
/// `WHERE tenant_id = $1 AND environment_id = $2` -- `events_page_after`'s MIN probe and
/// `events_after` itself.
///
/// SO THIS TEST IS A CANARY FOR NEITHER LAYER, and an earlier version of this paragraph
/// nominated it as the one that would go red if RLS were dropped. MEASURED, on this file:
/// drop the policy and leave the predicate -> 3 passed; delete the predicate from both
/// queries and leave the policy -> 3 passed; remove both -> this test alone goes red, on the
/// `quiet` assertion below. Either layer on its own is sufficient, so losing one is invisible
/// here. What holds the RLS half is `migration.rs`'s
/// `outbox_messages_carries_its_isolation_and_its_structural_state_constraints`, which asserts
/// `relrowsecurity AND relforcerowsecurity` and the named policy out of the catalogue. What
/// THIS test adds is that the two layers together actually produce a scoped tally.
#[tokio::test]
async fn activity_is_metered_to_the_scope_that_performed_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let busy = db.seed_scope(&env).await;
    let quiet = db.seed_scope(&env).await;

    sign_in(&db, &env, busy, "usr_alice").await;
    redeem_one_token(&db, &env, busy, "usr_alice").await;

    // 2 meterable rows: one `user.signed_in` and one `token.issued`.
    let busy_tally = meter(&db, busy, 2).await;
    assert_eq!(busy_tally.monthly_active_users(), 1);
    assert_eq!(busy_tally.tokens_issued(), 1);

    let quiet_tally = meter_quiet(&db, quiet).await;
    assert_eq!(
        quiet_tally.monthly_active_users(),
        0,
        "the other scope's sign-in must not appear here"
    );
    assert_eq!(quiet_tally.tokens_issued(), 0, "nor its token");
}
