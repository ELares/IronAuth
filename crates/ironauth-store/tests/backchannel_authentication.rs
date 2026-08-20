// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CIBA backchannel-authentication table's own guarantees (issue #131), over a real
//! database (`DATABASE_URL`).
//!
//! These assertions are about the SCHEMA, not about application code. `ciba.rs` already
//! tests the protocol rules as pure functions; what cannot be tested there is whether the
//! data can escape those rules by a path that does not go through them. So this file writes
//! SQL directly and tries to do the forbidden thing.
//!
//! The distinction matters for #131 criterion 3. "An `auth_req_id` cannot be redeemed by a
//! different client" and "expires within `requested_expiry` bounds" are only real if the
//! client binding and the expiry cannot be rewritten after INSERT. That is a property of the
//! column-scoped `UPDATE` grant, and a test of the repository would not notice if the grant
//! were widened to table-wide tomorrow.

use ironauth_env::Env;
use ironauth_store::ciba::DeliveryMode;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    BackchannelApprovalLinkage, BackchannelAuthRequestId, BackchannelPoll, NewBackchannelRequest,
    Scope,
};
use sqlx::Row;

/// Bind the transaction-local row-level-security scope variables, exactly as the
/// repository does. Raw SQL is the point of this file, so the binding the repository would
/// have done has to be done by hand.
async fn bind_scope(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, scope: Scope) {
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(scope.tenant().to_string())
        .execute(&mut **tx)
        .await
        .expect("bind tenant scope");
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(scope.environment().to_string())
        .execute(&mut **tx)
        .await
        .expect("bind environment scope");
}

/// A far-future expiry (year 2100), so a seeded request is live under the real clock.
const FAR_FUTURE: &str = "2100-01-01T00:00:00Z";

/// The same far-future instant in epoch microseconds, for the repository paths that take a
/// clock reading rather than a timestamp literal.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Insert a request row directly, returning the database's answer.
///
/// Deliberately parameterized over the columns the CHECKs constrain, so each test states
/// exactly the one thing it is varying.
async fn insert(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    delivery_mode: &str,
    notification_url: Option<&str>,
    notification_token: Option<&[u8]>,
    interval_secs: i32,
) -> Result<(), sqlx::Error> {
    let id = BackchannelAuthRequestId::generate(env, &scope);
    let digest = format!("{:064x}", id.to_string().len());
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let result = sqlx::query(
        "INSERT INTO backchannel_authentication_requests (
             auth_req_id_digest, tenant_id, environment_id, id, client_id,
             delivery_mode, client_notification_url, client_notification_token,
             status, interval_secs, subject, expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, $11::timestamptz)",
    )
    .bind(&digest)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(id.to_string())
    .bind("cli_test")
    .bind(delivery_mode)
    .bind(notification_url)
    .bind(notification_token)
    .bind(interval_secs)
    .bind("usr_test")
    .bind(FAR_FUTURE)
    .execute(&mut *tx)
    .await
    .map(|_| ());
    if result.is_ok() {
        tx.commit().await.expect("commit");
    }
    result
}

/// A poll-mode request with no notification target is accepted.
///
/// The positive control. Without it every refusal below could be passing because the INSERT
/// is broken in some way that has nothing to do with the constraint under test.
#[tokio::test]
async fn a_well_formed_poll_request_is_accepted() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    insert(&db, &env, scope, "poll", None, None, 5)
        .await
        .expect("a well-formed poll request is accepted");
}

/// A ping-mode request carrying both halves of its notification target is accepted.
#[tokio::test]
async fn a_well_formed_ping_request_is_accepted() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    insert(
        &db,
        &env,
        scope,
        "ping",
        Some("https://client.test/ciba"),
        Some(b"sealed-token"),
        5,
    )
    .await
    .expect("a well-formed ping request is accepted");
}

/// `push` cannot be stored at all (#131 criterion 6).
///
/// The application refuses push in `DeliveryMode::parse`. This proves the refusal is also
/// STRUCTURAL: there is no state of the database in which a push-mode request exists, so a
/// future writer who has not read `docs/WILL-NOT-IMPLEMENT.md` cannot create one.
#[tokio::test]
async fn push_mode_cannot_be_stored() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let error = insert(
        &db,
        &env,
        scope,
        "push",
        Some("https://client.test/ciba"),
        Some(b"sealed-token"),
        5,
    )
    .await
    .expect_err("push must be refused by the schema, not only by the parser");
    assert!(
        error.to_string().contains("mode_known"),
        "the closed delivery-mode vocabulary should be what refuses it: {error}"
    );
}

/// A ping request without a notification target is refused, and so is a poll request WITH
/// one.
///
/// Both directions, because only the first is obvious. A poll-mode row carrying a
/// notification URL would be inert today and honoured by whichever future reader stops
/// checking the mode first -- which is precisely how a poll-mode request becomes a way to
/// make the server call an arbitrary URL.
#[tokio::test]
async fn the_notification_target_is_paired_with_the_delivery_mode_in_both_directions() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let error = insert(&db, &env, scope, "ping", None, None, 5)
        .await
        .expect_err("ping without a notification target must be refused");
    assert!(
        error.to_string().contains("ping_has_notification"),
        "{error}"
    );

    let error = insert(
        &db,
        &env,
        scope,
        "poll",
        Some("https://attacker.test/"),
        Some(b"sealed-token"),
        5,
    )
    .await
    .expect_err("poll carrying a notification target must be refused");
    assert!(
        error.to_string().contains("ping_has_notification"),
        "{error}"
    );
}

/// A zero polling interval cannot be stored, so `slow_down` cannot be disabled by data.
#[tokio::test]
async fn a_non_positive_interval_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let error = insert(&db, &env, scope, "poll", None, None, 0)
        .await
        .expect_err("a zero interval must be refused");
    assert!(error.to_string().contains("interval_positive"), "{error}");
}

/// The client binding and the expiry are write-once for the data plane (#131 criterion 3).
///
/// This is the assertion the whole file exists for. "Cannot be redeemed by a different
/// client" and "expires within `requested_expiry` bounds" are guarantees only if the data
/// plane cannot rewrite `client_id` or `expires_at` after the fact. The migration grants a
/// COLUMN-SCOPED `UPDATE` that omits both; this proves the grant is actually in force,
/// rather than a comment describing an intention.
///
/// A permitted column is updated first as a positive control, so a blanket "all UPDATEs
/// fail" (a broken transaction, a missing row, an RLS refusal) cannot masquerade as the
/// narrow guarantee being tested.
#[tokio::test]
async fn the_client_binding_and_expiry_cannot_be_rewritten_by_the_data_plane() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    insert(&db, &env, scope, "poll", None, None, 5)
        .await
        .expect("seed");

    // Positive control: a column the data plane IS granted.
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    sqlx::query("UPDATE backchannel_authentication_requests SET status = 'approved'")
        .execute(&mut *tx)
        .await
        .expect("status is a data-plane column and must be writable");
    tx.commit().await.expect("commit");

    // The client binding.
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let error =
        sqlx::query("UPDATE backchannel_authentication_requests SET client_id = 'cli_other'")
            .execute(&mut *tx)
            .await
            .expect_err("the client binding must not be rewritable by the data plane");
    assert!(
        error.to_string().contains("permission denied"),
        "expected a privilege refusal, got: {error}"
    );

    // The expiry.
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let error = sqlx::query(
        "UPDATE backchannel_authentication_requests SET expires_at = '2200-01-01T00:00:00Z'",
    )
    .execute(&mut *tx)
    .await
    .expect_err("the expiry must not be extendable by the data plane");
    assert!(
        error.to_string().contains("permission denied"),
        "expected a privilege refusal, got: {error}"
    );
}

/// A request is invisible outside its own scope.
///
/// Forced row-level security, so the read returns an EMPTY result rather than an error --
/// which is why this asserts on the count and not on a refusal.
#[tokio::test]
async fn a_request_is_invisible_from_another_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let mine = db.seed_scope(&env).await;
    let theirs = db.seed_scope(&env).await;
    insert(&db, &env, mine, "poll", None, None, 5)
        .await
        .expect("seed");

    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, mine).await;
    let count: i64 = sqlx::query("SELECT count(*) FROM backchannel_authentication_requests")
        .fetch_one(&mut *tx)
        .await
        .expect("count in my own scope")
        .get(0);
    assert_eq!(count, 1, "the request is visible in its own scope");
    drop(tx);

    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, theirs).await;
    let count: i64 = sqlx::query("SELECT count(*) FROM backchannel_authentication_requests")
        .fetch_one(&mut *tx)
        .await
        .expect("count in another scope")
        .get(0);
    assert_eq!(count, 0, "another scope sees nothing");
}

/// A far-future instant in epoch microseconds, matching `FAR_FUTURE` above.
const NOW_MICROS: i64 = 1_800_000_000_000_000;

/// Seed an APPROVED request for `client`, returning its digest.
/// A distinct 64-hex digest per input, so fixtures cannot collide on the primary key.
fn digest_of(seed: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut hasher);
    let a = hasher.finish();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    (seed, a).hash(&mut hasher);
    let b = hasher.finish();
    format!("{a:016x}{b:016x}{a:016x}{b:016x}")
}

/// An approved request WITH the grant its approval opened, which is the only redeemable
/// shape.
///
/// It returns the grant because redemption now REQUIRES the spine. An approval that opened no
/// grant has nothing for the tokens to hang off and nothing for a revocation to reach, so a
/// fixture without one models a request that cannot legitimately be redeemed at all. Four
/// rounds of review chased holes reachable only through that shape.
///
/// `requested_scope` is set, because it is the ceiling on what an issued token may claim and
/// a NULL one bounds every token to no scope at all.
async fn seed_approved_linked(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    client: &str,
) -> (String, ironauth_store::GrantId) {
    let grant = ironauth_store::GrantId::generate(env, &scope);
    seed_grant(db, scope, &grant.to_string(), client, "usr_subject").await;
    let digest = seed_approved_with_grant(db, env, scope, client, Some(&grant.to_string())).await;
    (digest, grant)
}

/// The same, with explicit control over the spine, for the tests that need a NULL one or one
/// pointing at a grant they built themselves.
async fn seed_approved_with_grant(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    client: &str,
    grant_id: Option<&str>,
) -> String {
    let id = BackchannelAuthRequestId::generate(env, &scope);
    // Derived from the ID, not from its LENGTH. The original derived it from
    // `id.to_string().len()`, which is the same for every id, so two approved fixtures in one
    // test collided on the primary key and the failure surfaced as an opaque `.expect` inside
    // this helper rather than as anything about the test. `create_pending_with_id` has the
    // same bug and the same workaround one function down.
    let digest = digest_of(&id.to_string());
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    sqlx::query(
        "INSERT INTO backchannel_authentication_requests (
             auth_req_id_digest, tenant_id, environment_id, id, client_id,
             delivery_mode, status, interval_secs, subject, expires_at,
             grant_id, requested_scope
         ) VALUES ($1, $2, $3, $4, $5, 'poll', 'approved', 5, $6, $7::timestamptz, $8, $9)",
    )
    .bind(&digest)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(id.to_string())
    .bind(client)
    .bind("usr_subject")
    .bind(FAR_FUTURE)
    .bind(grant_id)
    .bind("openid profile")
    .execute(&mut *tx)
    .await
    .expect("seed an approved request");
    tx.commit().await.expect("commit");
    digest
}

async fn seed_approved(db: &TestDatabase, env: &Env, scope: Scope, client: &str) -> String {
    seed_approved_with_grant(db, env, scope, client, None).await
}

/// An approved request redeems exactly once (#131 criterion 3, single-use).
#[tokio::test]
async fn an_approved_request_redeems_exactly_once() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let digest = seed_approved(&db, &env, scope, "cli_owner").await;
    let repo = db.store().scoped(scope);

    let first = repo
        .backchannel_auth()
        .redeem(&digest, "cli_owner", NOW_MICROS)
        .await
        .expect("redeem");
    let first = first.expect("the first redemption succeeds");
    assert_eq!(first.subject, "usr_subject");

    let second = repo
        .backchannel_auth()
        .redeem(&digest, "cli_owner", NOW_MICROS)
        .await
        .expect("redeem");
    assert!(
        second.is_none(),
        "a second redemption must find nothing: the auth_req_id is single-use"
    );
}

/// A different client cannot redeem, AND does not burn the request (#131 criterion 3).
///
/// The second half is the one worth having. If a wrong-client attempt consumed the request,
/// any party who learned an `auth_req_id` could destroy a legitimate client's pending
/// redemption without ever obtaining a token -- a denial of service that a test only
/// checking "the wrong client gets nothing" would call a pass.
#[tokio::test]
async fn a_different_client_cannot_redeem_and_does_not_burn_the_request() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let digest = seed_approved(&db, &env, scope, "cli_owner").await;
    let repo = db.store().scoped(scope);

    let stolen = repo
        .backchannel_auth()
        .redeem(&digest, "cli_attacker", NOW_MICROS)
        .await
        .expect("redeem");
    assert!(stolen.is_none(), "another client must not redeem it");

    let rightful = repo
        .backchannel_auth()
        .redeem(&digest, "cli_owner", NOW_MICROS)
        .await
        .expect("redeem");
    assert!(
        rightful.is_some(),
        "the wrong client's attempt must NOT have burned the request"
    );
}

/// An expired request does not redeem, and expiry is judged by the passed-in clock.
#[tokio::test]
async fn an_expired_request_does_not_redeem() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let digest = seed_approved(&db, &env, scope, "cli_owner").await;
    // A "now" past the year-2100 expiry: the application clock seam decides, not the
    // database clock, which is why this can be tested at all without waiting.
    let after_expiry: i64 = 5_000_000_000_000_000;
    let outcome = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem(&digest, "cli_owner", after_expiry)
        .await
        .expect("redeem");
    assert!(outcome.is_none(), "an expired request must not redeem");
}

/// A request that was never approved cannot be redeemed straight from pending.
#[tokio::test]
async fn a_pending_request_cannot_be_redeemed() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    insert(&db, &env, scope, "poll", None, None, 5)
        .await
        .expect("seed a pending request");
    // The digest the `insert` helper derives.
    let id_len = BackchannelAuthRequestId::generate(env_ref(), &scope)
        .to_string()
        .len();
    let digest = format!("{id_len:064x}");
    let outcome = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem(&digest, "cli_test", NOW_MICROS)
        .await
        .expect("redeem");
    assert!(
        outcome.is_none(),
        "tokens must require an approval that actually happened"
    );
}

/// A borrow of the system environment, so the digest derivation above matches `insert`.
fn env_ref() -> &'static Env {
    static ENV: std::sync::OnceLock<Env> = std::sync::OnceLock::new();
    ENV.get_or_init(Env::system)
}

/// Create a pending poll-mode request through the REPOSITORY (not raw SQL), returning its
/// digest. Uses the real `create` so these tests exercise the path production takes.
async fn create_pending(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    client: &str,
    interval_secs: i32,
    expires_at_micros: i64,
) -> String {
    let id = BackchannelAuthRequestId::generate(env, &scope);
    let digest = format!("{:064x}", id.to_string().len() + 11);
    db.store()
        .scoped(scope)
        .backchannel_auth()
        .create(&NewBackchannelRequest {
            auth_req_id_digest: &digest,
            id: &id,
            client_id: client,
            delivery_mode: DeliveryMode::Poll,
            client_notification_url: None,
            client_notification_token: None,
            requested_scope: Some("openid"),
            authorization_details: None,
            binding_message: Some("Approve sign-in 42"),
            subject: "usr_subject",
            interval_secs,
            expires_at_micros,
        })
        .await
        .expect("create a pending request");
    digest
}

/// A second-too-soon poll is told to slow down, and the interval GROWS (#131 criterion 1).
///
/// Three polls, because two would not distinguish "`slow_down` is returned" from "the interval
/// actually increased". The third poll is still inside the widened window, so its reported
/// interval must be larger again -- which is the property that makes a client ignoring
/// `slow_down` get progressively slower rather than merely scolded.
#[tokio::test]
async fn polling_faster_than_the_interval_slows_the_client_down_progressively() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let digest = create_pending(&db, &env, scope, "cli_owner", 5, FAR_FUTURE_MICROS).await;
    let repo = db.store().scoped(scope);

    // First poll: nothing to compare against, so it is honoured.
    let first = repo
        .backchannel_auth()
        .poll(&digest, "cli_owner", NOW_MICROS, 5)
        .await
        .expect("poll");
    assert_eq!(
        first,
        BackchannelPoll::Pending,
        "the first poll is honoured"
    );

    // One second later, well inside the 5s interval.
    let second = repo
        .backchannel_auth()
        .poll(&digest, "cli_owner", NOW_MICROS + 1_000_000, 5)
        .await
        .expect("poll");
    assert_eq!(
        second,
        BackchannelPoll::SlowDown { interval_secs: 10 },
        "a too-soon poll must slow_down AND widen the interval"
    );

    // Another second later, inside the WIDENED window.
    let third = repo
        .backchannel_auth()
        .poll(&digest, "cli_owner", NOW_MICROS + 2_000_000, 5)
        .await
        .expect("poll");
    assert_eq!(
        third,
        BackchannelPoll::SlowDown { interval_secs: 15 },
        "ignoring slow_down must keep widening the interval"
    );
}

/// A client that respects the interval never sees `slow_down`.
///
/// The positive control for the test above: without it, an implementation that answered
/// `SlowDown` to EVERY poll would pass.
#[tokio::test]
async fn a_client_that_respects_the_interval_is_never_slowed_down() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let digest = create_pending(&db, &env, scope, "cli_owner", 5, FAR_FUTURE_MICROS).await;
    let repo = db.store().scoped(scope);

    for step in 0..3_i64 {
        let outcome = repo
            .backchannel_auth()
            .poll(&digest, "cli_owner", NOW_MICROS + step * 6_000_000, 5)
            .await
            .expect("poll");
        assert_eq!(
            outcome,
            BackchannelPoll::Pending,
            "poll {step} respected the 5s interval and must not be slowed"
        );
    }
}

/// Polling is not an existence oracle: another client's request answers `NotFound`.
#[tokio::test]
async fn polling_another_clients_request_is_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let digest = create_pending(&db, &env, scope, "cli_owner", 5, FAR_FUTURE_MICROS).await;
    let outcome = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .poll(&digest, "cli_attacker", NOW_MICROS, 5)
        .await
        .expect("poll");
    assert_eq!(outcome, BackchannelPoll::NotFound);
}

/// An expired request reports `Expired` rather than `Pending` forever.
#[tokio::test]
async fn an_expired_request_reports_expired_when_polled() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    // Expires one second after NOW_MICROS.
    let digest = create_pending(&db, &env, scope, "cli_owner", 5, NOW_MICROS + 1_000_000).await;
    let repo = db.store().scoped(scope);

    let live = repo
        .backchannel_auth()
        .poll(&digest, "cli_owner", NOW_MICROS, 5)
        .await
        .expect("poll");
    assert_eq!(live, BackchannelPoll::Pending, "still inside its TTL");

    // Well past the expiry, and past the interval so this is not a slow_down.
    let dead = repo
        .backchannel_auth()
        .poll(&digest, "cli_owner", NOW_MICROS + 60_000_000, 5)
        .await
        .expect("poll");
    assert_eq!(dead, BackchannelPoll::Expired);
}

/// A ping request without its notification target is refused by `create`.
///
/// The schema CHECK already proves the DATABASE refuses it; this proves the refusal is
/// reached through the repository, which is the path production actually takes.
#[tokio::test]
async fn creating_a_ping_request_without_a_notification_target_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = BackchannelAuthRequestId::generate(&env, &scope);
    let digest = format!("{:064x}", id.to_string().len() + 23);
    let outcome = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .create(&NewBackchannelRequest {
            auth_req_id_digest: &digest,
            id: &id,
            client_id: "cli_owner",
            delivery_mode: DeliveryMode::Ping,
            client_notification_url: None,
            client_notification_token: None,
            requested_scope: None,
            authorization_details: None,
            binding_message: None,
            subject: "usr_subject",
            interval_secs: 5,
            expires_at_micros: FAR_FUTURE_MICROS,
        })
        .await;
    assert!(
        outcome.is_err(),
        "a ping request with nowhere to ping must be refused"
    );
}

/// Create a pending request and return `(digest, id)` so a decision can be submitted.
/// Create a pending request with a digest that varies with `nonce`.
///
/// `create_pending_with_id` derives its digest from the request id's LENGTH, which is the same
/// for every id, so two calls in one test collide on the primary key. Tests that need more
/// than one pending request use this instead.
async fn create_pending_nonce(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    client: &str,
    subject: &str,
    nonce: u32,
) -> (String, BackchannelAuthRequestId) {
    let id = BackchannelAuthRequestId::generate(env, &scope);
    let digest = format!("{:064x}", u64::from(nonce) + 4096);
    db.store()
        .scoped(scope)
        .backchannel_auth()
        .create(&NewBackchannelRequest {
            auth_req_id_digest: &digest,
            id: &id,
            client_id: client,
            delivery_mode: DeliveryMode::Poll,
            client_notification_url: None,
            client_notification_token: None,
            requested_scope: Some("openid profile"),
            authorization_details: None,
            binding_message: Some("Approve transfer of 40 EUR"),
            subject,
            interval_secs: 5,
            expires_at_micros: FAR_FUTURE_MICROS,
        })
        .await
        .expect("create");
    (digest, id)
}

async fn create_pending_with_id(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    client: &str,
    subject: &str,
) -> (String, BackchannelAuthRequestId) {
    let id = BackchannelAuthRequestId::generate(env, &scope);
    let digest = format!("{:064x}", id.to_string().len() + 31);
    db.store()
        .scoped(scope)
        .backchannel_auth()
        .create(&NewBackchannelRequest {
            auth_req_id_digest: &digest,
            id: &id,
            client_id: client,
            delivery_mode: DeliveryMode::Poll,
            client_notification_url: None,
            client_notification_token: None,
            requested_scope: Some("openid profile"),
            authorization_details: None,
            binding_message: Some("Approve transfer of 40 EUR"),
            subject,
            interval_secs: 5,
            expires_at_micros: FAR_FUTURE_MICROS,
        })
        .await
        .expect("create");
    (digest, id)
}

/// The approval surface renders the binding message, for the right user only.
#[tokio::test]
async fn a_pending_request_is_listed_for_its_subject_with_its_binding_message() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (_digest, id) = create_pending_with_id(&db, &env, scope, "cli_owner", "usr_ada").await;
    let repo = db.store().scoped(scope);

    let mine = repo
        .backchannel_auth()
        .pending_for_subject("usr_ada", NOW_MICROS)
        .await
        .expect("list");
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].id, id);
    assert_eq!(
        mine[0].binding_message.as_deref(),
        Some("Approve transfer of 40 EUR"),
        "the surface must be able to say WHICH request is being approved"
    );

    // Another user sees nothing, so a prompt cannot be rendered for someone else's request.
    let theirs = repo
        .backchannel_auth()
        .pending_for_subject("usr_grace", NOW_MICROS)
        .await
        .expect("list");
    assert!(
        theirs.is_empty(),
        "a request is listed only for its subject"
    );
}

/// Only the named subject may decide, and only once (#131 criterion 1).
#[tokio::test]
async fn only_the_named_subject_can_decide_and_only_from_pending() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (_digest, id) = create_pending_with_id(&db, &env, scope, "cli_owner", "usr_ada").await;
    let repo = db.store().scoped(scope);

    // Someone else's approval decides nothing.
    let stolen = repo
        .backchannel_auth()
        .decide(
            &env,
            &id,
            "usr_grace",
            true,
            BackchannelApprovalLinkage::default(),
            NOW_MICROS,
        )
        .await
        .expect("decide");
    assert!(!stolen, "another user must not be able to approve it");

    // The rightful subject denies.
    let denied = repo
        .backchannel_auth()
        .decide(
            &env,
            &id,
            "usr_ada",
            false,
            BackchannelApprovalLinkage::default(),
            NOW_MICROS,
        )
        .await
        .expect("decide");
    assert!(denied, "the named subject decides");

    // A late approval cannot flip a denial. This is the one that matters: without the
    // pending guard, a second click after a refusal would silently authorize the request.
    let flipped = repo
        .backchannel_auth()
        .decide(
            &env,
            &id,
            "usr_ada",
            true,
            BackchannelApprovalLinkage::default(),
            NOW_MICROS,
        )
        .await
        .expect("decide");
    assert!(!flipped, "a decided request must not be decidable again");
}

/// An approved request becomes redeemable, and a denied one never does.
#[tokio::test]
async fn approval_makes_a_request_redeemable_and_denial_does_not() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let repo = db.store().scoped(scope);

    let (approved_digest, approved_id) =
        create_pending_with_id(&db, &env, scope, "cli_owner", "usr_ada").await;
    assert!(
        repo.backchannel_auth()
            .decide(
                &env,
                &approved_id,
                "usr_ada",
                true,
                BackchannelApprovalLinkage::default(),
                NOW_MICROS
            )
            .await
            .expect("decide")
    );
    let redeemed = repo
        .backchannel_auth()
        .redeem(&approved_digest, "cli_owner", NOW_MICROS)
        .await
        .expect("redeem");
    assert!(redeemed.is_some(), "approval makes it redeemable");
    assert_eq!(redeemed.expect("some").subject, "usr_ada");
}

/// A client cannot register push mode, and cannot hold a mismatched notification endpoint
/// (#131 criteria 2 and 6).
///
/// Asserted against the SCHEMA, because that is what makes the refusal survive a caller that
/// forgets to ask. The application refuses push in `DeliveryMode::parse`; this proves there is
/// no state of the database in which a push-mode client exists.
///
/// The poll-WITH-an-endpoint direction is the one worth having. Such a row is inert today,
/// and the first future reader that consults the endpoint column before checking the mode
/// turns a poll registration into a server-side request to an attacker-chosen URL. An unused
/// URL on a row is exactly the latent capability that becomes an SSRF the day someone wires
/// it up.
#[tokio::test]
async fn a_client_cannot_register_push_or_a_mismatched_notification_endpoint() {
    async fn set(
        db: &TestDatabase,
        scope: Scope,
        mode: &str,
        endpoint: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = db.app_pool().begin().await.expect("begin");
        bind_scope(&mut tx, scope).await;
        let result = sqlx::query(
            "UPDATE clients SET backchannel_delivery_mode = $1, \
             backchannel_client_notification_endpoint = $2",
        )
        .bind(mode)
        .bind(endpoint)
        .execute(&mut *tx)
        .await
        .map(|done| {
            assert_eq!(
                done.rows_affected(),
                1,
                "the statement must touch exactly one client row; zero rows would make every \
                 assertion in this test vacuous"
            );
        });
        if result.is_ok() {
            tx.commit().await.expect("commit");
        }
        result
    }
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    // A REAL client row. Without one every UPDATE below touches zero rows and succeeds
    // trivially -- which is exactly how this test first passed its positive controls while
    // proving nothing. A CHECK constraint only fires on a row that exists.
    let client_id = db
        .store()
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .clients()
        .create(&env, "ciba delivery test client")
        .await
        .expect("create a client");
    assert_eq!(client_id.scope(), scope);

    // Positive controls first: both legitimate shapes must be accepted, or every refusal
    // below could be passing for an unrelated reason.
    set(&db, scope, "poll", None).await.expect("poll is valid");
    set(&db, scope, "ping", Some("https://client.test/ciba"))
        .await
        .expect("ping with an endpoint is valid");

    let error = set(&db, scope, "push", Some("https://client.test/ciba"))
        .await
        .expect_err("push must be refused by the schema, not only by the parser");
    assert!(
        error.to_string().contains("delivery_mode_known"),
        "the closed vocabulary should be what refuses it: {error}"
    );

    let error = set(&db, scope, "ping", None)
        .await
        .expect_err("ping with nowhere to ping must be refused");
    assert!(error.to_string().contains("ping_has_endpoint"), "{error}");

    let error = set(&db, scope, "poll", Some("https://attacker.test/"))
        .await
        .expect_err("a poll client must not carry a notification endpoint");
    assert!(error.to_string().contains("ping_has_endpoint"), "{error}");
}

/// Seed a request in the given delivery mode, wired consistently with the schema's
/// mode/endpoint/token pairing.
async fn seed(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    mode: DeliveryMode,
) -> BackchannelAuthRequestId {
    let id = BackchannelAuthRequestId::generate(env, &scope);
    let digest = format!(
        "{:064x}",
        id.to_string().len() + usize::from(mode == DeliveryMode::Ping) + 41
    );
    db.store()
        .scoped(scope)
        .backchannel_auth()
        .create(&NewBackchannelRequest {
            auth_req_id_digest: &digest,
            id: &id,
            client_id: "cli_owner",
            delivery_mode: mode,
            client_notification_url: match mode {
                DeliveryMode::Ping => Some("https://client.test/ciba"),
                DeliveryMode::Poll => None,
            },
            client_notification_token: match mode {
                DeliveryMode::Ping => Some(b"nt-secret"),
                DeliveryMode::Poll => None,
            },
            requested_scope: None,
            authorization_details: None,
            binding_message: None,
            subject: "usr_ada",
            interval_secs: 5,
            expires_at_micros: FAR_FUTURE_MICROS,
        })
        .await
        .expect("create");
    id
}

/// Claim and complete every pending CIBA ping, returning their payloads.
async fn drain_pings(db: &TestDatabase, env: &Env, scope: Scope) -> Vec<serde_json::Value> {
    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            env,
            ironauth_store::CIBA_PING_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim pings");
    let payloads = claimed.iter().map(|m| m.payload.clone()).collect();
    for m in claimed {
        db.store()
            .scoped(scope)
            .outbox()
            .complete(env, &m)
            .await
            .expect("complete");
    }
    payloads
}

/// Approving a PING request enqueues exactly one ping; approving a POLL request enqueues
/// none (#131 criterion 2).
///
/// Both halves, because only together do they say the enqueue is conditional. A test that
/// checked the ping alone would pass an implementation that notified every approval, which
/// would call a poll client's endpoint -- and a poll client has no endpoint, so the message
/// would carry a null URL and fail forever in the retry loop.
#[tokio::test]
async fn approving_a_ping_request_enqueues_one_notification_and_poll_enqueues_none() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let repo = db.store().scoped(scope);

    // POLL: approving must enqueue nothing.
    let poll_id = seed(&db, &env, scope, DeliveryMode::Poll).await;
    assert!(
        repo.backchannel_auth()
            .decide(
                &env,
                &poll_id,
                "usr_ada",
                true,
                BackchannelApprovalLinkage::default(),
                NOW_MICROS
            )
            .await
            .expect("decide")
    );
    assert!(
        drain_pings(&db, &env, scope).await.is_empty(),
        "a poll client has no endpoint; notifying one would queue a null URL that fails forever"
    );

    // PING: approving must enqueue exactly one, carrying the endpoint and NOT the token.
    let ping_id = seed(&db, &env, scope, DeliveryMode::Ping).await;
    assert!(
        repo.backchannel_auth()
            .decide(
                &env,
                &ping_id,
                "usr_ada",
                true,
                BackchannelApprovalLinkage::default(),
                NOW_MICROS
            )
            .await
            .expect("decide")
    );
    let pings = drain_pings(&db, &env, scope).await;
    assert_eq!(pings.len(), 1, "exactly one ping per approval: {pings:?}");
    assert_eq!(pings[0]["auth_req_id"], ping_id.to_string());
    assert_eq!(pings[0]["notification_url"], "https://client.test/ciba");
    assert!(
        pings[0].get("client_notification_token").is_none(),
        "the notification token is a live bearer credential and must never ride in the \
         queue payload: {:?}",
        pings[0]
    );
}

/// A DENIAL enqueues no ping.
///
/// The client learns nothing by notification when the user said no -- it discovers the
/// denial by polling, exactly as CIBA Core describes. Notifying on denial would also mean an
/// endpoint that is down burns retry budget for a request that will never issue tokens.
#[tokio::test]
async fn denying_a_ping_request_enqueues_no_notification() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = BackchannelAuthRequestId::generate(&env, &scope);
    let digest = format!("{:064x}", id.to_string().len() + 61);
    db.store()
        .scoped(scope)
        .backchannel_auth()
        .create(&NewBackchannelRequest {
            auth_req_id_digest: &digest,
            id: &id,
            client_id: "cli_owner",
            delivery_mode: DeliveryMode::Ping,
            client_notification_url: Some("https://client.test/ciba"),
            client_notification_token: Some(b"nt-secret"),
            requested_scope: None,
            authorization_details: None,
            binding_message: None,
            subject: "usr_ada",
            interval_secs: 5,
            expires_at_micros: FAR_FUTURE_MICROS,
        })
        .await
        .expect("create");

    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .decide(
                &env,
                &id,
                "usr_ada",
                false,
                BackchannelApprovalLinkage::default(),
                NOW_MICROS
            )
            .await
            .expect("decide")
    );
    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::CIBA_PING_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim");
    assert!(claimed.is_empty(), "a denial notifies nobody");
}

/// Approving with a grant id opens a REAL grant, for the request's own client and subject
/// (#131 criterion 5).
///
/// The CLIENT is the part that can only come from the request: there is no client parameter,
/// and a grant must name the client whose tokens will hang off it. The subject is read from
/// the same row for consistency rather than for safety -- the decision filters on `subject`,
/// so on any committing path the two are provably equal. Asserted here anyway, because the
/// grant is the revocation spine every issued token hangs off and "it names the right client
/// and subject" is the property that makes revocation reach the right tokens.
#[tokio::test]
async fn approving_with_a_grant_opens_it_for_the_requests_own_client_and_subject() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (_digest, id) = create_pending_with_id(&db, &env, scope, "cli_owner", "usr_ada").await;
    let grant_id = ironauth_store::GrantId::generate(&env, &scope);

    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .decide(
                &env,
                &id,
                "usr_ada",
                true,
                BackchannelApprovalLinkage {
                    grant_id: Some(&grant_id.to_string()),
                    consent_ref: None,
                    auth_methods: Some("pwd"),
                    auth_time_micros: Some(NOW_MICROS),
                },
                NOW_MICROS,
            )
            .await
            .expect("decide")
    );

    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let row = sqlx::query("SELECT client_id, subject FROM grants WHERE id = $1")
        .bind(grant_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .expect("read grant")
        .expect("the grant must exist");
    assert_eq!(row.get::<String, _>("client_id"), "cli_owner");
    assert_eq!(row.get::<String, _>("subject"), "usr_ada");
}

/// A REFUSED decision opens no grant.
///
/// This is what makes the single transaction load-bearing rather than incidental. The grant
/// is inserted BEFORE the decision statement (the composite foreign key demands that order),
/// so if the decision then matches nothing the transaction must be dropped rather than
/// committed -- otherwise every rejected approval attempt would leave a live grant behind,
/// and a grant is exactly what a token hangs off.
#[tokio::test]
async fn a_refused_decision_leaves_no_grant_behind() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (_digest, id) = create_pending_with_id(&db, &env, scope, "cli_owner", "usr_ada").await;
    let grant_id = ironauth_store::GrantId::generate(&env, &scope);

    // The WRONG subject: the decision matches no row.
    assert!(
        !db.store()
            .scoped(scope)
            .backchannel_auth()
            .decide(
                &env,
                &id,
                "usr_grace",
                true,
                BackchannelApprovalLinkage {
                    grant_id: Some(&grant_id.to_string()),
                    consent_ref: None,
                    auth_methods: None,
                    auth_time_micros: None,
                },
                NOW_MICROS,
            )
            .await
            .expect("decide")
    );

    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let count: i64 = sqlx::query("SELECT count(*) FROM grants WHERE id = $1")
        .bind(grant_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .expect("count")
        .get(0);
    assert_eq!(
        count, 0,
        "a decision that did not happen must not leave a grant behind"
    );
}

/// The opened grant is what a redemption reports (#131 criterion 5).
///
/// Ties the two halves together: the grant the approval opened is the grant the client's
/// tokens will hang off, rather than a value that merely round-trips through a column.
#[tokio::test]
async fn the_opened_grant_is_the_one_redemption_reports() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, id) = create_pending_with_id(&db, &env, scope, "cli_owner", "usr_ada").await;
    let grant_id = ironauth_store::GrantId::generate(&env, &scope);
    let repo = db.store().scoped(scope);

    assert!(
        repo.backchannel_auth()
            .decide(
                &env,
                &id,
                "usr_ada",
                true,
                BackchannelApprovalLinkage {
                    grant_id: Some(&grant_id.to_string()),
                    consent_ref: None,
                    auth_methods: Some("pwd otp"),
                    auth_time_micros: Some(NOW_MICROS),
                },
                NOW_MICROS,
            )
            .await
            .expect("decide")
    );

    let redeemed = repo
        .backchannel_auth()
        .redeem(&digest, "cli_owner", NOW_MICROS)
        .await
        .expect("redeem")
        .expect("an approved request redeems");
    assert_eq!(
        redeemed.grant_id.as_deref(),
        Some(grant_id.to_string().as_str())
    );
    assert_eq!(redeemed.auth_methods.as_deref(), Some("pwd otp"));
    assert_eq!(redeemed.subject, "usr_ada");
}

/// Seed a grant row for `client`.
///
/// `issued_tokens.grant_id` has a foreign key to `grants`, so a token row cannot land without
/// one, and `redeem_approved` additionally requires the grant to BELONG to the presenting
/// client. Both are database-enforced rather than conventions, which is why recording the
/// tokens belongs in the redeeming transaction.
async fn seed_grant(db: &TestDatabase, scope: Scope, grant_id: &str, client: &str, subject: &str) {
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    sqlx::query(
        "INSERT INTO grants (id, tenant_id, environment_id, client_id, subject, created_at) \
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind(grant_id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(client)
    .bind(subject)
    .execute(&mut *tx)
    .await
    .expect("seed the grant");
    tx.commit().await.expect("commit");
}

/// How many issued-token rows and `token.issue` audit rows exist for `grant_id`.
///
/// Read back out of the database rather than inferred, because "recorded in the same
/// transaction as the flip" is the property this file exists to prove and an earlier version
/// of it asserted neither: review deleted the token-insert loop and the audit row in turn and
/// the suite stayed green.
async fn recorded_for(db: &TestDatabase, scope: Scope, grant_id: &str) -> (i64, i64) {
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let tokens: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issued_tokens WHERE grant_id = $1 AND tenant_id = $2 \
         AND environment_id = $3",
    )
    .bind(grant_id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *tx)
    .await
    .expect("count issued tokens");
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'token.issue' AND target_id = $1 \
         AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(grant_id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *tx)
    .await
    .expect("count audit rows");
    tx.commit().await.expect("commit");
    (tokens, audited)
}

/// Redeeming records the minted tokens in the SAME transaction as the flip, and does it at
/// most once (issue #131 criteria 2 and 3).
///
/// # Why this method had to exist before the token endpoint could
///
/// `redeem` consumes the request and returns its details, which is enough to mint FROM but
/// not enough to build the grant on. The device grant does two things this could not: it
/// mints BEFORE consuming, so a signing failure never burns an approval, and it records the
/// issued tokens in the same transaction as the flip, because a token that is issued and not
/// recorded cannot be revoked. Building the CIBA grant on `redeem` alone would have meant
/// either unrecorded tokens or a second transaction that can fail independently, and both
/// look like a working deployment.
///
/// So the pair is `approved_details` (a non-consuming read, to mint from) and this.
///
/// Every claim below is asserted rather than described. An earlier version of this comment
/// said it asserted the token row and did not: review deleted the whole token-insert loop,
/// and separately the audit row, and the suite stayed green at 26 passed. Both are the
/// properties this method exists for, so both are now read back out of the database.
#[tokio::test]
async fn redeeming_records_its_tokens_atomically_and_only_once() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let token_id = ironauth_store::IssuedTokenId::generate(&env, &scope);

    // The details are readable WITHOUT consuming: that is what lets the grant mint first.
    let details = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .approved_details(&digest, "cli_owner", NOW_MICROS)
        .await
        .expect("read approved details")
        .expect("an approved request is readable before it is consumed");
    assert_eq!(details.subject, "usr_subject");

    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );

    let first = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &grant_id,
                tokens: &[ironauth_store::IssuedTokenRecord {
                    id: token_id,
                    kind: ironauth_store::TokenKind::Access,
                }],
                opaque: None,
            },
        )
        .await
        .expect("redeem with tokens");
    assert!(first, "an approved request redeems once");

    let second = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &grant_id,
                tokens: &[],
                opaque: None,
            },
        )
        .await
        .expect("second redeem");
    assert!(
        !second,
        "a second redemption flips nothing: the auth_req_id is single-use"
    );

    let (tokens, audited) = recorded_for(&db, scope, &grant_id.to_string()).await;
    assert_eq!(
        tokens, 1,
        "the redemption must record the token it was handed, in the same transaction as the \
         flip: a token that is issued and not recorded cannot be revoked"
    );
    assert_eq!(audited, 1, "the issuance must be audited exactly once");
}

/// A redemption whose token rows fail leaves the approval intact (issue #131).
///
/// This is what "atomic" has to mean here, and it is why the recording lives in the redeeming
/// transaction rather than beside it. The user approved on a separate device; a failure after
/// the flip that consumed the request anyway would make them approve again for a fault that
/// was ours.
///
/// The failure is real rather than simulated, and lands MID-BATCH: two token records share
/// one id, so the first row lands and the second violates the primary key, after the flip has
/// already happened inside the same transaction. An earlier version used an unseeded grant,
/// which the ownership check now refuses before the insert is ever reached: the test would
/// have kept passing for a reason that had nothing to do with atomicity.
#[tokio::test]
async fn a_failed_token_insert_rolls_the_flip_back_and_leaves_the_request_redeemable() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    // ONE ID, TWO RECORDS: the first row lands, the second violates the primary key.
    let duplicate = ironauth_store::IssuedTokenId::generate(&env, &scope);

    let failed = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &grant_id,
                tokens: &[
                    ironauth_store::IssuedTokenRecord {
                        id: duplicate,
                        kind: ironauth_store::TokenKind::Access,
                    },
                    ironauth_store::IssuedTokenRecord {
                        id: duplicate,
                        kind: ironauth_store::TokenKind::Id,
                    },
                ],
                opaque: None,
            },
        )
        .await;
    assert!(
        failed.is_err(),
        "a token row that cannot land must fail the redemption"
    );

    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .approved_details(&digest, "cli_owner", NOW_MICROS)
            .await
            .expect("read")
            .is_some(),
        "the flip must roll back with the failed insert, or the user approves again on their \
         other device for a failure that was ours"
    );

    // AND THE ROW THAT DID LAND rolled back with it: a partial batch would leave live tokens
    // against a request the store still thinks is approved.
    let (tokens, audited) = recorded_for(&db, scope, &grant_id.to_string()).await;
    assert_eq!(
        (tokens, audited),
        (0, 0),
        "the first token row landed before the failure and must roll back with the flip"
    );
}

/// Neither new method answers for ANOTHER CLIENT (issue #131 criterion 3).
///
/// The pre-existing cases cover `redeem`. These two methods are their own surface and were
/// untested, which review demonstrated by deleting each filter in turn with the suite green.
/// A wrong client gets the SAME answer as an absent request, so neither is an existence
/// oracle.
///
/// # The fixture detail that makes this measure anything
///
/// `cli_other` is given its OWN valid grant for the same user. That way the ownership
/// predicate ACCEPTS what it presents and the flip's `client_id` filter is the only thing
/// left that can refuse. Handing `cli_other` the owner's grant instead makes the ownership
/// predicate refuse one step later, the call returns `Err`, and `.expect("redeem")` panics
/// before the assertion runs: measured, that is exactly how the first version of this test
/// died, so the assertion naming the client was asserting nothing.
#[tokio::test]
async fn the_new_readers_refuse_another_client() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let others_grant = ironauth_store::GrantId::generate(&env, &scope);
    seed_grant(
        &db,
        scope,
        &others_grant.to_string(),
        "cli_other",
        "usr_subject",
    )
    .await;

    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .approved_details(&digest, "cli_other", NOW_MICROS)
            .await
            .expect("read")
            .is_none(),
        "another client's request must read as absent"
    );
    assert!(
        !db.store()
            .scoped(scope)
            .backchannel_auth()
            .redeem_approved(
                &env,
                &acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: &digest,
                    presenting_client_id: "cli_other",
                    now_micros: NOW_MICROS,
                    grant_id: &others_grant,
                    tokens: &[],
                    opaque: None,
                },
            )
            .await
            .expect("redeem"),
        "another client must not redeem it"
    );

    assert_owner_can_still_read_and_redeem(&db, &env, scope, &acting, &digest, &grant_id).await;
}

/// Neither new method answers AFTER EXPIRY (issue #131 criterion 3).
#[tokio::test]
async fn the_new_readers_refuse_an_expired_request() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let past_expiry = FAR_FUTURE_MICROS + 1;

    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .approved_details(&digest, "cli_owner", past_expiry)
            .await
            .expect("read")
            .is_none(),
        "an expired request is not readable"
    );
    assert!(
        !db.store()
            .scoped(scope)
            .backchannel_auth()
            .redeem_approved(
                &env,
                &acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: &digest,
                    presenting_client_id: "cli_owner",
                    now_micros: past_expiry,
                    grant_id: &grant_id,
                    tokens: &[],
                    opaque: None,
                },
            )
            .await
            .expect("redeem"),
        "an expired request is not redeemable"
    );

    assert_owner_can_still_read_and_redeem(&db, &env, scope, &acting, &digest, &grant_id).await;
}

/// The positive control both refusal tests need: the owner, in time, still reads AND redeems.
///
/// Without the REDEMPTION half a fixture that could never redeem passes every negative above.
/// It runs last because it consumes the request.
async fn assert_owner_can_still_read_and_redeem(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    acting: &ironauth_store::ActingContext,
    digest: &str,
    grant_id: &ironauth_store::GrantId,
) {
    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .approved_details(digest, "cli_owner", NOW_MICROS)
            .await
            .expect("read")
            .is_some(),
        "the owning client still reads it"
    );
    // The SPINE grant, not a fresh one. An earlier version of this control invented a grant
    // the approval never opened and redeemed against it, which only worked because a NULL
    // spine accepted anything: review pointed out the control depended on the very
    // permissiveness the neighbouring tests exist to refuse.
    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .redeem_approved(
                env,
                acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: digest,
                    presenting_client_id: "cli_owner",
                    now_micros: NOW_MICROS,
                    grant_id,
                    tokens: &[],
                    opaque: None,
                },
            )
            .await
            .expect("redeem"),
        "the owning client, in time, still redeems it, so the refusals are about the client \
         and the clock rather than about a fixture that could never redeem"
    );
}

/// The tokens hang off the grant the APPROVAL opened, not one the caller names (issue #131).
///
/// # The failure this refuses
///
/// `backchannel_authentication_requests.grant_id` is the revocation spine: `decide` opens it
/// in the approving transaction, and the issued tokens are supposed to hang off it so that
/// revoking the grant revokes them. `redeem_approved` takes a grant from its caller, and
/// review demonstrated redeeming with an unrelated grant owned by a DIFFERENT client: the
/// tokens landed under that grant, none under the spine, and the audit row named the wrong
/// one. Revoking the CIBA grant then revoked nothing, and the issuance was mis-attributed.
///
/// Naming the fields in a struct does not prevent that. Comparing them does, and the row
/// being flipped already carries the answer, so it is checked rather than trusted.
///
/// # Why the wrong grant here belongs to the SAME client
///
/// A grant owned by someone else is refused one guard earlier, by the ownership predicate, so
/// a fixture using one would pass with the spine comparison DELETED. Measured: disabling the
/// comparison left this suite green until the grant below was seeded to `cli_owner`.
///
/// Same-client confusion is the harm ownership cannot reach. One client holding two grants
/// that redeems against the wrong one attaches the tokens to a grant the CIBA revocation
/// spine does not name, so revoking the CIBA grant reaches none of them, and both grants pass
/// every ownership test that could be written. Only the spine says which one the user
/// actually approved.
#[tokio::test]
async fn redeeming_against_a_grant_the_approval_did_not_open_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, id) = create_pending_with_id(&db, &env, scope, "cli_owner", "usr_ada").await;
    let opened = ironauth_store::GrantId::generate(&env, &scope);
    let unrelated = ironauth_store::GrantId::generate(&env, &scope);
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );

    db.store()
        .scoped(scope)
        .backchannel_auth()
        .decide(
            &env,
            &id,
            "usr_ada",
            true,
            BackchannelApprovalLinkage {
                grant_id: Some(&opened.to_string()),
                consent_ref: None,
                auth_methods: Some("pwd"),
                auth_time_micros: Some(NOW_MICROS),
            },
            NOW_MICROS,
        )
        .await
        .expect("approve with a grant");

    // A REAL grant, owned by the SAME client, so the ownership predicate accepts it and the
    // spine comparison is the only thing left that can refuse it.
    seed_grant(&db, scope, &unrelated.to_string(), "cli_owner", "usr_ada").await;

    let wrong = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &unrelated,
                tokens: &[],
                opaque: None,
            },
        )
        .await;
    assert!(
        wrong.is_err(),
        "a grant the approval did not open must be refused, or the tokens hang off something \
         revoking the CIBA grant will never reach"
    );

    // AND THE REQUEST SURVIVES THE REFUSAL, so a caller passing the wrong grant has not
    // burned an approval the user gave on another device.
    let right = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &opened,
                tokens: &[],
                opaque: None,
            },
        )
        .await
        .expect("redeem with the opened grant");
    assert!(
        right,
        "the grant the approval opened still redeems: the check is about WHICH grant, not a \
         fixture that was never redeemable"
    );
}

/// A request approved with NO grant still cannot mint against another client's grant
/// (issue #131).
///
/// # The branch this closes
///
/// Comparing the caller's grant against the request's spine only bites when there IS a spine.
/// `decide` may open none, which is what `BackchannelApprovalLinkage::default()` does and
/// what most of this file's fixtures use, and in that branch any grant the caller named was
/// accepted, including one belonging to a different client. The tokens and the audit row
/// landed against it, so revoking the CIBA grant reached nothing and the issuance was
/// attributed to the wrong client. Same harm as the linked case, through the default path.
///
/// The guard is that the grant must BELONG to the presenting client, which closes both
/// An approval that opened NO grant is not redeemable at all (issue #131).
///
/// # Why this replaces four rounds of patching
///
/// This test used to assert something narrower: that a request approved with no grant could
/// not mint against ANOTHER CLIENT's grant. It passed, and it was the wrong shape, because
/// each round of review found one more thing the NULL-spine branch still admitted. Round 2
/// closed cross-client. Round 3 closed cross-subject. Round 4 then showed a caller could
/// still present any live grant of the same client and user and have the tokens inherit its
/// `claims_request`, `granted_resources` and `org_id` from an unrelated flow, while the
/// request kept `grant_id NULL` and nothing linked the issued tokens to the `auth_req_id`.
///
/// The branch is gone. A CIBA approval with no grant has nothing for tokens to hang off and
/// nothing for a revocation to reach, so redemption refuses it outright and there is no
/// dimension left to patch.
#[tokio::test]
async fn an_approval_that_opened_no_grant_is_not_redeemable() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let digest = seed_approved_with_grant(&db, &env, scope, "cli_owner", None).await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );

    // A grant that is beyond reproach on every dimension the earlier rounds added: right
    // client, right subject, live, in scope. It is still refused, because the approval did
    // not open it.
    let impeccable = ironauth_store::GrantId::generate(&env, &scope);
    seed_grant(
        &db,
        scope,
        &impeccable.to_string(),
        "cli_owner",
        "usr_subject",
    )
    .await;

    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .redeem_approved(
                &env,
                &acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: &digest,
                    presenting_client_id: "cli_owner",
                    now_micros: NOW_MICROS,
                    grant_id: &impeccable,
                    tokens: &[ironauth_store::IssuedTokenRecord {
                        id: ironauth_store::IssuedTokenId::generate(&env, &scope),
                        kind: ironauth_store::TokenKind::Access,
                    }],
                    opaque: None,
                },
            )
            .await
            .is_err(),
        "an approval that opened no grant must not be redeemable, whatever grant is presented"
    );
    assert_eq!(
        recorded_for(&db, scope, &impeccable.to_string()).await,
        (0, 0),
        "and nothing is recorded against the grant it was offered"
    );

    // POSITIVE CONTROL: the identical request WITH a linked grant redeems, so the refusal is
    // about the missing spine and not about the rest of the fixture.
    let (linked, spine) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .redeem_approved(
                &env,
                &acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: &linked,
                    presenting_client_id: "cli_owner",
                    now_micros: NOW_MICROS,
                    grant_id: &spine,
                    tokens: &[],
                    opaque: None,
                },
            )
            .await
            .expect("redeem the linked request"),
        "the same shape with a spine redeems"
    );
}

/// The opaque branch runs, keeps every audience, and keeps the `DPoP` binding (issue #131).
///
/// # Why this test exists
///
/// Every other case in this file passes `opaque: None`, so the opaque INSERT was never
/// executed once: it could have been renumbered wrongly, or dropped a column, and the suite
/// would not have noticed. Review caught that the rewrite from ten binds to twelve was
/// unexercised.
///
/// The two columns it asserts are the ones whose absence is silent rather than loud. A NULL
/// `audiences` makes the resolver fall back to the single `audience`, so a multi-audience
/// token INTROSPECTS NARROWER than it was issued. A NULL `dpop_jkt` reads back as "not key
/// bound", so a sender-constrained token degrades to a bearer token that anyone holding it
/// can replay. Neither fails anything at issuance.
#[tokio::test]
async fn an_opaque_token_keeps_its_audiences_and_its_dpop_binding() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );

    let audiences = vec![
        "https://api.one.test".to_string(),
        "https://api.two.test".to_string(),
    ];
    let jti = ironauth_store::IssuedTokenId::generate(&env, &scope);
    let redeemed = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &grant_id,
                tokens: &[],
                opaque: Some(ironauth_store::NewOpaqueAccessToken {
                    token_digest: "digest-of-the-opaque-token",
                    grant_id: None,
                    subject: "usr_subject",
                    client_id: "cli_owner",
                    audience: "https://api.one.test",
                    audiences: &audiences,
                    scope: Some("openid"),
                    jti: &jti,
                    expires_at_unix_micros: FAR_FUTURE_MICROS,
                    dpop_jkt: Some("thumbprint-of-the-clients-key"),
                }),
            },
        )
        .await
        .expect("redeem with an opaque token");
    assert!(redeemed, "the redemption flips");

    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let row = sqlx::query(
        "SELECT audiences, dpop_jkt, grant_id FROM opaque_access_tokens \
         WHERE token_digest = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind("digest-of-the-opaque-token")
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *tx)
    .await
    .expect("the opaque row landed");
    let stored_audiences: Option<String> = row.get("audiences");
    let stored_jkt: Option<String> = row.get("dpop_jkt");
    let stored_grant: String = row.get("grant_id");
    tx.commit().await.expect("commit");

    // The column is `text` holding a JSON array (migration 0019), so compare the PARSED
    // value: asserting on the raw string would also be asserting serde's spacing.
    let parsed: Option<serde_json::Value> = stored_audiences
        .as_deref()
        .map(|raw| serde_json::from_str(raw).expect("the stored audiences parse as JSON"));
    assert_eq!(
        parsed,
        Some(serde_json::json!([
            "https://api.one.test",
            "https://api.two.test"
        ])),
        "every audience must be stored, or the token introspects narrower than it was issued"
    );
    assert_eq!(
        stored_jkt.as_deref(),
        Some("thumbprint-of-the-clients-key"),
        "the DPoP thumbprint must be stored, or a sender-constrained token degrades to bearer"
    );
    assert_eq!(
        stored_grant,
        grant_id.to_string(),
        "the row hangs off the redemption's grant, not the one the caller put in the struct"
    );
}

/// A token identifier minted in ANOTHER scope is refused (issue #131).
///
/// The device grant already guards this and this did not. Untested until review pointed out
/// that disabling the guard left the suite green.
#[tokio::test]
async fn a_token_id_from_another_scope_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );

    let foreign = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &grant_id,
                tokens: &[ironauth_store::IssuedTokenRecord {
                    id: ironauth_store::IssuedTokenId::generate(&env, &elsewhere),
                    kind: ironauth_store::TokenKind::Access,
                }],
                opaque: None,
            },
        )
        .await;
    assert!(
        foreign.is_err(),
        "a token id minted under another scope must not be written into this one"
    );
    let (tokens, _) = recorded_for(&db, scope, &grant_id.to_string()).await;
    assert_eq!(tokens, 0, "and nothing lands");

    // AND THE APPROVAL SURVIVES. The shipped code rolls back because the `Err` drops the
    // transaction, but nothing asserted it: review committed before this refusal and the
    // suite stayed green. A refusal that burned the approval would make the user re-approve
    // on their separate device for a fault that was entirely ours.
    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .approved_details(&digest, "cli_owner", NOW_MICROS)
            .await
            .expect("read")
            .is_some(),
        "the refusal must not have consumed the approval"
    );
}

/// A CIBA-issued token is a COUNTED token (issue #131).
///
/// # Why this is here and not left to the token endpoint
///
/// `token.issued` had exactly one producer, in the authorization-code `redeem`. Tokens minted
/// through the device grant and tokens minted here were never counted, so `tokens_issued`
/// under-reports by exactly those tokens, and it under-reports SILENTLY: the metering fold
/// sums whatever rows it is handed, and a producer that never fires is indistinguishable from
/// a tenant that never issued anything.
///
/// The assertion reads the OUTBOX rather than appending envelopes and counting them back, so
/// it measures the producer being wired rather than the fold's arithmetic. Deleting the emit
/// loop must turn this red.
#[tokio::test]
async fn every_redeemed_token_is_metered_in_the_same_transaction() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );

    let before = metering_events_for(&db, scope, &grant_id.to_string()).await;
    assert_eq!(before, 0, "the fixture enqueues none of its own");

    db.store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &grant_id,
                tokens: &[
                    ironauth_store::IssuedTokenRecord {
                        id: ironauth_store::IssuedTokenId::generate(&env, &scope),
                        kind: ironauth_store::TokenKind::Access,
                    },
                    ironauth_store::IssuedTokenRecord {
                        id: ironauth_store::IssuedTokenId::generate(&env, &scope),
                        kind: ironauth_store::TokenKind::Id,
                    },
                ],
                opaque: None,
            },
        )
        .await
        .expect("redeem");

    assert_eq!(
        metering_events_for(&db, scope, &grant_id.to_string()).await,
        2,
        "one metering event per issued token, or usage under-reports CIBA issuance"
    );
}

/// Count enqueued `token.issued` metering events for one grant.
///
/// Reads `outbox_messages` directly: the point is that the PRODUCER fired, and a helper that
/// went through the metering fold would pass just as happily on seeded envelopes.
async fn metering_events_for(db: &TestDatabase, scope: ironauth_store::Scope, grant: &str) -> i64 {
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 \
           AND payload->>'type' = 'token.issued' \
           AND payload->'payload'->>'grant_id' = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(grant)
    .fetch_one(&mut *tx)
    .await
    .expect("count metering events");
    tx.commit().await.expect("commit");
    count
}

/// Seed a grant, optionally already revoked.
async fn seed_grant_revoked(db: &TestDatabase, scope: Scope, grant_id: &str, client: &str) {
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    sqlx::query(
        "INSERT INTO grants (id, tenant_id, environment_id, client_id, subject, created_at, \
          revoked_at) \
         VALUES ($1, $2, $3, $4, $5, now(), now())",
    )
    .bind(grant_id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(client)
    .bind("usr_subject")
    .execute(&mut *tx)
    .await
    .expect("seed a revoked grant");
    tx.commit().await.expect("commit");
}

/// A grant belonging to ANOTHER USER of the same client is refused (issue #131).
///
/// # Why this is the worst of the grant confusions
///
/// The other cases mis-attribute an issuance. This one changes WHO THE TOKEN IS.
/// `resolve_access_token` joins `grants` and returns the GRANT'S subject, and `UserInfo` answers
/// from it, so a token hung off another user's grant authenticates as that other user.
///
/// It survived two rounds of review because both earlier guards were about the client. The
/// approval linked no grant, which is what `BackchannelApprovalLinkage::default()` does, so
/// the spine comparison was skipped; the grant belonged to the right client, so the ownership
/// predicate passed. Nothing looked at the subject. Measured before the fix: the redemption
/// A spine pointing at ANOTHER USER's grant is refused (issue #131).
///
/// # Why the ownership predicate still earns its place
///
/// With the spine required, the caller can no longer choose the grant: it must equal the one
/// the approval opened. So this guard is now about a MISLINKED spine, which is a real failure
/// (a buggy or compromised approval surface calling `decide` with the wrong grant) and the
/// one with the worst consequence.
///
/// `resolve_access_token` joins `grants` and returns the GRANT'S subject, and `UserInfo`
/// answers from it. A token hung off another user's grant does not merely mis-attribute an
/// issuance: it AUTHENTICATES AS THAT USER. Review demonstrated exactly that before the
/// subject predicate existed, resolving the resulting token as `usr_victim`.
#[tokio::test]
async fn a_spine_pointing_at_another_users_grant_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );

    // Same client, DIFFERENT user, and the approval is linked to it. Only the subject differs
    // from a good fixture, so only the subject predicate can refuse it.
    let victims = ironauth_store::GrantId::generate(&env, &scope);
    seed_grant(&db, scope, &victims.to_string(), "cli_owner", "usr_victim").await;
    let digest =
        seed_approved_with_grant(&db, &env, scope, "cli_owner", Some(&victims.to_string())).await;

    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .redeem_approved(
                &env,
                &acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: &digest,
                    presenting_client_id: "cli_owner",
                    now_micros: NOW_MICROS,
                    grant_id: &victims,
                    tokens: &[ironauth_store::IssuedTokenRecord {
                        id: ironauth_store::IssuedTokenId::generate(&env, &scope),
                        kind: ironauth_store::TokenKind::Access,
                    }],
                    opaque: None,
                },
            )
            .await
            .is_err(),
        "a grant belonging to another user must be refused, or the token authenticates as \
         that user"
    );
    assert_eq!(
        recorded_for(&db, scope, &victims.to_string()).await,
        (0, 0),
        "and nothing is recorded against the victim's grant"
    );

    // POSITIVE CONTROL: the same shape whose spine names the REQUEST's own subject redeems.
    let (good, spine) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .redeem_approved(
                &env,
                &acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: &good,
                    presenting_client_id: "cli_owner",
                    now_micros: NOW_MICROS,
                    grant_id: &spine,
                    tokens: &[],
                    opaque: None,
                },
            )
            .await
            .expect("redeem"),
        "the approving user's own grant still redeems"
    );
}

/// A REVOKED grant is refused BEFORE the flip (issue #131).
///
/// Accepting one commits the flip and hands back tokens that `resolve_access_token` reports
/// inactive. That burns an approval the user gave on a separate device, for a fault entirely
/// ours, which is the exact harm this file's atomicity argument exists to prevent. The
/// A REVOKED spine grant is refused, and the approval is not consumed (issue #131).
///
/// Accepting one commits the flip and hands back tokens that `resolve_access_token` reports
/// inactive. The client gets dead tokens, and the user has to approve again on their separate
/// device for a fault that is entirely ours. That is the exact harm this file's atomicity
/// argument exists to prevent, so the refusal has to happen BEFORE the flip.
#[tokio::test]
async fn a_revoked_spine_grant_is_refused_and_the_approval_is_not_consumed() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let dead = ironauth_store::GrantId::generate(&env, &scope);
    seed_grant_revoked(&db, scope, &dead.to_string(), "cli_owner").await;
    let digest =
        seed_approved_with_grant(&db, &env, scope, "cli_owner", Some(&dead.to_string())).await;

    // A SECOND grant, live, same client, same subject. It exists so that the predicate's
    // `id = $1` term is load-bearing here: without this row, neutralising `id = $1` still
    // finds nothing and the refusal happens anyway, which is how review measured that term
    // surviving mutation. With it, a predicate that forgot WHICH grant would accept this
    // redemption and the test goes red.
    let other_live = ironauth_store::GrantId::generate(&env, &scope);
    seed_grant(
        &db,
        scope,
        &other_live.to_string(),
        "cli_owner",
        "usr_subject",
    )
    .await;

    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .redeem_approved(
                &env,
                &acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: &digest,
                    presenting_client_id: "cli_owner",
                    now_micros: NOW_MICROS,
                    grant_id: &dead,
                    tokens: &[],
                    opaque: None,
                },
            )
            .await
            .is_err(),
        "a revoked grant must be refused"
    );

    // THE APPROVAL SURVIVES. It cannot be redeemed against this grant ever again, but it must
    // still READ as approved: the request was not consumed by our refusal, so an operator who
    // repairs the grant linkage has something left to repair.
    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .approved_details(&digest, "cli_owner", NOW_MICROS)
            .await
            .expect("read")
            .is_some(),
        "the refusal must not have consumed the approval"
    );
}

/// The opaque row's identity columns are the redemption's, not the caller's (issue #131).
///
/// `subject` and `client_id` are handed back verbatim by `resolve_opaque_access_token` to RFC
/// 7662 introspection. Both arrived as caller input, and review landed a row reading
/// `subject = usr_victim`, `client_id = cli_someone_else` through a redemption that returned
/// `Ok`, so a resource server trusting introspection saw a token owned by another client for
/// another user.
///
/// A mismatch is REFUSED rather than silently overwritten: binding the right values over a
/// caller's wrong ones stores a correct row and leaves the caller believing it wrote a
/// different one.
#[tokio::test]
async fn an_opaque_token_claiming_another_identity_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let audiences = vec!["https://api.one.test".to_string()];

    for (subject, client, why) in [
        (
            "usr_victim",
            "cli_owner",
            "a subject the approval did not name",
        ),
        (
            "usr_subject",
            "cli_someone_else",
            "a client that is not presenting",
        ),
    ] {
        let jti = ironauth_store::IssuedTokenId::generate(&env, &scope);
        let refused = db
            .store()
            .scoped(scope)
            .backchannel_auth()
            .redeem_approved(
                &env,
                &acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: &digest,
                    presenting_client_id: "cli_owner",
                    now_micros: NOW_MICROS,
                    grant_id: &grant_id,
                    tokens: &[],
                    opaque: Some(ironauth_store::NewOpaqueAccessToken {
                        token_digest: "digest-of-the-opaque-token",
                        grant_id: None,
                        subject,
                        client_id: client,
                        audience: "https://api.one.test",
                        audiences: &audiences,
                        scope: Some("openid"),
                        jti: &jti,
                        expires_at_unix_micros: FAR_FUTURE_MICROS,
                        dpop_jkt: None,
                    }),
                },
            )
            .await;
        assert!(refused.is_err(), "{why} must be refused");
        assert_eq!(
            opaque_rows_for(&db, scope, "digest-of-the-opaque-token").await,
            0,
            "and no opaque row lands for {why}"
        );
    }
}

/// A foreign-scope OPAQUE jti is refused, as the authorization-code redeem already refuses it.
///
/// An earlier round guarded only `tokens` and claimed parity with the sibling, which guards
/// the opaque jti too. Review landed a row in this scope carrying another environment's `tok_`
/// id, which introspection then reports as the token's `jti`. `opaque_access_tokens` is UNIQUE
/// on (tenant, environment, jti), so the database catches nothing.
#[tokio::test]
async fn a_foreign_scope_opaque_jti_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let audiences = vec!["https://api.one.test".to_string()];
    let foreign_jti = ironauth_store::IssuedTokenId::generate(&env, &elsewhere);

    let refused = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &grant_id,
                tokens: &[],
                opaque: Some(ironauth_store::NewOpaqueAccessToken {
                    token_digest: "digest-of-the-foreign-token",
                    grant_id: None,
                    subject: "usr_subject",
                    client_id: "cli_owner",
                    audience: "https://api.one.test",
                    audiences: &audiences,
                    scope: Some("openid"),
                    jti: &foreign_jti,
                    expires_at_unix_micros: FAR_FUTURE_MICROS,
                    dpop_jkt: None,
                }),
            },
        )
        .await;
    assert!(
        refused.is_err(),
        "an opaque jti minted under another scope must not be written into this one"
    );
    assert_eq!(
        opaque_rows_for(&db, scope, "digest-of-the-foreign-token").await,
        0,
        "and nothing lands"
    );
}

/// Every issued token is metered, including the opaque one (issue #131).
///
/// An opaque access token produces NO `IssuedTokenRecord`, so a metering loop over `tokens`
/// alone never counts it.
///
/// The PRODUCTION shape is the first case here. An earlier version of this test used
/// `tokens: &[]`, and its comment claimed both production builders pass an empty record list.
/// Review measured that as false: `token.rs:420` and `device.rs:458` both push the ID token
/// first, so the real shape is `[Id]` plus an opaque token, two tokens and two events, and
/// the under-count was one event rather than all of them. The empty case is kept as the
/// boundary, not as the representative one.
#[tokio::test]
async fn every_issued_token_is_metered_including_the_opaque_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let audiences = vec!["https://api.one.test".to_string()];
    let jti = ironauth_store::IssuedTokenId::generate(&env, &scope);

    db.store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &grant_id,
                // EMPTY, which is what the production builders pass for an opaque token.
                tokens: &[],
                opaque: Some(ironauth_store::NewOpaqueAccessToken {
                    token_digest: "digest-of-the-only-token",
                    grant_id: None,
                    subject: "usr_subject",
                    client_id: "cli_owner",
                    audience: "https://api.one.test",
                    audiences: &audiences,
                    scope: Some("openid"),
                    jti: &jti,
                    expires_at_unix_micros: FAR_FUTURE_MICROS,
                    dpop_jkt: None,
                }),
            },
        )
        .await
        .expect("redeem");

    assert_eq!(
        metering_events_for(&db, scope, &grant_id.to_string()).await,
        1,
        "an opaque access token is one issued token and must be counted as one"
    );

    // AND THE PRODUCTION SHAPE: an ID token record alongside the opaque access token, which
    // is what `token.rs:420` and `device.rs:458` actually build. Two tokens, two events.
    let (prod_digest, prod_grant) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let prod_jti = ironauth_store::IssuedTokenId::generate(&env, &scope);
    db.store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &prod_digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &prod_grant,
                tokens: &[ironauth_store::IssuedTokenRecord {
                    id: ironauth_store::IssuedTokenId::generate(&env, &scope),
                    kind: ironauth_store::TokenKind::Id,
                }],
                opaque: Some(ironauth_store::NewOpaqueAccessToken {
                    token_digest: "digest-production-shape",
                    grant_id: None,
                    subject: "usr_subject",
                    client_id: "cli_owner",
                    audience: "https://api.one.test",
                    audiences: &audiences,
                    scope: Some("openid"),
                    jti: &prod_jti,
                    expires_at_unix_micros: FAR_FUTURE_MICROS,
                    dpop_jkt: None,
                }),
            },
        )
        .await
        .expect("redeem the production shape");
    assert_eq!(
        metering_events_for(&db, scope, &prod_grant.to_string()).await,
        2,
        "an ID token plus an opaque access token is two issued tokens and two events"
    );
}

/// `approved_details` answers only for an APPROVED request (issue #131).
///
/// The `status = 'approved'` filter is the whole point of the method, and it was measured
/// SURVIVING: neutralising it left the suite green because all five call sites used an
/// approved fixture. If it regresses, a client reads the subject, requested scope and
/// `authorization_details` of a request the user has not approved, or has explicitly denied.
#[tokio::test]
async fn approved_details_refuses_pending_denied_and_redeemed_requests() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let repo = || db.store().scoped(scope);

    // PENDING: created, nobody has decided.
    let (pending, _) = create_pending_nonce(&db, &env, scope, "cli_owner", "usr_ada", 1).await;
    assert!(
        repo()
            .backchannel_auth()
            .approved_details(&pending, "cli_owner", NOW_MICROS)
            .await
            .expect("read")
            .is_none(),
        "a pending request must not be readable, or the token endpoint mints before the \
         user has answered"
    );

    // DENIED: the user said no.
    let (denied, denied_id) =
        create_pending_nonce(&db, &env, scope, "cli_owner", "usr_ada", 2).await;
    repo()
        .backchannel_auth()
        .decide(
            &env,
            &denied_id,
            "usr_ada",
            false,
            BackchannelApprovalLinkage::default(),
            NOW_MICROS,
        )
        .await
        .expect("deny");
    assert!(
        repo()
            .backchannel_auth()
            .approved_details(&denied, "cli_owner", NOW_MICROS)
            .await
            .expect("read")
            .is_none(),
        "a denied request must not be readable, or a refusal mints tokens"
    );

    // REDEEMED: already consumed. Positive control first, so the transition is visible.
    let (redeemed, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    assert!(
        repo()
            .backchannel_auth()
            .approved_details(&redeemed, "cli_owner", NOW_MICROS)
            .await
            .expect("read")
            .is_some(),
        "an approved request IS readable, so the refusals above are about status"
    );
    repo()
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &redeemed,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &grant_id,
                tokens: &[],
                opaque: None,
            },
        )
        .await
        .expect("redeem");
    assert!(
        repo()
            .backchannel_auth()
            .approved_details(&redeemed, "cli_owner", NOW_MICROS)
            .await
            .expect("read")
            .is_none(),
        "a redeemed request must not still read as approved"
    );
}

/// How many opaque rows exist for a token digest.
async fn opaque_rows_for(db: &TestDatabase, scope: Scope, digest: &str) -> i64 {
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM opaque_access_tokens \
         WHERE token_digest = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(digest)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *tx)
    .await
    .expect("count opaque rows");
    tx.commit().await.expect("commit");
    count
}

/// Neither new method reaches across scopes (issue #131).
///
/// # What this measures, and what it cannot
///
/// It measures the OUTCOME: a request created in one scope is not readable or redeemable
/// through a store scoped to another. It cannot attribute WHICH layer refused. Both methods
/// carry `tenant_id`/`environment_id` predicates, and both tables are `FORCE ROW LEVEL
/// SECURITY`, and `auth_req_id_digest` is a global primary key, so three mechanisms overlap
/// and neutralising the predicates alone leaves the suite green.
///
/// That survival was raised in review as the isolation doctrine's second layer being
/// unmeasured here. It is honest to say a test at this level cannot separate the layers: the
/// only thing that would is disabling RLS, which is a database-level property with its own
/// coverage. This asserts the property that actually matters to a tenant and says plainly
/// that it is backstopped.
#[tokio::test]
async fn neither_new_reader_reaches_across_scopes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let home = db.seed_scope(&env).await;
    let neighbour = db.seed_scope(&env).await;
    let (digest, home_grant) = seed_approved_linked(&db, &env, home, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );

    assert!(
        db.store()
            .scoped(neighbour)
            .backchannel_auth()
            .approved_details(&digest, "cli_owner", NOW_MICROS)
            .await
            .expect("read")
            .is_none(),
        "another scope's request must read as absent"
    );

    let grant_id = ironauth_store::GrantId::generate(&env, &neighbour);
    seed_grant(
        &db,
        neighbour,
        &grant_id.to_string(),
        "cli_owner",
        "usr_subject",
    )
    .await;
    assert!(
        !db.store()
            .scoped(neighbour)
            .backchannel_auth()
            .redeem_approved(
                &env,
                &acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: &digest,
                    presenting_client_id: "cli_owner",
                    now_micros: NOW_MICROS,
                    grant_id: &grant_id,
                    tokens: &[],
                    opaque: None,
                },
            )
            .await
            .expect("redeem"),
        "another scope's request must not be redeemable"
    );

    // AND IT IS STILL REDEEMABLE AT HOME, so the refusals above are about the scope rather
    // than about a request that was already consumed or was never valid.
    assert!(
        db.store()
            .scoped(home)
            .backchannel_auth()
            .redeem_approved(
                &env,
                &acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: &digest,
                    presenting_client_id: "cli_owner",
                    now_micros: NOW_MICROS,
                    grant_id: &home_grant,
                    tokens: &[],
                    opaque: None,
                },
            )
            .await
            .expect("redeem"),
        "the request is untouched in its own scope"
    );
}

/// The opaque row carries the REDEMPTION's identity, read back out of the database
/// (issue #131).
///
/// # Why reading it back matters
///
/// Round 4 refused a mismatched `subject` or `client_id` and bound the authoritative values.
/// Only the refusal was measured. Review showed the binding half was not: reverting
/// `.bind(subject)` to `.bind(op.subject)`, reverting the client the same way, doing both at
/// once, and TRANSPOSING the two arguments at the call site all left the suite green, because
/// no test ever read those two columns back.
///
/// The transposition is the sharp one. The helper took five adjacent `&str` parameters, so
/// swapping two of them compiled and wrote `subject = "cli_owner"`, `client_id = "usr_..."`
/// into the exact columns the round-4 blocker was about. That is now impossible by
/// construction (they are fields of `RedemptionIdentity`), and this test is the belt.
#[tokio::test]
async fn the_opaque_row_carries_the_redemptions_identity_and_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let audiences = vec!["https://api.one.test".to_string()];
    let jti = ironauth_store::IssuedTokenId::generate(&env, &scope);

    db.store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &grant_id,
                tokens: &[],
                opaque: Some(ironauth_store::NewOpaqueAccessToken {
                    token_digest: "digest-identity",
                    grant_id: None,
                    subject: "usr_subject",
                    client_id: "cli_owner",
                    audience: "https://api.one.test",
                    audiences: &audiences,
                    scope: Some("openid"),
                    jti: &jti,
                    expires_at_unix_micros: FAR_FUTURE_MICROS,
                    dpop_jkt: None,
                }),
            },
        )
        .await
        .expect("redeem");

    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let row = sqlx::query(
        "SELECT subject, client_id, scope FROM opaque_access_tokens \
         WHERE token_digest = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind("digest-identity")
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *tx)
    .await
    .expect("the opaque row landed");
    let subject: String = row.get("subject");
    let client_id: String = row.get("client_id");
    let stored_scope: Option<String> = row.get("scope");
    tx.commit().await.expect("commit");

    assert_eq!(
        subject, "usr_subject",
        "the subject column must hold the approval's subject"
    );
    assert_eq!(
        client_id, "cli_owner",
        "the client column must hold the presenting client, not the subject"
    );
    assert_eq!(
        stored_scope.as_deref(),
        Some("openid"),
        "the scope column must hold what was issued"
    );
}

/// An opaque token may not claim a WIDER scope than the approval carried (issue #131).
///
/// # The fourth column introspection reports verbatim
///
/// `resolve_opaque_access_token` returns `scope` and `introspection.rs` echoes it into the RFC
/// 7662 response, so a resource server authorises on it. Rounds 3 and 4 pinned the opaque
/// row's `subject`, `client_id` and grant, and left `scope` as pure caller input. Review
/// redeemed a request whose `requested_scope` was "openid profile" while presenting
/// "openid profile admin:everything payments:write", and introspection reported the wider set.
/// The user approved the narrower one.
///
/// CONTAINMENT, not equality: a grant may legitimately narrow what was asked for, so a subset
/// is correct and a superset never is.
#[tokio::test]
async fn an_opaque_token_may_not_widen_the_approved_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let audiences = vec!["https://api.one.test".to_string()];

    // The fixture's requested_scope is "openid profile".
    for (claimed, allowed, why) in [
        (
            Some("openid profile admin:everything"),
            false,
            "a scope the approval never carried",
        ),
        (
            Some("payments:write"),
            false,
            "a scope wholly outside the approval",
        ),
        (
            Some("profile openid"),
            true,
            "the same set in another order",
        ),
        (Some("openid"), true, "a narrower subset"),
        (None, true, "no scope at all"),
    ] {
        let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
        let jti = ironauth_store::IssuedTokenId::generate(&env, &scope);
        let token_digest = format!("digest-{}", claimed.unwrap_or("none").replace(' ', "-"));
        let outcome = db
            .store()
            .scoped(scope)
            .backchannel_auth()
            .redeem_approved(
                &env,
                &acting,
                ironauth_store::BackchannelRedemption {
                    auth_req_id_digest: &digest,
                    presenting_client_id: "cli_owner",
                    now_micros: NOW_MICROS,
                    grant_id: &grant_id,
                    tokens: &[],
                    opaque: Some(ironauth_store::NewOpaqueAccessToken {
                        token_digest: &token_digest,
                        grant_id: None,
                        subject: "usr_subject",
                        client_id: "cli_owner",
                        audience: "https://api.one.test",
                        audiences: &audiences,
                        scope: claimed,
                        jti: &jti,
                        expires_at_unix_micros: FAR_FUTURE_MICROS,
                        dpop_jkt: None,
                    }),
                },
            )
            .await;
        assert_eq!(
            outcome.is_ok(),
            allowed,
            "{why}: expected allowed={allowed}, got {outcome:?}"
        );
        assert_eq!(
            opaque_rows_for(&db, scope, &token_digest).await,
            i64::from(allowed),
            "{why}: the row must land only when the scope fits"
        );
    }
}

/// A grant named in the opaque struct that disagrees with the redemption is refused
/// (issue #131).
///
/// Review found this field being silently IGNORED while its two neighbours in the same struct
/// were refused on mismatch. That is a worse state than either rule alone: the row hung off
/// the right grant so nothing broke, and a caller that had resolved the wrong one was never
/// told. Consistency is the point.
#[tokio::test]
async fn an_opaque_struct_naming_a_different_grant_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let elsewhere = ironauth_store::GrantId::generate(&env, &scope);
    seed_grant(
        &db,
        scope,
        &elsewhere.to_string(),
        "cli_owner",
        "usr_subject",
    )
    .await;
    let audiences = vec!["https://api.one.test".to_string()];
    let jti = ironauth_store::IssuedTokenId::generate(&env, &scope);

    let refused = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            &env,
            &acting,
            ironauth_store::BackchannelRedemption {
                auth_req_id_digest: &digest,
                presenting_client_id: "cli_owner",
                now_micros: NOW_MICROS,
                grant_id: &grant_id,
                tokens: &[],
                opaque: Some(ironauth_store::NewOpaqueAccessToken {
                    token_digest: "digest-other-grant",
                    grant_id: Some(&elsewhere),
                    subject: "usr_subject",
                    client_id: "cli_owner",
                    audience: "https://api.one.test",
                    audiences: &audiences,
                    scope: Some("openid"),
                    jti: &jti,
                    expires_at_unix_micros: FAR_FUTURE_MICROS,
                    dpop_jkt: None,
                }),
            },
        )
        .await;
    assert!(
        refused.is_err(),
        "an opaque struct naming a grant the redemption did not verify must be refused"
    );
    assert_eq!(
        opaque_rows_for(&db, scope, "digest-other-grant").await,
        0,
        "and nothing lands"
    );
}
