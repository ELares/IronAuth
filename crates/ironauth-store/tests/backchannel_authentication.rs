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
    // 'redeemed' rather than 'approved': migration 0151 forbids an approved row with no
    // grant, and this fixture has none. The point of the assertion is that `status` is
    // WRITABLE by the data plane, which any legal value demonstrates.
    sqlx::query("UPDATE backchannel_authentication_requests SET status = 'redeemed'")
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

/// The linkage an APPROVAL must carry: a grant for the tokens to hang off.
///
/// `BackchannelApprovalLinkage::default()` leaves `grant_id` `None`, and `decide` now refuses
/// that when approving, because an approval with no grant is one redemption can never honour
/// and the user has already answered on their separate device. Denials still use `default()`:
/// a refusal has nothing to hang off.
fn approving_linkage(grant: &ironauth_store::GrantId) -> BackchannelApprovalLinkage<'_> {
    BackchannelApprovalLinkage {
        grant_id: Some(grant),
        consent_ref: None,
        auth_methods: None,
        auth_time_micros: None,
    }
}

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
    seed_approved_scoped(db, env, scope, client, grant_id, Some("openid profile")).await
}

/// The same, with explicit control over `requested_scope`, including a NULL one.
async fn seed_approved_scoped(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    client: &str,
    grant_id: Option<&str>,
    requested_scope: Option<&str>,
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
    .bind(requested_scope)
    .execute(&mut *tx)
    .await
    .expect("seed an approved request");
    tx.commit().await.expect("commit");
    digest
}

/// Seed an approved request with NO spine, by defeating the CHECK that forbids it.
///
/// Migration 0151 makes `status = 'approved' AND grant_id IS NULL` unrepresentable, which is
/// the point: it is the enforcement that survives a writer who has not read `decide`. It also
/// makes the shape unconstructible from a fixture, and three code guards exist precisely to
/// refuse it (`decide` will not create it, `approved_details` will not report it, `redeem`
/// will not consume it). Guards nothing can exercise are guards nothing measures, which is
/// the defect this whole PR has been about.
///
/// So the constraint is dropped, the row inserted, and the constraint restored `NOT VALID`,
/// which leaves the planted row in place while every future write is still checked. That is
/// not a contrivance: it is exactly the state a database would be in if the row predated the
/// constraint, which is the case the code guards are the last line against.
async fn seed_approved_without_a_spine(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    client: &str,
) -> String {
    const CONSTRAINT: &str = "backchannel_authentication_requests_approved_has_grant";
    sqlx::query(&format!(
        "ALTER TABLE backchannel_authentication_requests DROP CONSTRAINT {CONSTRAINT}"
    ))
    .execute(db.owner_pool())
    .await
    .expect("drop the check");
    let digest = seed_approved_scoped(db, env, scope, client, None, Some("openid profile")).await;
    sqlx::query(&format!(
        "ALTER TABLE backchannel_authentication_requests ADD CONSTRAINT {CONSTRAINT} \
         CHECK (status <> 'approved' OR grant_id IS NOT NULL) NOT VALID"
    ))
    .execute(db.owner_pool())
    .await
    .expect("restore the check");
    digest
}

/// An approved request redeems exactly once (#131 criterion 3, single-use).
#[tokio::test]
async fn an_approved_request_redeems_exactly_once() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, _grant) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
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
    let (digest, _grant) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
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
    let (digest, _grant) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
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

/// Create a pending request, returning its digest and id.
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
    // Every approval below must name a grant: `decide` refuses an approval whose linkage
    // carries none. These are NOT seeded, because `decide` INSERTs the grant itself; seeding
    // one first is a primary-key collision. One id per approval attempt, since a second
    // successful `decide` would collide on the first one's row.
    let decide_grant = ironauth_store::GrantId::generate(&env, &scope);
    let decide_grant_b = ironauth_store::GrantId::generate(&env, &scope);
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
            approving_linkage(&decide_grant),
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
            approving_linkage(&decide_grant_b),
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
    // Every approval below must name a grant: `decide` refuses an approval whose linkage
    // carries none. These are NOT seeded, because `decide` INSERTs the grant itself; seeding
    // one first is a primary-key collision. One id per approval attempt, since a second
    // successful `decide` would collide on the first one's row.
    let decide_grant = ironauth_store::GrantId::generate(&env, &scope);
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
                approving_linkage(&decide_grant),
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
    // Every approval below must name a grant: `decide` refuses an approval whose linkage
    // carries none. These are NOT seeded, because `decide` INSERTs the grant itself; seeding
    // one first is a primary-key collision. One id per approval attempt, since a second
    // successful `decide` would collide on the first one's row.
    let decide_grant = ironauth_store::GrantId::generate(&env, &scope);
    let decide_grant_b = ironauth_store::GrantId::generate(&env, &scope);
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
                approving_linkage(&decide_grant),
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
                approving_linkage(&decide_grant_b),
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
                    grant_id: Some(&grant_id),
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
                    grant_id: Some(&grant_id),
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
                    grant_id: Some(&grant_id),
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
    assert_eq!(redeemed.grant_id, grant_id);
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
                grant_id: Some(&opened),
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
    let digest = seed_approved_without_a_spine(&db, &env, scope, "cli_owner").await;
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

    // AND IT DOES NOT EVEN READ AS APPROVED. `decide` refuses to create this shape, so the row
    // here was written directly, which is the only way it can now arise: an operator or a
    // buggy data-plane write against a column the migration's GRANT list permits.
    //
    // Failing closed at the READ is what the device grant's sibling does
    // (`approved_device_outcome`: "an approved row missing its grant id is an inconsistent
    // state, so it fails closed rather than minting against no grant"). Without this
    // assertion the guard is unmeasured: review measured `AND grant_id IS NOT NULL` surviving
    // its removal, because every other fixture reaches this method through `decide`.
    // Matched on the whole Result rather than `.expect("read").is_none()`. With the predicate
    // disabled the row comes back and the explicit NULL refusal fires, so `.expect` panicked
    // before this assertion ran and the message naming the property never printed.
    let read = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .approved_details(&digest, "cli_owner", NOW_MICROS)
        .await;
    assert!(
        matches!(read, Ok(None)),
        "an approved row with no spine must not read as redeemable, or the token endpoint \
         mints first and discovers the problem afterwards. Got {read:?}"
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
                // EMPTY. This is the BOUNDARY case, not the production shape: both builders push the
                // ID token first, so the real list is `[Id]`. The production shape is asserted below.
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

/// A spine pointing at ANOTHER CLIENT's grant is refused (issue #131).
///
/// # Why this test had to come back
///
/// An earlier version of it lived on the NULL-spine path, and round 5 deleted that path and
/// rewrote this test into one whose grant is impeccable on every dimension INCLUDING the
/// client. That left `client_id = $4` as the only term of the ownership predicate with no
/// negative fixture, and review measured the consequence: neutralising it left the suite at
/// 44 passed. The guard was live and correct and nothing would have noticed it going away.
///
/// So this varies ONE dimension, the client, exactly as the sibling tests vary subject and
/// revocation. The spine names a grant belonging to `cli_other` for the SAME user, which is
/// the mislinked-spine case: `decide` cannot produce it (it inserts the grant with the client
/// read off the request row), but `backchannel_authentication_requests.grant_id` is in the
/// migration's column-scoped GRANT UPDATE list, so a compromised or buggy data-plane write
/// can repoint a spine at another client's grant. That is the failure the predicate names.
#[tokio::test]
async fn a_spine_pointing_at_another_clients_grant_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );

    // Another CLIENT, the same user, and the approval is linked to it.
    let theirs = ironauth_store::GrantId::generate(&env, &scope);
    seed_grant(&db, scope, &theirs.to_string(), "cli_other", "usr_subject").await;
    let digest =
        seed_approved_with_grant(&db, &env, scope, "cli_owner", Some(&theirs.to_string())).await;

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
                    grant_id: &theirs,
                    tokens: &[ironauth_store::IssuedTokenRecord {
                        id: ironauth_store::IssuedTokenId::generate(&env, &scope),
                        kind: ironauth_store::TokenKind::Access,
                    }],
                    opaque: None,
                },
            )
            .await
            .is_err(),
        "a spine naming another client's grant must be refused, or the tokens hang off a \
         grant this client's revocation will never reach"
    );
    assert_eq!(
        recorded_for(&db, scope, &theirs.to_string()).await,
        (0, 0),
        "and nothing is recorded against the other client's grant"
    );

    // POSITIVE CONTROL: the same shape whose spine belongs to the presenting client redeems.
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
        "the presenting client's own grant still redeems"
    );
}

/// `approved_details` reports the spine and the ceiling the caller mints from (issue #131).
///
/// Both fields are load-bearing and neither was read by any test: review neutralised
/// `grant_id` to `None` and `requested_scope` to `None` in turn, and the suite stayed at 44.
///
/// `grant_id` is the ONLY channel by which the token endpoint learns the spine that
/// redemption now requires, so a `None` there makes every redemption fail. `requested_scope`
/// is the ceiling the endpoint mints under, and a `None` there silently narrows every issued
/// token to no scope at all. Both fail quietly rather than loudly, which is why they need
/// reading back rather than trusting.
#[tokio::test]
async fn approved_details_reports_the_spine_and_the_requested_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, grant_id) = seed_approved_linked(&db, &env, scope, "cli_owner").await;

    let details = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .approved_details(&digest, "cli_owner", NOW_MICROS)
        .await
        .expect("read")
        .expect("the request is approved");

    assert_eq!(
        details.grant_id, grant_id,
        "the spine must be reported, or the token endpoint cannot build a redemption at all"
    );
    assert_eq!(
        details.requested_scope.as_deref(),
        Some("openid profile"),
        "the requested scope must be reported, or every issued token is silently narrowed"
    );
    assert_eq!(
        details.subject, "usr_subject",
        "and the subject the approval names"
    );
}

/// An approval that names no grant is refused where it is CREATED (issue #131).
///
/// # Why both ends
///
/// Redemption refuses a spine-less approval, and refusing only there strands the user.
/// `decide` would return `Ok(true)`, the row would read `approved`, `approved_details` would
/// answer `Some`, ping mode would notify the client to come and collect, and the token
/// endpoint would do the signing work and then fail forever with no audit row and nothing
/// distinguishing the failure from a bad `auth_req_id`. The person approved on their separate
/// device and can never be told why nothing happened.
///
/// A DENIAL still needs no grant, because a refusal has nothing to hang off, and that half is
/// asserted here too so the rule is not read as "every decision needs a grant".
#[tokio::test]
async fn approving_without_a_grant_is_refused_and_denying_without_one_is_not() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (_, approve_id) = create_pending_nonce(&db, &env, scope, "cli_app", "usr_ada", 41).await;
    let (denied_digest, deny_id) =
        create_pending_nonce(&db, &env, scope, "cli_app", "usr_ada", 42).await;
    let repo = || db.store().scoped(scope);

    let refused = repo()
        .backchannel_auth()
        .decide(
            &env,
            &approve_id,
            "usr_ada",
            true,
            BackchannelApprovalLinkage::default(),
            NOW_MICROS,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(refused, ironauth_store::StoreError::NotFound),
        "the CODE guard must refuse this, not the CHECK constraint. `.is_err()` cannot tell \
         them apart: with the guard removed the constraint raises StoreError::Database and \
         the weaker assertion still passes, which is how review measured BOTH enforcement \
         points surviving mutation while the test stayed green. It matters to a caller too, \
         because `decide`'s own doc makes NotFound the malformed-call answer and a Database \
         error is a 500. Got {refused:?}"
    );

    // AND NOTHING WAS COMMITTED: the request is still pending, so a caller that fixes its
    // linkage can approve properly.
    let grant = ironauth_store::GrantId::generate(&env, &scope);
    assert!(
        repo()
            .backchannel_auth()
            .decide(
                &env,
                &approve_id,
                "usr_ada",
                true,
                approving_linkage(&grant),
                NOW_MICROS,
            )
            .await
            .expect("approve with a grant"),
        "the refusal must leave the request decidable"
    );

    // A DENIAL needs no grant.
    assert!(
        repo()
            .backchannel_auth()
            .decide(
                &env,
                &deny_id,
                "usr_ada",
                false,
                BackchannelApprovalLinkage::default(),
                NOW_MICROS,
            )
            .await
            .expect("deny without a grant"),
        "a denial has nothing to hang off a grant and must not require one"
    );
    assert!(
        repo()
            .backchannel_auth()
            .approved_details(&denied_digest, "cli_app", NOW_MICROS)
            .await
            .expect("read")
            .is_none(),
        "and the denial took effect"
    );
}

/// Scope containment is exact, case-sensitive and whole-token (issue #131).
///
/// # The three ways it could quietly widen
///
/// Review measured all three surviving as mutants, because the original case table pinned the
/// happy paths and not the near-misses:
///
/// - CASE INSENSITIVITY. Scope values are case-sensitive per RFC 6749 3.3, so `OPENID` is a
///   different scope from `openid` and must not pass.
/// - PREFIX MATCHING. The classic scope-containment widening: `admin` must not pass merely
///   because the approval carried `administrator`.
/// - AN ABSENT CEILING ADMITTING EVERYTHING. A request naming no scope bounds the token to
///   none, and no fixture had a NULL `requested_scope` at all.
#[tokio::test]
async fn scope_containment_is_case_sensitive_whole_token_and_closed_when_absent() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let audiences = vec!["https://api.one.test".to_string()];

    // (requested_scope on the request, scope the token claims, allowed, why)
    let cases: [(Option<&str>, Option<&str>, bool, &str); 6] = [
        (
            Some("openid profile"),
            Some("OPENID"),
            false,
            "a different case is a different scope",
        ),
        (
            Some("administrator"),
            Some("admin"),
            false,
            "a prefix is not a member",
        ),
        (
            Some("admin"),
            Some("administrator"),
            false,
            "nor is an extension of one",
        ),
        (
            None,
            Some("openid"),
            false,
            "an absent ceiling admits nothing",
        ),
        (
            None,
            None,
            true,
            "and an absent ceiling still admits nothing claimed",
        ),
        (
            Some("openid profile"),
            Some(""),
            true,
            "an empty claim is no claim",
        ),
    ];
    for (idx, (requested, claimed, allowed, why)) in cases.into_iter().enumerate() {
        let grant = ironauth_store::GrantId::generate(&env, &scope);
        seed_grant(&db, scope, &grant.to_string(), "cli_owner", "usr_subject").await;
        let digest = seed_approved_scoped(
            &db,
            &env,
            scope,
            "cli_owner",
            Some(&grant.to_string()),
            requested,
        )
        .await;
        let jti = ironauth_store::IssuedTokenId::generate(&env, &scope);
        let token_digest = format!("digest-case-{idx}");
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
                    grant_id: &grant,
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
            "{why}: requested={requested:?} claimed={claimed:?} got {outcome:?}"
        );
    }
}

/// Everything the approval froze for the ID token is readable back (issue #131).
///
/// # Why this exists
///
/// `decide` freezes `auth_time`, `auth_methods` and `consent_ref` at approval, and the
/// `auth_time` column says outright that it is there so the issued ID token's `auth_time` is
/// truthful. Nothing read any of it back, and review measured the consequence: deleting the
/// `auth_time` expression from BOTH readers, and the `consent_ref` column from one, left the
/// suite at 48 passed. A client registered with `require_auth_time` could not have been
/// served correctly and no test would have said so.
///
/// A value written on the assumption that someone downstream will read it is the same defect
/// as a layer with no caller, from the other direction.
#[tokio::test]
async fn the_approval_instant_and_consent_are_readable_by_the_token_endpoint() {
    const APPROVED_AT: i64 = 1_700_000_000_123_456;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, id) = create_pending_nonce(&db, &env, scope, "cli_app", "usr_ada", 77).await;
    let grant = ironauth_store::GrantId::generate(&env, &scope);

    db.store()
        .scoped(scope)
        .backchannel_auth()
        .decide(
            &env,
            &id,
            "usr_ada",
            true,
            BackchannelApprovalLinkage {
                grant_id: Some(&grant),
                consent_ref: Some("cns_the_user_said_yes"),
                auth_methods: Some("pwd mfa"),
                auth_time_micros: Some(APPROVED_AT),
            },
            NOW_MICROS,
        )
        .await
        .expect("approve");

    let details = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .approved_details(&digest, "cli_app", NOW_MICROS)
        .await
        .expect("read")
        .expect("approved");

    assert_eq!(
        details.auth_time_unix_micros,
        Some(APPROVED_AT),
        "the approval instant must survive the round trip to the microsecond, or the ID \
         token's auth_time is a guess"
    );
    assert_eq!(
        details.consent_ref.as_deref(),
        Some("cns_the_user_said_yes"),
        "the consent decision must be readable, or nothing can point at what was agreed"
    );
    assert_eq!(
        details.auth_methods.as_deref(),
        Some("pwd mfa"),
        "and the amr"
    );
}

/// An issued token's KIND is recorded and metered as its own kind (issue #131).
///
/// `recorded_for` counts rows and `metering_events_for` filters on the grant, so neither
/// distinguishes an access token from an ID token. Review measured all three consequences:
/// binding `issued_tokens.token_kind` to a constant, and forcing either metering payload's
/// `token_kind`, all left the suite green. `token.issued` feeds `tokens_issued`, so the kind
/// breakdown is billable data that nothing pinned.
#[tokio::test]
async fn each_issued_token_is_recorded_and_metered_under_its_own_kind() {
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
                // BOTH kinds in the record list, which is the `at+jwt` production shape
                // (`token.rs:420`, `device.rs:458`). The earlier version passed `[Id]` only,
                // and review measured why that cannot work: with one record of one kind, a
                // mutant binding a CONSTANT kind still produces the expected single value.
                // A fixture whose expectation is one element cannot distinguish "the kind was
                // read" from "the kind was assumed".
                tokens: &[
                    ironauth_store::IssuedTokenRecord {
                        id: ironauth_store::IssuedTokenId::generate(&env, &scope),
                        kind: ironauth_store::TokenKind::Id,
                    },
                    ironauth_store::IssuedTokenRecord {
                        id: ironauth_store::IssuedTokenId::generate(&env, &scope),
                        kind: ironauth_store::TokenKind::Access,
                    },
                ],
                opaque: Some(ironauth_store::NewOpaqueAccessToken {
                    token_digest: "digest-kinds",
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
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT token_kind FROM issued_tokens \
         WHERE grant_id = $1 AND tenant_id = $2 AND environment_id = $3 ORDER BY token_kind",
    )
    .bind(grant_id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(&mut *tx)
    .await
    .expect("read the issued token kinds");
    let metered: Vec<String> = sqlx::query_scalar(
        "SELECT payload->'payload'->>'token_kind' FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 \
           AND payload->>'type' = 'token.issued' \
           AND payload->'payload'->>'grant_id' = $3 \
         ORDER BY 1",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(grant_id.to_string())
    .fetch_all(&mut *tx)
    .await
    .expect("read the metered kinds");
    tx.commit().await.expect("commit");

    assert_eq!(
        kinds,
        vec!["access".to_string(), "id".to_string()],
        "each issued-token row must record ITS OWN kind, not a constant"
    );
    assert_eq!(
        metered,
        vec!["access".to_string(), "access".to_string(), "id".to_string()],
        "and every token must be metered under its own kind: two from the record list plus \
         the opaque access token. A constant here leaves the TOTAL right and the usage \
         breakdown wrong, which is the half nothing was checking"
    );
}

/// A redemption naming a grant from ANOTHER SCOPE is refused before the transaction opens.
///
/// # What actually refuses it, corrected
///
/// An earlier version of this doc said the top-of-function scope check "is the only thing
/// standing between a foreign grant id and the ownership predicate". Measurably false:
/// review disabled that check and the suite stayed green, because a foreign-scope `GrantId`
/// can never equal the in-scope spine, so the spine comparison refuses it first. The early
/// return is a cheap exit before the transaction opens, not the load-bearing guard, and the
/// behaviour this test pins holds either way.
#[tokio::test]
async fn a_redemption_naming_a_foreign_scope_grant_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    let (digest, _spine) = seed_approved_linked(&db, &env, scope, "cli_owner").await;
    let acting = ironauth_store::ActingContext::new(
        db.test_actor(&env),
        ironauth_store::CorrelationId::generate(&env),
    );
    let foreign = ironauth_store::GrantId::generate(&env, &elsewhere);

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
                    grant_id: &foreign,
                    tokens: &[],
                    opaque: None,
                },
            )
            .await
            .is_err(),
        "a grant minted under another scope must be refused"
    );

    // AND THE APPROVAL SURVIVES, since the refusal happens before the flip.
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

/// `decide` refuses a grant minted for another scope (issue #131).
///
/// A typed id cannot be malformed, but it can have been minted elsewhere, and review showed
/// that shape passing the `is_none()` guard: `Ok(true)`, a row `approved_details` reported as
/// redeemable, and a redemption refused forever. Same stranding, one type away.
#[tokio::test]
async fn approving_with_a_foreign_scope_grant_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    let (digest, id) = create_pending_nonce(&db, &env, scope, "cli_app", "usr_ada", 78).await;
    let foreign = ironauth_store::GrantId::generate(&env, &elsewhere);

    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .decide(
                &env,
                &id,
                "usr_ada",
                true,
                approving_linkage(&foreign),
                NOW_MICROS,
            )
            .await
            .is_err(),
        "approving with another scope's grant must be refused, not stored for a redemption \
         that can never succeed"
    );
    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .approved_details(&digest, "cli_app", NOW_MICROS)
            .await
            .expect("read")
            .is_none(),
        "and nothing was approved"
    );
}

/// The CHECK refuses the two shapes the data plane can otherwise write (issue #131).
///
/// # Why this exists separately from the code guard
///
/// `decide` refusing a grant-less approval and migration 0151's CHECK mask each other. The
/// only test of the code guard asserted `.is_err()`, which the CHECK satisfies too, so review
/// measured BOTH surviving mutation independently: remove either and the suite stayed green.
/// Two enforcement points that are only jointly observable are one enforcement point with
/// extra steps.
///
/// So this asserts the CHECK on its own terms, through the DATA PLANE role under RLS, which
/// is the writer it exists to survive. `status` and `grant_id` are independently writable in
/// the table's column-scoped GRANT list, so both shapes below are within that role's granted
/// privileges and neither goes anywhere near `decide`.
#[tokio::test]
async fn the_check_refuses_a_spine_less_approval_written_by_the_data_plane() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // 1. An INSERT naming `approved` and omitting the grant.
    let id = BackchannelAuthRequestId::generate(&env, &scope);
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let inserted = sqlx::query(
        "INSERT INTO backchannel_authentication_requests (
             auth_req_id_digest, tenant_id, environment_id, id, client_id,
             delivery_mode, status, interval_secs, subject, expires_at
         ) VALUES ($1, $2, $3, $4, 'cli_app', 'poll', 'approved', 5, 'usr_ada', $5::timestamptz)",
    )
    .bind(digest_of("check-insert"))
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(id.to_string())
    .bind(FAR_FUTURE)
    .execute(&mut *tx)
    .await;
    assert!(
        inserted.is_err(),
        "the data plane must not be able to INSERT an approved request with no grant"
    );
    drop(tx);

    // 2. An UPDATE moving a pending request to approved without setting one.
    let (_, pending_id) = create_pending_nonce(&db, &env, scope, "cli_app", "usr_ada", 91).await;
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let updated = sqlx::query(
        "UPDATE backchannel_authentication_requests SET status = 'approved' \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(pending_id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(&mut *tx)
    .await;
    assert!(
        updated.is_err(),
        "nor UPDATE one into existence, which is the shape a future writer who has not read \
         `decide` produces"
    );
    drop(tx);

    // POSITIVE CONTROL: the same UPDATE with a grant is allowed, so the refusals above are
    // about the constraint and not about the role's privileges.
    let grant = ironauth_store::GrantId::generate(&env, &scope);
    seed_grant(&db, scope, &grant.to_string(), "cli_app", "usr_ada").await;
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    sqlx::query(
        "UPDATE backchannel_authentication_requests SET status = 'approved', grant_id = $4 \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(pending_id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(grant.to_string())
    .execute(&mut *tx)
    .await
    .expect("approving WITH a grant is permitted");
    tx.commit().await.expect("commit");
}

/// `redeem` refuses a spine-less row, and reports what the approval froze (issue #131).
///
/// # Three unmeasured changes in one method
///
/// Review found every change a previous round made to `redeem` surviving mutation: its new
/// `grant_id IS NOT NULL` predicate, its `auth_time` read, and its `consent_ref` read. The
/// predicate was the fix for a blocking finding (this method was consuming spine-less rows
/// and BURNING the approval) and it shipped with no test, because the only fixture that can
/// produce that row was written for `approved_details` and never pointed here.
#[tokio::test]
async fn redeem_refuses_a_spine_less_row_and_reports_the_approval_instant() {
    const APPROVED_AT: i64 = 1_700_000_000_123_456;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let planted = seed_approved_without_a_spine(&db, &env, scope, "cli_owner").await;

    // Whole Result, for the same reason as its twin.
    let consumed = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem(&planted, "cli_owner", NOW_MICROS)
        .await;
    assert!(
        matches!(consumed, Ok(None)),
        "a spine-less row must not be consumable, or the approval is burned for a token that \
         can hang off nothing. Got {consumed:?}"
    );

    // AND IT IS STILL THERE: the refusal must not have flipped it.
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let status: String = sqlx::query_scalar(
        "SELECT status FROM backchannel_authentication_requests \
         WHERE auth_req_id_digest = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(&planted)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *tx)
    .await
    .expect("the row survives");
    tx.commit().await.expect("commit");
    assert_eq!(
        status, "approved",
        "the refusal must not consume the request"
    );

    // AND THE READS: a properly approved request reports what `decide` froze.
    let (digest, id) = create_pending_nonce(&db, &env, scope, "cli_app", "usr_ada", 92).await;
    let grant = ironauth_store::GrantId::generate(&env, &scope);
    db.store()
        .scoped(scope)
        .backchannel_auth()
        .decide(
            &env,
            &id,
            "usr_ada",
            true,
            BackchannelApprovalLinkage {
                grant_id: Some(&grant),
                consent_ref: Some("cns_redeem_side"),
                auth_methods: Some("pwd"),
                auth_time_micros: Some(APPROVED_AT),
            },
            NOW_MICROS,
        )
        .await
        .expect("approve");

    let redeemed = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem(&digest, "cli_app", NOW_MICROS)
        .await
        .expect("read")
        .expect("an approved request redeems");
    assert_eq!(redeemed.grant_id, grant, "and it reports its spine");
    assert_eq!(
        redeemed.auth_time_unix_micros,
        Some(APPROVED_AT),
        "the approval instant must survive this reader too, not only the other one"
    );
    assert_eq!(
        redeemed.consent_ref.as_deref(),
        Some("cns_redeem_side"),
        "and the consent decision"
    );
}

/// A denial records no grant, whatever the caller named (issue #131).
///
/// `approval_linkage_is_usable` checks nothing on the denial path, correctly, because a
/// refusal has nothing to hang off. Review found that `decide` then WROTE whatever grant the
/// linkage carried anyway, including one belonging to another client for another user. No
/// token can come of it, since every reader filters on `approved`, but the foreign key pins
/// an unrelated grant against deletion and the index reports a link a revocation or an audit
/// read would believe.
#[tokio::test]
async fn a_denial_records_no_grant_even_when_one_is_named() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (digest, id) = create_pending_nonce(&db, &env, scope, "cli_app", "usr_ada", 93).await;

    // A real grant belonging to somebody else entirely.
    let theirs = ironauth_store::GrantId::generate(&env, &scope);
    seed_grant(&db, scope, &theirs.to_string(), "cli_other", "usr_victim").await;

    assert!(
        db.store()
            .scoped(scope)
            .backchannel_auth()
            .decide(
                &env,
                &id,
                "usr_ada",
                false,
                approving_linkage(&theirs),
                NOW_MICROS,
            )
            .await
            .expect("deny"),
        "the denial itself is recorded"
    );

    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT grant_id FROM backchannel_authentication_requests \
         WHERE auth_req_id_digest = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(&digest)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *tx)
    .await
    .expect("read the denied row");
    tx.commit().await.expect("commit");

    assert_eq!(
        stored, None,
        "a denial must record no grant, or it pins an unrelated one against deletion and \
         reports a link that never existed"
    );
}

/// A grant id that does not parse refuses WITHOUT burning the approval (issue #131).
///
/// # The ordering this pins
///
/// `redeem` flips the row to `redeemed` in its own statement. An earlier version committed
/// that flip and THEN parsed, so a parse failure returned `Err` on a request already
/// consumed: the approval burned, no tokens issued, and nothing to distinguish it from a bad
/// `auth_req_id`. The person had approved on a separate device and could never be told why.
///
/// It is reachable without any code being wrong. `grants.id` is bare `text PRIMARY KEY`
/// (migration 0004) with no format check, the data plane may INSERT into `grants`, and the
/// composite foreign key accepts any id that exists. So a row whose id was not minted by
/// `GrantId` satisfies every constraint and fails only at the parse.
///
/// The previous comment claimed the `grant_id IS NOT NULL` predicate made the parse
/// infallible. It constrains NULLITY, not parseability.
#[tokio::test]
async fn an_unparseable_grant_id_refuses_without_consuming_the_request() {
    const LEGACY: &str = "legacy-grant-0001";
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // A grants row whose id was never minted by `GrantId`, written the way the data plane
    // can write it.
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    sqlx::query(
        "INSERT INTO grants (id, tenant_id, environment_id, client_id, subject, created_at) \
         VALUES ($1, $2, $3, 'cli_owner', 'usr_subject', now())",
    )
    .bind(LEGACY)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(&mut *tx)
    .await
    .expect("grants.id has no format check, so this is allowed");
    tx.commit().await.expect("commit");

    let digest = seed_approved_scoped(
        &db,
        &env,
        scope,
        "cli_owner",
        Some(LEGACY),
        Some("openid profile"),
    )
    .await;

    let refused = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem(&digest, "cli_owner", NOW_MICROS)
        .await
        .unwrap_err();
    assert!(
        matches!(refused, ironauth_store::StoreError::NotFound),
        "an unparseable grant id must be refused as NotFound. `.is_err()` alone cannot tell \
         that apart from a refusal for ANY reason: review inserted an unconditional error \
         after the flip and this test passed both assertions. Got {refused:?}"
    );

    // AND THE REQUEST SURVIVES. This is the assertion that matters: the refusal must roll
    // back the flip, not report a failure on a request it already consumed.
    let mut tx = db.app_pool().begin().await.expect("begin");
    bind_scope(&mut tx, scope).await;
    let status: String = sqlx::query_scalar(
        "SELECT status FROM backchannel_authentication_requests \
         WHERE auth_req_id_digest = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(&digest)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(&mut *tx)
    .await
    .expect("the request survives");
    tx.commit().await.expect("commit");

    assert_eq!(
        status, "approved",
        "the refusal must roll the flip back, or a fault of ours burns an approval a person \
         gave on their other device"
    );
}
