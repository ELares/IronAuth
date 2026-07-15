// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-RP back-channel-logout delivery queue (issue #34), against a real database.
//!
//! The #35 outbox tells a worker "a session ended, fan out". This queue is what the
//! back-channel logout worker EXPLODES each drained session-ended event into: one row per
//! participating relying party (a client that registered a `backchannel_logout_uri`),
//! each carrying that client's OWN `sid` (never another client's), with its own
//! at-least-once retry state. This suite pins the queue's guarantees:
//!
//! - Explode targets ONLY registered participants, one row per (event, client), each with
//!   the client's own sid; a re-explode of the same event queues nothing new.
//! - `claim_due` leases due rows; a lapsed lease reappears them (a crashed worker
//!   re-delivers); `mark_delivered` retires a row idempotently.
//! - `record_failure` schedules a bounded backoff retry, or DEAD-LETTERS the row once the
//!   caller decides the attempts cap is reached, recording the last error.
//! - Two concurrent claimers lease DISJOINT sets and never block (FOR UPDATE SKIP LOCKED),
//!   so two workers never double-deliver.
//! - The queue is cross-tenant isolated: a scope never drains another tenant's deliveries.

use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ClientId, CorrelationId, Scope, SessionEndCause, SessionId, UserId};
use sqlx::Row;

/// A far-future expiry (year 2100) in epoch microseconds, so a session is live until it is
/// explicitly ended.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Create a live SSO session in `scope` for `subject`.
async fn create_session(db: &TestDatabase, env: &Env, scope: Scope, subject: &str) -> SessionId {
    let id = SessionId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .rotate(
            env,
            &id,
            None,
            ironauth_store::NewSession {
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
        .expect("rotate session");
    id
}

/// Create a client, optionally register a `backchannel_logout_uri`, and bind a per-client
/// session (its `sid`) to `session`. Returns the client id and its sid.
async fn create_participant(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    session: &SessionId,
    logout_uri: Option<&str>,
) -> (ClientId, String) {
    let client = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .clients()
        .create(env, "rp")
        .await
        .expect("create client");
    if let Some(uri) = logout_uri {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(env), CorrelationId::generate(env))
            .clients()
            .register_backchannel_logout(env, &client, Some(uri), false)
            .await
            .expect("register backchannel logout");
    }
    let sid = db
        .store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(env, session, &client.to_string(), 0)
        .await
        .expect("ensure sid");
    (client, sid)
}

/// End `session` as a logout (enqueues one session-ended outbox event) and return the
/// enqueued event's id.
async fn end_session(db: &TestDatabase, env: &Env, scope: Scope, session: &SessionId) -> String {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .revoke(env, session, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("revoke session");
    db.store()
        .scoped(scope)
        .session_events()
        .pending(100)
        .await
        .expect("pending events")
        .into_iter()
        .find(|event| event.session_id == session.to_string())
        .expect("an outbox event for the ended session")
        .id
}

#[tokio::test]
async fn explode_queues_one_delivery_per_registered_rp_each_with_its_own_sid() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject).await;

    // Two clients register a back-channel URI; a third does NOT (it is not a participant).
    let (client_a, sid_a) =
        create_participant(&db, &env, scope, &session, Some("https://a.example/bc")).await;
    let (client_b, sid_b) =
        create_participant(&db, &env, scope, &session, Some("https://b.example/bc")).await;
    let (_client_c, _sid_c) = create_participant(&db, &env, scope, &session, None).await;

    // The two sids are distinct per (client, session): an RP only ever learns its own.
    assert_ne!(sid_a, sid_b, "each client's sid is distinct");

    let event_id = end_session(&db, &env, scope, &session).await;
    let queued = db
        .store()
        .scoped(scope)
        .backchannel_deliveries()
        .enqueue_for_event(&env, &event_id, &session.to_string())
        .await
        .expect("explode");
    assert_eq!(queued, 2, "only the two registered RPs get a delivery");

    let deliveries = db
        .store()
        .scoped(scope)
        .backchannel_deliveries()
        .pending(100)
        .await
        .expect("pending deliveries");
    assert_eq!(deliveries.len(), 2);
    // Each delivery carries its OWN client's sid and logout_uri (no cross-client leak).
    let for_a = deliveries
        .iter()
        .find(|d| d.client_id == client_a.to_string())
        .expect("a delivery for client A");
    let for_b = deliveries
        .iter()
        .find(|d| d.client_id == client_b.to_string())
        .expect("a delivery for client B");
    assert_eq!(for_a.sid, sid_a, "A's delivery carries A's sid");
    assert_eq!(for_a.logout_uri, "https://a.example/bc");
    assert_eq!(for_b.sid, sid_b, "B's delivery carries B's sid");
    assert_eq!(for_b.logout_uri, "https://b.example/bc");

    // Re-exploding the same outbox event queues nothing new (idempotent, at-least-once).
    let requeued = db
        .store()
        .scoped(scope)
        .backchannel_deliveries()
        .enqueue_for_event(&env, &event_id, &session.to_string())
        .await
        .expect("re-explode");
    assert_eq!(
        requeued, 0,
        "a redelivered outbox event queues no duplicate"
    );
}

#[tokio::test]
async fn claim_due_leases_then_reappears_after_lease_and_mark_delivered_retires() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject).await;
    create_participant(&db, &env, scope, &session, Some("https://a.example/bc")).await;
    let event_id = end_session(&db, &env, scope, &session).await;

    let scoped = db.store().scoped(scope);
    let queue = scoped.backchannel_deliveries();
    queue
        .enqueue_for_event(&env, &event_id, &session.to_string())
        .await
        .expect("explode");
    let lease = Duration::from_secs(60);

    let claimed = queue.claim_due(&env, lease, 100).await.expect("claim");
    assert_eq!(claimed.len(), 1, "the one due delivery is claimed");
    let id = claimed[0].id.clone();

    // A second claim before the lease lapses sees nothing (hidden in flight).
    assert!(
        queue
            .claim_due(&env, lease, 100)
            .await
            .expect("claim")
            .is_empty(),
        "a leased delivery is hidden until its lease lapses"
    );

    // The lease lapses; the delivery reappears (at-least-once).
    clock.advance(Duration::from_secs(61));
    let reclaimed = queue.claim_due(&env, lease, 100).await.expect("re-claim");
    assert_eq!(reclaimed.len(), 1, "a lapsed lease reappears the delivery");
    assert_eq!(reclaimed[0].id, id);

    // Marking it delivered retires it; the mark is idempotent.
    assert!(queue.mark_delivered(&env, &id).await.expect("mark"));
    assert!(!queue.mark_delivered(&env, &id).await.expect("mark again"));
    clock.advance(Duration::from_secs(3600));
    assert!(
        queue
            .claim_due(&env, lease, 100)
            .await
            .expect("claim")
            .is_empty(),
        "a delivered delivery never redrains"
    );
}

#[tokio::test]
async fn record_failure_schedules_backoff_then_dead_letters() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 11);
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject).await;
    create_participant(&db, &env, scope, &session, Some("https://a.example/bc")).await;
    let event_id = end_session(&db, &env, scope, &session).await;

    let scoped = db.store().scoped(scope);
    let queue = scoped.backchannel_deliveries();
    queue
        .enqueue_for_event(&env, &event_id, &session.to_string())
        .await
        .expect("explode");
    let lease = Duration::from_secs(30);

    // First attempt fails: schedule a backoff retry 100s out.
    let claimed = queue.claim_due(&env, lease, 100).await.expect("claim");
    let id = claimed[0].id.clone();
    let now_micros = 0_i64;
    let next = now_micros + 100 * 1_000_000;
    assert!(
        queue
            .record_failure(&env, &id, 1, Some(next), "http_status_503")
            .await
            .expect("record failure")
    );

    // Not due yet (the backoff gate holds it back), even though the lease was released.
    assert!(
        queue
            .claim_due(&env, lease, 100)
            .await
            .expect("claim")
            .is_empty(),
        "the backoff gate hides the delivery until next_attempt_at"
    );

    // Advance past the backoff: it is due again and carries the recorded attempts count.
    clock.advance(Duration::from_secs(101));
    let reclaimed = queue.claim_due(&env, lease, 100).await.expect("re-claim");
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(
        reclaimed[0].attempts, 1,
        "the recorded attempt count survives"
    );

    // Second attempt fails and hits the cap: dead-letter it (no next attempt).
    assert!(
        queue
            .record_failure(&env, &id, 2, None, "http_status_503")
            .await
            .expect("dead-letter")
    );
    assert!(
        queue
            .claim_due(&env, lease, 100)
            .await
            .expect("claim")
            .is_empty(),
        "a dead-lettered delivery never drains again"
    );
    assert!(
        queue.pending(100).await.expect("pending").is_empty(),
        "a dead-lettered delivery is not pending"
    );
    // The full listing shows the terminal dead-letter state with its last error.
    let listed = queue.list(100).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].attempts, 2);
    assert_eq!(listed[0].last_error.as_deref(), Some("http_status_503"));
    assert!(listed[0].dead_lettered_at_unix_micros.is_some());
    assert!(listed[0].delivered_at_unix_micros.is_none());
}

#[tokio::test]
async fn two_concurrent_claimers_lease_disjoint_via_skip_locked() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject).await;

    // Four registered RPs on one session, so ending it explodes into four deliveries.
    for _ in 0..4 {
        create_participant(&db, &env, scope, &session, Some("https://rp.example/bc")).await;
    }
    let event_id = end_session(&db, &env, scope, &session).await;
    db.store()
        .scoped(scope)
        .backchannel_deliveries()
        .enqueue_for_event(&env, &event_id, &session.to_string())
        .await
        .expect("explode");
    let all_ids: std::collections::HashSet<String> = db
        .store()
        .scoped(scope)
        .backchannel_deliveries()
        .pending(100)
        .await
        .expect("pending")
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(all_ids.len(), 4, "four deliveries are queued");

    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    // Worker A leases the first two rows with claim_due's own SELECT (FOR UPDATE SKIP
    // LOCKED) and HOLDS the transaction open so its locks stay held.
    let mut worker_a = db.app_pool().begin().await.expect("begin worker A");
    bind_scope(&mut worker_a, &tenant, &environment).await;
    let a_rows = sqlx::query(
        "SELECT id FROM backchannel_logout_deliveries \
         WHERE tenant_id = $1 AND environment_id = $2 \
         AND delivered_at IS NULL AND dead_lettered_at IS NULL AND claimed_at IS NULL \
         ORDER BY next_attempt_at LIMIT 2 FOR UPDATE SKIP LOCKED",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_all(&mut *worker_a)
    .await
    .expect("worker A leases");
    let a_ids: std::collections::HashSet<String> = a_rows
        .iter()
        .map(|row| row.get::<String, _>("id"))
        .collect();
    assert_eq!(a_ids.len(), 2);

    // Worker B claims through the store while A holds its locks: SKIP LOCKED means B
    // never blocks and never sees A's rows.
    let b_ids: std::collections::HashSet<String> = db
        .store()
        .scoped(scope)
        .backchannel_deliveries()
        .claim_due(&env, Duration::from_secs(60), 100)
        .await
        .expect("worker B claims")
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(b_ids.len(), 2);
    assert!(
        a_ids.is_disjoint(&b_ids),
        "concurrent claimers lease disjoint sets (no double delivery)"
    );
    let union: std::collections::HashSet<String> = a_ids.union(&b_ids).cloned().collect();
    assert_eq!(union, all_ids, "together they cover every delivery once");

    // A rolls back (a crashed worker): its rows never got a claimed_at, so they reappear.
    worker_a.rollback().await.expect("worker A rolls back");
    let reappeared: std::collections::HashSet<String> = db
        .store()
        .scoped(scope)
        .backchannel_deliveries()
        .claim_due(&env, Duration::from_secs(60), 100)
        .await
        .expect("drain after rollback")
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(reappeared, a_ids, "A's un-committed rows reappear");
}

#[tokio::test]
async fn the_delivery_queue_is_isolated_across_tenants() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope_a).to_string();
    let session = create_session(&db, &env, scope_a, &subject).await;
    create_participant(&db, &env, scope_a, &session, Some("https://a.example/bc")).await;
    let event_id = end_session(&db, &env, scope_a, &session).await;
    db.store()
        .scoped(scope_a)
        .backchannel_deliveries()
        .enqueue_for_event(&env, &event_id, &session.to_string())
        .await
        .expect("explode in A");

    assert_eq!(
        db.store()
            .scoped(scope_a)
            .backchannel_deliveries()
            .pending(100)
            .await
            .expect("A pending")
            .len(),
        1,
        "A sees its own delivery"
    );
    assert!(
        db.store()
            .scoped(scope_b)
            .backchannel_deliveries()
            .claim_due(&env, Duration::from_secs(60), 100)
            .await
            .expect("B claim")
            .is_empty(),
        "B never claims A's deliveries"
    );
    // A raw B-scoped SELECT sees nothing: RLS enforces the boundary beneath the repo.
    let mut tx = db.app_pool().begin().await.expect("begin B tx");
    bind_scope(
        &mut tx,
        &scope_b.tenant().to_string(),
        &scope_b.environment().to_string(),
    )
    .await;
    let visible: i64 = sqlx::query("SELECT count(*) AS n FROM backchannel_logout_deliveries")
        .fetch_one(&mut *tx)
        .await
        .expect("count")
        .get("n");
    assert_eq!(
        visible, 0,
        "RLS hides A's deliveries from a B-scoped connection"
    );
    let _ = tx.rollback().await;
}

#[tokio::test]
async fn a_foreign_scope_or_malformed_id_is_a_uniform_no_op() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope_a).to_string();
    let session = create_session(&db, &env, scope_a, &subject).await;
    create_participant(&db, &env, scope_a, &session, Some("https://a.example/bc")).await;
    let event_id = end_session(&db, &env, scope_a, &session).await;
    db.store()
        .scoped(scope_a)
        .backchannel_deliveries()
        .enqueue_for_event(&env, &event_id, &session.to_string())
        .await
        .expect("explode");
    let id = db
        .store()
        .scoped(scope_a)
        .backchannel_deliveries()
        .pending(100)
        .await
        .expect("pending")[0]
        .id
        .clone();

    // Marking or failing A's delivery through B's scope is a uniform no-op.
    assert!(
        !db.store()
            .scoped(scope_b)
            .backchannel_deliveries()
            .mark_delivered(&env, &id)
            .await
            .expect("cross-scope mark")
    );
    assert!(
        !db.store()
            .scoped(scope_a)
            .backchannel_deliveries()
            .mark_delivered(&env, "not-an-id")
            .await
            .expect("malformed mark")
    );
    assert!(
        !db.store()
            .scoped(scope_b)
            .backchannel_deliveries()
            .record_failure(&env, &id, 1, None, "x")
            .await
            .expect("cross-scope record")
    );
    // A's delivery is untouched.
    assert_eq!(
        db.store()
            .scoped(scope_a)
            .backchannel_deliveries()
            .pending(100)
            .await
            .expect("pending")
            .len(),
        1
    );
}

/// Bind the transaction-local row-level-security scope variables, exactly as the
/// repository does, so a raw adversarial query runs under the same scope.
async fn bind_scope(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    environment: &str,
) {
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(tenant)
        .execute(&mut **tx)
        .await
        .expect("bind tenant scope");
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(environment)
        .execute(&mut **tx)
        .await
        .expect("bind environment scope");
}
