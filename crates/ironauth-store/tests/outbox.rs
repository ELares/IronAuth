// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generic transactional outbox and lease based job queue (issue #104), against a
//! real database.
//!
//! This is the substrate every async path in M11 dispatches through, so the properties it
//! is held to here are the ones every consumer inherits and none of them can restate:
//!
//! - **Transactional enqueue.** A message commits with the domain write that caused it,
//!   and a rolled-back domain write emits nothing.
//! - **Lease claim, expiry, and reclaim under CONCURRENT workers.** Two workers draining
//!   one consumer lease disjoint sets and never block on each other; a crashed worker's
//!   messages come back once the visibility timeout lapses and not one moment before.
//! - **Bounded retry ending in a dead letter.** A failing message backs off, the attempts
//!   bound is what stops it rather than an operator noticing, and the counter advances
//!   exactly once however many callers report the same attempt at once.
//! - **The FENCING TOKEN.** A worker whose lease lapsed can neither complete nor fail a
//!   message the live worker holds, so a stale holder can never release an ordering group
//!   under the worker still working through it.
//! - **Per-aggregate ordering under concurrency.** Two messages sharing an ordering key
//!   are never in flight at once and are delivered in enqueue order, whatever the worker
//!   count, and whether the head succeeds, fails into a backoff, or is abandoned. Held
//!   here for producers that meet the non-overlap precondition the `OutboxRepo` type
//!   documentation states; every enqueue in this suite meets it.
//! - **The batch does not share one deadline.** Each message's lease is re-stamped before
//!   it is handled, so a pass that runs far past the visibility timeout keeps what it is
//!   working on and cleanly hands off, rather than double-handling, what it has not
//!   reached.
//! - **The consumer framework.** Registration refuses a duplicate name, a permanent
//!   failure dead-letters without burning the schedule, a consumer PANIC costs its message
//!   an attempt and the pool nothing, the pool is a pool, and `size` is the LIVE worker
//!   count rather than the number that were started.
//! - **The depth gauge.** All five counters measured at once, at five distinct non-zero
//!   values, and again after the clock moves.
//! - **Retention** (issue #104, PR 3). The reap predicates, the batch bound and its
//!   saturation signal, the fenced-scope skip, the missing-grant fault, what a reaped row
//!   gives up, and the SWEEPER's own liveness properties: the sliced sleep, the drop guard,
//!   the unavailable-scopes report, and a task that unwinds.
//!
//! The isolation and least-privilege halves are not restated here: they live in
//! `tests/migration.rs` (the policy, the CHECKs, the three indexes, the grant shape) and
//! in `tests/session_ended_fanout.rs` (the cross-tenant drain and the raw adversarial
//! writes as the app role), both of which now target this table.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_store::outbox::{
    ConsumerError, ConsumerRegistry, DrainStats, OutboxConsumer, OutboxObserver, OutboxReaper,
    OutboxWorker, OutboxWorkerPool, RetentionObserver, RetentionSettings, RetentionStats,
    RetentionSweeper, ScopeSource, SilentObserver, SilentRetentionObserver, StaticScopes,
    WorkerSettings,
};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, FailureOutcome, NewOutboxMessage, OutboxMessage, RetryPolicy, Scope,
    SessionEndCause, SessionId, StoreError, UserId,
};

/// A far-future expiry (year 2100) in epoch microseconds, so a session that stops
/// resolving can ONLY have stopped because it ended.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// The consumer name every message in this suite is routed to, unless a test is about
/// two consumers sharing the queue.
const CONSUMER: &str = "test_consumer";

/// The observer a test that is not ABOUT observability passes: reports nothing. Spelled
/// out at each call site rather than defaulted, because the pool requires the argument.
fn silent() -> Arc<dyn OutboxObserver> {
    Arc::new(SilentObserver)
}

/// Enqueue one message under `CONSUMER` with the given keys and a trivial payload.
async fn enqueue(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    idempotency_key: &str,
    ordering_key: &str,
) -> String {
    enqueue_for(db, env, scope, CONSUMER, idempotency_key, ordering_key).await
}

/// Enqueue one message for an explicit `consumer`.
async fn enqueue_for(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    consumer: &str,
    idempotency_key: &str,
    ordering_key: &str,
) -> String {
    db.store()
        .scoped(scope)
        .outbox()
        .enqueue(
            env,
            &NewOutboxMessage {
                consumer,
                idempotency_key,
                ordering_key,
                payload: serde_json::json!({ "key": idempotency_key }),
            },
        )
        .await
        .expect("enqueue")
}

/// The env clock's current instant in epoch microseconds, in the dialect every instant in
/// the outbox module is written in. Time comes from the SEAM here exactly as it does in
/// the repository, so a raw probe stamps the same shape of value a real claim does.
fn epoch_micros_of(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("the test clock is at or after the epoch")
            .as_micros(),
    )
    .expect("an epoch microsecond instant fits in i64")
}

/// The idempotency keys of `CONSUMER`'s non-terminal messages, in drain order.
async fn pending_keys(db: &TestDatabase, scope: Scope) -> Vec<String> {
    db.store()
        .scoped(scope)
        .outbox()
        .pending(CONSUMER, 100)
        .await
        .expect("pending")
        .into_iter()
        .map(|message| message.idempotency_key)
        .collect()
}

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

// ---------------------------------------------------------------------------
// 1. Transactional enqueue: the property the whole substrate exists for.

#[tokio::test]
async fn a_message_commits_with_its_domain_write_and_a_rolled_back_one_emits_nothing() {
    // Driven through a REAL domain write (the session revoke, which enqueues the
    // session-ended message inside its own transaction) rather than through a fixture
    // that opens a transaction and rolls it back. A fixture would prove that Postgres
    // rolls back, which nobody doubts; this proves that the enqueue is INSIDE the domain
    // write's transaction, which is the thing that can regress.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let committed = create_session(&db, &env, scope, &subject).await;
    let rolled_back = create_session(&db, &env, scope, &subject).await;

    // The committing half: a real revoke leaves exactly one message on the queue, keyed
    // by the ended session.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &committed, SessionEndCause::Revoked, false, None)
        .await
        .expect("revoke");
    let queued = db
        .store()
        .scoped(scope)
        .outbox()
        .pending("session_ended", 100)
        .await
        .expect("pending");
    assert_eq!(
        queued.len(),
        1,
        "a committed domain write emits exactly one"
    );
    assert_eq!(
        queued[0].idempotency_key,
        committed.to_string(),
        "the message is keyed by the domain fact, so a retry cannot duplicate it"
    );
    assert_eq!(
        queued[0].ordering_key,
        committed.to_string(),
        "one session is one aggregate"
    );
    assert_eq!(
        queued[0].payload.get("subject").and_then(|v| v.as_str()),
        Some(subject.as_str()),
        "the payload carries the body the typed facade decodes"
    );

    // The rolling-back half: the same revoke path with a failure injected AFTER the
    // enqueue, in the same transaction.
    let result = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke_injecting_post_audit_failure(&env, &rolled_back, SessionEndCause::Revoked)
        .await;
    assert!(
        result.is_err(),
        "the injected failure rolls the revoke back"
    );
    let after = db
        .store()
        .scoped(scope)
        .outbox()
        .pending("session_ended", 100)
        .await
        .expect("pending");
    assert_eq!(
        after.len(),
        1,
        "a rolled-back domain write emits nothing: the queue is unchanged"
    );
    assert_eq!(
        after[0].idempotency_key,
        committed.to_string(),
        "the one message on the queue is still the committed one"
    );
}

#[tokio::test]
async fn a_second_enqueue_under_one_idempotency_key_is_refused_per_consumer() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    enqueue(&db, &env, scope, "fact-1", "agg-a").await;
    let duplicate = db
        .store()
        .scoped(scope)
        .outbox()
        .enqueue(
            &env,
            &NewOutboxMessage {
                consumer: CONSUMER,
                idempotency_key: "fact-1",
                ordering_key: "agg-a",
                payload: serde_json::json!({}),
            },
        )
        .await;
    assert!(
        duplicate.is_err(),
        "two messages for one domain fact is a unique violation, not a silent second row"
    );

    // The key is scoped to the CONSUMER: another consumer may key on the same domain fact
    // without colliding, which is what lets two subsystems both react to one event.
    enqueue_for(&db, &env, scope, "other_consumer", "fact-1", "agg-a").await;
    assert_eq!(pending_keys(&db, scope).await, vec!["fact-1".to_owned()]);
    assert_eq!(
        db.store()
            .scoped(scope)
            .outbox()
            .pending("other_consumer", 100)
            .await
            .expect("pending")
            .len(),
        1,
        "a second consumer's queue is independent"
    );
}

// ---------------------------------------------------------------------------
// 2. Lease claim, expiry, and reclaim, under concurrent workers.

#[tokio::test]
async fn a_claim_leases_and_a_crashed_workers_lease_is_reclaimed_at_the_visibility_timeout() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
    let scope = db.seed_scope(&env).await;
    let lease = Duration::from_secs(30);
    let id = enqueue(&db, &env, scope, "fact-1", "agg-a").await;

    let store = db.store();
    let queue = store.scoped(scope);
    let queue = queue.outbox();

    let claimed = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1, "the one due message is leased");
    assert_eq!(claimed[0].id, id);

    // The worker now "crashes": it never completes and never fails the message. A second
    // claim sees nothing while the lease holds.
    assert!(
        queue
            .claim(&env, CONSUMER, lease, 100)
            .await
            .expect("claim")
            .is_empty(),
        "a leased message is hidden while its lease holds"
    );
    // The boundary is pinned to the microsecond, from BOTH sides, because a claim that
    // ignored the lease entirely would satisfy the reclaim assertion alone. At exactly
    // the visibility timeout the message is STILL hidden: the reclaim predicate is
    // `claimed_at < now - lease`, so the lease covers its whole nominal duration, which is
    // the same boundary the two queues that preceded this one use.
    clock.advance(lease);
    assert!(
        queue
            .claim(&env, CONSUMER, lease, 100)
            .await
            .expect("claim")
            .is_empty(),
        "at exactly the visibility timeout the lease still holds"
    );
    // One microsecond past it, the message is reclaimed. That is the whole crash-recovery
    // story: no operator action and no separate reclaim call, just the absence of a live
    // lease.
    clock.advance(Duration::from_micros(1));
    let reclaimed = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("reclaim");
    assert_eq!(reclaimed.len(), 1, "a lapsed lease reappears the message");
    assert_eq!(reclaimed[0].id, id, "the same message comes back");

    // Completing it is terminal and idempotent. The token presented is the one THIS claim
    // stamped, which is the only thing that authorizes the write.
    let held = &reclaimed[0];
    assert!(
        held.lease_stamp_unix_micros.is_some(),
        "a claimed message carries the lease it was stamped with"
    );
    assert!(queue.complete(&env, held).await.expect("complete"));
    assert!(
        !queue.complete(&env, held).await.expect("complete again"),
        "complete flips at most once"
    );
    clock.advance(Duration::from_secs(3_600));
    assert!(
        queue
            .claim(&env, CONSUMER, lease, 100)
            .await
            .expect("claim")
            .is_empty(),
        "a completed message never redrains, whatever the lease"
    );
}

#[tokio::test]
async fn two_concurrent_workers_lease_disjoint_sets_and_neither_blocks() {
    // Four messages in four DISTINCT ordering groups, so the ordering rule leaves all
    // four eligible and the only thing deciding who gets what is SKIP LOCKED. (The
    // ordering rule's own effect is measured separately below.)
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    for n in 0..4 {
        enqueue(&db, &env, scope, &format!("fact-{n}"), &format!("agg-{n}")).await;
    }
    let all: std::collections::HashSet<String> = db
        .store()
        .scoped(scope)
        .outbox()
        .pending(CONSUMER, 100)
        .await
        .expect("pending")
        .into_iter()
        .map(|message| message.id)
        .collect();
    assert_eq!(all.len(), 4);

    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    // Worker A holds its row locks open on the raw app pool, standing in for a worker
    // mid-pass on another replica.
    let mut worker_a = db.app_pool().begin().await.expect("begin worker A");
    bind_scope(&mut worker_a, &tenant, &environment).await;
    let a_ids: std::collections::HashSet<String> = sqlx::query(
        "SELECT id FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND consumer = $3 \
         AND completed_at IS NULL AND dead_lettered_at IS NULL AND claimed_at IS NULL \
         ORDER BY sequence LIMIT 2 FOR UPDATE SKIP LOCKED",
    )
    .bind(&tenant)
    .bind(&environment)
    .bind(CONSUMER)
    .fetch_all(&mut *worker_a)
    .await
    .expect("worker A leases its batch")
    .iter()
    .map(|row| sqlx::Row::get::<String, _>(row, "id"))
    .collect();
    assert_eq!(a_ids.len(), 2, "worker A holds two row locks");

    // Worker B drains through the real claim while A still holds its locks. It must not
    // BLOCK (this test would hang rather than fail if it did) and must not see A's rows.
    let b_ids: std::collections::HashSet<String> = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(&env, CONSUMER, Duration::from_secs(60), 100)
        .await
        .expect("worker B claims concurrently")
        .into_iter()
        .map(|message| message.id)
        .collect();
    assert_eq!(b_ids.len(), 2, "worker B leases the two A did not hold");
    assert!(
        a_ids.is_disjoint(&b_ids),
        "concurrent workers lease disjoint sets: no message is handled twice at once"
    );
    let union: std::collections::HashSet<String> = a_ids.union(&b_ids).cloned().collect();
    assert_eq!(union, all, "together they cover the queue exactly once");

    // A rolls back (a crash before it ever stamped a lease): its messages are claimable
    // again immediately, while B's leased ones stay hidden.
    worker_a.rollback().await.expect("worker A rolls back");
    let reappeared: std::collections::HashSet<String> = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(&env, CONSUMER, Duration::from_secs(60), 100)
        .await
        .expect("drain after A rolls back")
        .into_iter()
        .map(|message| message.id)
        .collect();
    assert_eq!(
        reappeared, a_ids,
        "A's uncommitted messages come back; B's leased ones stay hidden"
    );
}

// ---------------------------------------------------------------------------
// 3. Bounded retry to dead letter.

#[tokio::test]
async fn a_failing_message_backs_off_and_the_attempts_bound_dead_letters_it() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 11);
    let scope = db.seed_scope(&env).await;
    let policy = RetryPolicy {
        max_attempts: 3,
        retry_base: Duration::from_secs(10),
    };
    let lease = Duration::from_secs(30);
    enqueue(&db, &env, scope, "fact-1", "agg-a").await;

    let store = db.store();
    let queue = store.scoped(scope);
    let queue = queue.outbox();

    // Attempts one and two: retried, each with a later gate than the last (the doubling).
    let mut gates = Vec::new();
    for attempt in 1..=2_i32 {
        let claimed = queue
            .claim(&env, CONSUMER, lease, 100)
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1, "attempt {attempt} claims the message");
        assert_eq!(
            claimed[0].attempts,
            attempt - 1,
            "the claim reports the attempts made BEFORE this one"
        );
        match queue
            .fail(&env, &claimed[0], "http_status_503", policy)
            .await
            .expect("fail")
        {
            FailureOutcome::Retrying {
                attempts,
                next_attempt_at_unix_micros,
            } => {
                assert_eq!(attempts, attempt);
                gates.push(next_attempt_at_unix_micros);
            }
            other => panic!("attempt {attempt} must retry, got {other:?}"),
        }
        // The gate is REAL: the message is not claimable until the clock reaches it, so a
        // hot-looping worker cannot burn the whole schedule in one pass.
        assert!(
            queue
                .claim(&env, CONSUMER, lease, 100)
                .await
                .expect("claim")
                .is_empty(),
            "the backoff gate hides the message until it is due"
        );
        clock.advance(Duration::from_secs(4_000));
    }
    assert!(
        gates[1] > gates[0],
        "the backoff grows: {gates:?} must be increasing"
    );

    // The third attempt reaches the bound and dead-letters.
    let claimed = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].attempts, 2);
    assert_eq!(
        queue
            .fail(&env, &claimed[0], "http_status_503", policy)
            .await
            .expect("fail"),
        FailureOutcome::DeadLettered { attempts: 3 },
        "the third of three attempts is terminal"
    );

    // Terminal means terminal: never claimable again, gone from the pending peek, still
    // in the full listing with its last error, and counted as a dead letter.
    clock.advance(Duration::from_secs(86_400));
    assert!(
        queue
            .claim(&env, CONSUMER, lease, 100)
            .await
            .expect("claim")
            .is_empty(),
        "a dead-lettered message never drains again"
    );
    assert!(pending_keys(&db, scope).await.is_empty());
    let listed = queue.list(CONSUMER, 100).await.expect("list");
    assert_eq!(listed.len(), 1, "the dead letter is still on the record");
    assert_eq!(listed[0].attempts, 3);
    assert_eq!(listed[0].last_error.as_deref(), Some("http_status_503"));
    assert!(listed[0].dead_lettered_at_unix_micros.is_some());
    assert!(listed[0].completed_at_unix_micros.is_none());
    let depth = queue.depth(&env, CONSUMER, lease).await.expect("depth");
    assert_eq!(
        depth,
        ironauth_store::OutboxDepth {
            ready: 0,
            in_flight: 0,
            scheduled: 0,
            dead_lettered: 1,
            completed: 0,
        },
        "the dead letter is the number an alert fires on"
    );
}

#[tokio::test]
async fn failing_a_foreign_or_malformed_id_is_a_uniform_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    enqueue(&db, &env, scope_a, "fact-1", "agg-a").await;

    let store = db.store();
    // A REAL claimed message, so its fencing token is live and the only thing wrong with
    // the calls below is the scope or the id. Presenting an unleased message would fail
    // for the wrong reason and this test would measure nothing about the boundary.
    let a = store.scoped(scope_a);
    let a = a.outbox();
    let held = a
        .claim(&env, CONSUMER, Duration::from_secs(60), 100)
        .await
        .expect("claim")
        .remove(0);
    assert!(held.lease_stamp_unix_micros.is_some());
    let mut malformed = held.clone();
    malformed.id = "not-an-id".to_owned();

    let b = store.scoped(scope_b);
    let b = b.outbox();
    let policy = RetryPolicy::default();
    // A's live claim, presented in B's scope, and a message whose id is not an id at all:
    // the SAME outcome, so a caller learns nothing about another tenant's queue.
    assert_eq!(
        b.fail(&env, &held, "x", policy).await.expect("foreign"),
        FailureOutcome::NotFound
    );
    assert_eq!(
        b.fail(&env, &malformed, "x", policy)
            .await
            .expect("malformed"),
        FailureOutcome::NotFound
    );
    assert!(!b.complete(&env, &held).await.expect("foreign complete"));
    // The control at the other end: the same call in A's OWN scope, with the same live
    // token, does flip. Without this the three refusals above would pass just as well
    // against a `complete` that refused everything.
    assert!(
        a.complete(&env, &held).await.expect("own-scope complete"),
        "the identical call inside A's scope succeeds: the refusals are about the \
         boundary, not about the message"
    );
    assert!(pending_keys(&db, scope_a).await.is_empty());
}

// ---------------------------------------------------------------------------
// 4. Per-aggregate ordering, under concurrency.

#[tokio::test]
async fn one_aggregates_messages_are_never_in_flight_together_and_arrive_in_order() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 13);
    let scope = db.seed_scope(&env).await;
    let lease = Duration::from_secs(30);
    // Three messages of ONE aggregate, plus one of another so the queue is not trivially
    // serial and a claim that simply returned "the oldest one row" could not pass. All
    // four are enqueued from NON-OVERLAPPING transactions, which is the producer
    // precondition the strong ordering form requires; see the OutboxRepo type docs.
    let first = enqueue(&db, &env, scope, "a-1", "agg-a").await;
    let second = enqueue(&db, &env, scope, "a-2", "agg-a").await;
    let third = enqueue(&db, &env, scope, "a-3", "agg-a").await;
    let other = enqueue(&db, &env, scope, "b-1", "agg-b").await;

    let store = db.store();
    let queue = store.scoped(scope);
    let queue = queue.outbox();

    // A batch large enough for all four returns exactly TWO: the head of each group.
    let claimed = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("claim");
    let ids: Vec<&str> = claimed.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![first.as_str(), other.as_str()],
        "one message per ordering group, and the group's OLDEST, not an arbitrary one"
    );
    // Retire the other group's message so the rest of this test observes agg-a alone.
    // Left non-terminal it would reappear on every clock advance below (its lease lapses)
    // and every assertion about "what came back" would be about two groups at once.
    assert!(
        queue
            .complete(&env, &claimed[1])
            .await
            .expect("complete b-1")
    );

    // The head is in flight. Its group is blocked even though a worker is idle and a
    // second message of that group is due: this is the cost the ordering guarantee buys.
    assert!(
        queue
            .claim(&env, CONSUMER, lease, 100)
            .await
            .expect("claim")
            .is_empty(),
        "a-2 must not be claimable while a-1 is in flight"
    );

    // A FAILED head keeps blocking. This is the case that separates a real ordering rule
    // from one that keys on the lease: a-1 is no longer leased (fail releases it), but it
    // is not terminal either, so a-2 must still wait.
    assert!(matches!(
        queue
            .fail(&env, &claimed[0], "http_status_503", RetryPolicy::default())
            .await
            .expect("fail the head"),
        FailureOutcome::Retrying { .. }
    ));
    clock.advance(Duration::from_secs(3_600));
    let after_failure = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("claim");
    assert_eq!(
        after_failure
            .iter()
            .map(|m| m.id.clone())
            .collect::<Vec<_>>(),
        vec![first.clone()],
        "the failed head is retried; a-2 is STILL blocked behind it"
    );

    // Completing the head releases exactly one successor, never the whole group. The
    // token presented is the one the RE-CLAIM stamped, not the original: a lease is
    // per-claim, and the earlier one is dead.
    assert!(
        queue
            .complete(&env, &after_failure[0])
            .await
            .expect("complete a-1")
    );
    clock.advance(Duration::from_secs(3_600));
    let released = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("claim");
    assert_eq!(
        released.iter().map(|m| m.id.clone()).collect::<Vec<_>>(),
        vec![second.clone()],
        "a-2 is released, a-3 is not: the group advances one message at a time"
    );

    // A DEAD LETTER also releases the group. It must, or a poison message would wedge its
    // aggregate forever, which is the reason the attempts bound has to be finite.
    assert_eq!(
        queue
            .fail(
                &env,
                &released[0],
                "poison",
                RetryPolicy {
                    max_attempts: 1,
                    retry_base: Duration::from_secs(10),
                },
            )
            .await
            .expect("dead-letter a-2"),
        FailureOutcome::DeadLettered { attempts: 1 }
    );
    let after_dead_letter = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("claim");
    assert_eq!(
        after_dead_letter
            .iter()
            .map(|m| m.id.clone())
            .collect::<Vec<_>>(),
        vec![third.clone()],
        "a dead letter is terminal, so it unblocks its group"
    );
}

#[tokio::test]
async fn concurrent_workers_never_take_two_messages_of_one_aggregate() {
    // The concurrency half of the ordering rule. Worker A does exactly what a real claim
    // does to the group's head: it takes the row lock AND STAMPS `claimed_at`, in an
    // uncommitted transaction, standing in for a worker mid-handler on another replica.
    //
    // The stamp is the point. Under READ COMMITTED, worker B cannot see A's uncommitted
    // `claimed_at`: to B the head still reads as unleased. So a claim whose head-of-group
    // test keyed on the LEASE rather than on TERMINALITY would conclude that agg-a has no
    // live head and hand a-2 to B, putting two messages of one aggregate in flight. The
    // rule keys on terminality instead, and A's stamp changes neither terminal marker, so
    // the correct answer is that B takes NOTHING from that group: not the head (skip
    // locked) and not its successor (the head is still non-terminal).
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 23);
    let scope = db.seed_scope(&env).await;
    enqueue(&db, &env, scope, "a-1", "agg-a").await;
    enqueue(&db, &env, scope, "a-2", "agg-a").await;
    let free = enqueue(&db, &env, scope, "b-1", "agg-b").await;

    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let mut worker_a = db.app_pool().begin().await.expect("begin worker A");
    bind_scope(&mut worker_a, &tenant, &environment).await;
    // The lease instant comes from the CLOCK SEAM and is written in the same epoch
    // microseconds dialect the repository uses, so this stand-in worker is stamping the
    // column the real claim stamps, with a value of the real shape.
    let now_micros = epoch_micros_of(&env);
    // A MATERIALIZED CTE, exactly as the real claim uses, so the `LIMIT 1` is a bound
    // rather than a suggestion; see the note on `OutboxRepo::claim`.
    let held = sqlx::query(
        "WITH picked AS MATERIALIZED ( \
             SELECT id AS picked_id FROM outbox_messages \
             WHERE tenant_id = $1 AND environment_id = $2 AND consumer = $3 \
             AND ordering_key = 'agg-a' AND completed_at IS NULL AND dead_lettered_at IS NULL \
             ORDER BY sequence LIMIT 1 FOR UPDATE SKIP LOCKED) \
         UPDATE outbox_messages \
         SET claimed_at = TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval \
         FROM picked WHERE outbox_messages.id = picked.picked_id \
         RETURNING id",
    )
    .bind(&tenant)
    .bind(&environment)
    .bind(CONSUMER)
    .bind(now_micros)
    .fetch_all(&mut *worker_a)
    .await
    .expect("worker A leases the head");
    let held_ids: Vec<String> = held
        .iter()
        .map(|r| sqlx::Row::get::<String, _>(r, "id"))
        .collect();
    assert_eq!(
        held.len(),
        1,
        "worker A holds and has stamped agg-a's head; got {held_ids:?}"
    );

    let b_claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(&env, CONSUMER, Duration::from_secs(60), 100)
        .await
        .expect("worker B claims concurrently");
    assert_eq!(
        b_claimed.iter().map(|m| m.id.clone()).collect::<Vec<_>>(),
        vec![free],
        "B takes the free group's message and NOTHING from agg-a: not the locked head \
         (skip-locked) and not a-2 (the head is still non-terminal)"
    );
    worker_a.rollback().await.expect("worker A rolls back");
}

// ---------------------------------------------------------------------------
// 5. The consumer framework.

/// A consumer that records what it was handed and answers from a programmable script.
struct ScriptedConsumer {
    name: String,
    handled: std::sync::Mutex<Vec<String>>,
    outcome: std::sync::Mutex<Option<ConsumerError>>,
    calls: AtomicUsize,
}

impl ScriptedConsumer {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_owned(),
            handled: std::sync::Mutex::new(Vec::new()),
            outcome: std::sync::Mutex::new(None),
            calls: AtomicUsize::new(0),
        })
    }

    fn fail_with(&self, error: ConsumerError) {
        *self.outcome.lock().expect("outcome lock") = Some(error);
    }

    fn handled(&self) -> Vec<String> {
        self.handled.lock().expect("handled lock").clone()
    }

    /// How many times `handle` was ENTERED, counted before anything else it does. It is
    /// the only number that can distinguish "handled once" from "handled twice", which
    /// the deduplicated `handled` list by construction cannot.
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl OutboxConsumer for ScriptedConsumer {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        _env: &'a Env,
        _scope: Scope,
        message: &'a OutboxMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ConsumerError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.handled
                .lock()
                .expect("handled lock")
                .push(message.idempotency_key.clone());
            match self.outcome.lock().expect("outcome lock").clone() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        })
    }
}

#[tokio::test]
async fn the_registry_refuses_two_consumers_under_one_name() {
    let mut registry = ConsumerRegistry::new();
    assert!(registry.is_empty());
    registry
        .register(ScriptedConsumer::new("webhooks"))
        .expect("first registration");
    registry
        .register(ScriptedConsumer::new("siem"))
        .expect("a distinct name registers");
    let clash = registry
        .register(ScriptedConsumer::new("webhooks"))
        .expect_err("a duplicate name must be refused");
    assert_eq!(clash.name, "webhooks");
    // Refused, not silently replaced: both original registrations survive, so the
    // failure cannot present as "some events just never arrive".
    assert_eq!(registry.len(), 2);
    assert_eq!(registry.names(), vec!["siem", "webhooks"]);
    assert!(registry.get("webhooks").is_some());
    assert!(registry.get("nobody").is_none());
}

#[tokio::test]
async fn a_worker_completes_retries_and_dead_letters_through_the_consumer_seam() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 17);
    let scope = db.seed_scope(&env).await;
    let consumer = ScriptedConsumer::new(CONSUMER);
    let settings = WorkerSettings {
        concurrency: 3,
        visibility_timeout: Duration::from_secs(30),
        poll_interval: Duration::from_millis(10),
        batch: 64,
        retry: RetryPolicy {
            max_attempts: 2,
            retry_base: Duration::from_secs(10),
        },
    };
    let worker = OutboxWorker::new(
        db.store().clone(),
        env.clone(),
        Arc::clone(&consumer) as Arc<dyn OutboxConsumer>,
        settings,
    );
    assert_eq!(worker.consumer_name(), CONSUMER);

    // A successful pass completes what it claimed.
    enqueue(&db, &env, scope, "ok-1", "agg-ok").await;
    assert_eq!(
        worker.run_once(scope).await.expect("pass"),
        DrainStats {
            claimed: 1,
            completed: 1,
            retried: 0,
            dead_lettered: 0,
            lease_lost: 0
        }
    );
    assert_eq!(consumer.handled(), vec!["ok-1".to_owned()]);
    assert!(pending_keys(&db, scope).await.is_empty());

    // A RETRYABLE failure schedules a retry; the bound then dead-letters it.
    enqueue(&db, &env, scope, "flaky-1", "agg-flaky").await;
    consumer.fail_with(ConsumerError::retryable("http_status_503"));
    assert_eq!(
        worker.run_once(scope).await.expect("pass"),
        DrainStats {
            claimed: 1,
            completed: 0,
            retried: 1,
            dead_lettered: 0,
            lease_lost: 0
        }
    );
    clock.advance(Duration::from_secs(3_600));
    assert_eq!(
        worker.run_once(scope).await.expect("pass"),
        DrainStats {
            claimed: 1,
            completed: 0,
            retried: 0,
            dead_lettered: 1,
            lease_lost: 0
        },
        "the second of two attempts reaches the bound"
    );

    // A PERMANENT failure dead-letters on the FIRST attempt, without burning the
    // schedule. That matters beyond politeness: while a message is retrying it blocks its
    // aggregate, so retrying something that can never succeed blocks real work.
    enqueue(&db, &env, scope, "poison-1", "agg-poison").await;
    consumer.fail_with(ConsumerError::permanent("unparseable_payload"));
    assert_eq!(
        worker.run_once(scope).await.expect("pass"),
        DrainStats {
            claimed: 1,
            completed: 0,
            retried: 0,
            dead_lettered: 1,
            lease_lost: 0
        },
        "a permanent failure is terminal at once, not after the whole schedule"
    );
    let listed = db
        .store()
        .scoped(scope)
        .outbox()
        .list(CONSUMER, 100)
        .await
        .expect("list");
    let poison = listed
        .iter()
        .find(|m| m.idempotency_key == "poison-1")
        .expect("the poison message is on the record");
    assert_eq!(poison.attempts, 1, "one attempt, not the full bound");
    assert_eq!(poison.last_error.as_deref(), Some("unparseable_payload"));
    assert!(poison.dead_lettered_at_unix_micros.is_some());
}

#[tokio::test]
async fn the_pool_runs_every_configured_worker_and_drains_to_completion() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let consumer = ScriptedConsumer::new(CONSUMER);
    // Eight messages in eight groups, so the pool's workers can genuinely run in
    // parallel rather than serialize behind one aggregate.
    for n in 0..8 {
        enqueue(&db, &env, scope, &format!("fact-{n}"), &format!("agg-{n}")).await;
    }

    let settings = WorkerSettings {
        concurrency: 4,
        visibility_timeout: Duration::from_secs(30),
        poll_interval: Duration::from_millis(10),
        batch: 2,
        retry: RetryPolicy::default(),
    };
    let scopes: Arc<dyn ScopeSource> = Arc::new(StaticScopes::new(vec![scope]));
    let pool = OutboxWorkerPool::spawn(
        &OutboxWorker::new(
            db.store().clone(),
            env.clone(),
            Arc::clone(&consumer) as Arc<dyn OutboxConsumer>,
            settings,
        ),
        &scopes,
        &silent(),
    );
    assert_eq!(
        pool.configured_size(),
        4,
        "the pool is a POOL, not a singleton"
    );
    assert_eq!(pool.size(), 4, "and all four are alive");

    // Wait for the queue to drain. Bounded so a regression fails rather than hangs.
    let mut drained = false;
    for _ in 0..200 {
        if pending_keys(&db, scope).await.is_empty() {
            drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        pool.size(),
        pool.configured_size(),
        "no worker died during the drain"
    );
    pool.shutdown().await;
    assert!(drained, "four workers drained the queue");

    // Every message was handled EXACTLY once, by SOME worker: at-least-once with no
    // duplicate handling in the uncontended case, which is what the lease buys.
    //
    // The "exactly" has to be asserted BEFORE deduplication, and separately on the call
    // counter, or it is not asserted at all: a message handled twice deduplicates back to
    // eight distinct keys and a `dedup`-then-length check cannot fail. The counter is the
    // independent witness, incremented on entry to `handle` before anything else.
    let handled = consumer.handled();
    assert_eq!(
        handled.len(),
        8,
        "eight handler calls, not nine: no message was handled twice. Got {handled:?}"
    );
    assert_eq!(
        consumer.calls(),
        8,
        "the call counter agrees with the recorded list, so neither is silently short"
    );
    let mut distinct = handled;
    distinct.sort();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        8,
        "and the eight calls were eight DISTINCT messages"
    );
    let listed = db
        .store()
        .scoped(scope)
        .outbox()
        .list(CONSUMER, 100)
        .await
        .expect("list");
    assert_eq!(listed.len(), 8);
    assert!(
        listed.iter().all(|m| m.completed_at_unix_micros.is_some()),
        "every message reached the terminal success state"
    );
}

// ---------------------------------------------------------------------------
// 6. The fencing token: a stale worker cannot record an outcome a live one owns.

#[tokio::test]
async fn a_stale_lease_holder_can_neither_complete_nor_fail_a_message_a_live_worker_holds() {
    // The half of the ordering break that lives in the LIFECYCLE writes rather than in the
    // claim. Worker A claims, stalls past the visibility timeout, and worker B legitimately
    // re-claims. Without a fencing token A's `complete` still succeeds, which retires a
    // message B is inside its handler for AND releases the ordering group, handing B's
    // successor out while B has not finished the predecessor. The same shape lets a stale
    // A dead-letter what B holds.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 29);
    let scope = db.seed_scope(&env).await;
    let lease = Duration::from_secs(30);
    let store = db.store();
    let queue = store.scoped(scope);
    let queue = queue.outbox();

    // Two messages in ONE group, so the consequence of a stale retirement is visible: it
    // would release the successor.
    enqueue(&db, &env, scope, "a-1", "agg-a").await;
    enqueue(&db, &env, scope, "a-2", "agg-a").await;

    let a_held = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("worker A claims")
        .remove(0);
    // A stalls past its lease; B re-claims the SAME message under a new one.
    clock.advance(lease + Duration::from_micros(1));
    let b_held = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("worker B re-claims")
        .remove(0);
    assert_eq!(
        b_held.id, a_held.id,
        "B re-claimed the very message A holds"
    );
    assert_ne!(
        b_held.lease_stamp_unix_micros, a_held.lease_stamp_unix_micros,
        "and it carries a different lease: the token is what tells them apart"
    );

    // A wakes up and reports success on a message it no longer holds. Refused.
    assert!(
        !queue.complete(&env, &a_held).await.expect("stale complete"),
        "a stale holder's completion is refused"
    );
    // A wakes up and reports failure instead. Also refused, and it burns no attempt: the
    // counter belongs to the worker that actually made the attempt.
    assert_eq!(
        queue
            .fail(
                &env,
                &a_held,
                "a_was_stale",
                RetryPolicy {
                    max_attempts: 1,
                    retry_base: Duration::from_secs(10),
                },
            )
            .await
            .expect("stale fail"),
        FailureOutcome::NotFound,
        "a stale holder cannot dead-letter the message the live worker holds"
    );

    // The consequences, measured rather than assumed. The message is still B's, still
    // non-terminal, still un-attempted, and its successor is still blocked behind it.
    let listed = queue.list(CONSUMER, 100).await.expect("list");
    let target = listed
        .iter()
        .find(|m| m.id == b_held.id)
        .expect("the contested message is on the record");
    assert_eq!(
        target.attempts, 0,
        "no attempt was burned by the stale worker"
    );
    assert_eq!(
        target.last_error, None,
        "and no failure label was written over the live worker's message"
    );
    assert!(target.completed_at_unix_micros.is_none());
    assert!(target.dead_lettered_at_unix_micros.is_none());
    assert_eq!(
        pending_keys(&db, scope).await,
        vec!["a-1".to_owned(), "a-2".to_owned()],
        "both are still pending: the group was not released under B"
    );

    // The control at the other end: B, holding the live lease, CAN complete it, and that
    // is what releases a-2. Without this the four refusals above would pass equally
    // against a `complete` and a `fail` that refused everything.
    assert!(
        queue.complete(&env, &b_held).await.expect("live complete"),
        "the live holder's completion is accepted"
    );
    let released = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("claim after release");
    assert_eq!(
        released
            .iter()
            .map(|m| m.idempotency_key.clone())
            .collect::<Vec<_>>(),
        vec!["a-2".to_owned()],
        "the successor is released by the LIVE worker's completion, and only by it"
    );
}

#[tokio::test]
async fn four_concurrent_failures_each_count_exactly_one_attempt_under_the_row_lock() {
    // `fail` reads the attempts counter and then writes it back, which is a
    // read-modify-write, and the `FOR UPDATE` on the read is the only thing that makes it
    // atomic. That claim was previously unmeasured: deleting the `FOR UPDATE` left the
    // entire shipped suite green.
    //
    // Four callers present the SAME live lease token concurrently. Correct behaviour is
    // that exactly one of them lands: the row lock serializes them, the first releases the
    // lease as part of recording the attempt, and the other three then find no row
    // matching that token. With the lock deleted all four read `attempts = 0` from the
    // same snapshot, all four report attempt 1, and the counter advances once for four
    // recorded attempts.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    // A pool wide enough that four concurrent transactions really are concurrent; on a
    // narrower pool they would serialize on connection acquisition and this test would
    // measure nothing.
    let store = db.app_store_with_pool(8).await;
    enqueue(&db, &env, scope, "fact-1", "agg-a").await;

    let held = {
        let queue = store.scoped(scope);
        queue
            .outbox()
            .claim(&env, CONSUMER, Duration::from_secs(300), 100)
            .await
            .expect("claim")
            .remove(0)
    };

    let policy = RetryPolicy {
        max_attempts: 2,
        retry_base: Duration::from_secs(10),
    };
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let store = store.clone();
        let env = env.clone();
        let held = held.clone();
        tasks.push(tokio::spawn(async move {
            let queue = store.scoped(scope);
            queue
                .outbox()
                .fail(&env, &held, "concurrent", policy)
                .await
                .expect("fail")
        }));
    }
    let mut retried = 0;
    let mut dead_lettered = 0;
    let mut not_found = 0;
    for task in tasks {
        match task.await.expect("the failure task did not panic") {
            FailureOutcome::Retrying { attempts, .. } => {
                assert_eq!(attempts, 1, "the one attempt that lands is the FIRST");
                retried += 1;
            }
            FailureOutcome::DeadLettered { .. } => dead_lettered += 1,
            FailureOutcome::NotFound => not_found += 1,
        }
    }
    assert_eq!(
        (retried, dead_lettered, not_found),
        (1, 0, 3),
        "exactly one of four concurrent reports of the same attempt is recorded"
    );

    let listed = store
        .scoped(scope)
        .outbox()
        .list(CONSUMER, 100)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].attempts, 1,
        "the counter advanced once, for the one recorded attempt"
    );
    assert!(
        listed[0].dead_lettered_at_unix_micros.is_none(),
        "a two-attempt bound is NOT reached by one attempt, whatever the concurrency"
    );
}

// ---------------------------------------------------------------------------
// 7. The batch does not share one lease, and a consumer panic does not kill a worker.

#[tokio::test]
async fn renewing_a_lease_protects_the_message_being_handled_and_refuses_a_stolen_one() {
    // The absolute claim, "two workers never hold the same message", is false for a BATCH
    // that shares one lease: at the shipped defaults (claim_batch 64, visibility 30s) any
    // handler slower than about 469ms puts the tail of a batch past its own lease, and
    // another worker starts redelivering messages this one has not reached yet.
    //
    // Two messages, ONE claim, ONE stamp, a three-second lease, and then four seconds of
    // work. The message that was RENEWED at the two-second mark is still ours at four
    // seconds; the identical message that was not is gone. That contrast is the whole
    // measurement, and it is why the visibility timeout is now a deadline on one handler
    // rather than on the batch.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 31);
    let scope = db.seed_scope(&env).await;
    let lease = Duration::from_secs(3);
    let first = enqueue(&db, &env, scope, "fact-0", "agg-0").await;
    let second = enqueue(&db, &env, scope, "fact-1", "agg-1").await;
    let store = db.store();
    let queue = store.scoped(scope);
    let queue = queue.outbox();

    let mut batch = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("claim the batch");
    assert_eq!(batch.len(), 2, "one batch, two messages");
    assert_eq!(
        batch[0].lease_stamp_unix_micros, batch[1].lease_stamp_unix_micros,
        "the claim stamps the whole batch at ONE instant, which is the condition that \
         makes the tail's lease stale"
    );
    let (head, tail) = batch.split_at_mut(1);
    let (head, tail) = (&mut head[0], &mut tail[0]);
    assert_eq!(head.id, first);
    assert_eq!(tail.id, second);

    // Two seconds of handling the head, still inside the shared lease.
    clock.advance(Duration::from_secs(2));
    let before = head.lease_stamp_unix_micros;
    assert!(
        queue.renew_lease(&env, head).await.expect("renew the head"),
        "the head is still ours at two seconds"
    );
    assert!(
        head.lease_stamp_unix_micros > before,
        "the renewal MOVED the token; one that did not would leave the message exactly \
         as exposed as before"
    );

    // Two more seconds. The shared claim stamp is now four seconds old, past the
    // three-second lease. A competing worker sweeps.
    clock.advance(Duration::from_secs(2));
    let stolen = queue
        .claim(&env, CONSUMER, lease, 100)
        .await
        .expect("a competing worker sweeps");
    assert_eq!(
        stolen.iter().map(|m| m.id.clone()).collect::<Vec<_>>(),
        vec![second.clone()],
        "the RENEWED head is invisible to the competing worker and the un-renewed tail is \
         not: without the renewal both would have been taken while this worker still \
         intended to handle them"
    );

    // The head's renewed token is what authorizes its completion, and it still works.
    assert!(
        queue.complete(&env, head).await.expect("complete the head"),
        "the renewed lease is a real lease: it authorizes the write"
    );
    // The tail is gone, and the worker that lost it learns so BEFORE handling it, which is
    // what turns a double delivery into a clean hand-off.
    assert!(
        !queue.renew_lease(&env, tail).await.expect("stale renew"),
        "a worker whose message has been taken cannot renew it back, and must skip it"
    );
}

/// A slow consumer that, part way through its worker's batch, lets ANOTHER worker sweep.
///
/// It stands in for the thing that cannot be scheduled deterministically: a second replica
/// claiming while this one is inside a handler. Every call burns `per_message` of manual
/// clock, exactly as a slow handler does; on the second call it also issues a competing
/// claim, which is that replica's sweep.
struct StealingConsumer {
    name: String,
    store: ironauth_store::Store,
    scope: Scope,
    clock: Arc<ironauth_env::ManualClock>,
    lease: Duration,
    per_message: Duration,
    /// Which call (1-based) issues the competing claim.
    steal_on_call: usize,
    handled: std::sync::Mutex<Vec<String>>,
    stolen: std::sync::Mutex<Vec<String>>,
}

impl OutboxConsumer for StealingConsumer {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        _scope: Scope,
        message: &'a OutboxMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ConsumerError>> + Send + 'a>>
    {
        Box::pin(async move {
            let call = {
                let mut handled = self.handled.lock().expect("handled lock");
                handled.push(message.idempotency_key.clone());
                handled.len()
            };
            self.clock.advance(self.per_message);
            if call == self.steal_on_call {
                let queue = self.store.scoped(self.scope);
                let taken = queue
                    .outbox()
                    .claim(env, &self.name, self.lease, 100)
                    .await
                    .expect("the competing worker claims");
                *self.stolen.lock().expect("stolen lock") =
                    taken.into_iter().map(|m| m.idempotency_key).collect();
            }
            Ok(())
        })
    }
}

#[tokio::test]
async fn a_pass_keeps_what_it_renewed_and_skips_what_another_worker_took() {
    // The worker-level half of the same property, and the two halves of it in one pass.
    //
    // Three messages, one claim, one stamp, a three-second lease, and a handler that burns
    // two seconds each. When the competing worker sweeps at the four-second mark, the
    // shared claim stamp is one second stale, so every message that still carries it is
    // takeable. The message currently being handled does NOT still carry it: `run_once`
    // re-stamped it two seconds in. So the sweep takes the untouched tail and leaves the
    // one in flight alone, and the worker then SKIPS the tail rather than handing it to
    // the consumer a second time.
    //
    // Without the re-stamp both would go, the pass would report a second lost message, and
    // the consumer would have been called for a message another worker was already
    // handling.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 43);
    let scope = db.seed_scope(&env).await;
    let lease = Duration::from_secs(3);
    for n in 0..3 {
        enqueue(&db, &env, scope, &format!("fact-{n}"), &format!("agg-{n}")).await;
    }
    let consumer = Arc::new(StealingConsumer {
        name: CONSUMER.to_owned(),
        store: db.store().clone(),
        scope,
        clock: Arc::clone(&clock),
        lease,
        per_message: Duration::from_secs(2),
        steal_on_call: 2,
        handled: std::sync::Mutex::new(Vec::new()),
        stolen: std::sync::Mutex::new(Vec::new()),
    });
    let worker = OutboxWorker::new(
        db.store().clone(),
        env.clone(),
        Arc::clone(&consumer) as Arc<dyn OutboxConsumer>,
        WorkerSettings {
            concurrency: 1,
            visibility_timeout: lease,
            poll_interval: Duration::from_millis(10),
            batch: 64,
            retry: RetryPolicy::default(),
        },
    );

    assert_eq!(
        worker.run_once(scope).await.expect("pass"),
        DrainStats {
            claimed: 3,
            completed: 2,
            retried: 0,
            dead_lettered: 0,
            lease_lost: 1
        },
        "three claimed, two carried through a pass four times longer than the visibility \
         timeout, and the one another worker took reported as lost rather than handled twice"
    );
    assert_eq!(
        consumer.stolen.lock().expect("stolen lock").as_slice(),
        ["fact-2".to_owned()],
        "the competing sweep took ONLY the un-renewed tail: the message in flight was \
         invisible to it, which is the property under test"
    );
    assert_eq!(
        consumer.handled.lock().expect("handled lock").as_slice(),
        ["fact-0".to_owned(), "fact-1".to_owned()],
        "and the consumer was never called for the message it no longer held"
    );

    // Nothing was lost. The one that moved is non-terminal, un-attempted, and held by the
    // worker that took it.
    let listed = db
        .store()
        .scoped(scope)
        .outbox()
        .list(CONSUMER, 100)
        .await
        .expect("list");
    let outstanding: Vec<&OutboxMessage> = listed
        .iter()
        .filter(|m| m.completed_at_unix_micros.is_none())
        .collect();
    assert_eq!(
        outstanding
            .iter()
            .map(|m| m.idempotency_key.clone())
            .collect::<Vec<_>>(),
        vec!["fact-2".to_owned()]
    );
    assert!(
        outstanding[0].attempts == 0 && outstanding[0].dead_lettered_at_unix_micros.is_none(),
        "a lost lease is not a failure: no attempt is burned and nothing is dead-lettered"
    );
}

/// A consumer that PANICS on any message whose idempotency key starts with `poison`, and
/// records every other message it is handed.
///
/// The panic is raised with no lock held, deliberately: a panic inside a `std::sync::Mutex`
/// guard would poison the mutex and every later call would fail for that reason instead,
/// which would make this fixture measure lock poisoning rather than panic containment.
struct PanickingConsumer {
    name: String,
    handled: std::sync::Mutex<Vec<String>>,
}

impl PanickingConsumer {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_owned(),
            handled: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn handled(&self) -> Vec<String> {
        self.handled.lock().expect("handled lock").clone()
    }
}

impl OutboxConsumer for PanickingConsumer {
    fn name(&self) -> &str {
        &self.name
    }

    fn handle<'a>(
        &'a self,
        _env: &'a Env,
        _scope: Scope,
        message: &'a OutboxMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ConsumerError>> + Send + 'a>>
    {
        Box::pin(async move {
            let poison = message.idempotency_key.starts_with("poison");
            if !poison {
                self.handled
                    .lock()
                    .expect("handled lock")
                    .push(message.idempotency_key.clone());
                return Ok(());
            }
            // A yield first, so the panic happens on a poll AFTER the first one and the
            // containment is measured against a future that has genuinely suspended,
            // which is the shape a real handler (an HTTP call) has.
            tokio::task::yield_now().await;
            panic!("this consumer has a bug");
        })
    }
}

#[tokio::test]
async fn a_panicking_consumer_costs_its_message_an_attempt_and_costs_the_pool_nothing() {
    // Measured before the fix: a panic aborted the spawned task, `shutdown` swallowed the
    // `JoinError`, `size()` kept reporting the spawn count, and healthy work in a DIFFERENT
    // ordering group was never handled again. The poison message stayed at attempts 0
    // forever, because the only thing that counts an attempt is a `fail` that never ran, so
    // the finite bound never fired and that aggregate was wedged permanently too.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 37);
    let scope = db.seed_scope(&env).await;
    let consumer = PanickingConsumer::new(CONSUMER);
    let settings = WorkerSettings {
        concurrency: 2,
        visibility_timeout: Duration::from_secs(30),
        poll_interval: Duration::from_millis(10),
        batch: 64,
        retry: RetryPolicy {
            max_attempts: 2,
            retry_base: Duration::from_secs(10),
        },
    };
    let worker = OutboxWorker::new(
        db.store().clone(),
        env.clone(),
        Arc::clone(&consumer) as Arc<dyn OutboxConsumer>,
        settings,
    );

    // One poison message and one healthy message, in DIFFERENT ordering groups, claimed in
    // the same batch. The pass must survive the panic and go on to handle the healthy one.
    enqueue(&db, &env, scope, "poison-1", "agg-poison").await;
    enqueue(&db, &env, scope, "ok-1", "agg-ok").await;
    assert_eq!(
        worker.run_once(scope).await.expect("the pass survives"),
        DrainStats {
            claimed: 2,
            completed: 1,
            retried: 1,
            dead_lettered: 0,
            lease_lost: 0
        },
        "the panic is one message's retryable failure, not the pass's death"
    );
    assert_eq!(
        consumer.handled(),
        vec!["ok-1".to_owned()],
        "the healthy message in the other group was handled in the SAME pass"
    );

    // The attempt was counted and labelled, which is what makes the finite bound reachable.
    let poison_row = |listed: Vec<OutboxMessage>| {
        listed
            .into_iter()
            .find(|m| m.idempotency_key == "poison-1")
            .expect("the poison message is on the record")
    };
    let after_first = poison_row(
        db.store()
            .scoped(scope)
            .outbox()
            .list(CONSUMER, 100)
            .await
            .expect("list"),
    );
    assert_eq!(
        after_first.attempts, 1,
        "a caught panic COUNTS: at attempts 0 the bound would never be reached"
    );
    assert_eq!(after_first.last_error.as_deref(), Some("consumer_panic"));

    // And the bound is reached: the second attempt dead-letters it, which is also what
    // releases its ordering group.
    clock.advance(Duration::from_secs(3_600));
    assert_eq!(
        worker.run_once(scope).await.expect("second pass"),
        DrainStats {
            claimed: 1,
            completed: 0,
            retried: 0,
            dead_lettered: 1,
            lease_lost: 0
        },
        "a repeatedly panicking consumer dead-letters its message rather than looping"
    );
    let final_row = poison_row(
        db.store()
            .scoped(scope)
            .outbox()
            .list(CONSUMER, 100)
            .await
            .expect("list"),
    );
    assert_eq!(final_row.attempts, 2);
    assert!(final_row.dead_lettered_at_unix_micros.is_some());
}

#[tokio::test]
async fn a_pool_survives_a_poison_message_and_keeps_draining_other_aggregates() {
    // The pool half of the containment property, and the one that names the failure the
    // framework's whole "never a singleton" argument is about. Measured before the fix:
    // two workers, one poison message, and afterwards healthy work in a DIFFERENT ordering
    // group was never handled, because both worker tasks had died on the panic and nothing
    // reported it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let consumer = PanickingConsumer::new(CONSUMER);
    let worker = OutboxWorker::new(
        db.store().clone(),
        env.clone(),
        Arc::clone(&consumer) as Arc<dyn OutboxConsumer>,
        WorkerSettings {
            concurrency: 2,
            visibility_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_millis(10),
            batch: 64,
            retry: RetryPolicy {
                max_attempts: 2,
                retry_base: Duration::from_secs(10),
            },
        },
    );
    // The poison message FIRST, so a pool that dies on it never reaches the healthy work.
    enqueue(&db, &env, scope, "poison-1", "agg-poison").await;
    for n in 0..4 {
        enqueue(
            &db,
            &env,
            scope,
            &format!("later-{n}"),
            &format!("agg-later-{n}"),
        )
        .await;
    }

    let scopes: Arc<dyn ScopeSource> = Arc::new(StaticScopes::new(vec![scope]));
    let pool = OutboxWorkerPool::spawn(&worker, &scopes, &silent());
    let mut drained = false;
    for _ in 0..200 {
        if consumer.handled().len() == 4 {
            drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        pool.size(),
        pool.configured_size(),
        "both workers are still ALIVE after the poison message"
    );
    pool.shutdown().await;
    assert!(
        drained,
        "healthy work in other ordering groups kept draining; handled {:?}",
        consumer.handled()
    );
    let mut handled = consumer.handled();
    handled.sort();
    assert_eq!(
        handled,
        vec![
            "later-0".to_owned(),
            "later-1".to_owned(),
            "later-2".to_owned(),
            "later-3".to_owned()
        ],
        "each healthy message once, and the poison one never handled successfully"
    );
}

#[tokio::test]
async fn a_fenced_scope_is_not_drained_and_its_work_survives_the_suspension() {
    // A SUSPENDED scope is fenced on the data plane: its issuer will not load, its keys
    // will not sign, everything a handler touches there refuses. Draining it anyway is not
    // merely wasted work, it DESTROYS the queued work: every one of those refusals is a
    // retryable failure, retryable failures burn a finite attempts budget, and a suspension
    // that outlasts the backoff schedule dead-letters everything queued in the scope. The
    // work would be discarded precisely BECAUSE an operator paused the tenant, and resuming
    // would not bring it back.
    //
    // So a fenced scope is skipped before anything is claimed, and the measurement is that
    // the message is untouched (attempts still zero, not merely undelivered) and drains
    // normally the moment the scope is resumed.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let consumer = ScriptedConsumer::new(CONSUMER);
    let worker = OutboxWorker::new(
        db.store().clone(),
        env.clone(),
        Arc::clone(&consumer) as Arc<dyn OutboxConsumer>,
        WorkerSettings {
            concurrency: 1,
            visibility_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(5),
            batch: 64,
            retry: RetryPolicy::default(),
        },
    );
    enqueue(&db, &env, scope, "fact-1", "agg-a").await;

    db.set_environment_serving_state(scope, "suspended").await;
    // Several passes, because ONE pass not draining could be a claim that found nothing
    // due; the attempts assertion below is what distinguishes "skipped" from "failed".
    for _ in 0..3 {
        assert_eq!(
            worker.run_once(scope).await.expect("pass"),
            DrainStats::default(),
            "a fenced scope is not claimed from at all"
        );
    }
    assert!(
        consumer.handled().is_empty(),
        "the handler was never called in a fenced scope"
    );
    let held = db
        .store()
        .scoped(scope)
        .outbox()
        .pending(CONSUMER, 10)
        .await
        .expect("pending");
    assert_eq!(held.len(), 1, "the work is still queued");
    assert_eq!(
        held[0].attempts, 0,
        "and UNTOUCHED: not one attempt was burned against the suspension, which is what          keeps a long suspension from dead-lettering everything queued in the scope"
    );

    // Resumed, it drains normally. Without this the assertions above would also pass
    // against a worker that had simply stopped draining anything.
    db.set_environment_serving_state(scope, "active").await;
    assert_eq!(
        worker.run_once(scope).await.expect("pass"),
        DrainStats {
            claimed: 1,
            completed: 1,
            retried: 0,
            dead_lettered: 0,
            lease_lost: 0
        },
        "a resumed scope drains the work the suspension preserved"
    );
    assert_eq!(consumer.handled(), vec!["fact-1".to_owned()]);
}

/// A consumer that sets a flag the FIRST time it is called: a stand-in for the shutdown
/// signal arriving while a handler is running, which is the only moment the stop check
/// between messages can be distinguished from a stop check around the batch.
struct StoppingConsumer {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handled: std::sync::Mutex<Vec<String>>,
}

impl OutboxConsumer for StoppingConsumer {
    fn name(&self) -> &str {
        CONSUMER
    }

    fn handle<'a>(
        &'a self,
        _env: &'a Env,
        _scope: Scope,
        message: &'a OutboxMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ConsumerError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.handled
                .lock()
                .expect("handled lock")
                .push(message.idempotency_key.clone());
            self.stop.store(true, Ordering::Relaxed);
            Ok(())
        })
    }
}

#[tokio::test]
async fn a_stop_between_messages_abandons_the_rest_of_the_claimed_batch() {
    // What `shutdown().await` actually costs. A pass that only checked the stop flag
    // around its whole batch had to run every message the last claim took, so a stop cost
    // one CLAIM BATCH of handlers rather than one handler: at the shipped `claim_batch` of
    // 64 and a logout request timeout of 10 seconds, about ten minutes of a shutdown an
    // orchestrator resolves with SIGKILL.
    //
    // Driven deterministically rather than by timing: the consumer itself raises the flag
    // as it handles the first message, which is exactly the moment the check has to be read
    // at. Nothing is lost by abandoning the rest, and the last assertion measures that:
    // they are still queued, unattempted, and drain on the next pass.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let consumer = Arc::new(StoppingConsumer {
        stop: Arc::clone(&stop),
        handled: std::sync::Mutex::new(Vec::new()),
    });
    let worker = OutboxWorker::new(
        db.store().clone(),
        env.clone(),
        Arc::clone(&consumer) as Arc<dyn OutboxConsumer>,
        WorkerSettings {
            concurrency: 1,
            visibility_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(5),
            batch: 64,
            retry: RetryPolicy::default(),
        },
    );
    // Four messages in FOUR ordering groups, so all four are claimable at once and the
    // count below is about the stop check rather than about head-of-group blocking.
    for n in 0..4 {
        enqueue(&db, &env, scope, &format!("fact-{n}"), &format!("agg-{n}")).await;
    }

    let stats = worker
        .run_once_until(scope, &stop)
        .await
        .expect("the pass returns rather than erroring when it is stopped");
    assert_eq!(
        stats.claimed, 4,
        "the claim leased the whole batch, which is what makes the rest abandonable rather          than never taken"
    );
    assert_eq!(
        stats.completed, 1,
        "exactly ONE handler ran after the flag was raised inside it"
    );
    assert_eq!(
        consumer.handled.lock().expect("handled lock").len(),
        1,
        "a stop costs one handler, not one claim batch of them"
    );

    // Nothing was lost. The three abandoned messages are leased, not terminal, and not
    // attempted; once their lease lapses another worker or the next boot takes them, which
    // is the same path a crash takes.
    let remaining = db
        .store()
        .scoped(scope)
        .outbox()
        .list(CONSUMER, 100)
        .await
        .expect("list");
    let abandoned: Vec<&OutboxMessage> = remaining
        .iter()
        .filter(|message| message.completed_at_unix_micros.is_none())
        .collect();
    assert_eq!(abandoned.len(), 3, "three were abandoned mid-batch");
    for message in abandoned {
        assert_eq!(
            message.attempts, 0,
            "an abandoned message is not a failed one: it burned no attempt"
        );
        assert!(
            message.dead_lettered_at_unix_micros.is_none(),
            "and it is not terminal"
        );
    }
}

#[tokio::test]
async fn the_pools_size_is_the_live_worker_count_and_falls_when_a_worker_dies() {
    // `size()` must be measured, not remembered. A `ScopeSource` that panics kills the
    // worker task outright (nothing catches a panic in the sweep loop, only in the
    // handler), and a pool that reported its SPAWN count would go on claiming three
    // healthy workers with none left. That is the exact shape of the availability defect
    // this framework exists to avoid, so the count an operator reads has to be live.
    struct PanickingScopes;
    impl ScopeSource for PanickingScopes {
        fn scopes(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Vec<Scope>, ironauth_store::StoreError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async { panic!("the scope source has a bug") })
        }
    }

    let db = TestDatabase::start().await;
    let env = Env::system();
    let consumer = ScriptedConsumer::new(CONSUMER);
    let settings = WorkerSettings {
        concurrency: 3,
        visibility_timeout: Duration::from_secs(30),
        poll_interval: Duration::from_millis(10),
        batch: 8,
        retry: RetryPolicy::default(),
    };
    let scopes: Arc<dyn ScopeSource> = Arc::new(PanickingScopes);
    let pool = OutboxWorkerPool::spawn(
        &OutboxWorker::new(
            db.store().clone(),
            env.clone(),
            Arc::clone(&consumer) as Arc<dyn OutboxConsumer>,
            settings,
        ),
        &scopes,
        &silent(),
    );
    assert_eq!(pool.configured_size(), 3, "three were started");

    let mut empty = false;
    for _ in 0..200 {
        if pool.size() == 0 {
            empty = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        empty,
        "every worker died and `size` says so; it still reports {}",
        pool.size()
    );
    assert_eq!(
        pool.configured_size(),
        3,
        "the configured count is unchanged, which is what makes the gap readable"
    );
    pool.shutdown().await;
}

#[tokio::test]
async fn a_handler_that_outruns_its_own_renewed_lease_reports_lost_rather_than_completed() {
    // The residual case the re-stamp does NOT remove, measured rather than hand-waved. The
    // lease is re-stamped when a handler STARTS, so a handler that runs longer than the
    // whole visibility timeout still loses its message part way through, and its completion
    // is then refused by the fencing token. That is the irreducible meaning of the timeout
    // and the reason its documentation says it must exceed one handler.
    //
    // What must NOT happen is that the pass counts the work as completed anyway: the other
    // worker owns the outcome, will handle the message again, and a pass that reported
    // `completed` here would hide the misconfiguration that caused it.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 53);
    let scope = db.seed_scope(&env).await;
    let lease = Duration::from_secs(3);
    for n in 0..2 {
        enqueue(&db, &env, scope, &format!("fact-{n}"), &format!("agg-{n}")).await;
    }
    let consumer = Arc::new(StealingConsumer {
        name: CONSUMER.to_owned(),
        store: db.store().clone(),
        scope,
        clock: Arc::clone(&clock),
        lease,
        // Longer than the whole visibility timeout: this handler cannot finish in time.
        per_message: lease + Duration::from_secs(1),
        steal_on_call: 1,
        handled: std::sync::Mutex::new(Vec::new()),
        stolen: std::sync::Mutex::new(Vec::new()),
    });
    let worker = OutboxWorker::new(
        db.store().clone(),
        env.clone(),
        Arc::clone(&consumer) as Arc<dyn OutboxConsumer>,
        WorkerSettings {
            concurrency: 1,
            visibility_timeout: lease,
            poll_interval: Duration::from_millis(10),
            batch: 64,
            retry: RetryPolicy::default(),
        },
    );

    assert_eq!(
        worker.run_once(scope).await.expect("pass"),
        DrainStats {
            claimed: 2,
            completed: 0,
            retried: 0,
            dead_lettered: 0,
            lease_lost: 2
        },
        "the handler outran its own renewed lease, so its completion is refused and \
         counted as lost; the message behind it was taken and skipped"
    );
    assert_eq!(
        consumer.handled.lock().expect("handled lock").as_slice(),
        ["fact-0".to_owned()],
        "only the one message this worker actually still held was handled"
    );
    assert_eq!(
        consumer.stolen.lock().expect("stolen lock").len(),
        2,
        "the competing worker took both, which is what makes the refusal correct"
    );
    // Nothing was completed and nothing was failed: the whole batch belongs to the other
    // worker now, un-attempted.
    let listed = db
        .store()
        .scoped(scope)
        .outbox()
        .list(CONSUMER, 100)
        .await
        .expect("list");
    assert_eq!(listed.len(), 2);
    assert!(
        listed.iter().all(|m| m.completed_at_unix_micros.is_none()
            && m.dead_lettered_at_unix_micros.is_none()
            && m.attempts == 0),
        "a lost lease writes nothing at all: not a completion, not an attempt"
    );
}

#[tokio::test]
async fn the_claim_batch_is_a_hard_bound_and_not_a_hint_the_planner_may_decline() {
    // `outbox.claim_batch` is a configured, range-checked knob, and it was not a bound.
    // Written as `WHERE id IN (SELECT ... LIMIT n ...)`, the planner may run the selection
    // once per candidate row instead of once; each rescan re-evaluates the lease gate
    // against the rows the SAME statement has already stamped, so the earlier picks drop
    // out, the next ones replace them, and the whole eligible set is leased. Measured on
    // Postgres 18.4 against one unanalysed table: `LIMIT 3` over ten due messages leased
    // all ten, under a Nested Loop Semi Join with loops=10.
    //
    // What that costs in production is not a rounding error: one worker leases the entire
    // due backlog into memory, under one lease it cannot possibly finish inside, and the
    // batch knob an operator turned down does nothing.
    //
    // Twenty due messages and a batch of three, three times over, with a control at each
    // end: the first claim must be bounded, and the queue must still drain completely, so
    // this cannot be satisfied by a claim that returns nothing.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 47);
    let scope = db.seed_scope(&env).await;
    let lease = Duration::from_secs(30);
    for n in 0..20 {
        enqueue(
            &db,
            &env,
            scope,
            &format!("fact-{n:02}"),
            &format!("agg-{n:02}"),
        )
        .await;
    }
    let store = db.store();
    let queue = store.scoped(scope);
    let queue = queue.outbox();

    let mut seen: Vec<String> = Vec::new();
    for round in 0..3 {
        let batch = queue.claim(&env, CONSUMER, lease, 3).await.expect("claim");
        assert_eq!(
            batch.len(),
            3,
            "round {round} claimed {} messages under a batch of 3",
            batch.len()
        );
        for message in &batch {
            assert!(
                queue.complete(&env, message).await.expect("complete"),
                "the bounded batch is a real claim, not an empty one"
            );
            seen.push(message.idempotency_key.clone());
        }
        // Past any lease, so a round that leased more than it reported would show up as a
        // later round claiming messages that are already retired.
        clock.advance(lease + Duration::from_secs(1));
    }
    assert_eq!(
        seen,
        (0..9).map(|n| format!("fact-{n:02}")).collect::<Vec<_>>(),
        "nine messages in three bounded rounds, in sequence order and each exactly once"
    );
    assert_eq!(
        queue
            .depth(&env, CONSUMER, lease)
            .await
            .expect("depth")
            .ready,
        11,
        "and the other eleven were never leased: a bound that leased everything would \
         leave nothing here"
    );
}

// ---------------------------------------------------------------------------
// 8. The depth gauge, in a state where every counter is distinct and non-zero.

#[tokio::test]
async fn depth_reports_ready_in_flight_scheduled_dead_lettered_and_completed_separately() {
    // `depth` is the observability primitive an exporter reads and an alert fires on, and
    // three of its counters were previously only ever asserted as zero. Measured: the
    // `ready` filter's due gate could be INVERTED (`next_attempt_at > now` instead of
    // `<=`) and the entire suite stayed green.
    //
    // The five counts here are deliberately DISTINCT (1, 2, 3, 4, 5) rather than all one,
    // so a pair of swapped filters is a failure too, not just a wrong predicate.
    //
    // `completed` is the retention counter (issue #104, PR 3). Without it an operator has
    // no number that moves when a reaper works and no number that stands still when one is
    // missing: the other four count non-terminal rows and the dead-letter tail retention
    // keeps forever by default, so none of them could ever show the reapable backlog.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 41);
    let scope = db.seed_scope(&env).await;
    let lease = Duration::from_secs(30);
    let store = db.store();
    let queue = store.scoped(scope);
    let queue = queue.outbox();

    // Fifteen messages in fifteen groups, so none of them blocks another and the state each
    // ends in is the state this test put it in.
    for n in 0..15 {
        enqueue(
            &db,
            &env,
            scope,
            &format!("fact-{n:02}"),
            &format!("agg-{n:02}"),
        )
        .await;
    }
    // Claim the first fourteen, leaving the fifteenth never claimed: that one is READY.
    let claimed = queue.claim(&env, CONSUMER, lease, 14).await.expect("claim");
    assert_eq!(
        claimed.len(),
        14,
        "the batch limit left exactly one unclaimed; got {:?}",
        claimed
            .iter()
            .map(|m| m.idempotency_key.clone())
            .collect::<Vec<_>>()
    );

    // Two are left LEASED and untouched: those are IN FLIGHT.
    // Three are failed retryably, which releases the lease and sets a future gate: those
    // are SCHEDULED.
    for message in &claimed[2..5] {
        assert!(matches!(
            queue
                .fail(&env, message, "http_status_503", RetryPolicy::default())
                .await
                .expect("retryable failure"),
            FailureOutcome::Retrying { .. }
        ));
    }
    // Four are failed under a one-attempt policy: those are DEAD LETTERED.
    for message in &claimed[5..9] {
        assert!(matches!(
            queue
                .fail(
                    &env,
                    message,
                    "poison",
                    RetryPolicy {
                        max_attempts: 1,
                        retry_base: Duration::from_secs(10),
                    },
                )
                .await
                .expect("terminal failure"),
            FailureOutcome::DeadLettered { .. }
        ));
    }
    // Five are completed: those are the reapable backlog.
    for message in &claimed[9..14] {
        assert!(
            queue.complete(&env, message).await.expect("completion"),
            "the lease is still ours, so the completion lands"
        );
    }

    assert_eq!(
        queue.depth(&env, CONSUMER, lease).await.expect("depth"),
        ironauth_store::OutboxDepth {
            ready: 1,
            in_flight: 2,
            scheduled: 3,
            dead_lettered: 4,
            completed: 5,
        },
        "every counter is separately measured, and no two of them are the same number"
    );

    // The gauge is a function of the CLOCK as well as the rows. Advance past both the
    // lease and the longest backoff and nothing on the table changes, yet the two
    // transient states must empty into `ready`: the in-flight two because their leases
    // lapsed, the scheduled three because their gates came due.
    clock.advance(Duration::from_secs(7_200));
    assert_eq!(
        queue.depth(&env, CONSUMER, lease).await.expect("depth"),
        ironauth_store::OutboxDepth {
            ready: 6,
            in_flight: 0,
            scheduled: 0,
            dead_lettered: 4,
            completed: 5,
        },
        "in flight and scheduled are readings of the clock against the row, not stored \
         states; the dead letters and the completions are the two permanent ones"
    );
}

// ---------------------------------------------------------------------------
// 9. What the six-column grant does and does not buy.

#[tokio::test]
async fn the_data_plane_can_resurrect_a_completed_message_so_terminality_is_enforced_in_sql() {
    // The grant is least privilege on the ROUTING and the PAYLOAD, and it is deliberately
    // NOT least privilege on the lifecycle: a drain has to be able to write `completed_at`
    // to complete anything, and a column a role can write it can write NULL to. So the
    // data plane can UN-complete a terminal message and make it drain again.
    //
    // `outbox_messages_one_terminal_state` looks like it closes this and does not: it stops
    // a row being completed AND dead-lettered at once, not being un-completed. Terminality
    // is therefore enforced by the inline `completed_at IS NULL AND dead_lettered_at IS
    // NULL` predicate every lifecycle write in the repository carries, and this test is why
    // that predicate is not redundant with the CHECK.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.store();
    let queue = store.scoped(scope);
    let queue = queue.outbox();
    let id = enqueue(&db, &env, scope, "fact-1", "agg-a").await;

    let held = queue
        .claim(&env, CONSUMER, Duration::from_secs(60), 100)
        .await
        .expect("claim")
        .remove(0);
    assert!(queue.complete(&env, &held).await.expect("complete"));
    assert!(pending_keys(&db, scope).await.is_empty());

    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let mut raw = db.app_pool().begin().await.expect("begin as the app role");
    bind_scope(&mut raw, &tenant, &environment).await;
    let resurrected = sqlx::query(
        "UPDATE outbox_messages SET completed_at = NULL \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(&id)
    .bind(&tenant)
    .bind(&environment)
    .execute(&mut *raw)
    .await
    .expect("the app role holds UPDATE on completed_at, so this is permitted");
    assert_eq!(
        resurrected.rows_affected(),
        1,
        "the data plane CAN null a terminal marker: this is what the grant comment says"
    );
    // The control on the other half of the grant, which IS least privilege: the same role
    // in the same transaction cannot retarget the message at another consumer.
    let retarget = sqlx::query(
        "UPDATE outbox_messages SET consumer = 'someone_else' \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(&id)
    .bind(&tenant)
    .bind(&environment)
    .execute(&mut *raw)
    .await;
    assert!(
        retarget.is_err(),
        "the routing is immutable to the drain: no column grant on `consumer`"
    );
    raw.rollback()
        .await
        .expect("the retarget aborted the transaction");

    // Committed this time, so the consequence is observable through the repository.
    let mut raw = db.app_pool().begin().await.expect("begin as the app role");
    bind_scope(&mut raw, &tenant, &environment).await;
    sqlx::query(
        "UPDATE outbox_messages SET completed_at = NULL \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(&id)
    .bind(&tenant)
    .bind(&environment)
    .execute(&mut *raw)
    .await
    .expect("resurrect");
    raw.commit().await.expect("commit the resurrection");
    assert_eq!(
        pending_keys(&db, scope).await,
        vec!["fact-1".to_owned()],
        "and it redrains: the CHECK is not what makes a completion final"
    );
}

// ---------------------------------------------------------------------------
// 10. Retention (issue #104, PR 3).
//
// Every test in this section reaps through the CONTROL store, because
// `0102_outbox_retention.sql` grants DELETE on `outbox_messages` to `ironauth_control`
// and to no other role. Enqueue, claim and complete still go through the app store, so
// the rows being reaped are rows the real drain path wrote.

/// The shipped retention windows, with only the batch shrunk where a test is about the
/// bound. Seven days for the completed tail; dead letters kept FOREVER, which is the
/// shipped default and the opposite of what a zero-second window would mean.
fn retention() -> RetentionSettings {
    RetentionSettings::default()
}

/// A reaper over the CONTROL store, which is the only role that may delete here.
fn reaper(db: &TestDatabase, env: &Env, settings: RetentionSettings) -> OutboxReaper {
    OutboxReaper::new(db.control_store().clone(), env.clone(), settings)
}

/// Claim and COMPLETE every due message of `CONSUMER` in `scope`, returning how many were
/// retired. Runs as the data plane, which is the role that drains.
async fn complete_all_due(db: &TestDatabase, env: &Env, scope: Scope) -> usize {
    let store = db.store();
    let scoped = store.scoped(scope);
    let queue = scoped.outbox();
    let claimed = queue
        .claim(env, CONSUMER, Duration::from_secs(300), 1_000)
        .await
        .expect("claim");
    for message in &claimed {
        assert!(
            queue.complete(env, message).await.expect("completion"),
            "the lease is still ours"
        );
    }
    claimed.len()
}

/// How many messages of `CONSUMER` remain in `scope`, in ANY state.
async fn remaining(db: &TestDatabase, scope: Scope) -> usize {
    db.store()
        .scoped(scope)
        .outbox()
        .list(CONSUMER, 1_000)
        .await
        .expect("list")
        .len()
}

/// A [`RetentionObserver`] that records what it was told, so a test can assert on the
/// reports rather than only on the rows.
#[derive(Default)]
struct RecordingRetentionObserver {
    finished: std::sync::Mutex<Vec<(String, RetentionStats)>>,
    failures: std::sync::Mutex<Vec<String>>,
    /// How many times the sweep said it could not resolve its scopes. A COUNT rather than
    /// a boolean, so a test can watch it move across passes.
    unavailable: std::sync::atomic::AtomicUsize,
}

impl RecordingRetentionObserver {
    fn finished(&self) -> Vec<(String, RetentionStats)> {
        self.finished.lock().expect("finished lock").clone()
    }

    fn failures(&self) -> Vec<String> {
        self.failures.lock().expect("failures lock").clone()
    }

    fn unavailable(&self) -> usize {
        self.unavailable.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl RetentionObserver for RecordingRetentionObserver {
    fn pass_finished(&self, _scope: Scope, consumer: &str, stats: &RetentionStats) {
        self.finished
            .lock()
            .expect("finished lock")
            .push((consumer.to_owned(), *stats));
    }

    fn pass_failed(&self, _scope: Scope, consumer: Option<&str>, _error: &StoreError) {
        self.failures
            .lock()
            .expect("failures lock")
            .push(consumer.unwrap_or("<scope>").to_owned());
    }

    fn scopes_unavailable(&self, _error: &StoreError) {
        self.unavailable
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A [`ScopeSource`] that always fails, so the sweeper's own loop is the thing under test
/// rather than anything it would have swept.
struct FailingScopes;

impl ScopeSource for FailingScopes {
    fn scopes(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Scope>, StoreError>> + Send + '_>,
    > {
        // The variant is immaterial: all the loop can observe is that the answer was
        // `Err`, and what it must not do is swallow it.
        Box::pin(async { Err(StoreError::NotFound) })
    }
}

/// A [`ScopeSource`] that PANICS, which is how a sweeper task dies. A panic in the source
/// or the observer is the only thing that unwinds it, and nothing restarts it.
struct PanickingScopes;

impl ScopeSource for PanickingScopes {
    fn scopes(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Scope>, StoreError>> + Send + '_>,
    > {
        Box::pin(async { panic!("the scope source panicked") })
    }
}

/// A [`ScopeSource`] that answers with a fixed list and COUNTS how many times it was asked.
/// The count is what makes "the task stopped" observable from outside the task.
struct CountingScopes {
    scopes: Vec<Scope>,
    calls: Arc<AtomicUsize>,
}

impl ScopeSource for CountingScopes {
    fn scopes(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Scope>, StoreError>> + Send + '_>,
    > {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let scopes = self.scopes.clone();
        Box::pin(async move { Ok(scopes) })
    }
}

#[tokio::test]
async fn a_completed_message_is_reaped_past_its_window_and_kept_inside_it() {
    // The base case, and the one that makes every other test in this section mean
    // something: without it a reaper that deleted NOTHING would satisfy all of them.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 91);
    let scope = db.seed_scope(&env).await;

    enqueue(&db, &env, scope, "fact-1", "agg-a").await;
    assert_eq!(complete_all_due(&db, &env, scope).await, 1);

    let reaper = reaper(&db, &env, retention());
    let inside = reaper.reap_once(scope, CONSUMER).await.expect("pass");
    assert_eq!(
        inside,
        RetentionStats::default(),
        "a message completed a moment ago is inside the window and is not touched"
    );
    assert_eq!(remaining(&db, scope).await, 1);

    // Past the seven day window, by one second, so the boundary is the thing under test
    // rather than an arbitrary jump.
    clock.advance(retention().completed_retention + Duration::from_secs(1));
    let past = reaper.reap_once(scope, CONSUMER).await.expect("pass");
    assert_eq!(
        past,
        RetentionStats {
            completed_reaped: 1,
            dead_letters_reaped: 0,
            saturated: false,
        },
        "past its window the completed message is removed, and one row is not a saturated \
         pass"
    );
    assert_eq!(
        remaining(&db, scope).await,
        0,
        "the row is gone from the table, not merely from a projection"
    );
}

#[tokio::test]
async fn a_non_terminal_message_is_never_reaped_however_old_it_is() {
    // THE test of this PR. A message with both terminal columns NULL is not stale, it is
    // UNDELIVERED, and there is a shipped configuration that produces exactly that
    // population at scale: `oidc.backchannel_logout_enabled` defaults OFF while the
    // producer that enqueues `session_ended` runs regardless, so a deployment accumulates
    // undrained messages by design and turning the switch on begins by draining them.
    //
    // A predicate keyed on `enqueued_at` deletes those pending logouts, and `depth` then
    // reports a clean queue because the rows it counted are gone. It is worse than a silent
    // loss: the claim's head-of-group rule reads TERMINAL state, so deleting a group's
    // non-terminal head unblocks the rest of its group and the survivors deliver out of
    // order. The second aggregate below is that case.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 92);
    let scope = db.seed_scope(&env).await;

    // Three shapes of non-terminal row, all enqueued at the epoch and then left to age far
    // past every window this reaper knows: never claimed, claimed and released with a
    // retry pending, and the HEAD of a two message ordering group.
    enqueue(&db, &env, scope, "never-claimed", "agg-a").await;
    enqueue(&db, &env, scope, "failed-once", "agg-b").await;
    enqueue(&db, &env, scope, "group-head", "agg-c").await;
    enqueue(&db, &env, scope, "group-tail", "agg-c").await;

    let store = db.store();
    let scoped = store.scoped(scope);
    let queue = scoped.outbox();
    let claimed = queue
        .claim(&env, CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim");
    let failed = claimed
        .iter()
        .find(|m| m.idempotency_key == "failed-once")
        .expect("the retryable message was claimed");
    assert!(matches!(
        queue
            .fail(&env, failed, "http_status_503", RetryPolicy::default())
            .await
            .expect("retryable failure"),
        FailureOutcome::Retrying { .. }
    ));

    // A YEAR past enqueue, which is far beyond the seven day completed window and beyond
    // the ninety day ceiling any operator could configure.
    clock.advance(Duration::from_secs(365 * 24 * 60 * 60));
    let stats = reaper(&db, &env, retention())
        .reap_once(scope, CONSUMER)
        .await
        .expect("pass");
    assert_eq!(
        stats,
        RetentionStats::default(),
        "a message that is neither completed nor dead-lettered is UNDELIVERED work, not a \
         stale row, whatever its age: a predicate keyed on enqueued_at deletes pending \
         logouts and leaves depth() reporting a clean queue"
    );

    let mut left = pending_keys(&db, scope).await;
    left.sort();
    assert_eq!(
        left,
        vec![
            "failed-once".to_owned(),
            "group-head".to_owned(),
            "group-tail".to_owned(),
            "never-claimed".to_owned(),
        ],
        "every non-terminal message survives, including the ordering-group head whose \
         deletion would let its tail jump the queue"
    );
}

#[tokio::test]
async fn a_dead_letter_is_kept_forever_by_default_and_only_a_window_an_operator_set_reaps_it() {
    // The two tails are NOT the same kind of row and the tree ships them different
    // defaults. A dead letter is work GIVEN UP ON, which for the back-channel logout
    // fan-out can be an entire session's relying parties left un-notified, and the row is
    // the only record that it happened.
    //
    // Two failures are measured here, and they are different failures. Folding the dead
    // letters into the completed predicate would delete this row on the FIRST pass below,
    // where no dead-letter window is configured at all. Keying `reap_dead_lettered` on
    // `completed_at` instead of `dead_lettered_at` would delete NOTHING on the second pass,
    // because a dead-lettered row has `completed_at IS NULL`.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 93);
    let scope = db.seed_scope(&env).await;

    enqueue(&db, &env, scope, "poison", "agg-a").await;
    let store = db.store();
    let scoped = store.scoped(scope);
    let queue = scoped.outbox();
    let claimed = queue
        .claim(&env, CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim");
    assert!(matches!(
        queue
            .fail(
                &env,
                &claimed[0],
                "poison",
                RetryPolicy {
                    max_attempts: 1,
                    retry_base: Duration::from_secs(10),
                },
            )
            .await
            .expect("terminal failure"),
        FailureOutcome::DeadLettered { .. }
    ));

    // A year later, at the SHIPPED default, where dead letters are kept forever.
    clock.advance(Duration::from_secs(365 * 24 * 60 * 60));
    let default_settings = retention();
    assert!(
        default_settings.dead_letter_retention.is_none(),
        "the shipped default keeps dead letters forever, which is what this case measures"
    );
    let kept = reaper(&db, &env, default_settings)
        .reap_once(scope, CONSUMER)
        .await
        .expect("pass");
    assert_eq!(
        kept,
        RetentionStats::default(),
        "with no dead-letter window configured the dead letter is kept, and it is far past \
         the COMPLETED window, so a reaper that folded the two tails together would have \
         taken it"
    );
    assert_eq!(remaining(&db, scope).await, 1);

    // The same row, with a window an operator chose that it is NOT yet past.
    let far = RetentionSettings {
        dead_letter_retention: Some(Duration::from_secs(400 * 24 * 60 * 60)),
        ..retention()
    };
    assert_eq!(
        reaper(&db, &env, far)
            .reap_once(scope, CONSUMER)
            .await
            .expect("pass"),
        RetentionStats::default(),
        "a dead letter inside its own window stays: the window is measured from \
         dead_lettered_at"
    );
    assert_eq!(remaining(&db, scope).await, 1);

    // And now a window it IS past.
    let near = RetentionSettings {
        dead_letter_retention: Some(Duration::from_secs(30 * 24 * 60 * 60)),
        ..retention()
    };
    assert_eq!(
        reaper(&db, &env, near)
            .reap_once(scope, CONSUMER)
            .await
            .expect("pass"),
        RetentionStats {
            completed_reaped: 0,
            dead_letters_reaped: 1,
            saturated: false,
        },
        "past a window an operator deliberately set, the dead letter is reaped, and it is \
         counted on the dead-letter side rather than the completed one"
    );
    assert_eq!(remaining(&db, scope).await, 0);
}

#[tokio::test]
async fn the_reap_batch_is_a_hard_bound_and_a_saturated_pass_says_so() {
    // The pass is bounded and does NOT loop until drained: an unbounded delete over a first
    // run's accumulated backlog holds a long lock and produces one enormous WAL record,
    // which stalls a replica.
    //
    // Saturation is a distinct signal because without it "removed 2 rows" is the same
    // report whether the reaper is keeping up or has been falling behind for a month, and
    // those need different actions.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 94);
    let scope = db.seed_scope(&env).await;

    for n in 0..5 {
        enqueue(&db, &env, scope, &format!("fact-{n}"), &format!("agg-{n}")).await;
    }
    assert_eq!(complete_all_due(&db, &env, scope).await, 5);
    clock.advance(retention().completed_retention + Duration::from_secs(1));

    let reaper = reaper(
        &db,
        &env,
        RetentionSettings {
            batch: 2,
            ..retention()
        },
    );
    for expected_left in [3, 1] {
        let stats = reaper.reap_once(scope, CONSUMER).await.expect("pass");
        assert_eq!(
            stats,
            RetentionStats {
                completed_reaped: 2,
                dead_letters_reaped: 0,
                saturated: true,
            },
            "a pass removes at most its batch and REPORTS that it ran out of budget rather \
             than out of work"
        );
        assert_eq!(remaining(&db, scope).await, expected_left);
    }
    let last = reaper.reap_once(scope, CONSUMER).await.expect("pass");
    assert_eq!(
        last,
        RetentionStats {
            completed_reaped: 1,
            dead_letters_reaped: 0,
            saturated: false,
        },
        "the pass that finally clears the backlog removed less than its budget, so it is \
         NOT saturated: that is the transition an operator watches for"
    );
    assert_eq!(remaining(&db, scope).await, 0);
}

#[tokio::test]
async fn retention_removes_only_its_own_scopes_messages() {
    // Row-level security is what confines the delete, and it is the bound the migration
    // header claims. A reaper that dropped its scope binding would take every tenant's
    // retired messages in one statement.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 95);
    let mine = db.seed_scope(&env).await;
    let theirs = db.seed_scope(&env).await;

    for scope in [mine, theirs] {
        enqueue(&db, &env, scope, "fact-1", "agg-a").await;
        assert_eq!(complete_all_due(&db, &env, scope).await, 1);
    }
    clock.advance(retention().completed_retention + Duration::from_secs(1));

    let stats = reaper(&db, &env, retention())
        .reap_once(mine, CONSUMER)
        .await
        .expect("pass");
    assert_eq!(stats.completed_reaped, 1);
    assert_eq!(remaining(&db, mine).await, 0, "my retired message is gone");
    assert_eq!(
        remaining(&db, theirs).await,
        1,
        "another scope's retired message is untouched, and nothing in the reap statement \
         names that scope: the policy is what refused it"
    );
}

#[tokio::test]
async fn a_fenced_scope_is_not_reaped_and_a_sweep_covers_every_consumer_in_a_live_one() {
    // A suspended scope is one an operator PAUSED, and quietly deleting its data while it
    // is paused is the last thing a pause should do. The drain already refuses a fenced
    // scope, so its queue does not move: its completed tail is exactly the delivery
    // evidence somebody investigating the suspension reads.
    //
    // The same test drives the live half, because "reaped nothing" has to be measured
    // against a scope where the identical sweep reaps everything. It also covers the
    // consumer enumeration: TWO consumers have rows here, and a sweep that walked a
    // registry rather than the table would miss whichever one this process does not run.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 96);
    let paused = db.seed_scope(&env).await;
    let live = db.seed_scope(&env).await;

    for scope in [paused, live] {
        for consumer in [CONSUMER, "second_consumer"] {
            enqueue_for(&db, &env, scope, consumer, "fact-1", "agg-a").await;
            let store = db.store();
            let scoped = store.scoped(scope);
            let queue = scoped.outbox();
            let claimed = queue
                .claim(&env, consumer, Duration::from_secs(300), 10)
                .await
                .expect("claim");
            assert_eq!(claimed.len(), 1);
            assert!(queue.complete(&env, &claimed[0]).await.expect("complete"));
        }
    }
    clock.advance(retention().completed_retention + Duration::from_secs(1));
    db.set_environment_serving_state(paused, "suspended").await;

    let reaper = reaper(&db, &env, retention());
    let stop = std::sync::atomic::AtomicBool::new(false);
    let observer = RecordingRetentionObserver::default();

    reaper
        .sweep_scope_until(paused, &stop, &observer)
        .await
        .expect("the fenced sweep is not an error");
    assert!(
        observer.finished().is_empty() && observer.failures().is_empty(),
        "a fenced scope is skipped before anything is read per consumer, so it reports no \
         pass at all; it reported {:?}",
        observer.finished()
    );
    assert_eq!(
        db.store()
            .scoped(paused)
            .outbox()
            .list(CONSUMER, 10)
            .await
            .expect("list")
            .len(),
        1,
        "the paused scope keeps its retired messages: they are the evidence an operator \
         investigating the suspension reads"
    );

    reaper
        .sweep_scope_until(live, &stop, &observer)
        .await
        .expect("the live sweep");
    let mut reported = observer.finished();
    reported.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        reported,
        vec![
            (
                "second_consumer".to_owned(),
                RetentionStats {
                    completed_reaped: 1,
                    dead_letters_reaped: 0,
                    saturated: false,
                }
            ),
            (
                CONSUMER.to_owned(),
                RetentionStats {
                    completed_reaped: 1,
                    dead_letters_reaped: 0,
                    saturated: false,
                }
            ),
        ],
        "the live scope's sweep covers EVERY consumer with rows in it and reports each by \
         name; the consumer list comes from the table, not from a registry this process \
         happens to hold"
    );
    assert_eq!(remaining(&db, live).await, 0);
}

#[tokio::test]
async fn a_stop_between_consumers_abandons_the_rest_of_the_sweep() {
    // The flag is read between consumers as well as between scopes, so a shutdown costs at
    // most one bounded delete. Measured by setting it BEFORE the sweep: nothing is reaped
    // and nothing is reported, which is only possible if the check sits inside the loop.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 97);
    let scope = db.seed_scope(&env).await;

    enqueue(&db, &env, scope, "fact-1", "agg-a").await;
    assert_eq!(complete_all_due(&db, &env, scope).await, 1);
    clock.advance(retention().completed_retention + Duration::from_secs(1));

    let observer = RecordingRetentionObserver::default();
    let stop = std::sync::atomic::AtomicBool::new(true);
    reaper(&db, &env, retention())
        .sweep_scope_until(scope, &stop, &observer)
        .await
        .expect("sweep");
    assert!(
        observer.finished().is_empty(),
        "a stopped sweep reaps nothing and reports nothing"
    );
    assert_eq!(remaining(&db, scope).await, 1);
}

#[tokio::test]
async fn a_reaper_without_the_delete_grant_reports_the_fault_rather_than_reaping_nothing_quietly() {
    // The failure an operator actually hits: a deployment upgraded past this PR whose
    // control-plane role never received the 0102 grant. Postgres refuses the DELETE, and
    // the whole point of the observer is that the refusal LEAVES the process. Without it a
    // table that grows forever and a reaper with nothing to do look identical.
    //
    // Induced the way an operator induces it by accident, by taking the grant away, so the
    // fault is a real permission fault on the real statement.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 98);
    let scope = db.seed_scope(&env).await;

    enqueue(&db, &env, scope, "fact-1", "agg-a").await;
    assert_eq!(complete_all_due(&db, &env, scope).await, 1);
    clock.advance(retention().completed_retention + Duration::from_secs(1));

    db.execute_owner_sql("REVOKE DELETE ON outbox_messages FROM ironauth_control")
        .await;
    let observer = RecordingRetentionObserver::default();
    let stop = std::sync::atomic::AtomicBool::new(false);
    reaper(&db, &env, retention())
        .sweep_scope_until(scope, &stop, &observer)
        .await
        .expect("the scope-level reads still succeed");
    db.execute_owner_sql("GRANT DELETE ON outbox_messages TO ironauth_control")
        .await;

    assert_eq!(
        observer.failures(),
        vec![CONSUMER.to_owned()],
        "the refusal is reported OUT, naming the consumer whose tail was not reaped"
    );
    assert!(
        observer.finished().is_empty(),
        "and no pass is reported as finished, so a fault cannot read as a quiet success"
    );
    assert_eq!(remaining(&db, scope).await, 1);
}

#[tokio::test]
async fn reaping_a_completed_message_frees_its_idempotency_key_and_the_work_becomes_deliverable_again()
 {
    // What a completed row carries that is NOT delivery evidence, measured rather than
    // asserted. While it exists the row occupies its slot in
    // `UNIQUE (tenant_id, environment_id, consumer, idempotency_key)`, and that constraint
    // IS the queue's at-most-once ledger: it is what `enqueue_all` relies on to make a
    // producer's re-run a no-op. Reaping the row frees the key.
    //
    // This is the contract, pinned so it is measured rather than believed. It is not
    // reachable with today's consumers (a producer can only re-enqueue while its own
    // driving message is still non-terminal, which at the shipped outbox defaults is about
    // 200 seconds against a one hour floor), and that is exactly why it needs a test: the
    // thing that makes it safe is arithmetic in another section of the config, not
    // anything the queue enforces.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 99);
    let scope = db.seed_scope(&env).await;
    let key = "one-domain-fact";

    enqueue(&db, &env, scope, key, "agg-a").await;
    assert_eq!(complete_all_due(&db, &env, scope).await, 1);

    // BEFORE the reap: the ledger holds, and a producer re-running its enqueue is a no-op.
    let store = db.store();
    let scoped = store.scoped(scope);
    let queue = scoped.outbox();
    let again = queue
        .enqueue_all(
            &env,
            &[NewOutboxMessage {
                consumer: CONSUMER,
                idempotency_key: key,
                ordering_key: "agg-a",
                payload: serde_json::json!({}),
            }],
        )
        .await
        .expect("re-enqueue over a live completed row");
    assert_eq!(
        again, 0,
        "while the completed row exists the unique index refuses the second insert, which \
         is the at-most-once property the fan-out consumer rests its idempotence on"
    );
    assert_eq!(remaining(&db, scope).await, 1);

    // AFTER the reap: the same call inserts, and what it inserted is CLAIMABLE.
    clock.advance(retention().completed_retention + Duration::from_secs(1));
    assert_eq!(
        reaper(&db, &env, retention())
            .reap_once(scope, CONSUMER)
            .await
            .expect("pass")
            .completed_reaped,
        1
    );
    let after = queue
        .enqueue_all(
            &env,
            &[NewOutboxMessage {
                consumer: CONSUMER,
                idempotency_key: key,
                ordering_key: "agg-a",
                payload: serde_json::json!({}),
            }],
        )
        .await
        .expect("re-enqueue after the reap");
    assert_eq!(
        after, 1,
        "reaping the completed row FREED its idempotency key: the second enqueue conflicts \
         with nothing and inserts. This is the contract the retention floor exists to keep \
         out of a producer's reach"
    );
    let claimed = queue
        .claim(&env, CONSUMER, Duration::from_secs(300), 10)
        .await
        .expect("claim");
    assert_eq!(
        claimed.len(),
        1,
        "and the re-inserted message is CLAIMABLE, so the work is deliverable a second \
         time rather than merely re-recorded"
    );
    assert_eq!(claimed[0].idempotency_key, key);
}

#[tokio::test]
async fn a_sweeper_reports_scopes_it_could_not_resolve_rather_than_looping_at_full_health() {
    // Nothing about the sweeper's liveness can reveal this: the task is alive and looping,
    // the interval is being honoured, and not one row is being examined. Without the
    // report a permanently broken scope enumeration and a healthy idle reaper produce the
    // same evidence, which is none.
    let observer = Arc::new(RecordingRetentionObserver::default());
    let reported: Arc<dyn RetentionObserver> = observer.clone();
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 100);
    let reaper = reaper(
        &db,
        &env,
        RetentionSettings {
            interval: Duration::from_millis(50),
            ..retention()
        },
    );
    let scopes: Arc<dyn ScopeSource> = Arc::new(FailingScopes);
    let sweeper = RetentionSweeper::spawn(&reaper, &scopes, &reported);

    let mut seen = 0;
    for _ in 0..400 {
        seen = observer.unavailable();
        if seen > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // The sweeper is at full health while this is happening, which is the whole point.
    assert!(
        sweeper.is_running(),
        "the task is alive: liveness cannot be what tells an operator about this"
    );
    sweeper.shutdown().await;
    assert!(
        seen > 0,
        "a sweep that cannot resolve its scopes reaped NO scope at all, and that has to \
         leave the process: swallowing it makes a permanently failing sweeper \
         indistinguishable from an idle one"
    );
    assert!(
        observer.finished().is_empty(),
        "and no pass is reported as finished, so the failure cannot read as a quiet success"
    );
}

#[tokio::test]
async fn a_sweeper_whose_task_unwinds_stops_reporting_itself_as_running() {
    // `is_running` is the LIVE state and not "was spawned", and the difference is only
    // observable when the task actually dies. A panicking `ScopeSource` is what gets there;
    // nothing restarts the task, so a handle that reported its own existence would go on
    // claiming a reaper was running with none left.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 101);
    let reaper = reaper(
        &db,
        &env,
        RetentionSettings {
            interval: Duration::from_millis(50),
            ..retention()
        },
    );
    let scopes: Arc<dyn ScopeSource> = Arc::new(PanickingScopes);
    let observer: Arc<dyn RetentionObserver> = Arc::new(SilentRetentionObserver);
    let sweeper = RetentionSweeper::spawn(&reaper, &scopes, &observer);

    let mut alive = true;
    for _ in 0..400 {
        alive = sweeper.is_running();
        if !alive {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        !alive,
        "a sweeper whose task unwound must report itself as NOT running: nothing restarts \
         it, so the alternative is a handle that claims a reaper exists forever"
    );
}

#[tokio::test]
async fn an_hourly_sweeper_still_shuts_down_promptly_because_it_sleeps_in_slices() {
    // The wait between passes is almost all of a sweeper's life, and the stop checks
    // between scopes and between consumers say nothing about it. A single
    // `sleep(interval).await` would be correct and unusable: at the shipped hourly
    // interval, `shutdown().await` would take up to an hour, which an orchestrator
    // resolves with SIGKILL.
    //
    // Measured through the real seam rather than against the private helper. The interval
    // here is a full hour, so a sweeper that slept it whole could not answer inside the
    // timeout below, and the assertion is a TIMEOUT rather than a stopwatch so no
    // wall-clock reading appears in this test.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 102);
    let scope = db.seed_scope(&env).await;
    enqueue(&db, &env, scope, "fact-1", "agg-a").await;
    assert_eq!(complete_all_due(&db, &env, scope).await, 1);
    clock.advance(retention().completed_retention + Duration::from_secs(1));

    let reaper = reaper(
        &db,
        &env,
        RetentionSettings {
            interval: Duration::from_secs(60 * 60),
            ..retention()
        },
    );
    let scopes: Arc<dyn ScopeSource> = Arc::new(StaticScopes::new(vec![scope]));
    let observer: Arc<dyn RetentionObserver> = Arc::new(SilentRetentionObserver);
    let sweeper = RetentionSweeper::spawn(&reaper, &scopes, &observer);

    // Wait until the FIRST pass has finished, so the task is demonstrably inside its long
    // wait rather than still working. Without this the task could observe the stop flag at
    // the top of the loop and a whole sleep would survive the test.
    let mut first_pass_landed = false;
    for _ in 0..400 {
        if remaining(&db, scope).await == 0 {
            first_pass_landed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        first_pass_landed,
        "the first pass must land before the wait is measured"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;

    tokio::time::timeout(Duration::from_secs(10), sweeper.shutdown())
        .await
        .expect(
            "shutdown must return while the sweeper is inside an HOUR-long wait: the wait \
             is sliced and each slice re-reads the stop flag. A single un-sliced sleep \
             makes a graceful stop take up to the whole interval",
        );
}

#[tokio::test]
async fn a_dropped_sweeper_stops_rather_than_leaving_a_task_deleting_rows_behind_it() {
    // Dropping the handle DETACHES the tokio task, so without the `Drop` guard a sweeper
    // that goes out of scope keeps sweeping forever with nothing left to stop it: rows
    // keep being deleted behind an operator's back and no handle exists to await.
    //
    // Measured through the ScopeSource, because that is the one thing the loop touches on
    // every single pass whether or not there is anything to reap.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 103);
    let scope = db.seed_scope(&env).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let reaper = reaper(
        &db,
        &env,
        RetentionSettings {
            interval: Duration::from_millis(25),
            ..retention()
        },
    );
    let scopes: Arc<dyn ScopeSource> = Arc::new(CountingScopes {
        scopes: vec![scope],
        calls: Arc::clone(&calls),
    });
    let observer: Arc<dyn RetentionObserver> = Arc::new(SilentRetentionObserver);

    {
        let sweeper = RetentionSweeper::spawn(&reaper, &scopes, &observer);
        for _ in 0..400 {
            if calls.load(Ordering::Relaxed) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            calls.load(Ordering::Relaxed) >= 2,
            "the sweeper must be genuinely LOOPING before the drop, otherwise a flat count \
             afterwards would prove nothing"
        );
        drop(sweeper);
    }

    // Past several intervals, so a still-running task would certainly have swept again.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let settled = calls.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        calls.load(Ordering::Relaxed),
        settled,
        "the dropped sweeper stopped: its task observed the flag `Drop` set and left the \
         loop. Without that guard the detached task keeps deleting rows with no handle \
         left to stop it"
    );
}

/// Bind the transaction-local row-level-security scope variables, exactly as the
/// repository does, so a raw query runs under the same scope a real connection would.
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

#[tokio::test]
async fn the_shipped_retry_defaults_span_a_real_outage_and_still_terminate() {
    // Issue #106 requires that a consumer whose endpoint died recover on its own rather
    // than through an operator replay. The shipped defaults used to make that impossible:
    // five attempts on a ten second base exhausted the whole budget in about two and a
    // half MINUTES, so any receiver down for five dead-lettered every delivery.
    //
    // This pins the SPAN of the shipped schedule, not a formula, because the span is the
    // property #106 actually asks for and it is what a well-meaning tuning of either knob
    // would silently destroy. It drives the real `fail` path under a manual clock and adds
    // up the gates the queue itself scheduled.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 29);
    let scope = db.seed_scope(&env).await;
    // The SHIPPED defaults, deliberately: a policy written here would pin nothing about
    // what a deployment actually gets.
    let policy = RetryPolicy::default();
    let lease = Duration::from_secs(30);
    enqueue(&db, &env, scope, "fact-span", "agg-span").await;

    let store = db.store();
    let queue = store.scoped(scope);
    let queue = queue.outbox();

    let mut delays = Vec::new();
    let mut dead_lettered = false;
    for _ in 0..policy.max_attempts {
        let claimed = queue
            .claim(&env, CONSUMER, lease, 100)
            .await
            .expect("claim");
        assert_eq!(
            claimed.len(),
            1,
            "the message is claimable while non-terminal"
        );
        let before = epoch_micros_of(&env);
        match queue
            .fail(&env, &claimed[0], "http_status_503", policy)
            .await
            .expect("fail")
        {
            FailureOutcome::Retrying {
                next_attempt_at_unix_micros,
                ..
            } => {
                let delay = next_attempt_at_unix_micros - before;
                assert!(delay > 0, "a retry is scheduled into the future");
                delays.push(delay);
                // Step the clock past the gate so the next claim sees the message due.
                clock.advance(Duration::from_micros(
                    u64::try_from(delay).expect("positive") + 1_000_000,
                ));
            }
            FailureOutcome::DeadLettered { .. } => {
                dead_lettered = true;
                break;
            }
            FailureOutcome::NotFound => panic!("the lease token was rejected"),
        }
    }

    assert!(
        dead_lettered,
        "the schedule TERMINATES: an unbounded retry would wedge the ordering group forever"
    );

    let total_secs: i64 = delays.iter().sum::<i64>() / 1_000_000;
    assert!(
        total_secs >= 24 * 3600,
        "the shipped retry schedule must outlast a real outage, not a hiccup: it spans \
         {total_secs}s ({}h) across {} retries",
        total_secs / 3600,
        delays.len()
    );

    // Non-decreasing, so the backoff never gets SHORTER as a receiver stays down. The
    // ceiling flattens the tail rather than reversing it.
    for pair in delays.windows(2) {
        assert!(
            pair[1] >= pair[0],
            "the backoff never shrinks: {:?}",
            delays.iter().map(|d| d / 1_000_000).collect::<Vec<_>>()
        );
    }
}
