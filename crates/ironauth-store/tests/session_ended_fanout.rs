// SPDX-License-Identifier: MIT OR Apache-2.0

//! The durable session-ended event fan-out (issue #35), against a real database.
//!
//! The field's most-reported logout gap is missing PROPAGATION: a session ends and no
//! signal reaches the relying parties. This suite pins the substrate that closes the
//! class: ONE internal session-ended event, produced by EVERY terminal end, written in
//! the SAME transaction as the state change, drained off ONE seam. It pins the hazards
//! the milestone is defined by:
//!
//! - A ROTATION is not a session end. A re-authentication re-points a session's lineage
//!   onto its successor and enqueues nothing; only a terminal end does. A naive consumer
//!   draining the outbox therefore never logs a user out on a mere re-auth.
//! - The cause matrix: every terminal cause (logout, single revoke, bulk revoke,
//!   revoke-everything-for-a-user, replaced-by-other-subject) enqueues exactly one event
//!   carrying its own cause.
//! - Transactional outbox: the enqueue commits with the revocation or not at all, so a
//!   forced rollback of the revoke emits nothing.
//! - Cross-tenant isolation: a scope can never drain another tenant's session-ended
//!   events.
//! - At-least-once delivery with a claim lease: a claim hides an event, a lapsed lease
//!   reappears it, and a delivered event never drains again.
//! - Concurrent-drain safety: two workers claiming the same scope at once lease DISJOINT
//!   event sets and never block on each other (`FOR UPDATE SKIP LOCKED`).
//! - Least privilege: the app role can claim and mark delivered, but cannot rewrite the
//!   immutable event body (no table-wide UPDATE, the #31 lesson).

use std::time::{Duration, SystemTime};

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, Scope, SessionEndCause, SessionEndedEvent, SessionId, UserId};
use sqlx::Row;

/// A far-future expiry (year 2100) in epoch microseconds, so a session that stops
/// resolving can ONLY have stopped because it ended, never because it expired.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Create a live SSO session in `scope` for `subject`, rotating away `prior` if given.
async fn create_session(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &str,
    prior: Option<&SessionId>,
) -> SessionId {
    let id = SessionId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .rotate(
            env,
            &id,
            prior,
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

/// The pending (undelivered) events in `scope`, oldest first.
async fn pending(db: &TestDatabase, scope: Scope) -> Vec<SessionEndedEvent> {
    db.store()
        .scoped(scope)
        .session_events()
        .pending(100)
        .await
        .expect("read pending session-ended events")
}

#[tokio::test]
async fn a_terminal_end_enqueues_one_event_but_a_rotation_enqueues_none() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();

    // A first login (no prior) creates a session: NOT a terminal end, so nothing is
    // enqueued.
    let first = create_session(&db, &env, scope, &subject, None).await;
    assert!(
        pending(&db, scope).await.is_empty(),
        "a session creation is not a session end"
    );

    // A re-authentication of the SAME subject ROTATES: the lineage is carried onto the
    // successor, the prior id stops resolving, but this is NOT a terminal end. A naive
    // consumer must not see a logout here.
    let second = create_session(&db, &env, scope, &subject, Some(&first)).await;
    assert!(
        pending(&db, scope).await.is_empty(),
        "a rotation is not a session end: the fan-out must not fire on a re-auth"
    );

    // Now a real terminal end: revoke the live successor. EXACTLY one event, carrying
    // the ended session, the subject, and the terminal cause.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &second, SessionEndCause::Revoked, false, None)
        .await
        .expect("revoke");

    let events = pending(&db, scope).await;
    assert_eq!(
        events.len(),
        1,
        "exactly one event for the one terminal end"
    );
    let event = &events[0];
    assert_eq!(
        event.session_id,
        second.to_string(),
        "names the ended session"
    );
    assert_eq!(event.subject, subject, "names the user");
    assert_eq!(event.cause, SessionEndCause::Revoked, "carries the cause");
    assert!(
        event.id.starts_with("sev_"),
        "the event id is a scoped sev_ id (the idempotency key)"
    );
    assert!(
        event.correlation_id.starts_with("req_"),
        "the event carries the request correlation id"
    );
}

#[tokio::test]
async fn every_terminal_cause_enqueues_its_own_cause() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Logout (an end-user RP logout, the #33 caller passes LoggedOut).
    let subject_a = UserId::generate(&env, &scope).to_string();
    let s_logout = create_session(&db, &env, scope, &subject_a, None).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &s_logout, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("logout revoke");

    // A single operator revoke.
    let subject_b = UserId::generate(&env, &scope).to_string();
    let s_revoke = create_session(&db, &env, scope, &subject_b, None).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &s_revoke, SessionEndCause::Revoked, false, None)
        .await
        .expect("single revoke");

    // A bulk revoke: each session in the batch carries its own event.
    let subject_c = UserId::generate(&env, &scope).to_string();
    let s_bulk = create_session(&db, &env, scope, &subject_c, None).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .bulk_revoke(&env, std::slice::from_ref(&s_bulk), false, None)
        .await
        .expect("bulk revoke");

    // Replaced-by-other-subject: a login while presenting SOMEBODY ELSE's cookie
    // terminally revokes the prior session (the incoming user inherits nothing).
    let owner = UserId::generate(&env, &scope).to_string();
    let s_owner = create_session(&db, &env, scope, &owner, None).await;
    let intruder = UserId::generate(&env, &scope).to_string();
    let _successor = create_session(&db, &env, scope, &intruder, Some(&s_owner)).await;

    // Revoke-everything-for-a-user (kept last so its session is distinct).
    let victim = UserId::generate(&env, &scope);
    let victim_text = victim.to_string();
    let s_userall = create_session(&db, &env, scope, &victim_text, None).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke_all_for_user(&env, &victim, false, None)
        .await
        .expect("revoke all for user");

    // Collect the cause per ended session.
    let events = pending(&db, scope).await;
    let cause_of = |session: &SessionId| -> SessionEndCause {
        events
            .iter()
            .find(|event| event.session_id == session.to_string())
            .unwrap_or_else(|| panic!("no event for session {session}"))
            .cause
    };
    assert_eq!(cause_of(&s_logout), SessionEndCause::LoggedOut);
    assert_eq!(cause_of(&s_revoke), SessionEndCause::Revoked);
    assert_eq!(cause_of(&s_bulk), SessionEndCause::BulkRevoked);
    assert_eq!(cause_of(&s_owner), SessionEndCause::ReplacedByOtherSubject);
    assert_eq!(cause_of(&s_userall), SessionEndCause::UserRevokedAll);
    assert_eq!(
        events.len(),
        5,
        "exactly one event per terminal end, and none for the two rotations/creations"
    );
}

#[tokio::test]
async fn revoke_all_for_a_user_enqueues_one_ordered_event_per_ended_session() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let victim = UserId::generate(&env, &scope);
    let subject = victim.to_string();
    let bystander = UserId::generate(&env, &scope).to_string();

    let s1 = create_session(&db, &env, scope, &subject, None).await;
    let s2 = create_session(&db, &env, scope, &subject, None).await;
    let s3 = create_session(&db, &env, scope, &subject, None).await;
    // A different user's live session must NOT be swept into the fan-out.
    let _other = create_session(&db, &env, scope, &bystander, None).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke_all_for_user(&env, &victim, false, None)
        .await
        .expect("revoke all");

    let events = pending(&db, scope).await;
    assert_eq!(
        events.len(),
        3,
        "one event per ended session, the bystander untouched"
    );
    for event in &events {
        assert_eq!(event.cause, SessionEndCause::UserRevokedAll);
        assert_eq!(event.subject, subject);
    }
    let ended: std::collections::HashSet<String> = events
        .iter()
        .map(|event| event.session_id.clone())
        .collect();
    for session in [&s1, &s2, &s3] {
        assert!(
            ended.contains(&session.to_string()),
            "{session} has an event"
        );
    }
    // pending() sorts by the monotonic sequence, so within one drain the returned rows
    // come back in ascending sequence order. This is a best-effort ordering HINT for the
    // visible tail, NOT a global total order: these ends were enqueued serially in this
    // test, so their sequences are strictly ascending, but under concurrent producers a
    // lower sequence can commit after a higher one, which is why the drain is
    // at-least-once per row and never advances a sequence high-water-mark.
    let sequences: Vec<i64> = events.iter().map(|event| event.sequence).collect();
    let mut sorted = sequences.clone();
    sorted.sort_unstable();
    assert_eq!(
        sequences, sorted,
        "pending() returns events sorted by the sequence hint"
    );
    assert!(
        sequences.windows(2).all(|pair| pair[0] < pair[1]),
        "serially enqueued events carry strictly ascending sequences"
    );
}

#[tokio::test]
async fn a_forced_rollback_of_the_revoke_emits_no_event() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject, None).await;

    // The testing probe runs a real revoke (the flip, the cascade, the audit row, AND
    // the outbox enqueue), then forces a failure in the SAME transaction. The whole
    // transaction rolls back, so no event is enqueued for a revoke that never committed.
    let result = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke_injecting_post_audit_failure(&env, &session, SessionEndCause::Revoked)
        .await;
    assert!(
        result.is_err(),
        "the injected failure rolls the revoke back"
    );

    assert!(
        pending(&db, scope).await.is_empty(),
        "a rolled-back revoke emits no session-ended event (transactional outbox)"
    );
    // The session itself is still live (proving the rollback really rolled back), so a
    // later real revoke can still enqueue.
    assert!(
        db.store()
            .scoped(scope)
            .sessions()
            .get(&session, 0, 0)
            .await
            .expect("read")
            .is_some(),
        "the session survived the rolled-back revoke"
    );
}

#[tokio::test]
async fn the_outbox_is_isolated_across_tenants() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let subject_a = UserId::generate(&env, &scope_a).to_string();

    // End a session in tenant A.
    let session = create_session(&db, &env, scope_a, &subject_a, None).await;
    db.store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::Revoked, false, None)
        .await
        .expect("revoke in A");

    assert_eq!(pending(&db, scope_a).await.len(), 1, "A sees its own event");
    assert!(
        pending(&db, scope_b).await.is_empty(),
        "B cannot drain A's session-ended events"
    );
    // A claim in B's scope also returns nothing: the isolation holds on the mutating
    // drain path, not only the read path.
    assert!(
        db.store()
            .scoped(scope_b)
            .session_events()
            .claim(&env, Duration::from_secs(60), 100)
            .await
            .expect("claim in B")
            .is_empty(),
        "a claim in B never leases A's events"
    );
    // A raw adversarial SELECT as the app role, bound to B's scope, sees nothing:
    // Postgres row-level security enforces the boundary beneath the repository.
    let mut tx = db.app_pool().begin().await.expect("begin app tx");
    bind_scope(
        &mut tx,
        &scope_b.tenant().to_string(),
        &scope_b.environment().to_string(),
    )
    .await;
    let visible: i64 = sqlx::query("SELECT count(*) AS n FROM session_ended_events")
        .fetch_one(&mut *tx)
        .await
        .expect("count")
        .get("n");
    assert_eq!(
        visible, 0,
        "RLS hides A's events from a B-scoped connection"
    );
    let _ = tx.rollback().await;
}

#[tokio::test]
async fn claim_leases_then_marks_delivered_and_a_delivered_event_never_redrains() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 42);
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject, None).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::Revoked, false, None)
        .await
        .expect("revoke");

    let outbox = db.store().scoped(scope);
    let outbox = outbox.session_events();
    let lease = Duration::from_secs(60);

    // First claim leases the one event.
    let claimed = outbox.claim(&env, lease, 100).await.expect("claim");
    assert_eq!(claimed.len(), 1, "the one undelivered event is claimed");
    let event_id = claimed[0].id.clone();

    // A second claim BEFORE the lease lapses sees nothing: the event is hidden in
    // flight, so two workers never process it concurrently.
    assert!(
        outbox
            .claim(&env, lease, 100)
            .await
            .expect("claim")
            .is_empty(),
        "a leased event is hidden until its lease lapses"
    );

    // The lease lapses; the event reappears (at-least-once: a crashed worker's event is
    // redelivered).
    clock.advance(Duration::from_secs(61));
    let reclaimed = outbox.claim(&env, lease, 100).await.expect("re-claim");
    assert_eq!(reclaimed.len(), 1, "a lapsed lease reappears the event");
    assert_eq!(reclaimed[0].id, event_id, "the same event reappears");

    // Marking it delivered is the terminal step; it flips once and reports true.
    assert!(
        outbox.mark_delivered(&env, &event_id).await.expect("mark"),
        "the first mark-delivered flips the event"
    );
    // A second mark is idempotent (a re-claim racing a mark, or a double mark): false.
    assert!(
        !outbox
            .mark_delivered(&env, &event_id)
            .await
            .expect("mark again"),
        "mark-delivered is idempotent: it flips at most once"
    );

    // A delivered event never drains again, whatever the lease.
    clock.advance(Duration::from_secs(3600));
    assert!(
        outbox
            .claim(&env, lease, 100)
            .await
            .expect("claim")
            .is_empty(),
        "a delivered event never redrains"
    );
    assert!(
        outbox.pending(100).await.expect("pending").is_empty(),
        "a delivered event is no longer pending"
    );
}

#[tokio::test]
async fn two_concurrent_claimers_lease_disjoint_event_sets_via_skip_locked() {
    // The substrate's concurrent-drain guarantee, pinned against the real Postgres: a
    // claim runs `FOR UPDATE SKIP LOCKED`, so two workers draining the SAME scope at once
    // never lease the same event, and the second worker never BLOCKS on the first (it
    // skips the rows in flight rather than waiting on them). This is the property the
    // whole at-least-once fan-out rests on: without it, two back-channel logout workers
    // could double-deliver or serialize into a stall.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();

    // Enqueue four undelivered events, one terminal revoke each.
    for _ in 0..4 {
        let session = create_session(&db, &env, scope, &subject, None).await;
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .sessions()
            .revoke(&env, &session, SessionEndCause::Revoked, false, None)
            .await
            .expect("revoke");
    }
    let all_ids: std::collections::HashSet<String> = pending(&db, scope)
        .await
        .into_iter()
        .map(|event| event.id)
        .collect();
    assert_eq!(all_ids.len(), 4, "four undelivered events are enqueued");

    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    // Worker A: open a claim transaction and HOLD it open. It leases the first two rows
    // with the exact claimable SELECT `claim` runs (`FOR UPDATE SKIP LOCKED`), then keeps
    // the transaction open so its row locks stay held while worker B drains concurrently.
    // It runs on the raw app pool, a pool distinct from the store's, so B never contends
    // for A's connection.
    let mut worker_a = db
        .app_pool()
        .begin()
        .await
        .expect("begin worker A claim tx");
    bind_scope(&mut worker_a, &tenant, &environment).await;
    let a_rows = sqlx::query(
        "SELECT id FROM session_ended_events \
         WHERE tenant_id = $1 AND environment_id = $2 \
         AND delivered_at IS NULL AND claimed_at IS NULL \
         ORDER BY sequence LIMIT 2 FOR UPDATE SKIP LOCKED",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_all(&mut *worker_a)
    .await
    .expect("worker A leases its batch");
    let a_ids: std::collections::HashSet<String> = a_rows
        .iter()
        .map(|row| row.get::<String, _>("id"))
        .collect();
    assert_eq!(
        a_ids.len(),
        2,
        "worker A leases two rows and holds their locks"
    );

    // Worker B: a real `claim` through the store while A still holds its locks. SKIP
    // LOCKED means B does not block on A and never sees A's rows: it leases only the
    // remaining two.
    let b_ids: std::collections::HashSet<String> = db
        .store()
        .scoped(scope)
        .session_events()
        .claim(&env, Duration::from_secs(60), 100)
        .await
        .expect("worker B claims concurrently")
        .into_iter()
        .map(|event| event.id)
        .collect();
    assert_eq!(
        b_ids.len(),
        2,
        "worker B leases the two rows A did not hold"
    );

    // The two leases are DISJOINT: no event is delivered to both workers.
    assert!(
        a_ids.is_disjoint(&b_ids),
        "concurrent claimers lease disjoint sets (SKIP LOCKED, no double delivery)"
    );
    // Together they cover the whole undelivered set exactly once: nothing was lost, and B
    // was not blocked into leasing nothing.
    let union: std::collections::HashSet<String> = a_ids.union(&b_ids).cloned().collect();
    assert_eq!(
        union, all_ids,
        "A and B together cover every undelivered event exactly once"
    );

    // A rolls back, standing in for a crashed worker: its two rows never got a claimed_at
    // stamp, so they are claimable again and reappear on the next drain (at-least-once),
    // while B's freshly leased rows stay hidden under their unexpired lease.
    worker_a.rollback().await.expect("worker A rolls back");
    let reappeared: std::collections::HashSet<String> = db
        .store()
        .scoped(scope)
        .session_events()
        .claim(&env, Duration::from_secs(60), 100)
        .await
        .expect("drain after worker A rolls back")
        .into_iter()
        .map(|event| event.id)
        .collect();
    assert_eq!(
        reappeared, a_ids,
        "A's un-committed rows reappear for another worker; B's leased rows stay hidden"
    );
}

#[tokio::test]
async fn a_foreign_scope_or_malformed_id_is_a_uniform_no_op_on_mark_delivered() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope_a).to_string();
    let session = create_session(&db, &env, scope_a, &subject, None).await;
    db.store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::Revoked, false, None)
        .await
        .expect("revoke");
    let event_id = pending(&db, scope_a).await[0].id.clone();

    // Marking A's event through B's scope is a uniform no-op: the id parses out of B's
    // scope, so the row is never touched and never revealed.
    assert!(
        !db.store()
            .scoped(scope_b)
            .session_events()
            .mark_delivered(&env, &event_id)
            .await
            .expect("cross-scope mark"),
        "a foreign-scope event id is a no-op, never a cross-tenant write"
    );
    // A malformed id is likewise a no-op, not an error.
    assert!(
        !db.store()
            .scoped(scope_a)
            .session_events()
            .mark_delivered(&env, "not-an-id")
            .await
            .expect("malformed mark"),
        "a malformed id is a uniform no-op"
    );
    // A's event is still pending (nothing marked it).
    assert_eq!(
        pending(&db, scope_a).await.len(),
        1,
        "A's event is untouched"
    );
}

#[tokio::test]
async fn the_app_role_can_drain_but_cannot_rewrite_the_immutable_event_body() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&db, &env, scope, &subject, None).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .revoke(&env, &session, SessionEndCause::Revoked, false, None)
        .await
        .expect("revoke");
    let event_id = pending(&db, scope).await[0].id.clone();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    // The app role CAN stamp the two lifecycle columns a drain touches (its
    // column-scoped grant), proving the drain works on the low-privilege role.
    {
        let mut tx = db.app_pool().begin().await.expect("begin app tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        let claimed =
            sqlx::query("UPDATE session_ended_events SET claimed_at = now() WHERE id = $1")
                .bind(&event_id)
                .execute(&mut *tx)
                .await
                .expect("app stamps claimed_at")
                .rows_affected();
        assert_eq!(claimed, 1, "the app role can stamp claimed_at");
        let delivered =
            sqlx::query("UPDATE session_ended_events SET delivered_at = now() WHERE id = $1")
                .bind(&event_id)
                .execute(&mut *tx)
                .await
                .expect("app stamps delivered_at")
                .rows_affected();
        assert_eq!(delivered, 1, "the app role can stamp delivered_at");
        tx.commit().await.expect("commit lifecycle stamps");
    }

    // The app role is REFUSED (permission denied, 42501) on every immutable body column:
    // there is NO table-wide UPDATE grant (the #31 lesson), so cause, subject, actor,
    // and occurred_at can never be rewritten by a data-plane path.
    for column_set in [
        "cause = 'logged_out'",
        "subject = 'usr_forged'",
        "actor_id = 'svc_forged'",
        "occurred_at = TIMESTAMPTZ 'epoch'",
    ] {
        let mut tx = db.app_pool().begin().await.expect("begin app tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        let denied = sqlx::query(&format!(
            "UPDATE session_ended_events SET {column_set} WHERE id = $1"
        ))
        .bind(&event_id)
        .execute(&mut *tx)
        .await;
        assert_permission_denied(denied, column_set);
        let _ = tx.rollback().await;
    }
}

/// Assert a statement was refused with the PostgreSQL insufficient-privilege error
/// (SQLSTATE 42501), the signal that a column-level grant blocked the write.
fn assert_permission_denied(
    result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
    what: &str,
) {
    match result {
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("42501") => {}
        other => panic!("expected permission denied (42501) for `{what}`, got: {other:?}"),
    }
}

/// Bind the transaction-local row-level-security scope variables, exactly as the
/// repository does, so a raw adversarial query runs under the same scope a real
/// connection would.
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
