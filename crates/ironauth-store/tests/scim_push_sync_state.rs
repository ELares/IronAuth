// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where each outbound connection has read to, and how it is doing (issue #137).
//!
//! # What this file is about
//!
//! Two of #137's criteria are answered from one row. Criterion 2 wants "cursor position, lag and
//! per-resource errors via the management API", and the worker wants a checkpoint that survives
//! a restart. The interesting properties are the ones where those two uses pull against each
//! other, and they are what the tests below drive:
//!
//! * a failure does NOT move the cursor, because an outage must pause the feed rather than drop
//!   events, so the same events are re-read when the pause expires,
//! * a restart mid-backfill RESUMES rather than restarting, which is the difference between
//!   `backfill_after` surviving and not,
//! * and a connection cannot tail before its backfill is complete, because the first event for
//!   an unprovisioned user would create a resource the backfill then duplicates.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewScimPushConnection, OrganizationId, ScimDeletionPolicy,
    ScimPushBackfillState, ScimPushConnectionId, ScimWriteMode, Scope, StoreError,
};

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now_micros(env), name, None)
        .await
        .expect("create organization");
    id
}

async fn seed_connection(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    label: &str,
) -> ScimPushConnectionId {
    let id = ScimPushConnectionId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .scim_push_connections()
        .create(
            env,
            NewScimPushConnection {
                id: &id,
                organization_id: organization,
                display_name: label,
                base_url: "https://downstream.example.com/scim/v2",
                credential_secret_name: "downstream_token",
                attribute_mapping: &serde_json::json!({}),
                user_scope_filter: None,
                group_scope_filter: None,
                write_mode: ScimWriteMode::Patch,
                deletion_policy: ScimDeletionPolicy::Deactivate,
            },
            None,
            None,
        )
        .await
        .expect("create the push connection");
    id
}

#[tokio::test]
async fn a_backfill_resumes_where_it_stopped_rather_than_starting_over() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let state = db.store().scoped(scope);

    state
        .scim_push_sync_state()
        .begin_backfill(&connection)
        .await
        .expect("begin");
    state
        .scim_push_sync_state()
        .record_backfill_progress(&connection, "usr_500")
        .await
        .expect("progress");

    // THE RESTART. A worker that comes back up calls `begin_backfill` again, and the whole point
    // is that this second call does NOT rewind: an INSERT that overwrote the row would set
    // backfill_after back to NULL and the next run would re-enumerate from the start, which for
    // a large org means re-pushing tens of thousands of users.
    state
        .scim_push_sync_state()
        .begin_backfill(&connection)
        .await
        .expect("begin again after a restart");

    let resumed = state
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(
        resumed.backfill_after.as_deref(),
        Some("usr_500"),
        "the restart rewound the backfill"
    );
    assert_eq!(resumed.backfill_state, ScimPushBackfillState::Users);
    assert_eq!(
        resumed.cursor_sequence, None,
        "a running backfill must not be tailing"
    );
}

#[tokio::test]
async fn tailing_cannot_start_before_the_backfill_is_complete() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);

    store
        .scim_push_sync_state()
        .begin_backfill(&connection)
        .await
        .expect("begin");

    // THE DEFECT THIS EXCLUDES. A connection that tails while its backfill is still running
    // meets the first event for a user the backfill has not reached, CREATES that user, and the
    // backfill then creates them a second time. That is the duplicate criterion 3 forbids,
    // arriving through the one door the externalId lookup does not cover.
    let early = store
        .scim_push_sync_state()
        .advance(&connection, Some(0), 1)
        .await;
    assert!(
        matches!(early, Err(StoreError::NotFound)),
        "a connection tailed before its backfill finished: {early:?}"
    );

    // CONTROL: the very same call succeeds once the backfill is complete, so the refusal above
    // is the backfill state doing the refusing and not the call being broken.
    store
        .scim_push_sync_state()
        .complete_backfill(&connection, 0)
        .await
        .expect("complete");
    store
        .scim_push_sync_state()
        .advance(&connection, Some(0), 1)
        .await
        .expect("tailing starts once the backfill is done");

    let tailing = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(tailing.cursor_sequence, Some(1));
    assert_eq!(tailing.backfill_state, ScimPushBackfillState::Done);
    assert_eq!(
        tailing.backfill_after, None,
        "a completed backfill left its resume point behind"
    );

    // AND POSTGRES ENFORCES IT TOO, not just the repository predicate above.
    //
    // This arm exists because deleting the column CHECK from 0191 broke NOTHING: the assertions
    // above are all satisfied by the repository's `AND backfill_state = 'complete'`, so the
    // constraint was decoration. The two are not redundant. The predicate protects the callers
    // that exist; the CHECK protects the ones that do not exist yet, and a method added later
    // that forgets the predicate is exactly how a connection starts tailing mid-backfill.
    let mut tx = db.app_pool().begin().await.expect("begin");
    for (name, value) in [
        ("ironauth.tenant_id", scope.tenant().to_string()),
        ("ironauth.environment_id", scope.environment().to_string()),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(name)
            .bind(value)
            .execute(&mut *tx)
            .await
            .expect("set the scope");
    }
    let rogue = sqlx::query(
        "UPDATE scim_push_connections SET backfill_state = 'users', cursor_sequence = 9 \
         WHERE tenant_id = $1 AND environment_id = $2 AND id = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(connection.to_string())
    .execute(&mut *tx)
    .await;
    let code = rogue
        .expect_err("a cursor was set on a connection whose backfill is not complete")
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned);
    // The CODE, not merely a failure: row-level security and a missing grant also fail here, and
    // either would let this pass while the CHECK was gone. 0190's vocabulary test was caught by
    // exactly that, answering 42501.
    assert_eq!(
        code.as_deref(),
        Some("23514"),
        "refused, but not by the no-tailing-before-backfill CHECK"
    );
}

#[tokio::test]
async fn completing_a_backfill_writes_the_cursor_and_cannot_clobber_one_that_is_tailing() {
    // WHY THIS EXISTS. `complete_backfill` writes `cursor`, and the value it writes was measured
    // by nothing: every call in this file was followed immediately by an `advance` that supplied
    // its own cursor, so deleting `cursor = $4` from the statement left all six tests green. The
    // five-line doc comment arguing for that exact value was decoration.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);

    store
        .scim_push_sync_state()
        .begin_backfill(&connection)
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection, 42)
        .await
        .expect("complete");

    // READ IT BACK BEFORE ANYTHING ELSE WRITES. The tail must resume from the position the
    // caller read BEFORE enumerating, so the overlap is re-applied idempotently rather than lost.
    let after = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(
        after.cursor_sequence,
        Some(42),
        "the backfill did not store the position it was given"
    );

    // AND IT CANNOT RUN AGAIN OVER A LIVE CURSOR.
    //
    // This is the critical half. Without a `backfill_state = 'running'` predicate the statement
    // writes `cursor` on any row it can see, so a worker that restarted, read the CURRENT feed
    // head and re-enumerated would overwrite a cursor that was already tailing. Every event
    // between the old position and the new head is then behind the checkpoint and nothing
    // re-reads it: silent loss, which is the inverse of "pause rather than drop".
    store
        .scim_push_sync_state()
        .advance(&connection, Some(42), 9000)
        .await
        .expect("tail");
    let clobber = store
        .scim_push_sync_state()
        .complete_backfill(&connection, 9500)
        .await;
    assert!(
        matches!(clobber, Err(StoreError::NotFound)),
        "a second complete_backfill moved a live cursor: {clobber:?}"
    );
    let unmoved = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(
        unmoved.cursor_sequence,
        Some(9000),
        "the cursor moved anyway"
    );
}

#[tokio::test]
async fn a_checkpoint_from_a_worker_whose_cursor_moved_underneath_it_is_refused() {
    // NOTHING ELECTS A SINGLE WORKER PER CONNECTION. Two processes, or one restarted before its
    // predecessor noticed, both read a page and both checkpoint. A bare `SET cursor = $n` lets
    // the slower one land last and move the cursor BACKWARDS, so events are re-read; in the
    // mirror case it lands ahead and events are never read at all.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);
    store
        .scim_push_sync_state()
        .begin_backfill(&connection)
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection, 100)
        .await
        .expect("complete");

    // Worker A reads seq-100, does its work, and checkpoints. It wins.
    store
        .scim_push_sync_state()
        .advance(&connection, Some(100), 200)
        .await
        .expect("the first writer checkpoints");

    // Worker B read seq-100 too, and is slower. Its checkpoint would rewind the cursor by a
    // hundred events, every one of which has already been pushed downstream.
    let stale = store
        .scim_push_sync_state()
        .advance(&connection, Some(100), 150)
        .await;
    assert!(
        matches!(stale, Err(StoreError::NotFound)),
        "a stale writer moved the cursor: {stale:?}"
    );
    let held = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(held.cursor_sequence, Some(200));

    // CONTROL: the winner can carry on, so the refusal above is the stale expectation and not
    // the connection being wedged.
    store
        .scim_push_sync_state()
        .advance(&connection, Some(200), 300)
        .await
        .expect("the current holder continues");
}

#[tokio::test]
async fn a_rebuilt_downstream_can_be_enumerated_again() {
    // A completed backfill used to be a dead end: `begin_backfill` is ON CONFLICT DO NOTHING, so
    // nothing could return a row to `running`. That is wrong for the case this feature exists to
    // survive. A downstream that is rebuilt comes back EMPTY, and tailing from a stored cursor
    // never re-creates the resources that predate it: the connection sits healthy, cursor
    // advancing, provisioning nobody who was already there.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);
    store
        .scim_push_sync_state()
        .begin_backfill(&connection)
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection, 100)
        .await
        .expect("complete");
    store
        .scim_push_sync_state()
        .advance(&connection, Some(100), 500)
        .await
        .expect("tail");

    store
        .scim_push_sync_state()
        .restart_backfill(&connection)
        .await
        .expect("re-enumerate");

    let restarted = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(restarted.backfill_state, ScimPushBackfillState::Users);
    // THE CURSOR IS CLEARED, which is what makes this safe rather than merely possible: a
    // connection that went back to enumerating must not also be tailing, and that is the
    // invariant the column CHECK states.
    assert_eq!(
        restarted.cursor_sequence, None,
        "a re-enumerating connection was left tailing: {restarted:?}"
    );
    assert_eq!(restarted.backfill_after, None);

    // AND TAILING IS REFUSED AGAIN until the new enumeration finishes.
    let early = store
        .scim_push_sync_state()
        .advance(&connection, None, 600)
        .await;
    assert!(
        matches!(early, Err(StoreError::NotFound)),
        "a re-enumerating connection could tail: {early:?}"
    );
}

#[tokio::test]
async fn an_outage_pauses_the_cursor_rather_than_moving_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);

    store
        .scim_push_sync_state()
        .begin_backfill(&connection)
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection, 0)
        .await
        .expect("complete");
    store
        .scim_push_sync_state()
        .advance(&connection, Some(0), 7)
        .await
        .expect("advance");

    let resume_at = now_micros(&env) + 60_000_000;
    store
        .scim_push_sync_state()
        .record_failure(&connection, "downstream answered 503", Some(resume_at))
        .await
        .expect("record the failure");

    let paused = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    // THE POINT, and the sentence in #137 it comes from: "a downstream outage pauses the cursor
    // rather than dropping events". A failure that advanced the cursor would skip exactly the
    // events that could not be delivered, and they would never be retried.
    assert_eq!(
        paused.cursor_sequence,
        Some(7),
        "the failure moved the cursor"
    );
    assert_eq!(paused.consecutive_failures, 1);
    assert_eq!(
        paused.last_error.as_deref(),
        Some("downstream answered 503")
    );
    assert!(paused.paused_until_unix_micros.is_some());

    // A SECOND failure counts up, which is what a backoff is computed from.
    store
        .scim_push_sync_state()
        .record_failure(&connection, "downstream answered 503", Some(resume_at))
        .await
        .expect("record the second failure");
    let twice = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(twice.consecutive_failures, 2);

    // AND A SUCCESS CLEARS THE PAUSE. Recovery has to be automatic: a pause that outlived the
    // outage would need an operator to clear it, and nothing would tell them to.
    store
        .scim_push_sync_state()
        .advance(&connection, Some(7), 8)
        .await
        .expect("advance after recovery");
    let recovered = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(recovered.consecutive_failures, 0);
    assert_eq!(recovered.last_error, None);
    assert_eq!(recovered.paused_until_unix_micros, None);
}

#[tokio::test]
async fn a_failure_without_a_new_deadline_leaves_the_pause_that_is_already_running() {
    // WHY THIS EXISTS. `record_failure` took `paused_until: Option<i64>` and wrote it straight
    // in, so `None` CLEARED a pause that was already running. A connection in a backoff would be
    // un-paused by the next failure that happened not to compute a new deadline, which is the
    // opposite of what a failure should do: it would resume hammering a downstream that is
    // already failing, and the backoff would never lengthen.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);
    store
        .scim_push_sync_state()
        .begin_backfill(&connection)
        .await
        .expect("begin");

    let deadline = now_micros(&env) + 300_000_000;
    store
        .scim_push_sync_state()
        .record_failure(&connection, "downstream answered 503", Some(deadline))
        .await
        .expect("the first failure sets a pause");
    let paused = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    let held = paused
        .paused_until_unix_micros
        .expect("the first failure paused the connection");

    // A SECOND FAILURE WITH NO DEADLINE. The count still rises, the message is still recorded,
    // and the pause is LEFT ALONE.
    store
        .scim_push_sync_state()
        .record_failure(&connection, "downstream answered 503 again", None)
        .await
        .expect("the second failure records");
    let still = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(
        still.paused_until_unix_micros,
        Some(held),
        "a failure with no deadline cleared the pause that was running"
    );
    assert_eq!(still.consecutive_failures, 2);

    // CONTROL: a failure that DOES carry a deadline still moves it, so the behaviour above is
    // "leave it alone", not "never write it".
    let later = held + 600_000_000;
    store
        .scim_push_sync_state()
        .record_failure(&connection, "still failing", Some(later))
        .await
        .expect("the third failure extends the pause");
    let extended = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(extended.paused_until_unix_micros, Some(later));
}

#[tokio::test]
async fn the_due_index_can_serve_a_pause_that_has_expired() {
    // WHY AN INDEX HAS A TEST.
    //
    // The first version was `WHERE paused_until IS NULL`, and a pause here is a self-clearing
    // DEADLINE: the worker's due query is `paused_until IS NULL OR paused_until <= now()`. A
    // partial index holding only the NULL rows can never serve the second half, so a connection
    // whose outage had ENDED was excluded from the index for ever. That is the exact opposite of
    // the recovery property the deadline was chosen for, and no behavioural test can see it: the
    // rows are still correct, they are just unreachable by the plan the worker will use.
    //
    // So this asserts the index DEFINITION, which is the only place the property lives.
    let db = TestDatabase::start().await;
    let definition: String = sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE indexname = 'scim_push_connections_due'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("the due index exists");

    // NOT "has no WHERE clause". 0192's index is partial on `active`, which is legitimate: a
    // disabled connection is never due, so excluding it shrinks the index without hiding
    // anything a query would ask for. The property that matters is narrower and precise: the
    // predicate must not filter on `paused_until`, because the due query asks for rows whose
    // pause has EXPIRED and a `paused_until IS NULL` predicate can never return one.
    let predicate = definition
        .split_once(" WHERE ")
        .map(|(_, w)| w.to_owned())
        .unwrap_or_default();
    assert!(
        !predicate.contains("paused_until"),
        "the due index filters on paused_until, so a connection whose outage ENDED is \
         unreachable through it: {definition}"
    );
    assert!(
        definition.contains("paused_until"),
        "the due index cannot range-scan expired pauses: {definition}"
    );
    assert!(
        definition.contains("last_polled_at"),
        "the due index cannot order the work: {definition}"
    );

    // AND THE QUERY THE WORKER WILL ACTUALLY RUN returns a connection whose pause has passed.
    // The index assertions above are about the plan; this is about the answer.
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);
    store
        .scim_push_sync_state()
        .begin_backfill(&connection)
        .await
        .expect("begin");
    // A pause that expired a minute ago.
    store
        .scim_push_sync_state()
        .record_failure(
            &connection,
            "past outage",
            Some(now_micros(&env) - 60_000_000),
        )
        .await
        .expect("record");

    let due: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM scim_push_connections \
         WHERE tenant_id = $1 AND environment_id = $2 AND active \
           AND (paused_until IS NULL OR paused_until <= now())",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("the due query runs");
    assert_eq!(
        due, 1,
        "a connection whose pause has expired is not due, so it would never run again"
    );
}

#[tokio::test]
async fn an_empty_poll_is_distinguishable_from_a_wedged_worker() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);

    store
        .scim_push_sync_state()
        .begin_backfill(&connection)
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection, 0)
        .await
        .expect("complete");
    store
        .scim_push_sync_state()
        .advance(&connection, Some(0), 3)
        .await
        .expect("advance");

    let before = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");

    // A POLL THAT FOUND NOTHING moves `last_polled_at` and leaves `last_event_at` alone. That
    // separation is what lets the health surface say "this connection is healthy and the feed is
    // quiet" rather than "this connection is four hours behind": one timestamp cannot say both,
    // and the wrong answer sends an operator looking for an outage that is not happening.
    store
        .scim_push_sync_state()
        .record_poll(&connection)
        .await
        .expect("poll");
    let after = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");

    assert_eq!(
        after.last_success_at_unix_micros, before.last_success_at_unix_micros,
        "an empty poll moved the success clock"
    );
    assert_eq!(
        after.cursor_sequence, before.cursor_sequence,
        "an empty poll moved the cursor"
    );
    assert!(
        after.last_polled_at_unix_micros > before.last_polled_at_unix_micros,
        "an empty poll did not move the poll clock: {:?} then {:?}",
        before.last_polled_at_unix_micros,
        after.last_polled_at_unix_micros
    );
}

#[tokio::test]
async fn deleting_the_connection_takes_its_sync_state_with_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    db.store()
        .scoped(scope)
        .scim_push_sync_state()
        .begin_backfill(&connection)
        .await
        .expect("begin");

    // 0189's delete is a hard DELETE, so without the cascade this call fails with 23503 the
    // moment a connection had ever run, and an operator could not remove it.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_push_connections()
        .delete(&env, &org, &connection, None)
        .await
        .expect("delete the connection");

    let left = db
        .store()
        .scoped(scope)
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get");
    assert!(
        left.is_none(),
        "a checkpoint outlived its connection: {left:?}"
    );
}

#[tokio::test]
async fn every_backfill_state_round_trips_and_an_unknown_one_does_not() {
    // WHY THIS EXISTS, and it is 0190's argument in a second place: `backfill_state` is a string
    // with a CHECK in Postgres and an enum in Rust. Adding a variant without extending the CHECK
    // gives a 23514 at the first write; extending the CHECK without teaching `from_str` gives a
    // NotFound on every READ of that row, which reads as "this connection was never enabled" and
    // would make a worker start the whole backfill again.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;

    for state in ScimPushBackfillState::ALL.iter().copied() {
        let mut tx = db.app_pool().begin().await.expect("begin");
        for (name, value) in [
            ("ironauth.tenant_id", scope.tenant().to_string()),
            ("ironauth.environment_id", scope.environment().to_string()),
        ] {
            sqlx::query("SELECT set_config($1, $2, true)")
                .bind(name)
                .bind(value)
                .execute(&mut *tx)
                .await
                .expect("set the scope");
        }
        sqlx::query(
            "UPDATE scim_push_connections SET backfill_state = $4 \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(connection.to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(state.as_str())
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|error| panic!("{} is not writable: {error:?}", state.as_str()));
        tx.commit().await.expect("commit");

        let read = db
            .store()
            .scoped(scope)
            .scim_push_sync_state()
            .get(&connection)
            .await
            .unwrap_or_else(|error| panic!("{} is not readable: {error:?}", state.as_str()))
            .unwrap_or_else(|| panic!("{} round trip lost the row", state.as_str()));
        assert_eq!(read.backfill_state, state);
    }

    // THE NEGATIVE ARM. Counting rows back would not do it: a CHECK that accepted anything would
    // still return the row. This asks Postgres directly and asserts the CODE, because an insert
    // refused by row-level security or a missing grant also fails and would let this pass while
    // the CHECK was absent.
    let mut tx = db.app_pool().begin().await.expect("begin");
    for (name, value) in [
        ("ironauth.tenant_id", scope.tenant().to_string()),
        ("ironauth.environment_id", scope.environment().to_string()),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(name)
            .bind(value)
            .execute(&mut *tx)
            .await
            .expect("set the scope");
    }
    let rogue = sqlx::query(
        "UPDATE scim_push_connections SET backfill_state = 'halfway' \
         WHERE tenant_id = $1 AND environment_id = $2 AND id = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(connection.to_string())
    .execute(&mut *tx)
    .await;
    let code = rogue
        .expect_err("a backfill state outside the vocabulary was accepted")
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned);
    assert_eq!(
        code.as_deref(),
        Some("23514"),
        "refused, but not by the backfill_state CHECK"
    );
}
