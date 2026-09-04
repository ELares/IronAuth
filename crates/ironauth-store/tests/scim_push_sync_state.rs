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
    CorrelationId, NewScimPushConnection, OrganizationId, ScimBackfillState, ScimDeletionPolicy,
    ScimPushConnectionId, ScimWriteMode, Scope, StoreError,
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
        .begin_backfill(&connection, Some(0))
        .await
        .expect("begin");
    state
        .scim_push_sync_state()
        .record_backfill_progress(&connection, "usr_500", 0, true)
        .await
        .expect("progress");

    // THE RESTART. A worker that comes back up calls `begin_backfill` again, and the whole point
    // is that this second call does NOT rewind: an INSERT that overwrote the row would set
    // backfill_after back to NULL and the next run would re-enumerate from the start, which for
    // a large org means re-pushing tens of thousands of users.
    state
        .scim_push_sync_state()
        .begin_backfill(&connection, Some(0))
        .await
        .expect("begin again after a restart");

    let resumed = state
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(
        resumed.backfill_after_id.as_deref(),
        Some("usr_500"),
        "the restart rewound the backfill"
    );
    assert_eq!(resumed.backfill_state, ScimBackfillState::Users);
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
        .begin_backfill(&connection, Some(0))
        .await
        .expect("begin");

    // THE DEFECT THIS EXCLUDES. A connection that tails while its backfill is still running
    // meets the first event for a user the backfill has not reached, CREATES that user, and the
    // backfill then creates them a second time. That is the duplicate criterion 3 forbids,
    // arriving through the one door the externalId lookup does not cover.
    let early = store
        .scim_push_sync_state()
        .advance(&connection, Some(0), 0, 1, true)
        .await;
    assert!(
        matches!(early, Err(StoreError::NotFound)),
        "a connection tailed before its backfill finished: {early:?}"
    );

    // CONTROL: the very same call succeeds once the backfill is complete, so the refusal above
    // is the backfill state doing the refusing and not the call being broken.
    store
        .scim_push_sync_state()
        .begin_group_backfill(&connection)
        .await
        .expect("users done, on to groups");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection)
        .await
        .expect("complete");
    store
        .scim_push_sync_state()
        .advance(&connection, Some(0), 0, 1, true)
        .await
        .expect("tailing starts once the backfill is done");

    let tailing = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(tailing.cursor_sequence, Some(1));
    assert_eq!(tailing.backfill_state, ScimBackfillState::Done);
    assert_eq!(
        tailing.backfill_after_id, None,
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
        .begin_backfill(&connection, Some(42))
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .begin_group_backfill(&connection)
        .await
        .expect("users done, on to groups");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection)
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
        .advance(&connection, Some(42), 0, 9000, true)
        .await
        .expect("tail");
    // NO TRANSITION HERE, deliberately. This connection is TAILING, and the point of the
    // assertion below is that `complete_backfill` refuses it. The refusal is now structural
    // rather than incidental: completing requires the `groups` state, and a tailing connection is
    // `done`, so a second completion cannot reach the cursor at all.
    let clobber = store
        .scim_push_sync_state()
        .complete_backfill(&connection)
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
        .begin_backfill(&connection, Some(100))
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .begin_group_backfill(&connection)
        .await
        .expect("users done, on to groups");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection)
        .await
        .expect("complete");

    // Worker A reads seq-100, does its work, and checkpoints. It wins.
    store
        .scim_push_sync_state()
        .advance(&connection, Some(100), 0, 200, true)
        .await
        .expect("the first writer checkpoints");

    // Worker B read seq-100 too, and is slower. Its checkpoint would rewind the cursor by a
    // hundred events, every one of which has already been pushed downstream.
    let stale = store
        .scim_push_sync_state()
        .advance(&connection, Some(100), 0, 150, true)
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
        .advance(&connection, Some(200), 0, 300, true)
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
        .begin_backfill(&connection, Some(100))
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .begin_group_backfill(&connection)
        .await
        .expect("users done, on to groups");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection)
        .await
        .expect("complete");
    store
        .scim_push_sync_state()
        .advance(&connection, Some(100), 0, 500, true)
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
    assert_eq!(restarted.backfill_state, ScimBackfillState::Users);
    // THE CURSOR IS CLEARED, which is what makes this safe rather than merely possible: a
    // connection that went back to enumerating must not also be tailing, and that is the
    // invariant the column CHECK states.
    assert_eq!(
        restarted.cursor_sequence, None,
        "a re-enumerating connection was left tailing: {restarted:?}"
    );
    assert_eq!(restarted.backfill_after_id, None);

    // AND TAILING IS REFUSED AGAIN until the new enumeration finishes.
    let early = store
        .scim_push_sync_state()
        .advance(&connection, None, 0, 600, true)
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
        .begin_backfill(&connection, Some(0))
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .begin_group_backfill(&connection)
        .await
        .expect("users done, on to groups");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection)
        .await
        .expect("complete");
    store
        .scim_push_sync_state()
        .advance(&connection, Some(0), 0, 7, true)
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
        .advance(&connection, Some(7), 2, 8, true)
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
async fn a_checkpoint_cannot_erase_a_pause_that_began_after_the_pass_started() {
    // WHY THIS EXISTS. The checkpoint compares the cursor but CLEARS seven columns: the failure
    // count, the error and its time, and the pause, as well as moving the cursor and the clocks.
    // `record_failure` writes those health columns without touching the cursor, so a guard that
    // compared only the cursor could not see one at all.
    //
    // The sequence that breaks it is ordinary. A pass reads the state, pushes a page slowly, and
    // while it is in flight the downstream fails a DIFFERENT pass, which pauses the connection.
    // The slow pass then checkpoints against the cursor it still holds, which is unchanged, and
    // the pause it never saw is erased. #137 asks for an outage to pause the cursor; a pause any
    // in-flight pass can clear on its way past is not one.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);

    store
        .scim_push_sync_state()
        .begin_backfill(&connection, Some(0))
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .begin_group_backfill(&connection)
        .await
        .expect("users done, on to groups");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection)
        .await
        .expect("complete");

    // The slow pass reads here. Both of the values it will compare are what it holds from now on.
    let read = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(read.cursor_sequence, Some(0));
    assert_eq!(read.consecutive_failures, 0);

    // The outage happens while it is in flight. Note the cursor does NOT move.
    let resume_at = now_micros(&env) + 60_000_000;
    store
        .scim_push_sync_state()
        .record_failure(&connection, "downstream answered 503", Some(resume_at))
        .await
        .expect("record the failure");

    let refused = store
        .scim_push_sync_state()
        .advance(
            &connection,
            read.cursor_sequence,
            read.consecutive_failures,
            9,
            true,
        )
        .await;
    assert!(
        matches!(refused, Err(StoreError::NotFound)),
        "a checkpoint erased a failure state its caller never saw: {refused:?}"
    );

    // AND THE PAUSE IS STILL THERE, which is the half that matters operationally: refusing the
    // write is only useful if the outage state survives it.
    let after = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(after.consecutive_failures, 1, "the failure count was reset");
    assert_eq!(
        after.last_error.as_deref(),
        Some("downstream answered 503"),
        "the error was cleared"
    );
    assert!(
        after.paused_until_unix_micros.is_some(),
        "the pause was cleared"
    );
    assert_eq!(after.cursor_sequence, Some(0), "the cursor moved anyway");

    // A PASS THAT DID SEE THE FAILURE STILL CHECKPOINTS. The guard has to refuse a stale caller
    // without refusing recovery, or an outage would be permanent.
    store
        .scim_push_sync_state()
        .advance(&connection, Some(0), 1, 9, true)
        .await
        .expect("a caller holding the current failure count checkpoints");
    let recovered = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(recovered.cursor_sequence, Some(9));
    assert_eq!(recovered.consecutive_failures, 0);
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
        .begin_backfill(&connection, Some(0))
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
        .begin_backfill(&connection, Some(0))
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
async fn recording_backfill_progress_carries_the_same_two_guards_as_the_checkpoint() {
    // WHY THIS EXISTS. `record_backfill_progress` clears the identical failure state the
    // checkpoint clears -- the count, the error and its time, and the pause -- and it did so
    // against no comparison at all, and stamped `last_success_at` whatever the subject did.
    //
    // Both are the defects that were fixed on the tail path, still live on the backfill path.
    // Naming a guard on one of two sibling writers and calling the defect closed is how a fix
    // gets believed to be everywhere while it is in one place.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);

    store
        .scim_push_sync_state()
        .begin_backfill(&connection, Some(0))
        .await
        .expect("begin");

    // A subject that DID reach the downstream, so there is a success to be wrongly overwritten.
    store
        .scim_push_sync_state()
        .record_backfill_progress(&connection, "usr_100", 0, true)
        .await
        .expect("a delivered subject records progress");
    let delivered = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    let success_at = delivered
        .last_success_at_unix_micros
        .expect("a delivered subject records a success");

    // A subject that was enumerated and then vanished: progress moves, the success does not.
    store
        .scim_push_sync_state()
        .record_backfill_progress(&connection, "usr_101", 0, false)
        .await
        .expect("a vanished subject still records progress");
    let skipped = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(
        skipped.backfill_after_id.as_deref(),
        Some("usr_101"),
        "progress must move: this subject will not be enumerated again"
    );
    assert_eq!(
        skipped.last_success_at_unix_micros,
        Some(success_at),
        "a subject that reached no downstream claimed a delivery"
    );

    // AND THE OUTAGE STATE IS GUARDED. A pass that began before a failure cannot clear it.
    let resume_at = now_micros(&env) + 60_000_000;
    store
        .scim_push_sync_state()
        .record_failure(&connection, "downstream answered 503", Some(resume_at))
        .await
        .expect("record the failure");
    let stale = store
        .scim_push_sync_state()
        .record_backfill_progress(&connection, "usr_102", 0, true)
        .await;
    assert!(
        matches!(stale, Err(StoreError::NotFound)),
        "a backfill record erased a failure state its caller never saw: {stale:?}"
    );
    let after = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(after.consecutive_failures, 1, "the failure count was reset");
    assert!(
        after.paused_until_unix_micros.is_some(),
        "the pause was cleared"
    );
    assert_eq!(
        after.backfill_after_id.as_deref(),
        Some("usr_101"),
        "the refused record moved progress anyway"
    );

    // A caller that DID see the failure still records, or an outage would freeze the backfill.
    store
        .scim_push_sync_state()
        .record_backfill_progress(&connection, "usr_102", 1, true)
        .await
        .expect("a caller holding the current failure count records progress");
    let recovered = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(recovered.consecutive_failures, 0);
    assert_eq!(recovered.paused_until_unix_micros, None);
}

#[tokio::test]
async fn completing_a_backfill_does_not_claim_a_success_it_never_made() {
    // WHY THIS EXISTS. `complete_backfill` runs on the EMPTY groups page -- the pass that finds
    // nothing left to enumerate -- and it stamped `last_success_at`. A connection whose scope
    // filter matches nobody therefore reported a fresh delivery having never sent one request,
    // which is the one case where an operator most needs the surface to say so.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);

    store
        .scim_push_sync_state()
        .begin_backfill(&connection, Some(0))
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .begin_group_backfill(&connection)
        .await
        .expect("users done, on to groups");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection)
        .await
        .expect("complete");

    let done = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert!(
        done.backfill_state.is_done(),
        "the backfill did not complete"
    );
    assert_eq!(
        done.last_success_at_unix_micros, None,
        "an empty scope claimed a delivery it never made"
    );
    assert_eq!(
        done.cursor_sequence,
        Some(0),
        "completing must still hand the tail its starting position"
    );
}

#[tokio::test]
async fn a_page_that_delivered_nothing_moves_the_cursor_without_claiming_a_success() {
    // WHY THIS EXISTS. The checkpoint stamped `last_success_at = now()` on any non-empty page,
    // and the management view says of that column that it "moves only when something was written
    // downstream". The two disagreed, and the view was the one telling the truth about what an
    // operator needs.
    //
    // It is not a corner case. The feed carries every event the environment emits and a SCIM
    // connection translates almost none of them, so a page with nothing to push is the ORDINARY
    // page. Stamping success on it made the column an alias for `last_polled_at`, and the
    // question it exists to answer -- has this connection delivered anything lately -- had no
    // column left that could answer it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    let store = db.store().scoped(scope);

    store
        .scim_push_sync_state()
        .begin_backfill(&connection, Some(0))
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .begin_group_backfill(&connection)
        .await
        .expect("users done, on to groups");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection)
        .await
        .expect("complete");

    // A page that DID deliver, so there is a success timestamp to be wrongly overwritten later.
    store
        .scim_push_sync_state()
        .advance(&connection, Some(0), 0, 10, true)
        .await
        .expect("a delivering page checkpoints");
    let delivered = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    let success_at = delivered
        .last_success_at_unix_micros
        .expect("a delivering page records a success");

    // Now a page that read events, moved the cursor, and pushed nothing at all.
    store
        .scim_push_sync_state()
        .advance(&connection, Some(10), 0, 20, false)
        .await
        .expect("a page carrying no provisioning signal still checkpoints");
    let quiet = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");

    assert_eq!(
        quiet.cursor_sequence,
        Some(20),
        "the cursor must move: those events are read and will not be offered again"
    );
    assert_eq!(
        quiet.last_success_at_unix_micros,
        Some(success_at),
        "a page that pushed nothing claimed a delivery"
    );
    // AND THE POLL CLOCK STILL MOVES, which is the pair that makes the surface readable: the
    // worker is running (it polled) and it is not delivering (no success since).
    assert!(
        quiet.last_polled_at_unix_micros >= delivered.last_polled_at_unix_micros,
        "the poll clock stalled, so a running worker looks wedged"
    );
    assert!(
        quiet.last_polled_at_unix_micros.is_some(),
        "a checkpoint that does not record the poll leaves nothing saying the worker ran"
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
        .begin_backfill(&connection, Some(0))
        .await
        .expect("begin");
    store
        .scim_push_sync_state()
        .begin_group_backfill(&connection)
        .await
        .expect("users done, on to groups");
    store
        .scim_push_sync_state()
        .complete_backfill(&connection)
        .await
        .expect("complete");
    store
        .scim_push_sync_state()
        .advance(&connection, Some(0), 0, 3, true)
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
        .begin_backfill(&connection, Some(0))
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

    for state in ScimBackfillState::ALL.iter().copied() {
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
