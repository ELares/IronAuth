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
    assert_eq!(resumed.backfill_state, ScimPushBackfillState::Running);
    assert_eq!(
        resumed.cursor, None,
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
        .advance(&connection, "cursor-1", Some(now_micros(&env)))
        .await;
    assert!(
        matches!(early, Err(StoreError::NotFound)),
        "a connection tailed before its backfill finished: {early:?}"
    );

    // CONTROL: the very same call succeeds once the backfill is complete, so the refusal above
    // is the backfill state doing the refusing and not the call being broken.
    store
        .scim_push_sync_state()
        .complete_backfill(&connection, "cursor-0")
        .await
        .expect("complete");
    store
        .scim_push_sync_state()
        .advance(&connection, "cursor-1", Some(now_micros(&env)))
        .await
        .expect("tailing starts once the backfill is done");

    let tailing = store
        .scim_push_sync_state()
        .get(&connection)
        .await
        .expect("get")
        .expect("a state row");
    assert_eq!(tailing.cursor.as_deref(), Some("cursor-1"));
    assert_eq!(tailing.backfill_state, ScimPushBackfillState::Complete);
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
        "UPDATE scim_push_sync_state SET backfill_state = 'running', cursor = 'cursor-9' \
         WHERE tenant_id = $1 AND environment_id = $2 AND connection_id = $3",
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
        .complete_backfill(&connection, "cursor-0")
        .await
        .expect("complete");
    store
        .scim_push_sync_state()
        .advance(&connection, "cursor-7", Some(now_micros(&env)))
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
        paused.cursor.as_deref(),
        Some("cursor-7"),
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
        .advance(&connection, "cursor-8", Some(now_micros(&env)))
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
        .complete_backfill(&connection, "cursor-0")
        .await
        .expect("complete");
    let applied_at = now_micros(&env);
    store
        .scim_push_sync_state()
        .advance(&connection, "cursor-3", Some(applied_at))
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
        after.last_event_at_unix_micros, before.last_event_at_unix_micros,
        "an empty poll moved the event clock"
    );
    assert_eq!(
        after.cursor, before.cursor,
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
            "INSERT INTO scim_push_sync_state \
             (connection_id, tenant_id, environment_id, backfill_state) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (connection_id) DO UPDATE SET backfill_state = EXCLUDED.backfill_state",
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
        "UPDATE scim_push_sync_state SET backfill_state = 'halfway' \
         WHERE tenant_id = $1 AND environment_id = $2 AND connection_id = $3",
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
