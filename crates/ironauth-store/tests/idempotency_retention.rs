// SPDX-License-Identifier: MIT OR Apache-2.0

//! Retention for the Idempotency-Key replay store (issue #186), against a real
//! database. 0003 shipped `idempotency_keys` with no expiry, no reaper and no DELETE
//! grant, so it grew without limit. 0109 adds the window; this pins what the window
//! MEANS, in both directions.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, IdempotencyWrite, OrganizationId, Scope, ServiceId, StoreError,
};
use sqlx::Row;

fn actor(env: &Env) -> ActorRef {
    ActorRef::service(ServiceId::generate(env))
}

fn write<'a>(key: &'a str, body: &'a str) -> IdempotencyWrite<'a> {
    IdempotencyWrite {
        credential_ref: "svc_probe",
        key,
        request_fingerprint: "fp",
        response_status: 201,
        response_body: body,
    }
}

/// Create an organization under `key`, returning whether the store accepted it.
async fn create_under_key(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    key: &str,
    body: &str,
) -> Result<(), StoreError> {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(
            env,
            &OrganizationId::generate(env, &scope),
            1_000,
            body,
            Some(write(key, body)),
        )
        .await
}

/// Force a stored key past its window, the way time passing would.
async fn expire(db: &TestDatabase, key: &str) {
    let affected = sqlx::query(
        "UPDATE idempotency_keys SET expires_at = now() - interval '1 second' \
         WHERE idempotency_key = $1",
    )
    .bind(key)
    .execute(db.owner_pool())
    .await
    .expect("age the stored key")
    .rows_affected();
    assert_eq!(affected, 1, "the fixture must actually age a stored row");
}

async fn stored_rows(db: &TestDatabase) -> i64 {
    sqlx::query("SELECT count(*) AS n FROM idempotency_keys")
        .fetch_one(db.owner_pool())
        .await
        .expect("count")
        .get::<i64, _>("n")
}

#[tokio::test]
async fn a_key_inside_its_window_is_still_a_replay() {
    // The direction that must NOT change. Retention is only safe if it leaves the
    // replay contract intact for every key that has not aged out, so this is asserted
    // first and separately: without it, a prune that deleted everything would satisfy
    // the expiry test below and silently destroy idempotency.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    create_under_key(&db, &env, scope, "k-live", "first")
        .await
        .expect("the first create stores its response");

    let stored = db
        .control_store()
        .management()
        .idempotency()
        .lookup("svc_probe", "k-live")
        .await
        .expect("lookup")
        .expect("a live key still replays");
    assert_eq!(stored.response_body, "first");

    let second = create_under_key(&db, &env, scope, "k-live", "second").await;
    assert!(
        matches!(second, Err(StoreError::IdempotencyConflict)),
        "a live key must still refuse a second execution, got {second:?}"
    );
}

#[tokio::test]
async fn an_expired_key_is_treated_as_fresh_rather_than_a_replay() {
    // The issue's own acceptance. Past the window the stored response stops being a
    // replay and the caller RE-EXECUTES, which is the documented contract for a key
    // older than the window rather than a failure.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    create_under_key(&db, &env, scope, "k-old", "first")
        .await
        .expect("the first create stores its response");
    expire(&db, "k-old").await;

    let looked_up = db
        .control_store()
        .management()
        .idempotency()
        .lookup("svc_probe", "k-old")
        .await
        .expect("lookup");
    assert!(
        looked_up.is_none(),
        "an expired key must not answer as a stored response"
    );

    // The discriminating half: the expired row still OCCUPIES the primary key, so a
    // re-execution under the same key only succeeds if the write path releases it.
    // Without that release this returns IdempotencyConflict and the caller is told to
    // replay a response the lookup above just reported absent.
    create_under_key(&db, &env, scope, "k-old", "second")
        .await
        .expect("an expired key re-executes rather than conflicting");

    let stored = db
        .control_store()
        .management()
        .idempotency()
        .lookup("svc_probe", "k-old")
        .await
        .expect("lookup")
        .expect("the re-execution stored its own response");
    assert_eq!(
        stored.response_body, "second",
        "the fresh execution's response replaced the expired one"
    );
}

#[tokio::test]
async fn a_write_prunes_expired_rows_and_keeps_live_ones() {
    // The bounding property: the table shrinks on ordinary traffic, and it shrinks
    // ONLY by rows that have aged out.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    for key in ["k-a", "k-b", "k-c"] {
        create_under_key(&db, &env, scope, key, key)
            .await
            .expect("store a response");
    }
    assert_eq!(stored_rows(&db).await, 3);

    expire(&db, "k-a").await;
    expire(&db, "k-b").await;

    // Any subsequent idempotent write carries the prune.
    create_under_key(&db, &env, scope, "k-d", "d")
        .await
        .expect("store a response");

    let remaining: Vec<String> = sqlx::query("SELECT idempotency_key AS k FROM idempotency_keys")
        .fetch_all(db.owner_pool())
        .await
        .expect("read the surviving keys")
        .into_iter()
        .map(|row| row.get::<String, _>("k"))
        .collect();
    let mut remaining = remaining;
    remaining.sort();
    assert_eq!(
        remaining,
        vec!["k-c".to_owned(), "k-d".to_owned()],
        "only the aged-out rows are pruned"
    );
}

#[tokio::test]
async fn a_key_left_behind_by_a_full_prune_batch_is_still_released() {
    // The case the targeted release exists for, and it is NOT reachable at small
    // scale: with only a handful of expired rows the bounded batch happens to remove
    // the key being rewritten, so the release looks redundant. Measured, not assumed:
    // removing the release left every other test in this file green.
    //
    // Here the batch is saturated with OLDER expired rows, so the ordered drain takes
    // all of them and never reaches the target. The expired target row therefore still
    // holds the primary key when the insert runs, which is exactly the state that
    // turns a fresh request into a spurious IdempotencyConflict.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    create_under_key(&db, &env, scope, "k-target", "first")
        .await
        .expect("store the target response");

    // 100 rows (one full batch) that all expired BEFORE the target does.
    for index in 0..100 {
        sqlx::query(
            "INSERT INTO idempotency_keys \
             (credential_ref, idempotency_key, request_fingerprint, response_status, \
              response_body, expires_at) \
             VALUES ($1, $2, 'fp', 200, 'filler', now() - interval '1 hour' - ($3 || ' seconds')::interval)",
        )
        .bind("svc_filler")
        .bind(format!("filler-{index}"))
        .bind(index.to_string())
        .execute(db.owner_pool())
        .await
        .expect("seed a filler row");
    }
    // The target expires most recently, so the oldest-first batch never reaches it.
    expire(&db, "k-target").await;

    create_under_key(&db, &env, scope, "k-target", "second")
        .await
        .expect("an expired key must re-execute even when the prune batch is full");

    let stored = db
        .control_store()
        .management()
        .idempotency()
        .lookup("svc_probe", "k-target")
        .await
        .expect("lookup")
        .expect("the re-execution stored its own response");
    assert_eq!(stored.response_body, "second");
}
