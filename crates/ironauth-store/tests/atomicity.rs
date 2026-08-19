// SPDX-License-Identifier: MIT OR Apache-2.0

//! Same-transaction atomicity of the audited-write primitive.
//!
//! The contract is that a data change and its audit row commit together or not
//! at all. Both directions are proved: a failure after both inserts leaves no
//! orphan of either kind, and a data-insert failure writes no audit row. Counts
//! are read through the owner pool, which bypasses row-level security and so
//! would reveal an orphan in any scope.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, EnvironmentId, IdempotencyWrite, NewOutboxMessage, Scope, StoreError, TenantId,
};
use sqlx::Row;

/// Count every row in `table` via the owner pool (bypasses row-level security).
async fn count_all(db: &TestDatabase, table: &str) -> i64 {
    // `table` is a fixed test-local literal, never user input.
    sqlx::query(&format!("SELECT count(*) AS c FROM {table}"))
        .fetch_one(db.owner_pool())
        .await
        .expect("count rows")
        .get("c")
}

#[tokio::test]
async fn a_mid_transaction_failure_leaves_no_orphan_data_or_audit_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let writer = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients();

    assert_eq!(count_all(&db, "clients").await, 0, "baseline: no clients");
    assert_eq!(
        count_all(&db, "audit_log").await,
        0,
        "baseline: no audit rows"
    );

    // Run a real create (client insert + audit insert), then force a guaranteed
    // failure inside the SAME transaction. Because all three share one
    // transaction, the failure rolls back both inserts.
    let result = writer
        .create_injecting_post_audit_failure(&env, "doomed")
        .await;
    assert!(
        matches!(result, Err(StoreError::Database(_))),
        "the poisoned write must fail: {result:?}"
    );

    // No orphan client row and no orphan audit row survive.
    assert_eq!(
        count_all(&db, "clients").await,
        0,
        "a mid-transaction failure leaves no orphan client row"
    );
    assert_eq!(
        count_all(&db, "audit_log").await,
        0,
        "a mid-transaction failure leaves no orphan audit row"
    );
}

#[tokio::test]
async fn a_data_insert_failure_writes_no_audit_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // A scope whose tenant and environment were never seeded. The client insert
    // passes the row-level-security WITH CHECK (its scope matches the bound
    // session variables) but violates the foreign key to `environments`, so the
    // data insert fails before any audit row could be written.
    let unseeded = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
    let writer = db
        .store()
        .scoped(unseeded)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients();

    assert_eq!(
        count_all(&db, "audit_log").await,
        0,
        "baseline: no audit rows"
    );

    let result = writer.create(&env, "orphan attempt").await;
    // The REFUSAL SHAPE changed under this test and its subject did not (issues #409,
    // #449). A write into a scope that was never created trips the foreign key exactly
    // as it always did, and nothing about the atomicity this file exists to pin has
    // moved; what changed is that the store now reports that failure as the uniform
    // not-found rather than as a database FAULT, because on the unauthenticated data
    // plane the difference between the two was an environment existence oracle.
    //
    // But asserting the VARIANT no longer pins the failure injector, and the earlier
    // wording here claimed that it did. `StoreError::Database` could only come from
    // Postgres, so the old assertion ruled out a write that never reached the database;
    // `NotFound` is returned by early guards throughout the store, so it does not. That
    // was MEASURED: short-circuiting `ClientRepo::create` with a bare `NotFound` before
    // it touches Postgres left this test green, with both counts below passing against a
    // write that never ran. The control at the end of the test is what rules that out.
    assert!(
        matches!(result, Err(StoreError::NotFound)),
        "create against an unseeded scope must fail the foreign key, reported as the \
         uniform not-found: {result:?}"
    );

    assert_eq!(
        count_all(&db, "audit_log").await,
        0,
        "a failed data insert writes no audit row"
    );
    assert_eq!(count_all(&db, "clients").await, 0, "and no client row");

    // THE CONTROL. The SAME call, differing only in that its scope was seeded, has to
    // SUCCEED and write both rows. Without it the two counts above measure nothing: a
    // create that refused everything before reaching Postgres would satisfy them too,
    // and the failure this test exists to inject would no longer be the foreign key.
    let seeded = db.seed_scope(&env).await;
    let live = db
        .store()
        .scoped(seeded)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients();
    live.create(&env, "control attempt").await.expect(
        "the same create into a SEEDED scope must succeed, or the refusal above is the \
         store declining to write rather than the foreign key firing",
    );
    assert_eq!(
        count_all(&db, "clients").await,
        1,
        "the control write must land its client row"
    );
    assert_eq!(
        count_all(&db, "audit_log").await,
        1,
        "and its audit row, which is what proves the path under test really writes both"
    );
}

/// The envelope a usage publish carries, built through the SAME catalog helper the endpoint
/// uses. A hand-rolled one is refused by the emit-time schema guard under the `testing`
/// feature, and the failure would then be that guard rather than the rollback under test.
fn usage_envelope(scope: Scope) -> serde_json::Value {
    ironauth_store::event_catalog::envelope(
        PROBE_EVENT_ID,
        "usage.reported",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1_700_000_000_000,
        &serde_json::json!({
            "monthly_active_users": 1,
            "tokens_issued": 2,
            "connections": 3,
            "truncated": false,
        }),
    )
    .expect("the catalog builds a usage.reported envelope")
}

/// The idempotency record a usage publish writes alongside its append.
fn probe_idempotency() -> IdempotencyWrite<'static> {
    IdempotencyWrite {
        credential_ref: "cred_atomicity_probe",
        key: "k-atomicity",
        request_fingerprint: "fingerprint",
        response_status: 200,
        response_body: "{}",
    }
}

/// The three row counts a publish touches: feed, idempotency, audit.
async fn publish_counts(db: &TestDatabase) -> (i64, i64, i64) {
    (
        count_all(db, "outbox_messages").await,
        count_all(db, "idempotency_keys").await,
        count_all(db, "audit_log").await,
    )
}

const PROBE_EVENT_ID: &str = "evt_atomicity_probe";

/// The usage publish's THREE writes commit together or not at all (issue #107).
///
/// Every other audited write in this store carries two rows, the data change and its audit
/// row. This one carries three: the outbox append, the `Idempotency-Key` record, and the
/// audit row. Three is the whole reason it was routed through `write_audited` rather than
/// given a transaction of its own, and that argument had no test for three review rounds.
///
/// The partial failures it rules out are not equivalent, and one of them is silent. An
/// append with no idempotency row means a retried `POST` publishes a SECOND snapshot and the
/// customer is billed twice. An idempotency row with no append means the retry replays a 200
/// describing an event that is not on the feed, so the billing pipeline is never told. An
/// audit row with no append is a record of a publish that did not happen.
#[tokio::test]
async fn a_mid_transaction_failure_leaves_no_publish_no_key_and_no_audit_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    // The CONTROL store, because that is the one the management plane hands this repo:
    // `idempotency_keys` is a control-plane table and only `ironauth_control` may write it.
    let writer = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .usage();
    let ordering = format!("{}/{}", scope.tenant(), scope.environment());
    let message = |scope| NewOutboxMessage {
        consumer: ironauth_store::WEBHOOK_EVENT_CONSUMER,
        idempotency_key: PROBE_EVENT_ID,
        ordering_key: &ordering,
        payload: usage_envelope(scope),
    };

    let before = publish_counts(&db).await;
    assert_eq!(
        (before.0, before.1),
        (0, 0),
        "baseline: no feed row and no idempotency row"
    );

    let result = writer
        .publish_snapshot_injecting_post_audit_failure(
            &env,
            &message(scope),
            Some(probe_idempotency()),
        )
        .await;
    assert!(
        matches!(result, Err(StoreError::Database(_))),
        "the poisoned publish must fail: {result:?}"
    );
    assert_eq!(
        publish_counts(&db).await,
        before,
        "a mid-transaction failure leaves NO event on the feed, no idempotency row (which \
         would make a retry replay a 200 for an event that was never published) and no \
         audit row for a publish that did not happen"
    );

    // THE CONTROL. The same call without the injected failure has to write all three, or
    // the assertion above is satisfied by a method that does nothing at all.
    writer
        .publish_snapshot(&env, &message(scope), Some(probe_idempotency()))
        .await
        .expect("the unpoisoned publish succeeds");
    assert_eq!(
        publish_counts(&db).await,
        (before.0 + 1, before.1 + 1, before.2 + 1),
        "the control appends, records the key and audits"
    );
}
