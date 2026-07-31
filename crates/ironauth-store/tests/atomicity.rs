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
use ironauth_store::{CorrelationId, EnvironmentId, Scope, StoreError, TenantId};
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
