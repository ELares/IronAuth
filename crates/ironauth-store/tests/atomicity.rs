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
    assert!(
        matches!(result, Err(StoreError::Database(_))),
        "create against an unseeded scope must fail the foreign key: {result:?}"
    );

    assert_eq!(
        count_all(&db, "audit_log").await,
        0,
        "a failed data insert writes no audit row"
    );
    assert_eq!(count_all(&db, "clients").await, 0, "and no client row");
}
