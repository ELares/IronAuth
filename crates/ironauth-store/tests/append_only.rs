// SPDX-License-Identifier: MIT OR Apache-2.0

//! Append-only enforcement on the audit log, verified AS the low-privilege
//! application role.
//!
//! The application role is granted SELECT and INSERT on `audit_log` but never
//! UPDATE, DELETE, or TRUNCATE. A row, once written, cannot be rewritten or
//! erased by the role the application connects as, nor can the log be wiped
//! wholesale; retention is a separate, privileged operation. This runs every
//! statement as `ironauth_app` (neither a superuser nor the table owner, so
//! grants and row-level security genuinely apply) and proves UPDATE, DELETE, and
//! TRUNCATE are refused while INSERT and SELECT in scope work.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{AuditId, CorrelationId, ServiceId};
use sqlx::Row;

/// The Postgres "insufficient privilege" SQLSTATE.
const INSUFFICIENT_PRIVILEGE: &str = "42501";

fn is_permission_denied(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == INSUFFICIENT_PRIVILEGE)
}

#[tokio::test]
async fn app_role_may_select_and_insert_but_never_update_or_delete_audit_rows() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Write a real audit row through a mutation (as the app role).
    let target = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "audited client")
        .await
        .expect("create");

    let pool = db.app_pool();

    // Precondition: we are the low-privilege role, not a superuser.
    let who = sqlx::query(
        "SELECT current_user AS u, \
         (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_super",
    )
    .fetch_one(pool)
    .await
    .expect("identify session role");
    assert_eq!(
        who.get::<String, _>("u"),
        "ironauth_app",
        "test must run as the low-privilege role"
    );
    assert!(
        !who.get::<bool, _>("is_super"),
        "the low-privilege role must not be a superuser"
    );

    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    // SELECT in scope works and sees the row.
    {
        let mut tx = pool.begin().await.expect("begin select");
        bind_scope(&mut tx, &tenant, &environment).await;
        let count: i64 = sqlx::query("SELECT count(*) AS c FROM audit_log")
            .fetch_one(&mut *tx)
            .await
            .expect("select audit rows in scope")
            .get("c");
        assert_eq!(count, 1, "SELECT in scope returns the audit row");
        tx.commit().await.expect("commit select");
    }

    // UPDATE, DELETE, and TRUNCATE are each denied: the role has none of those
    // grants on audit_log, so a row can be neither rewritten, erased, nor the
    // log wiped wholesale.
    assert_denied_in_scope(
        pool,
        &tenant,
        &environment,
        "UPDATE audit_log SET action = 'tampered'",
    )
    .await;
    assert_denied_in_scope(pool, &tenant, &environment, "DELETE FROM audit_log").await;
    assert_denied_in_scope(pool, &tenant, &environment, "TRUNCATE audit_log").await;

    // INSERT in scope works: append-only permits appends.
    {
        let mut tx = pool.begin().await.expect("begin insert");
        bind_scope(&mut tx, &tenant, &environment).await;
        let result = sqlx::query(
            "INSERT INTO audit_log \
             (id, tenant_id, environment_id, action, actor_kind, actor_id, \
              target_kind, target_id, correlation_id, occurred_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())",
        )
        .bind(AuditId::generate(&env, &scope).to_string())
        .bind(&tenant)
        .bind(&environment)
        .bind("client.create")
        .bind("service")
        .bind(ServiceId::generate(&env).to_string())
        .bind("cli")
        .bind(target.to_string())
        .bind(CorrelationId::generate(&env).to_string())
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_ok(),
            "INSERT in scope must be permitted for an append-only log: {result:?}"
        );
        tx.commit().await.expect("commit insert");
    }
}

/// Run `statement` in a scoped transaction as the application role and assert it
/// is refused as insufficient privilege (append-only enforcement).
async fn assert_denied_in_scope(
    pool: &sqlx::PgPool,
    tenant: &str,
    environment: &str,
    statement: &str,
) {
    let mut tx = pool.begin().await.expect("begin denied-statement tx");
    bind_scope(&mut tx, tenant, environment).await;
    let result = sqlx::query(statement).execute(&mut *tx).await;
    assert!(
        result.as_ref().err().is_some_and(is_permission_denied),
        "statement must be refused as insufficient privilege: {statement:?} -> {result:?}"
    );
    let _ = tx.rollback().await;
}

/// Bind the transaction-local row-level-security scope variables, exactly as the
/// repository does.
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
