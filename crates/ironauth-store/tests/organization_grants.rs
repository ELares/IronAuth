// SPDX-License-Identifier: MIT OR Apache-2.0

//! Least-privilege enforcement of the data-plane role on `organizations` (issue
//! #41 and #94, applying the #31 lesson to the other role).
//!
//! The organization LIFECYCLE is entirely a control-plane operation: no data-plane
//! path creates, mutates, or soft-deletes organizations. Migration 0027 REVOKED the
//! over-broad grant the isolation root (0001) gave the low-privilege `ironauth_app`
//! role when the level was a schema slot only; migration 0084 (M10) re-grants ONLY
//! the data-plane SELECT (membership resolution and org-context validation READ an
//! organization). This proves the shape: as `ironauth_app`, SELECT is now allowed
//! (and still RLS-scoped), but every MUTATING statement on `organizations` is refused
//! as insufficient privilege, so the role can neither HARD DELETE a row (which would
//! break the soft-delete retention the append-only `audit_log` foreign key depends
//! on) nor INSERT or UPDATE any column. The positive control confirms the control
//! role `ironauth_control` keeps its column-scoped soft delete.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ActorRef, CorrelationId, OrganizationId, ServiceId, StoreError};
use sqlx::Row;

/// The Postgres "insufficient privilege" SQLSTATE.
const INSUFFICIENT_PRIVILEGE: &str = "42501";

fn is_permission_denied(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == INSUFFICIENT_PRIVILEGE)
}

#[tokio::test]
async fn app_role_has_read_only_grant_on_organizations_while_control_soft_deletes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // A live organization, created through the control plane (the only plane that
    // manages organizations), so the negative statements below act on a real row
    // and the positive control has something to soft-delete.
    let id = OrganizationId::generate(&env, &scope);
    db.control_store()
        .management()
        .acting(
            ActorRef::service(ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .organizations(scope)
        .create(&env, &id, 1_000_000, "Globex", None)
        .await
        .expect("control plane creates the organization");

    let pool = db.app_pool();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    // Precondition: we are the low-privilege data-plane role, not a superuser (so
    // grants genuinely apply rather than being bypassed).
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
        "the negative test must run as the low-privilege data-plane role"
    );
    assert!(
        !who.get::<bool, _>("is_super"),
        "the low-privilege role must not be a superuser"
    );

    // The two hazards the reviewer called out: a hard DELETE would erase a row and
    // break the soft-delete retention the append-only audit_log foreign key needs,
    // and a non-deleted_at UPDATE would rewrite any column (id, tenant_id,
    // environment_id, display_name). Both are refused as insufficient privilege.
    assert_denied_in_scope(pool, &tenant, &environment, "DELETE FROM organizations").await;
    assert_denied_in_scope(
        pool,
        &tenant,
        &environment,
        "UPDATE organizations SET display_name = 'tampered'",
    )
    .await;

    // INSERT is revoked too: the data plane never WRITES organizations, so the
    // revoke covers the create verb as well as the mutating ones.
    assert_denied_in_scope(
        pool,
        &tenant,
        &environment,
        "INSERT INTO organizations (id, tenant_id, environment_id, display_name) \
         VALUES ('org_probe', 'probe', 'probe', 'probe')",
    )
    .await;

    // SELECT, however, is re-granted in M10 (0084): the data plane READS an
    // organization to validate an org-context and to resolve a membership. It is
    // allowed AND still RLS-scoped, so bound to this scope it sees exactly the one
    // live row and never a foreign-scope organization.
    let mut tx = pool.begin().await.expect("begin select tx");
    bind_scope(&mut tx, &tenant, &environment).await;
    let in_scope: i64 = sqlx::query("SELECT count(*) AS n FROM organizations")
        .fetch_one(&mut *tx)
        .await
        .expect("the data-plane SELECT on organizations is re-granted in M10")
        .get("n");
    assert_eq!(
        in_scope, 1,
        "the app SELECT is RLS-scoped to this scope's row"
    );
    let _ = tx.rollback().await;

    // Positive control: the control role's column-scoped soft delete succeeds, and
    // the organization then reads as absent through the control plane.
    db.control_store()
        .management()
        .acting(
            ActorRef::service(ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .organizations(scope)
        .delete(&env, &id)
        .await
        .expect("control plane soft-deletes the organization");
    assert!(
        matches!(
            db.control_store()
                .management()
                .organizations(scope)
                .get(&id)
                .await,
            Err(StoreError::NotFound)
        ),
        "a soft-deleted organization reads as absent"
    );
}

/// Run `statement` in a scoped transaction as the application role and assert it
/// is refused as insufficient privilege.
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
/// repository does. The privilege check precedes row-level security, so the
/// denials above hold regardless, but binding mirrors a real request.
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
