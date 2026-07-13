// SPDX-License-Identifier: MIT OR Apache-2.0

//! Row-level security as defense in depth, verified as a LOW-PRIVILEGE role.
//!
//! Every statement here runs as `ironauth_app`, which is neither a superuser
//! (superusers bypass row-level security entirely) nor the table owner (owners
//! bypass it unless the table forces row-level security, which these tables do).
//! The test subverts the application-layer filter deliberately and proves the
//! database still refuses the cross-tenant read.

use ironauth_env::Env;
use ironauth_store::ClientId;
use ironauth_store::test_support::TestDatabase;
use sqlx::Row;

// The test walks four distinct scenarios (deny-by-default, mis-scoped read,
// positive control, write-side WITH CHECK) against one fixture, so keeping them
// in one function is clearer than splitting the shared setup.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn rls_blocks_cross_tenant_reads_for_a_low_privilege_role() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // Two tenants sharing one database (the pooled shared-schema model).
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    // A client owned by tenant B, created through the repository as the app role.
    let id_b = db
        .store()
        .scoped(scope_b)
        .clients()
        .create(&env, "tenant B client")
        .await
        .expect("create in B");

    let pool = db.app_pool();

    // Precondition: we really are the low-privilege role. If this were a
    // superuser or the owner, row-level security would be bypassed and the rest
    // of the test would prove nothing.
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

    // 1. Deny by default. No scope variables set on the session: zero rows, even
    //    though a client exists.
    let unset: i64 = sqlx::query("SELECT count(*) AS c FROM clients")
        .fetch_one(pool)
        .await
        .expect("count with unset scope")
        .get("c");
    assert_eq!(unset, 0, "an unset scope must see nothing");

    // 2. Mis-scoped session with the app-layer filter SUBVERTED. The session is
    //    scoped to tenant A, but the query explicitly targets tenant B's rows,
    //    exactly as a bypassed or buggy repository filter would. Row-level
    //    security still returns zero rows: this is the defense-in-depth claim.
    {
        let mut tx = pool.begin().await.expect("begin as tenant A");
        bind_scope(
            &mut tx,
            &scope_a.tenant().to_string(),
            &scope_a.environment().to_string(),
        )
        .await;

        let attacker_filtered: i64 =
            sqlx::query("SELECT count(*) AS c FROM clients WHERE tenant_id = $1")
                .bind(scope_b.tenant().to_string())
                .fetch_one(&mut *tx)
                .await
                .expect("cross-tenant count")
                .get("c");
        assert_eq!(
            attacker_filtered, 0,
            "RLS must hide tenant B rows from a tenant A session even when the app filter is bypassed"
        );

        let blanket: i64 = sqlx::query("SELECT count(*) AS c FROM clients")
            .fetch_one(&mut *tx)
            .await
            .expect("blanket count")
            .get("c");
        assert_eq!(blanket, 0, "tenant A has no clients of its own");
        tx.commit().await.expect("commit A read");
    }

    // 3. Positive control: scoped to tenant B, the same role sees exactly B's row.
    {
        let mut tx = pool.begin().await.expect("begin as tenant B");
        bind_scope(
            &mut tx,
            &scope_b.tenant().to_string(),
            &scope_b.environment().to_string(),
        )
        .await;
        let visible: i64 = sqlx::query("SELECT count(*) AS c FROM clients")
            .fetch_one(&mut *tx)
            .await
            .expect("count in B")
            .get("c");
        assert_eq!(visible, 1, "tenant B sees its own client");
        let seen_id: String = sqlx::query("SELECT id FROM clients")
            .fetch_one(&mut *tx)
            .await
            .expect("select in B")
            .get("id");
        assert_eq!(seen_id, id_b.to_string());
        tx.commit().await.expect("commit B read");
    }

    // 4. Write-side isolation. A tenant A session cannot INSERT a row that
    //    claims to belong to tenant B: the policy's WITH CHECK rejects it.
    {
        let mut tx = pool.begin().await.expect("begin as tenant A for write");
        bind_scope(
            &mut tx,
            &scope_a.tenant().to_string(),
            &scope_a.environment().to_string(),
        )
        .await;
        let forged = ClientId::generate(&env, &scope_b).to_string();
        let result = sqlx::query(
            "INSERT INTO clients (id, tenant_id, environment_id, display_name) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(forged)
        .bind(scope_b.tenant().to_string())
        .bind(scope_b.environment().to_string())
        .bind("smuggled")
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "RLS WITH CHECK must reject writing another tenant's row"
        );
        // Roll back the failed transaction.
        let _ = tx.rollback().await;
    }
}

/// Bind the transaction-local row-level-security scope variables, exactly as
/// the repository does.
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
