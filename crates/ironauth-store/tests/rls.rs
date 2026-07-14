// SPDX-License-Identifier: MIT OR Apache-2.0

//! Row-level security as defense in depth, verified as a LOW-PRIVILEGE role.
//!
//! Every statement here runs as `ironauth_app`, which is neither a superuser
//! (superusers bypass row-level security entirely) nor the table owner (owners
//! bypass it unless the table forces row-level security, which these tables do).
//! The test subverts the application-layer filter deliberately and proves the
//! database still refuses the cross-tenant read.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ClientId, CorrelationId, InitialAccessTokenId, ManagementKeyId};
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
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
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

/// Deny-by-default must hold on a POOLED connection that already carried a scope,
/// not only on a pristine one. After a repository transaction commits, its
/// transaction-local scope variables revert to the EMPTY STRING, not NULL, so the
/// policy check becomes `tenant_id = ''`. This test reproduces that warmed state
/// and proves the connection still sees nothing, because the CHECK constraints
/// forbid any scoped row from carrying an empty scope. The main test above only
/// exercises the pristine (NULL) path; this closes the reused-connection gap.
#[tokio::test]
async fn rls_denies_by_default_on_a_warmed_connection() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // A real client exists, owned by a real scope.
    let scope = db.seed_scope(&env).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "a real client")
        .await
        .expect("create");

    // Hold one low-privilege connection and put it in exactly the state a pooled
    // connection is in after a scoped transaction: the scope variables reverted
    // to the empty string. (set_config with is_local=false leaves the value set
    // at session scope, which is the observable end state of the commit revert.)
    let mut conn = db.app_pool().acquire().await.expect("acquire connection");
    sqlx::query("SELECT set_config('ironauth.tenant_id', '', false)")
        .execute(&mut *conn)
        .await
        .expect("warm tenant variable");
    sqlx::query("SELECT set_config('ironauth.environment_id', '', false)")
        .execute(&mut *conn)
        .await
        .expect("warm environment variable");

    // The scope variable is the empty string, NOT NULL: the exact condition the
    // deny-by-default comment in the migration now documents.
    let state = sqlx::query(
        "SELECT current_setting('ironauth.tenant_id', true) IS NULL AS is_null, \
         current_setting('ironauth.tenant_id', true) = '' AS is_empty",
    )
    .fetch_one(&mut *conn)
    .await
    .expect("read scope variable state");
    assert!(
        !state.get::<bool, _>("is_null") && state.get::<bool, _>("is_empty"),
        "a warmed connection's scope variable is the empty string, not NULL"
    );

    // Deny by default still returns nothing on this warmed connection.
    let warmed: i64 = sqlx::query("SELECT count(*) AS c FROM clients")
        .fetch_one(&mut *conn)
        .await
        .expect("warmed count")
        .get("c");
    assert_eq!(
        warmed, 0,
        "a warmed (empty-scope) connection must still see no rows"
    );
}

/// Deny-by-default on a warmed connection relies on the invariant that no scoped
/// row ever carries an empty scope. Prove the database enforces that invariant
/// below row-level security: insert as the superuser owner (which bypasses RLS
/// entirely), so only the table constraints -- the CHECK and the foreign keys --
/// can reject the row. A regression that dropped the CHECK would have to fall
/// back on the foreign key alone; this test fails loudly either way if an
/// empty-scope row can ever be stored.
#[tokio::test]
async fn empty_scope_rows_are_rejected() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let owner = db.owner_pool();
    let result = sqlx::query(
        "INSERT INTO clients (id, tenant_id, environment_id, display_name) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(ClientId::generate(&env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind("")
    .bind("empty scope")
    .execute(owner)
    .await;
    assert!(
        result.is_err(),
        "a row with an empty environment_id must be rejected"
    );
}

/// The `management_credentials` mirror of the clients RLS test: as the
/// low-privilege CONTROL role, a cross-scope raw SELECT and UPDATE are denied by
/// the forced policy even with the app-layer filter subverted, and the write-side
/// WITH CHECK rejects forging another scope's row. (issue #11)
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn rls_blocks_cross_scope_management_credentials_for_the_control_role() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // Two scopes sharing one database.
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    // A management credential owned by scope B, inserted as the owner (a
    // superuser, so it bypasses row-level security) to set up the fixture.
    let key_b = ManagementKeyId::generate(&env, &scope_b).to_string();
    sqlx::query(
        "INSERT INTO management_credentials \
         (id, tenant_id, environment_id, key_hash, display_name) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&key_b)
    .bind(scope_b.tenant().to_string())
    .bind(scope_b.environment().to_string())
    .bind("hash-b")
    .bind("scope B key")
    .execute(db.owner_pool())
    .await
    .expect("seed credential in B");

    let pool = db.control_pool();

    // Precondition: we really are the low-privilege CONTROL role, not a superuser.
    let who = sqlx::query(
        "SELECT current_user AS u, \
         (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_super",
    )
    .fetch_one(pool)
    .await
    .expect("identify session role");
    assert_eq!(
        who.get::<String, _>("u"),
        "ironauth_control",
        "test must run as the low-privilege control role"
    );
    assert!(
        !who.get::<bool, _>("is_super"),
        "the control role must not be a superuser"
    );

    // 1. Deny by default: no scope set on the session, zero rows.
    let unset: i64 = sqlx::query("SELECT count(*) AS c FROM management_credentials")
        .fetch_one(pool)
        .await
        .expect("count with unset scope")
        .get("c");
    assert_eq!(
        unset, 0,
        "an unset scope must see no management credentials"
    );

    // 2. Mis-scoped session with the app filter SUBVERTED: scoped to A, the query
    //    explicitly targets B's rows. Row-level security still returns zero.
    {
        let mut tx = pool.begin().await.expect("begin as scope A");
        bind_scope(
            &mut tx,
            &scope_a.tenant().to_string(),
            &scope_a.environment().to_string(),
        )
        .await;
        let attacker_filtered: i64 = sqlx::query(
            "SELECT count(*) AS c FROM management_credentials \
             WHERE tenant_id = $1 AND environment_id = $2",
        )
        .bind(scope_b.tenant().to_string())
        .bind(scope_b.environment().to_string())
        .fetch_one(&mut *tx)
        .await
        .expect("cross-scope count")
        .get("c");
        assert_eq!(
            attacker_filtered, 0,
            "RLS must hide scope B credentials from a scope A session even when the app filter is bypassed"
        );
        tx.commit().await.expect("commit A read");
    }

    // 3. Positive control: scoped to B, the same role sees exactly B's row.
    {
        let mut tx = pool.begin().await.expect("begin as scope B");
        bind_scope(
            &mut tx,
            &scope_b.tenant().to_string(),
            &scope_b.environment().to_string(),
        )
        .await;
        let visible: i64 = sqlx::query("SELECT count(*) AS c FROM management_credentials")
            .fetch_one(&mut *tx)
            .await
            .expect("count in B")
            .get("c");
        assert_eq!(visible, 1, "scope B sees its own credential");
        tx.commit().await.expect("commit B read");
    }

    // 4. Write-side isolation. A scope A session cannot UPDATE scope B's row (the
    //    USING clause hides it) nor INSERT one claiming scope B (the WITH CHECK
    //    rejects it).
    {
        let mut tx = pool.begin().await.expect("begin as scope A for write");
        bind_scope(
            &mut tx,
            &scope_a.tenant().to_string(),
            &scope_a.environment().to_string(),
        )
        .await;
        let updated = sqlx::query(
            "UPDATE management_credentials SET display_name = 'hijacked' WHERE tenant_id = $1",
        )
        .bind(scope_b.tenant().to_string())
        .execute(&mut *tx)
        .await
        .expect("update runs")
        .rows_affected();
        assert_eq!(
            updated, 0,
            "RLS must hide scope B rows from a scope A UPDATE"
        );

        let forged = ManagementKeyId::generate(&env, &scope_b).to_string();
        let insert = sqlx::query(
            "INSERT INTO management_credentials \
             (id, tenant_id, environment_id, key_hash, display_name) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(forged)
        .bind(scope_b.tenant().to_string())
        .bind(scope_b.environment().to_string())
        .bind("forged")
        .bind("smuggled")
        .execute(&mut *tx)
        .await;
        assert!(
            insert.is_err(),
            "RLS WITH CHECK must reject writing another scope's credential"
        );
        let _ = tx.rollback().await;
    }
}

/// Deny-by-default on a warmed control connection: after a scoped transaction
/// commits, the scope variables revert to the EMPTY STRING (not NULL), and the
/// nonempty-scope CHECK forbids any credential from carrying an empty scope, so
/// the connection still sees nothing. Mirrors the clients warmed-connection test.
#[tokio::test]
async fn management_credentials_deny_by_default_on_a_warmed_connection() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // A real credential exists, owned by a real scope.
    sqlx::query(
        "INSERT INTO management_credentials \
         (id, tenant_id, environment_id, key_hash, display_name) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(ManagementKeyId::generate(&env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind("hash")
    .bind("a real key")
    .execute(db.owner_pool())
    .await
    .expect("seed credential");

    // Warm a control connection into the empty-string scope state (the observable
    // post-commit revert of a scoped transaction's local variables).
    let mut conn = db
        .control_pool()
        .acquire()
        .await
        .expect("acquire control connection");
    sqlx::query("SELECT set_config('ironauth.tenant_id', '', false)")
        .execute(&mut *conn)
        .await
        .expect("warm tenant variable");
    sqlx::query("SELECT set_config('ironauth.environment_id', '', false)")
        .execute(&mut *conn)
        .await
        .expect("warm environment variable");

    let warmed: i64 = sqlx::query("SELECT count(*) AS c FROM management_credentials")
        .fetch_one(&mut *conn)
        .await
        .expect("warmed count")
        .get("c");
    assert_eq!(
        warmed, 0,
        "a warmed (empty-scope) control connection must still see no credentials"
    );
}

/// The two clients-quarantine columns are CONTROL-plane-only (issue #31, FIX 1):
/// migration 0001 gave `ironauth_app` a TABLE-WIDE UPDATE on clients, and a Postgres
/// table-level UPDATE auto-covers columns added later, so without the 0017 narrowing
/// the data-plane role could self-verify a quarantined client. This proves the app
/// role is REFUSED (permission denied, 42501) on `quarantined`/`verified_at` while it
/// can still update a normal data-plane column, and that the control role CAN write
/// the quarantine columns (a real split, not a lockout).
#[tokio::test]
async fn app_role_cannot_write_the_control_plane_only_quarantine_columns() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // A client exists in scope, created through the data-plane repository.
    let id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "grant-narrowing client")
        .await
        .expect("create client");
    let id = id.to_string();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    // As the low-privilege APP role, scoped so the row is visible: writing either
    // quarantine column is refused with permission denied, even though the app role
    // can see and otherwise update the row.
    {
        let mut tx = db.app_pool().begin().await.expect("begin app tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        let denied = sqlx::query("UPDATE clients SET quarantined = false WHERE id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await;
        assert_permission_denied(denied, "app UPDATE clients.quarantined");
        let _ = tx.rollback().await;
    }
    {
        let mut tx = db.app_pool().begin().await.expect("begin app tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        let denied = sqlx::query(
            "UPDATE clients \
             SET verified_at = TIMESTAMPTZ 'epoch' WHERE id = $1",
        )
        .bind(&id)
        .execute(&mut *tx)
        .await;
        assert_permission_denied(denied, "app UPDATE clients.verified_at");
        let _ = tx.rollback().await;
    }

    // Positive control: the app role CAN still update a data-plane column, so the
    // narrowed grant is not an over-revoke.
    {
        let mut tx = db.app_pool().begin().await.expect("begin app tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        let affected = sqlx::query("UPDATE clients SET display_name = $1 WHERE id = $2")
            .bind("renamed by app")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .expect("app updates a data-plane column")
            .rows_affected();
        assert_eq!(affected, 1, "the app role can update a data-plane column");
        tx.commit().await.expect("commit app update");
    }

    // The CONTROL role CAN write both quarantine columns (its narrow
    // UPDATE(quarantined, verified_at) grant), proving the split is a real separation.
    {
        let mut tx = db.control_pool().begin().await.expect("begin control tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        let affected = sqlx::query(
            "UPDATE clients \
             SET quarantined = true, verified_at = TIMESTAMPTZ 'epoch' WHERE id = $1",
        )
        .bind(&id)
        .execute(&mut *tx)
        .await
        .expect("control lifts quarantine")
        .rows_affected();
        assert_eq!(
            affected, 1,
            "the control role can write the quarantine columns"
        );
        tx.commit().await.expect("commit control update");
    }
}

/// The data plane's ONLY mutation of an initial access token is the atomic consume,
/// which bumps `use_count` and nothing else (issue #31, FIX 2). Migration 0017 grants
/// `ironauth_app` SELECT plus a COLUMN-SCOPED `UPDATE(use_count)`, so a data-plane path
/// cannot rewrite a token's security-bearing fields (`max_uses`, `policy_chain`,
/// `token_hash`, `expires_at`) to lift its own cap or swap the bound policy. This
/// proves the app role CAN bump `use_count` but is REFUSED (42501) on every other
/// column.
#[tokio::test]
async fn app_role_iat_update_is_scoped_to_use_count() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Seed a token row as the OWNER (bypasses RLS), so the grant test does not depend
    // on the control-plane mint path.
    let iat_id = InitialAccessTokenId::generate(&env, &scope).to_string();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    sqlx::query(
        "INSERT INTO dcr_initial_access_tokens \
         (id, tenant_id, environment_id, token_hash, policy_chain, expires_at, \
          max_uses, use_count, created_at) \
         VALUES ($1, $2, $3, $4, '[]', now() + interval '1 hour', 5, 0, now())",
    )
    .bind(&iat_id)
    .bind(&tenant)
    .bind(&environment)
    .bind("deadbeefdeadbeef")
    .execute(db.owner_pool())
    .await
    .expect("seed initial access token");

    // The app role CAN bump use_count (the consume path).
    {
        let mut tx = db.app_pool().begin().await.expect("begin app tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        let affected = sqlx::query(
            "UPDATE dcr_initial_access_tokens SET use_count = use_count + 1 WHERE id = $1",
        )
        .bind(&iat_id)
        .execute(&mut *tx)
        .await
        .expect("app bumps use_count")
        .rows_affected();
        assert_eq!(affected, 1, "the app role can bump use_count (consume)");
        tx.commit().await.expect("commit use_count bump");
    }

    // The app role CANNOT rewrite any security-bearing column: each is column-scoped
    // away, so the write is refused with permission denied.
    let forbidden: [&str; 4] = [
        "UPDATE dcr_initial_access_tokens SET max_uses = 999999 WHERE id = $1",
        "UPDATE dcr_initial_access_tokens SET policy_chain = '[]' WHERE id = $1",
        "UPDATE dcr_initial_access_tokens \
         SET expires_at = now() + interval '100 years' WHERE id = $1",
        "UPDATE dcr_initial_access_tokens SET token_hash = 'attacker' WHERE id = $1",
    ];
    for statement in forbidden {
        let mut tx = db.app_pool().begin().await.expect("begin app tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        let denied = sqlx::query(statement).bind(&iat_id).execute(&mut *tx).await;
        assert_permission_denied(denied, statement);
        let _ = tx.rollback().await;
    }
}

/// Assert a statement was refused with the PostgreSQL insufficient-privilege error
/// (SQLSTATE 42501), the signal that a column-level grant blocked the write.
fn assert_permission_denied(
    result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>,
    what: &str,
) {
    match result {
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("42501") => {}
        other => panic!("expected permission denied (42501) for `{what}`, got: {other:?}"),
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
