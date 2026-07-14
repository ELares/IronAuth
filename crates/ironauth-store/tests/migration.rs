// SPDX-License-Identifier: MIT OR Apache-2.0

//! The expand-contract migration framework, against a real database.
//!
//! Custom chains run against a fresh, empty database (an empty ledger) so they
//! are isolated from the two-migration production chain. The worked
//! expand-contract example lives here as a test-only chain (it never ships to a
//! real schema), and the production chain is separately asserted to contain
//! only its two migrations and leave no demo object behind.

use ironauth_store::test_support::TestDatabase;
use ironauth_store::{Migration, MigrationError, MigrationRunner, Phase};
use sqlx::Row;

/// A throwaway migration with the given version, phase, and SQL text.
fn step(version: i64, phase: Phase, sql: &'static str) -> Migration {
    Migration {
        version,
        name: "test-step",
        phase,
        sql,
    }
}

async fn table_exists(pool: &sqlx::PgPool, name: &str) -> bool {
    sqlx::query("SELECT to_regclass($1) IS NOT NULL AS present")
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("regclass lookup")
        .get("present")
}

async fn column_exists(pool: &sqlx::PgPool, table: &str, column: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM information_schema.columns \
            WHERE table_name = $1 AND column_name = $2 \
         ) AS present",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("column lookup")
    .get("present")
}

#[tokio::test]
async fn in_order_apply_records_each_and_is_idempotent() {
    let pool = TestDatabase::fresh_owner_pool().await;
    let chain = vec![
        step(1, Phase::Expand, "CREATE TABLE mtest_a (id int);"),
        step(2, Phase::Expand, "CREATE TABLE mtest_b (id int);"),
        step(3, Phase::Expand, "CREATE TABLE mtest_c (id int);"),
    ];

    let report = MigrationRunner::from_migrations(&pool, chain.clone())
        .run()
        .await
        .expect("apply chain");
    assert_eq!(
        report.newly_applied().to_vec(),
        vec![1_i64, 2, 3],
        "all three applied in order"
    );
    assert_eq!(report.already_applied(), 0);

    // The ledger recorded each migration.
    let recorded: i64 = sqlx::query("SELECT count(*) AS c FROM _schema_migrations")
        .fetch_one(&pool)
        .await
        .expect("count ledger")
        .get("c");
    assert_eq!(recorded, 3, "each migration is recorded");

    // Each table was created.
    for table in ["mtest_a", "mtest_b", "mtest_c"] {
        assert!(table_exists(&pool, table).await, "{table} should exist");
    }

    // Idempotent: a second run applies nothing.
    let again = MigrationRunner::from_migrations(&pool, chain)
        .run()
        .await
        .expect("re-run chain");
    assert!(
        again.newly_applied().is_empty(),
        "a second run applies nothing"
    );
    assert_eq!(again.already_applied(), 3);
}

#[tokio::test]
async fn out_of_order_application_is_rejected_and_applies_nothing() {
    let pool = TestDatabase::fresh_owner_pool().await;
    let m1 = step(1, Phase::Expand, "CREATE TABLE mooo_1 (id int);");
    let m2 = step(2, Phase::Expand, "CREATE TABLE mooo_2 (id int);");
    let m3 = step(3, Phase::Expand, "CREATE TABLE mooo_3 (id int);");

    // Apply only version 1.
    MigrationRunner::from_migrations(&pool, vec![m1])
        .run()
        .await
        .expect("apply version 1");

    // Plant version 3 as already applied (with its correct checksum, so the
    // checksum check passes and the ORDERING check is what fires) while version
    // 2 remains pending.
    sqlx::query(
        "INSERT INTO _schema_migrations (version, name, checksum, phase) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(m3.version)
    .bind(m3.name)
    .bind(m3.checksum())
    .bind(m3.phase.as_str())
    .execute(&pool)
    .await
    .expect("plant version 3");

    // Running [1, 2, 3] now: version 2 is pending but version 3 is applied.
    let err = MigrationRunner::from_migrations(&pool, vec![m1, m2, m3])
        .run()
        .await
        .expect_err("out-of-order application must be refused");
    assert!(
        matches!(
            err,
            MigrationError::OutOfOrder {
                applied: 3,
                missing: 2
            }
        ),
        "expected OutOfOrder{{applied:3, missing:2}}, got: {err:?}"
    );

    // A refused run applies nothing: version 2's table was never created.
    assert!(
        !table_exists(&pool, "mooo_2").await,
        "a rejected run must apply nothing"
    );
}

#[tokio::test]
async fn checksum_mismatch_on_an_applied_migration_is_rejected() {
    let pool = TestDatabase::fresh_owner_pool().await;

    // Apply version 1 with its original text.
    MigrationRunner::from_migrations(
        &pool,
        vec![step(1, Phase::Expand, "CREATE TABLE mck_1 (id int);")],
    )
    .run()
    .await
    .expect("apply original");

    // Present the same version with different text: its checksum no longer
    // matches what the ledger recorded.
    let tampered = step(1, Phase::Expand, "CREATE TABLE mck_1_tampered (id int);");
    let err = MigrationRunner::from_migrations(&pool, vec![tampered])
        .run()
        .await
        .expect_err("a checksum drift must be refused");
    assert!(
        matches!(err, MigrationError::ChecksumMismatch { version: 1 }),
        "expected ChecksumMismatch{{version:1}}, got: {err:?}"
    );
}

/// The worked expand-contract example, TEST-ONLY (it never ships to the
/// production schema). Expand adds a nullable column and seeds a row; migrate
/// backfills it; contract drops the old column. Proves all three phases run in
/// order and that contract removed the expanded-from artifact.
#[tokio::test]
async fn expand_contract_example_chain_runs_all_three_phases_and_contract_removes_the_old_column() {
    let pool = TestDatabase::fresh_owner_pool().await;
    let chain = vec![
        step(
            1,
            Phase::Expand,
            "CREATE TABLE migration_demo (id text PRIMARY KEY, legacy_name text NOT NULL); \
             INSERT INTO migration_demo (id, legacy_name) VALUES ('demo-1', 'alpha'); \
             ALTER TABLE migration_demo ADD COLUMN display_name text;",
        ),
        step(
            2,
            Phase::Migrate,
            "UPDATE migration_demo SET display_name = legacy_name WHERE display_name IS NULL;",
        ),
        step(
            3,
            Phase::Contract,
            "ALTER TABLE migration_demo DROP COLUMN legacy_name;",
        ),
    ];

    let report = MigrationRunner::from_migrations(&pool, chain)
        .run()
        .await
        .expect("apply the expand-contract chain");
    assert_eq!(
        report.newly_applied().to_vec(),
        vec![1_i64, 2, 3],
        "all three phases applied in order"
    );

    // The phases are recorded in order.
    let pool_ref = &pool;
    let phase_of = |version: i64| async move {
        sqlx::query("SELECT phase FROM _schema_migrations WHERE version = $1")
            .bind(version)
            .fetch_one(pool_ref)
            .await
            .expect("phase lookup")
            .get::<String, _>("phase")
    };
    assert_eq!(phase_of(1).await, "expand");
    assert_eq!(phase_of(2).await, "migrate");
    assert_eq!(phase_of(3).await, "contract");

    // Forward chain: the migrate step backfilled display_name from legacy_name.
    let display: String =
        sqlx::query("SELECT display_name FROM migration_demo WHERE id = 'demo-1'")
            .fetch_one(&pool)
            .await
            .expect("demo row")
            .get("display_name");
    assert_eq!(
        display, "alpha",
        "the migrate phase backfilled display_name from legacy_name"
    );

    // Contract removed the expanded-from artifact; the expanded column remains.
    assert!(
        !column_exists(&pool, "migration_demo", "legacy_name").await,
        "the contract phase dropped legacy_name"
    );
    assert!(
        column_exists(&pool, "migration_demo", "display_name").await,
        "the expanded column remains after contract"
    );
}

/// The PRODUCTION chain (`MigrationRunner::new`) contains exactly the twelve real
/// migrations and leaves no throwaway demo object in a real database.
// A long but linear ledger-and-table assertion sweep (one line per migration and
// per real table); splitting it would not make it clearer.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn production_chain_is_only_the_twelve_real_migrations_and_ships_no_demo_object() {
    // TestDatabase::start runs Store::migrate() (the production chain) on a
    // fresh, empty database.
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // Re-running is idempotent and reports exactly twelve tracked migrations.
    let report = MigrationRunner::new(pool)
        .run()
        .await
        .expect("re-run the production chain");
    assert!(
        report.newly_applied().is_empty(),
        "the harness already applied the production chain"
    );
    assert_eq!(
        report.already_applied(),
        12,
        "the production chain is exactly twelve migrations (isolation, audit log, management API, \
         OIDC authorization, signing keys, login/consent, authentication context, redirect \
         registration, UserInfo claims, consent scope upsert, resource servers, opaque access \
         tokens)"
    );

    // The ledger holds exactly versions 1 through 12.
    assert_eq!(
        applied_versions(pool).await,
        vec![1_i64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    );
    let phase_of = |version: i64| async move {
        sqlx::query("SELECT phase FROM _schema_migrations WHERE version = $1")
            .bind(version)
            .fetch_one(pool)
            .await
            .expect("phase lookup")
            .get::<String, _>("phase")
    };
    assert_eq!(phase_of(1).await, "expand");
    assert_eq!(phase_of(2).await, "expand");
    assert_eq!(phase_of(3).await, "expand");
    assert_eq!(phase_of(4).await, "expand");
    assert_eq!(phase_of(5).await, "expand");
    assert_eq!(phase_of(6).await, "expand");
    assert_eq!(phase_of(7).await, "expand");
    assert_eq!(phase_of(8).await, "expand");
    assert_eq!(phase_of(9).await, "expand");
    assert_eq!(phase_of(10).await, "expand");
    // A CREATE TABLE is an additive expand (issue #29).
    assert_eq!(phase_of(11).await, "expand");
    assert_eq!(phase_of(12).await, "expand");

    // The demo object never reaches a production database.
    assert!(
        !table_exists(pool, "migration_demo").await,
        "the production migrate() must not create a demo table"
    );
    // The real tables and the audit log do exist.
    assert!(table_exists(pool, "clients").await, "clients exists");
    assert!(table_exists(pool, "audit_log").await, "audit_log exists");
    // The management-plane tables (issue #11) exist.
    assert!(
        table_exists(pool, "management_credentials").await,
        "management_credentials exists"
    );
    assert!(
        table_exists(pool, "idempotency_keys").await,
        "idempotency_keys exists"
    );
    // The OIDC authorization tables (issue #12) exist.
    assert!(table_exists(pool, "grants").await, "grants exists");
    assert!(
        table_exists(pool, "authorization_codes").await,
        "authorization_codes exists"
    );
    assert!(
        table_exists(pool, "issued_tokens").await,
        "issued_tokens exists"
    );
    // The per-environment signing keys table (issue #19) exists.
    assert!(
        table_exists(pool, "signing_keys").await,
        "signing_keys exists"
    );
    // The bootstrap login/consent/session tables (issue #20) exist.
    assert!(table_exists(pool, "users").await, "users exists");
    assert!(table_exists(pool, "sessions").await, "sessions exists");
    assert!(table_exists(pool, "consents").await, "consents exists");
    // The authentication-context columns (issue #14) exist: the recorded login
    // methods on sessions and codes, the frozen auth_time on codes, and the
    // client's require_auth_time registration flag.
    assert!(
        column_exists(pool, "sessions", "auth_methods").await,
        "sessions.auth_methods exists"
    );
    assert!(
        column_exists(pool, "authorization_codes", "auth_methods").await,
        "authorization_codes.auth_methods exists"
    );
    assert!(
        column_exists(pool, "authorization_codes", "auth_time").await,
        "authorization_codes.auth_time exists"
    );
    assert!(
        column_exists(pool, "clients", "require_auth_time").await,
        "clients.require_auth_time exists"
    );
    // The registered redirect URIs for the exact-string redirect match (issue #13).
    assert!(
        column_exists(pool, "clients", "redirect_uris").await,
        "clients.redirect_uris exists"
    );
    // The UserInfo standard-claim store (issue #15): the additive users.claims
    // column backing the scope-derived and claims-parameter-selected claim sets,
    // plus the persisted `claims` request parameter frozen onto the grant (read by
    // UserInfo) and the code (read at the token endpoint).
    assert!(
        column_exists(pool, "users", "claims").await,
        "users.claims exists"
    );
    assert!(
        column_exists(pool, "grants", "claims_request").await,
        "grants.claims_request exists"
    );
    assert!(
        column_exists(pool, "authorization_codes", "claims_request").await,
        "authorization_codes.claims_request exists"
    );
    // The resource-server registry and the digest-only opaque-token store (issue
    // #29): the audience-to-format table the mint reads, and the digest-only table
    // the internal resolve reads.
    assert!(
        table_exists(pool, "resource_servers").await,
        "resource_servers exists"
    );
    assert!(
        table_exists(pool, "opaque_access_tokens").await,
        "opaque_access_tokens exists"
    );
}

#[tokio::test]
async fn not_sorted_is_rejected_for_descending_and_duplicate_versions() {
    let pool = TestDatabase::fresh_owner_pool().await;

    // Descending: version 1 follows version 2.
    let descending = MigrationRunner::from_migrations(
        &pool,
        vec![
            step(2, Phase::Expand, "CREATE TABLE ns_desc_2 (id int);"),
            step(1, Phase::Expand, "CREATE TABLE ns_desc_1 (id int);"),
        ],
    )
    .run()
    .await
    .expect_err("a descending chain must be refused");
    assert!(
        matches!(descending, MigrationError::NotSorted { version: 1 }),
        "expected NotSorted{{version:1}}, got: {descending:?}"
    );

    // Duplicate: version 1 appears twice (not strictly ascending).
    let duplicate = MigrationRunner::from_migrations(
        &pool,
        vec![
            step(1, Phase::Expand, "CREATE TABLE ns_dup_a (id int);"),
            step(1, Phase::Expand, "CREATE TABLE ns_dup_b (id int);"),
        ],
    )
    .run()
    .await
    .expect_err("a duplicate version must be refused");
    assert!(
        matches!(duplicate, MigrationError::NotSorted { version: 1 }),
        "expected NotSorted{{version:1}}, got: {duplicate:?}"
    );

    // A refused sort check touches no connection: neither table was created.
    assert!(!table_exists(&pool, "ns_desc_1").await);
    assert!(!table_exists(&pool, "ns_dup_a").await);
}

#[tokio::test]
async fn unknown_applied_version_is_rejected_and_nothing_is_applied() {
    // The N/N-1 downgrade guard: a ledger migrated by a newer build (which knows
    // version 3) presented to an older build whose registry stops at version 2.
    let pool = TestDatabase::fresh_owner_pool().await;

    // A "newer build" applies versions 1 to 3.
    MigrationRunner::from_migrations(
        &pool,
        vec![
            step(1, Phase::Expand, "CREATE TABLE dg_1 (id int);"),
            step(2, Phase::Expand, "CREATE TABLE dg_2 (id int);"),
            step(3, Phase::Expand, "CREATE TABLE dg_3 (id int);"),
        ],
    )
    .run()
    .await
    .expect("newer build applies 1 to 3");

    // The "older build" only knows versions 1 and 2, and adds an unapplied
    // version 2b to prove nothing pending is applied either.
    let older = MigrationRunner::from_migrations(
        &pool,
        vec![
            step(1, Phase::Expand, "CREATE TABLE dg_1 (id int);"),
            step(2, Phase::Expand, "CREATE TABLE dg_2 (id int);"),
        ],
    )
    .run()
    .await
    .expect_err("a ledger version unknown to this build must be refused");
    assert!(
        matches!(older, MigrationError::UnknownApplied { version: 3 }),
        "expected UnknownApplied{{version:3}}, got: {older:?}"
    );

    // Nothing changed: the ledger still holds exactly 1, 2, 3.
    assert_eq!(applied_versions(&pool).await, vec![1_i64, 2, 3]);
}

#[tokio::test]
async fn a_failed_migration_records_no_ledger_row_and_stops_the_chain() {
    let pool = TestDatabase::fresh_owner_pool().await;

    // Version 2's DDL is invalid (an undefined column type). It must roll back
    // with no ledger row, and version 3 must never be attempted.
    let err = MigrationRunner::from_migrations(
        &pool,
        vec![
            step(1, Phase::Expand, "CREATE TABLE fdl_1 (id int);"),
            step(
                2,
                Phase::Expand,
                "CREATE TABLE fdl_2 (id int, broken nonexistent_type_xyz);",
            ),
            step(3, Phase::Expand, "CREATE TABLE fdl_3 (id int);"),
        ],
    )
    .run()
    .await
    .expect_err("a migration with invalid DDL must fail");
    assert!(
        matches!(err, MigrationError::Database(_)),
        "expected a Database error, got: {err:?}"
    );

    // Version 1 committed; version 2 rolled back (no table, no ledger row);
    // version 3 was never attempted.
    assert_eq!(
        applied_versions(&pool).await,
        vec![1_i64],
        "only version 1 is recorded"
    );
    assert!(table_exists(&pool, "fdl_1").await, "version 1 committed");
    assert!(
        !table_exists(&pool, "fdl_2").await,
        "the failed migration's DDL rolled back"
    );
    assert!(
        !table_exists(&pool, "fdl_3").await,
        "the chain stopped at the failure"
    );
}

#[tokio::test]
async fn concurrent_runners_serialize_cleanly_via_the_advisory_lock() {
    // Two runners racing on one fresh database (the rolling-upgrade boot race).
    // Without the advisory lock the loser would race to CREATE and fail with a
    // raw "relation already exists" error; with it, the loser waits and finds
    // nothing pending. Both must complete cleanly and the ledger must be [1, 2].
    let pool = TestDatabase::fresh_owner_pool().await;
    let chain = || {
        vec![
            step(1, Phase::Expand, "CREATE TABLE conc_a (id int);"),
            step(2, Phase::Expand, "CREATE TABLE conc_b (id int);"),
        ]
    };

    let runner_a = MigrationRunner::from_migrations(&pool, chain());
    let runner_b = MigrationRunner::from_migrations(&pool, chain());
    let (a, b) = tokio::join!(runner_a.run(), runner_b.run());

    a.expect("runner A completes without a raw error");
    b.expect("runner B completes without a raw error");

    // Exactly one full apply happened; the final ledger is [1, 2].
    assert_eq!(applied_versions(&pool).await, vec![1_i64, 2]);
    assert!(table_exists(&pool, "conc_a").await);
    assert!(table_exists(&pool, "conc_b").await);
}

/// The versions recorded in the ledger, ascending.
async fn applied_versions(pool: &sqlx::PgPool) -> Vec<i64> {
    sqlx::query("SELECT version FROM _schema_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .expect("read ledger versions")
        .iter()
        .map(|row| row.get::<i64, _>("version"))
        .collect()
}
