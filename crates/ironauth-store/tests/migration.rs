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

/// The SQL `data_type` of `table.column` (`information_schema.columns`), for
/// asserting a sealed column is a `bytea` (secret material at rest is ciphertext).
async fn column_data_type(pool: &sqlx::PgPool, table: &str, column: &str) -> String {
    sqlx::query(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("data type lookup")
    .get("data_type")
}

/// Whether `table` has BOTH `ENABLE` and `FORCE` row-level security on (`pg_class`).
async fn rls_enabled_and_forced(pool: &sqlx::PgPool, table: &str) -> bool {
    sqlx::query(
        "SELECT (relrowsecurity AND relforcerowsecurity) AS present \
         FROM pg_catalog.pg_class WHERE oid = $1::regclass",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .expect("rls lookup")
    .get("present")
}

/// Whether a row-level-security policy named `policy` exists on `table`.
async fn policy_exists(pool: &sqlx::PgPool, table: &str, policy: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_policies \
            WHERE tablename = $1 AND policyname = $2 \
         ) AS present",
    )
    .bind(table)
    .bind(policy)
    .fetch_one(pool)
    .await
    .expect("policy lookup")
    .get("present")
}

/// Whether a CHECK constraint named `constraint_name` exists on `table`.
async fn check_constraint_exists(pool: &sqlx::PgPool, table: &str, constraint_name: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_constraint \
            WHERE conrelid = $1::regclass AND contype = 'c' AND conname = $2 \
         ) AS present",
    )
    .bind(table)
    .bind(constraint_name)
    .fetch_one(pool)
    .await
    .expect("check constraint lookup")
    .get("present")
}

/// Whether a PARTIAL UNIQUE index named `index` exists on `table` (unique with a
/// `WHERE` predicate).
async fn partial_unique_index_exists(pool: &sqlx::PgPool, table: &str, index: &str) -> bool {
    sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_index i \
            JOIN pg_catalog.pg_class c ON c.oid = i.indexrelid \
            WHERE i.indrelid = $1::regclass AND c.relname = $2 \
              AND i.indisunique AND i.indpred IS NOT NULL \
         ) AS present",
    )
    .bind(table)
    .bind(index)
    .fetch_one(pool)
    .await
    .expect("partial unique index lookup")
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

/// The PRODUCTION chain (`MigrationRunner::new`) contains exactly the fifty-one
/// real migrations and leaves no throwaway demo object in a real database.
// A long but linear ledger-and-table assertion sweep (one line per migration and
// per real table); splitting it would not make it clearer.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn production_chain_is_only_the_fifty_five_real_migrations_and_ships_no_demo_object() {
    // TestDatabase::start runs Store::migrate() (the production chain) on a
    // fresh, empty database.
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // Re-running is idempotent and reports exactly the tracked migrations.
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
        55,
        "the production chain is exactly fifty-five migrations (isolation, audit log, management \
         API, OIDC authorization, signing keys, login/consent, authentication context, redirect \
         registration, UserInfo claims, consent scope upsert, resource servers, opaque access \
         tokens, client auth suite, dynamic client registration, pushed authorization requests, \
         refresh tokens, client-credentials service accounts, DCR abuse controls, resource \
         indicators, JWT bearer assertion grant, device authorization, session model, RP-initiated \
         logout, session-ended events, back-channel logout, front-channel logout, resource-model \
         APIs, envelope encryption, environment guardrails, tenant lifecycle, BYOK bindings, \
         snapshot export, custom domains, environment secrets and variables, config promotion, \
         self-service account, admin user lifecycle, identity traits, foreign password \
         import, user invitations, flexible identifiers, exit-export credential grants, \
         migration state machine, webauthn credentials, totp credentials, credential abuse \
         defenses, step-up policies, email OTP and scanner-safe magic links, credential-class \
         policies, guarded SMS OTP, passkey attestation, admin sudo elevations, trusted devices, \
         risk engine, federation connectors)"
    );

    // The ledger holds exactly versions 1 through 55.
    assert_eq!(
        applied_versions(pool).await,
        vec![
            1_i64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55
        ]
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
    // An ALTER TABLE ADD COLUMN and a CREATE TABLE are both additive expands (#25).
    assert_eq!(phase_of(13).await, "expand");
    // The DCR clients-column expand is additive (#30).
    assert_eq!(phase_of(14).await, "expand");
    // A CREATE TABLE and an additive ALTER TABLE ADD COLUMN are both expands (#27).
    assert_eq!(phase_of(15).await, "expand");
    // Two CREATE TABLEs and two additive ALTERs are all expands (issue #21).
    assert_eq!(phase_of(16).await, "expand");
    // A CREATE TABLE plus two additive clients ALTERs are all expands (issue #23),
    // and three CREATE TABLEs plus additive clients and audit_log ALTERs are all
    // expands (issue #31).
    assert_eq!(phase_of(17).await, "expand");
    assert_eq!(phase_of(18).await, "expand");
    // The resource-indicator columns are all additive ALTER TABLE ADD COLUMNs plus a
    // CHECK and a column-scoped grant, so this is an expand too (issue #28).
    assert_eq!(phase_of(19).await, "expand");
    // Three CREATE TABLEs (the trust anchors, the subject-mapping rules, and the
    // external-issuer jti replay cache) are all additive expands (issue #26).
    assert_eq!(phase_of(20).await, "expand");
    // A CREATE TABLE plus two additive clients ALTERs are all expands (issue #24).
    assert_eq!(phase_of(21).await, "expand");
    // The session-model expand (issue #32): an additive sessions ALTER, a new
    // client_sessions table, and additive refresh_families indexes are all expands.
    assert_eq!(phase_of(22).await, "expand");
    // The RP-initiated logout expand (issue #33): an additive clients ALTER ADD COLUMN
    // (post_logout_redirect_uris) plus its column-scoped grant is an expand.
    assert_eq!(phase_of(23).await, "expand");
    // The session-ended outbox (issue #35): one new CREATE TABLE plus its indexes,
    // policy, and column-scoped grants are all additive, so this is an expand too.
    assert_eq!(phase_of(24).await, "expand");
    // Back-channel logout (issue #34): two additive clients ALTER ADD COLUMNs plus one
    // new backchannel_logout_deliveries table, indexes, policy, and column-scoped grants
    // are all additive, so this is an expand too.
    assert_eq!(phase_of(25).await, "expand");
    // The front-channel logout expand (issue #39): two additive clients ALTER ADD
    // COLUMNs (frontchannel_logout_uri, frontchannel_logout_session_required) plus a
    // column-scoped grant are all expands.
    assert_eq!(phase_of(26).await, "expand");
    // The resource-model APIs expand (issue #41): one additive organizations ALTER
    // ADD COLUMN (deleted_at) plus control-plane grants, and a REVOKE of the unused
    // over-broad data-plane grant on organizations (the #31 least-privilege lesson).
    // The revoke is expand-safe: no pre-#41 binary issued an organization statement
    // as ironauth_app, so removing the grant depends on and breaks nothing.
    assert_eq!(phase_of(27).await, "expand");
    // The envelope-encryption migration (issue #48): three new CREATE TABLEs
    // (tenant_keks, tenant_deks, encrypted_secrets) with their indexes, policies,
    // and column-scoped grants, PLUS the conversion of the two plaintext users PII
    // columns to sealed envelope columns (a full expand-contract folded in, since
    // the pre-1.0 bootstrap users table has no cross-release contract to protect).
    // The predominant shape is additive, so it is registered as an expand.
    assert_eq!(phase_of(28).await, "expand");
    // The environment-guardrails expand (issue #42): two additive environments
    // ALTER ADD COLUMNs (kind, custom_domain), one CHECK pinning the closed kind
    // set, and a GRANT INSERT on signing_keys to the control role (so environment
    // creation can provision the day-one key). Purely additive, so it is an expand.
    assert_eq!(phase_of(29).await, "expand");
    // The tenant-lifecycle migration (issue #46): additive tenants.status,
    // tenants.home_region, tenants.purged_at, and environments.region columns, a new
    // environment_states scoped table with its policy and grants, and a
    // control-plane crypto-shred grant on tenant_keks. All additive, so this is an
    // expand too.
    assert_eq!(phase_of(30).await, "expand");
    // The BYOK-bindings migration (issue #49): one new tenant_byok_bindings scoped
    // table with its index, isolation policy, nonempty-scope and value CHECKs, and
    // column-scoped grants (data-plane SELECT/INSERT, control-plane SELECT plus a
    // column-scoped sever UPDATE). Purely additive, so it is an expand too.
    assert_eq!(phase_of(31).await, "expand");
    // The snapshot-export migration (issue #43): a single GRANT SELECT on
    // resource_servers to the control role, so the management-plane snapshot export
    // can read the promotable resource-server registry. A pure grant, no schema
    // change, so this is an expand too.
    assert_eq!(phase_of(32).await, "expand");
    // The custom-domains migration (issue #47): two new tenant-scoped tables
    // (custom_domains and acme_challenges) with their indexes, policies, and
    // column-scoped grants, plus a global partial unique index that gives a
    // verified domain exactly one owner platform-wide. All additive, so it is an
    // expand.
    assert_eq!(phase_of(33).await, "expand");
    // The environment secrets and variables migration (issue #45): two new
    // tenant-scoped tables (environment_variables and environment_secrets) with
    // their indexes, isolation policies, nonempty-scope CHECKs, and column-scoped
    // grants (a control-plane SELECT on variables for the snapshot export). All
    // additive, so it is an expand too.
    assert_eq!(phase_of(34).await, "expand");
    // The config-promotion migration (issue #44): a set of control-plane grants so
    // the transactional promotion apply can create, overwrite, and remove the
    // promoted resource types (resource servers, DCR policies, environment
    // variables) and read the presence of an environment secret. A pure grant, no
    // schema change, so this is an expand too.
    assert_eq!(phase_of(35).await, "expand");
    // The self-service account migration (issue #61): a column-scoped UPDATE grant
    // on users.password_hash (so a self-service password change can replace the
    // verifier) plus one new account_credentials scoped table with its indexes,
    // isolation policy, nonempty-scope and closed-type CHECKs, and column-scoped
    // grants. All additive, so this is an expand too.
    assert_eq!(phase_of(36).await, "expand");
    // The admin-user-lifecycle migration (issue #52): additive users columns (state,
    // external-id blind index + sealed value + its DEK version, scheduled-offboarding
    // instant, updated_at, deleted_at), a state CHECK, a per-scope partial unique
    // index on the external-id blind index, and a set of grants (control-plane
    // SELECT/INSERT plus a column-scoped UPDATE on users, and control-plane
    // SELECT/INSERT on the envelope key tables). All additive, so it is an expand too.
    assert_eq!(phase_of(37).await, "expand");
    // The identity-traits migration (issue #53): two new tenant-scoped tables
    // (trait_schemas, trait_migration_jobs) with their indexes, isolation policies,
    // nonempty-scope CHECKs, and column-scoped grants, plus three additive users
    // columns (traits_sealed, traits_dek_version, traits_schema_version) with a
    // column-scoped grant. All additive, so it is an expand too.
    assert_eq!(phase_of(38).await, "expand");
    // The foreign-password-import migration (issue #55): two additive nullable users
    // columns (foreign_password_hash, foreign_password_algo) plus a column-scoped
    // UPDATE grant to the data and control roles so the verify-then-rehash login
    // landing can retire the foreign hash. All additive, so it is an expand too.
    assert_eq!(phase_of(39).await, "expand");
    // The user-invitations migration (issue #60): one new user_invitations scoped
    // table with its unique digest index, scope and identifier indexes, isolation
    // policy, nonempty-scope / closed-credential-type / closed-state CHECKs, and
    // column-scoped grants (control-plane SELECT/INSERT plus a lifecycle UPDATE,
    // data-plane SELECT plus an accept UPDATE). All additive, so it is an expand too.
    assert_eq!(phase_of(40).await, "expand");
    // The flexible-identifiers migration (issue #54): one new user_identifiers scoped
    // table with its resolution and per-user indexes, the partial uniqueness index on
    // the mode discriminator, isolation policy, nonempty-scope / closed-type CHECKs,
    // and column-scoped grants. The identifier value is sealed and blind-indexed (no
    // plaintext PII column). All additive, so it is an expand too.
    assert_eq!(phase_of(41).await, "expand");
    // The exit-export credential-grant migration (issue #58): a purely additive pair
    // of control-plane privileges (SELECT + INSERT) on the existing
    // account_credentials table so the full export reads the credential registry and
    // the mirror import restores it. No table, column, policy, or backfill, so it is
    // an expand.
    assert_eq!(phase_of(42).await, "expand");
    // The migration state-machine migration (issue #59): two new tenant-scoped tables
    // (migration_runs, migration_run_records) with their indexes, isolation policies,
    // nonempty-scope / closed-kind / closed-state / closed-outcome CHECKs, and
    // column-scoped grants. The record subject is sealed and blind-indexed (no plaintext
    // PII column). All additive, so it is an expand too.
    assert_eq!(phase_of(43).await, "expand");
    // The WebAuthn passkey migration (issue #65) is an EXPAND: two new tenant-scoped
    // tables, no rewrite of existing state.
    assert_eq!(phase_of(44).await, "expand");
    // The TOTP migration (issue #69) is an EXPAND: two new tenant-scoped tables
    // (totp_credentials, recovery_codes), no rewrite of existing state.
    assert_eq!(phase_of(45).await, "expand");
    // The credential-abuse-defenses migration (issue #64) is an EXPAND: one new
    // tenant-scoped ban table, no rewrite of existing state.
    assert_eq!(phase_of(46).await, "expand");
    // The step-up policies migration (issue #72) is an EXPAND: one new tenant-scoped
    // per-scope policy table plus additive clients and refresh_families columns, no
    // rewrite of existing state.
    assert_eq!(phase_of(47).await, "expand");
    // The email-OTP + magic-links migration (issue #68) is an EXPAND: two new
    // tenant-scoped tables (email_otp_codes, magic_link_tokens), no rewrite of existing
    // state.
    assert_eq!(phase_of(48).await, "expand");
    // The credential-class-policies migration (issue #66) is an EXPAND: two new
    // tenant-scoped tables (credential_class_policies, attestation_config) plus additive
    // users columns and a guard trigger, no rewrite of existing state.
    assert_eq!(phase_of(49).await, "expand");
    // The guarded SMS-OTP migration (issue #70) is an EXPAND: four new tenant-scoped
    // tables (sms_otp_codes, sms_config, sms_country_allowlist, sms_route_stats), no
    // rewrite of existing state.
    assert_eq!(phase_of(50).await, "expand");
    // The passkey-attestation migration (issue #66, PR B) is an EXPAND: two new
    // tenant-scoped tables (mds3_blob_cache, aaguid_rules) plus additive
    // webauthn_credentials attestation columns, no rewrite of existing state.
    assert_eq!(phase_of(51).await, "expand");
    // The admin-sudo-elevations migration (issue #73) is an EXPAND: one new
    // tenant-scoped append-only ledger table, no rewrite of existing state.
    assert_eq!(phase_of(52).await, "expand");
    // The trusted-devices migration (issue #71) is an EXPAND: one new tenant-scoped
    // remember-device state table, no rewrite of existing state.
    assert_eq!(phase_of(53).await, "expand");
    // The risk-engine migration (issue #79) is an EXPAND: three new tenant-scoped tables
    // (risk_login_geo, risk_decisions, risk_disavowal_tokens), no rewrite of existing state.
    assert_eq!(phase_of(54).await, "expand");
    // The federation-connectors migration (issue #75) is an EXPAND: one new tenant-scoped
    // table (connectors), no rewrite of existing state.
    assert_eq!(phase_of(55).await, "expand");

    // The step-up second-factor abuse path (issue #72): migration 0047 WIDENED the
    // abuse_bans auth_path CHECK (0046 pinned the closed set) to also admit
    // 'second_factor', so the RFC 9470 step-up challenge is a first-class throttled
    // path that can carry a ban independently of password/passkey. The widened CHECK
    // definition names the new value.
    let auth_path_check: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'abuse_bans'::regclass AND conname = 'abuse_bans_auth_path_known'",
    )
    .fetch_one(pool)
    .await
    .expect("auth_path check constraint lookup")
    .get("def");
    assert!(
        auth_path_check.contains("second_factor"),
        "the abuse_bans auth_path CHECK must admit the step-up second-factor path, got: \
         {auth_path_check}"
    );

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
    // The typed-environment columns (issue #42): the environment kind (dev,
    // staging, prod) that drives the guardrail asymmetry, and the configured
    // custom domain the production custom-domain guardrail requires.
    assert!(
        column_exists(pool, "environments", "kind").await,
        "environments.kind exists"
    );
    assert!(
        column_exists(pool, "environments", "custom_domain").await,
        "environments.custom_domain exists"
    );
    // The bootstrap login/consent/session tables (issue #20) exist.
    assert!(table_exists(pool, "users").await, "users exists");
    assert!(table_exists(pool, "sessions").await, "sessions exists");
    assert!(table_exists(pool, "consents").await, "consents exists");
    // The self-service account-credential registry (issue #61) exists, with its
    // per-user credential columns: the subject the credential belongs to, the closed
    // factor type, the sealed friendly name and its DEK version (user PII never lands
    // on a plaintext column), the primary-login-usable flag, and the created /
    // last-used timestamps the account UI shows.
    assert!(
        table_exists(pool, "account_credentials").await,
        "account_credentials exists"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "credential_type",
        "friendly_name_sealed",
        "pii_dek_version",
        "usable_for_login",
        "created_at",
        "last_used_at",
    ] {
        assert!(
            column_exists(pool, "account_credentials", column).await,
            "account_credentials.{column} exists after 0036"
        );
    }
    // A credential's friendly name is user-authored PII, sealed under the scope DEK
    // (issue #48): the plaintext label never lands on a column.
    assert!(
        !column_exists(pool, "account_credentials", "friendly_name").await,
        "account_credentials must have no plaintext friendly_name column after 0036"
    );
    // The trusted-devices remember-device state (issue #71): a tenant-scoped, RLS-forced
    // table with the server-side secret digest (never a self-contained token), the
    // subject+session lineage binding, sealed UA/geo (PII), the max-age/idle duration
    // columns, and the immediate revoked_at kill switch.
    assert!(
        table_exists(pool, "trusted_devices").await,
        "trusted_devices exists after 0053"
    );
    assert!(
        rls_enabled_and_forced(pool, "trusted_devices").await,
        "trusted_devices has row-level security ENABLED and FORCED"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "device_secret_hash",
        "session_lineage",
        "user_agent_sealed",
        "geo_sealed",
        "pii_dek_version",
        "created_at",
        "last_seen_at",
        "max_age_expires_at",
        "idle_expires_at",
        "revoked_at",
        "revoke_reason",
    ] {
        assert!(
            column_exists(pool, "trusted_devices", column).await,
            "trusted_devices.{column} exists after 0053"
        );
    }
    // The device metadata is end-user PII, sealed under the scope DEK (issue #48): the
    // plaintext User-Agent and location never land on a column.
    assert!(
        !column_exists(pool, "trusted_devices", "user_agent").await,
        "trusted_devices must have no plaintext user_agent column after 0053"
    );
    assert!(
        !column_exists(pool, "trusted_devices", "geo").await,
        "trusted_devices must have no plaintext geo column after 0053"
    );
    // The revoke-reason CHECK pins the closed set, so an unknown reason can never be
    // written and the reason is present exactly when the row is revoked.
    let trusted_device_revoke_check: String = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS def FROM pg_catalog.pg_constraint \
         WHERE conrelid = 'trusted_devices'::regclass \
         AND conname = 'trusted_devices_revoke_reason_known'",
    )
    .fetch_one(pool)
    .await
    .expect("trusted_devices revoke-reason check lookup")
    .get("def");
    for reason in ["user", "admin", "password_change", "factor_change"] {
        assert!(
            trusted_device_revoke_check.contains(reason),
            "the trusted_devices revoke-reason CHECK must admit {reason}, got: \
             {trusted_device_revoke_check}"
        );
    }
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
    // The UserInfo standard-claim store (issue #15) is now SEALED, not plaintext
    // (issue #48): migration 0027 replaced the plaintext users.claims text column
    // with the sealed claims_sealed ciphertext (asserted with the other users PII
    // columns below). The persisted `claims` request parameter (which claim NAMES
    // to release, not values) stays plaintext on the grant (read by UserInfo) and
    // the code (read at the token endpoint).
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
    // The JWT-assertion client-authentication suite (issue #25): the additive
    // clients key/alg registration columns, the cross-node single-use jti replay
    // cache, and the out-of-band diagnostics sink.
    assert!(
        column_exists(pool, "clients", "jwks").await,
        "clients.jwks exists"
    );
    assert!(
        column_exists(pool, "clients", "jwks_uri").await,
        "clients.jwks_uri exists"
    );
    assert!(
        column_exists(pool, "clients", "token_endpoint_auth_signing_alg").await,
        "clients.token_endpoint_auth_signing_alg exists"
    );
    assert!(
        table_exists(pool, "client_assertion_jtis").await,
        "client_assertion_jtis exists"
    );
    assert!(
        table_exists(pool, "client_auth_diagnostics").await,
        "client_auth_diagnostics exists"
    );
    // The Dynamic Client Registration and configuration-management columns (issue
    // #30): the RFC 7592 registration access token hash and client URI, the
    // negotiated id_token signing algorithm, the RFC 8252 application type, and the
    // DCR-origin flag.
    assert!(
        column_exists(pool, "clients", "registration_access_token_hash").await,
        "clients.registration_access_token_hash exists"
    );
    assert!(
        column_exists(pool, "clients", "registration_client_uri").await,
        "clients.registration_client_uri exists"
    );
    assert!(
        column_exists(pool, "clients", "id_token_signed_response_alg").await,
        "clients.id_token_signed_response_alg exists"
    );
    assert!(
        column_exists(pool, "clients", "application_type").await,
        "clients.application_type exists"
    );
    assert!(
        column_exists(pool, "clients", "dcr_registered").await,
        "clients.dcr_registered exists"
    );
    // The pushed-authorization-request store and the per-client require-PAR flag
    // (issue #27): the single-use request_uri table and the additive clients column.
    assert!(
        table_exists(pool, "pushed_authorization_requests").await,
        "pushed_authorization_requests exists"
    );
    assert!(
        column_exists(pool, "clients", "require_pushed_authorization_requests").await,
        "clients.require_pushed_authorization_requests exists"
    );
    // The refresh-token rotation suite (issue #21): the family spine, the
    // digest-only token store, the additive clients consent-mode / rotation-override
    // columns, and the additive consents.expires_at.
    assert!(
        table_exists(pool, "refresh_families").await,
        "refresh_families exists"
    );
    assert!(
        table_exists(pool, "refresh_tokens").await,
        "refresh_tokens exists"
    );
    assert!(
        column_exists(pool, "clients", "consent_mode").await,
        "clients.consent_mode exists"
    );
    assert!(
        column_exists(pool, "clients", "skip_consent").await,
        "clients.skip_consent exists"
    );
    assert!(
        column_exists(pool, "clients", "store_skipped_consent").await,
        "clients.store_skipped_consent exists"
    );
    assert!(
        column_exists(pool, "clients", "refresh_rotation").await,
        "clients.refresh_rotation exists"
    );
    assert!(
        column_exists(pool, "consents", "expires_at").await,
        "consents.expires_at exists"
    );
    // The digest-only invariant (issue #21, acceptance criterion 7): the
    // refresh_tokens table has NO plaintext-token column, only a digest.
    assert!(
        column_exists(pool, "refresh_tokens", "token_digest").await,
        "refresh_tokens stores a digest"
    );
    for forbidden in ["token", "secret", "plaintext", "refresh_token"] {
        assert!(
            !column_exists(pool, "refresh_tokens", forbidden).await,
            "refresh_tokens must have no plaintext-token column ({forbidden})"
        );
    }
    // The client-credentials service-account principal table and the per-client
    // custom-claims column (issue #23): the stable machine-`sub` mapping and the
    // declarative M2M token claims.
    assert!(
        table_exists(pool, "service_accounts").await,
        "service_accounts exists"
    );
    assert!(
        column_exists(pool, "clients", "custom_token_claims").await,
        "clients.custom_token_claims exists"
    );
    // The Dynamic Client Registration abuse-control tables (issue #31): the
    // reusable named policy objects, the SHA-256-hashed initial-access-token store,
    // and the endpoint-local rate counters.
    assert!(
        table_exists(pool, "dcr_policies").await,
        "dcr_policies exists"
    );
    assert!(
        table_exists(pool, "dcr_initial_access_tokens").await,
        "dcr_initial_access_tokens exists"
    );
    assert!(
        table_exists(pool, "dcr_rate_counters").await,
        "dcr_rate_counters exists"
    );
    // The initial-access-token store keeps only the token's HASH, never the
    // plaintext (the credential-at-rest invariant, issue #31).
    assert!(
        column_exists(pool, "dcr_initial_access_tokens", "token_hash").await,
        "dcr_initial_access_tokens stores a hash"
    );
    for forbidden in ["token", "secret", "plaintext"] {
        assert!(
            !column_exists(pool, "dcr_initial_access_tokens", forbidden).await,
            "dcr_initial_access_tokens must have no plaintext-token column ({forbidden})"
        );
    }
    // The unverified-client quarantine columns (issue #31): the quarantine flag,
    // the admin verification timestamp, and the policy-chain snapshot that binds
    // RFC 7592 updates for the client's lifetime.
    assert!(
        column_exists(pool, "clients", "quarantined").await,
        "clients.quarantined exists"
    );
    assert!(
        column_exists(pool, "clients", "verified_at").await,
        "clients.verified_at exists"
    );
    assert!(
        column_exists(pool, "clients", "dcr_policy_chain").await,
        "clients.dcr_policy_chain exists"
    );
    // The out-of-band actionable audit detail dimension (issue #31).
    assert!(
        column_exists(pool, "audit_log", "detail").await,
        "audit_log.detail exists"
    );
    // The device-authorization grant table (issue #24, RFC 8628): the digest-only
    // device-code and hashed user-code store, plus the two additive clients columns
    // (the grant allowlist and the display logo).
    assert!(
        table_exists(pool, "device_codes").await,
        "device_codes exists"
    );
    // The device-authorization credential-at-rest invariant (RFC 8628 5.1/6.1): the
    // table stores only a digest of the device code and a hash of the user code,
    // never a plaintext of either.
    assert!(
        column_exists(pool, "device_codes", "device_code_digest").await,
        "device_codes stores a device-code digest"
    );
    assert!(
        column_exists(pool, "device_codes", "user_code_hash").await,
        "device_codes stores a user-code hash"
    );
    for forbidden in ["device_code", "user_code", "secret", "plaintext"] {
        assert!(
            !column_exists(pool, "device_codes", forbidden).await,
            "device_codes must have no plaintext device_code/user_code column ({forbidden})"
        );
    }
    // The polling and cross-device-BCP bookkeeping columns (issue #24): the enforced
    // slow_down interval and last-poll instant, the failed-match death counter, and
    // the initiation-location hint.
    for column in [
        "interval_secs",
        "last_poll_at",
        "failed_attempts",
        "initiation_hint",
        "status",
    ] {
        assert!(
            column_exists(pool, "device_codes", column).await,
            "device_codes.{column} exists"
        );
    }
    // The per-client device-grant allowlist and display logo (issue #24).
    assert!(
        column_exists(pool, "clients", "grant_types").await,
        "clients.grant_types exists"
    );
    assert!(
        column_exists(pool, "clients", "logo_uri").await,
        "clients.logo_uri exists"
    );
    // The RFC 8707 resource-indicator columns (issue #28): the per-client allowlist
    // and no-resource policy, the frozen granted-resource ceiling on the grant and
    // the code, and the recorded audience array on an opaque token.
    assert!(
        column_exists(pool, "clients", "allowed_resources").await,
        "clients.allowed_resources exists"
    );
    assert!(
        column_exists(pool, "clients", "resource_indicator_policy").await,
        "clients.resource_indicator_policy exists"
    );
    assert!(
        column_exists(pool, "grants", "granted_resources").await,
        "grants.granted_resources exists"
    );
    assert!(
        column_exists(pool, "authorization_codes", "granted_resources").await,
        "authorization_codes.granted_resources exists"
    );
    assert!(
        column_exists(pool, "opaque_access_tokens", "audiences").await,
        "opaque_access_tokens.audiences exists"
    );
    // The JWT bearer assertion grant trust and mapping stores (issue #26): the
    // registered external assertion issuers, the explicit subject-mapping rules, and
    // the external-issuer single-use jti replay cache (distinct from the #25 client
    // cache so an external jti cannot collide with a client-assertion jti).
    assert!(
        table_exists(pool, "external_assertion_issuers").await,
        "external_assertion_issuers exists"
    );
    assert!(
        table_exists(pool, "external_assertion_subject_mappings").await,
        "external_assertion_subject_mappings exists"
    );
    assert!(
        table_exists(pool, "external_assertion_jtis").await,
        "external_assertion_jtis exists"
    );
    // The external-issuer jti cache is keyed by the ISSUER (not a client id), the
    // distinct-table choice that keeps an external jti from colliding with a
    // client-assertion jti.
    assert!(
        column_exists(pool, "external_assertion_jtis", "issuer").await,
        "external_assertion_jtis is keyed by issuer"
    );
    // A registered issuer carries an enable switch and a key source.
    assert!(
        column_exists(pool, "external_assertion_issuers", "enabled").await,
        "external_assertion_issuers.enabled exists"
    );
    // A subject-mapping rule maps to an explicit principal (never auto-provisioned).
    assert!(
        column_exists(pool, "external_assertion_subject_mappings", "principal").await,
        "external_assertion_subject_mappings.principal exists"
    );
    // Both trust-config tables carry an `enabled` switch, so a compromised issuer or
    // a mis-authored mapping can be REVOKED through the column-scoped data-plane
    // grant (issue #26 revocability fix). The issuer switch shipped with the table;
    // the mapping switch is the additive column this fix added within migration 20.
    assert!(
        column_exists(pool, "external_assertion_subject_mappings", "enabled").await,
        "external_assertion_subject_mappings.enabled exists"
    );
    // The authoritative two-tier session model (issue #32). Tier two is the new
    // per-client session table: it carries the per-(client, session) `sid` claim,
    // which is STORED (never `sid = session_id`), so it is stable per pair and
    // distinct across pairs.
    assert!(
        table_exists(pool, "client_sessions").await,
        "client_sessions exists"
    );
    for column in ["session_id", "client_id", "sid", "revoked_at"] {
        assert!(
            column_exists(pool, "client_sessions", column).await,
            "client_sessions.{column} exists"
        );
    }
    // Tier one is the EXPANDED sessions table. It gains the immediate-revocation and
    // rotation-lineage guard columns (a revoked or rotated session must stop
    // resolving at once, never merely on expiry) and the session-expiry columns THIS
    // issue owns (idle_expires_at, absolute_expires_at, ended_at, end_cause), so a
    // later issue must not re-add them.
    for column in [
        "revoked_at",
        "revoke_reason",
        "superseded_by",
        "idle_expires_at",
        "absolute_expires_at",
        "ended_at",
        "end_cause",
        "last_seen_at",
        "user_agent",
        "peer_ip",
    ] {
        assert!(
            column_exists(pool, "sessions", column).await,
            "sessions.{column} exists"
        );
    }
    // The RP-initiated logout registered set (issue #33): the additive clients column
    // the end_session endpoint matches a post_logout_redirect_uri against by exact
    // string.
    assert!(
        column_exists(pool, "clients", "post_logout_redirect_uris").await,
        "clients.post_logout_redirect_uris exists"
    );
    // The durable session-ended outbox (issue #35): the transactional-outbox table the
    // session domain enqueues a row on for EVERY terminal end, drained by the
    // back-channel logout worker. Its lifecycle columns (claimed_at, delivered_at) are
    // the only ones a draining consumer is granted UPDATE on.
    assert!(
        table_exists(pool, "session_ended_events").await,
        "session_ended_events exists"
    );
    for column in [
        "session_id",
        "subject",
        "cause",
        "actor_kind",
        "occurred_at",
        "claimed_at",
        "delivered_at",
    ] {
        assert!(
            column_exists(pool, "session_ended_events", column).await,
            "session_ended_events.{column} exists"
        );
    }
    // Back-channel logout registration and the per-RP delivery queue (issue #34): the two
    // additive clients columns the worker resolves a participant from, and the
    // at-least-once delivery table with its own attempts / backoff / dead-letter state.
    assert!(
        column_exists(pool, "clients", "backchannel_logout_uri").await,
        "clients.backchannel_logout_uri exists"
    );
    assert!(
        column_exists(pool, "clients", "backchannel_logout_session_required").await,
        "clients.backchannel_logout_session_required exists"
    );
    assert!(
        table_exists(pool, "backchannel_logout_deliveries").await,
        "backchannel_logout_deliveries exists"
    );
    for column in [
        "event_id",
        "session_id",
        "client_id",
        "sid",
        "logout_uri",
        "jti",
        "attempts",
        "next_attempt_at",
        "claimed_at",
        "delivered_at",
        "dead_lettered_at",
    ] {
        assert!(
            column_exists(pool, "backchannel_logout_deliveries", column).await,
            "backchannel_logout_deliveries.{column} exists"
        );
    }
    // The Front-Channel Logout per-client registration (issue #39): the two additive
    // clients columns the end_session flow reads to decide which RPs get a hidden
    // logout iframe, and whether it carries iss and the RP's own sid.
    for column in [
        "frontchannel_logout_uri",
        "frontchannel_logout_session_required",
    ] {
        assert!(
            column_exists(pool, "clients", column).await,
            "clients.{column} exists"
        );
    }
    // The four-level resource model as public APIs (issue #41): the organizations
    // level table (a schema slot since #6) gains a soft-delete column so it can be
    // deactivated as a first-class management resource without ever hard-deleting a
    // row the append-only audit log references. The operators, tenants, and
    // environments level tables already exist from the isolation root.
    assert!(
        table_exists(pool, "organizations").await,
        "organizations exists"
    );
    assert!(table_exists(pool, "operators").await, "operators exists");
    assert!(
        column_exists(pool, "organizations", "deleted_at").await,
        "organizations.deleted_at exists"
    );
    // The per-tenant envelope-encryption tables (issue #48): the wrapped
    // key-encryption keys, the wrapped data-encryption keys, and the transparent
    // encrypted-secret store.
    assert!(
        table_exists(pool, "tenant_keks").await,
        "tenant_keks exists"
    );
    assert!(
        table_exists(pool, "tenant_deks").await,
        "tenant_deks exists"
    );
    assert!(
        table_exists(pool, "encrypted_secrets").await,
        "encrypted_secrets exists"
    );
    // A KEK/DEK row stores only WRAPPED key material, never a plaintext key.
    assert!(
        column_exists(pool, "tenant_keks", "wrapped_kek").await,
        "tenant_keks stores a wrapped KEK"
    );
    assert!(
        column_exists(pool, "tenant_deks", "wrapped_dek").await,
        "tenant_deks stores a wrapped DEK"
    );
    for forbidden in ["key", "key_material", "plaintext", "secret"] {
        assert!(
            !column_exists(pool, "tenant_keks", forbidden).await,
            "tenant_keks must have no plaintext-key column ({forbidden})"
        );
        assert!(
            !column_exists(pool, "tenant_deks", forbidden).await,
            "tenant_deks must have no plaintext-key column ({forbidden})"
        );
    }
    // The encrypted-secret store holds ONLY ciphertext, never a plaintext column.
    assert!(
        column_exists(pool, "encrypted_secrets", "ciphertext").await,
        "encrypted_secrets stores ciphertext"
    );
    for forbidden in ["plaintext", "secret_value", "value", "secret"] {
        assert!(
            !column_exists(pool, "encrypted_secrets", forbidden).await,
            "encrypted_secrets must have no plaintext column ({forbidden})"
        );
    }

    // The bootstrap users directory now routes its two PII columns through the
    // envelope substrate (issue #48): the plaintext identifier and claims columns
    // are GONE, replaced by a blind index for lookup, a sealed identifier, a sealed
    // claim document, and the DEK version that sealed them. A database dump of the
    // users table therefore carries neither the login handle nor the claim values.
    for forbidden in ["identifier", "claims"] {
        assert!(
            !column_exists(pool, "users", forbidden).await,
            "users must have no plaintext PII column ({forbidden}) after 0027"
        );
    }
    for sealed in [
        "identifier_bidx",
        "identifier_sealed",
        "claims_sealed",
        "pii_dek_version",
    ] {
        assert!(
            column_exists(pool, "users", sealed).await,
            "users.{sealed} exists after 0027"
        );
    }

    // The tenant lifecycle and residency attributes (issue #46): the reversible
    // suspend/resume status and the recorded home_region on tenants, plus the new
    // environment_states scoped table the data plane reads to fence a suspended
    // scope. The plaintext PII invariant does not apply here: home_region is an
    // operator-chosen region label, not end-user PII, and the serving status is a
    // control-plane flag.
    assert!(
        column_exists(pool, "tenants", "status").await,
        "tenants.status exists after 0030"
    );
    assert!(
        column_exists(pool, "tenants", "home_region").await,
        "tenants.home_region exists after 0030"
    );
    assert!(
        column_exists(pool, "tenants", "purged_at").await,
        "tenants.purged_at exists after 0030"
    );
    assert!(
        column_exists(pool, "environments", "region").await,
        "environments.region exists after 0030"
    );
    assert!(
        table_exists(pool, "environment_states").await,
        "environment_states exists after 0030"
    );
    for column in [
        "tenant_id",
        "environment_id",
        "serving_status",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "environment_states", column).await,
            "environment_states.{column} exists after 0030"
        );
    }

    // The BYOK bindings table (issue #49): the per-scope customer-managed-key
    // binding, holding the driver, an opaque external key REFERENCE (never key
    // material), and the binding's lifecycle status. The plaintext-PII invariant
    // does not apply: key_ref is a non-secret handle, not a key or end-user PII.
    assert!(
        table_exists(pool, "tenant_byok_bindings").await,
        "tenant_byok_bindings exists after 0031"
    );
    for column in [
        "tenant_id",
        "environment_id",
        "provider",
        "key_ref",
        "status",
        "created_at",
        "destroyed_at",
    ] {
        assert!(
            column_exists(pool, "tenant_byok_bindings", column).await,
            "tenant_byok_bindings.{column} exists after 0031"
        );
    }
    // The per-environment custom-domain registry and the ACME challenge lifecycle
    // (issue #47): the domains table and the challenges table, both new after 0033.
    assert!(
        table_exists(pool, "custom_domains").await,
        "custom_domains exists after 0033"
    );
    assert!(
        table_exists(pool, "acme_challenges").await,
        "acme_challenges exists after 0033"
    );
    for column in [
        "domain_name",
        "challenge_type",
        "verification_status",
        "cert_secret_id",
        "cert_not_after",
    ] {
        assert!(
            column_exists(pool, "custom_domains", column).await,
            "custom_domains.{column} exists after 0033"
        );
    }
    for column in [
        "domain_id",
        "challenge_type",
        "token",
        "status",
        "attempts",
        "next_attempt_at",
    ] {
        assert!(
            column_exists(pool, "acme_challenges", column).await,
            "acme_challenges.{column} exists after 0033"
        );
    }
    // A custom domain's certificate PRIVATE KEY is never stored on the domain row:
    // custom_domains carries only an opaque handle to the sealed bundle in
    // encrypted_secrets (issue #48), never a key or a certificate column. A dump of
    // custom_domains therefore reveals no key material.
    for forbidden in [
        "private_key",
        "cert_pem",
        "certificate",
        "key_material",
        "private_key_pem",
    ] {
        assert!(
            !column_exists(pool, "custom_domains", forbidden).await,
            "custom_domains must have no plaintext key/cert column ({forbidden})"
        );
    }
    // The per-environment secrets and variables store (issue #45): two new tables
    // after 0034. Variables carry a plaintext value (promotable, non-secret);
    // secrets carry ONLY sealed ciphertext, never a plaintext value column.
    assert!(
        table_exists(pool, "environment_variables").await,
        "environment_variables exists after 0034"
    );
    assert!(
        table_exists(pool, "environment_secrets").await,
        "environment_secrets exists after 0034"
    );
    for column in ["name", "value", "version", "created_at", "updated_at"] {
        assert!(
            column_exists(pool, "environment_variables", column).await,
            "environment_variables.{column} exists after 0034"
        );
    }
    for column in [
        "name",
        "dek_version",
        "ciphertext",
        "version",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "environment_secrets", column).await,
            "environment_secrets.{column} exists after 0034"
        );
    }
    // A secret VALUE is never stored in the clear: environment_secrets carries only
    // the sealed ciphertext, never a plaintext value / secret column. A dump of the
    // table therefore reveals no secret.
    for forbidden in ["value", "plaintext", "secret", "secret_value"] {
        assert!(
            !column_exists(pool, "environment_secrets", forbidden).await,
            "environment_secrets must have no plaintext secret column ({forbidden})"
        );
    }

    // The admin-user-lifecycle columns folded onto users (issue #52): the lifecycle
    // state, the external-id blind index + sealed value + its DEK version (the
    // plaintext external id never lands on a column), the scheduled-offboarding
    // instant, and the mutation / soft-delete timestamps.
    for column in [
        "state",
        "external_id_bidx",
        "external_id_sealed",
        "external_id_dek_version",
        "scheduled_offboarding_at",
        "updated_at",
        "deleted_at",
    ] {
        assert!(
            column_exists(pool, "users", column).await,
            "users.{column} exists after 0037"
        );
    }
    // The external id is a lookup key, so it follows the blind-index pattern (issue
    // #48): the plaintext external id never lands on a column.
    assert!(
        !column_exists(pool, "users", "external_id").await,
        "users must have no plaintext external_id column after 0037"
    );

    // The identity-traits tables and the per-user sealed trait columns (issue #53).
    assert!(
        table_exists(pool, "trait_schemas").await,
        "trait_schemas exists after 0038"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "version",
        "schema_json",
        "status",
    ] {
        assert!(
            column_exists(pool, "trait_schemas", column).await,
            "trait_schemas.{column} exists after 0038"
        );
    }
    assert!(
        table_exists(pool, "trait_migration_jobs").await,
        "trait_migration_jobs exists after 0038"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "kind",
        "from_version",
        "to_version",
        "transform_json",
        "status",
        "cursor_id",
        "total_count",
        "processed_count",
        "migrated_count",
        "failure_count",
        "failures_json",
    ] {
        assert!(
            column_exists(pool, "trait_migration_jobs", column).await,
            "trait_migration_jobs.{column} exists after 0038"
        );
    }
    // A user's traits are user profile PII, sealed under the scope DEK (issue #48):
    // the document lands only on the sealed bytea column, never a plaintext one, and
    // the identity records the schema version it was validated against.
    for column in [
        "traits_sealed",
        "traits_dek_version",
        "traits_schema_version",
    ] {
        assert!(
            column_exists(pool, "users", column).await,
            "users.{column} exists after 0038"
        );
    }
    assert!(
        !column_exists(pool, "users", "traits").await,
        "users must have no plaintext traits column after 0038"
    );
    // The foreign-password-import columns folded onto users (issue #55): the
    // algorithm-tagged foreign verifier and its non-secret algorithm tag, both
    // added by 0039. A password hash is a one-way verifier, not PII, so it is stored
    // as text exactly like the native password_hash.
    for column in ["foreign_password_hash", "foreign_password_algo"] {
        assert!(
            column_exists(pool, "users", column).await,
            "users.{column} exists after 0039"
        );
    }

    // The user-invitations table (issue #60): the pending invitation row with the
    // user it provisions, the token digest (never the token), the sealed and
    // blind-indexed invited identifier (user PII never lands on a plaintext column),
    // the closed credential type and lifecycle state, the expiry, and the terminal
    // timestamps.
    assert!(
        table_exists(pool, "user_invitations").await,
        "user_invitations exists after 0040"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "user_id",
        "token_digest",
        "target_identifier_sealed",
        "target_identifier_bidx",
        "pii_dek_version",
        "credential_type",
        "state",
        "org_context",
        "expires_at",
        "created_at",
        "updated_at",
        "accepted_at",
        "revoked_at",
    ] {
        assert!(
            column_exists(pool, "user_invitations", column).await,
            "user_invitations.{column} exists after 0040"
        );
    }
    // The digest-only invariant (issue #60, acceptance criterion 6): the
    // user_invitations table stores only a digest of the token, never a plaintext
    // token, so a database read cannot yield a redeemable link.
    assert!(
        column_exists(pool, "user_invitations", "token_digest").await,
        "user_invitations stores a token digest"
    );
    for forbidden in ["token", "secret", "plaintext", "invite_token", "raw_token"] {
        assert!(
            !column_exists(pool, "user_invitations", forbidden).await,
            "user_invitations must have no plaintext-token column ({forbidden})"
        );
    }
    // The invited identifier is user PII, sealed and blind-indexed (issue #48): the
    // plaintext identifier / email never lands on a column.
    for forbidden in ["target_identifier", "identifier", "email"] {
        assert!(
            !column_exists(pool, "user_invitations", forbidden).await,
            "user_invitations must have no plaintext identifier column ({forbidden})"
        );
    }

    // The flexible-identifiers table (issue #54): one new user_identifiers scoped
    // table with the owning user, the closed identifier kind, the CANONICAL blind
    // index and the RAW sealed value (user PII never lands on a plaintext column),
    // its DEK version, the per-identifier verified flag, the uniqueness-mode
    // discriminator, and the terminal timestamps.
    assert!(
        table_exists(pool, "user_identifiers").await,
        "user_identifiers exists after 0041"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "user_id",
        "identifier_type",
        "canonical_bidx",
        "raw_sealed",
        "pii_dek_version",
        "verified",
        "uniqueness_key",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "user_identifiers", column).await,
            "user_identifiers.{column} exists after 0041"
        );
    }
    // The identifier value is user PII, stored ONLY as the sealed raw value and the
    // canonical blind index (issue #48): no plaintext identifier / email / phone /
    // canonical column ever lands in the schema.
    for forbidden in [
        "identifier",
        "email",
        "phone",
        "phone_number",
        "canonical",
        "raw",
    ] {
        assert!(
            !column_exists(pool, "user_identifiers", forbidden).await,
            "user_identifiers must have no plaintext identifier column ({forbidden})"
        );
    }
    // The tenant-scoped-table obligations (migrate.rs checklist), asserted structurally
    // against pg_catalog: forced row-level security, the (tenant, environment) isolation
    // policy, the nonempty-scope and closed-type CHECK constraints, and the partial
    // UNIQUE index that enforces uniqueness-as-configuration. A future edit that drops
    // any of these silently reopens a cross-tenant leak or the uniqueness gap; this
    // fails the build instead.
    assert!(
        rls_enabled_and_forced(pool, "user_identifiers").await,
        "user_identifiers must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "user_identifiers",
            "user_identifiers_tenant_isolation"
        )
        .await,
        "the (tenant, environment) isolation policy must exist on user_identifiers"
    );
    for constraint in [
        "user_identifiers_scope_nonempty",
        "user_identifiers_type_known",
    ] {
        assert!(
            check_constraint_exists(pool, "user_identifiers", constraint).await,
            "user_identifiers must carry the {constraint} CHECK constraint"
        );
    }
    assert!(
        partial_unique_index_exists(pool, "user_identifiers", "user_identifiers_uniqueness").await,
        "the partial UNIQUE index user_identifiers_uniqueness must exist"
    );

    // The migration state-machine tables (issue #59): the run row carrying the named
    // lifecycle state and the count/backfill thresholds, and the per-record accounting
    // ledger the invariants re-evaluate against.
    assert!(
        table_exists(pool, "migration_runs").await,
        "migration_runs exists after 0043"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "kind",
        "state",
        "source_total",
        "backfill_expected",
        "subject_ref",
        "abandoned_reason",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "migration_runs", column).await,
            "migration_runs.{column} exists after 0043"
        );
    }
    assert!(
        table_exists(pool, "migration_run_records").await,
        "migration_run_records exists after 0043"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "run_id",
        "subject_bidx",
        "subject_sealed",
        "subject_dek_version",
        "outcome",
        "consistent",
        "backfilled",
        "detail",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "migration_run_records", column).await,
            "migration_run_records.{column} exists after 0043"
        );
    }
    // A record's natural subject is user PII, stored ONLY as the sealed value and the
    // blind index (issue #48): no plaintext subject / identifier / email column ever
    // lands in the schema.
    for forbidden in ["subject", "identifier", "email", "key", "subject_plain"] {
        assert!(
            !column_exists(pool, "migration_run_records", forbidden).await,
            "migration_run_records must have no plaintext subject column ({forbidden})"
        );
    }
    // The tenant-scoped-table obligations for both new tables (migrate.rs checklist),
    // asserted structurally against pg_catalog: forced row-level security, the
    // (tenant, environment) isolation policy, and the nonempty-scope / closed-set CHECKs.
    for table in ["migration_runs", "migration_run_records"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    for constraint in ["migration_runs_kind_known", "migration_runs_state_known"] {
        assert!(
            check_constraint_exists(pool, "migration_runs", constraint).await,
            "migration_runs must carry the {constraint} CHECK constraint"
        );
    }
    assert!(
        check_constraint_exists(
            pool,
            "migration_run_records",
            "migration_run_records_outcome_known"
        )
        .await,
        "migration_run_records must carry the outcome-known CHECK constraint"
    );

    // ---- 0044 webauthn credentials + challenges (issue #65) ----
    assert!(
        table_exists(pool, "webauthn_credentials").await,
        "webauthn_credentials exists after 0044"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "credential_id",
        "cose_public_key",
        "sign_count",
        "aaguid",
        "transports",
        "backup_eligible",
        "backup_state",
        "discoverable",
        "clone_detected",
        "nickname_sealed",
        "pii_dek_version",
        "created_at",
        "last_used_at",
    ] {
        assert!(
            column_exists(pool, "webauthn_credentials", column).await,
            "webauthn_credentials.{column} exists after 0044"
        );
    }
    // The user-authored nickname is user PII, stored ONLY as the sealed value
    // (issue #48): no plaintext nickname / friendly-name column ever lands.
    for forbidden in ["nickname", "friendly_name", "label"] {
        assert!(
            !column_exists(pool, "webauthn_credentials", forbidden).await,
            "webauthn_credentials must have no plaintext nickname column ({forbidden})"
        );
    }
    assert!(
        table_exists(pool, "webauthn_challenges").await,
        "webauthn_challenges exists after 0044"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "ceremony",
        "subject",
        "challenge",
        "consumed_at",
        "expires_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "webauthn_challenges", column).await,
            "webauthn_challenges.{column} exists after 0044"
        );
    }
    // The tenant-scoped-table obligations for both new tables.
    for table in ["webauthn_credentials", "webauthn_challenges"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    assert!(
        check_constraint_exists(
            pool,
            "webauthn_challenges",
            "webauthn_challenges_ceremony_known"
        )
        .await,
        "webauthn_challenges must carry the ceremony-known CHECK constraint"
    );

    // ---- 0045 totp credentials + recovery codes (issue #69) ----
    assert!(
        table_exists(pool, "totp_credentials").await,
        "totp_credentials exists after 0045"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "totp_seed",
        "friendly_name_sealed",
        "pii_dek_version",
        "algorithm",
        "digits",
        "period_secs",
        "status",
        "last_consumed_step",
        "last_offset",
        "created_at",
        "activated_at",
        "last_used_at",
    ] {
        assert!(
            column_exists(pool, "totp_credentials", column).await,
            "totp_credentials.{column} exists after 0045"
        );
    }
    // The RFC 6238 SEED is secret material: it lands ONLY as a sealed `bytea`
    // ciphertext (issue #48), never a plaintext column, and the pii-encryption-scan
    // enforces this structurally too. Assert the type is bytea and that no plaintext
    // seed / secret column ever exists.
    assert_eq!(
        column_data_type(pool, "totp_credentials", "totp_seed").await,
        "bytea",
        "the TOTP seed must be a sealed bytea, never plaintext"
    );
    for forbidden in [
        "seed",
        "secret",
        "totp_secret",
        "seed_plaintext",
        "shared_secret",
    ] {
        assert!(
            !column_exists(pool, "totp_credentials", forbidden).await,
            "totp_credentials must have no plaintext seed column ({forbidden})"
        );
    }
    assert!(
        table_exists(pool, "recovery_codes").await,
        "recovery_codes exists after 0045"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "code_hash",
        "generation",
        "consumed_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "recovery_codes", column).await,
            "recovery_codes.{column} exists after 0045"
        );
    }
    // Recovery codes are stored ONLY as a one-way hash, never a plaintext code.
    for forbidden in ["code", "code_plaintext", "recovery_code", "plaintext"] {
        assert!(
            !column_exists(pool, "recovery_codes", forbidden).await,
            "recovery_codes must have no plaintext code column ({forbidden})"
        );
    }
    // The tenant-scoped-table obligations for both new tables.
    for table in ["totp_credentials", "recovery_codes"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    // The closed status and RFC 6238 hash sets (no HOTP): a corrupt or unknown value
    // can never be written.
    assert!(
        check_constraint_exists(pool, "totp_credentials", "totp_credentials_status_known").await,
        "totp_credentials must carry the status-known CHECK constraint"
    );
    assert!(
        check_constraint_exists(pool, "totp_credentials", "totp_credentials_algorithm_known").await,
        "totp_credentials must carry the algorithm-known CHECK constraint (no HOTP)"
    );

    // The credential-abuse ban registry (issue #64, migration 0046).
    assert!(
        table_exists(pool, "abuse_bans").await,
        "abuse_bans exists after 0046"
    );
    for column in [
        "id",
        "subject_kind",
        "subject_bidx",
        "subject_sealed",
        "pii_dek_version",
        "auth_path",
        "reason",
        "expires_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "abuse_bans", column).await,
            "abuse_bans.{column} exists after 0045"
        );
    }
    // The regulated subject is PII (an identifier / IP): it is sealed and blind-indexed,
    // never a plaintext column.
    for forbidden in ["subject", "identifier", "ip", "email", "account_id"] {
        assert!(
            !column_exists(pool, "abuse_bans", forbidden).await,
            "abuse_bans must have no plaintext subject column ({forbidden})"
        );
    }
    assert!(
        rls_enabled_and_forced(pool, "abuse_bans").await,
        "abuse_bans must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "abuse_bans", "abuse_bans_tenant_isolation").await,
        "the (tenant, environment) isolation policy must exist on abuse_bans"
    );
    for constraint in [
        "abuse_bans_scope_nonempty",
        "abuse_bans_subject_kind_known",
        "abuse_bans_auth_path_known",
    ] {
        assert!(
            check_constraint_exists(pool, "abuse_bans", constraint).await,
            "abuse_bans must carry the {constraint} CHECK constraint"
        );
    }

    // ---- 0047 step-up policies (issue #72) ----
    assert!(
        table_exists(pool, "scope_step_up_policies").await,
        "scope_step_up_policies exists after 0047"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "scope",
        "min_acr",
        "max_auth_age_secs",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "scope_step_up_policies", column).await,
            "scope_step_up_policies.{column} exists after 0047"
        );
    }
    // The tenant-scoped-table obligations (migrate.rs checklist): forced row-level
    // security, the (tenant, environment) isolation policy, and the nonempty-scope
    // CHECK.
    assert!(
        rls_enabled_and_forced(pool, "scope_step_up_policies").await,
        "scope_step_up_policies must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "scope_step_up_policies",
            "scope_step_up_policies_tenant_isolation"
        )
        .await,
        "the (tenant, environment) isolation policy must exist on scope_step_up_policies"
    );
    for constraint in [
        "scope_step_up_policies_scope_nonempty",
        "scope_step_up_policies_scope_token_nonempty",
        "scope_step_up_policies_requirement_present",
    ] {
        assert!(
            check_constraint_exists(pool, "scope_step_up_policies", constraint).await,
            "scope_step_up_policies must carry the {constraint} CHECK constraint"
        );
    }
    // The additive per-client step-up floor columns (issue #72).
    for column in ["step_up_acr", "step_up_max_age_secs"] {
        assert!(
            column_exists(pool, "clients", column).await,
            "clients.{column} exists after 0047"
        );
    }
    // The frozen auth_time on the refresh family, so a refresh can re-evaluate the
    // max-age window without a new authentication (issue #72).
    assert!(
        column_exists(pool, "refresh_families", "auth_time").await,
        "refresh_families.auth_time exists after 0047"
    );

    // ---- 0048 email OTP + scanner-safe magic links (issue #68) ----
    assert!(
        table_exists(pool, "email_otp_codes").await,
        "email_otp_codes exists after 0048"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "purpose",
        "code_hash",
        "recipient_email_bidx",
        "recipient_email_sealed",
        "pii_dek_version",
        "attempt_count",
        "max_attempts",
        "expires_at",
        "consumed_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "email_otp_codes", column).await,
            "email_otp_codes.{column} exists after 0048"
        );
    }
    // A 6-8 digit code is a low-entropy secret: it lands ONLY as a one-way Argon2id hash,
    // never a plaintext column, and the recipient email is sealed (bytea), never plaintext.
    assert_eq!(
        column_data_type(pool, "email_otp_codes", "recipient_email_sealed").await,
        "bytea",
        "the recipient email must be a sealed bytea, never plaintext"
    );
    for forbidden in [
        "code",
        "code_plaintext",
        "otp",
        "plaintext",
        "email",
        "recipient_email",
    ] {
        assert!(
            !column_exists(pool, "email_otp_codes", forbidden).await,
            "email_otp_codes must have no plaintext code / email column ({forbidden})"
        );
    }
    assert!(
        table_exists(pool, "magic_link_tokens").await,
        "magic_link_tokens exists after 0048"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "purpose",
        "token_digest",
        "short_code_hash",
        "binding_digest",
        "recipient_email_bidx",
        "recipient_email_sealed",
        "pii_dek_version",
        "attempt_count",
        "max_attempts",
        "expires_at",
        "consumed_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "magic_link_tokens", column).await,
            "magic_link_tokens.{column} exists after 0048"
        );
    }
    // The magic-link token is stored ONLY as its SHA-256 digest and the short code as an
    // Argon2id hash, never a plaintext bearer value; the recipient email is sealed.
    assert_eq!(
        column_data_type(pool, "magic_link_tokens", "recipient_email_sealed").await,
        "bytea",
        "the recipient email must be a sealed bytea, never plaintext"
    );
    for forbidden in [
        "token",
        "secret",
        "short_code",
        "plaintext",
        "email",
        "recipient_email",
    ] {
        assert!(
            !column_exists(pool, "magic_link_tokens", forbidden).await,
            "magic_link_tokens must have no plaintext token / code / email column ({forbidden})"
        );
    }
    // The tenant-scoped-table obligations for both new tables.
    for table in ["email_otp_codes", "magic_link_tokens"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_purpose_known")).await,
            "{table} must carry the purpose-known CHECK constraint"
        );
        // Both factors attempt-limit their low-entropy secret (the OTP code; the magic
        // link's cross-device short code), so both carry the attempt-budget CHECK.
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_attempts_nonneg")).await,
            "{table} must carry the attempts-nonneg CHECK constraint"
        );
    }

    // ---- 0049 credential-class policies + attestation config + user-handle (issue #66) ----
    assert!(
        table_exists(pool, "credential_class_policies").await,
        "credential_class_policies exists after 0049"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject_kind",
        "subject_ref",
        "min_class",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "credential_class_policies", column).await,
            "credential_class_policies.{column} exists after 0049"
        );
    }
    assert!(
        table_exists(pool, "attestation_config").await,
        "attestation_config exists after 0049"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "mode",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "attestation_config", column).await,
            "attestation_config.{column} exists after 0049"
        );
    }
    // Neither table carries PII (a class token, a subject discriminator, a mode).
    // The tenant-scoped-table obligations for both new tables.
    for table in ["credential_class_policies", "attestation_config"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    for constraint in [
        "credential_class_policies_subject_kind_known",
        "credential_class_policies_min_class_known",
        "credential_class_policies_subject_ref_presence",
    ] {
        assert!(
            check_constraint_exists(pool, "credential_class_policies", constraint).await,
            "credential_class_policies must carry the {constraint} CHECK constraint"
        );
    }
    assert!(
        check_constraint_exists(pool, "attestation_config", "attestation_config_mode_known").await,
        "attestation_config must carry the mode-known CHECK constraint"
    );
    // The passkey-only account markers on users (issue #66): the immutable WebAuthn
    // user handle (a bytea) and the passwordless flag.
    for column in ["webauthn_user_handle", "passwordless"] {
        assert!(
            column_exists(pool, "users", column).await,
            "users.{column} exists after 0049"
        );
    }
    assert_eq!(
        column_data_type(pool, "users", "webauthn_user_handle").await,
        "bytea",
        "the WebAuthn user handle is an opaque bytea"
    );
    // The user-handle immutability trigger is the storage-layer half of the guarantee
    // (the other half is the deliberate omission of the column from every GRANT UPDATE).
    let trigger_present: bool = sqlx::query(
        "SELECT EXISTS ( \
            SELECT 1 FROM pg_catalog.pg_trigger \
            WHERE tgrelid = 'users'::regclass AND tgname = 'users_user_handle_immutable' \
              AND NOT tgisinternal \
         ) AS present",
    )
    .fetch_one(pool)
    .await
    .expect("trigger lookup")
    .get("present");
    assert!(
        trigger_present,
        "the users_user_handle_immutable BEFORE UPDATE trigger must exist"
    );

    // ---- 0050 guarded SMS OTP (issue #70) ----
    // The SMS-OTP code store mirrors email_otp_codes; the recipient is a sealed +
    // blind-indexed PHONE, never plaintext, and the code is a one-way Argon2id hash.
    assert!(
        table_exists(pool, "sms_otp_codes").await,
        "sms_otp_codes exists after 0050"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "purpose",
        "code_hash",
        "recipient_phone_bidx",
        "recipient_phone_sealed",
        "pii_dek_version",
        "attempt_count",
        "max_attempts",
        "expires_at",
        "consumed_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "sms_otp_codes", column).await,
            "sms_otp_codes.{column} exists after 0050"
        );
    }
    assert_eq!(
        column_data_type(pool, "sms_otp_codes", "recipient_phone_sealed").await,
        "bytea",
        "the recipient phone must be a sealed bytea, never plaintext"
    );
    for forbidden in [
        "code",
        "otp",
        "plaintext",
        "phone",
        "phone_number",
        "recipient_phone",
    ] {
        assert!(
            !column_exists(pool, "sms_otp_codes", forbidden).await,
            "sms_otp_codes must have no plaintext code / phone column ({forbidden})"
        );
    }
    assert!(
        rls_enabled_and_forced(pool, "sms_otp_codes").await,
        "sms_otp_codes must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "sms_otp_codes", "sms_otp_codes_tenant_isolation").await,
        "the (tenant, environment) isolation policy must exist on sms_otp_codes"
    );
    for constraint in [
        "sms_otp_codes_scope_nonempty",
        "sms_otp_codes_purpose_known",
        "sms_otp_codes_attempts_nonneg",
    ] {
        assert!(
            check_constraint_exists(pool, "sms_otp_codes", constraint).await,
            "sms_otp_codes must carry the {constraint} CHECK constraint"
        );
    }

    // The per-tenant SMS enablement: off by default (enabled DEFAULT false) and the
    // factor-downgrade opt-in (default false). Both are the safe defaults that keep SMS
    // off and non-downgrading everywhere.
    assert!(
        table_exists(pool, "sms_config").await,
        "sms_config exists after 0050"
    );
    for column in [
        "tenant_id",
        "environment_id",
        "enabled",
        "allow_factor_downgrade",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "sms_config", column).await,
            "sms_config.{column} exists after 0050"
        );
    }
    // The country ALLOWLIST (never a blocklist): a per (tenant, environment, country)
    // membership row.
    assert!(
        table_exists(pool, "sms_country_allowlist").await,
        "sms_country_allowlist exists after 0050"
    );
    for column in ["tenant_id", "environment_id", "country_code", "created_at"] {
        assert!(
            column_exists(pool, "sms_country_allowlist", column).await,
            "sms_country_allowlist.{column} exists after 0050"
        );
    }
    // The per-route send-to-verify conversion counters + auto-throttle state.
    assert!(
        table_exists(pool, "sms_route_stats").await,
        "sms_route_stats exists after 0050"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "route_key",
        "send_count",
        "verify_count",
        "window_started_at",
        "throttled_until",
        "alarm_active",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "sms_route_stats", column).await,
            "sms_route_stats.{column} exists after 0050"
        );
    }
    // The tenant-scoped-table obligations for every new SMS table.
    for table in ["sms_config", "sms_country_allowlist", "sms_route_stats"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }

    // ---- 0051 passkey attestation (issue #66, PR B) ----
    // The per-scope verified MDS3 BLOB cache: the extracted, trusted authenticator
    // entries the attestation path evaluates against, plus the raw-BLOB digest for
    // byte-identical-refetch change detection. No PII (public authenticator metadata).
    assert!(
        table_exists(pool, "mds3_blob_cache").await,
        "mds3_blob_cache exists after 0051"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "blob_no",
        "next_update",
        "payload_jsonb",
        "blob_digest",
        "fetched_at",
        "verified_at",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "mds3_blob_cache", column).await,
            "mds3_blob_cache.{column} exists after 0051"
        );
    }
    // The per-scope AAGUID allow / deny list: one disposition per pinned model.
    assert!(
        table_exists(pool, "aaguid_rules").await,
        "aaguid_rules exists after 0051"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "aaguid",
        "disposition",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "aaguid_rules", column).await,
            "aaguid_rules.{column} exists after 0051"
        );
    }
    // The tenant-scoped-table obligations for both new tables.
    for table in ["mds3_blob_cache", "aaguid_rules"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    // The AAGUID rule disposition is a closed set.
    assert!(
        check_constraint_exists(pool, "aaguid_rules", "aaguid_rules_disposition_known").await,
        "aaguid_rules must carry the disposition-known CHECK constraint"
    );
    // The reg-time attestation facts on the passkey credential row: captured once at
    // registration, immutable thereafter (INSERT-only, absent from every GRANT UPDATE).
    for column in [
        "attestation_type",
        "attestation_verified",
        "attestation_fmt",
    ] {
        assert!(
            column_exists(pool, "webauthn_credentials", column).await,
            "webauthn_credentials.{column} exists after 0051"
        );
    }
    for constraint in [
        "webauthn_credentials_attestation_type_known",
        "webauthn_credentials_attestation_fmt_known",
    ] {
        assert!(
            check_constraint_exists(pool, "webauthn_credentials", constraint).await,
            "webauthn_credentials must carry the {constraint} CHECK constraint"
        );
    }

    // ---- 0052 admin sudo elevations (issue #73) ----
    assert!(
        table_exists(pool, "admin_sudo_elevations").await,
        "admin_sudo_elevations exists after 0052"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "actor_kind",
        "actor_id",
        "acr",
        "elevated_at",
        "expires_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "admin_sudo_elevations", column).await,
            "admin_sudo_elevations.{column} exists after 0052"
        );
    }
    // The tenant-scoped-table obligations (migrate.rs checklist): forced row-level
    // security, the (tenant, environment) isolation policy, and the nonempty-scope
    // CHECK.
    assert!(
        rls_enabled_and_forced(pool, "admin_sudo_elevations").await,
        "admin_sudo_elevations must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(
            pool,
            "admin_sudo_elevations",
            "admin_sudo_elevations_tenant_isolation"
        )
        .await,
        "the (tenant, environment) isolation policy must exist on admin_sudo_elevations"
    );
    for constraint in [
        "admin_sudo_elevations_scope_nonempty",
        "admin_sudo_elevations_actor_nonempty",
        "admin_sudo_elevations_acr_nonempty",
    ] {
        assert!(
            check_constraint_exists(pool, "admin_sudo_elevations", constraint).await,
            "admin_sudo_elevations must carry the {constraint} CHECK constraint"
        );
    }

    // ---- 0054 minimal risk engine (issue #79) ----
    // The per-subject last-seen login geo the impossible-travel signal reads: the observed
    // IP, coarse location, and User-Agent are end-user device metadata (PII), each SEALED
    // under the scope DEK (issue #48), never a plaintext column.
    assert!(
        table_exists(pool, "risk_login_geo").await,
        "risk_login_geo exists after 0054"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "ip_sealed",
        "geo_sealed",
        "user_agent_sealed",
        "pii_dek_version",
        "observed_at",
        "created_at",
        "updated_at",
    ] {
        assert!(
            column_exists(pool, "risk_login_geo", column).await,
            "risk_login_geo.{column} exists after 0054"
        );
    }
    // The observed IP / location / User-Agent are PII, sealed under the scope DEK (issue
    // #48): no plaintext column ever lands.
    for forbidden in ["ip", "geo", "user_agent", "location", "ip_address"] {
        assert!(
            !column_exists(pool, "risk_login_geo", forbidden).await,
            "risk_login_geo must have no plaintext PII column ({forbidden}) after 0054"
        );
    }
    assert_eq!(
        column_data_type(pool, "risk_login_geo", "geo_sealed").await,
        "bytea",
        "the login geo must be a sealed bytea, never plaintext"
    );

    // The persisted decision record: the LOW/MED/HIGH score, the dispatched action, and the
    // enumerated contributing signals (no plaintext PII).
    assert!(
        table_exists(pool, "risk_decisions").await,
        "risk_decisions exists after 0054"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "correlation_id",
        "score",
        "action",
        "signals",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "risk_decisions", column).await,
            "risk_decisions.{column} exists after 0054"
        );
    }

    // The "this wasn't me" disavowal token: the SHA-256 digest of the single-use secret
    // (server-side state), the sessions it revokes, and the single-use consumed_at latch.
    assert!(
        table_exists(pool, "risk_disavowal_tokens").await,
        "risk_disavowal_tokens exists after 0054"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "subject",
        "token_digest",
        "decision_id",
        "session_ids",
        "consumed_at",
        "expires_at",
        "created_at",
    ] {
        assert!(
            column_exists(pool, "risk_disavowal_tokens", column).await,
            "risk_disavowal_tokens.{column} exists after 0054"
        );
    }
    // The disavowal token is stored ONLY as its SHA-256 digest, never a plaintext bearer
    // value.
    assert_eq!(
        column_data_type(pool, "risk_disavowal_tokens", "token_digest").await,
        "bytea",
        "the disavowal token is stored as a digest, never plaintext"
    );
    for forbidden in ["token", "secret", "plaintext", "raw_token"] {
        assert!(
            !column_exists(pool, "risk_disavowal_tokens", forbidden).await,
            "risk_disavowal_tokens must have no plaintext-token column ({forbidden})"
        );
    }

    // The tenant-scoped-table obligations for every new risk table: forced row-level
    // security, the (tenant, environment) isolation policy, and the nonempty-scope CHECK.
    for table in ["risk_login_geo", "risk_decisions", "risk_disavowal_tokens"] {
        assert!(
            rls_enabled_and_forced(pool, table).await,
            "{table} must ENABLE and FORCE row-level security"
        );
        assert!(
            policy_exists(pool, table, &format!("{table}_tenant_isolation")).await,
            "the (tenant, environment) isolation policy must exist on {table}"
        );
        assert!(
            check_constraint_exists(pool, table, &format!("{table}_scope_nonempty")).await,
            "{table} must carry the scope-nonempty CHECK constraint"
        );
    }
    // The decision score and action are closed sets: a corrupt or unknown value can never
    // be written.
    for constraint in ["risk_decisions_score_known", "risk_decisions_action_known"] {
        assert!(
            check_constraint_exists(pool, "risk_decisions", constraint).await,
            "risk_decisions must carry the {constraint} CHECK constraint"
        );
    }

    // Federation connectors (issue #75, migration 0055): one new tenant-scoped table.
    assert!(
        table_exists(pool, "connectors").await,
        "connectors exists after 0055"
    );
    for column in [
        "id",
        "tenant_id",
        "environment_id",
        "connector_slug",
        "definition_json",
        "client_secret_sealed",
        "client_secret_dek_version",
        "cap_refresh",
        "cap_groups",
        "cap_logout_propagation",
        "cap_email_verified_trust",
        "enabled",
    ] {
        assert!(
            column_exists(pool, "connectors", column).await,
            "connectors.{column} exists after 0055"
        );
    }
    // The upstream client secret is SEALED, never a plaintext column.
    assert_eq!(
        column_data_type(pool, "connectors", "client_secret_sealed").await,
        "bytea",
        "the connector client secret must be a sealed bytea column, never plaintext"
    );
    // The definition column is jsonb and SECRET-FREE (the client_secret field is stripped
    // before storage), so a raw plaintext client_secret column can never exist here.
    assert!(
        !column_exists(pool, "connectors", "client_secret").await,
        "connectors must have no plaintext client_secret column after 0055"
    );
    // The tenant-scoped-table obligations: forced RLS, the isolation policy, and the
    // nonempty-scope CHECK, plus the closed email-verified-trust CHECK.
    assert!(
        rls_enabled_and_forced(pool, "connectors").await,
        "connectors must ENABLE and FORCE row-level security"
    );
    assert!(
        policy_exists(pool, "connectors", "connectors_tenant_isolation").await,
        "the (tenant, environment) isolation policy must exist on connectors"
    );
    for constraint in [
        "connectors_scope_nonempty",
        "connectors_email_verified_trust_known",
    ] {
        assert!(
            check_constraint_exists(pool, "connectors", constraint).await,
            "connectors must carry the {constraint} CHECK constraint"
        );
    }
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
