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

/// The PRODUCTION chain (`MigrationRunner::new`) contains exactly the twenty-eight
/// real migrations and leaves no throwaway demo object in a real database.
// A long but linear ledger-and-table assertion sweep (one line per migration and
// per real table); splitting it would not make it clearer.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn production_chain_is_only_the_thirty_one_real_migrations_and_ships_no_demo_object() {
    // TestDatabase::start runs Store::migrate() (the production chain) on a
    // fresh, empty database.
    let db = TestDatabase::start().await;
    let pool = db.owner_pool();

    // Re-running is idempotent and reports exactly thirty-one tracked migrations.
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
        31,
        "the production chain is exactly thirty-one migrations (isolation, audit log, management \
         API, OIDC authorization, signing keys, login/consent, authentication context, redirect \
         registration, UserInfo claims, consent scope upsert, resource servers, opaque access \
         tokens, client auth suite, dynamic client registration, pushed authorization requests, \
         refresh tokens, client-credentials service accounts, DCR abuse controls, resource \
         indicators, JWT bearer assertion grant, device authorization, session model, RP-initiated \
         logout, session-ended events, back-channel logout, front-channel logout, resource-model \
         APIs, envelope encryption, environment guardrails, tenant lifecycle, snapshot export)"
    );

    // The ledger holds exactly versions 1 through 31.
    assert_eq!(
        applied_versions(pool).await,
        vec![
            1_i64, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31
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
    // The snapshot-export migration (issue #43): a single GRANT SELECT on
    // resource_servers to the control role, so the management-plane snapshot export
    // can read the promotable resource-server registry. A pure grant, no schema
    // change, so this is an expand too.
    assert_eq!(phase_of(31).await, "expand");

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
