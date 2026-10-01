// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact historical-checksum compatibility for the broken upstream 0237 view.
//! Every schema here belongs to the throwaway test cluster.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, MigrationError, MigrationRunner, chain};

const OLD_HASH: &str = "02bd786d62041c24c5a6268b8c33bf53cdcdc6610701b42a509c514dbd6f2530";

async fn old_ledger() -> TestDatabase {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .register(
            &env,
            "legacy-owner@example.test",
            "fixture-password-hash",
            None,
        )
        .await
        .expect("preexisting account");
    // Simulate the old recorded 0237 state without modifying a running database.
    // A real ordinary fresh chain could not reach it; compatibility nevertheless
    // preserves operators who previously worked around the broken view manually.
    sqlx::raw_sql(
        "DELETE FROM _schema_migrations WHERE version >= 243; \
         DROP VIEW environment_guardrails; \
         CREATE VIEW environment_guardrails AS \
           SELECT tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened, fips_profile \
           FROM environments WHERE tenant_id = current_setting('ironauth.tenant_id', true) \
           AND id = current_setting('ironauth.environment_id', true); \
         GRANT SELECT ON environment_guardrails TO ironauth_app, ironauth_control;",
    )
    .execute(db.owner_pool())
    .await
    .expect("owned historical fixture");
    sqlx::query("UPDATE _schema_migrations SET checksum = $1 WHERE version = 237")
        .bind(OLD_HASH)
        .execute(db.owner_pool())
        .await
        .expect("known old ledger");
    sqlx::query("UPDATE _schema_migrations SET checksum = $1 WHERE version = 242")
        .bind("59fa9390262ccdf8fa57542aa75f93d752a50be7e56bb816f558c371f5ef2121")
        .execute(db.owner_pool())
        .await
        .expect("published 0242 ledger");
    db
}

async fn view_identity(db: &TestDatabase) -> (String, Option<String>, Option<Vec<String>>) {
    sqlx::query_as("SELECT relowner::regrole::text, relacl::text, reloptions FROM pg_class WHERE oid = 'environment_guardrails'::regclass")
        .fetch_one(db.owner_pool()).await.expect("view owner/grants/options")
}

async fn data(db: &TestDatabase) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT value FROM ( \
         SELECT row_to_json(t)::text AS value FROM tenants t UNION ALL \
         SELECT row_to_json(e)::text FROM environments e UNION ALL \
         SELECT (to_jsonb(u) - 'recipient_email_bidx' - 'recipient_email_indexed')::text FROM users u \
         ) preserved ORDER BY value",
    ).fetch_all(db.owner_pool()).await.expect("retained account data")
}

#[tokio::test]
async fn corrected_fresh_chain_keeps_both_guardrail_columns_and_is_idempotent() {
    let db = TestDatabase::start().await;
    let names: Vec<String> = sqlx::query_scalar("SELECT attname::text FROM pg_attribute WHERE attrelid = 'environment_guardrails'::regclass AND attnum > 0 ORDER BY attnum")
        .fetch_all(db.owner_pool()).await.expect("columns");
    assert_eq!(
        names,
        [
            "tenant_id",
            "environment_id",
            "kind",
            "custom_domain",
            "auto_link_posture",
            "fapi_hardened",
            "fips_profile"
        ]
    );
    let report = MigrationRunner::new(db.owner_pool())
        .run()
        .await
        .expect("unchanged rerun");
    assert!(report.newly_applied().is_empty());
}

#[tokio::test]
async fn exact_old_checksum_upgrades_without_rewriting_ledger_data_view_grants_or_dependencies() {
    let db = old_ledger().await;
    // A dependent consumer remains valid because the repair appends a column; it
    // never drops/reorders existing columns and never uses CASCADE.
    sqlx::query(
        "CREATE VIEW owned_guardrail_consumer AS SELECT fapi_hardened FROM environment_guardrails",
    )
    .execute(db.owner_pool())
    .await
    .expect("existing dependent view");
    let before_view = view_identity(&db).await;
    let before_data = data(&db).await;
    let before_ledger: Vec<String> = sqlx::query_scalar(
        "SELECT row_to_json(m)::text FROM _schema_migrations m ORDER BY version",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("old ledger");
    let report = MigrationRunner::new(db.owner_pool())
        .run()
        .await
        .expect("known old checksum repair");
    assert_eq!(report.newly_applied(), [243, 244]);
    assert_eq!(before_view, view_identity(&db).await);
    assert_eq!(before_data, data(&db).await);
    let after_ledger: Vec<String> = sqlx::query_scalar("SELECT row_to_json(m)::text FROM _schema_migrations m WHERE version < 243 ORDER BY version")
        .fetch_all(db.owner_pool()).await.expect("preserved ledger");
    assert_eq!(
        before_ledger, after_ledger,
        "old checksums and timestamps are not rewritten"
    );
    sqlx::query("SELECT * FROM owned_guardrail_consumer")
        .fetch_all(db.owner_pool())
        .await
        .expect("dependent view intact");
    let report = MigrationRunner::new(db.owner_pool())
        .run()
        .await
        .expect("old-hash rerun remains idempotent");
    assert!(report.newly_applied().is_empty());
}

#[tokio::test]
async fn unknown_237_hash_and_other_historical_hashes_still_refuse() {
    for version in [237, 242, 62] {
        let db = old_ledger().await;
        sqlx::query(
            "UPDATE _schema_migrations SET checksum = 'unrecognized-checksum' WHERE version = $1",
        )
        .bind(version)
        .execute(db.owner_pool())
        .await
        .expect("adversarial ledger");
        assert!(
            matches!(MigrationRunner::new(db.owner_pool()).run().await, Err(MigrationError::ChecksumMismatch {version: actual}) if actual == version)
        );
        let later: i64 =
            sqlx::query_scalar("SELECT count(*) FROM _schema_migrations WHERE version >= 243")
                .fetch_one(db.owner_pool())
                .await
                .expect("no later migration");
        assert_eq!(later, 0);
    }
}

#[tokio::test]
async fn known_old_ledger_does_not_admit_another_edit_to_237_or_an_unexpected_view_definition() {
    let db = old_ledger().await;
    let mut altered = chain();
    let migration = altered
        .iter_mut()
        .find(|migration| migration.version == 237)
        .expect("0237");
    migration.sql = Box::leak(format!("{}\n-- another edit", migration.sql).into_boxed_str());
    assert!(matches!(
        MigrationRunner::from_migrations(db.owner_pool(), altered)
            .run()
            .await,
        Err(MigrationError::ChecksumMismatch { version: 237 })
    ));
    sqlx::query("CREATE OR REPLACE VIEW environment_guardrails AS SELECT tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened, fips_profile FROM environments WHERE false")
        .execute(db.owner_pool()).await.expect("unexpected security definition");
    let before = view_identity(&db).await;
    assert!(matches!(
        MigrationRunner::new(db.owner_pool()).run().await,
        Err(MigrationError::Database(_))
    ));
    assert_eq!(before, view_identity(&db).await);
    let applied: i64 =
        sqlx::query_scalar("SELECT count(*) FROM _schema_migrations WHERE version >= 243")
            .fetch_one(db.owner_pool())
            .await
            .expect("no partial forward migration");
    assert_eq!(applied, 0);
}

#[tokio::test]
async fn userinfo_metadata_grant_is_exactly_the_app_control_column() {
    let db = TestDatabase::start().await;
    for role in ["ironauth_app", "ironauth_control"] {
        let granted: bool = sqlx::query_scalar(
            "SELECT has_column_privilege($1, 'clients', 'userinfo_signed_response_alg', 'UPDATE')",
        )
        .bind(role)
        .fetch_one(db.owner_pool())
        .await
        .expect("metadata column grant");
        assert!(granted, "{role} retains metadata update");
    }
    let mut app = db.app_pool().begin().await.expect("application connection");
    sqlx::query("UPDATE clients SET userinfo_signed_response_alg = NULL WHERE false")
        .execute(&mut *app)
        .await
        .expect("actual app-role column update admitted");
    let denied = sqlx::query("UPDATE clients SET quarantined = quarantined WHERE false")
        .execute(&mut *app)
        .await;
    assert!(denied.is_err(), "quarantine remains control-plane only");
    app.rollback().await.expect("end app transaction");
    let mut limited = db.owner_pool().begin().await.expect("owned role fixture");
    sqlx::query("SET LOCAL ROLE ironauth_audit_retention")
        .execute(&mut *limited)
        .await
        .expect("limited role");
    assert!(
        sqlx::query("UPDATE clients SET userinfo_signed_response_alg = NULL WHERE false")
            .execute(&mut *limited)
            .await
            .is_err()
    );
    limited
        .rollback()
        .await
        .expect("end limited role transaction");
}

#[tokio::test]
async fn historical_237_without_fips_upgrades_through_corrected_242() {
    let db = old_ledger().await;
    sqlx::raw_sql(
        "DELETE FROM _schema_migrations WHERE version = 242;          DROP VIEW environment_guardrails;          ALTER TABLE environments DROP COLUMN fips_profile;          CREATE VIEW environment_guardrails AS            SELECT tenant_id, id AS environment_id, kind, custom_domain, fapi_hardened            FROM environments WHERE tenant_id = current_setting('ironauth.tenant_id', true)            AND id = current_setting('ironauth.environment_id', true);          GRANT SELECT ON environment_guardrails TO ironauth_app, ironauth_control;",
    ).execute(db.owner_pool()).await.expect("owned pre-FIPS fixture");
    let identity = view_identity(&db).await;
    let report = MigrationRunner::new(db.owner_pool())
        .run()
        .await
        .expect("FIPS upgrade");
    assert_eq!(report.newly_applied(), [242, 243, 244]);
    assert_eq!(identity, view_identity(&db).await);
    let names: Vec<String> = sqlx::query_scalar("SELECT attname::text FROM pg_attribute WHERE attrelid = 'environment_guardrails'::regclass AND attnum > 0 ORDER BY attnum")
        .fetch_all(db.owner_pool()).await.expect("retained view order");
    assert_eq!(
        names,
        [
            "tenant_id",
            "environment_id",
            "kind",
            "custom_domain",
            "fapi_hardened",
            "fips_profile",
            "auto_link_posture"
        ]
    );
    assert!(
        MigrationRunner::new(db.owner_pool())
            .run()
            .await
            .expect("replay")
            .newly_applied()
            .is_empty()
    );
}

#[tokio::test]
async fn published_242_checksum_does_not_admit_another_edit() {
    let db = old_ledger().await;
    let mut altered = chain();
    let migration = altered
        .iter_mut()
        .find(|migration| migration.version == 242)
        .expect("0242");
    migration.sql = Box::leak(format!("{}\n-- another edit", migration.sql).into_boxed_str());
    assert!(matches!(
        MigrationRunner::from_migrations(db.owner_pool(), altered)
            .run()
            .await,
        Err(MigrationError::ChecksumMismatch { version: 242 })
    ));
}
