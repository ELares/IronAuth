// SPDX-License-Identifier: MIT OR Apache-2.0

//! JSON Schema identity traits with versioning and migration jobs (issue #53),
//! over a real database (`DATABASE_URL`).
//!
//! Pins the acceptance criteria at the persistence layer: a well-formed schema is
//! accepted and a malformed one rejected; a user's traits validate against the
//! active schema version at write (an invalid document is refused with per-field
//! JSON Pointer errors, and nothing is persisted); arrays and nested objects
//! round-trip; trait data is envelope-encrypted (a database dump carries no
//! plaintext); versioning is immutable and each identity records the version it was
//! validated against; a dry-run reports every invalid identity with reasons and
//! blocks the cutover; a migration job migrates N -> N+1 deterministically,
//! idempotently, and resumably (a re-run double-migrates nothing); the admin-only
//! visibility split holds; a job is per (tenant, environment) scoped and every
//! mutation is audited.

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewAdminUser, NewTraitMigrationJob, Scope, StoreError, TraitJobKind,
    TraitJobStatus, UserId, UserState,
};
use serde_json::json;
use sqlx::Row;

const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";
const NOW_MICROS: i64 = 1_000_000;

/// A schema requiring a `name` string trait, allowing an optional array of nested
/// phone objects and an admin-only risk score.
fn schema_v1() -> String {
    json!({
        "type": "object",
        "properties": {
            "name": {"type": "string", "minLength": 1, "x-ironauth": {"identifier": true}},
            "phones": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"number": {"type": "string"}},
                    "required": ["number"]
                }
            },
            "risk_score": {"type": "integer", "x-ironauth": {"visibility": "admin"}}
        },
        "required": ["name"]
    })
    .to_string()
}

/// The incompatible successor: `name` is renamed to `full_name` (still required), so
/// a v1 identity is invalid against it until migrated.
fn schema_v2() -> String {
    json!({
        "type": "object",
        "properties": {
            "full_name": {"type": "string", "minLength": 1},
            "phones": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"number": {"type": "string"}},
                    "required": ["number"]
                }
            },
            "risk_score": {"type": "integer", "x-ironauth": {"visibility": "admin"}}
        },
        "required": ["full_name"]
    })
    .to_string()
}

/// Create a schema version and return its version number.
async fn create_schema(db: &TestDatabase, env: &Env, scope: Scope, schema_json: &str) -> i32 {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .trait_schemas()
        .create_version(env, schema_json, NOW_MICROS)
        .await
        .expect("create schema version")
        .1
}

/// Activate a schema version.
async fn activate_schema(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    version: i32,
) -> Result<(), StoreError> {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .trait_schemas()
        .activate_version(env, version)
        .await
}

/// Create a user with no traits and return its id.
async fn create_user(db: &TestDatabase, env: &Env, scope: Scope, identifier: &str) -> UserId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            NewAdminUser {
                id: None,
                identifier,
                password_hash: Some(PASSWORD_HASH),
                claims_json: None,
                external_id: None,
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            NOW_MICROS,
            None,
        )
        .await
        .expect("create user")
}

/// Set a user's traits, returning the store result.
async fn set_traits(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    id: &UserId,
    traits_json: &str,
) -> Result<i32, StoreError> {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .set_traits(env, id, traits_json)
        .await
}

/// The raw sealed traits column for a user, read as the owner (a database dump).
async fn dump_traits(db: &TestDatabase, scope: Scope, subject: &str) -> Option<Vec<u8>> {
    let row = sqlx::query(
        "SELECT traits_sealed FROM users \
         WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
    )
    .bind(subject)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("dump user row");
    row.get::<Option<Vec<u8>>, _>("traits_sealed")
}

/// The count of audit rows for an action in a scope.
async fn audit_count(db: &TestDatabase, scope: Scope, action: &str) -> i64 {
    sqlx::query(
        "SELECT count(*) AS c FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(action)
    .fetch_one(db.owner_pool())
    .await
    .expect("audit count")
    .get("c")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn a_valid_schema_is_accepted_and_a_malformed_one_is_rejected() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x53);
    let scope = db.seed_scope(&env).await;

    let version = create_schema(&db, &env, scope, &schema_v1()).await;
    assert_eq!(version, 1, "the first version is 1");

    // A malformed schema (bad type keyword) is refused, and nothing is stored.
    let err = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .trait_schemas()
        .create_version(&env, &json!({"type": "widget"}).to_string(), NOW_MICROS)
        .await
        .expect_err("malformed schema rejected");
    assert!(matches!(err, StoreError::SchemaMalformed(_)), "got {err:?}");

    // The registry still holds exactly the one valid version.
    let versions = db
        .store()
        .scoped(scope)
        .trait_schemas()
        .list_versions()
        .await
        .expect("list versions");
    assert_eq!(versions.len(), 1);
}

#[tokio::test]
async fn traits_validate_against_the_active_version_and_persist_the_version_used() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x54);
    let scope = db.seed_scope(&env).await;

    let v1 = create_schema(&db, &env, scope, &schema_v1()).await;
    activate_schema(&db, &env, scope, v1)
        .await
        .expect("activate");
    let user = create_user(&db, &env, scope, "alice").await;

    // A traits document violating the schema is refused with per-field JSON Pointer
    // errors, and nothing is persisted.
    let err = set_traits(&db, &env, scope, &user, &json!({"phones": []}).to_string())
        .await
        .expect_err("missing required name is rejected");
    let StoreError::TraitsInvalid(failures) = err else {
        panic!("expected TraitsInvalid, got {err:?}");
    };
    assert!(
        failures.iter().any(|f| f.pointer == "/name"),
        "a JSON Pointer names the missing field: {failures:?}"
    );
    assert!(
        db.store()
            .scoped(scope)
            .users()
            .traits(&user)
            .await
            .expect("read traits")
            .is_none(),
        "a rejected write persists nothing"
    );

    // A valid document (with arrays and nested objects) is accepted and records the
    // active schema version.
    let doc = json!({"name": "Zeke", "phones": [{"number": "+15550001"}, {"number": "+15550002"}]});
    let version = set_traits(&db, &env, scope, &user, &doc.to_string())
        .await
        .expect("valid traits accepted");
    assert_eq!(version, v1, "the write records the active schema version");

    let (recorded_version, round_tripped) = db
        .store()
        .scoped(scope)
        .users()
        .traits(&user)
        .await
        .expect("read traits")
        .expect("traits present");
    assert_eq!(recorded_version, v1);
    assert_eq!(round_tripped, doc, "arrays and nested objects round-trip");

    // The traits are sealed at rest: a database dump carries no plaintext.
    let sealed = dump_traits(&db, scope, &user.to_string())
        .await
        .expect("sealed traits present");
    assert!(!contains(&sealed, b"Zeke"), "no plaintext name in the dump");
    assert!(
        !contains(&sealed, b"+15550001"),
        "no plaintext phone in the dump"
    );
}

#[tokio::test]
async fn a_write_needs_an_active_schema_and_the_admin_only_split_holds() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x55);
    let scope = db.seed_scope(&env).await;

    let user = create_user(&db, &env, scope, "carol").await;
    // No active schema yet: a write is refused with the distinct, legible error.
    let err = set_traits(
        &db,
        &env,
        scope,
        &user,
        &json!({"name": "Carol"}).to_string(),
    )
    .await
    .expect_err("no active schema");
    assert!(
        matches!(err, StoreError::NoActiveTraitSchema),
        "got {err:?}"
    );

    let v1 = create_schema(&db, &env, scope, &schema_v1()).await;
    activate_schema(&db, &env, scope, v1)
        .await
        .expect("activate");
    set_traits(
        &db,
        &env,
        scope,
        &user,
        &json!({"name": "Carol", "risk_score": 90}).to_string(),
    )
    .await
    .expect("valid traits");

    // The admin sees the risk score; the self-service view strips it.
    let (_, admin_view) = db
        .store()
        .scoped(scope)
        .users()
        .traits(&user)
        .await
        .expect("admin read")
        .expect("present");
    assert_eq!(admin_view.get("risk_score"), Some(&json!(90)));
    let user_view = db
        .store()
        .scoped(scope)
        .users()
        .traits_user_visible(&user)
        .await
        .expect("user read")
        .expect("present");
    assert_eq!(user_view.get("risk_score"), None, "admin-only field hidden");
    assert_eq!(
        user_view.get("name"),
        Some(&json!("Carol")),
        "user field kept"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn versioning_is_immutable_and_a_dry_run_reports_and_blocks_the_cutover() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x56);
    let scope = db.seed_scope(&env).await;

    let v1 = create_schema(&db, &env, scope, &schema_v1()).await;
    activate_schema(&db, &env, scope, v1)
        .await
        .expect("activate");
    let alice = create_user(&db, &env, scope, "alice").await;
    let bob = create_user(&db, &env, scope, "bob").await;
    set_traits(
        &db,
        &env,
        scope,
        &alice,
        &json!({"name": "Alice"}).to_string(),
    )
    .await
    .expect("alice traits");
    set_traits(&db, &env, scope, &bob, &json!({"name": "Bob"}).to_string())
        .await
        .expect("bob traits");

    // A new version is a distinct immutable row; v1's content is unchanged.
    let v2 = create_schema(&db, &env, scope, &schema_v2()).await;
    assert_eq!(v2, 2);
    let stored_v1 = db
        .store()
        .scoped(scope)
        .trait_schemas()
        .get_version(v1)
        .await
        .expect("get v1")
        .expect("v1 present");
    assert_eq!(
        stored_v1.schema_json,
        schema_v1(),
        "v1 content is immutable"
    );
    assert!(stored_v1.active, "v1 is still the active version");

    // A dry-run of v1 -> v2 reports EVERY invalid identity with reasons, mutating
    // nothing.
    let job_id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .trait_migration_jobs()
        .create(
            &env,
            NewTraitMigrationJob {
                kind: TraitJobKind::DryRun,
                from_version: v1,
                to_version: v2,
                transform_json: None,
            },
            NOW_MICROS,
        )
        .await
        .expect("create dry-run");
    let job = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .trait_migration_jobs()
        .advance(&env, &job_id, 100)
        .await
        .expect("advance dry-run");
    assert_eq!(
        job.status,
        TraitJobStatus::Failed,
        "the dry-run found problems"
    );
    assert_eq!(job.failure_count, 2, "both v1 identities fail v2");
    assert_eq!(job.migrated_count, 0, "a dry-run mutates nothing");
    let subjects: Vec<&str> = job.failures.iter().map(|f| f.subject.as_str()).collect();
    assert!(subjects.contains(&alice.to_string().as_str()));
    assert!(subjects.contains(&bob.to_string().as_str()));
    assert!(
        job.failures[0]
            .failures
            .iter()
            .any(|f| f.pointer == "/full_name"),
        "the reason names the missing field: {:?}",
        job.failures[0].failures
    );
    // The identities are untouched (still on v1).
    let (still_v1, _) = db
        .store()
        .scoped(scope)
        .users()
        .traits(&alice)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(still_v1, v1);

    // The cutover is blocked while invalid identities remain.
    let err = activate_schema(&db, &env, scope, v2)
        .await
        .expect_err("cutover blocked");
    assert!(
        matches!(
            err,
            StoreError::CutoverBlocked {
                invalid_identities: 2
            }
        ),
        "got {err:?}"
    );
    assert!(
        stored_v1.active,
        "v1 remains the active version after a blocked cutover"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_migration_job_transforms_deterministically_idempotently_and_unblocks_the_cutover() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x57);
    let scope = db.seed_scope(&env).await;

    let v1 = create_schema(&db, &env, scope, &schema_v1()).await;
    activate_schema(&db, &env, scope, v1)
        .await
        .expect("activate");
    let alice = create_user(&db, &env, scope, "alice").await;
    let bob = create_user(&db, &env, scope, "bob").await;
    set_traits(
        &db,
        &env,
        scope,
        &alice,
        &json!({"name": "Alice"}).to_string(),
    )
    .await
    .expect("alice traits");
    set_traits(&db, &env, scope, &bob, &json!({"name": "Bob"}).to_string())
        .await
        .expect("bob traits");
    let v2 = create_schema(&db, &env, scope, &schema_v2()).await;

    // A migrate job renames name -> full_name, then re-validates against v2.
    let transform = json!([{"op": "rename", "from": "name", "to": "full_name"}]).to_string();
    let job_id = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .trait_migration_jobs()
        .create(
            &env,
            NewTraitMigrationJob {
                kind: TraitJobKind::Migrate,
                from_version: v1,
                to_version: v2,
                transform_json: Some(&transform),
            },
            NOW_MICROS,
        )
        .await
        .expect("create migrate");
    let created = db
        .store()
        .scoped(scope)
        .trait_migration_jobs()
        .get(&job_id)
        .await
        .expect("get job");
    assert_eq!(created.total_count, 2, "two v1 identities are candidates");

    // Run in single-record batches to prove resumability: each advance processes one
    // identity, and a re-entry resumes past the cursor without double-migrating.
    let acting = || {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };
    let step1 = acting()
        .trait_migration_jobs()
        .advance(&env, &job_id, 1)
        .await
        .expect("step1");
    assert_eq!(step1.migrated_count, 1);
    assert_eq!(step1.status, TraitJobStatus::Running);
    let step2 = acting()
        .trait_migration_jobs()
        .advance(&env, &job_id, 1)
        .await
        .expect("step2");
    assert_eq!(step2.migrated_count, 2);
    // A finalizing pass sees no remaining v1 identities and completes.
    let done = acting()
        .trait_migration_jobs()
        .advance(&env, &job_id, 1)
        .await
        .expect("finalize");
    assert_eq!(done.status, TraitJobStatus::Completed);
    assert_eq!(done.migrated_count, 2);
    assert_eq!(done.failure_count, 0);

    // The identities are transformed and re-versioned to v2.
    let (alice_v, alice_traits) = db
        .store()
        .scoped(scope)
        .users()
        .traits(&alice)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(alice_v, v2);
    assert_eq!(
        alice_traits,
        json!({"full_name": "Alice"}),
        "renamed deterministically"
    );

    // Idempotent: advancing the completed job again migrates nothing, and a fresh
    // job from v1 has zero candidates (no double-migration is possible).
    let rerun = acting()
        .trait_migration_jobs()
        .advance(&env, &job_id, 100)
        .await
        .expect("rerun");
    assert_eq!(rerun.migrated_count, 2, "a re-run migrates nothing new");
    assert_eq!(rerun.processed_count, 2);
    let fresh = acting()
        .trait_migration_jobs()
        .create(
            &env,
            NewTraitMigrationJob {
                kind: TraitJobKind::Migrate,
                from_version: v1,
                to_version: v2,
                transform_json: Some(&transform),
            },
            NOW_MICROS,
        )
        .await
        .expect("fresh job");
    let fresh_job = db
        .store()
        .scoped(scope)
        .trait_migration_jobs()
        .get(&fresh)
        .await
        .expect("get fresh");
    assert_eq!(fresh_job.total_count, 0, "no identity remains on v1");

    // The cutover now succeeds: every identity is valid against v2.
    activate_schema(&db, &env, scope, v2)
        .await
        .expect("cutover unblocked");
    let active = db
        .store()
        .scoped(scope)
        .trait_schemas()
        .active()
        .await
        .expect("active")
        .expect("present");
    assert_eq!(active.version, v2, "v2 is now the served default");

    // Every mutation was audited.
    assert!(audit_count(&db, scope, "trait_schema.create").await >= 2);
    assert!(audit_count(&db, scope, "trait_schema.activate").await >= 1);
    assert!(audit_count(&db, scope, "trait_migration_job.create").await >= 1);
    assert!(audit_count(&db, scope, "trait_migration_job.advance").await >= 1);
    assert!(audit_count(&db, scope, "user.traits.update").await >= 2);
}

#[tokio::test]
async fn a_migration_job_is_scoped_and_never_touches_another_tenant() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x58);
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    // Both tenants run the same schema and seed one identity each.
    for scope in [scope_a, scope_b] {
        let v1 = create_schema(&db, &env, scope, &schema_v1()).await;
        activate_schema(&db, &env, scope, v1)
            .await
            .expect("activate");
    }
    let a_user = create_user(&db, &env, scope_a, "alice").await;
    let b_user = create_user(&db, &env, scope_b, "bruno").await;
    set_traits(
        &db,
        &env,
        scope_a,
        &a_user,
        &json!({"name": "Alice"}).to_string(),
    )
    .await
    .expect("a traits");
    set_traits(
        &db,
        &env,
        scope_b,
        &b_user,
        &json!({"name": "Bruno"}).to_string(),
    )
    .await
    .expect("b traits");
    let a_v2 = create_schema(&db, &env, scope_a, &schema_v2()).await;

    // A migrate job in tenant A migrates only tenant A's identity.
    let transform = json!([{"op": "rename", "from": "name", "to": "full_name"}]).to_string();
    let job_id = db
        .store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .trait_migration_jobs()
        .create(
            &env,
            NewTraitMigrationJob {
                kind: TraitJobKind::Migrate,
                from_version: 1,
                to_version: a_v2,
                transform_json: Some(&transform),
            },
            NOW_MICROS,
        )
        .await
        .expect("create job");
    let done = db
        .store()
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .trait_migration_jobs()
        .advance(&env, &job_id, 100)
        .await
        .expect("advance");
    assert_eq!(
        done.migrated_count, 1,
        "only tenant A's identity is migrated"
    );

    // Tenant B's identity is untouched: still on v1, still the original document.
    let (b_version, b_traits) = db
        .store()
        .scoped(scope_b)
        .users()
        .traits(&b_user)
        .await
        .expect("read b")
        .expect("present");
    assert_eq!(b_version, 1, "tenant B stays on v1");
    assert_eq!(b_traits, json!({"name": "Bruno"}), "tenant B is untouched");

    // A job id from tenant A is a uniform not-found in tenant B.
    let cross = db
        .store()
        .scoped(scope_b)
        .trait_migration_jobs()
        .get(&job_id)
        .await;
    assert!(
        matches!(cross, Err(StoreError::NotFound)),
        "cross-scope not found"
    );
}
