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
    CorrelationId, NewAdminUser, NewTraitMigrationJob, NewUserTraits, Scope, StoreError,
    TraitJobKind, TraitJobStatus, TraitMigrationStart, TraitWriteVisibility, UserId, UserState,
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
                traits: None,
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
    assert_eq!(recorded_version, Some(v1));
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
            // These tests drive `advance` by hand, so the first batch message this write
            // also enqueues is never claimed. It is still written, which is the point:
            // the create is ONE transaction covering the job row and its first batch.
            TraitMigrationStart {
                first_batch_payload: &serde_json::json!({}),
                idempotency: None,
            },
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
    assert_eq!(still_v1, Some(v1));

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
            // These tests drive `advance` by hand, so the first batch message this write
            // also enqueues is never claimed. It is still written, which is the point:
            // the create is ONE transaction covering the job row and its first batch.
            TraitMigrationStart {
                first_batch_payload: &serde_json::json!({}),
                idempotency: None,
            },
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
    assert_eq!(alice_v, Some(v2));
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
            // These tests drive `advance` by hand, so the first batch message this write
            // also enqueues is never claimed. It is still written, which is the point:
            // the create is ONE transaction covering the job row and its first batch.
            TraitMigrationStart {
                first_batch_payload: &serde_json::json!({}),
                idempotency: None,
            },
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
            // These tests drive `advance` by hand, so the first batch message this write
            // also enqueues is never claimed. It is still written, which is the point:
            // the create is ONE transaction covering the job row and its first batch.
            TraitMigrationStart {
                first_batch_payload: &serde_json::json!({}),
                idempotency: None,
            },
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
    assert_eq!(b_version, Some(1), "tenant B stays on v1");
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

// ---------------------------------------------------------------------------
// The seam properties issue #53 PR 1 added: the visibility class on EVERY write
// path, the non-object shape, the cutover's concurrency, and the append-only
// registry's typed conflict.
// ---------------------------------------------------------------------------

/// A schema whose ONLY assertion is on `name`, with an admin-only `risk_score` and NO root
/// `type`. Nothing in the codebase requires a schema to assert a root `type`, and that is
/// exactly what makes the non-object submission below reach the write.
fn schema_no_root_type() -> String {
    json!({
        "properties": {
            "name": {"type": "string"},
            "risk_score": {"type": "integer", "x-ironauth": {"visibility": "admin"}}
        }
    })
    .to_string()
}

/// Create a user CARRYING traits under an explicit visibility class, returning the store
/// result so a refusal is observable.
async fn create_user_with_classed_traits(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    identifier: &str,
    traits_json: &str,
    schema_version: Option<i32>,
    visibility: TraitWriteVisibility,
) -> Result<UserId, StoreError> {
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
                traits: Some(NewUserTraits {
                    traits_json,
                    schema_version,
                    visibility,
                }),
            },
            NOW_MICROS,
            None,
        )
        .await
}

/// Set traits under an explicit visibility class.
async fn set_traits_classed(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    id: &UserId,
    traits_json: &str,
    visibility: TraitWriteVisibility,
) -> Result<i32, StoreError> {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .set_traits_with_visibility(env, id, traits_json, visibility, None)
        .await
}

/// The CREATE path carries the visibility class too, and a SELF-SERVICE create naming an
/// admin-only trait writes NOTHING.
///
/// This is the bypass the class was claimed to close and did not: `insert_admin_user_row`
/// is a second SQL site persisting `traits_sealed`, reached by `admin_create` (the FIRST
/// federated login is one of its callers) and by the joined invitation create, and it seals
/// VERBATIM. Without the class on the create, an upstream identity provider whose claim
/// mapping named an admin-only trait wrote it on first login and was refused only on the
/// second, which is both a bypass and a self-inflicted 500 on the returning login.
#[tokio::test]
async fn a_self_service_create_naming_an_admin_only_trait_writes_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let v1 = create_schema(&db, &env, scope, &schema_v1()).await;
    activate_schema(&db, &env, scope, v1)
        .await
        .expect("activate v1");

    // The ADMIN class is precisely where admin-only metadata is written, so the SAME
    // document must succeed there. Without this half the test would pass for a create that
    // refused everything.
    let admin_id = create_user_with_classed_traits(
        &db,
        &env,
        scope,
        "operator-created@example.test",
        r#"{"name":"ada","risk_score":90}"#,
        Some(v1),
        TraitWriteVisibility::Admin,
    )
    .await
    .expect("an ADMIN create may write admin-only metadata");
    let (_, stored) = db
        .store()
        .scoped(scope)
        .users()
        .traits(&admin_id)
        .await
        .expect("read")
        .expect("traits");
    assert_eq!(stored["risk_score"], json!(90));

    // The SELF-SERVICE class refuses the same document, per field, with its pointer.
    let refused = create_user_with_classed_traits(
        &db,
        &env,
        scope,
        "upstream-created@example.test",
        r#"{"name":"mallory","risk_score":0}"#,
        Some(v1),
        TraitWriteVisibility::SelfService,
    )
    .await
    .expect_err("a self-service create naming an admin-only trait must be refused");
    let StoreError::TraitsInvalid(failures) = refused else {
        panic!("expected a per-field refusal, got {refused:?}");
    };
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(failures[0].pointer, "/risk_score");

    // NOTHING was created: not the user, and not its `user.create` audit row. The refusal
    // runs before the create's transaction opens, so there is no partial state at all.
    let remaining: i64 =
        sqlx::query("SELECT count(*) AS c FROM users WHERE tenant_id = $1 AND environment_id = $2")
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("count users")
            .get("c");
    assert_eq!(remaining, 1, "only the ADMIN create landed");
    assert_eq!(
        audit_count(&db, scope, "user.create").await,
        1,
        "the refused create left no audit row either"
    );

    // A self-service create that names NO admin-only trait is allowed, so the class refuses
    // the field and not the surface.
    create_user_with_classed_traits(
        &db,
        &env,
        scope,
        "upstream-ok@example.test",
        r#"{"name":"grace"}"#,
        Some(v1),
        TraitWriteVisibility::SelfService,
    )
    .await
    .expect("a self-service create of user-visible traits is allowed");
}

/// A NON-OBJECT self-service submission cannot clear admin-only metadata by replacement.
///
/// The "cannot clear" half is implemented by carrying the existing admin-only members onto
/// the submission, and a non-object has no members to carry onto, so on its own it walks
/// straight past both halves: it names no top-level field (no violation), it survives
/// preservation unchanged, and it replaces the whole document. The doc claimed "the schema's
/// own `type` assertion is what refuses it"; nothing requires a schema to CARRY a root
/// `type`, and with one that does not, MEASURED, `[1, 2]` produced zero violations and the
/// write proceeded.
#[tokio::test]
async fn a_non_object_self_service_submission_cannot_clear_admin_only_metadata() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let v1 = create_schema(&db, &env, scope, &schema_no_root_type()).await;
    activate_schema(&db, &env, scope, v1)
        .await
        .expect("activate v1");
    let id = create_user(&db, &env, scope, "ada@example.test").await;
    set_traits(&db, &env, scope, &id, r#"{"name":"ada","risk_score":90}"#)
        .await
        .expect("admin write");

    // The premise the defect rests on, asserted rather than assumed: this schema really
    // does accept a non-object, so the refusal below cannot be the schema's doing.
    let compiled = ironauth_store::TraitSchema::compile(&schema_no_root_type()).expect("compile");
    assert!(
        compiled.validate(&json!([1, 2])).is_empty(),
        "the fixture schema accepts a non-object, which is what makes this reachable"
    );

    let refused = set_traits_classed(
        &db,
        &env,
        scope,
        &id,
        "[1,2]",
        TraitWriteVisibility::SelfService,
    )
    .await
    .expect_err("a non-object self-service replacement must be refused");
    let StoreError::TraitsInvalid(failures) = refused else {
        panic!("expected a refusal, got {refused:?}");
    };
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(
        failures[0].pointer, "",
        "the failure points at the document ROOT, which is what is wrong"
    );

    // The stored document is untouched: both the user field and the admin-only one.
    let (_, stored) = db
        .store()
        .scoped(scope)
        .users()
        .traits(&id)
        .await
        .expect("read")
        .expect("traits");
    assert_eq!(stored, json!({"name":"ada","risk_score":90}));

    // The ADMIN class is NOT constrained by this: the management plane owns the document,
    // so it may replace it with whatever the schema accepts.
    set_traits_classed(&db, &env, scope, &id, "[1,2]", TraitWriteVisibility::Admin)
        .await
        .expect("the admin class may write any schema-valid document");
}

/// The append-only registry's typed [`StoreError::Conflict`] on a concurrently-taken
/// version, driven rather than documented.
///
/// `create_version` allocates its version number in its OWN transaction now, because the
/// management surface has to know the id and version BEFORE the write in order to store the
/// response it will return under the Idempotency-Key in the same transaction as the version.
/// That widens the window in which two creates compute the same next version, which is
/// exactly why the unique index's refusal has to be a typed `Conflict` the surface renders
/// as a 409 rather than a bare database error, and exactly why that arm must be DRIVEN: the
/// 409 was documented in the OpenAPI responses with nothing reaching it.
///
/// Driven through `create_version_at` with an explicit, already-taken version rather than by
/// racing two `create_version` calls: the collision is then deterministic instead of
/// timing-dependent, and it is the SAME code path (the same INSERT against the same index),
/// so nothing about the arm is simulated.
#[tokio::test]
async fn a_version_already_taken_is_a_typed_conflict_not_a_database_error() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let v1 = create_schema(&db, &env, scope, &schema_v1()).await;
    assert_eq!(v1, 1);

    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let id = ironauth_store::TraitSchemaId::generate(&env, &scope);
    let conflict = acting
        .trait_schemas()
        .create_version_at(&env, &id, &schema_v2(), v1, NOW_MICROS, None)
        .await
        .expect_err("version 1 is already taken");
    assert!(
        matches!(conflict, StoreError::Conflict),
        "a taken version is the typed Conflict the surface renders as a 409, not an \
         undifferentiated database error: {conflict:?}"
    );

    // Nothing was appended, and no audit row was written for the refused create: the
    // collision rolls the whole audited transaction back.
    assert_eq!(
        db.store()
            .scoped(scope)
            .trait_schemas()
            .list_versions()
            .await
            .expect("list")
            .len(),
        1,
        "the refused create appended nothing"
    );
    assert_eq!(
        audit_count(&db, scope, "trait_schema.create").await,
        1,
        "only the successful create is audited"
    );

    // The NEXT version is still free, so a caller that re-plans against the now-higher
    // next version succeeds. That is what makes the 409 actionable rather than terminal.
    let next = db
        .store()
        .scoped(scope)
        .trait_schemas()
        .next_version()
        .await
        .expect("next version");
    assert_eq!(next, 2);
    let id2 = ironauth_store::TraitSchemaId::generate(&env, &scope);
    acting
        .trait_schemas()
        .create_version_at(&env, &id2, &schema_v2(), next, NOW_MICROS, None)
        .await
        .expect("re-planning against the next version succeeds");
}

/// The cutover schema pair for the concurrency probe: v2 additionally REQUIRES `motto`, so a
/// document without one is valid under v1 and invalid under v2.
fn cutover_v1() -> String {
    json!({
        "type": "object",
        "properties": {"name": {"type": "string"}, "motto": {"type": "string"}},
        "required": ["name"]
    })
    .to_string()
}

fn cutover_v2() -> String {
    json!({
        "type": "object",
        "properties": {"name": {"type": "string"}, "motto": {"type": "string"}},
        "required": ["name", "motto"]
    })
    .to_string()
}

/// How many identities the concurrency probe seeds. The activation's live scan runs INSIDE
/// the activation transaction, so the population is what gives the racing write a window to
/// land in; MEASURED, at zero delay and a population of this order the unlocked cutover
/// admits the write and activates anyway.
const RACE_POPULATION: usize = 200;

/// How many times the probe replays the race. One round can be lost to scheduling; the
/// invariant is asserted every round, so a single admitted straddle in any round fails.
const RACE_ROUNDS: usize = 3;

/// A trait write CANNOT straddle a cutover: at the instant the pointer moves, every stored
/// identity satisfies the newly active schema.
///
/// The gate was a MEASURED TOCTOU. `begin_scoped` pins READ COMMITTED,
/// `count_identities_failing_schema` is a plain `SELECT` with no `FOR SHARE`, and a trait
/// write read the active pointer in a transaction of its OWN and then committed in another,
/// so a write that validated against the still-active OLD schema landed inside the
/// activation's window: `write_ok=true activate_ok=true` with version 2 active while an
/// identity held a value that fails it. A 150 ms delay between the two does not race at all,
/// which is exactly why the shipped sequential test could not see it and why this one has to
/// start both sides with no delay.
///
/// The assertion is an EXCLUSIVE OR rather than a state check, because both orderings are
/// legitimate and each refuses one side: if the write commits first the scan sees it and the
/// activation is `CutoverBlocked`; if the activation commits first the write re-reads the
/// new pointer and is `TraitsInvalid`. Both succeeding is the defect, and both failing would
/// mean something else broke.
// One test rather than several: the sequential CONTROL and the concurrent rounds have to
// run against the SAME seeded population, or the control proves nothing about the rounds.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_trait_write_cannot_straddle_a_cutover() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let v1 = create_schema(&db, &env, scope, &cutover_v1()).await;
    activate_schema(&db, &env, scope, v1)
        .await
        .expect("activate v1");

    // A population that all satisfies v2, so the ONLY thing that can block the cutover is
    // the racing write itself.
    for n in 0..RACE_POPULATION {
        create_user_with_classed_traits(
            &db,
            &env,
            scope,
            &format!("filler-{n}@example.test"),
            r#"{"name":"filler","motto":"steady"}"#,
            Some(v1),
            TraitWriteVisibility::Admin,
        )
        .await
        .expect("seed filler identity");
    }

    // The CONTROL, and it runs first so a failure here means the fixture is wrong rather
    // than the lock: performed SEQUENTIALLY, the write after an activation is refused by the
    // new schema, and the write before one blocks the activation. Neither can be mistaken
    // for the concurrent case, and both must hold for the concurrent assertion to mean
    // anything.
    let control = create_user_with_classed_traits(
        &db,
        &env,
        scope,
        "control@example.test",
        r#"{"name":"control","motto":"steady"}"#,
        Some(v1),
        TraitWriteVisibility::Admin,
    )
    .await
    .expect("seed control identity");
    let control_v2 = create_schema(&db, &env, scope, &cutover_v2()).await;
    assert!(
        set_traits(&db, &env, scope, &control, r#"{"name":"control"}"#)
            .await
            .is_ok(),
        "before the cutover the motto-less document is valid under v1"
    );
    let blocked = activate_schema(&db, &env, scope, control_v2)
        .await
        .expect_err("the sequential write blocks the sequential cutover");
    assert!(
        matches!(blocked, StoreError::CutoverBlocked { .. }),
        "{blocked:?}"
    );
    set_traits(
        &db,
        &env,
        scope,
        &control,
        r#"{"name":"control","motto":"x"}"#,
    )
    .await
    .expect("restore the control identity");
    activate_schema(&db, &env, scope, control_v2)
        .await
        .expect("the cutover proceeds once nothing blocks it");
    // Put the scope back on a v1-shaped contract for the concurrent rounds by appending a
    // fresh permissive version and activating it.
    let back = create_schema(&db, &env, scope, &cutover_v1()).await;
    activate_schema(&db, &env, scope, back)
        .await
        .expect("back to the permissive contract");

    for round in 0..RACE_ROUNDS {
        let racer = create_user_with_classed_traits(
            &db,
            &env,
            scope,
            &format!("racer-{round}@example.test"),
            r#"{"name":"racer","motto":"steady"}"#,
            Some(back),
            TraitWriteVisibility::Admin,
        )
        .await
        .expect("seed racer identity");
        let target = create_schema(&db, &env, scope, &cutover_v2()).await;

        let writing = {
            let store = db.store().clone();
            tokio::spawn(async move {
                let env = Env::system();
                store
                    .scoped(scope)
                    .acting(
                        ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(
                            &env,
                        )),
                        CorrelationId::generate(&env),
                    )
                    .users()
                    // The motto is DROPPED: valid under the permissive version, invalid
                    // under the one being activated.
                    .set_traits(&env, &racer, r#"{"name":"racer"}"#)
                    .await
            })
        };
        let activating = {
            let store = db.store().clone();
            tokio::spawn(async move {
                let env = Env::system();
                store
                    .scoped(scope)
                    .acting(
                        ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(
                            &env,
                        )),
                        CorrelationId::generate(&env),
                    )
                    .trait_schemas()
                    .activate_version(&env, target)
                    .await
            })
        };
        let write_ok = writing.await.expect("the write task panicked").is_ok();
        let activate_ok = activating
            .await
            .expect("the activate task panicked")
            .is_ok();

        assert!(
            write_ok != activate_ok,
            "round {round}: exactly one of the two must be refused \
             (write_ok={write_ok} activate_ok={activate_ok}); both succeeding is the \
             straddle, where a version goes active while an identity fails it"
        );

        // The invariant stated directly, on the stored state rather than on the outcomes:
        // whenever the target version is the served default, the racer satisfies it.
        let active = db
            .store()
            .scoped(scope)
            .trait_schemas()
            .active()
            .await
            .expect("read active")
            .expect("an active version");
        if active.version == target {
            let (_, stored) = db
                .store()
                .scoped(scope)
                .users()
                .traits(&racer)
                .await
                .expect("read")
                .expect("traits");
            assert!(
                stored.get("motto").is_some(),
                "round {round}: version {target} is active while the racer holds a document \
                 that fails it: {stored}"
            );
            // Put the scope back on the permissive contract for the next round.
            let back = create_schema(&db, &env, scope, &cutover_v1()).await;
            activate_schema(&db, &env, scope, back)
                .await
                .expect("back to the permissive contract");
        }
        // Whichever way the round went, leave the racer satisfying every version so it
        // cannot block a later round.
        set_traits(
            &db,
            &env,
            scope,
            &racer,
            r#"{"name":"racer","motto":"steady"}"#,
        )
        .await
        .expect("restore the racer");
    }
}

/// Claim the one webhook event outstanding in `scope`, completing it so the ordering key is
/// released for the next.
async fn claim_one_event(db: &TestDatabase, env: &Env, scope: Scope) -> serde_json::Value {
    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            env,
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1, "expected exactly one queued event");
    for message in &claimed {
        db.store()
            .scoped(scope)
            .outbox()
            .complete(env, message)
            .await
            .expect("complete");
    }
    claimed.into_iter().next().expect("one message").payload
}

/// Registering a schema version and ACTIVATING it emit distinct types.
///
/// The distinction is the point: creating a version changes nothing a user can observe,
/// whereas ACTIVATING it changes how every trait in the environment is validated from that
/// moment. A consumer that treated the two alike would apply a schema before it was in force.
///
/// Neither event carries the schema BODY. The registry is the source of truth for the shape
/// and refetching it is one call; putting it on every event would make the payload unbounded
/// and duplicate a document that can already be read.
#[tokio::test]
async fn registering_and_activating_a_schema_version_emit_distinct_types() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = ironauth_store::TraitSchemaId::generate(&env, &scope);
    let subject = scope.environment().to_string();

    let created = ironauth_store::event_catalog::envelope(
        "evt_schema_created",
        "trait_schema.version_created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({ "version": 7 }),
    )
    .expect("trait_schema.version_created is registered");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .trait_schemas()
        .create_version_at_with_event(
            &env,
            &id,
            &schema_v2(),
            7,
            NOW_MICROS,
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_schema_created",
                subject: &subject,
                envelope: &created,
            }),
        )
        .await
        .expect("register version");

    let first = claim_one_event(&db, &env, scope).await;
    assert_eq!(first["type"], "trait_schema.version_created");
    assert_eq!(first["payload"]["version"], 7);
    ironauth_store::event_catalog::validate_event(&first)
        .expect("the envelope validates against the registry the fan-out enforces");
    assert!(
        !first.to_string().contains("properties"),
        "the event carried the schema BODY: {first}"
    );

    let activated = ironauth_store::event_catalog::envelope(
        "evt_schema_activated",
        "trait_schema.version_activated",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        2,
        &serde_json::json!({ "version": 7 }),
    )
    .expect("trait_schema.version_activated is registered");

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .trait_schemas()
        .activate_version_idempotent_with_event(
            &env,
            7,
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_schema_activated",
                subject: &subject,
                envelope: &activated,
            }),
        )
        .await
        .expect("activate version");

    let second = claim_one_event(&db, &env, scope).await;
    assert_eq!(
        second["type"], "trait_schema.version_activated",
        "an activation must NOT be announced as a registration: one changes nothing a user \
         can observe, the other changes how every trait is validated"
    );
    ironauth_store::event_catalog::validate_event(&second)
        .expect("the envelope validates against the registry the fan-out enforces");
}

#[tokio::test]
async fn traits_imported_without_a_schema_version_read_back_rather_than_panicking() {
    // `traits_schema_version` is NULLABLE (migration 0038 adds it with no NOT NULL) and the
    // write path allows it: `NewUserTraits::schema_version` is documented as `None` when the
    // source recorded none, which is what importing a user who carries traits from a system
    // with no schema registry produces. `admin_create` validates nothing and stores it
    // verbatim, so such a row is reachable through a supported surface, not only by hand.
    //
    // Reading it back used to decode the column as a bare `i32` and PANIC. The only other
    // place the repository decodes this column, the export projection feeding
    // `UserExportRecord`, already used `Option<i32>`; this was the outlier.
    //
    // A panic is worse than an error even where it is contained. The async flow-target
    // consumer reads traits on every delivery (issue #954), and the outbox catches a consumer
    // panic, records the retryable `consumer_panic`, and survives, so the worker does not
    // die. What it costs is that such an identity's delivery retries to the attempts cap and
    // dead-letters on a fault the read could have reported outright.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x53);
    let scope = db.seed_scope(&env).await;
    let doc = json!({"imported": true, "source": "legacy"});

    let user = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .admin_create(
            &env,
            NewAdminUser {
                id: None,
                identifier: "imported@example.test",
                password_hash: Some(PASSWORD_HASH),
                claims_json: None,
                external_id: None,
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits: Some(NewUserTraits {
                    traits_json: &doc.to_string(),
                    // The whole point of the fixture.
                    schema_version: None,
                    visibility: TraitWriteVisibility::Admin,
                }),
            },
            NOW_MICROS,
            None,
        )
        .await
        .expect("import a user carrying traits but no schema version");

    let (version, round_tripped) = db
        .store()
        .scoped(scope)
        .users()
        .traits(&user)
        .await
        .expect("the read succeeds instead of panicking")
        .expect("the traits are present");
    assert_eq!(
        version, None,
        "no version is recorded, and that is reported rather than invented"
    );
    assert_eq!(
        round_tripped, doc,
        "and the document itself is intact: the missing version is the only thing missing"
    );
}

#[tokio::test]
async fn an_active_schema_that_no_longer_compiles_refuses_the_redaction_rather_than_disclosing() {
    // The user-visible projection FAILS CLOSED when the active schema will not compile.
    //
    // This branch is reachable without anyone doing anything wrong. A stored schema is CHECKED
    // for well-formedness when it is written and again when it is activated, and nothing
    // re-checks it after that, while `check_schema_wellformed` has been tightened since: it now
    // refuses `x-ironauth` anywhere BELOW a top-level property (the document root stays
    // annotatable on purpose, so a lone sub-schema can be compiled on its own). A row activated
    // under the looser checker stays active, because activation is the only writer of `status`
    // and the table carries no DELETE grant, and it stops compiling. Readers compile it on
    // every use, which is how they meet it. The fixture reproduces that end state by writing
    // the row directly, which is the only way to reach it now that the write path compiles.
    //
    // The direction matters more than the branch. Returning the document unredacted was the
    // old behaviour, and for a REDACTION that is the unsafe answer: the annotations are what
    // say which fields to withhold, so being unable to read them is a reason to refuse rather
    // than to disclose. It became urgent when this projection gained a caller that POSTs the
    // result to a third-party endpoint (issue #954); before that its readers were in-process.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x53);
    let scope = db.seed_scope(&env).await;
    let user = create_user(&db, &env, scope, "carried@example.test").await;

    // Both halves have to be real: a genuine sealed traits document carrying an admin-only
    // field, and a genuine non-compiling active schema. So seed through a schema that DOES
    // compile, then swap the active row for one that does not.
    let v1 = create_schema(
        &db,
        &env,
        scope,
        r#"{"type":"object","properties":{"name":{"type":"string"},"risk_score":{"type":"integer","x-ironauth":{"visibility":"admin"}}}}"#,
    )
    .await;
    activate_schema(&db, &env, scope, v1)
        .await
        .expect("activate the compiling schema");
    set_traits(
        &db,
        &env,
        scope,
        &user,
        r#"{"name":"Zeke","risk_score":97}"#,
    )
    .await
    .expect("seed the traits under a compiling schema");

    // Sanity: while the schema compiles, the admin-only field IS stripped. Without this the
    // assertion below could pass because the projection is broken in some other way.
    let visible = db
        .store()
        .scoped(scope)
        .users()
        .traits_user_visible(&user)
        .await
        .expect("the read succeeds while the schema compiles")
        .expect("the traits are present");
    assert_eq!(
        visible,
        json!({"name": "Zeke"}),
        "the compiling case strips the admin-only field"
    );

    // Now the carried-forward row: annotation nested below a top-level property, which the
    // current checker refuses and an older one accepted.
    sqlx::query("UPDATE trait_schemas SET schema_json = $1 WHERE tenant_id = $2 AND environment_id = $3 AND status = 'active'")
        .bind(r#"{"type":"object","properties":{"name":{"type":"object","properties":{"inner":{"type":"string","x-ironauth":{"visibility":"admin"}}}}}}"#)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .execute(db.owner_pool())
        .await
        .expect("carry forward a schema the current checker refuses");

    let err = db
        .store()
        .scoped(scope)
        .users()
        .traits_user_visible(&user)
        .await
        .expect_err("a redaction that cannot read its annotations must refuse");
    assert!(
        matches!(err, StoreError::SchemaMalformed(_)),
        "and it refuses AS a schema fault rather than a generic one, which is what lets a \
         caller tell an operator-repairable misconfiguration from a database outage: {err:?}"
    );
}
