// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environment-scoped secrets and variables, over a real database
//! (`DATABASE_URL`) (issue #45).
//!
//! Proves the load-bearing properties of the per-environment config store the
//! promotion flagship resolves references against:
//!
//! - a SECRET is sealed at rest (a raw column probe of a stored secret yields no
//!   plaintext), a metadata read never returns the value, and the value opens back
//!   exactly under the platform master key;
//! - a VARIABLE round-trips its plaintext value (it is promotable, non-secret
//!   config);
//! - cross-tenant AND cross-environment isolation (a secret or variable in one
//!   scope is invisible in another);
//! - RESOLUTION reads the RIGHT environment's value (the same reference resolves to
//!   different values in two environments), and an unresolved reference is reported
//!   without touching the apply path;
//! - a config snapshot carries VARIABLES (and a secret REFERENCE embedded in a
//!   variable value) but NEVER a secret value;
//! - every mutation writes its audit row; and
//! - a referenced secret or variable cannot be deleted (the referent list), while
//!   an unreferenced one can.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, Reference, ReferenceKind, Resolved, Scope, StoreError, export_snapshot,
    reference_resolves, resolve_value,
};
use sqlx::Row;

/// A distinctive secret plaintext: it must NEVER appear in a raw column, a
/// metadata read, a snapshot, or an audit row.
const SECRET_MARKER: &[u8] = b"SUPER-SECRET-CONNECTOR-CREDENTIAL-DO-NOT-LEAK";

/// Write actor + correlation for a data-plane mutation.
fn acting(db: &TestDatabase, env: &Env) -> (ironauth_store::ActorRef, CorrelationId) {
    (db.test_actor(env), CorrelationId::generate(env))
}

#[tokio::test]
async fn a_secret_is_sealed_and_never_returns_its_value_but_opens_back() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let app = db.store();
    let master = db.master_key();

    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_secrets()
        .put(&env, &master, "connector-key", SECRET_MARKER, None)
        .await
        .expect("put secret");

    // A metadata read returns presence and metadata, NEVER the value.
    let metadata = app
        .scoped(scope)
        .environment_secrets()
        .metadata("connector-key")
        .await
        .expect("secret metadata");
    assert_eq!(metadata.name, "connector-key");
    assert_eq!(metadata.version, 1);

    // The RAW stored column is ciphertext: a database dump reveals no plaintext.
    let ciphertext: Vec<u8> = sqlx::query(
        "SELECT ciphertext FROM environment_secrets \
         WHERE tenant_id = $1 AND environment_id = $2 AND name = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind("connector-key")
    .fetch_one(db.owner_pool())
    .await
    .expect("read raw ciphertext")
    .get("ciphertext");
    assert!(
        !contains_subslice(&ciphertext, SECRET_MARKER),
        "the stored secret column must not contain the plaintext"
    );
    // The table carries no plaintext column at all (no `value`/`plaintext`).
    let has_value_column: bool = sqlx::query(
        "SELECT EXISTS ( SELECT 1 FROM information_schema.columns \
         WHERE table_name = 'environment_secrets' AND column_name = 'value' ) AS present",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("column lookup")
    .get("present");
    assert!(!has_value_column, "environment_secrets has no value column");

    // The value opens back EXACTLY under the master key (the apply-time path).
    let opened = app
        .scoped(scope)
        .environment_secrets()
        .open_value(&master, "connector-key")
        .await
        .expect("open secret");
    assert_eq!(opened, SECRET_MARKER, "the secret round-trips its value");
}

#[tokio::test]
async fn a_secret_overwrite_bumps_version_and_reseals() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let app = db.store();
    let master = db.master_key();

    let (a, ca) = acting(&db, &env);
    app.scoped(scope)
        .acting(a, ca)
        .environment_secrets()
        .put(&env, &master, "k", b"first", None)
        .await
        .expect("first put");
    let (b, cb) = acting(&db, &env);
    app.scoped(scope)
        .acting(b, cb)
        .environment_secrets()
        .put(&env, &master, "k", b"second", None)
        .await
        .expect("overwrite");

    let metadata = app
        .scoped(scope)
        .environment_secrets()
        .metadata("k")
        .await
        .expect("metadata");
    assert_eq!(metadata.version, 2, "an overwrite bumps the version");
    let opened = app
        .scoped(scope)
        .environment_secrets()
        .open_value(&master, "k")
        .await
        .expect("open");
    assert_eq!(opened, b"second", "the overwrite value is what opens back");
}

#[tokio::test]
async fn a_variable_round_trips_its_value() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let app = db.store();

    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_variables()
        .set(&env, "api-base-url", "https://api.dev.example", None)
        .await
        .expect("set variable");

    let record = app
        .scoped(scope)
        .environment_variables()
        .get("api-base-url")
        .await
        .expect("get variable");
    assert_eq!(record.value, "https://api.dev.example");
    assert_eq!(record.version, 1);

    // An overwrite updates the value and bumps the version.
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_variables()
        .set(&env, "api-base-url", "https://api.dev.example/v2", None)
        .await
        .expect("overwrite variable");
    let record = app
        .scoped(scope)
        .environment_variables()
        .get("api-base-url")
        .await
        .expect("get variable");
    assert_eq!(record.value, "https://api.dev.example/v2");
    assert_eq!(record.version, 2);
}

#[tokio::test]
async fn secrets_and_variables_are_cross_tenant_and_cross_environment_isolated() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let master = db.master_key();
    let app = db.store();

    // Two scopes: env B is a SIBLING environment under the SAME tenant as A, and
    // env C is under a DIFFERENT tenant. Neither may see A's secret or variable.
    let scope_a = db.seed_scope(&env).await;
    let env_b = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_b = Scope::new(scope_a.tenant(), env_b);
    let scope_c = db.seed_scope(&env).await;

    let (actor, corr) = acting(&db, &env);
    app.scoped(scope_a)
        .acting(actor, corr)
        .environment_secrets()
        .put(&env, &master, "shared-name", SECRET_MARKER, None)
        .await
        .expect("put secret in A");
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope_a)
        .acting(actor, corr)
        .environment_variables()
        .set(&env, "shared-var", "value-in-A", None)
        .await
        .expect("set variable in A");

    for other in [scope_b, scope_c] {
        // The secret is invisible: metadata, existence, and open all miss.
        assert!(matches!(
            app.scoped(other)
                .environment_secrets()
                .metadata("shared-name")
                .await,
            Err(StoreError::NotFound)
        ));
        assert!(
            !app.scoped(other)
                .environment_secrets()
                .exists("shared-name")
                .await
                .expect("exists")
        );
        assert!(matches!(
            app.scoped(other)
                .environment_secrets()
                .open_value(&master, "shared-name")
                .await,
            Err(StoreError::NotFound)
        ));
        // The variable is invisible too.
        assert!(matches!(
            app.scoped(other)
                .environment_variables()
                .get("shared-var")
                .await,
            Err(StoreError::NotFound)
        ));
    }
}

#[tokio::test]
async fn resolution_reads_the_right_environments_value() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let master = db.master_key();
    let app = db.store();

    // The SAME reference names, resolved in two environments, yield DIFFERENT
    // values: this is the environment-scoped resolution the promotion pipeline
    // depends on (one canonical reference, per-environment values).
    let scope_a = db.seed_scope(&env).await;
    let env_b = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_b = Scope::new(scope_a.tenant(), env_b);

    for (scope, secret, variable) in [
        (scope_a, b"secret-A".to_vec(), "var-A"),
        (scope_b, b"secret-B".to_vec(), "var-B"),
    ] {
        let (actor, corr) = acting(&db, &env);
        app.scoped(scope)
            .acting(actor, corr)
            .environment_secrets()
            .put(&env, &master, "db-password", &secret, None)
            .await
            .expect("put secret");
        let (actor, corr) = acting(&db, &env);
        app.scoped(scope)
            .acting(actor, corr)
            .environment_variables()
            .set(&env, "endpoint", variable, None)
            .await
            .expect("set variable");
    }

    let secret_ref = Reference {
        kind: ReferenceKind::Secret,
        name: "db-password".to_string(),
    };
    let variable_ref = Reference {
        kind: ReferenceKind::Variable,
        name: "endpoint".to_string(),
    };

    let resolved_a = resolve_value(&app.scoped(scope_a), Some(&master), &secret_ref)
        .await
        .expect("resolve secret in A");
    let resolved_b = resolve_value(&app.scoped(scope_b), Some(&master), &secret_ref)
        .await
        .expect("resolve secret in B");
    assert_eq!(resolved_a, Resolved::Secret(b"secret-A".to_vec()));
    assert_eq!(resolved_b, Resolved::Secret(b"secret-B".to_vec()));

    let var_a = resolve_value(&app.scoped(scope_a), Some(&master), &variable_ref)
        .await
        .expect("resolve variable in A");
    assert_eq!(var_a, Resolved::Variable("var-A".to_string()));

    // Plan-time existence: the reference resolves where the value exists.
    assert!(
        reference_resolves(&app.scoped(scope_a), &secret_ref)
            .await
            .expect("plan check A")
    );
    // An unresolved reference in a scope that lacks it is reported as unresolved,
    // never a decryption or apply attempt.
    let scope_c = db.seed_scope(&env).await;
    assert!(
        !reference_resolves(&app.scoped(scope_c), &secret_ref)
            .await
            .expect("plan check C")
    );
    assert!(matches!(
        resolve_value(&app.scoped(scope_c), Some(&master), &variable_ref).await,
        Err(ironauth_store::ResolveError::Unresolved(_))
    ));
}

#[tokio::test]
async fn a_snapshot_carries_variables_and_secret_references_but_never_a_secret_value() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let master = db.master_key();
    let app = db.store();

    // A secret with a distinctive plaintext, and a variable whose VALUE is a
    // reference to that secret (a config field carrying a reference).
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_secrets()
        .put(&env, &master, "api-key", SECRET_MARKER, None)
        .await
        .expect("put secret");
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_variables()
        .set(
            &env,
            "connector-endpoint",
            "https://connector.example",
            None,
        )
        .await
        .expect("set variable");
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_variables()
        .set(&env, "connector-token", "${secret:api-key}", None)
        .await
        .expect("set reference variable");

    // Export through the CONTROL plane (the management-plane reader), exactly as
    // production does.
    let snapshot = export_snapshot(&db.control_store().scoped(scope))
        .await
        .expect("export snapshot");
    let text = snapshot.to_canonical_string().expect("canonical string");

    // The variables (name and value) travel, including the one carrying a secret
    // REFERENCE.
    assert!(
        text.contains("connector-endpoint") && text.contains("https://connector.example"),
        "a variable's name and value travel in the snapshot"
    );
    assert!(
        text.contains("${secret:api-key}"),
        "a secret REFERENCE embedded in a variable value travels"
    );
    // The SECRET VALUE never appears anywhere in the snapshot.
    let marker = std::str::from_utf8(SECRET_MARKER).expect("utf8 marker");
    assert!(
        !text.contains(marker),
        "a secret value must never appear in a snapshot"
    );
    // The environment_secret type is environment-identity: it is NOT a snapshot
    // resource key at all.
    assert!(
        !text.contains("environment_secret"),
        "a secret is not a snapshot resource"
    );

    // The exported variable count matches (two variables set).
    assert_eq!(
        snapshot.resources.variable.len(),
        2,
        "both variables are exported"
    );
}

#[tokio::test]
async fn mutations_are_audited() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let master = db.master_key();
    let app = db.store();

    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_variables()
        .set(&env, "v", "1", None)
        .await
        .expect("set variable");
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_secrets()
        .put(&env, &master, "s", b"x", None)
        .await
        .expect("put secret");
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_variables()
        .delete(&env, "v")
        .await
        .expect("delete variable");
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_secrets()
        .delete(&env, "s")
        .await
        .expect("delete secret");

    for action in [
        "environment_variable.set",
        "environment_secret.put",
        "environment_variable.delete",
        "environment_secret.delete",
    ] {
        let count: i64 = sqlx::query(
            "SELECT count(*) AS c FROM audit_log \
             WHERE tenant_id = $1 AND environment_id = $2 AND action = $3",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(action)
        .fetch_one(db.owner_pool())
        .await
        .expect("count audit rows")
        .get("c");
        assert_eq!(count, 1, "exactly one {action} audit row");
    }

    // No audit row ever carries the secret value.
    let secret_leak: i64 = sqlx::query(
        "SELECT count(*) AS c FROM audit_log \
         WHERE action LIKE 'environment_secret%' AND target_id LIKE '%x%' AND target_id NOT LIKE 'esec_%'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("count")
    .get("c");
    assert_eq!(
        secret_leak, 0,
        "an audit target is the esec_ id, never a value"
    );
}

#[tokio::test]
async fn a_referenced_secret_or_variable_cannot_be_deleted() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let master = db.master_key();
    let app = db.store();

    // A secret, and a variable whose value references it.
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_secrets()
        .put(&env, &master, "db-password", b"x", None)
        .await
        .expect("put secret");
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_variables()
        .set(&env, "db-url", "${secret:db-password}", None)
        .await
        .expect("set referencing variable");

    // The referent list names the referencing variable.
    let secret_ref = Reference {
        kind: ReferenceKind::Secret,
        name: "db-password".to_string(),
    };
    let referents = app
        .scoped(scope)
        .environment_variables()
        .referents(&secret_ref)
        .await
        .expect("referents");
    assert_eq!(referents, vec!["db-url".to_string()]);

    // Deleting the referenced secret is REJECTED.
    let (actor, corr) = acting(&db, &env);
    assert!(matches!(
        app.scoped(scope)
            .acting(actor, corr)
            .environment_secrets()
            .delete(&env, "db-password")
            .await,
        Err(StoreError::Conflict)
    ));

    // Remove the referent, then the delete succeeds.
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_variables()
        .delete(&env, "db-url")
        .await
        .expect("delete referent variable");
    let (actor, corr) = acting(&db, &env);
    app.scoped(scope)
        .acting(actor, corr)
        .environment_secrets()
        .delete(&env, "db-password")
        .await
        .expect("delete now-unreferenced secret");
    assert!(
        !app.scoped(scope)
            .environment_secrets()
            .exists("db-password")
            .await
            .expect("exists")
    );
}

#[tokio::test]
async fn an_invalid_name_is_rejected_before_a_write() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let master = db.master_key();
    let app = db.store();

    let (actor, corr) = acting(&db, &env);
    assert!(matches!(
        app.scoped(scope)
            .acting(actor, corr)
            .environment_variables()
            .set(&env, "has space", "v", None)
            .await,
        Err(StoreError::InvalidName)
    ));
    let (actor, corr) = acting(&db, &env);
    assert!(matches!(
        app.scoped(scope)
            .acting(actor, corr)
            .environment_secrets()
            .put(&env, &master, "", b"v", None)
            .await,
        Err(StoreError::InvalidName)
    ));
}

/// Whether `haystack` contains `needle` as a contiguous byte subslice.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
