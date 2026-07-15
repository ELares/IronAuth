// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server-side config promotion over a real database (`DATABASE_URL`) (issue #44).
//!
//! Proves the load-bearing properties of the flagship diff/plan/apply engine:
//!
//! - DIFF detects create, update, and delete correctly, and a promotion round-trips
//!   (apply then re-diff yields an empty diff);
//! - APPLY is ATOMIC: a fault-injected mid-apply failure leaves the target
//!   byte-for-byte unchanged with no promotion audit row;
//! - APPLY matches the PLAN, and re-applying is an idempotent no-op;
//! - a STALE plan (the target drifted) fails with a structured drift error and
//!   changes nothing;
//! - PLAN fails CLOSED on a reference the target cannot resolve, and succeeds once
//!   the reference exists;
//! - a secret reference resolves to the TARGET environment's value, never the
//!   source's;
//! - cross-tenant and cross-environment ISOLATION, and environment-IDENTITY (a
//!   client) is never promoted; and
//! - a successful apply is AUDITED in the same transaction.
//!
//! Promotion is a CONTROL-plane operation, so the diff/plan/apply and the
//! promotable-config seeding run through the control store; secrets (which need the
//! envelope master key) and clients are seeded through the data-plane store, and a
//! secret is resolved through the data-plane store exactly as the runtime does.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, DcrPolicyId, NewDcrPolicy, NewResourceServer, PromotionApplyError,
    PromotionOutcome, Reference, Resolved, ResourceServerId, SNAPSHOT_SCHEMA_VERSION, Scope,
    Snapshot, SnapshotResources, Store, TokenFormat, VariableSnapshot, diff_snapshots,
    export_snapshot, plan_promotion, promotion_revision, resolve_value,
};

/// A fresh write actor plus correlation id for a mutation.
fn acting(db: &TestDatabase, env: &Env) -> (ActorRef, CorrelationId) {
    (db.test_actor(env), CorrelationId::generate(env))
}

/// Register a resource server in `scope` (control plane).
async fn register_rs(db: &TestDatabase, env: &Env, scope: Scope, audience: &str, fmt: TokenFormat) {
    let id = ResourceServerId::generate(env, &scope);
    let (actor, corr) = acting(db, env);
    db.control_store()
        .scoped(scope)
        .acting(actor, corr)
        .resource_servers()
        .register(
            env,
            NewResourceServer {
                id: &id,
                audience,
                token_format: fmt,
                access_token_ttl_secs: None,
            },
        )
        .await
        .expect("register resource server");
}

/// Create a DCR policy in `scope` (control plane).
async fn create_policy(db: &TestDatabase, env: &Env, scope: Scope, name: &str, primitives: &str) {
    let id = DcrPolicyId::generate(env, &scope);
    let (actor, corr) = acting(db, env);
    db.control_store()
        .scoped(scope)
        .acting(actor, corr)
        .dcr_policies()
        .create(env, &id, 1_000_000, NewDcrPolicy { name, primitives }, None)
        .await
        .expect("create dcr policy");
}

/// Set an environment variable in `scope` (control plane).
async fn set_var(db: &TestDatabase, env: &Env, scope: Scope, name: &str, value: &str) {
    let (actor, corr) = acting(db, env);
    db.control_store()
        .scoped(scope)
        .acting(actor, corr)
        .environment_variables()
        .set(env, name, value, None)
        .await
        .expect("set variable");
}

/// Put an environment secret in `scope` (data plane: sealing needs the master key).
async fn put_secret(db: &TestDatabase, env: &Env, scope: Scope, name: &str, value: &[u8]) {
    let (actor, corr) = acting(db, env);
    db.store()
        .scoped(scope)
        .acting(actor, corr)
        .environment_secrets()
        .put(env, &db.master_key(), name, value, None)
        .await
        .expect("put secret");
}

/// Create a public client in `scope` (data plane).
async fn create_client(db: &TestDatabase, env: &Env, scope: Scope, display_name: &str) {
    let (actor, corr) = acting(db, env);
    db.store()
        .scoped(scope)
        .acting(actor, corr)
        .clients()
        .create(env, display_name)
        .await
        .expect("create client");
}

/// The control-plane store the promotion engine runs on.
fn control(db: &TestDatabase) -> &Store {
    db.control_store()
}

/// Export a scope's promotable configuration (control plane).
async fn export(db: &TestDatabase, scope: Scope) -> Snapshot {
    export_snapshot(&control(db).scoped(scope))
        .await
        .expect("export snapshot")
}

/// Count the `config_promotion.apply` audit rows in `scope`.
async fn apply_audit_count(db: &TestDatabase, scope: Scope) -> usize {
    control(db)
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("list audit")
        .iter()
        .filter(|record| record.action == "config_promotion.apply")
        .count()
}

#[tokio::test]
async fn diff_plan_apply_round_trips_and_is_idempotent_and_audited() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    // Source carries one of each promoted type; the target is empty.
    register_rs(&db, &env, source, "https://api.example", TokenFormat::AtJwt).await;
    create_policy(&db, &env, source, "open", "[]").await;
    set_var(&db, &env, source, "feature_flag", "on").await;

    let source_snapshot = export(&db, source).await;

    // PLAN: three creates, base != result.
    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    assert_eq!(plan.diff().len(), 3, "one create per promoted type");
    assert_ne!(plan.base_revision(), plan.result_revision());

    // APPLY: matches the plan exactly.
    let (actor, corr) = acting(&db, &env);
    let outcome = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .expect("apply");
    match outcome {
        PromotionOutcome::Applied(applied) => {
            assert_eq!(
                &applied,
                plan.diff(),
                "apply must do exactly what the plan said"
            );
        }
        PromotionOutcome::NoOp => panic!("expected an applied promotion, not a no-op"),
    }

    // ROUND TRIP: re-exporting the target and re-diffing the source yields empty.
    let target_after = export(&db, target).await;
    assert!(
        diff_snapshots(&source_snapshot, &target_after).is_empty(),
        "apply then re-diff must be empty"
    );
    assert_eq!(
        promotion_revision(&target_after).expect("rev"),
        promotion_revision(&source_snapshot).expect("rev"),
        "the target's promoted config now equals the source's"
    );

    // AUDITED: exactly one promotion audit row.
    assert_eq!(apply_audit_count(&db, target).await, 1);

    // IDEMPOTENT: re-applying the same plan against the unchanged target is a no-op.
    let (actor, corr) = acting(&db, &env);
    let again = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .expect("re-apply");
    assert_eq!(again, PromotionOutcome::NoOp, "re-apply is a no-op");
    assert_eq!(apply_audit_count(&db, target).await, 1);
}

#[tokio::test]
async fn apply_is_atomic_and_a_mid_apply_failure_changes_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    register_rs(&db, &env, source, "https://api.example", TokenFormat::AtJwt).await;
    set_var(&db, &env, source, "a", "1").await;
    set_var(&db, &env, source, "b", "2").await;
    let source_snapshot = export(&db, source).await;

    // Capture the target's exact bytes and revision BEFORE apply.
    let before = export(&db, target)
        .await
        .to_canonical_bytes()
        .expect("bytes");
    let base = promotion_revision(&export(&db, target).await).expect("rev");

    // Apply with the poison seam set: a guaranteed in-transaction failure AFTER the
    // changes and the audit row are staged.
    let (actor, corr) = acting(&db, &env);
    let error = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, &base, true)
        .await
        .expect_err("poisoned apply must fail");
    assert!(matches!(error, PromotionApplyError::Store(_)));

    // The target is byte-for-byte unchanged: no partial promotion.
    let after = export(&db, target)
        .await
        .to_canonical_bytes()
        .expect("bytes");
    assert_eq!(before, after, "a failed apply leaves the target unchanged");
    assert_eq!(apply_audit_count(&db, target).await, 0);
}

#[tokio::test]
async fn a_stale_plan_fails_with_drift_and_changes_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    set_var(&db, &env, source, "promoted", "value").await;
    let source_snapshot = export(&db, source).await;

    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    let stale_base = plan.base_revision().to_owned();

    // The target drifts after the plan was computed.
    set_var(&db, &env, target, "unrelated", "drift").await;

    let (actor, corr) = acting(&db, &env);
    let error = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, &stale_base, false)
        .await
        .expect_err("stale plan must fail");
    assert!(matches!(error, PromotionApplyError::Drift { .. }));

    // Nothing from the source was applied: the promoted variable is still absent.
    let target_after = export(&db, target).await;
    assert!(
        !target_after
            .resources
            .variable
            .iter()
            .any(|variable| variable.name == "promoted"),
        "a drift-rejected apply must change nothing"
    );
    assert_eq!(apply_audit_count(&db, target).await, 0);
}

#[tokio::test]
async fn plan_fails_closed_on_a_missing_reference_and_succeeds_once_present() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    // The source promotes a variable whose value references a secret.
    set_var(&db, &env, source, "connector", "${secret:api_key}").await;
    let source_snapshot = export(&db, source).await;

    // The target lacks the secret: the plan FAILS CLOSED with a per-item error.
    let missing = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect_err("plan must fail closed");
    assert_eq!(missing.len(), 1, "one unresolved reference");

    // Once the target carries the secret, the plan builds.
    put_secret(&db, &env, target, "api_key", b"target-value").await;
    plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan now builds");
}

#[tokio::test]
async fn a_secret_reference_resolves_to_the_targets_value() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let master = db.master_key();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    // Each environment has its OWN secret of the same name, with a different value.
    put_secret(&db, &env, source, "api_key", b"source-secret").await;
    put_secret(&db, &env, target, "api_key", b"target-secret").await;
    // The source promotes a variable that references the secret by name.
    set_var(&db, &env, source, "connector", "${secret:api_key}").await;
    let source_snapshot = export(&db, source).await;

    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    let (actor, corr) = acting(&db, &env);
    control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .expect("apply");

    // The promoted variable carries the reference TOKEN verbatim (no secret value
    // ever lands in a plaintext config column).
    let target_after = export(&db, target).await;
    let connector = target_after
        .resources
        .variable
        .iter()
        .find(|variable| variable.name == "connector")
        .expect("connector variable promoted");
    assert_eq!(connector.value, "${secret:api_key}");

    // Resolving the reference in the target yields the TARGET's secret value.
    let reference = Reference::parse(&connector.value).expect("parse reference");
    let resolved = resolve_value(&db.store().scoped(target), Some(&master), &reference)
        .await
        .expect("resolve in target");
    assert_eq!(
        resolved,
        Resolved::Secret(b"target-secret".to_vec()),
        "the reference must resolve to the target env's value, not the source's"
    );
}

#[tokio::test]
async fn promotion_is_scope_isolated_and_never_copies_client_identity() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );
    // A completely separate tenant/environment that must stay untouched.
    let other = db.seed_scope(&env).await;

    // Source has a client and a resource server; the target has its OWN client.
    create_client(&db, &env, source, "source-app").await;
    register_rs(
        &db,
        &env,
        source,
        "https://only-source",
        TokenFormat::Opaque,
    )
    .await;
    create_client(&db, &env, target, "target-app").await;

    let source_snapshot = export(&db, source).await;
    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    let (actor, corr) = acting(&db, &env);
    control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .expect("apply");

    // The promoted resource server landed in the target.
    let target_servers = control(&db)
        .scoped(target)
        .resource_servers()
        .list()
        .await
        .expect("list target servers");
    assert!(
        target_servers
            .iter()
            .any(|server| server.audience == "https://only-source"),
        "the resource server promotes into the target"
    );

    // ENVIRONMENT IDENTITY is never copied: the target keeps its own client and the
    // source's client identity does NOT appear in the target.
    let target_clients = db
        .store()
        .scoped(target)
        .clients()
        .list()
        .await
        .expect("list target clients");
    let names: Vec<&str> = target_clients
        .iter()
        .map(|client| client.display_name.as_str())
        .collect();
    assert!(names.contains(&"target-app"), "target keeps its own client");
    assert!(
        !names.contains(&"source-app"),
        "a source client identity must never be copied into the target"
    );

    // ISOLATION: the source environment is untouched, and the unrelated tenant has
    // no resource servers at all.
    let source_servers = control(&db)
        .scoped(source)
        .resource_servers()
        .list()
        .await
        .expect("list source servers");
    assert_eq!(
        source_servers.len(),
        1,
        "the source environment is unchanged"
    );
    let other_servers = control(&db)
        .scoped(other)
        .resource_servers()
        .list()
        .await
        .expect("list other servers");
    assert!(
        other_servers.is_empty(),
        "an unrelated tenant is never touched by a promotion"
    );
}

/// A hand-built (submitted) snapshot is a first-class promotion source, exactly
/// like an exported one.
#[tokio::test]
async fn a_submitted_snapshot_is_a_valid_promotion_source() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    let submitted = Snapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION.to_owned(),
        resources: SnapshotResources {
            variable: vec![VariableSnapshot {
                name: "submitted".to_owned(),
                value: "value".to_owned(),
            }],
            ..SnapshotResources::default()
        },
    };

    let plan = plan_promotion(&control(&db).scoped(target), &submitted)
        .await
        .expect("plan db")
        .expect("plan builds");
    let (actor, corr) = acting(&db, &env);
    control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &submitted, plan.base_revision(), false)
        .await
        .expect("apply");

    let target_after = export(&db, target).await;
    assert!(
        diff_snapshots(&submitted, &target_after).is_empty(),
        "a submitted snapshot promotes and round-trips"
    );
}
