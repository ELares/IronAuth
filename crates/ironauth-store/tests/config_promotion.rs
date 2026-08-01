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
    ActorRef, BrandAssetKind, BrandId, CorrelationId, DcrPolicyId, FlowVersionRecord,
    FlowVersionSnapshot, LocaleBundleId, NewBrand, NewBrandAsset, NewDcrPolicy, NewFlowVersion,
    NewLocaleBundle, NewResourceServer, NewSignupForm, PromotionApplyError, PromotionOutcome,
    Reference, Resolved, ResourceServerId, SNAPSHOT_SCHEMA_VERSION, Scope, SignupFormId, Snapshot,
    SnapshotResources, Store, TokenFormat, VariableSnapshot, diff_snapshots, export_snapshot,
    plan_promotion, promotion_revision, resolve_value, validate_document,
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

/// The single client id installed in `scope` (data plane). Used where a test needs the
/// SCOPE-EMBEDDED client id of the environment it just seeded, rather than a literal.
async fn only_client_id(db: &TestDatabase, scope: Scope) -> String {
    let clients = db
        .store()
        .scoped(scope)
        .clients()
        .list()
        .await
        .expect("list clients");
    assert_eq!(clients.len(), 1, "expected exactly one seeded client");
    clients[0].id.to_string()
}

/// A minimal load-valid journey artifact whose internal id embeds `variant`, so distinct
/// variants are distinct (differing) artifacts for the same registry (`journey_id`, version).
fn journey_artifact(journey: &str, variant: u32) -> String {
    serde_json::json!({
        "schema_version": "ironauth.journey/v1",
        "id": format!("{journey}_v{variant}"),
        "engine_version": 1,
        "entry": "primary",
        "steps": [
            {"id": "primary", "kind": "identifier_password", "node_group": "password"},
            {"id": "done", "kind": "terminal"}
        ],
        "transitions": [{"from": "primary", "to": "done"}]
    })
    .to_string()
}

/// Create the next custom-journey version in `scope` (control plane), returning its number.
async fn create_flow_version(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    journey: &str,
    artifact_json: &str,
) -> i32 {
    let (actor, corr) = acting(db, env);
    db.control_store()
        .scoped(scope)
        .acting(actor, corr)
        .flow_versions()
        .create_next_version(
            env,
            NewFlowVersion {
                journey_id: journey,
                artifact_json,
            },
            1_000_000,
        )
        .await
        .expect("create flow version")
        .version
}

/// Move `journey`'s active pin to `version` in `scope` (control plane).
async fn pin_flow_version(db: &TestDatabase, env: &Env, scope: Scope, journey: &str, version: i32) {
    let (actor, corr) = acting(db, env);
    db.control_store()
        .scoped(scope)
        .acting(actor, corr)
        .flow_versions()
        .pin(env, journey, version, 2_000_000, None)
        .await
        .expect("pin flow version");
}

/// A journey's specific version in `scope`, if present (control plane).
async fn get_flow_version(
    db: &TestDatabase,
    scope: Scope,
    journey: &str,
    version: i32,
) -> Option<FlowVersionRecord> {
    control(db)
        .scoped(scope)
        .flow_versions()
        .get_version(journey, version)
        .await
        .expect("get flow version")
}

/// A journey's active pinned version in `scope`, if any (control plane).
async fn get_pinned_flow_version(
    db: &TestDatabase,
    scope: Scope,
    journey: &str,
) -> Option<FlowVersionRecord> {
    control(db)
        .scoped(scope)
        .flow_versions()
        .get_pinned(journey)
        .await
        .expect("get pinned flow version")
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

/// Two concurrent applies to the SAME (tenant, environment) sharing one base
/// revision must NOT both commit: the drift gate has to be authoritative under real
/// concurrency, not merely sequentially. Against the lock-free apply this fails --
/// both applies read the empty target's base revision, both pass the optimistic
/// drift gate, and both commit, leaving the target with BOTH variables (a state no
/// single plan enumerated). With the per-target advisory lock the second apply
/// blocks until the first commits, re-reads the now-changed revision, and returns
/// `Drift`, so EXACTLY one plan lands.
#[tokio::test]
async fn concurrent_applies_to_one_target_do_not_lose_an_update() {
    // A storm of concurrent applies onto ONE empty target, each promoting a DIFFERENT
    // single variable and all sharing the same empty-target base revision. Several
    // racers (not just two) so the lock-free path cannot pass by luck: for it to
    // avoid a lost update EVERY racer would have to serialize perfectly, which under a
    // real overlap it does not.
    const RACERS: usize = 8;

    let db = TestDatabase::start().await;
    let env = Env::system();
    let tenant = db.seed_scope(&env).await.tenant();
    let target = Scope::new(tenant, db.seed_environment(&env, tenant).await);

    // Build one distinct source snapshot per racer, each a single uniquely named
    // variable. All plans are computed against the same empty target, so they all
    // capture the same base revision.
    let mut snapshots = Vec::with_capacity(RACERS);
    let mut base_revision: Option<String> = None;
    for index in 0..RACERS {
        let source = Scope::new(tenant, db.seed_environment(&env, tenant).await);
        let name = format!("var_{index}");
        set_var(&db, &env, source, &name, "value").await;
        let snapshot = export(&db, source).await;
        let plan = plan_promotion(&control(&db).scoped(target), &snapshot)
            .await
            .expect("plan db")
            .expect("plan builds");
        match &base_revision {
            None => base_revision = Some(plan.base_revision().to_owned()),
            Some(base) => assert_eq!(
                base,
                plan.base_revision(),
                "every plan must capture the same empty-target base revision"
            ),
        }
        snapshots.push((name, snapshot));
    }
    let base_revision = base_revision.expect("at least one racer");

    // Pre-warm the pool to RACERS live connections with a concurrent round of cheap
    // reads, so the storm's overlap is governed by the applies themselves and not by
    // one-time connection establishment serializing them.
    let warmup: Vec<_> = (0..RACERS)
        .map(|_| {
            let db = db.clone();
            tokio::spawn(async move { apply_audit_count(&db, target).await })
        })
        .collect();
    for handle in warmup {
        handle.await.expect("warmup join");
    }

    // Release every apply together so their transactions genuinely overlap on the
    // real Postgres (each on its own pooled connection).
    let gate = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
    let handles: Vec<_> = snapshots
        .into_iter()
        .map(|(_, snapshot)| {
            let db = db.clone();
            let env = env.clone();
            let base = base_revision.clone();
            let gate = std::sync::Arc::clone(&gate);
            tokio::spawn(async move {
                let (actor, corr) = acting(&db, &env);
                gate.wait().await;
                db.control_store()
                    .scoped(target)
                    .acting(actor, corr)
                    .apply_promotion(&env, &snapshot, &base, false)
                    .await
            })
        })
        .collect();

    let mut results = Vec::with_capacity(RACERS);
    for handle in handles {
        results.push(handle.await.expect("apply join"));
    }

    // EXACTLY one apply commits; every other is refused as drift (which one wins is a
    // race, so accept any single winner).
    let applied = results
        .iter()
        .filter(|r| matches!(r, Ok(PromotionOutcome::Applied(_))))
        .count();
    let drifted = results
        .iter()
        .filter(|r| matches!(r, Err(PromotionApplyError::Drift { .. })))
        .count();
    assert_eq!(
        applied, 1,
        "exactly one concurrent apply may commit: {results:?}"
    );
    assert_eq!(
        drifted,
        RACERS - 1,
        "every losing concurrent apply must be refused as drift: {results:?}"
    );

    // The target carries the result of EXACTLY ONE plan, NEVER a merge of several: a
    // lost update would leave it with more than one variable.
    let target_after = export(&db, target).await;
    let names: Vec<&str> = target_after
        .resources
        .variable
        .iter()
        .map(|variable| variable.name.as_str())
        .collect();
    assert_eq!(
        names.len(),
        1,
        "the target must carry exactly one plan's result, never a merge: got {names:?}"
    );

    // Exactly one promotion was audited: every drift-refused apply wrote nothing.
    assert_eq!(apply_audit_count(&db, target).await, 1);
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

/// Custom-journey versions (issue #92) promote as APPEND-ONLY definitions into a fresh
/// target: every version is created (load-valid), a re-apply is an idempotent no-op, and
/// because the empty target had no pin the target stays UNPINNED (the version definitions
/// travel; activation does not).
#[tokio::test]
async fn flow_versions_promote_into_a_fresh_target_and_re_apply_is_a_no_op() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    // Source has three append-only versions of "login" (v3 pinned as its active journey).
    let journey = "login";
    assert_eq!(
        create_flow_version(&db, &env, source, journey, &journey_artifact(journey, 1)).await,
        1
    );
    assert_eq!(
        create_flow_version(&db, &env, source, journey, &journey_artifact(journey, 2)).await,
        2
    );
    assert_eq!(
        create_flow_version(&db, &env, source, journey, &journey_artifact(journey, 3)).await,
        3
    );
    pin_flow_version(&db, &env, source, journey, 3).await;

    let source_snapshot = export(&db, source).await;
    // The snapshot carries the source pin informationally (v3), but it is not an apply action.
    assert!(
        source_snapshot
            .resources
            .flow_version
            .iter()
            .any(|v| v.version == 3 && v.pinned),
        "the source pin travels in the snapshot for visibility"
    );

    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    assert_eq!(plan.diff().len(), 3, "one create per source version");

    let (actor, corr) = acting(&db, &env);
    control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .expect("apply");

    // All three versions landed in the target and are load-valid (get_version returns them).
    for version in 1..=3 {
        let record = get_flow_version(&db, target, journey, version)
            .await
            .unwrap_or_else(|| panic!("v{version} promoted into the target"));
        assert!(record.artifact_json.contains("identifier_password"));
    }
    // THE ACTIVATION GATE: the empty target had no pin, and the promoted pin was NOT applied,
    // so the target has NO active journey until a target-env admin pins one.
    assert!(
        get_pinned_flow_version(&db, target, journey)
            .await
            .is_none(),
        "a promoted pin must never auto-activate a journey in the target"
    );

    // AUDITED and ROUND-TRIPS: re-diff is empty and a re-apply is an idempotent no-op.
    assert_eq!(apply_audit_count(&db, target).await, 1);
    let target_after = export(&db, target).await;
    assert!(
        diff_snapshots(&source_snapshot, &target_after).is_empty(),
        "apply then re-diff must be empty"
    );
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

/// THE PER-ENVIRONMENT ACTIVATION GATE (security-critical): promoting a journey whose SOURCE
/// pin is v3 into a target whose ACTIVE pin is v1 imports v2 and v3 as definitions but LEAVES
/// the target's active pin on v1. A promoted pin never silently swaps the journey that
/// authenticates users in the target; a target admin must deliberately pin v3 to activate it.
#[tokio::test]
async fn apply_imports_versions_but_never_moves_the_targets_active_pin() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    let journey = "login";
    // Source: v1, v2, v3, with v3 the active (pinned) journey.
    create_flow_version(&db, &env, source, journey, &journey_artifact(journey, 1)).await;
    create_flow_version(&db, &env, source, journey, &journey_artifact(journey, 2)).await;
    create_flow_version(&db, &env, source, journey, &journey_artifact(journey, 3)).await;
    pin_flow_version(&db, &env, source, journey, 3).await;

    // Target already runs its OWN v1 (byte-identical to the source's v1, so no conflict) and
    // has pinned it as its active journey.
    create_flow_version(&db, &env, target, journey, &journey_artifact(journey, 1)).await;
    pin_flow_version(&db, &env, target, journey, 1).await;
    assert_eq!(
        get_pinned_flow_version(&db, target, journey)
            .await
            .expect("target pin exists")
            .version,
        1,
        "the target starts pinned to v1"
    );

    let source_snapshot = export(&db, source).await;
    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    // v1 is already present with the same artifact (a no-op); only v2 and v3 are created.
    assert_eq!(
        plan.diff().len(),
        2,
        "only the two missing versions are creates"
    );

    let (actor, corr) = acting(&db, &env);
    control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .expect("apply");

    // The target now HAS v3 (its definition was imported).
    assert!(
        get_flow_version(&db, target, journey, 3).await.is_some(),
        "v3's definition promoted into the target"
    );
    // THE GATE, proven: the target's ACTIVE pin is STILL v1, not the source's v3. A target
    // admin must pin v3 to activate it; promotion never did.
    let target_pin = get_pinned_flow_version(&db, target, journey)
        .await
        .expect("target still has a pin");
    assert_eq!(
        target_pin.version, 1,
        "apply must NOT move the target's active pin: it keeps its own v1"
    );
}

/// A source version whose `(journey_id, version)` already exists in the target with a
/// DIFFERENT artifact is refused as an append-only conflict: apply changes nothing and never
/// overwrites the target's immutable version.
#[tokio::test]
async fn a_conflicting_flow_version_artifact_is_refused_and_changes_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    let journey = "login";
    // Source v1 and target v1 are BOTH version 1 of "login" but carry DIFFERENT artifacts.
    create_flow_version(&db, &env, source, journey, &journey_artifact(journey, 1)).await;
    create_flow_version(&db, &env, target, journey, &journey_artifact(journey, 99)).await;
    let target_v1_before = get_flow_version(&db, target, journey, 1)
        .await
        .expect("target v1")
        .artifact_json;

    let source_snapshot = export(&db, source).await;
    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");

    let (actor, corr) = acting(&db, &env);
    let error = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .expect_err("a conflicting version must be refused");
    match error {
        PromotionApplyError::FlowVersionArtifactConflict {
            journey_id,
            version,
        } => {
            assert_eq!(journey_id, journey);
            assert_eq!(version, 1);
        }
        other => panic!("expected an append-only conflict, got {other:?}"),
    }

    // The target's immutable v1 is byte-for-byte unchanged, and nothing was audited.
    let target_v1_after = get_flow_version(&db, target, journey, 1)
        .await
        .expect("target v1 still present")
        .artifact_json;
    assert_eq!(
        target_v1_before, target_v1_after,
        "an append-only version is never overwritten"
    );
    assert_eq!(apply_audit_count(&db, target).await, 0);
}

/// A load-invalid promoted journey artifact rolls the WHOLE apply back (transactional): the
/// variable staged earlier in the same apply is not left behind.
#[tokio::test]
async fn a_load_invalid_promoted_artifact_rolls_back_the_whole_apply() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    // A hand-built snapshot: a valid variable AND a load-invalid journey artifact (a transition
    // to an undeclared step, which does not compile). A store export could never produce the
    // invalid artifact (the write gate refuses it), so a submitted snapshot exercises the apply
    // gate directly.
    let invalid_artifact = serde_json::json!({
        "schema_version": "ironauth.journey/v1",
        "id": "broken",
        "engine_version": 1,
        "entry": "primary",
        "steps": [
            {"id": "primary", "kind": "identifier_password", "node_group": "password"},
            {"id": "done", "kind": "terminal"}
        ],
        "transitions": [{"from": "primary", "to": "nowhere"}]
    });
    let submitted = Snapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION.to_owned(),
        resources: SnapshotResources {
            variable: vec![VariableSnapshot {
                name: "staged".to_owned(),
                value: "value".to_owned(),
            }],
            flow_version: vec![FlowVersionSnapshot {
                journey_id: "login".to_owned(),
                version: 1,
                artifact: invalid_artifact,
                pinned: false,
            }],
            ..SnapshotResources::default()
        },
    };

    let plan = plan_promotion(&control(&db).scoped(target), &submitted)
        .await
        .expect("plan db")
        .expect("plan builds");

    let (actor, corr) = acting(&db, &env);
    let error = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &submitted, plan.base_revision(), false)
        .await
        .expect_err("a load-invalid artifact must fail the apply");
    assert!(
        matches!(error, PromotionApplyError::Store(_)),
        "a load-invalid promoted artifact fails the apply: {error:?}"
    );

    // TRANSACTIONAL: the variable staged earlier in the same apply rolled back with it, and no
    // version and no audit row survive.
    let target_after = export(&db, target).await;
    assert!(
        target_after.resources.variable.is_empty(),
        "the staged variable must roll back with the failed apply"
    );
    assert!(
        get_flow_version(&db, target, "login", 1).await.is_none(),
        "no version survives a rolled-back apply"
    );
    assert_eq!(apply_audit_count(&db, target).await, 0);
}

/// Set a resource server's issue #98 permission-claim opt-in in `scope`, addressed
/// by audience (control plane).
async fn set_opt_in(db: &TestDatabase, env: &Env, scope: Scope, audience: &str, enabled: bool) {
    let record = control(db)
        .scoped(scope)
        .resource_servers()
        .by_audience(audience)
        .await
        .expect("read resource server")
        .expect("the resource server is registered");
    let (actor, corr) = acting(db, env);
    control(db)
        .management()
        .acting(actor, corr)
        .resource_servers(scope)
        .set_permission_claims(env, &record.id, enabled)
        .await
        .expect("set the permission-claim opt-in");
}

/// The stored opt-in of one audience in `scope` (control plane).
async fn opt_in_of(db: &TestDatabase, scope: Scope, audience: &str) -> bool {
    control(db)
        .scoped(scope)
        .resource_servers()
        .by_audience(audience)
        .await
        .expect("read resource server")
        .expect("the resource server is registered")
        .permission_claims_enabled
}

/// The issue #98 permission-claim opt-in survives an EXPORT and a re-APPLY intact,
/// on the CREATE arm and on the UPDATE arm, and it is a promotable difference in its
/// own right.
///
/// This is the end-to-end proof of the four promotion sites plus the schema, and it
/// is written so that breaking ANY ONE of them turns it red rather than leaving it
/// green on a coincidence. Concretely:
///
///   * Drop the field from `ResourceServerSnapshot` and it does not compile.
///   * Write `false` into the EXPORT (`snapshot::export`) and the source snapshot
///     carries `false`, so the create arm below lands `false` in the target.
///   * Write `false` into `read_promoted_snapshot` and the TARGET side of every diff
///     reads `false`, so the second phase reports no change for a difference that is
///     real and `assert!(diff.is_empty())` after the apply fails. Dropping the COLUMN
///     from that projection instead is louder still: `Row::get` panics with
///     `ColumnNotFound`, measured.
///   * Drop it from the apply's INSERT and the create arm lands the column default.
///   * Drop it from the apply's UPDATE SET list and the second phase changes nothing.
///   * Drop it from `RESOURCE_SERVER_KEYS` (the Rust mirror of the schema's
///     `additionalProperties: false`) and the plan fails validation outright, which
///     `the_exported_permission_claim_opt_in_validates_and_round_trips` below is the
///     test for.
#[tokio::test]
async fn the_permission_claim_opt_in_survives_an_export_and_an_apply() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    // --- Phase 1: the CREATE arm. The audience exists only in the source, opted IN.
    register_rs(
        &db,
        &env,
        source,
        "https://api.opted-in",
        TokenFormat::AtJwt,
    )
    .await;
    set_opt_in(&db, &env, source, "https://api.opted-in", true).await;
    // A second audience left opted OUT, so a bug that hard-codes `true` anywhere is
    // as visible as one that hard-codes `false`.
    register_rs(
        &db,
        &env,
        source,
        "https://api.opted-out",
        TokenFormat::AtJwt,
    )
    .await;

    let source_snapshot = export(&db, source).await;
    // The EXPORT site, asserted directly: the flag is IN the document, per audience.
    let exported: Vec<(&str, bool)> = source_snapshot
        .resources
        .resource_server
        .iter()
        .map(|server| (server.audience.as_str(), server.permission_claims_enabled))
        .collect();
    assert_eq!(
        exported,
        vec![
            ("https://api.opted-in", true),
            ("https://api.opted-out", false)
        ],
        "the export carries the opt-in per audience"
    );

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
        .expect("apply the creates");

    assert!(
        opt_in_of(&db, target, "https://api.opted-in").await,
        "the CREATE arm of the apply must land the opt-in, not the column default"
    );
    assert!(
        !opt_in_of(&db, target, "https://api.opted-out").await,
        "an opted-out audience must land opted out"
    );

    // The ROUND TRIP: re-exporting the target and re-diffing must be empty. This is
    // what `read_promoted_snapshot` is on the hook for, because that read is the
    // TARGET side of the diff.
    let target_after = export(&db, target).await;
    assert!(
        diff_snapshots(&source_snapshot, &target_after).is_empty(),
        "apply then re-diff must be empty: {:?}",
        diff_snapshots(&source_snapshot, &target_after)
    );

    // --- Phase 2: the UPDATE arm, driven by the OPT-IN ALONE. Both audiences exist
    //     in both environments now, so nothing but this one boolean differs.
    set_opt_in(&db, &env, source, "https://api.opted-in", false).await;
    set_opt_in(&db, &env, source, "https://api.opted-out", true).await;

    let flipped = export(&db, source).await;
    let diff = diff_snapshots(&flipped, &target_after);
    assert_eq!(
        diff.len(),
        2,
        "the opt-in alone must be a promotable difference: {diff:?}"
    );

    let plan = plan_promotion(&control(&db).scoped(target), &flipped)
        .await
        .expect("plan db")
        .expect("plan builds");
    let (actor, corr) = acting(&db, &env);
    control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &flipped, plan.base_revision(), false)
        .await
        .expect("apply the updates");

    assert!(
        !opt_in_of(&db, target, "https://api.opted-in").await,
        "the UPDATE arm must promote the opt-in OFF"
    );
    assert!(
        opt_in_of(&db, target, "https://api.opted-out").await,
        "the UPDATE arm must promote the opt-in ON"
    );
    assert!(
        diff_snapshots(&flipped, &export(&db, target).await).is_empty(),
        "the second apply must round-trip too"
    );
}

/// The exported opt-in VALIDATES against the snapshot schema's Rust mirror.
///
/// Its own test rather than more lines in the round-trip above, and it guards a
/// promotion site the round-trip cannot reach: `RESOURCE_SERVER_KEYS` in
/// `ironauth_store::snapshot` is the Rust copy of `additionalProperties: false` on
/// the published `docs/snapshot/snapshot.schema.json`. Drop the field from that list
/// and `validate_document` reports "unknown field" on the EXPORTER'S OWN OUTPUT: the
/// document stops being a legal snapshot, so no operator could submit it and the
/// whole promotion path for this resource type is dead. The apply path never calls
/// the validator, which is exactly why the round-trip test stays green under that
/// mutation and this one does not.
#[tokio::test]
async fn the_exported_permission_claim_opt_in_validates_and_round_trips() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    register_rs(&db, &env, scope, "https://api.opted-in", TokenFormat::AtJwt).await;
    set_opt_in(&db, &env, scope, "https://api.opted-in", true).await;

    let bytes = export(&db, scope)
        .await
        .to_canonical_bytes()
        .expect("canonicalize the exported snapshot");
    let parsed = validate_document(&bytes).expect("the exported snapshot must validate");
    assert_eq!(
        parsed
            .resources
            .resource_server
            .iter()
            .filter(|server| server.permission_claims_enabled)
            .count(),
        1,
        "the opt-in survives the validator"
    );
    // Validate then re-serialize is byte-identical, so the field survives a document
    // that has been through the validator rather than merely being tolerated by it.
    assert_eq!(
        bytes,
        parsed.to_canonical_bytes().expect("reserialize"),
        "the canonical snapshot must round-trip byte-identically"
    );
}

/// Migration 0094's `GRANT UPDATE (permission_claims_enabled)` is LOAD BEARING:
/// without it a config promotion that updates a resource server is refused by
/// Postgres with SQLSTATE 42501 and the whole apply fails.
///
/// The claim in the migration header is MEASURED here rather than asserted. The
/// grant is revoked on THIS test's throwaway database (`TestDatabase::start` creates
/// a fresh one per run, so no other test can see it), the apply is driven, and the
/// SQLSTATE is read off the failure. Then the grant is restored and the SAME apply is
/// driven again and succeeds, which is what rules out "the apply would have failed
/// anyway".
///
/// It also pins WHICH statement fails. The CREATE arm runs first, with the grant
/// already revoked, and SUCCEEDS, because 0035's `GRANT INSERT` is table-wide. Only
/// the column-scoped UPDATE is affected.
///
/// The source-side difference is introduced by editing the EXPORTED SNAPSHOT rather
/// than by writing the source database, deliberately: the store writer for this
/// column needs the very grant under test, so writing the source would fail for the
/// same reason and prove nothing about the apply. A snapshot is also exactly what an
/// operator promoting between environments actually submits.
#[tokio::test]
async fn the_promotion_apply_fails_42501_without_the_permission_claims_grant() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    register_rs(&db, &env, source, "https://api.example", TokenFormat::AtJwt).await;
    set_opt_in(&db, &env, source, "https://api.example", true).await;
    let source_snapshot = export(&db, source).await;

    // Revoke the grant 0094 added. The owner pool is the schema owner, so this leaves
    // the database in exactly the state an operator who applied 0035 and skipped
    // 0094 would have.
    sqlx::query(
        "REVOKE UPDATE (permission_claims_enabled) ON resource_servers FROM ironauth_control",
    )
    .execute(db.owner_pool())
    .await
    .expect("revoke the 0094 column grant");

    // The CREATE arm still works with the grant revoked: `GRANT INSERT` is table-wide.
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
        .expect("the create arm needs no column grant");
    assert!(
        opt_in_of(&db, target, "https://api.example").await,
        "the create landed the opt-in through the table-wide INSERT grant"
    );

    // Now drive the UPDATE arm, with the OPT-IN as the only difference, so the apply
    // must write the very column the grant was revoked on.
    let mut flipped = source_snapshot.clone();
    flipped.resources.resource_server[0].permission_claims_enabled = false;
    let plan = plan_promotion(&control(&db).scoped(target), &flipped)
        .await
        .expect("plan db")
        .expect("plan builds");
    assert_eq!(plan.diff().len(), 1, "exactly one update to apply");
    let (actor, corr) = acting(&db, &env);
    let error = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &flipped, plan.base_revision(), false)
        .await
        .expect_err("the update arm must be refused without the column grant");

    let PromotionApplyError::Store(store_error) = error else {
        panic!("expected a store error carrying the Postgres refusal, got {error:?}");
    };
    let sqlstate = match &store_error {
        ironauth_store::StoreError::Database(sqlx::Error::Database(database)) => database
            .code()
            .map(std::borrow::Cow::into_owned)
            .expect("the refusal carries a SQLSTATE"),
        other => panic!("expected a database error, got {other:?}"),
    };
    assert_eq!(
        sqlstate, "42501",
        "the missing column grant must surface as insufficient_privilege"
    );

    // ATOMIC: the refused apply changed nothing, so the target still reads what the
    // create landed.
    assert!(
        opt_in_of(&db, target, "https://api.example").await,
        "a refused apply must leave the target untouched"
    );

    // RESTORE the grant, and the SAME apply now succeeds. Without this half the test
    // would pass against an apply that was broken for some entirely other reason.
    sqlx::query("GRANT UPDATE (permission_claims_enabled) ON resource_servers TO ironauth_control")
        .execute(db.owner_pool())
        .await
        .expect("restore the 0094 column grant");

    let plan = plan_promotion(&control(&db).scoped(target), &flipped)
        .await
        .expect("plan db")
        .expect("plan builds");
    let (actor, corr) = acting(&db, &env);
    control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &flipped, plan.base_revision(), false)
        .await
        .expect("with the grant restored the same apply succeeds");
    assert!(
        !opt_in_of(&db, target, "https://api.example").await,
        "the restored grant lets the update land"
    );
}

// ===========================================================================
// Branding, localization, and signup fields (issue #475).
//
// M9's second exit criterion promises these three are "per-environment config,
// promotable via snapshots". They were in the snapshot EXPORT and absent from the
// promotion ENGINE, and this file had zero occurrences of `brand`, `locale` or
// `signup`, which is why nothing failed. Everything below drives a REAL promotion
// through plan + apply against a live database.
// ===========================================================================

/// A valid serialized design-token blob (the typed scalars the branding module validates).
const TOKENS_JSON: &str = r##"{"color_bg":"#f5f5f5","color_fg":"#1a1a1a","color_accent":"#2f5bde","color_accent_fg":"#ffffff","color_error":"#b00020","color_surface":"#ffffff","color_border":"#bbbbbb","font_family":"system_ui","radius":6,"space":16}"##;

/// A second, DIFFERENT token blob, so an update can be driven by the tokens alone.
const TOKENS_JSON_ALT: &str = r##"{"color_bg":"#000000","color_fg":"#ffffff","color_accent":"#2f5bde","color_accent_fg":"#ffffff","color_error":"#b00020","color_surface":"#ffffff","color_border":"#bbbbbb","font_family":"system_ui","radius":6,"space":16}"##;

/// A sanitized slot blob (already allowlist-sanitized markup, as the ingest path stores it).
const SLOTS_JSON: &str = r#"{"footer_legal":"<strong>Legal</strong>"}"#;

/// The smallest byte string the store accepts as a brand asset payload. Its exact content is
/// irrelevant (the store stores what the admin path already sniffed); what matters is that two
/// tests can produce the SAME bytes, so a digest resolves, or DIFFERENT bytes, so it does not.
fn asset_bytes(marker: u8) -> Vec<u8> {
    let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.push(marker);
    bytes
}

/// The lowercase hex sha256 of `bytes`, the content reference a snapshot carries.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Set a brand in `scope` (control plane), returning nothing: the slug is the natural key.
#[allow(clippy::too_many_arguments)]
async fn set_brand(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    slug: &str,
    is_default: bool,
    product_name: &str,
    tokens_json: &str,
    host_pattern: Option<&str>,
    client_id: Option<&str>,
) {
    let id = BrandId::generate(env, &scope);
    let (actor, corr) = acting(db, env);
    db.control_store()
        .scoped(scope)
        .acting(actor, corr)
        .brands()
        .set(
            env,
            &id,
            1_000_000,
            NewBrand {
                slug,
                is_default,
                product_name,
                show_wordmark: true,
                brand_token: None,
                tokens_json,
                tokens_dark_json: None,
                slots_json: SLOTS_JSON,
                host_pattern,
                client_id,
            },
        )
        .await
        .expect("set brand");
}

/// The simple brand fixture most tests want: no selection keys, non-default.
async fn set_simple_brand(db: &TestDatabase, env: &Env, scope: Scope, slug: &str, name: &str) {
    set_brand(db, env, scope, slug, false, name, TOKENS_JSON, None, None).await;
}

/// Install a brand asset in `scope` (control plane).
async fn set_asset(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    slug: &str,
    kind: BrandAssetKind,
    bytes: &[u8],
) {
    let brand = control(db)
        .scoped(scope)
        .brands()
        .get(slug)
        .await
        .expect("get brand")
        .expect("brand exists");
    let brand_id = BrandId::parse_in_scope(&brand.id, &scope).expect("in scope");
    let (actor, corr) = acting(db, env);
    db.control_store()
        .scoped(scope)
        .acting(actor, corr)
        .brand_assets()
        .set(
            env,
            &brand_id,
            1_000_000,
            NewBrandAsset {
                brand_slug: slug,
                kind,
                content_type: "image/png",
                bytes,
                sha256: &sha256_hex(bytes),
                size_bytes: i32::try_from(bytes.len()).expect("small"),
            },
        )
        .await
        .expect("set brand asset");
}

/// Set a locale bundle in `scope` (control plane).
async fn set_locale(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    locale: &str,
    is_env_default: bool,
    entries_json: &str,
) {
    let id = LocaleBundleId::generate(env, &scope);
    let (actor, corr) = acting(db, env);
    db.control_store()
        .scoped(scope)
        .acting(actor, corr)
        .locale_bundles()
        .set(
            env,
            &id,
            1_000_000,
            NewLocaleBundle {
                locale,
                is_env_default,
                entries_json,
            },
        )
        .await
        .expect("set locale bundle");
}

/// Set a signup form in `scope` (control plane), keyed on `client_id`.
async fn set_signup_form(db: &TestDatabase, env: &Env, scope: Scope, client_id: &str) {
    let id = SignupFormId::generate(env, &scope);
    let (actor, corr) = acting(db, env);
    db.control_store()
        .scoped(scope)
        .acting(actor, corr)
        .signup_forms()
        .set(
            env,
            &id,
            1_000_000,
            NewSignupForm {
                client_id,
                fields_json: "[]",
            },
        )
        .await
        .expect("set signup form");
}

/// A scope's brands, ordered by slug (control plane).
async fn brands_of(db: &TestDatabase, scope: Scope) -> Vec<ironauth_store::BrandRecord> {
    control(db)
        .scoped(scope)
        .brands()
        .list_all()
        .await
        .expect("list brands")
}

/// A scope's locale bundles, ordered by tag (control plane).
async fn locales_of(db: &TestDatabase, scope: Scope) -> Vec<ironauth_store::LocaleBundleRecord> {
    control(db)
        .scoped(scope)
        .locale_bundles()
        .list_all()
        .await
        .expect("list locale bundles")
}

/// Plan and apply `source` onto `target`, expecting success.
async fn promote(
    db: &TestDatabase,
    env: &Env,
    target: Scope,
    source_snapshot: &Snapshot,
) -> PromotionOutcome {
    let plan = plan_promotion(&control(db).scoped(target), source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    let (actor, corr) = acting(db, env);
    control(db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(env, source_snapshot, plan.base_revision(), false)
        .await
        .expect("apply")
}

/// A promotion CARRIES a brand and a locale bundle end to end, and re-applying is a no-op.
///
/// This is the criterion M9 promised and the engine did not implement: before issue #475 the
/// plan for this fixture was EMPTY (`brand` and `locale_bundle` were emptied by the promoted
/// projection), the apply was a no-op, and the target ended with no branding and no locales.
#[tokio::test]
async fn a_promotion_carries_branding_and_locales_and_is_idempotent() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    set_brand(
        &db,
        &env,
        source,
        "acme",
        true,
        "Acme",
        TOKENS_JSON,
        Some("login.acme.test"),
        None,
    )
    .await;
    set_locale(&db, &env, source, "fr", true, r#"{"1":"Bonjour"}"#).await;
    set_locale(&db, &env, source, "de", false, r#"{"1":"Hallo"}"#).await;

    let source_snapshot = export(&db, source).await;

    // PLAN: one create per promoted resource (one brand, two locale bundles).
    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    assert_eq!(
        plan.diff().len(),
        3,
        "one brand and two locale bundles must be enumerated: {:?}",
        plan.diff().changes()
    );

    let (actor, corr) = acting(&db, &env);
    let outcome = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .expect("apply");
    assert!(matches!(outcome, PromotionOutcome::Applied(_)));

    // The BRAND landed, whole: the wordmark, the typed tokens, the sanitized slots, the
    // env-default flag, and the per-domain selection key.
    let brands = brands_of(&db, target).await;
    assert_eq!(brands.len(), 1, "the brand must have been created");
    assert_eq!(brands[0].slug, "acme");
    assert_eq!(brands[0].product_name, "Acme");
    assert!(brands[0].is_default, "the env-default flag promotes");
    assert_eq!(brands[0].host_pattern.as_deref(), Some("login.acme.test"));
    assert!(brands[0].tokens_json.contains("#f5f5f5"), "tokens promote");
    assert!(brands[0].slots_json.contains("Legal"), "slots promote");

    // Both LOCALE BUNDLES landed, with the env-default flag on the right one.
    let locales = locales_of(&db, target).await;
    assert_eq!(locales.len(), 2);
    let fr = locales
        .iter()
        .find(|bundle| bundle.locale == "fr")
        .expect("fr promoted");
    assert!(
        fr.is_env_default,
        "the env-default bundle promotes as default"
    );
    assert!(fr.entries_json.contains("Bonjour"), "entries promote");
    let de = locales
        .iter()
        .find(|bundle| bundle.locale == "de")
        .expect("de promoted");
    assert!(!de.is_env_default);

    // ROUND TRIP: re-diffing the source against the target is empty.
    let target_after = export(&db, target).await;
    assert!(
        diff_snapshots(&source_snapshot, &target_after).is_empty(),
        "apply then re-diff must be empty: {:?}",
        diff_snapshots(&source_snapshot, &target_after).changes()
    );

    // IDEMPOTENT: re-applying changes nothing and writes no second audit row.
    let audits = apply_audit_count(&db, target).await;
    let again = promote(&db, &env, target, &source_snapshot).await;
    assert_eq!(again, PromotionOutcome::NoOp, "re-apply is a no-op");
    assert_eq!(apply_audit_count(&db, target).await, audits);
}

/// A promotion UPDATES and DELETES branding and locales, not just creates them.
#[tokio::test]
async fn a_promotion_updates_and_deletes_branding_and_locales() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    // The source keeps `acme` (with different tokens) and `fr` (reworded); the target
    // additionally carries a brand and a bundle the source does not.
    set_simple_brand(&db, &env, source, "acme", "Acme").await;
    set_locale(&db, &env, source, "fr", false, r#"{"1":"Bonjour"}"#).await;

    set_brand(
        &db,
        &env,
        target,
        "acme",
        false,
        "Stale",
        TOKENS_JSON_ALT,
        None,
        None,
    )
    .await;
    set_simple_brand(&db, &env, target, "obsolete", "Gone").await;
    set_locale(&db, &env, target, "fr", false, r#"{"1":"Salut"}"#).await;
    set_locale(&db, &env, target, "es", false, r#"{"1":"Hola"}"#).await;

    let source_snapshot = export(&db, source).await;
    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    // acme update, obsolete delete, fr update, es delete.
    assert_eq!(plan.diff().len(), 4, "{:?}", plan.diff().changes());

    let (actor, corr) = acting(&db, &env);
    control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .expect("apply");

    let brands = brands_of(&db, target).await;
    assert_eq!(brands.len(), 1, "the target-only brand is deleted");
    assert_eq!(brands[0].slug, "acme");
    assert_eq!(brands[0].product_name, "Acme", "the brand is updated");
    assert!(brands[0].tokens_json.contains("#f5f5f5"), "tokens updated");

    let locales = locales_of(&db, target).await;
    assert_eq!(locales.len(), 1, "the target-only bundle is deleted");
    assert_eq!(locales[0].locale, "fr");
    assert!(locales[0].entries_json.contains("Bonjour"));
}

/// NORMALIZATION, asserted as behaviour: a promotion NEVER moves a brand's per-CLIENT
/// selection key, and never moves it into the diff either.
///
/// A `client_id` is a scope-embedded identifier, so a source key can never match in the
/// target; worse, writing it would overwrite the target admin's own per-client selection with
/// a value that selects nothing. This is the brand analogue of the custom-journey activation
/// gate, and it is measured here the same way: the diff is empty, the apply is a no-op, and the
/// target's own key SURVIVES.
#[tokio::test]
async fn a_promotion_never_moves_the_brand_per_client_selection_key() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    // Two real clients, one per environment. Their ids differ BY CONSTRUCTION (a ClientId
    // embeds its (tenant, environment)), which is the whole reason for the normalization.
    create_client(&db, &env, source, "source app").await;
    create_client(&db, &env, target, "target app").await;
    let source_client = only_client_id(&db, source).await;
    let target_client = only_client_id(&db, target).await;
    assert_ne!(
        source_client, target_client,
        "a client id embeds its environment, so the two can never coincide"
    );

    set_brand(
        &db,
        &env,
        source,
        "acme",
        false,
        "Acme",
        TOKENS_JSON,
        None,
        Some(&source_client),
    )
    .await;
    set_brand(
        &db,
        &env,
        target,
        "acme",
        false,
        "Acme",
        TOKENS_JSON,
        None,
        Some(&target_client),
    )
    .await;

    // The two brands differ ONLY in the per-client key, so the diff is EMPTY and the apply is
    // an idempotent no-op. If the key entered the projection this would be an update.
    let source_snapshot = export(&db, source).await;
    let outcome = promote(&db, &env, target, &source_snapshot).await;
    assert_eq!(
        outcome,
        PromotionOutcome::NoOp,
        "a difference in the per-client selection key alone is not a promotable change"
    );

    // The target's OWN key survives untouched: the promotion did not overwrite it with the
    // source's (which could never match here anyway).
    let brands = brands_of(&db, target).await;
    assert_eq!(brands[0].client_id.as_deref(), Some(target_client.as_str()));

    // And the CONTROL: a promotable field difference in the same brand IS an update, so the
    // no-op above is the normalization, not a promotion that carries nothing.
    set_brand(
        &db,
        &env,
        source,
        "acme",
        false,
        "Globex",
        TOKENS_JSON,
        None,
        Some(&source_client),
    )
    .await;
    let renamed = export(&db, source).await;
    let outcome = promote(&db, &env, target, &renamed).await;
    assert!(matches!(outcome, PromotionOutcome::Applied(_)));
    let brands = brands_of(&db, target).await;
    assert_eq!(brands[0].product_name, "Globex");
    assert_eq!(
        brands[0].client_id.as_deref(),
        Some(target_client.as_str()),
        "even an update that DOES land must leave the per-client key alone"
    );
}

/// A promoted default brand DEMOTES the target's previous default rather than colliding with
/// the one-default-per-scope partial unique index.
///
/// The ORDERING here is the whole test, and getting it wrong makes the test vacuous. Changes
/// apply in natural-key order, so if the target's outgoing default sorts BEFORE the source's
/// incoming one, the diff demotes it on its own and the apply's demotion step is never
/// load-bearing (MEASURED: with that ordering, deleting the demotion step left this test green).
/// The source's default therefore sorts FIRST here, so at the moment it is written the target's
/// old default is still set and `brands_default_idx` would refuse the write outright.
#[tokio::test]
async fn a_promoted_default_brand_demotes_the_targets_previous_default() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    // `alpha` (the source's default) sorts BEFORE `zulu` (the target's), so `alpha` is written
    // while `zulu` is still the target's default.
    set_brand(
        &db,
        &env,
        source,
        "alpha",
        true,
        "Alpha",
        TOKENS_JSON,
        None,
        None,
    )
    .await;
    set_brand(
        &db,
        &env,
        source,
        "zulu",
        false,
        "Zulu",
        TOKENS_JSON,
        None,
        None,
    )
    .await;
    set_brand(
        &db,
        &env,
        target,
        "zulu",
        true,
        "Zulu",
        TOKENS_JSON,
        None,
        None,
    )
    .await;

    let source_snapshot = export(&db, source).await;
    let outcome = promote(&db, &env, target, &source_snapshot).await;
    assert!(matches!(outcome, PromotionOutcome::Applied(_)));

    let brands = brands_of(&db, target).await;
    let defaults: Vec<&str> = brands
        .iter()
        .filter(|brand| brand.is_default)
        .map(|brand| brand.slug.as_str())
        .collect();
    assert_eq!(
        defaults,
        vec!["alpha"],
        "exactly the source's default is default in the target"
    );
    // The promotion converges, which it could not if the write had been refused.
    let target_after = export(&db, target).await;
    assert!(diff_snapshots(&source_snapshot, &target_after).is_empty());
}

/// The same, for locale bundles, whose one-default-per-scope index is the identical shape and
/// whose apply needs the identical demotion step. Same ordering discipline: the source's
/// default (`ar`) sorts BEFORE the target's outgoing one (`de`).
#[tokio::test]
async fn a_promoted_default_locale_demotes_the_targets_previous_default() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    set_locale(&db, &env, source, "ar", true, r#"{"1":"Marhaba"}"#).await;
    set_locale(&db, &env, source, "de", false, r#"{"1":"Hallo"}"#).await;
    set_locale(&db, &env, target, "de", true, r#"{"1":"Hallo"}"#).await;

    let source_snapshot = export(&db, source).await;
    let outcome = promote(&db, &env, target, &source_snapshot).await;
    assert!(matches!(outcome, PromotionOutcome::Applied(_)));

    let target_locales = locales_of(&db, target).await;
    let defaults: Vec<&str> = target_locales
        .iter()
        .filter(|bundle| bundle.is_env_default)
        .map(|bundle| bundle.locale.as_str())
        .collect();
    assert_eq!(defaults, vec!["ar"]);
    let target_after = export(&db, target).await;
    assert!(diff_snapshots(&source_snapshot, &target_after).is_empty());
}

/// BRAND ASSET BYTES: a promoted brand whose asset bytes the target does NOT hold fails
/// CLOSED, and the whole promotion rolls back.
///
/// A snapshot carries an asset by content reference (its sha256), never as inline bytes, so
/// there is simply no source for bytes the target lacks. Refusing is the only honest outcome:
/// the alternatives are metadata pointing at nothing, or binding the promoted brand to whatever
/// different image the target happens to hold.
#[tokio::test]
async fn a_promoted_brand_asset_fails_closed_when_the_target_lacks_the_bytes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    set_simple_brand(&db, &env, source, "acme", "Acme").await;
    set_asset(
        &db,
        &env,
        source,
        "acme",
        BrandAssetKind::Logo,
        &asset_bytes(1),
    )
    .await;
    // A second promotable resource, so the rollback has something visible to undo.
    set_var(&db, &env, source, "flag", "on").await;

    let source_snapshot = export(&db, source).await;
    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    let (actor, corr) = acting(&db, &env);
    let error = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .expect_err("the target holds no bytes with that digest");
    match error {
        PromotionApplyError::BrandAssetBytesUnavailable { slug, kind, sha256 } => {
            assert_eq!(slug, "acme");
            assert_eq!(kind, "logo");
            assert_eq!(sha256, sha256_hex(&asset_bytes(1)));
        }
        other => panic!("expected a fail-closed asset refusal, got {other:?}"),
    }

    // ATOMIC: nothing landed, not even the brand row or the unrelated variable.
    assert!(
        brands_of(&db, target).await.is_empty(),
        "a refused apply must leave the target untouched"
    );
    assert!(
        export(&db, target).await.resources.variable.is_empty(),
        "the unrelated variable must have rolled back too"
    );
    assert_eq!(apply_audit_count(&db, target).await, 0);
}

/// BRAND ASSET BYTES, the resolving half: once the TARGET holds bytes with the promoted
/// digest, the promotion binds them to the promoted brand and round-trips.
///
/// This is the documented operator remedy for the refusal above, driven end to end. Without
/// this half the fail-closed test could pass against an apply that refuses everything.
#[tokio::test]
async fn a_promoted_brand_asset_resolves_against_bytes_the_target_already_holds() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    set_simple_brand(&db, &env, source, "acme", "Acme").await;
    set_asset(
        &db,
        &env,
        source,
        "acme",
        BrandAssetKind::Logo,
        &asset_bytes(1),
    )
    .await;

    // The operator's remedy: create the brand in the TARGET and upload the same bytes, here
    // under a DIFFERENT kind, so the resolution is genuinely content-addressed rather than a
    // (slug, kind) coincidence.
    set_simple_brand(&db, &env, target, "acme", "Acme").await;
    set_asset(
        &db,
        &env,
        target,
        "acme",
        BrandAssetKind::Favicon,
        &asset_bytes(1),
    )
    .await;

    let source_snapshot = export(&db, source).await;
    let outcome = promote(&db, &env, target, &source_snapshot).await;
    assert!(matches!(outcome, PromotionOutcome::Applied(_)));

    // The logo is now bound in the target, with the SOURCE's digest, from the target's bytes.
    let logo = control(&db)
        .scoped(target)
        .brands()
        .get_asset("acme", BrandAssetKind::Logo)
        .await
        .expect("get asset")
        .expect("the promoted logo is bound");
    assert_eq!(logo.sha256, sha256_hex(&asset_bytes(1)));
    assert_eq!(logo.bytes, asset_bytes(1));

    // The favicon the source does not carry is REMOVED, so the target matches the source.
    assert!(
        control(&db)
            .scoped(target)
            .brands()
            .get_asset("acme", BrandAssetKind::Favicon)
            .await
            .expect("get asset")
            .is_none(),
        "an asset kind the source dropped does not survive the promotion"
    );

    // ROUND TRIP and IDEMPOTENCE, which is what proves the resolved metadata reproduces the
    // source's exactly rather than approximately.
    let target_after = export(&db, target).await;
    assert!(
        diff_snapshots(&source_snapshot, &target_after).is_empty(),
        "{:?}",
        diff_snapshots(&source_snapshot, &target_after).changes()
    );
    assert_eq!(
        promote(&db, &env, target, &source_snapshot).await,
        PromotionOutcome::NoOp
    );
}

/// A promoted brand DELETE removes the brand's assets with it, so no orphaned bytes survive to
/// be inherited by a later brand of the same slug.
#[tokio::test]
async fn a_promoted_brand_delete_sweeps_the_brands_assets() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    // The source has no brands; the target has one, with an asset.
    set_var(&db, &env, source, "flag", "on").await;
    set_simple_brand(&db, &env, target, "acme", "Acme").await;
    set_asset(
        &db,
        &env,
        target,
        "acme",
        BrandAssetKind::Logo,
        &asset_bytes(2),
    )
    .await;

    let source_snapshot = export(&db, source).await;
    promote(&db, &env, target, &source_snapshot).await;

    assert!(brands_of(&db, target).await.is_empty());
    assert!(
        control(&db)
            .scoped(target)
            .brands()
            .list_all_asset_metadata()
            .await
            .expect("list asset metadata")
            .is_empty(),
        "the deleted brand's assets go with it"
    );
}

/// SIGNUP FORMS: the measured reason the engine does NOT promote them.
///
/// A signup form's natural key is an authorize `client_id`, and a `ClientId` embeds its
/// `(tenant, environment)`. This drives the measurement rather than describing it: the source's
/// key does not parse in the target scope, so it can address nothing there; a promotion
/// therefore leaves the target's forms EXACTLY as they were, rather than creating a row for a
/// client that cannot exist and deleting the target's own form. That is the same exclusion
/// `client` carries, for the same reason, and lifting it needs a stable scope-independent
/// public client identity (an owner-level snapshot-format decision).
#[tokio::test]
async fn the_signup_form_key_is_a_scope_embedded_client_id_so_it_cannot_address_the_target() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    create_client(&db, &env, source, "source app").await;
    create_client(&db, &env, target, "target app").await;
    let source_client = only_client_id(&db, source).await;
    let target_client = only_client_id(&db, target).await;

    // THE MEASUREMENT: the source's form key cannot be addressed in the target at all.
    assert!(
        ironauth_store::ClientId::parse_in_scope(&source_client, &target).is_err(),
        "a source-environment client id is a uniform not-found under the target scope, so a \
         signup form keyed on it could name nothing there"
    );

    set_signup_form(&db, &env, source, &source_client).await;
    set_signup_form(&db, &env, target, &target_client).await;

    // The EXPORT carries the form (it is promotable config and reviewable)...
    let source_snapshot = export(&db, source).await;
    assert_eq!(
        source_snapshot.resources.signup_form.len(),
        1,
        "the snapshot export still carries the form"
    );

    // ...but the promotion ENGINE leaves the target's forms exactly as they were: no create of
    // a dead row for the source's client, and no delete of the target's own form.
    let outcome = promote(&db, &env, target, &source_snapshot).await;
    assert_eq!(
        outcome,
        PromotionOutcome::NoOp,
        "signup forms are outside the promotable revision entirely"
    );
    let forms = control(&db)
        .scoped(target)
        .signup_forms()
        .list_all()
        .await
        .expect("list signup forms");
    assert_eq!(forms.len(), 1, "the target's own form survives");
    assert_eq!(forms[0].client_id, target_client);
}

/// A promoted `host_pattern` is CANONICALIZED, so the per-scope unique index can see that two
/// spellings are one host claim.
///
/// `brands_host_pattern_idx` is a partial unique index on the RAW column, and the management
/// writer folds the key at ingest so the index sees one spelling per host. A promotion is the
/// SECOND writer of that column. Before this fold, a submitted document carrying
/// `LOGIN.Acme.Test:8443` landed verbatim beside a stored `login.acme.test`, the index could not
/// tell they were the same host, and `select_brand` (which normalizes both sides before
/// comparing) resolved BOTH for the same request. That falsifies the "first match is also the
/// only match" property the selection order rests on, and the migration's own
/// routing-confusion defense with it.
///
/// The document is EDITED rather than seeded, deliberately: the store writer folds at ingest, so
/// only a submitted document can reach the apply with a non-canonical spelling, and a submitted
/// document is exactly what an operator promotes.
///
/// The second half is the invariant itself rather than a restatement of the first: with the key
/// stored canonically, a second brand claiming that host is REFUSED by the index. Against the
/// unfolded apply that write succeeded, which is the routing confusion.
#[tokio::test]
async fn a_promoted_host_pattern_is_canonicalized_so_the_uniqueness_index_can_see_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    set_brand(
        &db,
        &env,
        source,
        "acme",
        false,
        "Acme",
        TOKENS_JSON,
        Some("login.acme.test"),
        None,
    )
    .await;

    let mut source_snapshot = export(&db, source).await;
    source_snapshot.resources.brand[0].host_pattern = Some("  LOGIN.Acme.Test:8443 ".to_owned());

    let outcome = promote(&db, &env, target, &source_snapshot).await;
    assert!(matches!(outcome, PromotionOutcome::Applied(_)));

    let brands = brands_of(&db, target).await;
    assert_eq!(brands.len(), 1);
    assert_eq!(
        brands[0].host_pattern.as_deref(),
        Some("login.acme.test"),
        "the promoted host key must be stored in the canonical form the index and the \
         selection matcher both key on"
    );

    // THE INVARIANT: one host selects at most one brand in this environment.
    let second = BrandId::generate(&env, &target);
    let (actor, corr) = acting(&db, &env);
    let refused = db
        .control_store()
        .scoped(target)
        .acting(actor, corr)
        .brands()
        .set(
            &env,
            &second,
            1_000_000,
            NewBrand {
                slug: "other",
                is_default: false,
                product_name: "Other",
                show_wordmark: true,
                brand_token: None,
                tokens_json: TOKENS_JSON,
                tokens_dark_json: None,
                slots_json: SLOTS_JSON,
                host_pattern: Some("login.acme.test"),
                client_id: None,
            },
        )
        .await;
    assert!(
        refused.is_err(),
        "a second brand claiming the promoted host must be refused by \
         brands_host_pattern_idx; if it is accepted, two brands resolve for one request"
    );

    // CONVERGENCE: the fold happens in the projection too, so the diff reads the same key the
    // apply stored. Folding only at the bind would re-propose this update on every plan.
    let target_after = export(&db, target).await;
    assert!(
        diff_snapshots(&source_snapshot, &target_after).is_empty(),
        "the promotion must converge: {:?}",
        diff_snapshots(&source_snapshot, &target_after).changes()
    );
    assert_eq!(
        promote(&db, &env, target, &source_snapshot).await,
        PromotionOutcome::NoOp
    );
}

/// Seed a target holding `held_slug` on host `h.test`, promote a source holding `taken_slug` on
/// the same host, and assert the claim MOVED cleanly. `held_slug` is absent from the source, so
/// its change is a Delete; changes apply in natural-key order, so passing the two slugs in each
/// order drives the create-before-delete case and the delete-before-create case.
async fn promote_a_host_claim_between_slugs(taken_slug: &str, held_slug: &str) {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    set_brand(
        &db,
        &env,
        source,
        taken_slug,
        false,
        "Taken",
        TOKENS_JSON,
        Some("h.test"),
        None,
    )
    .await;
    set_brand(
        &db,
        &env,
        target,
        held_slug,
        false,
        "Held",
        TOKENS_JSON,
        Some("h.test"),
        None,
    )
    .await;

    let source_snapshot = export(&db, source).await;
    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    let (actor, corr) = acting(&db, &env);
    let outcome = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "promoting {taken_slug} over {held_slug} must apply, not abort: {error}. Whether \
                 the previous claimant is deleted before or after the new one is created is only \
                 an artifact of how the two slugs sort"
            )
        });
    assert!(matches!(outcome, PromotionOutcome::Applied(_)));

    let brands = brands_of(&db, target).await;
    assert_eq!(brands.len(), 1, "the target-only brand is deleted");
    assert_eq!(brands[0].slug, taken_slug);
    assert_eq!(brands[0].host_pattern.as_deref(), Some("h.test"));
    let target_after = export(&db, target).await;
    assert!(
        diff_snapshots(&source_snapshot, &target_after).is_empty(),
        "{:?}",
        diff_snapshots(&source_snapshot, &target_after).changes()
    );
}

/// A promoted host claim RELEASES the target's previous claimant, in EITHER slug order.
///
/// `brands_host_pattern_idx` is a partial unique index of exactly the same shape as
/// `brands_default_idx`, which the apply already demotes for, and it was missed. Changes apply
/// in natural-key order, so without a release step the outcome depended on how the slugs
/// happened to sort: `aaa` created before `zzz` was deleted raised
/// `23505 duplicate key value violates unique constraint "brands_host_pattern_idx"`, which the
/// management surface renders as an opaque 500 on a well formed plan, while the identical
/// logical promotion with the slugs swapped (so the delete ran first) succeeded. Both orders are
/// driven here, so the passing one is the control that rules out "it refuses everything".
#[tokio::test]
async fn a_promoted_host_claim_is_released_whatever_the_slug_order() {
    // The new claimant sorts FIRST, so it is created while the old one still holds the host.
    promote_a_host_claim_between_slugs("aaa", "zzz").await;
    // The old claimant sorts first, so its delete releases the host before the create.
    promote_a_host_claim_between_slugs("zzz", "aaa").await;
}

/// Two brands SWAP host patterns in one promotion, which NO key ordering can resolve without a
/// release step: both brands are present on both sides, so there is no delete to free either
/// host, and whichever brand is written first collides with the other's existing claim.
///
/// This is the case that makes the release necessary rather than merely convenient. Without it
/// the promotion is unconvergeable: every re-plan produces the same two updates and every apply
/// raises the same 23505, so an operator cannot land it at all without manual surgery in the
/// target database.
#[tokio::test]
async fn two_brands_can_swap_host_patterns_in_one_promotion() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    for (scope, first_host, second_host) in [
        (source, "second.test", "first.test"),
        (target, "first.test", "second.test"),
    ] {
        set_brand(
            &db,
            &env,
            scope,
            "aaa",
            false,
            "A",
            TOKENS_JSON,
            Some(first_host),
            None,
        )
        .await;
        set_brand(
            &db,
            &env,
            scope,
            "bbb",
            false,
            "B",
            TOKENS_JSON,
            Some(second_host),
            None,
        )
        .await;
    }

    let source_snapshot = export(&db, source).await;
    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    assert_eq!(
        plan.diff().len(),
        2,
        "both brands change: {:?}",
        plan.diff()
    );
    let (actor, corr) = acting(&db, &env);
    let outcome = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .unwrap_or_else(|error| panic!("a host swap must apply: {error}"));
    assert!(matches!(outcome, PromotionOutcome::Applied(_)));

    let brands = brands_of(&db, target).await;
    let claim = |slug: &str| {
        brands
            .iter()
            .find(|brand| brand.slug == slug)
            .and_then(|brand| brand.host_pattern.clone())
    };
    assert_eq!(claim("aaa").as_deref(), Some("second.test"));
    assert_eq!(claim("bbb").as_deref(), Some("first.test"));
    let target_after = export(&db, target).await;
    assert!(
        diff_snapshots(&source_snapshot, &target_after).is_empty(),
        "{:?}",
        diff_snapshots(&source_snapshot, &target_after).changes()
    );
}

/// Promote a source whose only brand is `kept_slug` (carrying a logo) onto a target whose only
/// brand is `dropped_slug` (holding exactly those bytes). The target's brand is absent from the
/// source, so its change is a Delete, which sweeps its asset rows; the two slugs decide whether
/// that sweep runs before or after the digest is resolved.
async fn promote_a_rename_that_keeps_its_logo(kept_slug: &str, dropped_slug: &str) {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let source = db.seed_scope(&env).await;
    let target = Scope::new(
        source.tenant(),
        db.seed_environment(&env, source.tenant()).await,
    );

    set_simple_brand(&db, &env, source, kept_slug, "Kept").await;
    set_asset(
        &db,
        &env,
        source,
        kept_slug,
        BrandAssetKind::Logo,
        &asset_bytes(7),
    )
    .await;

    // The target already holds exactly those bytes, under the brand the promotion removes: the
    // operator DID upload the asset, which is what makes a refusal here false.
    set_simple_brand(&db, &env, target, dropped_slug, "Dropped").await;
    set_asset(
        &db,
        &env,
        target,
        dropped_slug,
        BrandAssetKind::Logo,
        &asset_bytes(7),
    )
    .await;

    let source_snapshot = export(&db, source).await;
    let plan = plan_promotion(&control(&db).scoped(target), &source_snapshot)
        .await
        .expect("plan db")
        .expect("plan builds");
    let (actor, corr) = acting(&db, &env);
    let outcome = control(&db)
        .scoped(target)
        .acting(actor, corr)
        .apply_promotion(&env, &source_snapshot, plan.base_revision(), false)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "renaming {dropped_slug} to {kept_slug} while keeping its logo must apply: \
                 {error}. The bytes are present in the target, so a refusal telling the operator \
                 to upload them is FALSE, and whether it happens is only an artifact of how the \
                 two slugs sort"
            )
        });
    assert!(matches!(outcome, PromotionOutcome::Applied(_)));

    let logo = control(&db)
        .scoped(target)
        .brands()
        .get_asset(kept_slug, BrandAssetKind::Logo)
        .await
        .expect("get asset")
        .expect("the renamed brand keeps its logo");
    assert_eq!(logo.bytes, asset_bytes(7));
    assert_eq!(logo.sha256, sha256_hex(&asset_bytes(7)));
    assert!(
        brands_of(&db, target)
            .await
            .iter()
            .all(|brand| brand.slug == kept_slug),
        "the source's brand set is what the target ends with"
    );
}

/// A brand RENAME that keeps its logo applies in EITHER slug order.
///
/// Asset bytes are resolved by content reference against `brand_assets` as it stands, and a
/// brand delete inside the same apply loop sweeps the departing brand's asset rows. Resolving
/// per brand inside that loop therefore made the refusal order dependent AND false: when the
/// donor slug sorted first the apply raised `BrandAssetBytesUnavailable` and told the operator
/// to upload an asset they had already uploaded, while the identical promotion with the slugs
/// swapped succeeded. Resolving every digest up front, before any change is applied, is also
/// what makes the error's own documented contract ("nothing was changed", "upload it and
/// re-plan") true. Both orders are driven so the passing one is the control.
#[tokio::test]
async fn a_promoted_brand_rename_keeps_its_logo_whatever_the_slug_order() {
    // The donor sorts FIRST, so its sweep would run before the digest is resolved.
    promote_a_rename_that_keeps_its_logo("zzz", "aaa").await;
    // The donor sorts last: this direction already worked, and is the control.
    promote_a_rename_that_keeps_its_logo("aaa", "zzz").await;
}
