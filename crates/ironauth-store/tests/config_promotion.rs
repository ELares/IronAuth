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
    ActorRef, CorrelationId, DcrPolicyId, FlowVersionRecord, FlowVersionSnapshot, NewDcrPolicy,
    NewFlowVersion, NewResourceServer, PromotionApplyError, PromotionOutcome, Reference, Resolved,
    ResourceServerId, SNAPSHOT_SCHEMA_VERSION, Scope, Snapshot, SnapshotResources, Store,
    TokenFormat, VariableSnapshot, diff_snapshots, export_snapshot, plan_promotion,
    promotion_revision, resolve_value,
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
