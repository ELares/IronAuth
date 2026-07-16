// SPDX-License-Identifier: MIT OR Apache-2.0

//! Migrations as an invariant-checked state machine (issue #59), over a real
//! database (`DATABASE_URL`).
//!
//! Pins the acceptance-critical properties: a migration cannot transition to
//! `complete` while ANY invariant is violated, and the API names the violated
//! invariants and the offending records; the count invariant detects an injected
//! off-by-N discrepancy and blocks; a missing backfill sentinel blocks; the state
//! and its invariant verdicts SURVIVE a process restart and are RE-EVALUATED (not
//! read from a cached verdict); abandonment is an explicit audited transition; and a
//! property over transition sequences: no sequence reaches `complete` while an
//! invariant evaluator returns violations. The machine is applied to two concrete
//! kinds here: a schema migration job (issue #53) end to end, and a synthetic
//! bulk-import-shaped run (the streaming import wrap is exercised in
//! `ironauth-import`).

use std::collections::HashSet;
use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CompletionOutcome, CorrelationId, InvariantKind, MigrationKind, MigrationRecordOutcome,
    MigrationRunId, MigrationState, NewAdminUser, NewMigrationRun, NewTraitMigrationJob,
    RecordOutcomeInput, Scope, Store, StoreError, TraitJobKind, UserState,
};
use serde_json::json;
use sqlx::Row;

const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";
const NOW_MICROS: i64 = 1_000_000;

/// Define a run, returning its id.
async fn create_run(
    store: &Store,
    env: &Env,
    scope: Scope,
    kind: MigrationKind,
    source_total: i64,
    backfill_expected: i64,
) -> MigrationRunId {
    store
        .scoped(scope)
        .acting(actor(store, env, scope), CorrelationId::generate(env))
        .migration_runs()
        .create(
            env,
            NewMigrationRun {
                kind,
                source_total,
                backfill_expected,
                subject_ref: None,
            },
            NOW_MICROS,
        )
        .await
        .expect("create run")
}

/// A throwaway actor for a scope.
fn actor(store: &Store, env: &Env, _scope: Scope) -> ironauth_store::ActorRef {
    let _ = store;
    ironauth_store::ActorRef::human(ironauth_store::HumanId::generate(env))
}

/// Drive a fresh run through defined -> validating -> running.
async fn drive_to_running(store: &Store, env: &Env, scope: Scope, run: &MigrationRunId) {
    let repo = store
        .scoped(scope)
        .acting(actor(store, env, scope), CorrelationId::generate(env));
    repo.migration_runs()
        .transition(env, run, MigrationState::Validating)
        .await
        .expect("-> validating");
    repo.migration_runs()
        .transition(env, run, MigrationState::Running)
        .await
        .expect("-> running");
}

/// Move a run into reconciling (from running).
async fn to_reconciling(store: &Store, env: &Env, scope: Scope, run: &MigrationRunId) {
    store
        .scoped(scope)
        .acting(actor(store, env, scope), CorrelationId::generate(env))
        .migration_runs()
        .transition(env, run, MigrationState::Reconciling)
        .await
        .expect("-> reconciling");
}

/// Ingest a batch of owned outcomes.
async fn ingest(
    store: &Store,
    env: &Env,
    scope: Scope,
    run: &MigrationRunId,
    outcomes: &[(String, MigrationRecordOutcome, bool, bool)],
) {
    let inputs: Vec<RecordOutcomeInput<'_>> = outcomes
        .iter()
        .map(
            |(subject, outcome, consistent, backfilled)| RecordOutcomeInput {
                subject,
                outcome: *outcome,
                consistent: *consistent,
                backfilled: *backfilled,
                detail: None,
            },
        )
        .collect();
    store
        .scoped(scope)
        .acting(actor(store, env, scope), CorrelationId::generate(env))
        .migration_runs()
        .ingest_outcomes(env, run, &inputs)
        .await
        .expect("ingest outcomes");
}

/// Attempt completion.
async fn try_complete(
    store: &Store,
    env: &Env,
    scope: Scope,
    run: &MigrationRunId,
) -> CompletionOutcome {
    store
        .scoped(scope)
        .acting(actor(store, env, scope), CorrelationId::generate(env))
        .migration_runs()
        .try_complete(env, run)
        .await
        .expect("try_complete")
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

/// The satisfied flag for one invariant, from a live evaluation.
fn satisfied(evals: &[ironauth_store::InvariantEvaluation], kind: InvariantKind) -> bool {
    evals
        .iter()
        .find(|e| e.kind == kind)
        .map(|e| e.satisfied)
        .expect("invariant present")
}

#[tokio::test]
async fn count_invariant_detects_an_injected_off_by_n_and_blocks_completion() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x59);
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    // A run declaring FIVE source records, but only THREE are ever accounted: an
    // off-by-2 discrepancy the count invariant must catch.
    let run = create_run(store, &env, scope, MigrationKind::BulkImport, 5, 3).await;
    drive_to_running(store, &env, scope, &run).await;
    ingest(
        store,
        &env,
        scope,
        &run,
        &[
            (
                "usr_a".to_string(),
                MigrationRecordOutcome::Imported,
                true,
                true,
            ),
            (
                "usr_b".to_string(),
                MigrationRecordOutcome::Imported,
                true,
                true,
            ),
            (
                "usr_c".to_string(),
                MigrationRecordOutcome::Skipped,
                true,
                true,
            ),
        ],
    )
    .await;
    to_reconciling(store, &env, scope, &run).await;

    // Completion is BLOCKED, and the blocking evaluation names the count invariant.
    let outcome = try_complete(store, &env, scope, &run).await;
    let CompletionOutcome::Blocked(violated) = outcome else {
        panic!("expected a blocked completion, got {outcome:?}");
    };
    assert!(
        violated.iter().any(|e| e.kind == InvariantKind::Count),
        "the count invariant must be among the blockers: {violated:?}"
    );
    let count = violated
        .iter()
        .find(|e| e.kind == InvariantKind::Count)
        .expect("count invariant");
    assert!(
        count.current_value.contains("remainder=2"),
        "the current value must name the remainder: {}",
        count.current_value
    );

    // The run stayed in reconciling; nothing completed.
    let run_row = store
        .scoped(scope)
        .migration_runs()
        .get(&run)
        .await
        .expect("get");
    assert_eq!(run_row.state, MigrationState::Reconciling);
    assert_eq!(audit_count(&db, scope, "migration_run.complete").await, 0);

    // Account for the two missing records: completion now succeeds.
    ingest(
        store,
        &env,
        scope,
        &run,
        &[
            (
                "usr_d".to_string(),
                MigrationRecordOutcome::Imported,
                true,
                true,
            ),
            (
                "usr_e".to_string(),
                MigrationRecordOutcome::Failed,
                true,
                true,
            ),
        ],
    )
    .await;
    assert_eq!(
        try_complete(store, &env, scope, &run).await,
        CompletionOutcome::Completed
    );
    let run_row = store
        .scoped(scope)
        .migration_runs()
        .get(&run)
        .await
        .expect("get");
    assert_eq!(run_row.state, MigrationState::Complete);
    assert_eq!(audit_count(&db, scope, "migration_run.complete").await, 1);
}

#[tokio::test]
async fn consistency_invariant_blocks_and_names_the_offending_records() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x5a);
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    // Three records, all accounted and backfilled, but ONE is inconsistent.
    let run = create_run(store, &env, scope, MigrationKind::BulkImport, 3, 3).await;
    drive_to_running(store, &env, scope, &run).await;
    ingest(
        store,
        &env,
        scope,
        &run,
        &[
            (
                "usr_ok1".to_string(),
                MigrationRecordOutcome::Imported,
                true,
                true,
            ),
            (
                "usr_bad".to_string(),
                MigrationRecordOutcome::Failed,
                false,
                true,
            ),
            (
                "usr_ok2".to_string(),
                MigrationRecordOutcome::Imported,
                true,
                true,
            ),
        ],
    )
    .await;
    to_reconciling(store, &env, scope, &run).await;

    let outcome = try_complete(store, &env, scope, &run).await;
    let CompletionOutcome::Blocked(violated) = outcome else {
        panic!("expected blocked, got {outcome:?}");
    };
    assert!(
        violated
            .iter()
            .any(|e| e.kind == InvariantKind::Consistency),
        "consistency must block: {violated:?}"
    );

    // The paginated violation view names the specific offending record (opened subject).
    let offenders = store
        .scoped(scope)
        .migration_runs()
        .list_violations(&run, InvariantKind::Consistency, 100, None)
        .await
        .expect("list violations");
    assert_eq!(offenders.len(), 1, "exactly one inconsistent record");
    assert_eq!(offenders[0].subject, "usr_bad");
    assert!(!offenders[0].consistent);

    // The run cannot complete while the inconsistent identity stands.
    assert_eq!(
        store
            .scoped(scope)
            .migration_runs()
            .get(&run)
            .await
            .expect("get")
            .state,
        MigrationState::Reconciling
    );
}

#[tokio::test]
async fn a_missing_backfill_sentinel_blocks_and_marking_it_unblocks() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x5b);
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    // Two records, both accounted and consistent, but ONE is not backfill-marked.
    let run = create_run(store, &env, scope, MigrationKind::SchemaMigration, 2, 2).await;
    drive_to_running(store, &env, scope, &run).await;
    ingest(
        store,
        &env,
        scope,
        &run,
        &[
            (
                "usr_marked".to_string(),
                MigrationRecordOutcome::Imported,
                true,
                true,
            ),
            (
                "usr_unmarked".to_string(),
                MigrationRecordOutcome::Imported,
                true,
                false,
            ),
        ],
    )
    .await;
    to_reconciling(store, &env, scope, &run).await;

    let outcome = try_complete(store, &env, scope, &run).await;
    let CompletionOutcome::Blocked(violated) = outcome else {
        panic!("expected blocked, got {outcome:?}");
    };
    assert!(
        violated
            .iter()
            .any(|e| e.kind == InvariantKind::BackfillSentinel),
        "the sentinel invariant must block: {violated:?}"
    );
    let offenders = store
        .scoped(scope)
        .migration_runs()
        .list_violations(&run, InvariantKind::BackfillSentinel, 100, None)
        .await
        .expect("list violations");
    assert_eq!(offenders.len(), 1);
    assert_eq!(offenders[0].subject, "usr_unmarked");

    // Mark the sentinel: completion now succeeds.
    store
        .scoped(scope)
        .acting(actor(store, &env, scope), CorrelationId::generate(&env))
        .migration_runs()
        .mark_backfill(&env, &run, &["usr_unmarked"])
        .await
        .expect("mark backfill");
    assert_eq!(
        try_complete(store, &env, scope, &run).await,
        CompletionOutcome::Completed
    );
    assert_eq!(audit_count(&db, scope, "migration_run.backfill").await, 1);
}

#[tokio::test]
async fn state_and_invariants_survive_a_process_restart_and_are_re_evaluated() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x5c);
    let scope = db.seed_scope(&env).await;

    // Build a run to reconciling with a sentinel violation, on the ORIGINAL store.
    let run = {
        let store = db.store();
        let run = create_run(store, &env, scope, MigrationKind::BulkImport, 2, 2).await;
        drive_to_running(store, &env, scope, &run).await;
        ingest(
            store,
            &env,
            scope,
            &run,
            &[
                (
                    "usr_p".to_string(),
                    MigrationRecordOutcome::Imported,
                    true,
                    true,
                ),
                (
                    "usr_q".to_string(),
                    MigrationRecordOutcome::Imported,
                    true,
                    false,
                ),
            ],
        )
        .await;
        to_reconciling(store, &env, scope, &run).await;
        // Blocked before the restart.
        assert!(matches!(
            try_complete(store, &env, scope, &run).await,
            CompletionOutcome::Blocked(_)
        ));
        run
    };

    // Simulate a process restart: a BRAND-NEW store over the same database, no
    // in-memory state carried across.
    let restarted: Store = db.restart_app_store().await;

    // The state survived (still reconciling), and the invariant verdict is
    // RE-EVALUATED from the database (the pre-restart Blocked verdict was never
    // cached): the sentinel is still violated.
    let run_row = restarted
        .scoped(scope)
        .migration_runs()
        .get(&run)
        .await
        .expect("get");
    assert_eq!(run_row.state, MigrationState::Reconciling);
    let evals = restarted
        .scoped(scope)
        .migration_runs()
        .evaluate(&run)
        .await
        .expect("evaluate");
    assert!(
        !satisfied(&evals, InvariantKind::BackfillSentinel),
        "the sentinel violation must re-evaluate after restart: {evals:?}"
    );

    // Fixing and completing works through the restarted handle.
    restarted
        .scoped(scope)
        .acting(
            actor(&restarted, &env, scope),
            CorrelationId::generate(&env),
        )
        .migration_runs()
        .mark_backfill(&env, &run, &["usr_q"])
        .await
        .expect("mark backfill after restart");
    assert_eq!(
        try_complete(&restarted, &env, scope, &run).await,
        CompletionOutcome::Completed
    );
}

#[tokio::test]
async fn no_transition_sequence_reaches_complete_while_an_invariant_is_violated() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x5d);
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    // A run with a permanent count violation (10 declared, 3 accounted).
    let run = create_run(store, &env, scope, MigrationKind::BulkImport, 10, 0).await;

    // Illegal edges are refused (the machine's legality gate): completion is impossible
    // outside reconciling, and states cannot be skipped.
    let acting = || {
        store
            .scoped(scope)
            .acting(actor(store, &env, scope), CorrelationId::generate(&env))
    };
    assert!(matches!(
        acting().migration_runs().try_complete(&env, &run).await,
        Err(StoreError::IllegalMigrationTransition { .. })
    ));
    assert!(matches!(
        acting()
            .migration_runs()
            .transition(&env, &run, MigrationState::Running)
            .await,
        Err(StoreError::IllegalMigrationTransition { .. })
    ));

    drive_to_running(store, &env, scope, &run).await;
    ingest(
        store,
        &env,
        scope,
        &run,
        &[
            (
                "usr_1".to_string(),
                MigrationRecordOutcome::Imported,
                true,
                true,
            ),
            (
                "usr_2".to_string(),
                MigrationRecordOutcome::Imported,
                true,
                true,
            ),
            (
                "usr_3".to_string(),
                MigrationRecordOutcome::Imported,
                true,
                true,
            ),
        ],
    )
    .await;
    to_reconciling(store, &env, scope, &run).await;

    // Every ordering we can drive keeps failing to complete while the violation stands:
    // repeated attempts, and a reconciling -> running -> reconciling round trip.
    for _ in 0..3 {
        assert!(matches!(
            try_complete(store, &env, scope, &run).await,
            CompletionOutcome::Blocked(_)
        ));
        acting()
            .migration_runs()
            .transition(&env, &run, MigrationState::Running)
            .await
            .expect("reconciling -> running back edge");
        to_reconciling(store, &env, scope, &run).await;
    }
    assert!(matches!(
        try_complete(store, &env, scope, &run).await,
        CompletionOutcome::Blocked(_)
    ));
    // The run never became complete under any of those sequences.
    assert_eq!(
        store
            .scoped(scope)
            .migration_runs()
            .get(&run)
            .await
            .expect("get")
            .state,
        MigrationState::Reconciling
    );

    // The ONLY path to complete is to clear the violation.
    let rest: Vec<(String, MigrationRecordOutcome, bool, bool)> = (4..=10)
        .map(|n| {
            (
                format!("usr_{n}"),
                MigrationRecordOutcome::Imported,
                true,
                true,
            )
        })
        .collect();
    ingest(store, &env, scope, &run, &rest).await;
    assert_eq!(
        try_complete(store, &env, scope, &run).await,
        CompletionOutcome::Completed
    );
}

#[tokio::test]
async fn abandonment_is_an_explicit_audited_terminal_transition() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x5e);
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    let run = create_run(store, &env, scope, MigrationKind::BulkImport, 100, 0).await;
    drive_to_running(store, &env, scope, &run).await;

    store
        .scoped(scope)
        .acting(actor(store, &env, scope), CorrelationId::generate(&env))
        .migration_runs()
        .abandon(
            &env,
            &run,
            "source export corrupted; restarting from scratch",
        )
        .await
        .expect("abandon");

    let run_row = store
        .scoped(scope)
        .migration_runs()
        .get(&run)
        .await
        .expect("get");
    assert_eq!(run_row.state, MigrationState::Abandoned);
    assert_eq!(
        run_row.abandoned_reason.as_deref(),
        Some("source export corrupted; restarting from scratch")
    );
    assert_eq!(audit_count(&db, scope, "migration_run.abandon").await, 1);

    // A terminal run refuses further transitions and cannot be completed.
    let acting = store
        .scoped(scope)
        .acting(actor(store, &env, scope), CorrelationId::generate(&env));
    assert!(matches!(
        acting.migration_runs().try_complete(&env, &run).await,
        Err(StoreError::IllegalMigrationTransition { .. })
    ));
    assert!(matches!(
        acting.migration_runs().abandon(&env, &run, "again").await,
        Err(StoreError::IllegalMigrationTransition { .. })
    ));
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_schema_migration_job_wrapped_in_the_machine_blocks_on_failed_identities() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x5f);
    let scope = db.seed_scope(&env).await;
    let store = db.store();

    // A schema v1 requiring `name`; two identities on it.
    let schema_v1 = json!({
        "type": "object",
        "properties": {"name": {"type": "string", "minLength": 1}},
        "required": ["name"]
    })
    .to_string();
    let schema_v2 = json!({
        "type": "object",
        "properties": {"full_name": {"type": "string", "minLength": 1}},
        "required": ["full_name"]
    })
    .to_string();

    let acting = || {
        store
            .scoped(scope)
            .acting(actor(store, &env, scope), CorrelationId::generate(&env))
    };
    let v1 = acting()
        .trait_schemas()
        .create_version(&env, &schema_v1, NOW_MICROS)
        .await
        .expect("v1")
        .1;
    acting()
        .trait_schemas()
        .activate_version(&env, v1)
        .await
        .expect("activate v1");

    let mut ids = Vec::new();
    for handle in ["alice", "bob"] {
        let id = acting()
            .users()
            .admin_create(
                &env,
                NewAdminUser {
                    id: None,
                    identifier: handle,
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
            .expect("create user");
        acting()
            .users()
            .set_traits(&env, &id, &json!({"name": handle}).to_string())
            .await
            .expect("set traits");
        ids.push(id);
    }

    // A candidate v2 (rename name -> full_name) with NO transform: every identity fails
    // re-validation, so the wrapped run must not be completable.
    let v2 = acting()
        .trait_schemas()
        .create_version(&env, &schema_v2, NOW_MICROS)
        .await
        .expect("v2")
        .1;
    let job_id = acting()
        .trait_migration_jobs()
        .create(
            &env,
            NewTraitMigrationJob {
                kind: TraitJobKind::Migrate,
                from_version: v1,
                to_version: v2,
                transform_json: None,
            },
            NOW_MICROS,
        )
        .await
        .expect("create job");
    let job = acting()
        .trait_migration_jobs()
        .advance(&env, &job_id, 100)
        .await
        .expect("advance job");

    // WRAP the schema migration job in a run and RECONCILE its per-record outcomes: a
    // failed identity is failed + inconsistent; a migrated identity would be imported +
    // consistent + backfilled (its traits_schema_version now stamps to v2).
    let failed: HashSet<String> = job.failures.iter().map(|f| f.subject.clone()).collect();
    let run = create_run(
        store,
        &env,
        scope,
        MigrationKind::SchemaMigration,
        job.total_count,
        job.migrated_count,
    )
    .await;
    drive_to_running(store, &env, scope, &run).await;

    let mut outcomes = Vec::new();
    for id in &ids {
        let subject = id.to_string();
        let (version, _) = store
            .scoped(scope)
            .users()
            .traits(id)
            .await
            .expect("read traits")
            .expect("has traits");
        if failed.contains(&subject) {
            outcomes.push((subject, MigrationRecordOutcome::Failed, false, false));
        } else if version == v2 {
            outcomes.push((subject, MigrationRecordOutcome::Imported, true, true));
        } else {
            outcomes.push((subject, MigrationRecordOutcome::Skipped, true, false));
        }
    }
    ingest(store, &env, scope, &run, &outcomes).await;
    to_reconciling(store, &env, scope, &run).await;

    // The wrapped run is BLOCKED by the failed identities.
    let outcome = try_complete(store, &env, scope, &run).await;
    let CompletionOutcome::Blocked(violated) = outcome else {
        panic!("a schema migration with failed identities must not complete: {outcome:?}");
    };
    assert!(
        violated
            .iter()
            .any(|e| e.kind == InvariantKind::Consistency),
        "consistency must block the wrapped schema migration: {violated:?}"
    );
    // The offending records name the real identities that failed re-validation.
    let offenders = store
        .scoped(scope)
        .migration_runs()
        .list_violations(&run, InvariantKind::Consistency, 100, None)
        .await
        .expect("list violations");
    let named: HashSet<String> = offenders.into_iter().map(|o| o.subject).collect();
    assert_eq!(named, failed, "the API names exactly the failed identities");
}
