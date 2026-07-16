// SPDX-License-Identifier: MIT OR Apache-2.0

//! The dedicated, admission-controlled Argon2id hashing pool (issue #62),
//! DATABASE-FREE so it runs on every lane.
//!
//! Proves the four acceptance-critical properties: hashing executes OFF the tokio
//! runtime threads; new hashes carry the configured parameters and round-trip;
//! per-tenant fair-share admission isolates one tenant's stuffing storm from
//! another (the two-tenant load test); the bounded queue load-sheds with a TYPED
//! error rather than an inline hash; and the tuning probe returns sane parameters
//! within the target latency on the runner. Plus a metrics-presence check.

use std::sync::Arc;
use std::time::Duration;

use ironauth_config::{QuotaConfig, ScopeQuotaConfig};
use ironauth_env::Env;
use ironauth_oidc::{
    Argon2Params, HashRejection, HashingPool, describe_hashing_pool_metrics, hash_password_with,
    run_probe,
};
use ironauth_quota::QuotaEnforcer;
use ironauth_store::{EnvironmentId, Scope, TenantId};

/// Cheap Argon2id parameters so the admission/queue tests stay fast; hash cost is
/// irrelevant to the fairness and typing they exercise.
fn cheap_params() -> Argon2Params {
    // Argon2 requires m >= 8 * p; 8 KiB at p=1, t=1 is the cheapest valid triple.
    Argon2Params::new(8, 1, 1)
}

/// A fresh, unique `(tenant, environment)` scope.
fn fresh_scope() -> Scope {
    let env = Env::system();
    Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env))
}

/// A quota config whose password-hashing dimension has an exact per-environment
/// burst and no refill, so admission is a deterministic budget in tests.
fn hashing_quota(env_burst: u64) -> QuotaConfig {
    let scope = ScopeQuotaConfig {
        requests_per_second: 0,
        requests_burst: 0,
        token_issuance_per_second: 0,
        token_issuance_burst: 0,
        hook_seconds_per_second: 0,
        hook_seconds_burst: 0,
        password_hashing_per_second: 0, // no refill: an exact budget.
        password_hashing_burst: env_burst,
    };
    QuotaConfig {
        // A generous tenant envelope so the ENVIRONMENT bucket is the limiter.
        tenant: ScopeQuotaConfig {
            password_hashing_burst: 1_000_000,
            ..scope.clone()
        },
        environment: scope,
        usage_thresholds_percent: vec![100],
        idle_bucket_ttl_secs: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hashing_never_runs_on_a_tokio_thread() {
    // Acceptance: Argon2 executes on a dedicated worker, not a protocol-I/O (or
    // any tokio) thread. A dedicated std thread has NO tokio runtime context.
    let pool = HashingPool::new(Env::system(), cheap_params(), 2, 64, None);
    let diag = pool.thread_diagnostics().await.expect("diagnostics");
    assert!(diag.on_hash_worker, "the job must run on a hashing worker");
    assert!(
        !diag.tokio_runtime_present,
        "the worker must have no tokio runtime context, proving it is not an I/O thread"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hash_and_verify_round_trip_through_the_pool() {
    let pool = HashingPool::new(Env::system(), cheap_params(), 2, 64, None);
    let scope = fresh_scope();
    let hash = pool.hash(&scope, "correct horse").await.expect("hash");
    assert!(hash.starts_with("$argon2id$"), "{hash}");
    assert!(
        pool.verify(&scope, "correct horse", &hash)
            .await
            .expect("verify")
    );
    assert!(!pool.verify(&scope, "wrong", &hash).await.expect("verify"));
    // Absent-account spend always returns false, and is admitted here (no quota).
    assert!(
        !pool
            .verify_absent(&scope, "anything")
            .await
            .expect("absent")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_mints_new_hashes_at_the_configured_parameters() {
    // A parameter change applies to NEW hashes minted by the pool (issue #62).
    let params = Argon2Params::new(12_288, 3, 1);
    let pool = HashingPool::new(Env::system(), params, 1, 16, None);
    let hash = pool.hash(&fresh_scope(), "pw").await.expect("hash");
    assert!(hash.contains("m=12288"), "tuned memory: {hash}");
    assert!(hash.contains("t=3"), "tuned iterations: {hash}");
    assert!(hash.contains("p=1"), "tuned parallelism: {hash}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_tenant_stuffing_storm_degrades_only_the_noisy_tenant() {
    // The acceptance-critical isolation test. Tenant A saturates its fair-share
    // hashing admission and receives 429-shaped rejections; tenant B, drawing from
    // a DISJOINT bucket, is never starved: every B login is admitted and completes
    // quickly. One tenant's storm degrades ONLY that tenant.
    let burst = 5;
    let quota = Arc::new(QuotaEnforcer::from_config(
        &hashing_quota(burst),
        Env::system().clock_arc(),
    ));
    let pool = Arc::new(HashingPool::new(
        Env::system(),
        cheap_params(),
        4,
        4_096,
        Some(quota),
    ));

    let noisy = fresh_scope();
    let quiet = fresh_scope();

    // Tenant A floods far past its burst, concurrently.
    let mut a_handles = Vec::new();
    for _ in 0..80 {
        let pool = Arc::clone(&pool);
        let scope = noisy;
        a_handles.push(tokio::spawn(async move {
            pool.verify(&scope, "guess", "not-a-real-hash").await
        }));
    }
    // Tenant B logs in a handful of times, concurrently with A's storm, timing each
    // through the monotonic clock seam (never a direct process-clock read).
    let clock = Env::system().clock_arc();
    let mut b_handles = Vec::new();
    for _ in 0..5 {
        let pool = Arc::clone(&pool);
        let scope = quiet;
        let clock = Arc::clone(&clock);
        b_handles.push(tokio::spawn(async move {
            let start = clock.monotonic();
            let result = pool.verify(&scope, "guess", "not-a-real-hash").await;
            let elapsed = clock.monotonic().saturating_duration_since(start);
            (result, elapsed)
        }));
    }

    let mut a_admitted = 0;
    let mut a_rejected = 0;
    for handle in a_handles {
        match handle.await.expect("task") {
            Ok(_) => a_admitted += 1,
            Err(HashRejection::Overloaded(_)) => a_rejected += 1,
            Err(other) => panic!("unexpected A rejection: {other:?}"),
        }
    }
    let mut b_admitted = 0;
    let mut b_max_latency = Duration::ZERO;
    for handle in b_handles {
        let (result, elapsed) = handle.await.expect("task");
        assert!(
            result.is_ok(),
            "quiet tenant B must never be shed: {result:?}"
        );
        b_admitted += 1;
        b_max_latency = b_max_latency.max(elapsed);
    }

    // A got exactly its fair share admitted; everything beyond was shed as 429.
    assert_eq!(
        a_admitted, burst,
        "A admits exactly its burst, then is shed"
    );
    assert!(a_rejected > 0, "A's storm must earn fair-share rejections");
    // B is entirely unaffected: every login admitted, none starved behind A.
    assert_eq!(
        b_admitted, 5,
        "quiet tenant B is never starved by A's storm"
    );
    assert!(
        b_max_latency < Duration::from_secs(2),
        "B's login latency stayed within SLO despite A's storm: {b_max_latency:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_tenants_backlog_does_not_delay_another_tenants_admitted_work() {
    // The HIGH-2 acceptance-critical FAIR-QUEUING test. Unlike the admission-rate
    // test above, this saturates the QUEUE itself: a SINGLE worker (so the queue
    // genuinely backs up) and NO admission limit, so every hash is admitted and the
    // only thing standing between tenant B and its result is the queue discipline.
    //
    // Tenant A floods a large backlog of admitted hashes; tenant B then submits ONE.
    // A single global FIFO would force B behind A's entire backlog (the shipped
    // head-of-line bug: B ~9s behind A's 50 jobs). Per-tenant fair queuing
    // (round-robin across tenant sub-queues) must instead serve B after only a
    // couple of A's jobs, so B stays within SLO while A's backlog drains fairly.
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Tens of ms per hash so the single worker stays busy and the backlog is real.
    let params = Argon2Params::new(65_536, 2, 1);
    let pool = Arc::new(HashingPool::new(Env::system(), params, 1, 4_096, None));
    let clock = Env::system().clock_arc();

    let noisy = fresh_scope();
    let quiet = fresh_scope();
    let total_a: usize = 20;

    // A shared count of completed A hashes; B snapshots it when B finishes.
    let a_done = Arc::new(AtomicUsize::new(0));

    // Flood tenant A's backlog first (all admitted, no quota).
    let mut a_handles = Vec::new();
    for _ in 0..total_a {
        let pool = Arc::clone(&pool);
        let a_done = Arc::clone(&a_done);
        let scope = noisy;
        a_handles.push(tokio::spawn(async move {
            let result = pool.hash(&scope, "pw").await;
            a_done.fetch_add(1, Ordering::SeqCst);
            result
        }));
    }
    // Let A's tasks run their synchronous admit+enqueue before B joins the queue, so
    // A's backlog is genuinely built up behind the busy worker (no timer needed).
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }

    // Tenant B submits ONE admitted hash, timing it and snapshotting A's progress.
    let overall_start = clock.monotonic();
    let b_handle = {
        let pool = Arc::clone(&pool);
        let clock = Arc::clone(&clock);
        let a_done = Arc::clone(&a_done);
        let scope = quiet;
        tokio::spawn(async move {
            let start = clock.monotonic();
            let result = pool.hash(&scope, "pw").await;
            let elapsed = clock.monotonic().saturating_duration_since(start);
            let a_done_at_b = a_done.load(Ordering::SeqCst);
            (result, elapsed, a_done_at_b)
        })
    };

    let (b_result, b_latency, a_done_at_b) = b_handle.await.expect("b task");
    let mut a_admitted = 0;
    for handle in a_handles {
        if handle.await.expect("a task").is_ok() {
            a_admitted += 1;
        }
    }
    let a_total_latency = clock.monotonic().saturating_duration_since(overall_start);

    assert!(
        b_result.is_ok(),
        "B's admitted hash must complete: {b_result:?}"
    );
    // Fairness never starves A either: every A hash is admitted and completes.
    assert_eq!(
        a_admitted, total_a,
        "every A hash is admitted (no quota) and completes"
    );
    // THE proof: B did NOT wait behind A's whole backlog. Round-robin bounds the A
    // jobs served before B to a small handful; a global FIFO would be ~total_a.
    assert!(
        a_done_at_b < total_a / 2,
        "B jumped A's backlog via fair queuing: only {a_done_at_b} of {total_a} A-hashes \
         finished before B (a single global FIFO would be ~{total_a})"
    );
    // And B stayed within SLO: it finished well before A's backlog drained.
    assert!(
        b_latency < a_total_latency,
        "B's latency stayed within SLO under A's backlog: B={b_latency:?}, A total={a_total_latency:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_noisy_tenant_is_shed_without_shedding_an_innocent_tenant() {
    // Issue #62 HIGH-2: load-shedding is PER-TENANT. A single worker with a
    // per-tenant queue depth of 1 means tenant A (busy worker + one queued + a flood)
    // sheds its OWN overflow, while tenant B, whose sub-queue is empty, is admitted
    // to the queue and never shed for A's fill.
    let params = Argon2Params::new(65_536, 2, 1); // slow enough that the worker stays busy.
    let pool = Arc::new(HashingPool::new(Env::system(), params, 1, 1, None));
    let noisy = fresh_scope();
    let quiet = fresh_scope();

    // A floods far past its per-tenant depth: some shed as PoolExhausted (503).
    let mut a_handles = Vec::new();
    for _ in 0..24 {
        let pool = Arc::clone(&pool);
        let scope = noisy;
        a_handles.push(tokio::spawn(async move { pool.hash(&scope, "pw").await }));
    }
    // B submits one hash; its OWN sub-queue is empty, so it is never shed for A.
    let b_result = {
        let pool = Arc::clone(&pool);
        tokio::spawn(async move { pool.hash(&quiet, "pw").await })
    }
    .await
    .expect("b task");

    let mut a_shed = 0;
    for handle in a_handles {
        if matches!(
            handle.await.expect("a task"),
            Err(HashRejection::PoolExhausted)
        ) {
            a_shed += 1;
        }
    }
    assert!(
        a_shed > 0,
        "A's overflow is shed per-tenant (PoolExhausted)"
    );
    assert!(
        b_result.is_ok(),
        "innocent tenant B is never shed for A's fill: {b_result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_tenant_flooding_many_environments_does_not_shed_a_different_tenant() {
    // MEDIUM-1 regression (issue #62 re-review): the queue-layer isolation must be
    // genuinely PER-TENANT, not merely per-(tenant, environment). A single tenant using
    // many of its OWN environments must be shed on its OWN aggregate bound and must NEVER
    // exhaust the global backstop to shed a DIFFERENT, innocent tenant.
    //
    // Reproduces the reported attack: with a per-environment depth of 1 and the shipped
    // global fan-out of 16, tenant A spreading across >=16 environments used to fill 16
    // distinct (A, environment) keys up to the global backstop, so an innocent tenant B's
    // single hash was shed with PoolExhausted (the global valve). The per-tenant AGGREGATE
    // cap now bounds A's total across ALL its environments strictly below the backstop, so
    // A sheds on itself and B is always admitted. Under the pre-fix code B is shed here.
    let params = Argon2Params::new(65_536, 2, 1); // slow enough the single worker stays busy.
    let pool = Arc::new(HashingPool::new(Env::system(), params, 1, 1, None));

    // Tenant A spans 24 of its OWN environments (one tenant, distinct environments).
    let env = Env::system();
    let a_tenant = TenantId::generate(&env);
    let a_scopes: Vec<Scope> = (0..24)
        .map(|_| Scope::new(a_tenant, EnvironmentId::generate(&env)))
        .collect();

    // A floods one hash into each of its 24 environments, concurrently.
    let mut a_handles = Vec::new();
    for scope in a_scopes {
        let pool = Arc::clone(&pool);
        a_handles.push(tokio::spawn(async move { pool.hash(&scope, "pw").await }));
    }
    // An innocent, DIFFERENT tenant B submits one hash to its own environment.
    let b_scope = fresh_scope();
    let b_result = {
        let pool = Arc::clone(&pool);
        tokio::spawn(async move { pool.hash(&b_scope, "pw").await })
    }
    .await
    .expect("b task");

    let mut a_shed = 0;
    for handle in a_handles {
        if matches!(
            handle.await.expect("a task"),
            Err(HashRejection::PoolExhausted)
        ) {
            a_shed += 1;
        }
    }
    // A's flood across many of its environments is shed on ITS OWN aggregate bound: the
    // per-tenant total across all A's environments caps below the 16-deep global backstop,
    // so a large fraction of A's 24 submissions are shed while A's total never reaches the
    // backstop. (The exact shed count depends on worker timing; what matters is A sheds on
    // itself and cannot exhaust the shared valve.)
    assert!(
        a_shed > 0,
        "tenant A flooding many of its own environments is shed on its OWN aggregate bound"
    );
    // THE acceptance core: the innocent, different tenant B is NEVER shed. Under the pre-fix
    // per-(tenant, environment) bound A filled the global backstop and B got PoolExhausted;
    // the per-tenant aggregate cap keeps the backstop reachable only by a BROAD multi-tenant
    // flood, so B's single hash is always admitted and completes.
    assert!(
        b_result.is_ok(),
        "an innocent different tenant B is not shed by A's multi-environment flood: {b_result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_saturated_pool_sheds_with_a_typed_error_not_an_inline_hash() {
    // The bounded queue load-sheds with a TYPED PoolExhausted (retryable 503), and
    // verification never falls back to an unbounded inline hash. One worker plus a
    // queue depth of one means a concurrent burst overflows deterministically while
    // the single worker is busy on a moderately expensive hash.
    let pool = Arc::new(HashingPool::new(
        Env::system(),
        Argon2Params::new(131_072, 3, 1), // ~100ms+ per hash: the worker stays busy.
        1,
        1,
        None,
    ));
    let scope = fresh_scope();
    let mut handles = Vec::new();
    for _ in 0..24 {
        let pool = Arc::clone(&pool);
        handles.push(tokio::spawn(async move { pool.hash(&scope, "pw").await }));
    }
    let mut exhausted = 0;
    let mut ok = 0;
    for handle in handles {
        match handle.await.expect("task") {
            Ok(_) => ok += 1,
            Err(HashRejection::PoolExhausted) => exhausted += 1,
            Err(other) => panic!("unexpected rejection: {other:?}"),
        }
    }
    assert!(ok >= 1, "at least the running/queued jobs complete");
    assert!(
        exhausted > 0,
        "a saturated bounded queue must shed with PoolExhausted, never an inline hash"
    );
}

#[test]
fn tuning_probe_returns_sane_parameters_within_the_target() {
    // Acceptance: the probe on the CI runner returns sane parameters that meet the
    // configured latency target. Uses the shipped default target (250ms).
    let env = Env::system();
    let target_ms = 250;
    let budget_kib = 262_144; // 256 MiB per-hash cap.
    let report = run_probe(&env, target_ms, budget_kib);

    // Sane: at least the OWASP floor, valid iteration and parallelism.
    assert!(
        report.recommended.memory_kib() >= 8_192,
        "recommended memory is at least the security floor"
    );
    assert!(report.recommended.iterations() >= 1);
    assert!(report.recommended.parallelism() >= 1);
    assert!(
        report.within_target,
        "the runner is fast enough to meet a 250ms target: measured {}ms",
        report.measured_latency_ms
    );
    assert!(
        report.measured_latency_ms <= f64::from(u32::try_from(target_ms).unwrap()),
        "the recommendation's measured latency meets the target"
    );
    assert!(
        report.projected_logins_per_sec_per_core > 0.0,
        "a positive throughput projection"
    );

    // The recommended parameters, re-measured, still meet the target (with slack),
    // proving the recommendation is actionable and not a one-off measurement.
    let params = report.recommended;
    let start = env.clock().monotonic();
    let hash = hash_password_with(&env, "probe check", params).expect("hash");
    let elapsed = env.clock().monotonic().saturating_duration_since(start);
    assert!(hash.starts_with("$argon2id$"));
    assert!(
        elapsed < Duration::from_millis(target_ms * 4),
        "re-measured recommended latency is in the same ballpark as the target: {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_metrics_are_exported() {
    // Pool and admission metrics are visible (issue #62). Install the process
    // recorder (this test binary's sole installer), drive one admitted hash and one
    // rejected admission, and assert the series appear. Worker-thread metrics reach
    // the global facade, which is why a process (not local) recorder is used.
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("no recorder installed yet in this test binary");
    describe_hashing_pool_metrics();

    // Burst of 1 with no refill: the first hash is admitted, the second is over the
    // budget and rejected (over_share), exercising both metric paths.
    let quota = Arc::new(QuotaEnforcer::from_config(
        &hashing_quota(1),
        Env::system().clock_arc(),
    ));
    let pool = HashingPool::new(Env::system(), cheap_params(), 1, 8, Some(quota));
    let scope = fresh_scope();

    pool.hash(&scope, "pw").await.expect("first hash admitted");
    let second = pool.hash(&scope, "pw").await;
    assert!(
        matches!(second, Err(HashRejection::Overloaded(_))),
        "second hash is over the burst and rejected"
    );

    let rendered = handle.render();
    assert!(
        rendered.contains("ironauth_password_hash"),
        "pool metrics are exported:\n{rendered}"
    );
}
