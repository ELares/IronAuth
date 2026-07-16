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
