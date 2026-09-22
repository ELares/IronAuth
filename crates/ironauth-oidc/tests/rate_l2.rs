// SPDX-License-Identifier: MIT OR Apache-2.0

//! CRITERION 5, INDUCED: the shared (L2) bucket tier against a REAL IronCache (issue #150).
//!
//! `ironauth-quota`'s unit tests prove the seam's semantics with a fake store: two limiters
//! sharing one store enforce ONE budget, and an unavailable store falls back to the local
//! bucket with the outcome reporting it. What a fake cannot show is the IMPLEMENTATION: the
//! buckets actually living in a real cache, so two NODES (processes) share one budget. This
//! drives the whole chain — a real `ironcache` server, the `HotSharedRates` impl over the
//! `RATE_COUNTER` keyspace, and two limiters attached to it.
//!
//! The skip is loud, never silent: no `ironcache` binary prints exactly what was not
//! verified. CI's `ironcache-matrix` job installs the server and runs this test.

#![cfg(feature = "ironcache")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ironauth_config::{LimitConfig, RateLimitConfig};
use ironauth_env::ManualClock;
use ironauth_oidc::rate_store::HotSharedRates;
use ironauth_quota::Limit;
use ironauth_quota::layered::{LayeredLimiter, LayeredLimits, RateLayer, RequestIdentity};

fn shared_limits() -> RateLimitConfig {
    RateLimitConfig {
        per_ip: Some(LimitConfig {
            per_second: 1.0,
            burst: 2.0,
        }),
        per_tenant: None,
        per_environment: None,
        per_client: None,
        per_user: None,
    }
}

/// An identity that presents the per-IP key.
fn identified() -> RequestIdentity {
    RequestIdentity {
        ip: Some("198.51.100.7".to_owned()),
        user: None,
        client: None,
        tenant: Some("tnt_1".to_owned()),
        environment: Some("env_1".to_owned()),
    }
}

/// A limiter over the shared store with `limits`.
fn node(
    store: &Arc<dyn ironauth_quota::layered::SharedRateStore>,
    limits: &RateLimitConfig,
) -> LayeredLimiter {
    let mut limiter = LayeredLimits::unlimited();
    if let Some(limit) = limits.per_ip {
        limiter = limiter.with(RateLayer::PerIp, Limit::new(limit.per_second, limit.burst));
    }
    let clock: Arc<dyn ironauth_env::Clock> =
        Arc::new(ManualClock::new(std::time::SystemTime::UNIX_EPOCH));
    LayeredLimiter::new(limiter, clock).with_shared_store(Arc::clone(store))
}

#[tokio::test(flavor = "multi_thread")]
async fn two_nodes_share_one_budget_in_the_real_cache() {
    let Some(bin) = ironcache_bin() else {
        eprintln!(
            "SKIPPED: no `ironcache` server binary on this host, so the shared (L2) rate tier \
             was NOT verified against a real cache. Install it (cargo install --git \
             https://github.com/ELares/IronCache ironcache) or run with IRONCACHE_BIN set."
        );
        return;
    };
    let port = free_port();
    let mut cache = CacheGuard::start(&bin, port);
    wait_for_port(port, Duration::from_secs(30));

    let connection = ironauth_hot::ironcache::connect(&format!("redis://127.0.0.1:{port}"))
        .await
        .expect("the cache connects");
    let keyspace = ironauth_hot::ironcache::IronCacheKeyspace::new(connection, "rate");
    let shared: Arc<dyn ironauth_quota::layered::SharedRateStore> = Arc::new(HotSharedRates::new(
        Arc::new(keyspace) as Arc<dyn ironauth_hot::HotState>,
    ));

    // TWO NODES: separate processes' worth of state, one store.
    let node_a = node(&shared, &shared_limits());
    let node_b = node(&shared, &shared_limits());

    // Node A spends the shared burst of two.
    let first = node_a.admit(&identified(), 1.0).await;
    assert!(first.decision.is_admitted(), "{first:?}");
    let second = node_a.admit(&identified(), 1.0).await;
    assert!(second.decision.is_admitted(), "{second:?}");

    // NODE B, which never charged a local bucket, is refused: the budget lives in the
    // cache, not in node A's memory. This is the criterion's cross-node accuracy.
    let refused = node_b.admit(&identified(), 1.0).await;
    assert!(!refused.decision.is_admitted(), "{refused:?}");
    assert_eq!(refused.limiting_layer, Some(RateLayer::PerIp));
    assert!(
        !refused.shared_fell_back,
        "the cache answered; the refusal is the SHARED budget, not a fallback"
    );

    // THE BUCKET SURVIVES THE NODES: a third node created after the spends inherits the
    // same budget.
    let node_c = node(&shared, &shared_limits());
    let third = node_c.admit(&identified(), 1.0).await;
    assert!(!third.decision.is_admitted(), "{third:?}");

    // A DIFFERENT KEY IS UNTOUCHED: another address has its own shared bucket.
    let other = RequestIdentity {
        ip: Some("198.51.100.8".to_owned()),
        ..identified()
    };
    let control = node_c.admit(&other, 1.0).await;
    assert!(control.decision.is_admitted(), "{control:?}");

    cache.kill();
}

/// A real `ironcache` server on a test-chosen port.
struct CacheGuard {
    bin: PathBuf,
    port: u16,
    child: Option<std::process::Child>,
}

impl CacheGuard {
    fn start(bin: &std::path::Path, port: u16) -> Self {
        let mut guard = Self {
            bin: bin.to_owned(),
            port,
            child: None,
        };
        guard.spawn();
        guard
    }

    fn spawn(&mut self) {
        let child = Command::new(&self.bin)
            .args(["server", "--port"])
            .arg(self.port.to_string())
            .arg("--metrics-addr")
            .arg("off")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("ironcache server spawns");
        self.child = Some(child);
    }

    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for CacheGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

/// The `ironcache` server binary: `IRONCACHE_BIN`, then PATH.
fn ironcache_bin() -> Option<PathBuf> {
    if let Some(bin) = std::env::var_os("IRONCACHE_BIN") {
        let bin = PathBuf::from(bin);
        if bin.is_file() {
            return Some(bin);
        }
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("ironcache");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Poll a TCP port until something accepts, or `timeout` elapses.
fn wait_for_port(port: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout; // invariant-allow: time-via-env
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline, // invariant-allow: time-via-env
            "nothing is listening on {port} within the wait"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port to bind");
    listener.local_addr().expect("a bound address").port()
}

/// CRITERION 2, IN THE SHARED TIER: a noisy tenant's storm over the shared store does not
/// reduce a quiet tenant's admitted throughput. The read-modify-write race a storm
/// produces is real — the noisy tenant's own budget may overshoot by one spend per
/// concurrent node — but the quiet tenant's KEY is separate, so its admitted throughput
/// is exactly its own budget. That is the documented fairness bound with the L2 attached.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_noisy_tenant_storm_never_reduces_a_quiet_tenant_s_budget_in_the_shared_tier() {
    const BUDGET: u64 = 3;
    const RACERS: usize = 8;
    const PER_RACER: usize = 30;
    // THE QUIET TENANT SENDS SEQUENTIALLY: the read-modify-write race is real, and its
    // overshoot is bounded per key by the number of nodes concurrently charging THAT key.
    // Measuring the quiet tenant's admitted count under its OWN concurrency would measure
    // the race, not the fairness. One sequential spender has no race on its key, so its
    // admitted count must be EXACTLY its budget whatever the noisy storm beside it does.
    let Some(bin) = ironcache_bin() else {
        eprintln!(
            "SKIPPED: no `ironcache` server binary on this host, so the shared-tier \
             fairness-under-load bound was NOT verified against a real cache."
        );
        return;
    };
    let port = free_port();
    let mut cache = CacheGuard::start(&bin, port);
    wait_for_port(port, Duration::from_secs(30));
    let connection = ironauth_hot::ironcache::connect(&format!("redis://127.0.0.1:{port}"))
        .await
        .expect("the cache connects");
    let keyspace = ironauth_hot::ironcache::IronCacheKeyspace::new(connection, "rate");
    let shared: Arc<dyn ironauth_quota::layered::SharedRateStore> = Arc::new(HotSharedRates::new(
        Arc::new(keyspace) as Arc<dyn ironauth_hot::HotState>,
    ));

    let mut limits = LayeredLimits::unlimited();
    limits = limits.with(RateLayer::PerTenant, Limit::new(0.0, 3.0));
    let clock: Arc<dyn ironauth_env::Clock> =
        Arc::new(ManualClock::new(std::time::SystemTime::UNIX_EPOCH));
    let limiter =
        Arc::new(LayeredLimiter::new(limits, clock).with_shared_store(Arc::clone(&shared)));

    // Two tenants, one per-tenant key each.
    let noisy = RequestIdentity {
        ip: None,
        user: None,
        client: None,
        tenant: Some("tnt_noisy".to_owned()),
        environment: Some("env_1".to_owned()),
    };
    let quiet = RequestIdentity {
        tenant: Some("tnt_quiet".to_owned()),
        ..noisy.clone()
    };

    let noisy_admitted = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let quiet_admitted = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut tasks = Vec::with_capacity(RACERS + 1);
    for _ in 0..RACERS {
        let limiter = Arc::clone(&limiter);
        let identity = noisy.clone();
        let counter = Arc::clone(&noisy_admitted);
        tasks.push(tokio::spawn(async move {
            for _ in 0..PER_RACER {
                let outcome = limiter.admit(&identity, 1.0).await;
                if outcome.decision.is_admitted() {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }));
    }
    // The quiet tenant, sequential: its key is never raced by its own senders.
    for _ in 0..(RACERS * PER_RACER) {
        let outcome = limiter.admit(&quiet, 1.0).await;
        if outcome.decision.is_admitted() {
            quiet_admitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    for task in tasks {
        task.await.expect("task joins");
    }

    // THE DOCUMENTED BOUNDS. The noisy tenant may overshoot its burst by the racer count
    // (the read-modify-write race, one lost spend per concurrent node — that is the cost
    // of the fail-open class, and it is bounded, never an invented refusal).
    let noisy_total = noisy_admitted.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        noisy_total >= BUDGET,
        "the noisy tenant saturated: {noisy_total}"
    );
    // THE QUIET TENANT: exactly its own budget, whatever the storm beside it did. The
    // race cannot cross keys, so the fairness bound is zero interference here too.
    let quiet_total = quiet_admitted.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        quiet_total, BUDGET,
        "the quiet tenant's admitted throughput equals its own budget in the shared tier"
    );

    cache.kill();
}
