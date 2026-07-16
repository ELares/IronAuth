// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Argon2id parameter tuning probe (issue #62).
//!
//! Correct Argon2id parameters are hardware-dependent: fixed parameters are wrong
//! on both a slow host (logins too slow) and a fast one (weaker than the host
//! could afford). This module runs a MEASURED probe on the actual host, timing
//! real Argon2id hashes, and recommends the strongest memory cost whose hash still
//! fits the operator's target latency. It also projects how many logins per second
//! per core the recommendation sustains, so an operator can size capacity.
//!
//! The probe is exposed two ways over the SAME [`run_probe`] core: the `ironauth
//! hash-probe` CLI for headless installs, and (in spirit) the in-admin tuning
//! helper. It measures wall-clock time through the [`ironauth_env`] monotonic
//! seam, so it needs no direct process-clock read and stays inside the invariant
//! lints; under the production [`Env::system`](ironauth_env::Env::system) that is
//! real time, which is exactly what a host measurement requires.

use ironauth_env::Env;

use crate::password::{Argon2Params, hash_password_with};

/// The fixed iteration (time) cost the probe tunes around (OWASP `t = 2`). The
/// probe varies the MEMORY cost, following the OWASP guidance to hold `t` and `p`
/// and raise memory to the latency budget.
const PROBE_ITERATIONS: u32 = 2;
/// The fixed parallelism the probe tunes around (OWASP `p = 1`).
const PROBE_PARALLELISM: u32 = 1;
/// The security floor for the recommended memory cost, in KiB (8 MiB). Mirrors
/// `ironauth_config::PASSWORD_HASHING_MIN_MEMORY_KIB`; kept as a local constant so
/// this crate does not reach into config internals for a single number.
const PROBE_MIN_MEMORY_KIB: u32 = 8_192;
/// The candidate memory costs the probe measures, ascending. The probe stops at
/// the first candidate whose measured hash exceeds the target, so it never times a
/// wildly oversized hash; every value is a round, defensible Argon2id memory cost.
const PROBE_MEMORY_LADDER_KIB: [u32; 8] = [
    8_192, 16_384, 19_456, 32_768, 65_536, 131_072, 262_144, 524_288,
];
/// How many timed runs the probe takes per candidate; it keeps the fastest, which
/// best reflects the hash's intrinsic cost with the least scheduler noise.
const PROBE_RUNS_PER_CANDIDATE: u32 = 3;
/// A fixed throwaway plaintext the probe hashes. It protects no secret; it exists
/// only to spend representative Argon2id work.
const PROBE_PLAINTEXT: &str = "ironauth-tuning-probe-plaintext";

/// A parameter recommendation produced from a measured host probe.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeReport {
    /// The recommended Argon2id parameters: the strongest memory cost whose
    /// measured hash still met the target latency (or the floor, when even that
    /// exceeds the target on a slow host).
    pub recommended: Argon2Params,
    /// The measured per-hash latency of the recommendation, in milliseconds.
    pub measured_latency_ms: f64,
    /// The operator's target per-hash latency, in milliseconds.
    pub target_latency_ms: u64,
    /// Whether the recommendation met the target (`measured <= target`). False on
    /// a host too slow to hit the target even at the floor.
    pub within_target: bool,
    /// Projected logins per second a SINGLE core sustains at the recommendation
    /// (`1000 / measured_latency_ms`).
    pub projected_logins_per_sec_per_core: f64,
    /// Projected logins per second the whole host sustains
    /// (`per_core * host_threads`).
    pub projected_logins_per_sec_total: f64,
    /// The host parallelism the projection multiplies by.
    pub host_threads: usize,
    /// The host's available memory in KiB, when measurable (Linux `MemAvailable`),
    /// else `None`.
    pub available_memory_kib: Option<u64>,
    /// The per-hash memory budget the probe capped candidates at, in KiB.
    pub memory_budget_kib: u64,
}

/// Run the tuning probe on the host `env` measures time through, recommending the
/// strongest memory cost whose measured hash meets `target_latency_ms`, capped so
/// one hash never exceeds `memory_budget_kib`.
///
/// The probe times real Argon2id hashes; under the production system environment
/// that is a genuine host measurement. It returns a recommendation even on a host
/// too slow to hit the target (the memory floor, with `within_target = false`), so
/// it never fails: an operator always gets a defensible starting point.
#[must_use]
pub fn run_probe(env: &Env, target_latency_ms: u64, memory_budget_kib: u64) -> ProbeReport {
    let host_threads = crate::hashing_pool::default_pool_threads();
    let available = available_memory_kib();
    // Cap the candidate memory at the budget, and never exceed measurable host
    // memory (leaving generous headroom) when it is known.
    let mut cap = memory_budget_kib;
    if let Some(available) = available {
        cap = cap.min(available / 2);
    }

    // Walk the ladder ascending, keeping the strongest candidate that met the
    // target; stop at the first that exceeded it (or the budget cap).
    let mut best_memory = PROBE_MIN_MEMORY_KIB;
    let mut best_latency_ms = measure_ms(env, PROBE_MIN_MEMORY_KIB);
    for &candidate in &PROBE_MEMORY_LADDER_KIB {
        if candidate == PROBE_MIN_MEMORY_KIB {
            continue;
        }
        if u64::from(candidate) > cap {
            break;
        }
        let latency = measure_ms(env, candidate);
        if latency <= target_ms_f64(target_latency_ms) {
            best_memory = candidate;
            best_latency_ms = latency;
        } else {
            break;
        }
    }

    let recommended = Argon2Params::new(best_memory, PROBE_ITERATIONS, PROBE_PARALLELISM);
    let per_core = if best_latency_ms > 0.0 {
        1_000.0 / best_latency_ms
    } else {
        f64::INFINITY
    };
    ProbeReport {
        recommended,
        measured_latency_ms: best_latency_ms,
        target_latency_ms,
        within_target: best_latency_ms <= target_ms_f64(target_latency_ms),
        projected_logins_per_sec_per_core: per_core,
        projected_logins_per_sec_total: per_core * usize_to_f64(host_threads),
        host_threads,
        available_memory_kib: available,
        memory_budget_kib,
    }
}

/// The target latency as an `f64` for comparison against measured milliseconds.
#[allow(
    clippy::cast_precision_loss,
    reason = "a latency target in ms is a small magnitude far below 2^53"
)]
fn target_ms_f64(target_latency_ms: u64) -> f64 {
    target_latency_ms as f64
}

/// Widen a small host-thread count to `f64` for the projection multiply.
#[allow(
    clippy::cast_precision_loss,
    reason = "a host-thread count is a small magnitude far below 2^53"
)]
fn usize_to_f64(value: usize) -> f64 {
    value as f64
}

/// Measure the fastest of a few Argon2id hashes at `memory_kib`, in milliseconds,
/// through the environment's monotonic clock. A hashing error (an impossible
/// parameter triple) reports `f64::INFINITY`, so that candidate is never chosen.
fn measure_ms(env: &Env, memory_kib: u32) -> f64 {
    let params = Argon2Params::new(memory_kib, PROBE_ITERATIONS, PROBE_PARALLELISM);
    let mut best = f64::INFINITY;
    for _ in 0..PROBE_RUNS_PER_CANDIDATE {
        let start = env.clock().monotonic();
        let outcome = hash_password_with(env, PROBE_PLAINTEXT, params);
        let elapsed = env.clock().monotonic().saturating_duration_since(start);
        if outcome.is_err() {
            return f64::INFINITY;
        }
        let ms = duration_to_ms(elapsed);
        if ms < best {
            best = ms;
        }
    }
    best
}

/// A `Duration` as fractional milliseconds.
fn duration_to_ms(duration: std::time::Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

/// Best-effort available host memory in KiB. Reads Linux `/proc/meminfo`
/// `MemAvailable`; returns `None` on any other platform or on a read/parse
/// failure, in which case the probe relies on the configured memory budget alone.
#[must_use]
pub fn available_memory_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemAvailable:") {
                let kib = rest.split_whitespace().next()?;
                return kib.parse::<u64>().ok();
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
