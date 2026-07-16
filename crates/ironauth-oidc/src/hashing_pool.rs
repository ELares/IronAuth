// SPDX-License-Identifier: MIT OR Apache-2.0

//! The dedicated, admission-controlled Argon2id hashing pool (issue #62).
//!
//! Password hashing is the hottest and most denial-of-service-prone operation an
//! identity provider performs: OWASP-strength Argon2id costs tens of milliseconds
//! of CPU and tens of MiB of memory per hash, so a credential-stuffing storm can
//! consume every core and starve every tenant's logins. This module bounds that
//! risk with three layers, none of which invents a new fairness mechanism:
//!
//! 1. **Off the async threads.** Argon2 runs ONLY on a fixed set of dedicated OS
//!    worker threads (never a tokio protocol-I/O worker), so a hash can never
//!    block request I/O. The async call site awaits a [`tokio::sync::oneshot`]
//!    while a worker does the CPU work. A runtime check
//!    ([`HashingPool::thread_diagnostics`]) proves hashing does not execute on a
//!    tokio thread.
//! 2. **Per-tenant fair-share admission.** Before a job is queued it is charged
//!    against the [`QuotaDimension::PasswordHashing`] bucket of the SAME
//!    [`ironauth_quota`] engine the request path already uses (issue #50). A
//!    tenant over its share is shed with a retryable `429` carrying the quota
//!    layer's machine-readable block signal, so one tenant's storm drains only
//!    that tenant's hashing bucket, never another tenant's and never the pool.
//! 3. **A bounded queue.** Admitted jobs enter a fixed-depth queue; a submission
//!    that would exceed the depth is shed with a retryable `503`. Verification
//!    NEVER falls back to an unbounded inline hash: pool exhaustion and worker
//!    faults are typed [`HashRejection`] errors the caller surfaces.
//!
//! # Determinism seam
//!
//! Per-hash latency is measured through the [`ironauth_env`] monotonic clock, not
//! a direct process-clock read, so the invariant lints stay satisfied and a
//! deterministic test drives the timing. The salt still comes from the entropy seam.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use ironauth_env::Env;
use ironauth_quota::{
    EnvironmentId as QuotaEnvironmentId, QuotaDimension, QuotaEnforcer, RateLimitSnapshot,
    Scope as QuotaScope, TenantId as QuotaTenantId,
};
use ironauth_store::Scope;
use tokio::sync::oneshot;

use crate::password::{self, Argon2Params};

/// Per-hash latency histogram, in seconds, labeled by operation (`hash`/`verify`).
pub const HASH_DURATION_SECONDS: &str = "ironauth_password_hash_duration_seconds";
/// Current depth of the hashing pool's queue (jobs waiting for a worker).
pub const POOL_QUEUE_DEPTH: &str = "ironauth_password_hash_pool_queue_depth";
/// Number of worker threads currently executing a hash (pool utilization).
pub const POOL_ACTIVE_WORKERS: &str = "ironauth_password_hash_pool_active_workers";
/// The fixed worker-thread capacity of the pool (a gauge set once at boot).
pub const POOL_THREADS: &str = "ironauth_password_hash_pool_threads";
/// Admission rejections, labeled by `reason` (`over_share`/`pool_exhausted`).
pub const ADMISSION_REJECTED_TOTAL: &str = "ironauth_password_hash_admission_rejected_total";

thread_local! {
    /// True on a hashing-pool worker thread. Read by [`on_hash_worker_thread`] so
    /// a test can prove Argon2 executes off the async I/O threads.
    static ON_HASH_WORKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the current thread is a hashing-pool worker. Used by the acceptance
/// check that hashing never runs on a protocol-I/O thread.
#[must_use]
pub fn on_hash_worker_thread() -> bool {
    ON_HASH_WORKER.with(std::cell::Cell::get)
}

/// Why a hashing request could not be served by the pool. Every variant is a
/// TYPED, retryable-or-fatal outcome the caller surfaces; the pool never falls
/// back to an unbounded inline hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashRejection {
    /// The tenant exceeded its fair-share hashing admission (issue #50). Retryable
    /// `429`; the snapshot yields the `RateLimit` headers and the block signal.
    Overloaded(Box<RateLimitSnapshot>),
    /// The bounded pool queue is full. Retryable `503` (load shed).
    PoolExhausted,
    /// The pool could not complete the operation (a worker fault, a shutting-down
    /// pool, or an invalid parameter triple). Fatal server error; never a silent
    /// inline hash.
    Unavailable,
}

impl HashRejection {
    /// The retryable HTTP response for this rejection: a `429` carrying the quota
    /// layer's `RateLimit` headers and block signal for an over-share tenant, a
    /// `503` with `Retry-After` for a full pool, and a `500` for an internal pool
    /// fault. Every response body is a small, machine-readable JSON object with a
    /// stable `error` code, so a client (or a WAF) can act on it without parsing
    /// prose. Verification never falls back to an inline hash; it surfaces this.
    #[must_use]
    pub fn to_response(&self) -> axum::response::Response {
        use axum::http::{HeaderName, HeaderValue, StatusCode, header};
        use axum::response::IntoResponse;

        match self {
            HashRejection::Overloaded(snapshot) => {
                let body = "{\"error\":\"rate_limited\",\"error_description\":\"the tenant \
                            password-hashing quota was exceeded; retry after the indicated \
                            delay\"}";
                let mut response = (StatusCode::TOO_MANY_REQUESTS, body).into_response();
                let headers = response.headers_mut();
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                for (name, value) in snapshot.headers() {
                    if let (Ok(name), Ok(value)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(&value),
                    ) {
                        headers.insert(name, value);
                    }
                }
                if let Some(cookie) = snapshot.block_set_cookie() {
                    if let Ok(value) = HeaderValue::from_str(&cookie) {
                        headers.append(header::SET_COOKIE, value);
                    }
                }
                response
            }
            HashRejection::PoolExhausted => {
                let body = "{\"error\":\"hashing_overloaded\",\"error_description\":\"the hashing \
                            pool is saturated; retry shortly\"}";
                let mut response = (StatusCode::SERVICE_UNAVAILABLE, body).into_response();
                let headers = response.headers_mut();
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                headers.insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                response
            }
            HashRejection::Unavailable => {
                let body = "{\"error\":\"server_error\",\"error_description\":\"the password \
                            hashing pool could not complete the request\"}";
                let mut response = (StatusCode::INTERNAL_SERVER_ERROR, body).into_response();
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                response
            }
        }
    }
}

/// The operation a job performs, so the worker records the right metric label and
/// returns the right result shape.
enum Op {
    /// Hash a plaintext at the configured parameters, returning the PHC string.
    Hash {
        password: String,
        params: Argon2Params,
        reply: oneshot::Sender<Result<String, ()>>,
    },
    /// Verify a plaintext against a stored PHC hash, returning the boolean verdict.
    Verify {
        password: String,
        stored: String,
        reply: oneshot::Sender<bool>,
    },
    /// Spend a full verification against a fixed dummy hash (the absent-account
    /// path) and return the constant `false`, so a missing account costs the same
    /// as a present one.
    VerifyAbsent {
        password: String,
        reply: oneshot::Sender<bool>,
    },
    /// A test probe: report whether the worker ran off a tokio runtime thread.
    Diagnostics {
        reply: oneshot::Sender<ThreadDiagnostics>,
    },
}

/// The result of the thread diagnostics probe: proof the job ran on a dedicated
/// worker and NOT on a tokio runtime thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadDiagnostics {
    /// Whether the job ran on a hashing-pool worker thread.
    pub on_hash_worker: bool,
    /// Whether a tokio runtime context was present on the executing thread. A
    /// dedicated worker has none; a tokio protocol-I/O (or blocking) thread does.
    pub tokio_runtime_present: bool,
}

/// The shared queue and its signaling, owned by the pool and every worker.
struct Shared {
    /// The FIFO of pending jobs, guarded together with the shutdown flag.
    queue: Mutex<VecDeque<Op>>,
    /// Signaled when a job is enqueued or shutdown begins.
    available: Condvar,
    /// Set once at drop; workers drain then exit.
    shutdown: AtomicBool,
    /// The maximum number of jobs that may wait before load-shedding.
    max_queue_depth: usize,
    /// Current number of workers executing a job (for the utilization gauge).
    active: AtomicI64,
}

impl Shared {
    /// Try to enqueue a job, failing closed when the queue is at its bound.
    fn enqueue(&self, op: Op) -> Result<(), Op> {
        let mut queue = self.queue.lock().expect("hashing queue lock poisoned");
        if self.shutdown.load(Ordering::Acquire) || queue.len() >= self.max_queue_depth {
            return Err(op);
        }
        queue.push_back(op);
        let depth = queue.len();
        drop(queue);
        record_queue_depth(depth);
        self.available.notify_one();
        Ok(())
    }
}

/// The dedicated Argon2id hashing pool with per-tenant fair-share admission.
///
/// Cheap to share behind an `Arc`; a single pool serves every request thread.
/// Dropping the last handle shuts the worker threads down and joins them.
pub struct HashingPool {
    shared: Arc<Shared>,
    env: Env,
    params: Argon2Params,
    /// The per-tenant/per-environment fair-share admission engine (issue #50), or
    /// `None` to disable admission (the self-hoster posture; the queue bound still
    /// applies).
    quota: Option<Arc<QuotaEnforcer>>,
    workers: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for HashingPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashingPool")
            .field("threads", &self.workers.len())
            .field("max_queue_depth", &self.shared.max_queue_depth)
            .field("params", &self.params)
            .field("admission", &self.quota.is_some())
            .finish_non_exhaustive()
    }
}

impl HashingPool {
    /// Build a pool of `threads` workers (at least one) with a `max_queue_depth`
    /// bound, minting new hashes at `params`, and admission through `quota` (when
    /// `Some`). The salt and latency clock come from `env`.
    ///
    /// # Panics
    ///
    /// Panics if an OS worker thread cannot be spawned; in an identity provider a
    /// hashing pool that cannot start its workers must fail loudly at boot rather
    /// than silently run with no capacity.
    #[must_use]
    pub fn new(
        env: Env,
        params: Argon2Params,
        threads: usize,
        max_queue_depth: usize,
        quota: Option<Arc<QuotaEnforcer>>,
    ) -> Self {
        let threads = threads.max(1);
        let max_queue_depth = max_queue_depth.max(1);
        let shared = Arc::new(Shared {
            queue: Mutex::new(VecDeque::new()),
            available: Condvar::new(),
            shutdown: AtomicBool::new(false),
            max_queue_depth,
            active: AtomicI64::new(0),
        });
        let clock = env.clock_arc();
        let mut workers = Vec::with_capacity(threads);
        for index in 0..threads {
            let shared = Arc::clone(&shared);
            let worker_env = env.clone();
            let worker_clock = Arc::clone(&clock);
            let handle = std::thread::Builder::new()
                .name(format!("ironauth-hash-{index}"))
                .spawn(move || worker_loop(&shared, &worker_env, worker_clock.as_ref()))
                .expect("spawning a hashing worker thread");
            workers.push(handle);
        }
        record_pool_threads(threads);
        record_queue_depth(0);
        Self {
            shared,
            env,
            params,
            quota,
            workers,
        }
    }

    /// Charge one password-hash admission for `scope` against the fair-share
    /// engine. `Ok(())` admits; `Err` is the typed rejection with the block
    /// signal. A pool with no quota engine always admits.
    fn admit(&self, scope: &Scope) -> Result<(), HashRejection> {
        let Some(quota) = self.quota.as_ref() else {
            return Ok(());
        };
        let quota_scope = QuotaScope::Environment(
            QuotaTenantId::new(scope.tenant().to_string()),
            QuotaEnvironmentId::new(scope.environment().to_string()),
        );
        let outcome = quota.admit(&quota_scope, QuotaDimension::PasswordHashing, 1.0);
        if outcome.decision.is_denied() {
            metrics::counter!(ADMISSION_REJECTED_TOTAL, "reason" => "over_share").increment(1);
            return Err(HashRejection::Overloaded(Box::new(outcome.snapshot)));
        }
        Ok(())
    }

    /// Submit an already-admitted job, mapping a full queue to `PoolExhausted`.
    fn submit(&self, op: Op) -> Result<(), HashRejection> {
        self.shared.enqueue(op).map_err(|_| {
            metrics::counter!(ADMISSION_REJECTED_TOTAL, "reason" => "pool_exhausted").increment(1);
            HashRejection::PoolExhausted
        })
    }

    /// Hash `password` for `scope` at the configured parameters, off the async
    /// threads and behind fair-share admission.
    ///
    /// # Errors
    ///
    /// [`HashRejection`] when the tenant is over its share (`Overloaded`), the
    /// pool queue is full (`PoolExhausted`), or the pool could not complete the
    /// hash (`Unavailable`). Never falls back to an inline hash.
    pub async fn hash(&self, scope: &Scope, password: &str) -> Result<String, HashRejection> {
        self.admit(scope)?;
        let (reply, rx) = oneshot::channel();
        self.submit(Op::Hash {
            password: password.to_owned(),
            params: self.params,
            reply,
        })?;
        match rx.await {
            Ok(Ok(hash)) => Ok(hash),
            Ok(Err(())) | Err(_) => Err(HashRejection::Unavailable),
        }
    }

    /// Verify `password` against a stored PHC `hash` for `scope`, off the async
    /// threads and behind fair-share admission.
    ///
    /// # Errors
    ///
    /// [`HashRejection`] on over-share, pool exhaustion, or pool fault. A wrong
    /// password (or a malformed stored hash) is `Ok(false)`, never an error.
    pub async fn verify(
        &self,
        scope: &Scope,
        password: &str,
        hash: &str,
    ) -> Result<bool, HashRejection> {
        self.admit(scope)?;
        let (reply, rx) = oneshot::channel();
        self.submit(Op::Verify {
            password: password.to_owned(),
            stored: hash.to_owned(),
            reply,
        })?;
        rx.await.map_err(|_| HashRejection::Unavailable)
    }

    /// Spend a full verification for `scope` against a fixed dummy hash and return
    /// `false`, so an absent account is timing-indistinguishable from a present
    /// one. Still admission-controlled, so stuffing unknown identifiers cannot
    /// bypass fair-share admission.
    ///
    /// # Errors
    ///
    /// [`HashRejection`] on over-share, pool exhaustion, or pool fault.
    pub async fn verify_absent(
        &self,
        scope: &Scope,
        password: &str,
    ) -> Result<bool, HashRejection> {
        self.admit(scope)?;
        let (reply, rx) = oneshot::channel();
        self.submit(Op::VerifyAbsent {
            password: password.to_owned(),
            reply,
        })?;
        rx.await.map_err(|_| HashRejection::Unavailable)
    }

    /// The configured hashing parameters new hashes are minted at.
    #[must_use]
    pub fn params(&self) -> Argon2Params {
        self.params
    }

    /// The environment seam this pool hashes with.
    #[must_use]
    pub fn env(&self) -> &Env {
        &self.env
    }

    /// Run a diagnostics job and report the executing thread's context. Used by
    /// the acceptance check that hashing runs off the tokio runtime threads.
    ///
    /// # Errors
    ///
    /// [`HashRejection::PoolExhausted`] if the queue is full, or
    /// [`HashRejection::Unavailable`] if the worker could not answer.
    pub async fn thread_diagnostics(&self) -> Result<ThreadDiagnostics, HashRejection> {
        let (reply, rx) = oneshot::channel();
        self.submit(Op::Diagnostics { reply })?;
        rx.await.map_err(|_| HashRejection::Unavailable)
    }
}

impl Drop for HashingPool {
    fn drop(&mut self) {
        // Signal shutdown and wake every worker; a worker mid-hash finishes it,
        // then drains the (now shrinking) queue and exits.
        {
            let _guard = self
                .shared
                .queue
                .lock()
                .expect("hashing queue lock poisoned");
            self.shared.shutdown.store(true, Ordering::Release);
        }
        self.shared.available.notify_all();
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

/// The worker loop: block for a job, run it off the async threads, repeat until
/// shutdown drains the queue.
fn worker_loop(shared: &Shared, env: &Env, clock: &dyn ironauth_env::Clock) {
    ON_HASH_WORKER.with(|flag| flag.set(true));
    loop {
        let op = {
            let mut queue = shared.queue.lock().expect("hashing queue lock poisoned");
            loop {
                if let Some(op) = queue.pop_front() {
                    let depth = queue.len();
                    drop(queue);
                    record_queue_depth(depth);
                    break op;
                }
                if shared.shutdown.load(Ordering::Acquire) {
                    return;
                }
                queue = shared
                    .available
                    .wait(queue)
                    .expect("hashing queue lock poisoned");
            }
        };
        shared.active.fetch_add(1, Ordering::AcqRel);
        record_active(shared.active.load(Ordering::Acquire));
        run_op(op, env, clock);
        shared.active.fetch_sub(1, Ordering::AcqRel);
        record_active(shared.active.load(Ordering::Acquire));
    }
}

/// Execute one job on the worker thread, recording its latency.
fn run_op(op: Op, env: &Env, clock: &dyn ironauth_env::Clock) {
    match op {
        Op::Hash {
            password,
            params,
            reply,
        } => {
            let start = clock.monotonic();
            let result = password::hash_password_with(env, &password, params);
            record_duration("hash", clock, start);
            let _ = reply.send(result.map_err(|_| ()));
        }
        Op::Verify {
            password,
            stored,
            reply,
        } => {
            let start = clock.monotonic();
            let verdict = password::verify_password(&password, &stored);
            record_duration("verify", clock, start);
            let _ = reply.send(verdict);
        }
        Op::VerifyAbsent { password, reply } => {
            let start = clock.monotonic();
            let verdict = password::verify_absent(&password);
            record_duration("verify", clock, start);
            let _ = reply.send(verdict);
        }
        Op::Diagnostics { reply } => {
            let _ = reply.send(ThreadDiagnostics {
                on_hash_worker: on_hash_worker_thread(),
                tokio_runtime_present: tokio::runtime::Handle::try_current().is_ok(),
            });
        }
    }
}

/// Record a job's wall-clock duration through the monotonic seam.
fn record_duration(op: &'static str, clock: &dyn ironauth_env::Clock, start: std::time::Instant) {
    let elapsed = clock.monotonic().saturating_duration_since(start);
    metrics::histogram!(HASH_DURATION_SECONDS, "op" => op).record(elapsed.as_secs_f64());
}

/// Publish the current queue depth gauge.
#[allow(
    clippy::cast_precision_loss,
    reason = "queue depth is a small operational magnitude far below 2^53"
)]
fn record_queue_depth(depth: usize) {
    metrics::gauge!(POOL_QUEUE_DEPTH).set(depth as f64);
}

/// Publish the fixed worker-capacity gauge.
#[allow(
    clippy::cast_precision_loss,
    reason = "a worker-thread count is a small magnitude far below 2^53"
)]
fn record_pool_threads(threads: usize) {
    metrics::gauge!(POOL_THREADS).set(threads as f64);
}

/// Publish the current active-worker gauge.
#[allow(
    clippy::cast_precision_loss,
    reason = "active-worker count is a small magnitude far below 2^53"
)]
fn record_active(active: i64) {
    metrics::gauge!(POOL_ACTIVE_WORKERS).set(active.max(0) as f64);
}

/// Register the hashing-pool metric descriptions once, mirroring the server's
/// metrics-describe pattern. Safe to call after the Prometheus recorder is
/// installed; a no-op if no recorder is present.
pub fn describe_hashing_pool_metrics() {
    metrics::describe_histogram!(
        HASH_DURATION_SECONDS,
        metrics::Unit::Seconds,
        "Argon2id hash/verify duration by operation"
    );
    metrics::describe_gauge!(
        POOL_QUEUE_DEPTH,
        "Password-hash jobs waiting for a pool worker"
    );
    metrics::describe_gauge!(
        POOL_ACTIVE_WORKERS,
        "Pool worker threads currently executing a hash"
    );
    metrics::describe_gauge!(POOL_THREADS, "Configured hashing-pool worker capacity");
    metrics::describe_counter!(
        ADMISSION_REJECTED_TOTAL,
        "Password-hash admissions rejected, by reason (over_share/pool_exhausted)"
    );
}

/// Derive a safe default worker-thread count from the host core count when config
/// leaves `pool_threads` at 0. Uses all available parallelism, clamped to at least
/// one, so hashing scales with the host without a config change.
#[must_use]
pub fn default_pool_threads() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}
