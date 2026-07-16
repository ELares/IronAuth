// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inbound lazy-migration hook against a STUB verifier (issue #56), database-free.
//!
//! These tests drive the hook orchestration ([`LazyMigrationHook::attempt`]) and its
//! circuit breaker directly, without a database or the login path, plus the webhook
//! verifier's SSRF posture through the hardened fetcher and a metrics-presence render.
//! The end-to-end login path (create-on-verified, second-login-skips-hook, uniformity)
//! lives in the DB-backed `lazy_migration` test.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::sync::{Notify, Semaphore};

use ironauth_env::{Clock, ManualClock};
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_oidc::{
    BreakerState, CircuitBreaker, CredentialVerifier, HookError, HookOutcome, HookProfile,
    HookVerdict, LAZY_MIGRATION_BREAKER_STATE, LAZY_MIGRATION_BREAKER_TRANSITIONS_TOTAL,
    LAZY_MIGRATION_HOOK_LATENCY_SECONDS, LAZY_MIGRATION_HOOK_TOTAL, LAZY_MIGRATION_MIGRATED_TOTAL,
    LazyMigrationHook, WebhookVerifier,
};

/// What the stub verifier returns on its next call.
#[derive(Clone)]
enum Stub {
    /// A positive verdict with an optional profile.
    Verified(Option<HookProfile>),
    /// A negative verdict (wrong password / unknown to the legacy store).
    Rejected,
    /// A failed call (an error or a timeout).
    Fail(HookError),
}

/// A stub [`CredentialVerifier`] that counts calls and returns a settable response, so a
/// test can assert both the verdict handling and that an OPEN breaker does not call it.
struct StubVerifier {
    calls: AtomicUsize,
    stub: Mutex<Stub>,
}

impl StubVerifier {
    fn new(stub: Stub) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            stub: Mutex::new(stub),
        }
    }

    fn set(&self, stub: Stub) {
        *self.stub.lock().expect("stub lock") = stub;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl CredentialVerifier for StubVerifier {
    fn verify<'a>(
        &'a self,
        _identifier: &'a str,
        _credential: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<HookVerdict, HookError>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let stub = self.stub.lock().expect("stub lock").clone();
        Box::pin(async move {
            match stub {
                Stub::Verified(profile) => Ok(HookVerdict::Verified(profile)),
                Stub::Rejected => Ok(HookVerdict::Rejected),
                Stub::Fail(error) => Err(error),
            }
        })
    }
}

/// Assemble a hook over a stub verifier and a manual-clock breaker, returning the hook,
/// the stub handle (for call-count and response control), and the clock (to drive the
/// breaker window/cooldown deterministically).
fn hook_with_stub(
    stub: Stub,
    threshold: u32,
    window_secs: u64,
    cooldown_secs: u64,
) -> (LazyMigrationHook, Arc<StubVerifier>, Arc<ManualClock>) {
    let verifier = Arc::new(StubVerifier::new(stub));
    let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
    let breaker = CircuitBreaker::new(
        Arc::clone(&clock) as Arc<dyn Clock>,
        threshold,
        Duration::from_secs(window_secs),
        Duration::from_secs(cooldown_secs),
    );
    let hook = LazyMigrationHook::new(
        Arc::clone(&verifier) as Arc<dyn CredentialVerifier>,
        breaker,
        Arc::clone(&clock) as Arc<dyn Clock>,
        // A generous orchestrator timeout: these tests exercise verdict handling and the
        // breaker, not the timeout bound (that is `the_orchestrator_timeout_bounds...`).
        Duration::from_secs(3600),
    );
    (hook, verifier, clock)
}

#[tokio::test]
async fn a_verified_credential_returns_the_profile() {
    let profile = HookProfile {
        traits: Some(serde_json::json!({"email": "u@example.test"})),
    };
    let (hook, verifier, _clock) = hook_with_stub(Stub::Verified(Some(profile)), 3, 30, 30);
    match hook.attempt("u@example.test", "pw").await {
        HookOutcome::Verified(Some(profile)) => {
            assert_eq!(
                profile.traits.expect("traits")["email"],
                serde_json::json!("u@example.test")
            );
        }
        _ => panic!("expected a verified verdict with a profile"),
    }
    assert_eq!(verifier.calls(), 1);
    assert_eq!(hook.breaker_state(), BreakerState::Closed);
}

#[tokio::test]
async fn a_rejected_credential_does_not_trip_the_breaker() {
    // A verdict (even a negative one) is a HEALTHY response: many rejections in a row
    // never open the breaker.
    let (hook, verifier, _clock) = hook_with_stub(Stub::Rejected, 3, 30, 30);
    for _ in 0..10 {
        assert!(matches!(
            hook.attempt("u@example.test", "wrong").await,
            HookOutcome::Rejected
        ));
    }
    assert_eq!(verifier.calls(), 10);
    assert_eq!(
        hook.breaker_state(),
        BreakerState::Closed,
        "a wrong-password verdict is healthy and must not trip the breaker"
    );
}

#[tokio::test]
async fn timeouts_open_the_breaker_then_it_fails_fast_and_recovers() {
    let (hook, verifier, clock) = hook_with_stub(Stub::Fail(HookError::Timeout), 3, 30, 30);

    // Three timeouts within the window trip the breaker OPEN. Each is Unavailable.
    for _ in 0..3 {
        assert!(matches!(
            hook.attempt("u@example.test", "pw").await,
            HookOutcome::Unavailable
        ));
    }
    assert_eq!(verifier.calls(), 3);
    assert_eq!(hook.breaker_state(), BreakerState::Open);

    // While OPEN the hook fails fast WITHOUT calling the verifier: the call count is
    // frozen. This is the resilience property: a dead backend cannot stall logins.
    for _ in 0..5 {
        assert!(matches!(
            hook.attempt("u@example.test", "pw").await,
            HookOutcome::Unavailable
        ));
    }
    assert_eq!(
        verifier.calls(),
        3,
        "an OPEN breaker must not call the verifier"
    );

    // After the cooldown the breaker half-opens and trials one call; a success closes it.
    clock.advance(Duration::from_secs(30));
    verifier.set(Stub::Verified(None));
    assert!(matches!(
        hook.attempt("u@example.test", "pw").await,
        HookOutcome::Verified(None)
    ));
    assert_eq!(
        verifier.calls(),
        4,
        "the half-open trial calls the verifier once"
    );
    assert_eq!(
        hook.breaker_state(),
        BreakerState::Closed,
        "a successful trial closes the breaker"
    );
}

#[tokio::test]
async fn transport_errors_are_unavailable() {
    let (hook, _verifier, _clock) = hook_with_stub(Stub::Fail(HookError::Transport), 3, 30, 30);
    assert!(matches!(
        hook.attempt("u@example.test", "pw").await,
        HookOutcome::Unavailable
    ));
}

#[tokio::test]
async fn the_webhook_refuses_a_plaintext_http_target() {
    // A plaintext http endpoint is refused by the hardened fetcher (https-only) before
    // any connection: the hook maps that to Blocked. The resolver/dialer are never
    // reached because the scheme check fires first.
    let resolver = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let dialer = Arc::new(RecordingDialer::new("127.0.0.1:9".parse().expect("addr")));
    let fetcher = Arc::new(Fetcher::from_parts(
        FetchLimits::default(),
        resolver,
        dialer,
    ));
    let verifier = WebhookVerifier::new(fetcher, "http://legacy.test/verify", None);

    let result = verifier.verify("u@example.test", "pw").await;
    assert!(
        matches!(result, Err(HookError::Blocked)),
        "a plaintext http target must be refused (got {:?})",
        result.err()
    );
}

#[tokio::test]
async fn the_webhook_refuses_an_ssrf_loopback_target() {
    // An https endpoint whose host resolves to a loopback address is refused by the
    // SSRF policy at validation time (before any TLS handshake): the hook maps the
    // uniform fetcher block to Blocked.
    let resolver = Arc::new(StaticResolver::new(vec!["127.0.0.1".parse().expect("ip")]));
    let dialer = Arc::new(RecordingDialer::new("127.0.0.1:9".parse().expect("addr")));
    let fetcher = Arc::new(Fetcher::from_parts(
        FetchLimits::default(),
        resolver,
        dialer,
    ));
    let verifier = WebhookVerifier::new(fetcher, "https://legacy.internal/verify", None);

    let result = verifier.verify("u@example.test", "pw").await;
    assert!(
        matches!(result, Err(HookError::Blocked)),
        "a target resolving to loopback must be refused (got {:?})",
        result.err()
    );
}

#[tokio::test]
async fn migration_metrics_are_present_in_the_exposition() {
    // Install a Prometheus recorder for THIS test binary, then drive the hook so every
    // migration metric is recorded, and assert each name appears in the render.
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("install recorder");
    ironauth_oidc::describe_lazy_migration_metrics();

    let (hook, verifier, _clock) = hook_with_stub(Stub::Verified(None), 3, 30, 30);
    // A verified attempt records the outcome counter and the latency histogram.
    assert!(matches!(
        hook.attempt("u@example.test", "pw").await,
        HookOutcome::Verified(None)
    ));
    // The migrated counter.
    LazyMigrationHook::record_migrated();
    // Trip the breaker so the state gauge and the transition counter are emitted.
    verifier.set(Stub::Fail(HookError::Timeout));
    for _ in 0..3 {
        let _ = hook.attempt("u@example.test", "pw").await;
    }
    assert_eq!(hook.breaker_state(), BreakerState::Open);

    let text = handle.render();
    for name in [
        LAZY_MIGRATION_MIGRATED_TOTAL,
        LAZY_MIGRATION_HOOK_TOTAL,
        LAZY_MIGRATION_HOOK_LATENCY_SECONDS,
        LAZY_MIGRATION_BREAKER_STATE,
        LAZY_MIGRATION_BREAKER_TRANSITIONS_TOTAL,
    ] {
        assert!(text.contains(name), "metric {name} missing from:\n{text}");
    }
}

/// A verifier whose calls can be made to FAIL (to trip the breaker) or to BLOCK until the
/// test releases them (to hold a half-open trial in flight, or to be bounded by the
/// orchestrator timeout). It counts every entry, so a test can assert exactly how many
/// outbound calls a burst produced.
struct GatingVerifier {
    calls: AtomicUsize,
    /// 0 = fail immediately with a timeout error; 1 = block on `gate` until released.
    mode: AtomicU8,
    /// Signaled once a BLOCK-mode call has entered and taken the trial (so the test knows
    /// the single probe is in flight before it inspects the losers).
    entered: Notify,
    /// A BLOCK-mode call waits here; it never proceeds unless the test adds a permit.
    gate: Semaphore,
}

impl GatingVerifier {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mode: AtomicU8::new(0),
            entered: Notify::new(),
            gate: Semaphore::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn set_block(&self) {
        self.mode.store(1, Ordering::SeqCst);
    }

    /// Switch back to fail-fast mode (return a timeout error immediately), so a later
    /// recovery trial resolves promptly instead of parking on the gate.
    fn set_fail(&self) {
        self.mode.store(0, Ordering::SeqCst);
    }
}

impl CredentialVerifier for GatingVerifier {
    fn verify<'a>(
        &'a self,
        _identifier: &'a str,
        _credential: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<HookVerdict, HookError>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mode = self.mode.load(Ordering::SeqCst);
        Box::pin(async move {
            if mode == 0 {
                return Err(HookError::Timeout);
            }
            // Block-mode: announce we hold the trial, then wait to be released (which the
            // burst test never does; it aborts us) or to be cancelled by the orchestrator
            // timeout.
            self.entered.notify_one();
            let _permit = self.gate.acquire().await.expect("semaphore open");
            Ok(HookVerdict::Verified(None))
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_half_open_burst_fires_exactly_one_outbound_trial() {
    // The half-open probe is admitted ONCE, not once per concurrent login. Trip the breaker
    // (threshold 1), let the cooldown elapse, then fire a burst of 16 concurrent attempts
    // while the single trial is held in flight: exactly ONE reaches the backend; the other
    // 15 fail fast without an outbound call.
    let verifier = Arc::new(GatingVerifier::new());
    let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
    let breaker = CircuitBreaker::new(
        Arc::clone(&clock) as Arc<dyn Clock>,
        1,
        Duration::from_secs(30),
        Duration::from_secs(30),
    );
    let hook = Arc::new(LazyMigrationHook::new(
        Arc::clone(&verifier) as Arc<dyn CredentialVerifier>,
        breaker,
        Arc::clone(&clock) as Arc<dyn Clock>,
        // A large orchestrator timeout so it never fires here (this test is about the
        // breaker's one-trial gate, not the timeout).
        Duration::from_secs(3600),
    ));

    // 1. A single failure opens the breaker (fail mode).
    assert!(matches!(
        hook.attempt("u@example.test", "pw").await,
        HookOutcome::Unavailable
    ));
    assert_eq!(hook.breaker_state(), BreakerState::Open);
    assert_eq!(
        verifier.calls(),
        1,
        "one outbound so far (the failing call)"
    );

    // 2. Cooldown elapses; the next attempt would half-open. Switch to block mode so the
    //    single trial stays in flight while the burst races the breaker.
    clock.advance(Duration::from_secs(30));
    verifier.set_block();

    // 3. Fire 16 concurrent attempts. Exactly one wins the trial and blocks; the rest see a
    //    trial in progress and fail fast.
    let n = 16;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut handles = Vec::new();
    for _ in 0..n {
        let hook = Arc::clone(&hook);
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            let outcome = hook.attempt("u@example.test", "pw").await;
            // Only the fast-failers report; the single winner blocks and never sends.
            if matches!(outcome, HookOutcome::Unavailable) {
                let _ = tx.send(());
            }
        }));
    }
    drop(tx);

    // Wait until the winner is inside the backend holding the trial.
    verifier.entered.notified().await;

    // Exactly n-1 attempts fast-fail without an outbound call.
    for _ in 0..(n - 1) {
        rx.recv().await.expect("a fast-failed attempt");
    }
    assert_eq!(
        verifier.calls(),
        2,
        "exactly ONE outbound trial under the burst (plus the earlier failing call)"
    );
    assert_eq!(hook.breaker_state(), BreakerState::HalfOpen);

    // The winner is parked on the gate forever; abort it (and any stragglers).
    for handle in handles {
        handle.abort();
    }
}

#[tokio::test]
async fn the_orchestrator_timeout_bounds_a_verifier_that_does_not_self_bound() {
    // The shipped WebhookVerifier self-bounds via the fetcher, but the CredentialVerifier
    // trait admits a future impl (an M11 WASM verifier) that does not. The orchestrator
    // wraps the call in the configured timeout, so such a verifier cannot stall the login:
    // a block-forever verify is bounded and counted as a failure toward the breaker.
    let verifier = Arc::new(GatingVerifier::new());
    verifier.set_block();
    let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
    let breaker = CircuitBreaker::new(
        Arc::clone(&clock) as Arc<dyn Clock>,
        1,
        Duration::from_secs(30),
        Duration::from_secs(30),
    );
    let hook = LazyMigrationHook::new(
        Arc::clone(&verifier) as Arc<dyn CredentialVerifier>,
        breaker,
        Arc::clone(&clock) as Arc<dyn Clock>,
        // A short real-time orchestrator bound; the verifier would otherwise block forever.
        Duration::from_millis(100),
    );

    // Bound the whole attempt with a generous 5s tokio timeout: if the orchestrator did NOT
    // enforce its own 100ms timeout, the block-forever verifier would hang and this outer
    // timeout would fire (an `Err`), failing the test. That it resolves proves the
    // orchestrator bounded the non-self-bounding verifier well within the outer bound.
    let outcome =
        tokio::time::timeout(Duration::from_secs(5), hook.attempt("u@example.test", "pw"))
            .await
            .expect("the orchestrator bounds the verifier; the attempt must not hang");

    assert!(
        matches!(outcome, HookOutcome::Unavailable),
        "a non-self-bounding verifier is bounded to the uniform failure"
    );
    assert_eq!(verifier.calls(), 1, "the verifier was entered exactly once");
    assert_eq!(
        hook.breaker_state(),
        BreakerState::Open,
        "an orchestrator timeout counts as a failure toward the breaker"
    );
}

#[tokio::test]
async fn a_dropped_half_open_trial_re_opens_the_breaker_and_recovers() {
    // The login handler awaits `attempt` INLINE, so a client disconnect / request timeout /
    // graceful-shutdown cancellation drops the future mid-trial. Before the fix that left
    // `trial_in_progress` set forever, wedging the breaker in half-open and disabling lazy
    // migration on the node until restart. The RAII trial guard must release the slot and
    // re-open the breaker so it recovers on the next cooldown.
    let verifier = Arc::new(GatingVerifier::new());
    let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
    let breaker = CircuitBreaker::new(
        Arc::clone(&clock) as Arc<dyn Clock>,
        1,
        Duration::from_secs(30),
        Duration::from_secs(30),
    );
    let hook = LazyMigrationHook::new(
        Arc::clone(&verifier) as Arc<dyn CredentialVerifier>,
        breaker,
        Arc::clone(&clock) as Arc<dyn Clock>,
        // A large orchestrator timeout so the DROP, not the timeout, ends the trial.
        Duration::from_secs(3600),
    );

    // Open the breaker (one failure at threshold 1), then let the cooldown elapse so the
    // next attempt half-opens and takes the single trial slot.
    assert!(matches!(
        hook.attempt("u@example.test", "pw").await,
        HookOutcome::Unavailable
    ));
    assert_eq!(hook.breaker_state(), BreakerState::Open);
    clock.advance(Duration::from_secs(30));

    // Start a half-open trial that blocks in the backend holding the slot, then DROP the
    // attempt future mid-await while that single probe is in flight.
    verifier.set_block();
    {
        let mut fut = Box::pin(hook.attempt("u@example.test", "pw"));
        tokio::select! {
            biased;
            _ = &mut fut => panic!("the blocking trial must not resolve on its own"),
            () = verifier.entered.notified() => {}
        }
        assert_eq!(
            verifier.calls(),
            2,
            "the half-open trial reached the backend"
        );
        assert_eq!(
            hook.breaker_state(),
            BreakerState::HalfOpen,
            "the single probe is in flight"
        );
        // `fut` drops HERE (end of block), running the trial guard's Drop on an unresolved
        // trial.
    }

    // The RAII guard released the abandoned slot and re-opened the breaker IMMEDIATELY
    // (proof the guard fired, not merely the lazy allow() self-heal).
    assert_eq!(
        hook.breaker_state(),
        BreakerState::Open,
        "a dropped half-open trial re-opens the breaker instead of wedging it half-open"
    );

    // After the next cooldown a FRESH trial is admitted and EXACTLY ONE new outbound call
    // fires: proof the slot was truly released and the breaker recovered.
    clock.advance(Duration::from_secs(30));
    verifier.set_fail();
    let before = verifier.calls();
    assert!(matches!(
        hook.attempt("u@example.test", "pw").await,
        HookOutcome::Unavailable
    ));
    assert_eq!(
        verifier.calls(),
        before + 1,
        "recovery admits exactly one fresh trial after a dropped one (breaker not wedged)"
    );
}

/// A verifier that either fails fast (open the breaker) or PANICS across an await, so a
/// test can drive a panicking half-open trial and prove the guard still releases the slot.
struct PanicVerifier {
    calls: AtomicUsize,
    /// 0 = fail immediately with a timeout error; 1 = panic across an await point.
    mode: AtomicU8,
}

impl PanicVerifier {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mode: AtomicU8::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn set_panic(&self) {
        self.mode.store(1, Ordering::SeqCst);
    }

    fn set_fail(&self) {
        self.mode.store(0, Ordering::SeqCst);
    }
}

impl CredentialVerifier for PanicVerifier {
    fn verify<'a>(
        &'a self,
        _identifier: &'a str,
        _credential: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<HookVerdict, HookError>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mode = self.mode.load(Ordering::SeqCst);
        Box::pin(async move {
            if mode == 0 {
                return Err(HookError::Timeout);
            }
            // Panic ACROSS an await point, so the `attempt` future is unwound mid-poll and
            // the trial guard's Drop runs on the way out.
            tokio::task::yield_now().await;
            panic!("verifier panicked mid-trial");
        })
    }
}

#[tokio::test]
async fn a_panicking_half_open_trial_re_opens_the_breaker_and_recovers() {
    // A verifier that PANICS across the await also skips `record_success`/`record_failure`.
    // The trial guard's Drop, which runs as the panicking future unwinds, must release the
    // slot and re-open the breaker so the node is not stuck in half-open until restart.
    let verifier = Arc::new(PanicVerifier::new());
    let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
    let breaker = CircuitBreaker::new(
        Arc::clone(&clock) as Arc<dyn Clock>,
        1,
        Duration::from_secs(30),
        Duration::from_secs(30),
    );
    let hook = Arc::new(LazyMigrationHook::new(
        Arc::clone(&verifier) as Arc<dyn CredentialVerifier>,
        breaker,
        Arc::clone(&clock) as Arc<dyn Clock>,
        Duration::from_secs(3600),
    ));

    // Open the breaker (fail mode), then let the cooldown elapse.
    assert!(matches!(
        hook.attempt("u@example.test", "pw").await,
        HookOutcome::Unavailable
    ));
    assert_eq!(hook.breaker_state(), BreakerState::Open);
    clock.advance(Duration::from_secs(30));

    // The next attempt takes the half-open trial slot; the verifier PANICS. Run it in a
    // task so the panic is caught at the task boundary; the attempt future unwinds through
    // the trial guard's Drop on the way out.
    verifier.set_panic();
    let hook_task = Arc::clone(&hook);
    let joined = tokio::spawn(async move { hook_task.attempt("u@example.test", "pw").await }).await;
    match joined {
        Ok(_) => panic!("the panicking trial should have aborted the task, not resolved"),
        Err(err) => assert!(err.is_panic(), "the task ended by panic, as staged"),
    }
    assert_eq!(
        verifier.calls(),
        2,
        "the half-open trial reached the panicking verifier"
    );

    // The guard released the slot on unwind and re-opened the breaker: not wedged.
    assert_eq!(
        hook.breaker_state(),
        BreakerState::Open,
        "a panicking half-open trial re-opens the breaker instead of wedging it half-open"
    );

    // After the next cooldown a fresh trial is admitted (exactly one new outbound), proving
    // recovery.
    clock.advance(Duration::from_secs(30));
    verifier.set_fail();
    let before = verifier.calls();
    assert!(matches!(
        hook.attempt("u@example.test", "pw").await,
        HookOutcome::Unavailable
    ));
    assert_eq!(
        verifier.calls(),
        before + 1,
        "recovery admits exactly one fresh trial after a panicked one (breaker not wedged)"
    );
}
