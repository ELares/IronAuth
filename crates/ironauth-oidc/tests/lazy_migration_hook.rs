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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

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
    );
    (hook, verifier, clock)
}

#[tokio::test]
async fn a_verified_credential_returns_the_profile() {
    let profile = HookProfile {
        claims: Some(serde_json::json!({"email": "u@example.test"})),
        traits: None,
    };
    let (hook, verifier, _clock) = hook_with_stub(Stub::Verified(Some(profile)), 3, 30, 30);
    match hook.attempt("u@example.test", "pw").await {
        HookOutcome::Verified(Some(profile)) => {
            assert_eq!(
                profile.claims.expect("claims")["email"],
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
