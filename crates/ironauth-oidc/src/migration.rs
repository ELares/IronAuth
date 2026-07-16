// SPDX-License-Identifier: MIT OR Apache-2.0

//! The inbound lazy-migration hook (issue #56).
//!
//! Bulk import (issue #55) only works when the source system will export password
//! hashes. When it will not (Cognito can never export hashes; other stores are
//! simply unreachable), the industry answer is lazy migration: verify the user's
//! FIRST login against the legacy store, capture the password in flight, and rehash
//! it locally to the native Argon2id verifier. On success the user is created
//! locally and is MIGRATED by construction (a native hash and no foreign hash), so
//! every subsequent login verifies natively and never calls the hook again. A
//! standard #55 bulk import closes out the tail of stragglers, after which the hook
//! is disabled per environment (a pure config change).
//!
//! # Where it plugs in
//!
//! The login path ([`crate::login`]) calls [`LazyMigrationHook::attempt`] ONLY when
//! the submitted identifier is UNKNOWN locally (a user already present locally is
//! served entirely from the local store, including the #55 verify-then-rehash of an
//! imported foreign hash; the hook is never consulted for them). Every failure verdict
//! falls through to the SAME uniform login failure a local wrong password produces, so
//! the hook's existence is not observable to an attacker.
//!
//! # Implementation-agnostic contract
//!
//! The verifier is a trait ([`CredentialVerifier`]), so the M11 WASM hooks engine can
//! slot a WASM implementation in behind the same interface without touching the login
//! path. The only implementation shipped here is [`WebhookVerifier`], which delivers
//! the verification over the M1 SSRF-hardened outbound fetcher ([`ironauth_fetch`]),
//! HTTPS ONLY: a plaintext target, or one that resolves to a loopback or internal
//! address, is refused exactly like any other blocked destination.
//!
//! # Resilience
//!
//! The hook rides the login path, so a slow or dead legacy backend must never stall a
//! login for long. Three mechanisms bound the blast radius, all configurable with safe
//! defaults ([`ironauth_config::LazyMigrationConfig`]):
//!
//! - **Per-call timeout.** The fetcher aborts a call that exceeds `timeout_secs`, and the
//!   orchestrator ([`LazyMigrationHook::attempt`]) ALSO wraps the verifier in the same
//!   bound, so a verifier that does not self-bound (a future non-webhook impl) still cannot
//!   stall the login; there is no retry in the login path (one call, then a verdict). An
//!   elapsed timeout counts as a failure toward the breaker.
//! - **Circuit breaker.** [`CircuitBreaker`] opens when `breaker_failure_threshold`
//!   ERRORS or TIMEOUTS occur within `breaker_window_secs`. A verdict (verified OR
//!   rejected) is a HEALTHY response and never trips the breaker; only transport errors
//!   and timeouts do. While the breaker is OPEN, an unmigrated-user login fails fast
//!   with the uniform error and makes NO outbound call; local users are unaffected.
//!   After `breaker_cooldown_secs` the breaker HALF-OPENS and trials one call: a success
//!   closes it, a failure re-opens it for another cooldown. The breaker uses the
//!   [`ironauth_env`] monotonic clock seam, so its time window is deterministic under a
//!   manual clock in tests.
//! - **Observability.** Every attempt is metered (outcome counter and a latency
//!   histogram), the migrated count is a counter, and the breaker state is a gauge plus
//!   a transition counter. Breaker transitions are additionally recorded to the
//!   structured log stream (the process audit trail), the same discipline the fetcher
//!   uses for blocked destinations.
//!
//! Nothing in this module ever logs the identifier, the credential, or a profile.
//!
//! # Accepted timing residual (migration-window only)
//!
//! While the hook is armed, an unknown-local identifier takes the outbound-call path
//! (a network round trip) that an already-local wrong-password login does not, so an
//! attacker who can measure response time can distinguish an identifier that is ALREADY
//! migrated/local (fast) from one that is still unknown-local (slow, hits the hook). This
//! is an ACCEPTED, characterized residual, not a defect:
//!
//! - It reveals migration STATUS only, never credentials and never whether the identifier
//!   exists in the legacy store: a hook `Rejected` and a hook `Unavailable` both fall
//!   through to the same uniform failure the local wrong-password path produces, spending
//!   the same `verify_absent` work, so no verdict content leaks.
//! - It is bounded to the migration window: once the tail is drained and the hook is
//!   disabled per environment, the extra path is gone.
//! - It matches how Auth0 custom-database and Cognito `UserMigration` lazy migration
//!   behave; fully hiding a synchronous network call would require padding EVERY failed
//!   login to the hook timeout, a large latency tax on every user for a status-only
//!   signal. We deliberately do NOT add response-time padding.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http::{HeaderValue, Method, header};
use ironauth_config::{LazyMigrationConfig, SecretString};
use ironauth_env::{Clock, Env};
use ironauth_fetch::{FetchError, FetchLimits, FetchPurpose, FetchRequest, Fetcher};
use serde::Deserialize;

/// Total users created locally by the lazy-migration hook (issue #56).
pub const LAZY_MIGRATION_MIGRATED_TOTAL: &str = "ironauth_lazy_migration_migrated_total";
/// Total hook attempts, labeled by outcome
/// (`verified`/`rejected`/`timeout`/`blocked`/`error`/`breaker_open`).
pub const LAZY_MIGRATION_HOOK_TOTAL: &str = "ironauth_lazy_migration_hook_total";
/// Hook verification latency in seconds (the outbound call round-trip).
pub const LAZY_MIGRATION_HOOK_LATENCY_SECONDS: &str =
    "ironauth_lazy_migration_hook_latency_seconds";
/// The circuit-breaker state as a gauge: 0 closed, 1 half-open, 2 open.
pub const LAZY_MIGRATION_BREAKER_STATE: &str = "ironauth_lazy_migration_breaker_state";
/// Total circuit-breaker state transitions, labeled by the target state (`to`).
pub const LAZY_MIGRATION_BREAKER_TRANSITIONS_TOTAL: &str =
    "ironauth_lazy_migration_breaker_transitions_total";

/// Register the lazy-migration metric descriptions once, after a recorder is
/// installed. Optional (the metrics record without it); the binary calls it at
/// startup, next to the fetcher's `describe_metrics`, to attach help text.
pub fn describe_metrics() {
    metrics::describe_counter!(
        LAZY_MIGRATION_MIGRATED_TOTAL,
        "Users created locally by the lazy-migration hook on a verified first login"
    );
    metrics::describe_counter!(
        LAZY_MIGRATION_HOOK_TOTAL,
        "Lazy-migration hook attempts by outcome"
    );
    metrics::describe_histogram!(
        LAZY_MIGRATION_HOOK_LATENCY_SECONDS,
        metrics::Unit::Seconds,
        "Lazy-migration hook verification latency (the outbound call round-trip)"
    );
    metrics::describe_gauge!(
        LAZY_MIGRATION_BREAKER_STATE,
        "Lazy-migration circuit-breaker state: 0 closed, 1 half-open, 2 open"
    );
    metrics::describe_counter!(
        LAZY_MIGRATION_BREAKER_TRANSITIONS_TOTAL,
        "Lazy-migration circuit-breaker state transitions by target state"
    );
}

/// The optional profile a verifier returns alongside a positive verdict: the user's
/// identity-traits document, so the migration seeds the identity, not merely the
/// credential. Deliberately carries no `Debug`: traits are PII.
///
/// The traits document is the ONLY channel a legacy store seeds identity through, and it
/// is VALIDATED against the environment's active identity schema (issue #53) by the login
/// path before anything is persisted; an invalid profile is refused and nothing is
/// written. There is deliberately NO verbatim-claims channel: issue #56's profile spec is
/// "traits, identifiers ... validated against the active identity schema", so a hostile or
/// compromised legacy store cannot inject an attacker-controlled `email`/`email_verified`
/// or `groups`/`roles` claim that an RP would trust. The created user's released claims
/// come from the normal claim path, exactly like any other user. Additional login
/// identifiers a legacy store might return are out of scope for this issue: the submitted
/// login handle becomes the user's canonical identifier, and the flexible-identifier (#54)
/// fan-out from a migration profile is left to a later change.
#[derive(Clone, Default)]
pub struct HookProfile {
    /// The user's identity-traits document, or `None`. Validated against the active
    /// trait schema before the user is created; an invalid document refuses the whole
    /// migration.
    pub traits: Option<serde_json::Value>,
}

/// A verifier's verdict for one credential (issue #56).
pub enum HookVerdict {
    /// The legacy store confirmed the identifier plus credential, with an optional
    /// profile to seed the local identity.
    Verified(Option<HookProfile>),
    /// The legacy store answered but rejected the credential (a wrong password, or an
    /// identifier the legacy store does not know). A HEALTHY response: it does not trip
    /// the breaker.
    Rejected,
}

/// Why a verifier call did not yield a verdict (issue #56). Every variant is treated
/// as the hook being UNAVAILABLE: the login fails with the uniform error and the breaker
/// counts the call as a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookError {
    /// The per-call timeout elapsed before the legacy store answered.
    Timeout,
    /// The destination was refused by the SSRF policy, or a plaintext `http` target was
    /// presented (the uniform fetcher block).
    Blocked,
    /// A transport or protocol failure, a non-2xx response, or a malformed verdict body.
    Transport,
}

/// A pluggable external credential verifier (issue #56): the implementation-agnostic
/// seam the login path calls to check a first login against a legacy store. The M11
/// WASM hooks engine slots a WASM implementation in behind this same trait; the only
/// implementation shipped now is [`WebhookVerifier`].
pub trait CredentialVerifier: Send + Sync {
    /// Verify `identifier` plus `credential` against the legacy store. Neither argument
    /// is ever logged. Returns a [`HookVerdict`] when the store answered, or a
    /// [`HookError`] when the call could not be completed.
    fn verify<'a>(
        &'a self,
        identifier: &'a str,
        credential: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<HookVerdict, HookError>> + Send + 'a>>;
}

/// The webhook implementation of [`CredentialVerifier`] (issue #56): it POSTs the
/// identifier and credential as JSON to the configured legacy-store endpoint, over the
/// M1 SSRF-hardened fetcher, HTTPS ONLY, authenticated with the configured shared
/// bearer secret. Carries no `Debug` that could expose the secret.
pub struct WebhookVerifier {
    fetcher: Arc<Fetcher>,
    endpoint: String,
    secret: Option<SecretString>,
    // Permit a plaintext `http` endpoint. OFF in production (the endpoint is https-only,
    // enforced at config load AND by the fetcher); the test constructor turns it on so
    // an in-process loopback server can serve verdicts through the fetcher's injected
    // dialer.
    allow_http: bool,
}

impl std::fmt::Debug for WebhookVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookVerifier")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// The verdict body a webhook returns. Extra fields are ignored (forward compatible),
/// and the whole body is dropped if it does not parse. No `Debug`: the profile is PII.
#[derive(Deserialize)]
struct WebhookVerdict {
    /// Whether the legacy store confirmed the credential.
    verified: bool,
    /// The optional profile, present only on a positive verdict.
    #[serde(default)]
    profile: Option<WebhookProfile>,
}

/// The profile half of a webhook verdict body. A legacy store MAY send extra fields
/// (including a `claims` object): they are IGNORED, not persisted. The only channel that
/// seeds identity is the schema-validated `traits` document, so a hostile store cannot
/// inject an attacker-controlled claim that flows to an RP.
#[derive(Deserialize)]
struct WebhookProfile {
    #[serde(default)]
    traits: Option<serde_json::Value>,
}

impl WebhookVerifier {
    /// A production webhook verifier over `fetcher`, posting to `endpoint` (https-only)
    /// with the optional shared bearer `secret`.
    #[must_use]
    pub fn new(
        fetcher: Arc<Fetcher>,
        endpoint: impl Into<String>,
        secret: Option<SecretString>,
    ) -> Self {
        Self {
            fetcher,
            endpoint: endpoint.into(),
            secret,
            allow_http: false,
        }
    }

    /// Like [`WebhookVerifier::new`] but permitting a plaintext `http` endpoint, so an
    /// integration test can serve verdicts from an in-process loopback server through
    /// the fetcher's injected dialer. Behind the `testing` feature so it never exists in
    /// a production build.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn new_allow_http(
        fetcher: Arc<Fetcher>,
        endpoint: impl Into<String>,
        secret: Option<SecretString>,
    ) -> Self {
        Self {
            fetcher,
            endpoint: endpoint.into(),
            secret,
            allow_http: true,
        }
    }

    /// Map a fetcher error to the hook error class.
    fn classify(error: &FetchError) -> HookError {
        match error {
            FetchError::Timeout => HookError::Timeout,
            FetchError::Blocked | FetchError::SchemeNotAllowed => HookError::Blocked,
            _ => HookError::Transport,
        }
    }
}

impl CredentialVerifier for WebhookVerifier {
    fn verify<'a>(
        &'a self,
        identifier: &'a str,
        credential: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<HookVerdict, HookError>> + Send + 'a>> {
        Box::pin(async move {
            // The request body carries the credential to the legacy store over TLS; that
            // is the point of the hook. It is never logged.
            let body = serde_json::json!({
                "identifier": identifier,
                "credential": credential,
            })
            .to_string();

            let mut request =
                FetchRequest::new(FetchPurpose::LazyMigration, Method::POST, &self.endpoint)
                    .header(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    )
                    .body(body);
            if self.allow_http {
                request = request.allow_plaintext_http();
            }
            if let Some(secret) = &self.secret {
                // A malformed bearer value (a secret with control characters) is refused
                // rather than sent unauthenticated; treat it as a transport failure.
                let bearer = format!("Bearer {}", secret.expose());
                let Ok(value) = HeaderValue::from_str(&bearer) else {
                    return Err(HookError::Transport);
                };
                request = request.header(header::AUTHORIZATION, value);
            }

            let response = match self.fetcher.fetch(request).await {
                Ok(response) => response,
                Err(error) => return Err(Self::classify(&error)),
            };
            // A non-2xx is a backend problem (misconfigured endpoint, auth failure, or a
            // server error), not a verdict: count it as a failure so the breaker reacts.
            if !response.status().is_success() {
                return Err(HookError::Transport);
            }
            let Ok(verdict) = serde_json::from_slice::<WebhookVerdict>(response.body()) else {
                return Err(HookError::Transport);
            };
            if verdict.verified {
                let profile = verdict.profile.map(|profile| HookProfile {
                    traits: profile.traits,
                });
                Ok(HookVerdict::Verified(profile))
            } else {
                Ok(HookVerdict::Rejected)
            }
        })
    }
}

/// The circuit-breaker state (issue #56).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Calls flow to the verifier.
    Closed,
    /// The breaker is open: calls short-circuit to the uniform failure without an
    /// outbound call, until the cooldown elapses.
    Open,
    /// The cooldown elapsed and the breaker is trialing calls: a success closes it, a
    /// failure re-opens it.
    HalfOpen,
}

impl BreakerState {
    /// A stable, bounded label for metrics.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            BreakerState::Closed => "closed",
            BreakerState::Open => "open",
            BreakerState::HalfOpen => "half_open",
        }
    }

    /// The numeric gauge value: 0 closed, 1 half-open, 2 open.
    fn gauge(self) -> f64 {
        match self {
            BreakerState::Closed => 0.0,
            BreakerState::HalfOpen => 1.0,
            BreakerState::Open => 2.0,
        }
    }
}

/// The mutable breaker bookkeeping, behind one lock.
struct BreakerInner {
    state: BreakerState,
    /// Monotonic timestamps of the errors/timeouts inside the rolling window.
    failures: Vec<Instant>,
    /// When the breaker last opened (for the cooldown), on the monotonic clock.
    opened_at: Option<Instant>,
    /// Whether a HALF-OPEN trial call is currently outstanding. While it is, the breaker
    /// admits NO further calls: exactly one probe is in flight at a time, so a burst of
    /// concurrent logins after the cooldown does not stampede a still-dead backend. Reset
    /// on every transition out of half-open (success closes, failure re-opens), and also
    /// released by the orchestrator's RAII trial guard if a trial's future is abandoned
    /// (dropped mid-await or a panicking verifier) so the flag cannot stay set forever.
    trial_in_progress: bool,
    /// When the outstanding half-open trial was admitted, on the monotonic clock. Used by
    /// the [`allow`](CircuitBreaker::allow) self-heal backstop: if a trial has been
    /// in-flight longer than the cooldown (its future leaked without the guard or a
    /// `record_*` ever resolving it), the slot is treated as abandoned and reclaimed, so a
    /// dropped/forgotten trial can never wedge the breaker in half-open. `None` when no
    /// trial is outstanding.
    trial_started_at: Option<Instant>,
}

/// The breaker's decision for one call (the richer result of
/// [`CircuitBreaker::admit`]): whether the call may proceed, and if so whether this caller
/// took the single half-open trial slot. The orchestrator needs the latter so it can
/// arm the RAII guard that releases the slot when a trial is abandoned.
enum Admission {
    /// Fail fast: the breaker denied the call (open and still cooling, or a half-open
    /// trial is already outstanding and still fresh).
    Denied,
    /// The call may proceed to the verifier. `half_open_trial` is `true` when this caller
    /// took the single half-open trial slot and therefore owns it: it must resolve the
    /// trial (via `record_success`/`record_failure`) or release it on abandonment.
    Admitted { half_open_trial: bool },
}

/// An in-memory, per-node circuit breaker for the lazy-migration hook (issue #56).
///
/// In-memory and per-node by design: it is the simplest correct choice (no migration,
/// no shared state), and each node protecting itself is exactly the resilience the login
/// path needs. It opens on a sustained ERROR/TIMEOUT rate; a verdict never trips it. Its
/// time window and cooldown read the [`ironauth_env`] monotonic clock seam, so the whole
/// policy is deterministic under a manual clock in tests.
pub struct CircuitBreaker {
    clock: Arc<dyn Clock>,
    threshold: u32,
    window: Duration,
    cooldown: Duration,
    inner: Mutex<BreakerInner>,
}

impl std::fmt::Debug for CircuitBreaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitBreaker")
            .field("threshold", &self.threshold)
            .field("window", &self.window)
            .field("cooldown", &self.cooldown)
            .finish_non_exhaustive()
    }
}

impl CircuitBreaker {
    /// Build a breaker that opens on `threshold` errors/timeouts within `window` and
    /// stays open for `cooldown`, reading time from `clock`. `threshold` is clamped to at
    /// least 1 (a zero threshold would open on the first success-shaped call).
    #[must_use]
    pub fn new(
        clock: Arc<dyn Clock>,
        threshold: u32,
        window: Duration,
        cooldown: Duration,
    ) -> Self {
        Self {
            clock,
            threshold: threshold.max(1),
            window,
            cooldown,
            inner: Mutex::new(BreakerInner {
                state: BreakerState::Closed,
                failures: Vec::new(),
                opened_at: None,
                trial_in_progress: false,
                trial_started_at: None,
            }),
        }
    }

    /// Whether a call may proceed to the verifier, and whether this caller took the single
    /// half-open trial slot (so the orchestrator can release it if it abandons the call).
    ///
    /// When the breaker is OPEN and the cooldown has elapsed, this transitions it to
    /// HALF-OPEN and admits ONE trial call; while still cooling down it denies (the caller
    /// fails fast, uniform). In HALF-OPEN it admits exactly one outstanding trial at a
    /// time: a further caller while that trial is in flight fails fast (as if still open),
    /// so a concurrent burst after the cooldown produces a single probe, not a stampede
    /// against a possibly-dead backend. The trial resolves through
    /// [`record_success`](Self::record_success) (close) or
    /// [`record_failure`](Self::record_failure) (re-open).
    ///
    /// Self-heal backstop: if an outstanding half-open trial has been in flight LONGER than
    /// the cooldown, its future was abandoned without ever resolving (dropped mid-await or a
    /// panicking verifier that also somehow bypassed the RAII guard); the slot is then
    /// reclaimed and a fresh trial admitted, so an abandoned trial can never wedge the
    /// breaker in half-open. This complements the orchestrator's trial guard (belt and
    /// suspenders): the guard releases the slot promptly on a normal drop, and this covers
    /// a future refactor that bypasses it.
    fn admit(&self) -> Admission {
        let now = self.clock.monotonic();
        let mut inner = self.inner.lock().expect("breaker lock poisoned");
        match inner.state {
            BreakerState::Closed => Admission::Admitted {
                half_open_trial: false,
            },
            BreakerState::HalfOpen => {
                if inner.trial_in_progress {
                    // A trial is already outstanding. Admit no second concurrent probe
                    // UNLESS it has been in flight past the cooldown, in which case it was
                    // abandoned: reclaim the slot and admit a fresh trial rather than stay
                    // wedged forever.
                    let abandoned = inner.trial_started_at.is_none_or(|started| {
                        now.saturating_duration_since(started) >= self.cooldown
                    });
                    if abandoned {
                        inner.trial_started_at = Some(now);
                        Admission::Admitted {
                            half_open_trial: true,
                        }
                    } else {
                        Admission::Denied
                    }
                } else {
                    inner.trial_in_progress = true;
                    inner.trial_started_at = Some(now);
                    Admission::Admitted {
                        half_open_trial: true,
                    }
                }
            }
            BreakerState::Open => {
                let elapsed = inner
                    .opened_at
                    .map(|opened| now.saturating_duration_since(opened));
                if elapsed.is_some_and(|elapsed| elapsed >= self.cooldown) {
                    Self::transition(&mut inner, BreakerState::HalfOpen);
                    // This caller takes the single trial slot; concurrent callers that now
                    // see HalfOpen with a trial in progress fail fast until it resolves.
                    inner.trial_in_progress = true;
                    inner.trial_started_at = Some(now);
                    Admission::Admitted {
                        half_open_trial: true,
                    }
                } else {
                    Admission::Denied
                }
            }
        }
    }

    /// Whether a call may proceed to the verifier. A thin boolean view of
    /// [`admit`](Self::admit) for the management API and tests; the orchestrator uses
    /// `admit` so it learns whether it took the half-open trial slot.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned, which only happens after a panic on
    /// another thread holding it.
    #[must_use]
    pub fn allow(&self) -> bool {
        matches!(self.admit(), Admission::Admitted { .. })
    }

    /// Record a HEALTHY call (a verdict): clears the failure window and closes the
    /// breaker if it was trialing.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (only after a panic on another thread).
    pub fn record_success(&self) {
        let mut inner = self.inner.lock().expect("breaker lock poisoned");
        inner.failures.clear();
        // The trial (if any) resolved; free the slot regardless of the prior state.
        inner.trial_in_progress = false;
        inner.trial_started_at = None;
        if inner.state != BreakerState::Closed {
            inner.opened_at = None;
            Self::transition(&mut inner, BreakerState::Closed);
        }
    }

    /// Record a FAILED call (an error or a timeout): a half-open trial re-opens the
    /// breaker; a closed breaker opens once the threshold is reached within the window.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (only after a panic on another thread).
    pub fn record_failure(&self) {
        let now = self.clock.monotonic();
        let mut inner = self.inner.lock().expect("breaker lock poisoned");
        // Prune failures older than the rolling window, then record this one.
        let window = self.window;
        inner
            .failures
            .retain(|ts| now.saturating_duration_since(*ts) < window);
        inner.failures.push(now);
        match inner.state {
            BreakerState::HalfOpen => {
                inner.opened_at = Some(now);
                // The trial failed and resolved (or was abandoned by the orchestrator's
                // guard); free the slot and cool down again.
                inner.trial_in_progress = false;
                inner.trial_started_at = None;
                Self::transition(&mut inner, BreakerState::Open);
            }
            BreakerState::Closed => {
                let count = u32::try_from(inner.failures.len()).unwrap_or(u32::MAX);
                if count >= self.threshold {
                    inner.opened_at = Some(now);
                    Self::transition(&mut inner, BreakerState::Open);
                }
            }
            BreakerState::Open => {}
        }
    }

    /// The current breaker state, for the metrics gauge and the management API.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned (only after a panic on another thread).
    #[must_use]
    pub fn state(&self) -> BreakerState {
        self.inner.lock().expect("breaker lock poisoned").state
    }

    /// Apply a transition, emitting the metric gauge, the transition counter, and a
    /// structured log record (the process audit trail for a breaker flip). Called with
    /// the lock held; sets the new state before returning.
    fn transition(inner: &mut BreakerInner, to: BreakerState) {
        if inner.state == to {
            return;
        }
        let from = inner.state;
        inner.state = to;
        metrics::gauge!(LAZY_MIGRATION_BREAKER_STATE).set(to.gauge());
        metrics::counter!(LAZY_MIGRATION_BREAKER_TRANSITIONS_TOTAL, "to" => to.label())
            .increment(1);
        tracing::warn!(
            "lazy_migration.breaker.from" = from.label(),
            "lazy_migration.breaker.to" = to.label(),
            "lazy-migration circuit breaker changed state"
        );
    }
}

/// The outcome of a hook attempt, as the login path sees it (issue #56).
pub enum HookOutcome {
    /// The legacy store verified the credential, with an optional profile.
    Verified(Option<HookProfile>),
    /// The legacy store rejected the credential (wrong password / unknown to it).
    Rejected,
    /// The hook could not answer (timeout, error, blocked destination, or the breaker
    /// was open). The login fails with the uniform error, exactly as a local wrong
    /// password does.
    Unavailable,
}

/// The lazy-migration hook: a verifier plus the circuit breaker that guards it (issue
/// #56). One is built per node from config and installed on [`crate::OidcState`]; the
/// login path calls [`LazyMigrationHook::attempt`] for an unknown identifier.
pub struct LazyMigrationHook {
    verifier: Arc<dyn CredentialVerifier>,
    breaker: CircuitBreaker,
    clock: Arc<dyn Clock>,
    /// The per-call wall-clock bound the orchestrator enforces around the verifier, so a
    /// verifier that does not self-bound its work cannot stall the login path. The shipped
    /// [`WebhookVerifier`] already self-bounds via the fetcher deadline; this is
    /// defense-in-depth for an alternative [`CredentialVerifier`] (for example the M11 WASM
    /// engine). A timeout is a FAILURE toward the breaker, exactly like a transport error.
    timeout: Duration,
}

impl std::fmt::Debug for LazyMigrationHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyMigrationHook")
            .field("breaker", &self.breaker)
            .finish_non_exhaustive()
    }
}

/// An RAII guard for the single half-open trial slot, held across the verifier await in
/// [`LazyMigrationHook::attempt`].
///
/// The breaker admits exactly one half-open probe by setting `trial_in_progress`, which is
/// cleared only when the trial RESOLVES through `record_success`/`record_failure`. Those run
/// only if `attempt` reaches the `match result` arm AFTER the `tokio::time::timeout(..).await`.
/// If that future is DROPPED at the await point (the login handler awaits `attempt` INLINE, so
/// a client disconnect, request timeout, or graceful-shutdown cancellation drops it mid-trial)
/// or the verifier PANICS across the await, neither reset runs and the slot would stay taken
/// forever, wedging the breaker in half-open until process restart.
///
/// This guard closes that hole: when a trial's future is abandoned before it resolves, the
/// guard's `Drop` records a FAILURE on the breaker, which frees the slot AND re-opens the
/// breaker with a fresh cooldown, so the next cooldown admits a clean new probe. On the normal
/// path `attempt` marks the guard [`resolved`](Self::resolve) before recording the verdict, so
/// the drop is a no-op (no double count). The guard holds only a shared `&CircuitBreaker` (not a
/// live `MutexGuard`), so it is safe to carry across the await and its `Drop` takes the breaker
/// lock only briefly.
struct HalfOpenTrialGuard<'a> {
    breaker: &'a CircuitBreaker,
    resolved: bool,
}

impl<'a> HalfOpenTrialGuard<'a> {
    /// Arm a guard for a freshly-taken half-open trial slot.
    fn new(breaker: &'a CircuitBreaker) -> Self {
        Self {
            breaker,
            resolved: false,
        }
    }

    /// Mark the trial as resolved through the normal success/failure path, so `Drop`
    /// no-ops (the caller is about to record the verdict itself; do not double-count).
    fn resolve(&mut self) {
        self.resolved = true;
    }
}

impl Drop for HalfOpenTrialGuard<'_> {
    fn drop(&mut self) {
        if !self.resolved {
            // The trial was abandoned before it resolved: the `attempt` future was dropped
            // mid-await (client disconnect / request timeout / shutdown cancellation) or the
            // verifier panicked across the await. Release the slot and re-open with a fresh
            // cooldown so the breaker recovers instead of wedging in half-open.
            self.breaker.record_failure();
        }
    }
}

impl LazyMigrationHook {
    /// Assemble a hook from a verifier, a breaker, the clock seam (for the latency
    /// measurement), and the per-call `timeout` the orchestrator enforces around the
    /// verifier (defense-in-depth for a verifier that does not self-bound). `timeout` is
    /// clamped to at least one second.
    #[must_use]
    pub fn new(
        verifier: Arc<dyn CredentialVerifier>,
        breaker: CircuitBreaker,
        clock: Arc<dyn Clock>,
        timeout: Duration,
    ) -> Self {
        Self {
            verifier,
            breaker,
            clock,
            timeout: timeout.max(Duration::from_secs(1)),
        }
    }

    /// Attempt to verify `identifier` plus `credential` against the legacy store.
    ///
    /// Fails fast (no outbound call) when the breaker is open. Otherwise it calls the
    /// verifier once (no retry), meters the latency and the outcome, and feeds the
    /// breaker: a verdict (verified OR rejected) is a HEALTHY response and closes/keeps
    /// the breaker closed; a timeout or an error trips it. Never logs the identifier or
    /// the credential.
    pub async fn attempt(&self, identifier: &str, credential: &str) -> HookOutcome {
        let half_open_trial = match self.breaker.admit() {
            Admission::Denied => {
                record_outcome("breaker_open");
                return HookOutcome::Unavailable;
            }
            Admission::Admitted { half_open_trial } => half_open_trial,
        };
        // If we took the single half-open trial slot, guard it: should THIS future be
        // dropped mid-await (client disconnect / request timeout / shutdown cancellation)
        // or the verifier panic across the await, the guard's Drop releases the slot and
        // re-opens the breaker, so an abandoned trial cannot wedge it in half-open. A
        // Closed-state admission took no trial slot, so it needs no guard.
        let mut trial_guard = half_open_trial.then(|| HalfOpenTrialGuard::new(&self.breaker));
        let start = self.clock.monotonic();
        // Bound the verifier with the configured per-call timeout. The shipped
        // WebhookVerifier already self-bounds via the fetcher deadline, so this never fires
        // in production; it is defense-in-depth for an alternative verifier (an M11 WASM
        // impl) that does not self-bound, so it cannot stall the login path. A tokio I/O
        // timeout is the sanctioned bounded-wait here (the invariant-lint bans only raw
        // SystemTime/Instant, not tokio::time). An elapsed timeout is a FAILURE toward the
        // breaker, exactly like the fetcher's own timeout.
        let result =
            match tokio::time::timeout(self.timeout, self.verifier.verify(identifier, credential))
                .await
            {
                Ok(result) => result,
                Err(_elapsed) => Err(HookError::Timeout),
            };
        let elapsed = self.clock.monotonic().saturating_duration_since(start);
        metrics::histogram!(LAZY_MIGRATION_HOOK_LATENCY_SECONDS).record(elapsed.as_secs_f64());
        // The trial (if any) is resolving through the normal path below; disarm the guard
        // so its Drop is a no-op and we record the verdict exactly once.
        if let Some(guard) = trial_guard.as_mut() {
            guard.resolve();
        }
        match result {
            Ok(HookVerdict::Verified(profile)) => {
                self.breaker.record_success();
                record_outcome("verified");
                HookOutcome::Verified(profile)
            }
            Ok(HookVerdict::Rejected) => {
                self.breaker.record_success();
                record_outcome("rejected");
                HookOutcome::Rejected
            }
            Err(error) => {
                self.breaker.record_failure();
                record_outcome(match error {
                    HookError::Timeout => "timeout",
                    HookError::Blocked => "blocked",
                    HookError::Transport => "error",
                });
                HookOutcome::Unavailable
            }
        }
    }

    /// The current breaker state, for the management API and diagnostics.
    #[must_use]
    pub fn breaker_state(&self) -> BreakerState {
        self.breaker.state()
    }

    /// Record that a user was created locally by a verified first login (the migrated
    /// count metric). Called by the login path after the create commits.
    pub fn record_migrated() {
        metrics::counter!(LAZY_MIGRATION_MIGRATED_TOTAL).increment(1);
    }
}

/// Meter one hook attempt outcome.
fn record_outcome(outcome: &'static str) {
    metrics::counter!(LAZY_MIGRATION_HOOK_TOTAL, "outcome" => outcome).increment(1);
}

/// Build the inbound lazy-migration hook from `[oidc.lazy_migration]` config (issue #56),
/// or `None` when it is disabled.
///
/// Builds a DEDICATED SSRF-hardened fetcher whose total-request timeout is the configured
/// per-call timeout, resolves the shared secret through the config secret indirection, and
/// wires the circuit breaker to the env clock seam (so its window is deterministic under a
/// manual clock). Any failure (an unresolvable secret, a missing endpoint on an enabled
/// hook, a TLS setup failure) is logged and yields `None`: the hook is simply not armed and
/// an unknown-identifier login fails with the uniform error, never plaintext or a boot
/// failure. Registers the hook's metric descriptions when it arms.
///
/// The boot path calls this once and installs the returned `Arc` on BOTH the OIDC data
/// plane ([`crate::OidcState::with_migration_hook`]) and, so the management-plane progress
/// endpoint can report the breaker, the management state.
#[must_use]
pub fn build_from_config(
    config: &LazyMigrationConfig,
    env: &Env,
) -> Option<Arc<LazyMigrationHook>> {
    if !config.enabled {
        return None;
    }
    let Some(endpoint) = config.endpoint.clone() else {
        tracing::error!(
            "lazy migration is enabled but oidc.lazy_migration.endpoint is unset; the hook is \
             not armed and unknown-identifier logins fail uniformly"
        );
        return None;
    };
    let secret = match &config.secret {
        Some(secret) => match secret.resolve() {
            Ok(value) => Some(value),
            Err(error) => {
                tracing::error!(%error, "cannot resolve oidc.lazy_migration.secret; the hook is not armed");
                return None;
            }
        },
        None => None,
    };
    let timeout = Duration::from_secs(config.timeout_secs.max(1));
    let limits = FetchLimits {
        total_timeout: timeout,
        ..FetchLimits::default()
    };
    let fetcher = match Fetcher::new(limits) {
        Ok(fetcher) => Arc::new(fetcher),
        Err(error) => {
            tracing::error!(%error, "cannot build the lazy-migration fetcher; the hook is not armed");
            return None;
        }
    };
    let verifier: Arc<dyn CredentialVerifier> =
        Arc::new(WebhookVerifier::new(fetcher, endpoint, secret));
    let breaker = CircuitBreaker::new(
        env.clock_arc(),
        config.breaker_failure_threshold,
        Duration::from_secs(config.breaker_window_secs.max(1)),
        Duration::from_secs(config.breaker_cooldown_secs.max(1)),
    );
    describe_metrics();
    tracing::info!("inbound lazy-migration hook armed (issue #56)");
    Some(Arc::new(LazyMigrationHook::new(
        verifier,
        breaker,
        env.clock_arc(),
        timeout,
    )))
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use ironauth_env::{Clock, ManualClock};

    use super::*;

    fn breaker(
        clock: Arc<ManualClock>,
        threshold: u32,
        window_secs: u64,
        cooldown_secs: u64,
    ) -> CircuitBreaker {
        CircuitBreaker::new(
            clock as Arc<dyn Clock>,
            threshold,
            Duration::from_secs(window_secs),
            Duration::from_secs(cooldown_secs),
        )
    }

    #[test]
    fn breaker_opens_after_threshold_failures_and_short_circuits() {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let b = breaker(Arc::clone(&clock), 3, 30, 30);
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(b.allow());
        b.record_failure();
        b.record_failure();
        assert_eq!(
            b.state(),
            BreakerState::Closed,
            "below threshold stays closed"
        );
        assert!(b.allow());
        b.record_failure();
        assert_eq!(b.state(), BreakerState::Open, "threshold trips it open");
        assert!(!b.allow(), "an open breaker short-circuits");
    }

    #[test]
    fn a_success_resets_the_failure_window() {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let b = breaker(Arc::clone(&clock), 3, 30, 30);
        b.record_failure();
        b.record_failure();
        b.record_success();
        b.record_failure();
        b.record_failure();
        assert_eq!(
            b.state(),
            BreakerState::Closed,
            "the success cleared the window"
        );
    }

    #[test]
    fn failures_outside_the_window_do_not_accumulate() {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let b = breaker(Arc::clone(&clock), 3, 30, 30);
        b.record_failure();
        b.record_failure();
        // Move past the window: the two old failures fall out.
        clock.advance(Duration::from_secs(31));
        b.record_failure();
        assert_eq!(b.state(), BreakerState::Closed, "stale failures are pruned");
    }

    #[test]
    fn open_breaker_half_opens_after_cooldown_then_closes_on_success() {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let b = breaker(Arc::clone(&clock), 1, 30, 30);
        b.record_failure();
        assert_eq!(b.state(), BreakerState::Open);
        assert!(!b.allow(), "still cooling down");
        clock.advance(Duration::from_secs(30));
        assert!(b.allow(), "cooldown elapsed: half-open trial permitted");
        assert_eq!(b.state(), BreakerState::HalfOpen);
        b.record_success();
        assert_eq!(b.state(), BreakerState::Closed, "a trial success closes it");
    }

    #[test]
    fn half_open_admits_only_one_trial_at_a_time() {
        // After the cooldown, the FIRST caller takes the single trial slot; every further
        // caller while that trial is outstanding fails fast (as if still open), so a burst
        // of concurrent logins produces ONE probe, not a stampede at a possibly-dead
        // backend. Sequential calls model the burst deterministically: each is a caller
        // that observes the breaker before the trial resolves.
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let b = breaker(Arc::clone(&clock), 1, 30, 30);
        b.record_failure();
        assert_eq!(b.state(), BreakerState::Open);
        clock.advance(Duration::from_secs(30));

        assert!(b.allow(), "the first caller after cooldown gets the trial");
        assert_eq!(b.state(), BreakerState::HalfOpen);
        // A burst of 15 further callers while the trial is still in flight all fail fast.
        for _ in 0..15 {
            assert!(
                !b.allow(),
                "a concurrent caller must NOT get a second trial while one is outstanding"
            );
        }
        assert_eq!(
            b.state(),
            BreakerState::HalfOpen,
            "still trialing the one probe"
        );

        // Once the single trial resolves with a success, normal flow resumes.
        b.record_success();
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(b.allow(), "a closed breaker admits calls again");
    }

    #[test]
    fn half_open_readmits_a_trial_after_a_failed_one_re_cools_down() {
        // A failed trial re-opens and re-cools; only after the NEXT cooldown does a single
        // fresh trial become available again (never a burst).
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let b = breaker(Arc::clone(&clock), 1, 30, 30);
        b.record_failure();
        clock.advance(Duration::from_secs(30));
        assert!(b.allow(), "first trial");
        assert!(!b.allow(), "no second concurrent trial");
        b.record_failure();
        assert_eq!(b.state(), BreakerState::Open);
        clock.advance(Duration::from_secs(30));
        assert!(b.allow(), "a fresh single trial after the next cooldown");
        assert!(!b.allow(), "still only one at a time");
    }

    #[test]
    fn allow_self_heals_an_abandoned_half_open_trial_after_the_cooldown() {
        // Belt-and-suspenders backstop for the orchestrator's RAII trial guard: even if a
        // half-open trial is NEVER resolved (its future leaked without the guard or a
        // record_* ever running), the breaker must not stay wedged in half-open. `allow()`
        // reclaims a trial that has been outstanding longer than the cooldown and admits a
        // fresh one, so an abandoned trial self-heals on the next cooldown instead of
        // disabling lazy migration on the node until restart.
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let b = breaker(Arc::clone(&clock), 1, 30, 30);
        b.record_failure();
        clock.advance(Duration::from_secs(30));
        assert!(
            b.allow(),
            "the first caller after cooldown takes the trial slot"
        );
        assert_eq!(b.state(), BreakerState::HalfOpen);
        // The trial is deliberately NEVER resolved (models a leaked/forgotten future). A
        // fresh caller before the cooldown still fast-fails: exactly one probe at a time.
        assert!(
            !b.allow(),
            "a still-fresh outstanding trial keeps admitting exactly one probe"
        );
        assert_eq!(b.state(), BreakerState::HalfOpen);
        // Once the trial has been outstanding past the cooldown, the slot is treated as
        // abandoned: a new caller is admitted rather than wedged out forever.
        clock.advance(Duration::from_secs(30));
        assert!(
            b.allow(),
            "an outstanding trial past the cooldown is reclaimed and a fresh trial admitted"
        );
        assert_eq!(
            b.state(),
            BreakerState::HalfOpen,
            "still trialing, not wedged"
        );
        // And it is still one-at-a-time immediately after the self-heal.
        assert!(
            !b.allow(),
            "the self-heal admits exactly one fresh probe, not a burst"
        );
    }

    #[test]
    fn half_open_reopens_on_a_failed_trial() {
        let clock = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let b = breaker(Arc::clone(&clock), 1, 30, 30);
        b.record_failure();
        clock.advance(Duration::from_secs(30));
        assert!(b.allow());
        assert_eq!(b.state(), BreakerState::HalfOpen);
        b.record_failure();
        assert_eq!(b.state(), BreakerState::Open, "a trial failure re-opens it");
        assert!(!b.allow(), "and it cools down again");
    }
}
