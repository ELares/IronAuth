// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential-abuse regulation: the counter interface, its in-process L1 store, the
//! risk-based escalation, and the fail-open/closed matrix (issue #64).
//!
//! # Two complementary counter layers
//!
//! Regulation composes two counter layers with different purposes and different
//! failure biases:
//!
//! 1. The **fast request-shaping** layer (this module's [`CounterStore`] trait): coarse
//!    per-IP, per-client, and per-(tenant, environment) REQUEST counters that produce
//!    the standard rate-limit response headers and a coarse throttle. The L1
//!    implementation shipped here ([`MemoryCounterStore`]) is IN-PROCESS; an optional
//!    IronCache L2 slots in behind the SAME trait later (a covenant: no mandatory
//!    first-party infrastructure), without touching the regulation logic. This layer is
//!    AVAILABILITY-biased and FAILS OPEN: a cache outage must never lock every user out.
//!
//! 2. The **durable identity-scoped** layer (the store's `AbuseRepo`, DB-backed): the
//!    per-identifier failure escalation and the durable ban registry. It is keyed on the
//!    CANONICAL identifier (the #54 seam), survives a restart, and is SECURITY-biased and
//!    FAILS CLOSED: an attacker must not be able to knock out the backend to bypass
//!    online-guessing resistance or a ban.
//!
//! # Fail-open / fail-closed matrix
//!
//! | Layer                          | Backend                       | Bias         | On backend failure |
//! |--------------------------------|-------------------------------|--------------|--------------------|
//! | per-IP request counter         | L1 in-process (future L2)      | availability | FAIL OPEN (allow)  |
//! | per-client request counter     | L1 in-process (future L2)      | availability | FAIL OPEN (allow)  |
//! | per-(tenant,env) request meter | L1 in-process (future L2)      | availability | FAIL OPEN (allow)  |
//! | per-identifier failure counter | DB (`dcr_rate_counters` reuse) | security     | FAIL CLOSED (deny) |
//! | per-account failure counter    | DB (`dcr_rate_counters` reuse) | availability | FAIL OPEN (record)  |
//! | ban check                      | DB (`abuse_bans`)              | security     | FAIL CLOSED (deny) |
//!
//! The rationale: the in-process layer only shapes coarse request rate, so failing it
//! open costs a little rate protection but preserves availability; the per-identifier
//! counter and the ban check ARE request-path deny gates (a throttle or a ban refuses the
//! attempt) and are the source of truth already on the request path (the identifier lookup
//! itself hits the same DB), so failing them closed matches the rest of the system and
//! denies an attacker any bypass. The per-account counter is DIFFERENT: it is NOT a
//! request-path deny gate. It only drives the opt-in hard-lockout auto-ban, records
//! fail-OPEN (a backend error on its increment is swallowed, never a deny), and is
//! deliberately omitted from the pre-verify [`OidcState::regulate_before`] decision, so
//! failed-password spray against a victim can never turn the pre-check into an existence
//! oracle. Each cell has a test that injects the corresponding backend failure.
//!
//! The per-client and per-(tenant, environment) request counters are also RECORDED here
//! (L1, fail open) but are not yet a throttle input; tenant-plane fairness consumes them in
//! M5. They increment on every regulated attempt so the future layers have the history.
//!
//! # Account-DoS safety (per-path independence)
//!
//! Every counter and ban is keyed by an [`ironauth_store::AuthPath`]. Failed-password
//! spray raises only the password-path counters and can place only a password-path ban,
//! so it can never lock the legitimate owner out of the passkey ([#65]) or recovery
//! path (Keycloak CVE-2024-1722). Hard lockout is an explicit per-tenant opt-in and even
//! then is confined to the password path.
//!
//! # Anti-enumeration uniformity is a DEFAULT-posture property
//!
//! On the DEFAULT posture (`hard_lockout = false`) the pre-verify decision keys ONLY on
//! the existence-INDEPENDENT dimensions (the canonical identifier and the IP), so a
//! throttle never distinguishes a present from an absent identifier: the uniformity claim
//! holds. Enabling `hard_lockout` is an explicit opt-in that BREAKS that property: it adds
//! a login ENUMERATION oracle DISTINCT from the DoS-weaponization tradeoff. A real account
//! auto-bans once its per-account counter crosses the threshold, so the 429 ONSET (which
//! attempt first refuses on the full-wait banned shape) comes earlier for a present
//! account than for an absent identifier, and that timing/onset difference is INHERENT to
//! hard lockout and cannot be closed. What IS closed (issue #64) is the avoidable
//! RESPONSE-SHAPE leak: a banned present account and a throttled identifier carry the SAME
//! snapshot shape (status, body, and `Retry-After` semantics), so only the onset differs.
//! Both residuals are documented on the `hard_lockout` config field and in `docs/CONFIG.md`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use ironauth_config::RegulationConfig;
use ironauth_quota::RateLimitSnapshot;
use ironauth_store::{AbuseSubjectKind, AuthPath, CanonicalIdentifier};

/// A failure of the counter backend (issue #64). The in-process L1 store never returns
/// this; it exists so the callers of a future L2 (IronCache) can apply the
/// fail-open/closed matrix per layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterError {
    /// The counter backend is unavailable (a future L2 cache outage).
    Unavailable,
}

/// The counter-storage interface (issue #64): the fixed-window request counters behind
/// the fast request-shaping layer. The in-process L1 [`MemoryCounterStore`] implements
/// it now; an optional IronCache L2 implements the SAME trait later, so the regulation
/// logic is written against this interface and never against a concrete backend.
pub trait CounterStore: Send + Sync + std::fmt::Debug {
    /// Increment the fixed-window counter for `key` and return the new count within the
    /// current window. `window_secs` is the fixed window; `now_micros` is drawn from the
    /// caller's [`ironauth_env`] clock seam, so the window is deterministic under a
    /// manual clock in tests.
    ///
    /// # Errors
    ///
    /// [`CounterError::Unavailable`] when the backend cannot be reached (a future L2).
    fn incr(&self, key: &str, window_secs: u64, now_micros: i64) -> Result<u64, CounterError>;

    /// Read the current count for `key` WITHOUT incrementing, treating a rolled-over
    /// window as zero.
    ///
    /// # Errors
    ///
    /// [`CounterError::Unavailable`] when the backend cannot be reached (a future L2).
    fn peek(&self, key: &str, window_secs: u64, now_micros: i64) -> Result<u64, CounterError>;

    /// Clear the counter for `key` (issue #64): a SUCCESSFUL authentication relaxes the
    /// per-IP throttle so a legitimate user who typoed past the soft threshold is not
    /// punished for the rest of the window once they enter the correct credential. The
    /// caller treats it as best-effort (a clear failure just leaves the windowed counter
    /// to roll over on its own).
    ///
    /// # Errors
    ///
    /// [`CounterError::Unavailable`] when the backend cannot be reached (a future L2).
    fn clear(&self, key: &str) -> Result<(), CounterError>;
}

/// One fixed window: when it started (epoch microseconds) and its running count.
#[derive(Debug, Clone, Copy)]
struct Window {
    start_micros: i64,
    count: u64,
}

/// The in-process L1 counter store (issue #64): a sharded map of fixed windows. Never
/// fails (so its layers are effectively always available); it is lost on restart, which
/// is acceptable because the durable, security-critical state (bans and per-identifier
/// escalation) lives in the DB layer instead.
#[derive(Debug, Default)]
pub struct MemoryCounterStore {
    windows: Mutex<HashMap<String, Window>>,
}

impl MemoryCounterStore {
    /// A fresh, empty in-process counter store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The shared count-and-roll logic. `increment` distinguishes [`CounterStore::incr`]
    /// from [`CounterStore::peek`].
    fn count(&self, key: &str, window_secs: u64, now_micros: i64, increment: bool) -> u64 {
        let window_micros =
            i64::try_from(window_secs.saturating_mul(1_000_000)).unwrap_or(i64::MAX);
        let mut guard = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = guard.entry(key.to_owned()).or_insert(Window {
            start_micros: now_micros,
            count: 0,
        });
        // Roll the window forward if it has elapsed.
        if now_micros.saturating_sub(entry.start_micros) >= window_micros {
            entry.start_micros = now_micros;
            entry.count = 0;
        }
        if increment {
            entry.count = entry.count.saturating_add(1);
        }
        entry.count
    }
}

impl CounterStore for MemoryCounterStore {
    fn incr(&self, key: &str, window_secs: u64, now_micros: i64) -> Result<u64, CounterError> {
        Ok(self.count(key, window_secs, now_micros, true))
    }

    fn peek(&self, key: &str, window_secs: u64, now_micros: i64) -> Result<u64, CounterError> {
        Ok(self.count(key, window_secs, now_micros, false))
    }

    fn clear(&self, key: &str) -> Result<(), CounterError> {
        self.windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
        Ok(())
    }
}

/// The resolved regulation settings (issue #64): a cheap, copyable mirror of the
/// validated [`RegulationConfig`], held on the OIDC state.
#[derive(Debug, Clone, Copy)]
pub struct RegulationSettings {
    /// Whether regulation is active.
    pub enabled: bool,
    /// The fixed failure-count window.
    pub window: Duration,
    /// Failures within the window before escalation begins.
    pub soft_threshold: u64,
    /// The base escalation delay.
    pub base_delay: Duration,
    /// The ceiling on the escalating delay.
    pub max_delay: Duration,
    /// Whether hard account lockout is opted in (per-tenant).
    pub hard_lockout: bool,
    /// The account failure count that auto-places a password-path hard-lockout ban.
    pub hard_lockout_threshold: u64,
    /// How long an auto-placed hard-lockout ban lasts.
    pub hard_lockout_duration: Duration,
    /// Whether self-service registration is closed (send-suppression posture).
    pub registration_closed: bool,
}

impl RegulationSettings {
    /// Resolve the settings from validated config.
    #[must_use]
    pub fn from_config(config: &RegulationConfig) -> Self {
        Self {
            enabled: config.enabled,
            window: Duration::from_secs(config.window_secs),
            soft_threshold: u64::from(config.soft_threshold),
            base_delay: Duration::from_secs(config.base_delay_secs),
            max_delay: Duration::from_secs(config.max_delay_secs),
            hard_lockout: config.hard_lockout,
            hard_lockout_threshold: u64::from(config.hard_lockout_threshold),
            hard_lockout_duration: Duration::from_secs(config.hard_lockout_duration_secs),
            registration_closed: config.registration_closed,
        }
    }

    /// The window length in whole seconds, for the DB counter API.
    #[must_use]
    pub fn window_secs(&self) -> u64 {
        self.window.as_secs()
    }
}

/// The escalating `Retry-After` delay for a dimension that has `count` failures in the
/// current window, or [`None`] when the dimension is at or below the soft threshold
/// (issue #64).
///
/// Once over the threshold the delay doubles per further failure, capped at
/// `max_delay`. This is a delay the client is asked to wait (a 429 with `Retry-After`),
/// NEVER a hard lockout, so a legitimate owner is slowed but never permanently blocked
/// on the default posture.
#[must_use]
pub fn escalating_delay(settings: &RegulationSettings, count: u64) -> Option<Duration> {
    if !settings.enabled || count <= settings.soft_threshold {
        return None;
    }
    let over = count - settings.soft_threshold; // >= 1
    // base * 2^(over-1), SATURATING, capped at max_delay. `checked_shl` only guards the
    // shift against the type width; the shifted VALUE can still overflow and wrap (for
    // base_delay >= 2 a large shift wrapped to 0, making the cap non-monotone). Use a
    // saturating multiply so the delay is monotonically non-decreasing and clamps at
    // `max_delay` for any base/shift, never wrapping to 0 (issue #64 LOW-7).
    let base = settings.base_delay.as_secs().max(1);
    let shift = over - 1;
    let scaled = if shift >= 64 {
        u64::MAX
    } else {
        base.saturating_mul(1_u64 << shift)
    };
    let capped = scaled.min(settings.max_delay.as_secs());
    Some(Duration::from_secs(capped))
}

/// The rate-limit snapshot for a throttled response (issue #64), reusing the quota
/// crate's header contract (draft-ietf-httpapi-ratelimit-headers) so the abuse throttle
/// and the tenant-quota throttle stamp the SAME header shape. `limit` is the soft
/// threshold, `remaining` is what is left before it, and `retry_after` is the escalating
/// delay (present only on a throttle).
#[must_use]
pub fn throttle_snapshot(
    settings: &RegulationSettings,
    count: u64,
    retry_after: Duration,
) -> RateLimitSnapshot {
    RateLimitSnapshot {
        limit: Some(settings.soft_threshold),
        remaining: Some(settings.soft_threshold.saturating_sub(count)),
        reset_secs: settings.window.as_secs(),
        retry_after_secs: Some(retry_after.as_secs()),
    }
}

/// The L1 counter key for the per-IP failure layer, keyed by the authentication path so
/// the layers stay per-path independent (issue #64). The IP is the non-forgeable
/// resolved socket peer (the #31 lesson), non-PII in the same sense the device-verify
/// counter treats it.
#[must_use]
pub fn ip_counter_key(path: AuthPath, ip: &str) -> String {
    format!("abuse:{}:ip:{ip}", path.as_str())
}

/// The L1 counter key for the per-client failure layer (an opaque client id).
#[must_use]
pub fn client_counter_key(path: AuthPath, client_id: &str) -> String {
    format!("abuse:{}:client:{client_id}", path.as_str())
}

/// The L1 counter key for the per-(tenant, environment) failure layer.
#[must_use]
pub fn tenant_counter_key(path: AuthPath, tenant: &str, environment: &str) -> String {
    format!("abuse:{}:tenant:{tenant}:{environment}", path.as_str())
}

/// The L1 counter key for the browserless authorization challenge RESUME rate-limit cap (issue
/// #93, PR4): keyed on the STABLE half of the `auth_session` handle, the `flow_id`, so every
/// resume hop of one login (the handle rotates each step but the `flow_id` does not) shares one
/// bucket. Reuses the fast request-shaping L1 layer, not a new store.
#[must_use]
pub fn challenge_session_counter_key(scope: ironauth_store::Scope, flow_id: &str) -> String {
    format!(
        "challenge:session:{}:{}:{flow_id}",
        scope.tenant(),
        scope.environment()
    )
}

/// The L1 counter key for the browserless authorization challenge FRESH rate-limit cap (issue
/// #93, PR4): keyed on the client id and the resolved socket-peer IP (the #31 lesson, non-
/// forgeable), so fresh flow-creation spray from one client and IP shares one bucket.
#[must_use]
pub fn challenge_fresh_counter_key(
    scope: ironauth_store::Scope,
    client_id: &str,
    ip: &str,
) -> String {
    format!(
        "challenge:fresh:{}:{}:{client_id}:{ip}",
        scope.tenant(),
        scope.environment()
    )
}

/// The rate-limit snapshot for a ban or a fail-CLOSED security-layer error (issue #64):
/// a uniform throttle carrying the SAME shape an escalation throttle carries once it has
/// saturated at the cap. It is byte-identical to
/// [`throttle_snapshot`]`(settings, count, max_delay)` for any `count` past the soft
/// threshold: `limit = soft_threshold`, `remaining = 0`, `reset = window`, and
/// `Retry-After = max_delay`. That identity is load-bearing for anti-enumeration (issue
/// #64 MEDIUM-3): under `hard_lockout`, a banned PRESENT account and a throttled identifier
/// must return the same response, so a present account is not distinguished by the
/// response shape (only the inherent onset differs). `Retry-After` is `max_delay`, NOT the
/// full ban duration, so it deliberately understates the true wait exactly as the
/// escalation throttle does; the client that retries early simply gets another 429.
#[must_use]
pub fn banned_snapshot(settings: &RegulationSettings) -> RateLimitSnapshot {
    RateLimitSnapshot {
        limit: Some(settings.soft_threshold),
        remaining: Some(0),
        reset_secs: settings.window.as_secs(),
        retry_after_secs: Some(settings.max_delay.as_secs()),
    }
}

/// Stamp the standard rate-limit response headers (draft-ietf-httpapi-ratelimit-headers,
/// plus the legacy `X-RateLimit-*` and the block signal) from `snapshot` onto a throttled
/// response (issue #64), reusing the quota crate's header contract so an abuse throttle
/// and a tenant-quota throttle carry the SAME header shape.
pub fn stamp_rate_limit_headers(
    response: &mut axum::response::Response,
    snapshot: &RateLimitSnapshot,
) {
    use axum::http::{HeaderName, HeaderValue};
    let headers = response.headers_mut();
    for (name, value) in snapshot.headers() {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(name, value);
        }
    }
}

/// The RESOLVED client IP for abuse keying (issue #64, the #31 lesson): the value the
/// server's trusted-proxy middleware stamped into [`PEER_IP_HEADER`] (it `insert`s the
/// resolved socket peer, overwriting any client-supplied value, so this header is
/// non-forgeable). Falls back to [`None`] when absent (an in-process test router with no
/// middleware), which collapses to a single shared bucket rather than trusting a
/// spoofable header.
#[must_use]
pub fn resolved_client_ip(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(ironauth_config::PEER_IP_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Infer the [`ironauth_store::IdentifierType`] of a raw login handle for counter/ban
/// keying and canonicalize it through the #54 seam (issue #64), so a case/unicode variant
/// keys to the same canonical form. An `@` is an email; an all `+`/digit string is a
/// phone; everything else is a username. The inference need only be STABLE (the same raw
/// input always canonicalizes to the same key), which it is.
#[must_use]
#[rustfmt::skip] // keep the seam-allow marker on the signature line (see canonicalization-seam.sh)
pub fn canonical_login_identifier(raw: &str) -> CanonicalIdentifier { // seam-allow: returns the seam type; the value is produced ONLY by canonicalize_identifier below, never a struct literal
    use ironauth_store::{IdentifierType, canonicalize_identifier};
    let phoneish = |c: char| c.is_ascii_digit() || matches!(c, '+' | '-' | ' ' | '(' | ')');
    let kind = if raw.contains('@') {
        IdentifierType::Email
    } else if !raw.is_empty() && raw.chars().all(phoneish) {
        IdentifierType::Phone
    } else {
        IdentifierType::Username
    };
    canonicalize_identifier(kind, raw)
}

/// The context of one governed authentication attempt (issue #64): which path, which
/// scope, and the regulated dimensions available. The IP is the non-forgeable resolved
/// socket peer (the #31 lesson); the identifier is the CANONICAL form (the #54 seam);
/// the account id is present only once the identifier has resolved to an account.
#[derive(Debug, Clone)]
pub struct AttemptContext {
    /// The authentication path (keeps regulation per-path independent).
    pub path: AuthPath,
    /// The tenant/environment scope.
    pub scope: ironauth_store::Scope,
    /// The resolved socket peer IP, if known.
    pub ip: Option<String>,
    /// The canonical login identifier, if one was submitted.
    pub identifier: Option<CanonicalIdentifier>,
    /// The resolved account id (a `usr_` string), if the identifier resolved.
    pub account_id: Option<String>,
    /// The client id of the resuming authorization request, if known.
    pub client_id: Option<String>,
}

/// The regulation context for a step-up / second-factor verification attempt (RFC 9470,
/// issue #72; the #69 TOTP surface too). The second factor runs against an ALREADY
/// AUTHENTICATED session, so the subject is known and there is NO user-enumeration
/// concern: both the (fail-CLOSED, escalation-driving) identifier dimension AND the
/// account dimension key on the subject id, so a wrong-code storm against this subject's
/// second factor ESCALATES to a uniform 429 (and can auto-place a ban) BEFORE any seed is
/// opened or any code is compared. The IP is the non-forgeable resolved peer (the #31
/// lesson). The path is always [`AuthPath::SecondFactor`], governed INDEPENDENTLY of every
/// other path, so a second-factor guess storm can never lock the owner out of the password
/// or passkey login path (the Keycloak CVE-2024-1722 account-DoS safeguard).
#[must_use]
pub fn second_factor_attempt_context(
    scope: ironauth_store::Scope,
    subject: &ironauth_store::UserId,
    headers: &axum::http::HeaderMap,
) -> AttemptContext {
    let subject_str = subject.to_string();
    AttemptContext {
        path: AuthPath::SecondFactor,
        scope,
        ip: resolved_client_ip(headers),
        // No login handle is submitted at a step-up (the subject is recovered from the
        // session), so the escalation-driving identifier dimension keys on the subject id
        // itself; there is no present-vs-absent oracle to protect here.
        identifier: Some(canonical_login_identifier(&subject_str)),
        account_id: Some(subject_str),
        client_id: None,
    }
}

impl AttemptContext {
    /// The ban subjects to check for this attempt: the IP, the account, and the
    /// identifier dimensions that are present.
    #[must_use]
    pub fn ban_subjects(&self) -> Vec<ironauth_store::AbuseSubject> {
        let mut subjects = Vec::new();
        if let Some(ip) = &self.ip {
            subjects.push(ironauth_store::AbuseSubject::ip(ip.clone()));
        }
        if let Some(account) = &self.account_id {
            subjects.push(ironauth_store::AbuseSubject::account(account.clone()));
        }
        if let Some(identifier) = &self.identifier {
            subjects.push(ironauth_store::AbuseSubject::identifier(
                identifier.as_str().to_owned(),
            ));
        }
        subjects
    }
}

/// The regulation decision for an attempt (issue #64).
#[derive(Debug, Clone)]
pub enum RegulationOutcome {
    /// Proceed with the attempt (spend the credential verification).
    Allow,
    /// Refuse the attempt with a uniform throttle response carrying the rate-limit
    /// headers. Covers a ban, an over-threshold escalation, and a fail-CLOSED
    /// security-layer backend error.
    Throttled(RateLimitSnapshot),
}

impl RegulationOutcome {
    /// Whether the attempt is throttled (refused before spending a verification).
    #[must_use]
    pub fn is_throttled(&self) -> bool {
        matches!(self, RegulationOutcome::Throttled(_))
    }
}

/// Whether a subject kind's fast-layer counter fails OPEN on a backend error (issue
/// #64): the IP dimension is availability-biased, the identifier and account dimensions
/// are security-biased. Documented and exercised by the fail-matrix tests.
#[must_use]
pub fn layer_fails_open(kind: AbuseSubjectKind) -> bool {
    match kind {
        AbuseSubjectKind::Ip => true,
        AbuseSubjectKind::Account | AbuseSubjectKind::Identifier => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> RegulationSettings {
        RegulationSettings::from_config(&RegulationConfig::default())
    }

    #[test]
    fn memory_counter_increments_and_rolls_the_window() {
        let store = MemoryCounterStore::new();
        let window = 10;
        assert_eq!(store.incr("k", window, 0).unwrap(), 1);
        assert_eq!(store.incr("k", window, 1_000_000).unwrap(), 2);
        assert_eq!(store.peek("k", window, 1_000_000).unwrap(), 2);
        // Past the window: rolls back to a fresh count.
        assert_eq!(store.incr("k", window, 11_000_000).unwrap(), 1);
    }

    #[test]
    fn peek_is_zero_for_an_unknown_key() {
        let store = MemoryCounterStore::new();
        assert_eq!(store.peek("missing", 10, 0).unwrap(), 0);
    }

    #[test]
    fn no_escalation_at_or_below_soft_threshold() {
        let settings = settings();
        assert_eq!(escalating_delay(&settings, 0), None);
        assert_eq!(escalating_delay(&settings, settings.soft_threshold), None);
    }

    #[test]
    fn escalation_doubles_and_caps() {
        let settings = settings();
        let first = escalating_delay(&settings, settings.soft_threshold + 1).unwrap();
        let second = escalating_delay(&settings, settings.soft_threshold + 2).unwrap();
        assert_eq!(first, Duration::from_secs(1));
        assert_eq!(second, Duration::from_secs(2));
        // Far past the threshold saturates at max_delay, never unbounded.
        let capped = escalating_delay(&settings, settings.soft_threshold + 40).unwrap();
        assert_eq!(capped, settings.max_delay);
    }

    #[test]
    fn escalation_is_monotone_and_capped_for_a_larger_base_delay() {
        // Regression for the non-monotone cap (issue #64 LOW-7): with base_delay >= 2 the
        // old `checked_shl` wrapped the shifted value on overflow (base=2, shift=63 -> 0s),
        // so the delay was NOT monotone and could drop to 0. It must be monotonically
        // non-decreasing and clamp at max_delay for every shift, never wrapping.
        let mut settings = settings();
        settings.base_delay = Duration::from_secs(2);
        settings.max_delay = Duration::from_secs(60);
        let mut previous = Duration::ZERO;
        for over in 1..=200_u64 {
            let delay = escalating_delay(&settings, settings.soft_threshold + over)
                .expect("over the soft threshold escalates");
            assert!(
                delay >= previous,
                "the escalating delay must be monotonically non-decreasing (over={over})"
            );
            assert!(
                delay <= settings.max_delay,
                "the escalating delay must never exceed max_delay (over={over})"
            );
            assert!(
                delay > Duration::ZERO,
                "the escalating delay must never wrap to zero (over={over})"
            );
            previous = delay;
        }
        // Far past the threshold it is pinned at the cap, never wrapped.
        assert_eq!(
            escalating_delay(&settings, settings.soft_threshold + 1_000).unwrap(),
            settings.max_delay
        );
    }

    #[test]
    fn a_ban_snapshot_is_byte_identical_to_a_capped_escalation_throttle() {
        // Anti-enumeration uniformity (issue #64 MEDIUM-3): a banned present account and a
        // throttled identifier must be indistinguishable by the response. The ban snapshot
        // is exactly a throttle snapshot at the cap for any count past the soft threshold.
        let settings = settings();
        let banned = banned_snapshot(&settings);
        for count in [
            settings.soft_threshold + 8,
            settings.hard_lockout_threshold,
            settings.hard_lockout_threshold + 50,
        ] {
            let throttle = throttle_snapshot(&settings, count, settings.max_delay);
            assert_eq!(
                banned, throttle,
                "the ban snapshot must match a capped escalation throttle (count={count})"
            );
            assert_eq!(
                banned.headers(),
                throttle.headers(),
                "the headers must match too"
            );
        }
    }

    #[test]
    fn a_cleared_memory_counter_relaxes_the_throttle() {
        // A successful auth clears the per-IP counter so a legitimate user is not punished
        // after a correct login (issue #64 LOW-6).
        let store = MemoryCounterStore::new();
        let key = ip_counter_key(AuthPath::Password, "203.0.113.9");
        for _ in 0..7 {
            store.incr(&key, 300, 0).unwrap();
        }
        assert_eq!(store.peek(&key, 300, 0).unwrap(), 7);
        store.clear(&key).unwrap();
        assert_eq!(
            store.peek(&key, 300, 0).unwrap(),
            0,
            "clearing the counter relaxes the throttle"
        );
    }

    #[test]
    fn disabled_regulation_never_escalates() {
        let mut settings = settings();
        settings.enabled = false;
        assert_eq!(
            escalating_delay(&settings, settings.soft_threshold + 100),
            None
        );
    }

    #[test]
    fn identifier_canonicalization_folds_case_variants_to_one_key() {
        let a = canonical_login_identifier("Alice@Example.COM");
        let b = canonical_login_identifier("alice@example.com");
        assert_eq!(a.as_str(), b.as_str());
    }

    #[test]
    fn challenge_counter_keys_are_stable_scoped_and_distinct() {
        use std::time::SystemTime;

        use ironauth_env::Env;
        use ironauth_store::{EnvironmentId, Scope, TenantId};

        let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x00C0_FFEE);
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        // The resume key is namespaced under `challenge:session` and carries the scope + flow id;
        // it is STABLE for a given flow id (so a rotating handle keeps one bucket).
        let session = challenge_session_counter_key(scope, "flw_example");
        assert!(session.starts_with("challenge:session:"));
        assert!(session.ends_with(":flw_example"));
        assert_eq!(
            session,
            challenge_session_counter_key(scope, "flw_example"),
            "the resume key is stable for a flow id"
        );
        assert_ne!(
            session,
            challenge_session_counter_key(scope, "flw_other"),
            "a different flow id is a different bucket"
        );
        // The fresh key is namespaced under `challenge:fresh` and carries the scope + client + IP.
        let fresh = challenge_fresh_counter_key(scope, "cli_example", "203.0.113.7");
        assert!(fresh.starts_with("challenge:fresh:"));
        assert!(fresh.ends_with(":cli_example:203.0.113.7"));
        assert_ne!(
            fresh,
            challenge_fresh_counter_key(scope, "cli_example", "198.51.100.4"),
            "a different IP is a different bucket"
        );
        // The two families never collide.
        assert_ne!(session, fresh);
    }

    #[test]
    fn fail_open_matrix_is_ip_only() {
        assert!(layer_fails_open(AbuseSubjectKind::Ip));
        assert!(!layer_fails_open(AbuseSubjectKind::Account));
        assert!(!layer_fails_open(AbuseSubjectKind::Identifier));
    }

    /// A stub L2 that always errors, for the fail-open matrix tests. It proves the
    /// `CounterStore` interface supports backend-failure injection (the optional
    /// IronCache L2 slots in behind it).
    #[derive(Debug)]
    struct FailingCounterStore;

    impl CounterStore for FailingCounterStore {
        fn incr(&self, _key: &str, _window: u64, _now: i64) -> Result<u64, CounterError> {
            Err(CounterError::Unavailable)
        }
        fn peek(&self, _key: &str, _window: u64, _now: i64) -> Result<u64, CounterError> {
            Err(CounterError::Unavailable)
        }
        fn clear(&self, _key: &str) -> Result<(), CounterError> {
            Err(CounterError::Unavailable)
        }
    }

    #[test]
    fn a_failing_l2_surfaces_the_unavailable_error_for_the_fail_open_caller() {
        // The IP layer is fail-OPEN: the caller (`OidcState::regulate_before`) ignores a
        // counter-store error, so a backend outage does not block logins. This confirms
        // the interface returns the error the caller keys the matrix on, rather than
        // panicking or blocking.
        let store: &dyn CounterStore = &FailingCounterStore;
        assert_eq!(
            store.peek(&ip_counter_key(AuthPath::Password, "203.0.113.1"), 300, 0),
            Err(CounterError::Unavailable)
        );
        assert_eq!(
            store.incr(&tenant_counter_key(AuthPath::Password, "t", "e"), 300, 0),
            Err(CounterError::Unavailable)
        );
        // The IP dimension fails open, so its error is safe to ignore.
        assert!(layer_fails_open(AbuseSubjectKind::Ip));
    }
}
