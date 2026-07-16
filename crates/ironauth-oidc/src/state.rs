// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shared handler state for the OIDC provider.
//!
//! [`OidcState`] carries the data-plane [`Store`] (which in production
//! authenticates as the least-privilege `ironauth_app` role), the environment
//! seam, the per-environment issuer registry, the issuer base, and the configured
//! code and access-token lifetimes. It is the axum router state, so every handler
//! reaches it, and it is cheap to clone (everything lives behind one `Arc`).
//!
//! Issuers are PER ENVIRONMENT: [`OidcState::issuer_for`] derives a distinct
//! issuer string from the `(tenant, environment)` scope, so a token minted in one
//! environment carries an issuer no other environment shares. The signing key is
//! likewise selected per environment through the shared [`IssuerRegistry`], the ONE
//! holder of every environment's keys, algorithm policy, and salt, so moving a
//! client between environments is a configuration flip, not a key regeneration, and
//! the key the mint signs with is by construction the key the published JWKS
//! serves (they read the same registry entry).

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use tokio::sync::Semaphore;

use ironauth_config::{
    ClientAssertionAudience, ClientCredentialsAudience, OidcConfig, RegistrationMode,
};
use ironauth_env::Env;
use ironauth_jose::{JwsAlgorithm, TrustedKey, VerificationPolicy, VerifiedToken, verify};
use ironauth_quota::QuotaEnforcer;
use ironauth_store::{
    AbuseBanId, AbuseSubject, ActorRef, AuthPath, CorrelationId, GuardrailSet, NewBan, Scope,
    ServiceId, Store, TokenFormat,
};

use crate::util::epoch_micros;

use crate::client_keys::ClientKeyResolver;
use crate::introspection::{IntrospectionSerializer, default_serializer};
use crate::issuer::{IssuerEntry, IssuerRegistry};
use crate::registry::{ResponseMode, ResponseType};
use crate::revocation::{RevocationEventSink, default_sink};
use crate::subject::{PairwiseSalt, SubjectCache, SubjectConfig};
use crate::tokens::AccessTokenTarget;

/// The process-wide bound on CONCURRENT inline Argon2id hashes for the no-pool
/// fallback posture (issue #62).
///
/// Production always installs the dedicated pool ([`OidcState::with_hashing_pool`]),
/// which is the production path; this semaphore only guards the self-hoster,
/// embedded, and test posture where hashing runs on the tokio blocking pool. That
/// pool defaults to ~512 threads, so an unbounded flood could pin ~512 concurrent
/// Argon2id contexts (tens of MiB each, ~9.5 GiB) and exhaust threads and memory.
/// Capping concurrent inline hashes at the host core count keeps the fallback
/// bounded without admission, mirroring the pool's default worker sizing.
fn inline_hash_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(crate::hashing_pool::default_pool_threads())))
}

/// Run `f` on the tokio blocking pool while holding a permit from `sem`, so the
/// number of concurrent inline hashes never exceeds the semaphore's capacity. The
/// permit is moved into the blocking closure and released when the hash finishes.
///
/// # Errors
///
/// [`HashRejection::Unavailable`] if the semaphore is closed or the blocking task
/// could not be joined; never an unbounded inline hash.
async fn bounded_inline_on<T, F>(
    sem: &Arc<Semaphore>,
    f: F,
) -> Result<T, crate::hashing_pool::HashRejection>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let permit = Arc::clone(sem)
        .acquire_owned()
        .await
        .map_err(|_| crate::hashing_pool::HashRejection::Unavailable)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(|_| crate::hashing_pool::HashRejection::Unavailable)
}

/// [`bounded_inline_on`] against the process-wide [`inline_hash_semaphore`].
async fn bounded_inline<T, F>(f: F) -> Result<T, crate::hashing_pool::HashRejection>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    bounded_inline_on(inline_hash_semaphore(), f).await
}

/// Why resolving a set of RFC 8707 resource indicators to an access-token target
/// failed (issue #28). The token/authorization endpoints map [`InvalidTarget`] to
/// the `invalid_target` error (RFC 8707 section 2.2) and [`ServerError`] to an
/// opaque server error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceTargetError {
    /// A requested resource is unknown (no registered resource server in scope), or
    /// the targeted resource servers disagree on token format.
    InvalidTarget,
    /// A store fault prevented resolution. Fail closed rather than silently dropping
    /// the audience restriction (which would broaden the token).
    ServerError,
}

/// Breached-password screening outcomes, labeled by `outcome` (issue #63):
/// `not_breached`, `breached`, `fail_open` (a provider outage allowed under fail-open,
/// an audited unscreened acceptance), or `fail_closed` (a provider outage refused).
pub const PASSWORD_SCREEN_TOTAL: &str = "ironauth_password_screen_total";

/// A count of successful logins whose password was found BREACHED by the on-login screen
/// (issue #63): the now-compromised-credential signal. Each increment is also a
/// structured audit log naming the subject, so an operator can require a change.
pub const PASSWORD_BREACHED_AT_LOGIN_TOTAL: &str = "ironauth_password_breached_at_login_total";

/// The non-enumerating message shown when a password is refused for being in the breach
/// corpus (issue #63). It names the reason ("a known data breach") without revealing the
/// corpus, the provider, or anything account-specific.
pub(crate) const BREACHED_PASSWORD_MESSAGE: &str = "That password has appeared in a known data breach and cannot be used. Choose a \
     different password.";

/// The message shown when screening is refused under a fail-closed policy because the
/// provider was unavailable (issue #63): a retryable, non-specific server-side message.
pub(crate) const SCREENING_UNAVAILABLE_MESSAGE: &str = "We could not check your password against the breach corpus right now. Please try \
     again in a moment.";

/// The decision a breached-password screen yields for the set/change/reset paths (issue
/// #63): the password is allowed (not breached, screening disabled, or a fail-open
/// outage that was audited), rejected as breached, or refused because the provider was
/// unavailable under a fail-closed policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScreenDecision {
    /// The password may be set: it is not breached, or screening is disabled, or a
    /// fail-open provider outage was audited and allowed.
    Allowed,
    /// The password is present in the breach corpus: reject the set.
    Breached,
    /// The provider could not answer and the policy is fail-closed: refuse the set until
    /// screening succeeds.
    RefusedUnavailable,
}

/// Register the screening metric description, mirroring the server's metrics-describe
/// pattern. Safe to call after the recorder is installed; a no-op with no recorder.
pub fn describe_screening_metrics() {
    metrics::describe_counter!(
        PASSWORD_SCREEN_TOTAL,
        "Breached-password screening outcomes by outcome \
         (not_breached/breached/fail_open/fail_closed)"
    );
    metrics::describe_counter!(
        PASSWORD_BREACHED_AT_LOGIN_TOTAL,
        "Successful logins whose password was found breached by the on-login screen"
    );
}

/// Record the audit event for a fail-open screening acceptance (issue #63): the password
/// was accepted WITHOUT a successful screen because the provider was unavailable and the
/// policy is fail-open. A bounded metric plus a structured log, matching the platform's
/// other observable security events.
fn audit_screening_fail_open(scope: &Scope, provider: &str) {
    metrics::counter!(PASSWORD_SCREEN_TOTAL, "outcome" => "fail_open").increment(1);
    tracing::warn!(
        tenant = %scope.tenant(),
        environment = %scope.environment(),
        provider,
        "breach screening provider unavailable; failing open (password allowed unscreened)"
    );
}

/// Cheaply cloneable state shared by every OIDC handler.
#[derive(Clone)]
pub struct OidcState {
    inner: Arc<Inner>,
    // The internal revocation-event sink (issue #22): every successful revocation is
    // published here. Kept OUTSIDE `Inner` so it is swappable with a cheap builder
    // (the M4 external fan-out installs its own sink) while the rest of the state
    // stays a shared, immutable `Arc<Inner>`. Default: the no-op sink.
    revocation_sink: Arc<dyn RevocationEventSink>,
    // The pluggable introspection-response serializer (issue #22): the endpoint hands
    // it the typed claims and it renders the wire body, so the RFC 9701 signed-JWT
    // response (M16) slots in as a new serializer without touching the endpoint.
    // Default: the RFC 7662 plain-JSON serializer.
    introspection_serializer: Arc<dyn IntrospectionSerializer>,
    // Whether the experimental Global Token Revocation receiver (issue #36) is
    // mounted. Kept OUTSIDE `Inner` and set through the builder because it is NOT a
    // plain `OidcConfig` toggle an operator can flip directly (that would bypass the
    // experimental acknowledgment gate): the ONLY writer is the boot path, which
    // resolves it from the strict config feature ladder (feature enabled AND acked)
    // and sets it here. Default: false (the endpoint is unmounted).
    global_token_revocation_enabled: bool,
    // The per-tenant/per-environment quota enforcer (issue #50), the data plane's
    // tenant-fairness layer. Kept OUTSIDE `Inner` and installed by the boot path
    // (built from the [quota] config, seeded with the SAME env clock), so a spend
    // refills deterministically under a test's ManualClock. A single enforcer is
    // shared across every request thread. Default: `None`, which disables
    // enforcement entirely (every request admitted, nothing charged) so the
    // many DB-only OIDC tests and a self-hoster who wants no quota are unaffected.
    quota: Option<Arc<QuotaEnforcer>>,
    // The inbound lazy-migration hook (issue #56). Kept OUTSIDE `Inner` and installed by
    // the boot path (built from the [oidc.lazy_migration] config with a dedicated
    // SSRF-hardened fetcher and the same env clock), so its circuit breaker's time
    // window advances deterministically under a test's ManualClock. Shared across every
    // request thread. Default: `None`, which leaves the login path unchanged (an unknown
    // identifier is the uniform failure and no outbound call is made), so the many
    // DB-only OIDC tests and a deployment with no legacy store are unaffected.
    migration_hook: Option<Arc<crate::migration::LazyMigrationHook>>,
    // The dedicated, admission-controlled Argon2id hashing pool (issue #62). Kept
    // OUTSIDE `Inner` and installed by the boot path (built from [password_hashing]
    // config, sharing the SAME quota enforcer as the request path so hashing
    // admission is per-tenant fair-share). Argon2 runs ONLY on this pool's
    // dedicated threads, never a tokio protocol-I/O worker. Default: `None`, in
    // which case hashing runs on the tokio BLOCKING pool via spawn_blocking (still
    // off the protocol-I/O threads) with no admission, which keeps the many DB-only
    // OIDC tests and the self-hoster who wants no admission control unaffected.
    hashing_pool: Option<Arc<crate::hashing_pool::HashingPool>>,
    // The in-process L1 counter store for the fast request-shaping layer (issue #64).
    // Kept OUTSIDE `Inner` so it is swappable with a cheap builder: the optional
    // IronCache L2 installs its `CounterStore` impl here later, and a test wires a
    // failing stub to exercise the fail-open matrix. Default: the in-process
    // MemoryCounterStore. Shared across every request thread.
    abuse_counters: Arc<dyn crate::abuse::CounterStore>,
    // The verification / OTP send seam (issue #64). Kept OUTSIDE `Inner` so the real
    // transport (issue #68) installs its sender here later without a wire change.
    // Default: the no-op NullVerificationSender (no transport wired yet), so the
    // closed-registration acknowledgment is identical whether or not a send goes out.
    verification_sender: Arc<dyn crate::verification::VerificationSender>,
    // The resolved NIST SP 800-63B-4 password policy (issue #63): length floors, the
    // composition/rotation legacy overrides, and whether screening is enabled. Kept
    // OUTSIDE `Inner` and installed by the boot path from the top-level `[password_policy]`
    // config via `with_password_policy` (like the hashing pool from `[password_hashing]`).
    // Default: the shipped 63B-4 posture (`PasswordPolicy::default`), so a state built
    // without the builder still enforces the modern length/no-composition defaults.
    password_policy: ironauth_screening::PasswordPolicy,
    // What to do when the screening provider cannot answer (issue #63): fail-open (allow
    // and audit) or fail-closed (refuse). Config-derived, installed alongside the policy.
    screening_failure: ironauth_screening::FailurePolicy,
    // Whether to screen the presented password at LOGIN too (issue #63), so a
    // now-breached password is detected on the next sign-in. Default false (no per-login
    // outbound call); the boot path sets it from config.
    screen_on_login: bool,
    // The installed breached-password screening provider (issue #63): the online HIBP
    // range provider or the offline corpus provider, both behind the k-anonymity
    // `BreachRangeProvider` interface. Kept OUTSIDE `Inner` and installed by the boot path
    // (the HIBP provider needs a fetcher). Default: `None`. When screening is enabled in
    // policy but no provider is installed, screening treats the provider as unavailable and
    // applies the fail-open/closed policy, so the mandatory-screening default never
    // silently no-ops. The many DB-only OIDC tests install a stub provider to drive the
    // breached/clean/fail paths deterministically without the network.
    breach_provider: Option<Arc<dyn ironauth_screening::BreachRangeProvider>>,
}

// The per-environment policy flags each mirror an independent, individually
// documented OidcConfig toggle; folding them into a state machine or enums (the
// excessive-bools remedy) would obscure that one-to-one mapping to config for no
// gain, so the lint is allowed here.
#[allow(clippy::struct_excessive_bools)]
struct Inner {
    store: Store,
    env: Env,
    // The ONE holder of every environment's signing keys, algorithm policy, and
    // salt (issue #194). The mint resolves its signer through this SAME registry
    // the JWKS/discovery serving reads, so a signed `kid` is always in the
    // published JWKS. Store-backed and lazy in production; pre-populated in tests.
    issuers: Arc<IssuerRegistry>,
    issuer_base: String,
    code_ttl: Duration,
    access_token_ttl: Duration,
    // The access-token format this environment mints when no resource server is
    // targeted (issue #29). A registered resource server overrides it per audience.
    // The spec-conform default is `at_jwt`, which keeps UserInfo working.
    default_access_token_format: TokenFormat,
    reuse_grace: Duration,
    // The session ABSOLUTE hard-cap lifetime (issue #20 `session_ttl`, extended by
    // issue #32): the session cannot outlive this however active. `session_idle_ttl`
    // is the separate idle timeout (a session unused this long stops resolving); both
    // are enforced by the SessionRepo read guard against the application clock.
    session_ttl: Duration,
    session_idle_ttl: Duration,
    // The session-model policy knobs (issue #32). The CHIPS `Partitioned` cookie
    // attribute is OFF by default (only for embedded-widget scenarios); the peer-IP
    // and device/user-agent session binding are BOTH OFF by default (the tunability
    // principle: env-dependent behavior is config, never a baked-in one-way choice),
    // so a NAT or mobile IP change never logs a user out unless an operator opts in.
    session_partitioned_cookie: bool,
    session_peer_ip_binding: bool,
    session_device_binding: bool,
    // The pushed-authorization-request `request_uri` lifetime (RFC 9126, issue #27).
    // A pushed request is short-lived and single-use; validated non-zero and bounded
    // by config (oidc.par_ttl_secs).
    par_ttl: Duration,
    // Whether EVERY client in this environment must use a pushed authorization
    // request (RFC 9126 section 5, issue #27). Layered with the per-client flag: a
    // request must be pushed when either this OR the client's own flag is set. A
    // promotable per-environment setting sourced from OidcConfig; default false.
    require_pushed_authorization_requests: bool,
    // The per-environment PKCE policy for CONFIDENTIAL clients (issue #13). A
    // public client always requires PKCE (RFC 9700 2.1.1, enforced structurally in
    // the authorize path); this only governs confidential clients, and defaults to
    // required.
    require_pkce_for_confidential: bool,
    // Whether to copy the scope-derived claims into the ID token (the non-conform
    // node-oidc-provider `conformIdTokenClaims = false` behavior, issue #15). The
    // spec-conform default is false: scope claims live at UserInfo and the ID token
    // stays lean. A promotable per-environment setting sourced from OidcConfig.
    conform_id_token_claims: bool,
    // The registered SPA web origins allowed to call UserInfo cross-origin (issue
    // #15), matched exactly against a request's `Origin`. Empty means no CORS. CORS
    // is offered on UserInfo ONLY, never on the authorization endpoint. A promotable
    // per-environment setting sourced from OidcConfig.
    userinfo_cors_origins: BTreeSet<String>,
    // The per-environment legacy-flow enablement (issue #17). Each is a promotable
    // per-environment setting sourced from OidcConfig; all default to false, so the
    // safe default serves only the `code` flow with the `query` response mode. The
    // token-bearing response types are not represented here at all: they are
    // structurally unrepresentable in ResponseType, designed OUT rather than
    // configured off.
    enable_response_type_id_token: bool,
    enable_response_type_code_id_token: bool,
    enable_response_type_none: bool,
    enable_response_mode_form_post: bool,
    // Whether the Dynamic Client Registration endpoint is mounted and served
    // (issue #30). Default OFF: open self-service registration is an abuse surface
    // whose real gating (quotas, quarantine, initial-access-token policy) is owned
    // by issue #31; this flag is the plain on/off switch #31 layers policy onto.
    registration_enabled: bool,
    // OIDC Session Management 1.0 and Front-Channel Logout 1.0 (issue #39). Both
    // default OFF: these iframe mechanisms are degraded under third-party-cookie
    // partitioning and ship ONLY for certification completeness. When on, session
    // management mounts the check_session_iframe and emits session_state; front-channel
    // logout renders per-RP hidden logout iframes during end_session. Each still
    // requires a per-client opt-in, so neither turns on globally by accident.
    session_management_enabled: bool,
    frontchannel_logout_enabled: bool,
    // The DCR abuse controls (issue #31): the exposure switch (closed / token_gated
    // / open), the per-environment registered-client quota, and the endpoint-local
    // rate limit (max registrations per source or IAT per window). Safe defaults:
    // token_gated, a bounded quota, and a conservative rate limit.
    registration_mode: RegistrationMode,
    registration_max_clients: u32,
    registration_rate_limit: u32,
    registration_rate_window: Duration,
    // The audience policy an inbound JWT client assertion must satisfy (issue #25),
    // shared with the JWT bearer grant (#26). Default: accept the token-endpoint
    // URL OR the issuer; strict: the issuer only.
    client_assertion_audience: ClientAssertionAudience,
    // The clock-skew tolerance for a JWT client assertion's exp/nbf/iat (issue #25).
    client_assertion_skew: Duration,
    // The resolver for a private_key_jwt client's `jwks_uri` keys, fetched through
    // the SSRF-hardened fetcher and cached (issue #25). `None` when no fetcher is
    // wired: a `jwks_uri` client then fails closed (an inline-`jwks` client still
    // works). It is optional so the many database-only OIDC tests need not stand up
    // a fetcher, and the existing `OidcState::new` signature is unchanged.
    client_key_resolver: Option<Arc<ClientKeyResolver>>,
    // The one shared subject-derivation cache. The surface that emits a `sub` (the
    // ID token today, and `UserInfo`/introspection once they land) resolves it
    // through this cache; because it is a single shared derivation, any two
    // surfaces that call it agree, so a pairwise subject cannot diverge between
    // them. The cache partitions by the per-environment salt, keeping environments
    // isolated.
    subjects: SubjectCache,
    // Refresh-token rotation, families, and offline_access (issue #21). Lifetimes
    // are converted to Duration here at the single config boundary. The idle/max
    // pair differ for a session-bound versus an offline family; the rotation grace
    // and threshold govern reuse detection and the graduated rotation policy.
    issue_refresh_tokens: bool,
    refresh_idle_ttl: Duration,
    refresh_max_lifetime: Duration,
    offline_idle_ttl: Duration,
    offline_max_lifetime: Duration,
    refresh_rotation_grace: Duration,
    refresh_rotation_threshold_percent: u64,
    offline_access_requires_consent: bool,
    remembered_consent_ttl: Duration,
    // The default audience a client-credentials access token carries when no
    // resource server is targeted (issue #23): the client id or the per-environment
    // issuer. A registered resource server (the RFC 8707 `resource` parameter, #28)
    // overrides it. A promotable per-environment setting sourced from OidcConfig.
    client_credentials_default_audience: ClientCredentialsAudience,
    // Device-authorization grant policy (issue #24, RFC 8628). All sourced from
    // OidcConfig at this single boundary: the flow TTL, the base and slow_down poll
    // intervals, the per-flow failed-user-code bound, and the per-source verification
    // rate limit and its window.
    device_code_ttl: Duration,
    device_poll_interval_secs: u64,
    device_slow_down_increment_secs: u64,
    device_user_code_max_attempts: u32,
    device_verification_rate_limit: u32,
    device_verification_rate_window: Duration,
    // Whether the Global Token Revocation receiver (issue #36) hard-kills the
    // subject's offline_access families too, not only the session-bound ones. Effect
    // only when the endpoint is mounted; the safe default (false) preserves offline
    // grants (issue #21/#32).
    global_token_revocation_hard_kill: bool,
    // WebAuthn passkeys (issue #65). The RP ID override is None when derived from
    // the serving origin host; the challenge TTL, UV requirement, and clone-detection
    // policy come straight from OidcConfig (already validated at startup).
    webauthn_enabled: bool,
    webauthn_rp_id: Option<String>,
    // The related origins (issue #67): additional origins permitted to use this
    // environment's RP ID, canonicalized at construction. Empty for a single-origin
    // deployment. Served at GET /.well-known/webauthn and folded into the ceremony
    // allowed-origin set.
    webauthn_related_origins: Vec<String>,
    webauthn_challenge_ttl_secs: u64,
    webauthn_require_user_verification: bool,
    webauthn_clone_detection_block: bool,
    // Credential-abuse regulation policy (issue #64): the resolved risk-based escalation
    // and ban policy. Config-derived and immutable. The in-process L1 counter store for
    // the fast request-shaping layer lives OUTSIDE Inner (like the hashing pool) so it
    // is swappable for the optional IronCache L2 later.
    regulation: crate::abuse::RegulationSettings,
    // TOTP second factor and recovery codes (issue #69). All validated at startup.
    totp_enabled: bool,
    totp_issuer: Option<String>,
    totp_period_secs: u64,
    totp_digits: u32,
    totp_drift_steps: u32,
    totp_recovery_code_count: u32,
    mfa_required: bool,
    mfa_factor_order: Vec<String>,
    acr_order: Vec<String>,
}

impl OidcState {
    /// Build the OIDC state.
    ///
    /// In production `store` MUST authenticate as `ironauth_app` (the data-plane
    /// role), so the forced row-level-security backstop applies beneath the
    /// repository layer. `issuers` is the shared registry that holds (and, when
    /// store-backed, lazily loads) each environment's keys, algorithm policy, and
    /// salt; the JWKS/discovery serving reads the SAME `Arc`. `issuer_base` is the
    /// deployment's externally visible base URL (from `server.public_url`), which
    /// the per-environment issuer is derived from. The lifetimes come from
    /// [`OidcConfig`] (already validated non-zero and bounded).
    #[must_use]
    pub fn new(
        store: Store,
        env: Env,
        issuers: Arc<IssuerRegistry>,
        config: &OidcConfig,
        issuer_base: impl Into<String>,
    ) -> Self {
        Self::build(store, env, issuers, config, issuer_base, None)
    }

    /// Like [`OidcState::new`] but wiring the `private_key_jwt` client-key resolver
    /// (issue #25), so a `jwks_uri` client's keys are fetched (through the
    /// SSRF-hardened fetcher) and cached. Use this where clients authenticate with
    /// `private_key_jwt` via a `jwks_uri`; an inline-`jwks` client needs no
    /// resolver and works through [`OidcState::new`] too.
    #[must_use]
    pub fn with_client_key_resolver(
        store: Store,
        env: Env,
        issuers: Arc<IssuerRegistry>,
        config: &OidcConfig,
        issuer_base: impl Into<String>,
        resolver: Arc<ClientKeyResolver>,
    ) -> Self {
        Self::build(store, env, issuers, config, issuer_base, Some(resolver))
    }

    fn build(
        store: Store,
        env: Env,
        issuers: Arc<IssuerRegistry>,
        config: &OidcConfig,
        issuer_base: impl Into<String>,
        client_key_resolver: Option<Arc<ClientKeyResolver>>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                env,
                issuers,
                issuer_base: issuer_base.into(),
                code_ttl: Duration::from_secs(config.authorization_code_ttl_secs),
                access_token_ttl: Duration::from_secs(config.access_token_ttl_secs),
                default_access_token_format: map_token_format(config.default_access_token_format),
                reuse_grace: Duration::from_secs(config.reuse_grace_secs),
                session_ttl: Duration::from_secs(config.session_ttl_secs),
                session_idle_ttl: Duration::from_secs(config.session_idle_ttl_secs),
                session_partitioned_cookie: config.session_partitioned_cookie,
                session_peer_ip_binding: config.session_peer_ip_binding,
                session_device_binding: config.session_device_binding,
                par_ttl: Duration::from_secs(config.par_ttl_secs),
                require_pushed_authorization_requests: config.require_pushed_authorization_requests,
                require_pkce_for_confidential: config.require_pkce_for_confidential_clients,
                conform_id_token_claims: config.conform_id_token_claims,
                client_assertion_audience: config.client_assertion_audience,
                client_assertion_skew: Duration::from_secs(config.client_assertion_max_skew_secs),
                client_key_resolver,
                userinfo_cors_origins: config.userinfo_cors_origins.iter().cloned().collect(),
                enable_response_type_id_token: config.enable_response_type_id_token,
                enable_response_type_code_id_token: config.enable_response_type_code_id_token,
                enable_response_type_none: config.enable_response_type_none,
                enable_response_mode_form_post: config.enable_response_mode_form_post,
                registration_enabled: config.registration_enabled,
                session_management_enabled: config.session_management_enabled,
                frontchannel_logout_enabled: config.frontchannel_logout_enabled,
                registration_mode: config.registration_mode,
                registration_max_clients: config.registration_max_clients,
                registration_rate_limit: config.registration_rate_limit,
                registration_rate_window: Duration::from_secs(config.registration_rate_window_secs),
                subjects: SubjectCache::new(),
                issue_refresh_tokens: config.issue_refresh_tokens,
                refresh_idle_ttl: Duration::from_secs(config.refresh_idle_ttl_secs),
                refresh_max_lifetime: Duration::from_secs(config.refresh_max_lifetime_secs),
                offline_idle_ttl: Duration::from_secs(config.offline_idle_ttl_secs),
                offline_max_lifetime: Duration::from_secs(config.offline_max_lifetime_secs),
                refresh_rotation_grace: Duration::from_secs(config.refresh_rotation_grace_secs),
                refresh_rotation_threshold_percent: config.refresh_rotation_threshold_percent,
                offline_access_requires_consent: config.offline_access_requires_consent,
                remembered_consent_ttl: Duration::from_secs(config.remembered_consent_ttl_secs),
                client_credentials_default_audience: config.client_credentials_default_audience,
                device_code_ttl: Duration::from_secs(config.device_code_ttl_secs),
                device_poll_interval_secs: config.device_poll_interval_secs,
                device_slow_down_increment_secs: config.device_slow_down_increment_secs,
                device_user_code_max_attempts: config.device_user_code_max_attempts,
                device_verification_rate_limit: config.device_verification_rate_limit,
                device_verification_rate_window: Duration::from_secs(
                    config.device_verification_rate_window_secs,
                ),
                global_token_revocation_hard_kill: config.global_token_revocation_hard_kill,
                webauthn_enabled: config.webauthn_enabled,
                webauthn_rp_id: config.webauthn_rp_id.clone(),
                // Canonicalize each related origin (lowercased host, default port
                // dropped, path stripped) so the served document and the ceremony
                // allowed-origin comparison use the exact byte form a browser sends
                // in an Origin header (issue #67). Entries were format-validated at
                // startup, so any that fail to canonicalize here are simply dropped.
                webauthn_related_origins: config
                    .webauthn_related_origins
                    .iter()
                    .filter_map(|origin| origin_of(origin))
                    .collect(),
                webauthn_challenge_ttl_secs: config.webauthn_challenge_ttl_secs,
                webauthn_require_user_verification: config.webauthn_require_user_verification,
                webauthn_clone_detection_block: config.webauthn_clone_detection_block,
                regulation: crate::abuse::RegulationSettings::from_config(&config.regulation),
                totp_enabled: config.totp_enabled,
                totp_issuer: config.totp_issuer.clone(),
                totp_period_secs: config.totp_period_secs,
                totp_digits: config.totp_digits,
                totp_drift_steps: config.totp_drift_steps,
                totp_recovery_code_count: config.totp_recovery_code_count,
                mfa_required: config.mfa_required,
                mfa_factor_order: config.mfa_factor_order.clone(),
                acr_order: config.acr_order.clone(),
            }),
            revocation_sink: default_sink(),
            introspection_serializer: default_serializer(),
            global_token_revocation_enabled: false,
            quota: None,
            migration_hook: None,
            hashing_pool: None,
            abuse_counters: Arc::new(crate::abuse::MemoryCounterStore::new()),
            verification_sender: Arc::new(crate::verification::NullVerificationSender),
            password_policy: ironauth_screening::PasswordPolicy::default(),
            screening_failure: ironauth_screening::FailurePolicy::FailOpen,
            screen_on_login: false,
            breach_provider: None,
        }
    }

    /// Install a custom internal revocation-event sink (issue #22), replacing the
    /// default no-op sink. The M4 external fan-out wires its sink here; a test can
    /// wire a recording sink to assert an event is published on every revocation.
    #[must_use]
    pub fn with_revocation_sink(mut self, sink: Arc<dyn RevocationEventSink>) -> Self {
        self.revocation_sink = sink;
        self
    }

    /// Mount (or not) the experimental Global Token Revocation receiver (issue #36).
    ///
    /// The boot path is the ONLY caller: it resolves `enabled` from the strict config
    /// feature ladder (the `global-token-revocation` experimental feature enabled AND
    /// acknowledged at the exact draft revision) and passes the result here. It is a
    /// builder rather than an `OidcConfig` field precisely so an operator cannot arm
    /// the endpoint from the `[oidc]` table and bypass the experimental ack gate:
    /// enabling is only ever reachable through the ladder.
    #[must_use]
    pub fn with_global_token_revocation_enabled(mut self, enabled: bool) -> Self {
        self.global_token_revocation_enabled = enabled;
        self
    }

    /// Whether the experimental Global Token Revocation receiver is mounted (issue
    /// #36). The router mounts `POST /global-token-revocation` only when this is true.
    #[must_use]
    pub fn global_token_revocation_enabled(&self) -> bool {
        self.global_token_revocation_enabled
    }

    /// Install the per-tenant/per-environment quota enforcer (issue #50), turning
    /// on data-plane tenant fairness. The boot path builds one enforcer from the
    /// `[quota]` config (seeded with the same env clock) and installs it here; a
    /// test installs a small-budget enforcer to drive the 429 path. With no
    /// enforcer installed the data plane admits every request (no enforcement),
    /// which is the default and the self-hoster's unlimited posture.
    #[must_use]
    pub fn with_quota_enforcer(mut self, enforcer: Arc<QuotaEnforcer>) -> Self {
        self.quota = Some(enforcer);
        self
    }

    /// Install the inbound lazy-migration hook (issue #56), arming the login path to
    /// verify an unknown identifier's first login against a legacy store. The boot path
    /// builds one hook from the `[oidc.lazy_migration]` config (a dedicated SSRF-hardened
    /// fetcher plus a circuit breaker on the same env clock) and installs it here; a test
    /// installs a hook over a stub verifier. With no hook installed (the default) the
    /// login path is unchanged: an unknown identifier is the uniform failure and no
    /// outbound call is made.
    #[must_use]
    pub fn with_migration_hook(mut self, hook: Arc<crate::migration::LazyMigrationHook>) -> Self {
        self.migration_hook = Some(hook);
        self
    }

    /// The installed lazy-migration hook, if any (issue #56). The login path consults it
    /// ONLY when the submitted identifier is unknown locally.
    #[must_use]
    pub(crate) fn migration_hook(&self) -> Option<&Arc<crate::migration::LazyMigrationHook>> {
        self.migration_hook.as_ref()
    }

    /// Charge one request against the tenant and environment request-rate quota
    /// for `scope` (issue #50).
    ///
    /// Returns [`Some`] `429 Too Many Requests` response when the scope is over
    /// quota: the caller MUST return it and spend nothing further (fail-closed at
    /// the ceiling). Returns [`None`] when the request is admitted (or when no
    /// enforcer is installed), and the caller proceeds untouched. The spend draws
    /// from the environment bucket and, by nesting, its tenant bucket, so one
    /// tenant hitting its limit never consumes another tenant's share.
    #[must_use]
    pub(crate) fn enforce_request_quota(&self, scope: &Scope) -> Option<axum::response::Response> {
        crate::quota::enforce_request(self.quota.as_ref()?, scope)
    }

    /// Install the dedicated Argon2id hashing pool (issue #62), moving every
    /// password hash and verification off the async request threads and behind
    /// per-tenant fair-share admission. The boot path builds one pool from the
    /// `[password_hashing]` config, sharing the SAME quota enforcer as the request
    /// path; a test installs a small-pool, small-budget instance to drive the
    /// isolation and load-shedding paths. With no pool installed hashing runs on
    /// the tokio blocking pool (still off the protocol-I/O threads) with no
    /// admission but a bounded concurrency cap (issue #62,
    /// [`inline_hash_semaphore`]) so the fallback cannot exhaust threads or memory:
    /// the default and the self-hoster's posture. The installed pool is the
    /// production path.
    #[must_use]
    pub fn with_hashing_pool(mut self, pool: Arc<crate::hashing_pool::HashingPool>) -> Self {
        self.hashing_pool = Some(pool);
        self
    }

    /// The Argon2id parameters NEW hashes are minted at (issue #62): the installed
    /// pool's configured parameters, or the OWASP defaults when no pool is installed.
    /// The login path compares a stored native hash against these to decide whether
    /// to transparently rehash on a successful sign-in.
    #[must_use]
    pub(crate) fn hashing_params(&self) -> crate::password::Argon2Params {
        self.hashing_pool
            .as_ref()
            .map_or_else(crate::password::Argon2Params::owasp, |pool| pool.params())
    }

    /// Hash `password` for `scope` off the async threads (issue #62). Routes
    /// through the installed pool (fair-share admission plus the bounded queue) or,
    /// when none is installed, the tokio blocking pool at the OWASP defaults.
    ///
    /// # Errors
    ///
    /// [`HashRejection`] when the tenant is over its hashing share, the pool queue
    /// is full, or the pool could not complete the hash. Never an inline hash on an
    /// async request thread.
    pub(crate) async fn hash_password(
        &self,
        scope: &Scope,
        password: &str,
    ) -> Result<String, crate::hashing_pool::HashRejection> {
        // NFKC-normalize ONCE at the hashing seam (issue #63): the stored verifier is
        // derived from the normalized form, and verify normalizes identically, so a
        // Unicode password round-trips (63B-4: NFKC applied once, consistent set/verify).
        // NFKC is identity on ASCII, so existing ASCII passwords are unaffected.
        let password = ironauth_screening::normalize_nfkc(password);
        if let Some(pool) = &self.hashing_pool {
            return pool.hash(scope, &password).await;
        }
        let env = self.env().clone();
        bounded_inline(move || crate::password::hash_password(&env, &password))
            .await?
            .map_err(|_| crate::hashing_pool::HashRejection::Unavailable)
    }

    /// Verify `password` against a stored PHC `hash` for `scope` off the async
    /// threads (issue #62). Routes through the installed pool or the tokio blocking
    /// pool.
    ///
    /// # Errors
    ///
    /// [`HashRejection`] on over-share, pool exhaustion, or pool fault. A wrong
    /// password (or a malformed stored hash) is `Ok(false)`.
    pub(crate) async fn verify_password(
        &self,
        scope: &Scope,
        password: &str,
        hash: &str,
    ) -> Result<bool, crate::hashing_pool::HashRejection> {
        // Verify against the SAME NFKC-normalized form the stored verifier was minted from
        // (issue #63), so a Unicode password verifies. Identity on ASCII.
        let password = ironauth_screening::normalize_nfkc(password);
        if let Some(pool) = &self.hashing_pool {
            return pool.verify(scope, &password, hash).await;
        }
        let hash = hash.to_owned();
        bounded_inline(move || crate::password::verify_password(&password, &hash)).await
    }

    /// Spend a full verification for `scope` against a fixed dummy hash and return
    /// `false` (issue #62), so an absent account costs the same as a present one.
    /// Still admission-controlled through the pool.
    ///
    /// # Errors
    ///
    /// [`HashRejection`] on over-share, pool exhaustion, or pool fault.
    pub(crate) async fn verify_absent(
        &self,
        scope: &Scope,
        password: &str,
    ) -> Result<bool, crate::hashing_pool::HashRejection> {
        // Normalize identically to the present-account verify path (issue #63) so an
        // absent account is timing-symmetric with a present one on the same input.
        let password = ironauth_screening::normalize_nfkc(password);
        if let Some(pool) = &self.hashing_pool {
            return pool.verify_absent(scope, &password).await;
        }
        bounded_inline(move || crate::password::verify_absent(&password)).await
    }

    /// The resolved credential-abuse regulation settings (issue #64).
    #[must_use]
    pub(crate) fn regulation(&self) -> &crate::abuse::RegulationSettings {
        &self.inner.regulation
    }

    /// Install a custom counter store for the fast request-shaping layer (issue #64),
    /// replacing the default in-process L1. A test wires a failing stub here to exercise
    /// the fail-open matrix; the optional IronCache L2 wires its `CounterStore` impl here
    /// later. Called only before the state is shared across request threads.
    #[must_use]
    pub fn with_abuse_counters(mut self, counters: Arc<dyn crate::abuse::CounterStore>) -> Self {
        self.abuse_counters = counters;
        self
    }

    /// Install the verification / OTP sender (issue #64), replacing the default no-op
    /// [`NullVerificationSender`](crate::verification::NullVerificationSender). The real
    /// transport (issue #68) wires its sender here; a test wires a recording sender to
    /// assert the closed-registration suppression.
    #[must_use]
    pub fn with_verification_sender(
        mut self,
        sender: Arc<dyn crate::verification::VerificationSender>,
    ) -> Self {
        self.verification_sender = sender;
        self
    }

    /// Install the resolved NIST SP 800-63B-4 password policy (issue #63): the length
    /// floors and any legacy composition/rotation overrides, the provider-failure policy
    /// (fail-open/closed), and whether to screen at login. The boot path builds these from
    /// the top-level `[password_policy]` config; a test installs a policy to drive the
    /// length/composition/deviation and fail-open/closed paths. With no policy installed
    /// the state uses the shipped 63B-4 defaults.
    #[must_use]
    pub fn with_password_policy(
        mut self,
        policy: ironauth_screening::PasswordPolicy,
        on_provider_failure: ironauth_screening::FailurePolicy,
        screen_on_login: bool,
    ) -> Self {
        self.password_policy = policy;
        self.screening_failure = on_provider_failure;
        self.screen_on_login = screen_on_login;
        self
    }

    /// Install the breached-password screening provider (issue #63): the online HIBP range
    /// provider or the offline corpus provider, both behind the k-anonymity
    /// [`BreachRangeProvider`](ironauth_screening::BreachRangeProvider) interface. The boot
    /// path builds one from `[password_policy]` (the HIBP provider needs a fetcher; the
    /// offline provider loads the corpus file); a test installs a stub provider to drive
    /// the breached / clean / provider-failure paths without the network. With no provider
    /// installed and screening enabled in policy, screening treats the provider as
    /// unavailable and applies the fail-open/closed policy.
    #[must_use]
    pub fn with_breach_provider(
        mut self,
        provider: Arc<dyn ironauth_screening::BreachRangeProvider>,
    ) -> Self {
        self.breach_provider = Some(provider);
        self
    }

    /// The resolved 800-63B-4 password policy (issue #63): the length floors, the
    /// composition/rotation legacy settings, and the deviation annotations.
    #[must_use]
    pub(crate) fn password_policy(&self) -> &ironauth_screening::PasswordPolicy {
        &self.password_policy
    }

    /// Whether to screen the presented password at login (issue #63).
    #[must_use]
    pub(crate) fn screen_on_login(&self) -> bool {
        self.screen_on_login
    }

    /// Screen a NFKC-normalized `normalized` password against the installed provider under
    /// the configured fail-open/closed policy (issue #63). Only the 5-char SHA-1 prefix is
    /// ever sent to the provider; the full password and hash never leave the process. Emits
    /// the screening metric and, on a fail-open provider outage, an audit log recording the
    /// unscreened acceptance.
    pub(crate) async fn screen_password(&self, scope: &Scope, normalized: &str) -> ScreenDecision {
        use ironauth_screening::{FailurePolicy, ScreenOutcome, Screener};

        if !self.password_policy.screening_enabled() {
            return ScreenDecision::Allowed;
        }
        let Some(provider) = &self.breach_provider else {
            // Screening is mandatory in policy but no provider is installed: treat it as a
            // provider outage so the mandatory default never silently no-ops.
            return match self.screening_failure {
                FailurePolicy::FailOpen => {
                    audit_screening_fail_open(scope, "none");
                    ScreenDecision::Allowed
                }
                FailurePolicy::FailClosed => {
                    metrics::counter!(PASSWORD_SCREEN_TOTAL, "outcome" => "fail_closed")
                        .increment(1);
                    ScreenDecision::RefusedUnavailable
                }
            };
        };
        let screener = Screener::new(Arc::clone(provider), self.screening_failure);
        match screener.screen(normalized).await {
            ScreenOutcome::NotBreached => {
                metrics::counter!(PASSWORD_SCREEN_TOTAL, "outcome" => "not_breached").increment(1);
                ScreenDecision::Allowed
            }
            ScreenOutcome::Breached => {
                metrics::counter!(PASSWORD_SCREEN_TOTAL, "outcome" => "breached").increment(1);
                ScreenDecision::Breached
            }
            ScreenOutcome::AllowedProviderFailure { provider } => {
                audit_screening_fail_open(scope, provider);
                ScreenDecision::Allowed
            }
            ScreenOutcome::RefusedProviderFailure { .. } => {
                metrics::counter!(PASSWORD_SCREEN_TOTAL, "outcome" => "fail_closed").increment(1);
                ScreenDecision::RefusedUnavailable
            }
        }
    }

    /// Whether self-service registration is CLOSED (issue #64): the Logto send-suppression
    /// posture.
    #[must_use]
    pub(crate) fn registration_closed(&self) -> bool {
        self.inner.regulation.registration_closed
    }

    /// Dispatch a verification / OTP send through the seam (issue #64), applying the
    /// closed-registration SUPPRESSION: when `recipient_known` is false the send is
    /// silently dropped (a suppressed send is an audited-by-tracing event), but the caller
    /// returns the SAME user-visible acknowledgment either way, so a probe cannot
    /// distinguish an existing account from an unknown one.
    pub(crate) fn dispatch_verification(
        &self,
        scope: Scope,
        purpose: crate::verification::VerificationPurpose,
        recipient: &str,
        recipient_known: bool,
    ) {
        if recipient_known {
            self.verification_sender.send(scope, purpose, recipient);
        } else {
            // Suppressed send (issue #64): no delivery to an unknown recipient. Recorded
            // on the observability plane (never a body difference), so the acknowledgment
            // stays identical to a real send.
            tracing::info!(
                target: "ironauth.abuse",
                purpose = purpose.as_str(),
                tenant = %scope.tenant(),
                environment = %scope.environment(),
                "verification send suppressed for an unknown recipient (closed registration)"
            );
            metrics::counter!(
                "ironauth_verification_send_suppressed_total",
                "purpose" => purpose.as_str(),
            )
            .increment(1);
        }
    }

    /// Evaluate AND RECORD one credential-abuse regulation attempt BEFORE spending a
    /// credential verification (issue #64). The durable ban check runs first, then this
    /// RECORDS the attempt on every regulated dimension (so the counter CLIMBS on every
    /// attempt, throttled OR allowed) and computes the risk-based escalation from the
    /// now-incremented count over the existence-INDEPENDENT dimensions (the canonical
    /// identifier and the IP), so on the DEFAULT posture the decision never distinguishes a
    /// present from an absent identifier.
    ///
    /// Recording as part of the decision is what makes the escalation actually escalate
    /// (issue #64 HIGH-1): a throttled attempt still increments, so the per-identifier /
    /// per-IP delay keeps DOUBLING up to `max_delay` and the per-account counter keeps
    /// climbing until the opt-in `hard_lockout` threshold is REACHED (previously the
    /// counter froze at the soft threshold because a throttled attempt was never recorded).
    ///
    /// The ban check and the identifier layer are SECURITY-biased and FAIL CLOSED (a
    /// backend error refuses the attempt); the IP layer is AVAILABILITY-biased and FAILS
    /// OPEN (a future-L2 outage does not block logins). The per-account dimension is
    /// recorded fail-OPEN and is deliberately NOT a throttle input here (only the opt-in
    /// hard lockout consumes it), so failed spray against a victim cannot turn the
    /// pre-check into an existence oracle on the default path.
    pub(crate) async fn regulate_before(
        &self,
        ctx: &crate::abuse::AttemptContext,
    ) -> crate::abuse::RegulationOutcome {
        use crate::abuse::{
            RegulationOutcome, banned_snapshot, client_counter_key, escalating_delay,
            ip_counter_key, tenant_counter_key, throttle_snapshot,
        };
        let now = epoch_micros(self.now());
        let settings = *self.regulation();
        let scope = ctx.scope;
        // 1. Durable ban check (DB), fail CLOSED. Explicit operator bans (and an
        //    auto-placed hard-lockout ban) apply regardless of the auto-escalation switch.
        //    Keyed only on the subjects present, so it stays existence-independent on the
        //    default path.
        let subjects = ctx.ban_subjects();
        if !subjects.is_empty() {
            match self
                .store()
                .scoped(scope)
                .abuse()
                .active_ban(&subjects, ctx.path, now)
                .await
            {
                Ok(Some(_)) | Err(_) => {
                    return RegulationOutcome::Throttled(banned_snapshot(&settings));
                }
                Ok(None) => {}
            }
        }
        if !settings.enabled {
            return RegulationOutcome::Allow;
        }
        let window_secs = i64::try_from(settings.window_secs()).unwrap_or(i64::MAX);
        let mut worst: Option<(u64, std::time::Duration)> = None;
        // 2a. Per-identifier (DB), fail CLOSED. RECORD the attempt (increment) and compute
        //     the escalation from the now-climbing count. Existence-independent: the
        //     counter keys on the canonical identifier whether or not it resolves.
        if let Some(identifier) = &ctx.identifier {
            let subject = AbuseSubject::identifier(identifier.as_str().to_owned());
            match self
                .store()
                .scoped(scope)
                .abuse()
                .record_failure(&subject, ctx.path, window_secs, now)
                .await
            {
                Ok(count) => {
                    if let Some(delay) = escalating_delay(&settings, count) {
                        worst = Some(max_escalation(worst, count, delay));
                    }
                }
                Err(_) => {
                    return RegulationOutcome::Throttled(banned_snapshot(&settings));
                }
            }
        }
        // 2b. Per-IP (L1), fail OPEN: RECORD the attempt and escalate from the new count; a
        //     counter-store error is ignored (availability-biased).
        if let Some(ip) = &ctx.ip {
            if let Ok(count) =
                self.abuse_counters
                    .incr(&ip_counter_key(ctx.path, ip), settings.window_secs(), now)
            {
                if let Some(delay) = escalating_delay(&settings, count) {
                    worst = Some(max_escalation(worst, count, delay));
                }
            }
        }
        // 2c. Per-client and per-(tenant, environment) request counters (L1): recorded for
        //     the future edge/tenant-fairness layers (M5/M15), never a throttle input here.
        if let Some(client) = &ctx.client_id {
            let _ = self.abuse_counters.incr(
                &client_counter_key(ctx.path, client),
                settings.window_secs(),
                now,
            );
        }
        let _ = self.abuse_counters.incr(
            &tenant_counter_key(
                ctx.path,
                &scope.tenant().to_string(),
                &scope.environment().to_string(),
            ),
            settings.window_secs(),
            now,
        );
        // 2d. Per-account (DB) for the opt-in hard lockout ONLY, fail OPEN (records, never a
        //     request-path deny gate). Climbs every attempt so the threshold is REACHABLE;
        //     on crossing it (password path only) an auto hard-lockout ban is placed,
        //     confined to the account and the password path so the owner keeps the
        //     passkey/recovery paths. The response uses the UNIFORM banned shape so the
        //     just-banned present account is not distinguishable from a throttled
        //     identifier by the response (only the onset differs; issue #64 MEDIUM-3).
        if let Some(account) = &ctx.account_id {
            let subject = AbuseSubject::account(account.clone());
            let account_count = self
                .store()
                .scoped(scope)
                .abuse()
                .record_failure(&subject, ctx.path, window_secs, now)
                .await
                .unwrap_or(0);
            if settings.hard_lockout
                && ctx.path == AuthPath::Password
                && account_count >= settings.hard_lockout_threshold
            {
                self.auto_lockout(scope, account, now, &settings).await;
                return RegulationOutcome::Throttled(banned_snapshot(&settings));
            }
        }
        // 3. Throttle if the identifier or IP dimension is over the soft threshold.
        match worst {
            Some((count, delay)) => {
                RegulationOutcome::Throttled(throttle_snapshot(&settings, count, delay))
            }
            None => RegulationOutcome::Allow,
        }
    }

    /// Relax the per-identifier, per-account, and per-IP failure counters for `ctx`'s path
    /// after a SUCCESSFUL authentication (issue #64 LOW-6), so a legitimate user who typoed
    /// past the soft threshold is not throttled for the rest of the window once they enter
    /// the correct credential. Best-effort and per-PATH, so it never touches another path's
    /// state; a reset failure just leaves the (windowed) counter to roll over on its own.
    pub(crate) async fn reset_after_success(&self, ctx: &crate::abuse::AttemptContext) {
        let settings = *self.regulation();
        if !settings.enabled {
            return;
        }
        let scope = ctx.scope;
        if let Some(identifier) = &ctx.identifier {
            let subject = AbuseSubject::identifier(identifier.as_str().to_owned());
            let _ = self
                .store()
                .scoped(scope)
                .abuse()
                .clear_failures(&subject, ctx.path)
                .await;
        }
        if let Some(account) = &ctx.account_id {
            let subject = AbuseSubject::account(account.clone());
            let _ = self
                .store()
                .scoped(scope)
                .abuse()
                .clear_failures(&subject, ctx.path)
                .await;
        }
        if let Some(ip) = &ctx.ip {
            let _ = self
                .abuse_counters
                .clear(&crate::abuse::ip_counter_key(ctx.path, ip));
        }
    }

    /// Whether the passkey path is BANNED for `account` (issue #64 MEDIUM-2): a passkey- or
    /// `all`-path ban placed by an operator (or the auto-lockout, though that is password
    /// only) on the resolved account. Governs the passkey ceremony INDEPENDENTLY of the
    /// password path (a `password` ban never matches here), so failed-password spray can
    /// never lock the owner out of passkey login. FAILS CLOSED: a backend error is treated
    /// as banned, matching the password-path ban check.
    pub(crate) async fn passkey_account_banned(&self, scope: Scope, account: &str) -> bool {
        let now = epoch_micros(self.now());
        let subjects = [AbuseSubject::account(account.to_owned())];
        matches!(
            self.store()
                .scoped(scope)
                .abuse()
                .active_ban(&subjects, AuthPath::Passkey, now)
                .await,
            Ok(Some(_)) | Err(_)
        )
    }

    /// Auto-place a PASSWORD-path hard-lockout ban on `account` (issue #64), best-effort.
    /// Confined to the password path so the passkey and recovery paths stay open. A
    /// Conflict (already locked) is fine.
    async fn auto_lockout(
        &self,
        scope: Scope,
        account: &str,
        now: i64,
        settings: &crate::abuse::RegulationSettings,
    ) {
        let id = AbuseBanId::generate(self.env(), &scope);
        let subject = AbuseSubject::account(account.to_owned());
        let duration_micros =
            i64::try_from(settings.hard_lockout_duration.as_micros()).unwrap_or(i64::MAX);
        let expires_at = now.saturating_add(duration_micros);
        let actor = ActorRef::service(ServiceId::generate(self.env()));
        let _ = self
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(self.env()))
            .abuse()
            .ban(
                self.env(),
                NewBan {
                    id: &id,
                    subject: &subject,
                    auth_path: AuthPath::Password,
                    reason: "auto hard-lockout: failed-password threshold exceeded",
                    expires_at_unix_micros: Some(expires_at),
                },
                now,
            )
            .await;
    }

    /// Whether a Global Token Revocation hard-kills the subject's `offline_access`
    /// families too (issue #36). False (the safe default) preserves offline grants.
    #[must_use]
    pub(crate) fn global_token_revocation_hard_kill(&self) -> bool {
        self.inner.global_token_revocation_hard_kill
    }

    /// Install a custom introspection-response serializer (issue #22), replacing the
    /// default RFC 7662 plain-JSON serializer. The M16 RFC 9701 signed-JWT response
    /// wires its serializer here without touching the introspection endpoint.
    #[must_use]
    pub fn with_introspection_serializer(
        mut self,
        serializer: Arc<dyn IntrospectionSerializer>,
    ) -> Self {
        self.introspection_serializer = serializer;
        self
    }

    /// The internal revocation-event sink every successful revocation is published on.
    #[must_use]
    pub(crate) fn revocation_sink(&self) -> &Arc<dyn RevocationEventSink> {
        &self.revocation_sink
    }

    /// The pluggable introspection-response serializer.
    #[must_use]
    pub(crate) fn introspection_serializer(&self) -> &Arc<dyn IntrospectionSerializer> {
        &self.introspection_serializer
    }

    /// The shared subject-derivation cache.
    #[must_use]
    pub fn subjects(&self) -> &SubjectCache {
        &self.inner.subjects
    }

    /// Resolve an end user's `sub` for a client through the ONE shared derivation
    /// function ([`crate::resolve_subject`]), memoized.
    ///
    /// This is the single call every token surface uses, so the ID token,
    /// `UserInfo`, and future introspection responses cannot return a different
    /// `sub` for the same client and user. `config` selects public or pairwise;
    /// `salt` is the environment's pairwise salt (ignored for a public subject).
    #[must_use]
    pub fn resolve_subject(
        &self,
        config: &SubjectConfig,
        local_subject: &str,
        salt: &PairwiseSalt,
    ) -> String {
        self.inner.subjects.resolve(config, local_subject, salt)
    }

    /// Resolve a PUBLIC `sub` (the local account identifier) through the shared
    /// derivation. The per-client pairwise configuration (subject type, sector
    /// identifier, and the environment salt) is client-registration state that a
    /// later issue persists; until then the data-plane token path resolves public
    /// subjects, still routed through the one shared function so the wiring cannot
    /// diverge when pairwise registration lands.
    #[must_use]
    pub fn resolve_public_subject(&self, local_subject: &str) -> String {
        // A public subject never consults the salt, so an empty one is correct
        // here; the value flows through the same shared derivation regardless.
        self.resolve_subject(
            &SubjectConfig::public(),
            local_subject,
            &PairwiseSalt::new(Vec::new()),
        )
    }

    /// The data-plane store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// The environment seam (clock and entropy).
    #[must_use]
    pub fn env(&self) -> &Env {
        &self.inner.env
    }

    /// The configured authorization-code lifetime.
    #[must_use]
    pub fn code_ttl(&self) -> Duration {
        self.inner.code_ttl
    }

    /// The configured access-token lifetime.
    #[must_use]
    pub fn access_token_ttl(&self) -> Duration {
        self.inner.access_token_ttl
    }

    /// The environment's default access-token format (issue #29): the format used
    /// when no resource server is targeted. `at_jwt` by default.
    #[must_use]
    pub fn default_access_token_format(&self) -> TokenFormat {
        self.inner.default_access_token_format
    }

    /// Resolve the access-token target (audience(s), format, lifetime) for an
    /// exchange from a set of RFC 8707 resource indicators (issue #29 seam, extended
    /// for issue #28).
    ///
    /// This is ADDITIVE over the issue #29 single-resource seam:
    ///
    /// - **Empty `resources`** (the no-resource case, and every caller that mints
    ///   without a resource, for example the client-credentials, device, and
    ///   jwt-bearer grants): the ENVIRONMENT DEFAULT applies, EXACTLY as before #28.
    ///   The token's `aud` is a SINGLE audience, the `client_id` (so `UserInfo`'s
    ///   `aud == client` check keeps working), the format is the environment default,
    ///   and the lifetime is the environment access-token lifetime. This branch is
    ///   infallible.
    /// - **One or more `resources`**: EACH resource MUST name a registered resource
    ///   server's `audience` in this scope; an unknown resource is
    ///   [`ResourceTargetError::InvalidTarget`] (RFC 8707 section 2.2), never a silent
    ///   fallback (which would broaden the audience). The token's `aud` becomes the
    ///   full set of the targeted resource servers' audiences (a JSON array when more
    ///   than one). When multiple resource servers are targeted they MUST agree on
    ///   `token_format` (all-must-share-format-or-`invalid_target`: two servers that
    ///   disagree cannot be satisfied by one token, and picking one silently would be
    ///   surprising); the lifetime is the SHORTEST of the targeted servers'
    ///   `access_token_ttl_secs` (each falling back to the environment default when
    ///   unset), so bundling resources never LENGTHENS a token past what any one
    ///   resource server asked for.
    ///
    /// The caller (the token/authorization endpoints) validates the resource URIs,
    /// the per-client allowlist, and the downscope-not-expand rule BEFORE calling
    /// this; this method only maps already-authorized resources to their registered
    /// audiences/format/lifetime.
    ///
    /// # Errors
    ///
    /// [`ResourceTargetError::InvalidTarget`] if a requested resource is unknown or
    /// the targeted resource servers disagree on token format;
    /// [`ResourceTargetError::ServerError`] on a store fault (fail closed rather than
    /// silently dropping the audience restriction).
    pub async fn resolve_access_token_target(
        &self,
        scope: &Scope,
        resources: &[String],
        client_id: &str,
    ) -> Result<AccessTokenTarget, ResourceTargetError> {
        // The no-resource case: the environment default, a single client-id audience.
        // Identical to the pre-#28 behavior, so every mint that passes no resource
        // (client-credentials, device, jwt-bearer) is unchanged.
        if resources.is_empty() {
            return Ok(AccessTokenTarget {
                audiences: vec![client_id.to_owned()],
                format: self.inner.default_access_token_format,
                ttl: self.inner.access_token_ttl,
            });
        }

        let mut audiences: Vec<String> = Vec::with_capacity(resources.len());
        let mut format: Option<TokenFormat> = None;
        let mut ttl: Option<Duration> = None;
        for resource in resources {
            let server = match self
                .inner
                .store
                .scoped(*scope)
                .resource_servers()
                .by_audience(resource)
                .await
            {
                Ok(Some(server)) => server,
                // Unknown resource: RFC 8707 invalid_target, never a silent fallback.
                Ok(None) => return Err(ResourceTargetError::InvalidTarget),
                // Fail closed: a store blip must not drop the audience restriction.
                Err(_) => return Err(ResourceTargetError::ServerError),
            };
            // All targeted resource servers must agree on the token format.
            match format {
                None => format = Some(server.token_format),
                Some(existing) if existing != server.token_format => {
                    return Err(ResourceTargetError::InvalidTarget);
                }
                Some(_) => {}
            }
            // The lifetime is the SHORTEST of the targeted servers' TTLs (each
            // falling back to the environment default when unset).
            let rs_ttl = server
                .access_token_ttl_secs
                .and_then(|secs| u64::try_from(secs).ok())
                .map_or(self.inner.access_token_ttl, Duration::from_secs);
            ttl = Some(ttl.map_or(rs_ttl, |current| current.min(rs_ttl)));
            if !audiences.contains(&server.audience) {
                audiences.push(server.audience);
            }
        }
        Ok(AccessTokenTarget {
            audiences,
            format: format.unwrap_or(self.inner.default_access_token_format),
            ttl: ttl.unwrap_or(self.inner.access_token_ttl),
        })
    }

    /// Validate that EVERY requested resource names a registered resource server in
    /// scope (issue #28), for the AUTHORIZATION endpoint. Unlike
    /// [`Self::resolve_access_token_target`], this approves resources without minting
    /// a token, so it does NOT enforce token-format agreement: a client may have
    /// several resources of differing formats approved at once and later obtain a
    /// separate, format-consistent token for a subset of them at the token endpoint.
    ///
    /// # Errors
    ///
    /// [`ResourceTargetError::InvalidTarget`] if any resource is unknown (no
    /// registered resource server); [`ResourceTargetError::ServerError`] on a store
    /// fault (fail closed).
    pub(crate) async fn validate_resources_registered(
        &self,
        scope: &Scope,
        resources: &[String],
    ) -> Result<(), ResourceTargetError> {
        for resource in resources {
            match self
                .inner
                .store
                .scoped(*scope)
                .resource_servers()
                .by_audience(resource)
                .await
            {
                Ok(Some(_)) => {}
                Ok(None) => return Err(ResourceTargetError::InvalidTarget),
                Err(_) => return Err(ResourceTargetError::ServerError),
            }
        }
        Ok(())
    }

    /// The default audience a client-credentials access token (issue #23) carries
    /// when NO resource server is targeted, resolved for `client_id` in `scope`.
    ///
    /// Per the environment's `client_credentials_default_audience` policy: the OAuth
    /// client id (the default), or the per-environment issuer. This is the fallback
    /// audience the M2M mint passes into [`Self::resolve_access_token_target`]; when
    /// a request targets a registered resource server (the RFC 8707 `resource`
    /// parameter, issue #28), that resource server's audience wins instead and this
    /// default does not apply.
    #[must_use]
    pub fn client_credentials_default_audience(&self, scope: &Scope, client_id: &str) -> String {
        match self.inner.client_credentials_default_audience {
            ClientCredentialsAudience::ClientId => client_id.to_owned(),
            ClientCredentialsAudience::Issuer => self.issuer_for(scope),
        }
    }

    /// The configured reuse grace window for an already-consumed code. A second
    /// presentation within this window is a benign retry (no grant-chain revoke);
    /// beyond it, a genuine reuse that revokes the chain.
    #[must_use]
    pub fn reuse_grace(&self) -> Duration {
        self.inner.reuse_grace
    }

    /// Whether the authorization-code grant issues a refresh token (issue #21).
    #[must_use]
    pub fn issue_refresh_tokens(&self) -> bool {
        self.inner.issue_refresh_tokens
    }

    /// The idle timeout of a refresh token, by whether its family is offline
    /// (issue #21). An `offline_access` family gets the longer offline idle timeout;
    /// a session-bound family the shorter one.
    #[must_use]
    pub fn refresh_idle_ttl(&self, offline: bool) -> Duration {
        if offline {
            self.inner.offline_idle_ttl
        } else {
            self.inner.refresh_idle_ttl
        }
    }

    /// The absolute (hard-cap) lifetime of a refresh-token family, by whether it is
    /// offline (issue #21). This bounds the family's total rotated lifetime.
    #[must_use]
    pub fn refresh_max_lifetime(&self, offline: bool) -> Duration {
        if offline {
            self.inner.offline_max_lifetime
        } else {
            self.inner.refresh_max_lifetime
        }
    }

    /// The configured refresh-token rotation grace window (issue #21). Within this
    /// of a token's rotation a duplicate presentation is a benign concurrent
    /// refresh; beyond it, a genuine reuse that revokes the whole family.
    #[must_use]
    pub fn refresh_rotation_grace(&self) -> Duration {
        self.inner.refresh_rotation_grace
    }

    /// The configured rotation threshold as a whole percent of a refresh token's
    /// idle TTL (issue #21). A confidential or otherwise sender-bound client rotates
    /// only once its token has passed this fraction of its lifetime; a public,
    /// sender-unbound client always rotates.
    #[must_use]
    pub fn refresh_rotation_threshold_percent(&self) -> u64 {
        self.inner.refresh_rotation_threshold_percent
    }

    /// Whether `offline_access` requires explicit consent for a web client (issue
    /// #21, OIDC Core 11), subject to the trusted first-party carve-out.
    #[must_use]
    pub fn offline_access_requires_consent(&self) -> bool {
        self.inner.offline_access_requires_consent
    }

    /// The configured lifetime of a remembered consent (issue #21): the TTL applied
    /// to a recorded consent for a client whose consent mode is `remembered`.
    #[must_use]
    pub fn remembered_consent_ttl(&self) -> Duration {
        self.inner.remembered_consent_ttl
    }

    /// The configured session ABSOLUTE hard-cap lifetime (issue #20, extended by
    /// issue #32). A session cannot outlive this however active.
    #[must_use]
    pub fn session_ttl(&self) -> Duration {
        self.inner.session_ttl
    }

    /// The configured session IDLE timeout (issue #32): a session unused for longer
    /// than this stops resolving, independently of the absolute cap.
    #[must_use]
    pub fn session_idle_ttl(&self) -> Duration {
        self.inner.session_idle_ttl
    }

    /// Whether session cookies carry the CHIPS `Partitioned` attribute (issue #32).
    /// OFF by default; enabled for embedded-widget (cross-site) scenarios.
    #[must_use]
    pub fn session_partitioned_cookie(&self) -> bool {
        self.inner.session_partitioned_cookie
    }

    /// Whether the session is bound to the peer IP it was established from (issue
    /// #32). OFF by default (the tunability principle), so a NAT or mobile IP change
    /// never logs a user out unless an operator opts in.
    #[must_use]
    pub fn session_peer_ip_binding(&self) -> bool {
        self.inner.session_peer_ip_binding
    }

    /// Whether the session is bound to the device / user agent it was established
    /// from (issue #32). OFF by default (the tunability principle).
    #[must_use]
    pub fn session_device_binding(&self) -> bool {
        self.inner.session_device_binding
    }

    /// The configured pushed-authorization-request `request_uri` lifetime (RFC 9126,
    /// issue #27). A pushed request expires this long after it is pushed; validated
    /// non-zero and bounded by config.
    #[must_use]
    pub fn par_ttl(&self) -> Duration {
        self.inner.par_ttl
    }

    /// The configured device-authorization flow lifetime (issue #24, RFC 8628). Both
    /// the device code and the user code expire this long after issuance.
    #[must_use]
    pub fn device_code_ttl(&self) -> Duration {
        self.inner.device_code_ttl
    }

    /// The base minimum polling interval a device-authorization response advertises,
    /// in seconds (issue #24, RFC 8628 3.2 `interval`).
    #[must_use]
    pub fn device_poll_interval_secs(&self) -> u64 {
        self.inner.device_poll_interval_secs
    }

    /// The seconds the enforced polling interval grows by on each too-fast poll (issue
    /// #24, RFC 8628 3.5 `slow_down`).
    #[must_use]
    pub fn device_slow_down_increment_secs(&self) -> u64 {
        self.inner.device_slow_down_increment_secs
    }

    /// The number of failed user-code match attempts a single flow tolerates before it
    /// is invalidated (issue #24, RFC 8628 5.1).
    #[must_use]
    pub fn device_user_code_max_attempts(&self) -> u32 {
        self.inner.device_user_code_max_attempts
    }

    /// The per-source user-code submission limit for the verification page, and its
    /// window (issue #24, RFC 8628 5.1). A limit of 0 disables per-source rate
    /// limiting.
    #[must_use]
    pub fn device_verification_rate_limit(&self) -> u32 {
        self.inner.device_verification_rate_limit
    }

    /// The window for [`OidcState::device_verification_rate_limit`] (issue #24).
    #[must_use]
    pub fn device_verification_rate_window(&self) -> Duration {
        self.inner.device_verification_rate_window
    }

    /// The device-verification page URL for `scope` (issue #24, RFC 8628 3.2
    /// `verification_uri`): the per-environment issuer path plus `/device`, so the
    /// page is scope-routed by its own URL. The QR-friendly `verification_uri_complete`
    /// appends the user code as a query parameter.
    #[must_use]
    pub fn verification_uri_for(&self, scope: &Scope) -> String {
        format!("{}/device", self.issuer_for(scope))
    }

    /// Whether EVERY client in this environment must use a pushed authorization
    /// request (RFC 9126 section 5, issue #27). When true, the authorization endpoint
    /// rejects a plain (non-PAR) request. The per-client
    /// `require_pushed_authorization_requests` registration flag applies ON TOP of
    /// this: PAR is required when either is set.
    #[must_use]
    pub fn require_pushed_authorization_requests(&self) -> bool {
        self.inner.require_pushed_authorization_requests
    }

    /// The token endpoint's absolute URL (`{issuer_base}/token`). The token
    /// endpoint is mounted at the deployment root (shared across environments), so
    /// it is derived from `issuer_base`, not the per-environment issuer. One of the
    /// audiences a JWT client assertion may be addressed to (issue #25).
    #[must_use]
    pub fn token_endpoint_url(&self) -> String {
        format!("{}/token", self.inner.issuer_base.trim_end_matches('/'))
    }

    /// The set of audiences a JWT client assertion may be addressed to in `scope`
    /// under the configured audience policy (issue #25): the per-environment issuer
    /// (always), plus the token-endpoint URL unless the policy is issuer-only. The
    /// SHARED knob the JWT bearer grant (#26) reuses.
    #[must_use]
    pub fn client_assertion_audiences(&self, scope: &Scope) -> Vec<String> {
        let issuer = self.issuer_for(scope);
        match self.inner.client_assertion_audience {
            ClientAssertionAudience::IssuerOnly => vec![issuer],
            ClientAssertionAudience::TokenEndpointOrIssuer => {
                vec![issuer, self.token_endpoint_url()]
            }
        }
    }

    /// The clock-skew tolerance for a JWT client assertion's `exp`/`nbf`/`iat`
    /// (issue #25).
    #[must_use]
    pub fn client_assertion_skew(&self) -> Duration {
        self.inner.client_assertion_skew
    }

    /// The `private_key_jwt` client-key resolver, if one is wired (issue #25). A
    /// `jwks_uri` client fails closed when it is absent.
    #[must_use]
    pub fn client_key_resolver(&self) -> Option<&Arc<ClientKeyResolver>> {
        self.inner.client_key_resolver.as_ref()
    }

    /// Whether the Dynamic Client Registration endpoint is enabled for this
    /// deployment (issue #30). Default OFF: the endpoint is mounted and discovery
    /// advertises `registration_endpoint` only when this is set. The real abuse
    /// gating (quotas, quarantine, initial-access-token policy) is owned by issue
    /// #31; this is the plain on/off switch it layers policy onto.
    #[must_use]
    pub fn registration_enabled(&self) -> bool {
        self.inner.registration_enabled
    }

    /// Whether OIDC Session Management 1.0 is enabled for this deployment (issue #39).
    /// Default OFF: only when set does [`crate::oidc_router`] mount the
    /// `check_session_iframe`, discovery advertise `check_session_iframe`, and the
    /// authorization response carry `session_state`. Still requires a per-client
    /// opt-in, so it can never turn on globally by accident.
    #[must_use]
    pub fn session_management_enabled(&self) -> bool {
        self.inner.session_management_enabled
    }

    /// Whether OIDC Front-Channel Logout 1.0 is enabled for this deployment (issue
    /// #39). Default OFF: only when set does discovery advertise
    /// `frontchannel_logout_supported`/`_session_supported` and the `end_session` flow
    /// render per-RP hidden logout iframes. Still requires a per-client opt-in (a
    /// registered `frontchannel_logout_uri`), so it can never turn on globally by
    /// accident.
    #[must_use]
    pub fn frontchannel_logout_enabled(&self) -> bool {
        self.inner.frontchannel_logout_enabled
    }

    /// The Dynamic Client Registration exposure switch for this environment (issue
    /// #31): `closed` (management API only), `token_gated` (an initial access token
    /// is required), or `open` (anonymous, resulting client quarantined). Takes
    /// effect only when the endpoint is mounted ([`OidcState::registration_enabled`]).
    #[must_use]
    pub fn registration_mode(&self) -> RegistrationMode {
        self.inner.registration_mode
    }

    /// The per-environment cap on the number of dynamically registered clients
    /// (issue #31). A registration that would exceed it is refused with a typed
    /// error and a `dcr.quota_hit` audit event.
    #[must_use]
    pub fn registration_max_clients(&self) -> u32 {
        self.inner.registration_max_clients
    }

    /// The endpoint-local registration rate limit (issue #31): the maximum number
    /// of registration requests one source (or one initial access token) may make
    /// within [`OidcState::registration_rate_window`]. 0 disables rate limiting.
    #[must_use]
    pub fn registration_rate_limit(&self) -> u32 {
        self.inner.registration_rate_limit
    }

    /// The fixed rate-limit window for [`OidcState::registration_rate_limit`] (issue
    /// #31).
    #[must_use]
    pub fn registration_rate_window(&self) -> Duration {
        self.inner.registration_rate_window
    }

    /// Whether a CONFIDENTIAL client must use PKCE under this environment's policy
    /// (issue #13). Defaults to required. A public client always requires PKCE
    /// regardless of this value (RFC 9700 2.1.1), so the authorize path checks that
    /// separately; this governs only confidential clients.
    #[must_use]
    pub fn require_pkce_for_confidential(&self) -> bool {
        self.inner.require_pkce_for_confidential
    }

    /// The current wall-clock time from the environment clock seam.
    #[must_use]
    pub fn now(&self) -> SystemTime {
        self.inner.env.clock().now_utc()
    }

    /// The per-environment issuer for `scope`. Two environments never share an
    /// issuer, which is what makes a token from one environment unusable as one
    /// from another.
    #[must_use]
    pub fn issuer_for(&self, scope: &Scope) -> String {
        format!(
            "{}/t/{}/e/{}",
            self.inner.issuer_base.trim_end_matches('/'),
            scope.tenant(),
            scope.environment()
        )
    }

    /// This deployment's own web origin (`scheme://host[:port]`, no path), derived
    /// from the configured `issuer_base` (`server.public_url`), or [`None`] when the
    /// base URL has no parseable scheme+authority.
    ///
    /// Used as the CSRF Origin allowlist for the interactive login and consent POSTs
    /// (issue #196): a browser sends `Origin` on every cross-origin POST, so an
    /// `Origin` that does not match this value is a cross-site submission. The path,
    /// query, and per-environment `/t/../e/..` suffix are intentionally dropped: an
    /// `Origin` header is only ever `scheme://host[:port]`.
    #[must_use]
    pub fn self_origin(&self) -> Option<String> {
        origin_of(&self.inner.issuer_base)
    }

    /// Whether the WebAuthn passkey ceremony endpoints are mounted and the hosted
    /// login page offers conditional-UI passkey sign-in (issue #65).
    #[must_use]
    pub fn webauthn_enabled(&self) -> bool {
        self.inner.webauthn_enabled
    }

    /// The effective WebAuthn Relying Party ID and allowed origins for a ceremony
    /// (issue #65, extended by issue #67): the configured `oidc.webauthn_rp_id`
    /// (validated at startup) or, when unset, the serving origin's host. The allowed
    /// origins are this deployment's own origin FOLLOWED BY the configured related
    /// origins (WebAuthn Level 3 Related Origin Requests), deduplicated with the
    /// serving origin first. `None` when the serving origin cannot be derived from
    /// `server.public_url`, in which case a ceremony fails closed. WebAuthn origins
    /// are `scheme://host[:port]` with no path, so the per-environment `/t/../e/..`
    /// suffix is intentionally absent.
    ///
    /// Broadening the accepted origin set to the related origins is the ONLY change
    /// issue #67 makes to the ceremony security checks: the RP-ID hash, the
    /// assertion signature, and the single-use challenge are all unchanged. A
    /// clientData origin outside this exact set still fails with the non-enumerating
    /// ceremony error.
    #[must_use]
    pub fn webauthn_relying_party(&self) -> Option<WebauthnRelyingParty> {
        let origin = self.self_origin()?;
        let rp_id = match &self.inner.webauthn_rp_id {
            Some(configured) => configured.clone(),
            None => host_of(&origin)?,
        };
        let mut origins = Vec::with_capacity(1 + self.inner.webauthn_related_origins.len());
        origins.push(origin);
        for related in &self.inner.webauthn_related_origins {
            if !origins.contains(related) {
                origins.push(related.clone());
            }
        }
        Some(WebauthnRelyingParty { rp_id, origins })
    }

    /// The WebAuthn Related Origin Requests document served at
    /// `GET /.well-known/webauthn` (issue #67): the JSON `{"origins": [...]}` listing
    /// every origin permitted to use this environment's RP ID (the serving origin
    /// plus the configured related origins). `None` when the feature is not in use
    /// for this deployment (WebAuthn disabled, no related origins configured, or no
    /// derivable serving origin), which the handler maps to a `404` so an
    /// unconfigured domain serves no document. Generated from live state at request
    /// time, so a config change is reflected without a code redeploy.
    #[must_use]
    pub fn webauthn_related_origins_document(&self) -> Option<String> {
        if !self.inner.webauthn_enabled || self.inner.webauthn_related_origins.is_empty() {
            return None;
        }
        let rp = self.webauthn_relying_party()?;
        // serde_json over a borrowed slice of owned Strings: infallible for a Vec of
        // strings, so the document is a plain serialization of the origin list.
        serde_json::to_string(&serde_json::json!({ "origins": rp.origins })).ok()
    }

    /// The single-use WebAuthn challenge lifetime in seconds (issue #65).
    #[must_use]
    pub fn webauthn_challenge_ttl_secs(&self) -> u64 {
        self.inner.webauthn_challenge_ttl_secs
    }

    /// Whether a WebAuthn ceremony requires user verification (issue #65).
    #[must_use]
    pub fn webauthn_require_user_verification(&self) -> bool {
        self.inner.webauthn_require_user_verification
    }

    /// Whether a sign-count regression BLOCKS the sign-in (`true`) or only WARNS
    /// and records the event (`false`) (issue #65).
    #[must_use]
    pub fn webauthn_clone_detection_block(&self) -> bool {
        self.inner.webauthn_clone_detection_block
    }

    /// Whether the TOTP second-factor endpoints are mounted (issue #69). When off,
    /// the enroll/verify/recovery endpoints fail closed with a uniform 404.
    #[must_use]
    pub fn totp_enabled(&self) -> bool {
        self.inner.totp_enabled
    }

    /// The issuer label for a TOTP provisioning URI (issue #69): the configured
    /// `oidc.totp_issuer`, or the serving origin host when unset, or the fallback
    /// `IronAuth`. This is the human-facing label an authenticator app shows.
    #[must_use]
    pub fn totp_issuer(&self) -> String {
        if let Some(issuer) = &self.inner.totp_issuer {
            return issuer.clone();
        }
        self.self_origin()
            .and_then(|origin| host_of(&origin))
            .unwrap_or_else(|| "IronAuth".to_owned())
    }

    /// The RFC 6238 parameters a new TOTP enrollment is provisioned with (issue
    /// #69): the configured algorithm (SHA1, the authenticator-app default), digit
    /// count, and period. Validated at startup, so this cannot fail.
    #[must_use]
    pub fn totp_params(&self) -> ironauth_jose::TotpParams {
        ironauth_jose::TotpParams::new(
            ironauth_jose::TotpAlgorithm::Sha1,
            self.inner.totp_digits,
            self.inner.totp_period_secs,
        )
        .unwrap_or_else(|_| ironauth_jose::TotpParams::authenticator_default())
    }

    /// The one-sided TOTP drift tolerance in time-steps (issue #69).
    #[must_use]
    pub fn totp_drift_steps(&self) -> u32 {
        self.inner.totp_drift_steps
    }

    /// The number of one-time recovery codes minted at MFA enrollment (issue #69).
    #[must_use]
    pub fn totp_recovery_code_count(&self) -> u32 {
        self.inner.totp_recovery_code_count
    }

    /// Whether MFA enrollment is required after primary authentication (issue #69).
    #[must_use]
    pub fn mfa_required(&self) -> bool {
        self.inner.mfa_required
    }

    /// The per-tenant factor order (issue #69): the second-factor kinds offered or
    /// required first, honored by the factor-orchestration plan.
    #[must_use]
    pub fn mfa_factor_order(&self) -> &[String] {
        &self.inner.mfa_factor_order
    }

    /// The DEPLOYMENT-level `acr` order for step-up comparison (RFC 9470, issue #72),
    /// weakest first. Resolved once from `OidcConfig` at construction and applied across
    /// the deployment (NOT per (tenant, environment) today; per-tenant resolution is a
    /// future enhancement). Falls back to the default credential-ladder order when the
    /// configured list is empty, so a comparison always has a ranking to use.
    #[must_use]
    pub fn acr_order(&self) -> Vec<String> {
        if self.inner.acr_order.is_empty() {
            crate::step_up::default_acr_order()
        } else {
            self.inner.acr_order.clone()
        }
    }

    /// The shared per-environment issuer registry: the ONE holder of every
    /// environment's signing keys, algorithm policy, and salt. The JWKS/discovery
    /// serving reads the SAME `Arc`, so a signed `kid` cannot diverge from the
    /// published key set.
    #[must_use]
    pub fn issuers(&self) -> &Arc<IssuerRegistry> {
        &self.inner.issuers
    }

    /// Resolve the live issuer entry for `scope` (its key set, algorithm policy,
    /// and salt), loading and caching it from the store on the first access when
    /// the registry is store-backed.
    ///
    /// `None` when the environment has no provisioned signing key (fail closed) or
    /// names a cross-tenant environment (the RLS-scoped load yields no rows). The
    /// caller resolves this ONCE at the handler top, then hands the borrowed signer
    /// and policy into the pure, synchronous mint functions.
    pub(crate) async fn issuer_entry(&self, scope: &Scope) -> Option<Arc<IssuerEntry>> {
        self.inner.issuers.entry_for(scope).await
    }

    /// Resolve the environment's TYPED guardrail set for `scope` (issue #42),
    /// derived from its kind through the same shared registry the mint reads.
    ///
    /// `None` when the environment has no provisioned issuer entry (unprovisioned or
    /// cross-tenant, which fails closed). The client-registration paths consult this
    /// to enforce the two-class asymmetry (an `http` loopback redirect is
    /// registrable in a `dev`/`staging` environment and rejected in `prod`) without
    /// reading the environments level table the data plane has no grant on.
    pub(crate) async fn environment_guardrails(&self, scope: &Scope) -> Option<GuardrailSet> {
        self.issuer_entry(scope)
            .await
            .map(|entry| entry.guardrails())
    }

    /// The environment banner label to show on hosted pages for `scope` (issue #42),
    /// or `None` for a production environment (which shows no banner and is
    /// search-indexable). A non-production environment returns its guardrail class
    /// label (`non-production`), and the hosted pages additionally mark themselves
    /// `noindex`. `None` also when the environment has no provisioned issuer entry.
    pub(crate) async fn environment_banner(&self, scope: &Scope) -> Option<&'static str> {
        let guardrails = self.environment_guardrails(scope).await?;
        guardrails
            .show_environment_banner
            .then(|| guardrails.class.as_str())
    }

    /// Whether this environment copies the scope-derived claims into the ID token
    /// (issue #15). The spec-conform default is `false`: scope claims live at
    /// `UserInfo` and the ID token stays lean. When `true`, the token endpoint also
    /// places those claims in the ID token (a documented non-conform legacy mode).
    #[must_use]
    pub fn conform_id_token_claims(&self) -> bool {
        self.inner.conform_id_token_claims
    }

    /// Whether `origin` is a registered SPA origin allowed to call `UserInfo`
    /// cross-origin (issue #15). Matched EXACTLY; an unregistered origin is denied
    /// (no CORS headers). Used ONLY by the `UserInfo` endpoint.
    #[must_use]
    pub fn is_registered_spa_origin(&self, origin: &str) -> bool {
        self.inner.userinfo_cors_origins.contains(origin)
    }

    /// Whether `response_type` is enabled in this environment (issue #17). `code`
    /// is always enabled; the legacy types (`id_token`, `code id_token`, `none`)
    /// are DISABLED by default and turned on only by explicit per-environment
    /// config. A requested legacy type that is not enabled is
    /// `unsupported_response_type`. The token-bearing types cannot even be passed
    /// here: they are unrepresentable in [`ResponseType`].
    #[must_use]
    pub fn response_type_enabled(&self, response_type: ResponseType) -> bool {
        match response_type {
            ResponseType::Code => true,
            ResponseType::IdToken => self.inner.enable_response_type_id_token,
            ResponseType::CodeIdToken => self.inner.enable_response_type_code_id_token,
            ResponseType::None => self.inner.enable_response_type_none,
        }
    }

    /// Whether the `form_post` response mode is enabled in this environment (issue
    /// #17). Disabled by default; a client may request `response_mode=form_post`
    /// only where an operator has explicitly enabled it.
    #[must_use]
    pub fn form_post_enabled(&self) -> bool {
        self.inner.enable_response_mode_form_post
    }

    /// Whether `mode` is enabled for a client to REQUEST explicitly in this
    /// environment (issue #17). `query` is always available; `fragment` becomes
    /// available when a front-channel response type is enabled (it is that
    /// feature's default and only-useful mode); `form_post` is gated on its own
    /// toggle. This governs what a client may ask for and what discovery
    /// advertises; the error path may still ENCODE a redirect in any mode.
    #[must_use]
    pub fn response_mode_enabled(&self, mode: ResponseMode) -> bool {
        match mode {
            ResponseMode::Query => true,
            ResponseMode::Fragment => {
                self.inner.enable_response_type_id_token
                    || self.inner.enable_response_type_code_id_token
            }
            ResponseMode::FormPost => self.inner.enable_response_mode_form_post,
        }
    }

    /// Verify a presented access token (a compact `at+jwt` JWS) against the
    /// environment's signing keys, the per-environment issuer, and `audience` (the
    /// client the grant was resolved to), using the environment clock seam.
    ///
    /// This is the cryptographic half of `UserInfo`'s token check: it authenticates
    /// the token and enforces `exp`/`iss`/`aud` through the ONE hardened verify
    /// path ([`ironauth_jose::verify`]). The revocation and IDOR half is the
    /// scope-bound store resolution the caller performs alongside it. Returns
    /// `Err(())` when the environment has no keys, or the token fails to verify
    /// (bad signature, expired, wrong issuer or audience, malformed); the caller
    /// maps that to the RFC 6750 `invalid_token` challenge.
    ///
    /// # Errors
    ///
    /// `Err(())` if no signing key is provisioned for the scope's environment, or
    /// the token does not verify under the built policy.
    pub(crate) async fn verify_access_token(
        &self,
        scope: &Scope,
        audience: &str,
        token: &str,
    ) -> Result<VerifiedToken, ()> {
        // Resolve the ONE registry entry (the same keys the JWKS serves); an
        // unprovisioned or cross-tenant environment has none, and fails closed.
        let entry = self.issuer_entry(scope).await.ok_or(())?;
        // The keys published at `now` are exactly those a currently-valid token
        // could have been signed by (the rotation retention rule); a token's `kid`
        // only selects among these, never introduces one (issue #9's verify path).
        let keys = entry.keyset().published_signing_keys(self.now());
        if keys.is_empty() {
            return Err(());
        }
        let trusted: Vec<TrustedKey> = keys
            .iter()
            .filter_map(|key| key.verifying_key().ok())
            .collect();
        if trusted.is_empty() {
            return Err(());
        }
        // The allowlist is exactly the algorithms those published keys sign with.
        let mut algorithms: Vec<JwsAlgorithm> = Vec::new();
        for key in &keys {
            if !algorithms.contains(&key.algorithm()) {
                algorithms.push(key.algorithm());
            }
        }
        let issuer = self.issuer_for(scope);
        let policy = VerificationPolicy::new(algorithms, trusted, issuer, audience.to_owned())
            .map_err(|_| ())?;
        verify(token, &policy, self.inner.env.clock()).map_err(|_| ())
    }

    /// Verify an RP-Initiated Logout `id_token_hint` (issue #33): an id token THIS OP
    /// minted, presented at `end_session` ONLY to identify the session to end.
    ///
    /// It is verified through the SAME hardened [`ironauth_jose::verify`] path as an
    /// access token, against the environment's published signing keys, the
    /// per-environment issuer, and `audience` (the client the hint names in `aud`), with
    /// exactly ONE relaxation: [`VerificationPolicy::allow_expired`] accepts a PAST
    /// `exp`. That is mandated by the RP-Initiated Logout spec (a logout hint is
    /// routinely stale) and confers no access, since the hint only NAMES a session. A
    /// rotated-out key still verifies because `published_signing_keys` keeps the
    /// verification-retained keys. Every OTHER check stays: the signature over the
    /// environment's own keys, the algorithm allowlist, the exact issuer, the exact
    /// audience, `nbf`, and `iat`. A hint signed by a FOREIGN issuer, or tampered, fails
    /// the signature or issuer check and returns `Err(())`, so a logout never acts on an
    /// unverifiable or foreign hint.
    ///
    /// # Errors
    ///
    /// `Err(())` if no signing key is provisioned for the scope's environment, or the
    /// hint does not verify under the built policy (bad signature, wrong issuer or
    /// audience, non-allowlisted algorithm, missing `exp`, future `nbf`/`iat`,
    /// malformed).
    pub(crate) async fn verify_logout_hint(
        &self,
        scope: &Scope,
        audience: &str,
        token: &str,
    ) -> Result<VerifiedToken, ()> {
        let entry = self.issuer_entry(scope).await.ok_or(())?;
        let keys = entry.keyset().published_signing_keys(self.now());
        if keys.is_empty() {
            return Err(());
        }
        let trusted: Vec<TrustedKey> = keys
            .iter()
            .filter_map(|key| key.verifying_key().ok())
            .collect();
        if trusted.is_empty() {
            return Err(());
        }
        let mut algorithms: Vec<JwsAlgorithm> = Vec::new();
        for key in &keys {
            if !algorithms.contains(&key.algorithm()) {
                algorithms.push(key.algorithm());
            }
        }
        let issuer = self.issuer_for(scope);
        let policy = VerificationPolicy::new(algorithms, trusted, issuer, audience.to_owned())
            .map_err(|_| ())?
            .allow_expired(true);
        verify(token, &policy, self.inner.env.clock()).map_err(|_| ())
    }
}

impl std::fmt::Debug for OidcState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcState")
            .field("issuer_base", &self.inner.issuer_base)
            .field("code_ttl", &self.inner.code_ttl)
            .field("access_token_ttl", &self.inner.access_token_ttl)
            .field("reuse_grace", &self.inner.reuse_grace)
            .finish_non_exhaustive()
    }
}

/// The web origin (`scheme://host[:port]`) of a URL, in a canonical form, or
/// [`None`] when it has no `scheme://authority`. The path, query, and fragment are
/// dropped, so a base URL that carries a path (`https://host/base`) still yields the
/// bare origin an `Origin` header would (`https://host`).
///
/// The result is NORMALIZED so it compares byte-exact against a browser-sent
/// `Origin` (issue #196): the scheme and host are lowercased and the default port is
/// dropped (`:443` for https, `:80` for http). A `public_url` configured with an
/// uppercase host or an explicit default port therefore still matches the
/// `Origin` a browser normalizes and sends, instead of falsely rejecting every
/// legitimate same-origin login/consent/register POST. This normalization never
/// produces a false ALLOW: a genuinely different scheme, host, or non-default port
/// still differs after it. Used to derive this deployment's own origin from
/// `issuer_base` for the CSRF Origin allowlist, and to canonicalize the incoming
/// `Origin` before the comparison.
/// The effective WebAuthn relying party for a ceremony (issue #65): the RP ID the
/// authenticator scopes the credential to, and the origin(s) a ceremony may be
/// invoked from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebauthnRelyingParty {
    /// The relying party id (the origin host or a configured parent domain).
    pub rp_id: String,
    /// The origins allowed for this environment (`scheme://host[:port]`).
    pub origins: Vec<String>,
}

/// The host of an absolute URL, dropping the scheme and any port (issue #65). Used
/// to derive the default WebAuthn RP ID from the serving origin.
pub(crate) fn host_of(url: &str) -> Option<String> {
    let origin = origin_of(url)?;
    let authority = origin.split_once("://")?.1;
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => authority,
    };
    Some(host.to_owned())
}

pub(crate) fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    // The authority ends at the first path/query/fragment delimiter.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    // Lowercase the whole authority (host casing is insignificant); a port, if
    // present, is decimal ASCII and unaffected by lowercasing.
    let authority = authority.to_ascii_lowercase();
    // Drop an explicit default port so `host:443`/`host:80` match the bare `host` a
    // browser sends. `rsplit_once(':')` isolates the port even for a bracketed IPv6
    // literal (`[::1]:443`); a portless IPv6 literal (`[::1]`) never has a trailing
    // `:443`/`:80` tail, so nothing is stripped from it.
    let authority = match authority.rsplit_once(':') {
        Some((host, port)) if is_default_port(&scheme, port) => host,
        _ => &authority,
    };
    Some(format!("{scheme}://{authority}"))
}

/// Whether `port` is the default port for `scheme` (both already lowercased), so it
/// may be dropped from a canonical origin.
fn is_default_port(scheme: &str, port: &str) -> bool {
    matches!((scheme, port), ("https", "443") | ("http", "80"))
}

/// Map the config-layer access-token format onto the store-layer one (issue #29).
/// Two enums (one per crate boundary) keep the config contract and the store type
/// independent; this is the single crossing point.
fn map_token_format(format: ironauth_config::TokenFormat) -> TokenFormat {
    match format {
        ironauth_config::TokenFormat::AtJwt => TokenFormat::AtJwt,
        ironauth_config::TokenFormat::Opaque => TokenFormat::Opaque,
    }
}

/// Keep the escalation with the LARGER delay (issue #64): the binding layer is the one
/// asking the client to wait the longest, so the response reports the limit that bites
/// first.
fn max_escalation(
    current: Option<(u64, std::time::Duration)>,
    count: u64,
    delay: std::time::Duration,
) -> (u64, std::time::Duration) {
    match current {
        Some((existing_count, existing_delay)) if existing_delay >= delay => {
            (existing_count, existing_delay)
        }
        _ => (count, delay),
    }
}

#[cfg(test)]
mod tests {
    use super::origin_of;

    #[test]
    fn origin_of_keeps_scheme_and_authority_and_drops_the_path() {
        assert_eq!(
            origin_of("https://issuer.test").as_deref(),
            Some("https://issuer.test")
        );
        // A base URL with a path or a NON-default port still yields the bare origin,
        // port preserved.
        assert_eq!(
            origin_of("https://issuer.test:8443/base/path").as_deref(),
            Some("https://issuer.test:8443")
        );
        assert_eq!(
            origin_of("http://127.0.0.1:9000/").as_deref(),
            Some("http://127.0.0.1:9000")
        );
        // Malformed bases yield no origin (the caller then falls back to the
        // Sec-Fetch-Site rule alone).
        assert_eq!(origin_of("not-a-url"), None);
        assert_eq!(origin_of("://no-scheme"), None);
        assert_eq!(origin_of("https://"), None);
    }

    #[test]
    fn origin_of_normalizes_case_and_the_default_port() {
        // An uppercase scheme/host and an explicit DEFAULT port all normalize to the
        // bare lowercase origin a browser sends, so the CSRF comparison does not
        // falsely reject a legitimate same-origin POST (issue #196).
        assert_eq!(
            origin_of("https://Issuer.test:443").as_deref(),
            Some("https://issuer.test")
        );
        assert_eq!(
            origin_of("HTTPS://Issuer.Test/base").as_deref(),
            Some("https://issuer.test")
        );
        assert_eq!(
            origin_of("http://Host.test:80/").as_deref(),
            Some("http://host.test")
        );
        // A NON-default port is significant and stays (never a false allow): a
        // default port on the OTHER scheme is not a default and is kept too.
        assert_eq!(
            origin_of("https://issuer.test:8443").as_deref(),
            Some("https://issuer.test:8443")
        );
        assert_eq!(
            origin_of("https://issuer.test:80").as_deref(),
            Some("https://issuer.test:80")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bounded_inline_caps_concurrent_inline_hashes() {
        // Issue #62 MEDIUM-3: the no-pool fallback bounds CONCURRENT inline hashes
        // with a semaphore, so a flood cannot pin the whole tokio blocking pool
        // (~512 threads). Drive many concurrent jobs through a cap-2 semaphore and
        // assert the observed concurrency never exceeds the cap. Without the
        // semaphore the observed maximum would climb to the job count.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cap = 2;
        let sem = std::sync::Arc::new(super::Semaphore::new(cap));
        let current = std::sync::Arc::new(AtomicUsize::new(0));
        let observed_max = std::sync::Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..12 {
            let sem = std::sync::Arc::clone(&sem);
            let current = std::sync::Arc::clone(&current);
            let observed_max = std::sync::Arc::clone(&observed_max);
            handles.push(tokio::spawn(async move {
                super::bounded_inline_on(&sem, move || {
                    let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                    observed_max.fetch_max(now, Ordering::SeqCst);
                    // Hold the permit long enough to overlap with the other jobs.
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    current.fetch_sub(1, Ordering::SeqCst);
                })
                .await
                .expect("bounded inline runs");
            }));
        }
        for handle in handles {
            handle.await.expect("task");
        }

        let peak = observed_max.load(Ordering::SeqCst);
        assert!(
            peak >= 1 && peak <= cap,
            "concurrent inline hashes stayed within the cap ({cap}); observed peak {peak}"
        );
        assert_eq!(
            current.load(Ordering::SeqCst),
            0,
            "every permit was released"
        );
    }
}
