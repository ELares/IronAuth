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
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ironauth_config::{ClientAssertionAudience, OidcConfig, RegistrationMode};
use ironauth_env::Env;
use ironauth_jose::{JwsAlgorithm, TrustedKey, VerificationPolicy, VerifiedToken, verify};
use ironauth_store::{Scope, Store, TokenFormat};

use crate::client_keys::ClientKeyResolver;
use crate::issuer::{IssuerEntry, IssuerRegistry};
use crate::registry::{ResponseMode, ResponseType};
use crate::subject::{PairwiseSalt, SubjectCache, SubjectConfig};
use crate::tokens::AccessTokenTarget;

/// Cheaply cloneable state shared by every OIDC handler.
#[derive(Clone)]
pub struct OidcState {
    inner: Arc<Inner>,
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
    session_ttl: Duration,
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
            }),
        }
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

    /// Resolve the access-token target (audience, format, lifetime) for an exchange
    /// (issue #29): the SELECTION seam issue #28 feeds.
    ///
    /// When `resource` names a registered resource server's `audience` in this
    /// scope, its `token_format` and `access_token_ttl_secs` (falling back to the
    /// environment default lifetime when the resource server left it unset) apply,
    /// and the token's `aud` becomes that resource server's audience. Otherwise the
    /// environment default applies: the token's `aud` is the `client_id` (so
    /// `UserInfo`'s `aud == client` check keeps working), the format is the
    /// environment default, and the lifetime is the environment access-token
    /// lifetime.
    ///
    /// The full RFC 8707 `resource` REQUEST-parameter wiring is issue #28; today
    /// the token endpoint passes `resource = None`, so this resolves to the
    /// environment default. Taking the resolved audience here (rather than the
    /// request) is what lets #28 feed the `resource` parameter without reshaping
    /// the pure mint. A store read failure while looking up a resource server is
    /// treated as "no matching resource server" (the environment default applies),
    /// so a transient database blip never fails an otherwise-valid exchange or
    /// silently changes the audience.
    pub async fn resolve_access_token_target(
        &self,
        scope: &Scope,
        resource: Option<&str>,
        client_id: &str,
    ) -> AccessTokenTarget {
        if let Some(audience) = resource {
            if let Ok(Some(server)) = self
                .inner
                .store
                .scoped(*scope)
                .resource_servers()
                .by_audience(audience)
                .await
            {
                let ttl = server
                    .access_token_ttl_secs
                    .and_then(|secs| u64::try_from(secs).ok())
                    .map_or(self.inner.access_token_ttl, Duration::from_secs);
                return AccessTokenTarget {
                    audience: server.audience,
                    format: server.token_format,
                    ttl,
                };
            }
        }
        AccessTokenTarget {
            audience: client_id.to_owned(),
            format: self.inner.default_access_token_format,
            ttl: self.inner.access_token_ttl,
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

    /// The configured bootstrap session lifetime (issue #20).
    #[must_use]
    pub fn session_ttl(&self) -> Duration {
        self.inner.session_ttl
    }

    /// The configured pushed-authorization-request `request_uri` lifetime (RFC 9126,
    /// issue #27). A pushed request expires this long after it is pushed; validated
    /// non-zero and bounded by config.
    #[must_use]
    pub fn par_ttl(&self) -> Duration {
        self.inner.par_ttl
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
}
