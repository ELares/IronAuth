// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shared handler state for the OIDC provider.
//!
//! [`OidcState`] carries the data-plane [`Store`] (which in production
//! authenticates as the least-privilege `ironauth_app` role), the environment
//! seam, the per-environment signing keys, the issuer base, and the configured
//! code and access-token lifetimes. It is the axum router state, so every handler
//! reaches it, and it is cheap to clone (everything lives behind one `Arc`).
//!
//! Issuers are PER ENVIRONMENT: [`OidcState::issuer_for`] derives a distinct
//! issuer string from the `(tenant, environment)` scope, so a token minted in one
//! environment carries an issuer no other environment shares. The signing key is
//! likewise selected per environment from the [`EnvironmentKeyStore`], so moving a
//! client between environments is a configuration flip, not a key regeneration.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ironauth_config::OidcConfig;
use ironauth_env::Env;
use ironauth_jose::{
    EnvironmentKeyStore, JwsAlgorithm, SigningKey, TrustedKey, VerificationPolicy, VerifiedToken,
    verify,
};
use ironauth_store::{EnvironmentId, Scope, Store};

use crate::subject::{PairwiseSalt, SubjectCache, SubjectConfig};

/// Cheaply cloneable state shared by every OIDC handler.
#[derive(Clone)]
pub struct OidcState {
    inner: Arc<Inner>,
}

struct Inner {
    store: Store,
    env: Env,
    keys: EnvironmentKeyStore<EnvironmentId>,
    issuer_base: String,
    code_ttl: Duration,
    access_token_ttl: Duration,
    reuse_grace: Duration,
    session_ttl: Duration,
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
    // The one shared subject-derivation cache. The surface that emits a `sub` (the
    // ID token today, and `UserInfo`/introspection once they land) resolves it
    // through this cache; because it is a single shared derivation, any two
    // surfaces that call it agree, so a pairwise subject cannot diverge between
    // them. The cache partitions by the per-environment salt, keeping environments
    // isolated.
    subjects: SubjectCache,
}

impl OidcState {
    /// Build the OIDC state.
    ///
    /// In production `store` MUST authenticate as `ironauth_app` (the data-plane
    /// role), so the forced row-level-security backstop applies beneath the
    /// repository layer. `keys` holds one or more signing keys per environment;
    /// `issuer_base` is the deployment's externally visible base URL (from
    /// `server.public_url`), which the per-environment issuer is derived from. The
    /// lifetimes come from [`OidcConfig`] (already validated non-zero and bounded).
    #[must_use]
    pub fn new(
        store: Store,
        env: Env,
        keys: EnvironmentKeyStore<EnvironmentId>,
        config: &OidcConfig,
        issuer_base: impl Into<String>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                env,
                keys,
                issuer_base: issuer_base.into(),
                code_ttl: Duration::from_secs(config.authorization_code_ttl_secs),
                access_token_ttl: Duration::from_secs(config.access_token_ttl_secs),
                reuse_grace: Duration::from_secs(config.reuse_grace_secs),
                session_ttl: Duration::from_secs(config.session_ttl_secs),
                require_pkce_for_confidential: config.require_pkce_for_confidential_clients,
                conform_id_token_claims: config.conform_id_token_claims,
                userinfo_cors_origins: config.userinfo_cors_origins.iter().cloned().collect(),
                subjects: SubjectCache::new(),
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

    /// The configured reuse grace window for an already-consumed code. A second
    /// presentation within this window is a benign retry (no grant-chain revoke);
    /// beyond it, a genuine reuse that revokes the chain.
    #[must_use]
    pub fn reuse_grace(&self) -> Duration {
        self.inner.reuse_grace
    }

    /// The configured bootstrap session lifetime (issue #20).
    #[must_use]
    pub fn session_ttl(&self) -> Duration {
        self.inner.session_ttl
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

    /// The default signing key for `environment`, or `None` if the environment
    /// has no provisioned key. The first key inserted for the environment is the
    /// default (stable across a same-algorithm rotation).
    #[must_use]
    pub fn signer_for(&self, environment: &EnvironmentId) -> Option<&SigningKey> {
        self.inner.keys.keys_for(environment).first()
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
    pub(crate) fn verify_access_token(
        &self,
        scope: &Scope,
        audience: &str,
        token: &str,
    ) -> Result<VerifiedToken, ()> {
        let environment = scope.environment();
        let keys = self.inner.keys.keys_for(&environment);
        if keys.is_empty() {
            return Err(());
        }
        // Every current signing key is a trusted verifying key; a token's `kid`
        // only selects among these, never introduces one (issue #9's verify path).
        let trusted: Vec<TrustedKey> = keys
            .iter()
            .filter_map(|key| key.verifying_key().ok())
            .collect();
        if trusted.is_empty() {
            return Err(());
        }
        // The allowlist is exactly the algorithms the environment's keys sign with.
        let mut algorithms: Vec<JwsAlgorithm> = Vec::new();
        for key in keys {
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
