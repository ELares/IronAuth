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

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ironauth_config::OidcConfig;
use ironauth_env::Env;
use ironauth_jose::{EnvironmentKeyStore, SigningKey};
use ironauth_store::{EnvironmentId, Scope, Store};

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
            }),
        }
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
