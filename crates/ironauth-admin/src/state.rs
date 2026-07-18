// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shared handler state and the credential-resolution logic.
//!
//! [`AdminState`] carries the control-plane [`Store`], the environment seam, the
//! resolved bootstrap operator token, and the page-size configuration. It is the
//! axum router state, so every handler and the [`crate::auth::Principal`]
//! extractor reach it.
//!
//! In production the store's pool authenticates as the least-privilege
//! `ironauth_control` role (a distinct credential class from the data-plane
//! role), so the `management_credentials` FORCE row-level-security backstop
//! applies beneath the repository layer. The binary selects that DSN from
//! `admin.control_database_url`; in `dev_mode` it may fall back to
//! `database.url`, in which case the role separation and the FORCE-RLS backstop
//! are not enforced (a startup warning says so). See `crate::management_router`
//! and `docs/adr/0005-management-api.md`.

use std::sync::Arc;
use std::time::SystemTime;

use ironauth_config::{AdminConfig, SecretError, SecretString};
use ironauth_env::Env;
use ironauth_store::{
    ActorRef, MANAGEMENT_LIST_HARD_CAP, ManagementKeyId, OperatorId, Scope, ServiceId, Store,
};

use crate::auth::Principal;
use crate::error::ApiError;
use crate::hash::{constant_time_eq, sha256_hex};

/// The seed bytes of the well-known bootstrap identities. The bootstrap operator
/// (operator plane) and its audit service-actor are fixed, well-known identities
/// so they are stable across restarts; the full operator-plane credential class
/// with minted identities lands in M5.
const BOOTSTRAP_SEED: [u8; 16] = [0_u8; 16];

/// The display name recorded for the bootstrap operator row.
pub(crate) const BOOTSTRAP_OPERATOR_DISPLAY_NAME: &str = "IronAuth bootstrap operator";

/// Cheaply cloneable state shared by every management handler.
#[derive(Clone)]
pub struct AdminState {
    inner: Arc<Inner>,
}

// The admin state aggregates several independent experimental feature-gate flags (sudo mode,
// signup quarantine, advanced recovery); each is a distinct on/off surface arm, so they read
// clearer as separate bools than folded into an enum.
#[allow(clippy::struct_excessive_bools)]
struct Inner {
    store: Store,
    env: Env,
    // Wrapped in SecretString so it cannot leak through Debug/logs; the value is
    // reachable only via `.expose()` at the constant-time comparison site.
    bootstrap_operator_token: Option<SecretString>,
    bootstrap_operator_id: OperatorId,
    bootstrap_operator_actor: ActorRef,
    default_page_size: u32,
    max_page_size: u32,
    // The operator's configured data-residency region set (issue #46). A tenant's
    // home_region and a per-environment region pin must be one of these; empty means
    // residency pinning is unavailable and any pin on a create is refused.
    allowed_regions: Vec<String>,
    // The tenant-offboarding retention window in seconds (issue #46): the grace
    // period a soft-deleted tenant can be restored within.
    offboarding_retention_secs: u64,
    // Whether the outbound lazy-migration credential-verification endpoint is
    // enabled (issue #58). Off by default; the endpoint is a uniform not-found when
    // this is false.
    outbound_verification_enabled: bool,
    // The resolved shared bearer token a successor system presents to the outbound
    // verification endpoint (issue #58), or None when unset. Wrapped in SecretString
    // so it cannot leak through Debug/logs; reachable only via `.expose()` at the
    // constant-time comparison site. A distinct credential from the operator token
    // and management keys: it authorizes ONLY that one endpoint.
    outbound_verification_token: Option<SecretString>,
    // The single (tenant, environment) the outbound verification endpoint is
    // authorized for (issue #58), as the scoped-id strings that appear in the request
    // path. Both must be set and must match the request's path scope, or the endpoint
    // is a uniform not-found: the shared token can only ever verify credentials in its
    // one configured environment, never across tenants. None (either unset) fails
    // closed (matches nothing).
    outbound_verification_tenant: Option<String>,
    outbound_verification_environment: Option<String>,
    // The inbound lazy-migration hook (issue #56), shared with the OIDC data plane in the
    // same process when one is configured. Held so the management-plane migration-progress
    // endpoint can report THIS node's circuit-breaker state alongside the DB progress
    // counts. `None` when no hook is configured, or on a node that does not run the data
    // plane; the endpoint then reports progress with no breaker block.
    migration_hook: Option<Arc<ironauth_oidc::LazyMigrationHook>>,
    // The federation runtime (issue #76), shared with the OIDC data plane in the same process
    // when federation is enabled. Held so the management-plane per-connector health-diagnostics
    // read reports THIS node's live connector health (the SAME in-memory registry the login path
    // records into). `None` when federation is disabled or on a node that does not run the data
    // plane; the health read then reports every connector as never-exercised.
    federation: Option<Arc<ironauth_oidc::FederationRuntime>>,
    // Admin sudo mode (session privilege separation, issue #73): whether admin
    // mutations require a recent recorded re-authentication, and the freshness window in
    // seconds. Off by default; when off the mutation guard is a no-op and the admin
    // surface behaves exactly as before.
    sudo_mode_enabled: bool,
    sudo_mode_window_secs: u64,
    // Whether the experimental signup fraud-review-queue surface is armed (issue #82, PR 2).
    // Resolved by the boot path from the strict config feature ladder (the
    // `signup-quarantine` experimental feature enabled AND acked at the exact version) and
    // installed via the builder, NOT an AdminConfig toggle, so an operator cannot arm the
    // review-queue endpoints outside the experimental ack gate. Off by default; when off
    // every signup-quarantine review-queue endpoint answers a uniform 404.
    signup_quarantine_enabled: bool,
    // Whether the experimental advanced-recovery-modes surface is armed (issue #82, PR 3).
    // Resolved by the boot path from the strict config feature ladder (the
    // `advanced-recovery` experimental feature enabled AND acked at the exact version) and
    // installed via the builder, NOT an AdminConfig toggle, so an operator cannot arm the
    // recovery-approval review-queue endpoints outside the experimental ack gate. Off by
    // default; when off every recovery-approval endpoint answers a uniform 404.
    advanced_recovery_enabled: bool,
}

impl AdminState {
    /// Build the management state from a control-plane store, the environment
    /// seam, and the admin config.
    ///
    /// In production the `store` MUST authenticate as `ironauth_control`, not
    /// `ironauth_app`; the binary selects that DSN (see
    /// [`crate::management_router`]). A `dev_mode` fallback to `database.url` is
    /// permitted with the role separation not enforced.
    ///
    /// # Errors
    ///
    /// [`StateError::Secret`] if the bootstrap operator token secret cannot be
    /// resolved from its file or environment-variable source;
    /// [`StateError::EmptyToken`] if it resolves to an empty value (which would
    /// let an empty `Authorization: Bearer ` authenticate as the operator).
    pub fn new(store: Store, env: Env, config: &AdminConfig) -> Result<Self, StateError> {
        let bootstrap_operator_token = match &config.bootstrap_operator_token {
            Some(secret) => {
                let resolved = secret.resolve().map_err(StateError::Secret)?;
                // Presented bearer tokens are trimmed before comparison, so trim
                // the configured token to match, and fail closed if it is empty
                // or only whitespace. An empty configured token and an empty
                // presented bearer token compare equal in constant time, so an
                // empty configured token would authenticate anyone. Refuse to
                // build the state at all rather than enable that, and refuse
                // loudly at startup rather than silently disabling the operator
                // plane on a whitespace-only value.
                let trimmed = resolved.expose().trim();
                if trimmed.is_empty() {
                    return Err(StateError::EmptyToken);
                }
                Some(SecretString::new(trimmed))
            }
            None => None,
        };
        // Page sizes: a non-zero floor, the default never above the max, and the
        // max never above the store's hard cap. Config load already rejects a
        // configured max above the cap; clamping here is defense in depth for a
        // state built directly (for example in a test).
        let hard_cap = u32::try_from(MANAGEMENT_LIST_HARD_CAP).unwrap_or(u32::MAX);
        let max_page_size = config.max_page_size.max(1).min(hard_cap);
        let default_page_size = config.default_page_size.max(1).min(max_page_size);
        // The outbound verification token (issue #58) is resolved once here and, like
        // the operator token, trimmed and refused when empty so an empty configured
        // token can never match an empty presented bearer.
        let outbound_verification_token = match &config.outbound_verification_token {
            Some(secret) => {
                let resolved = secret.resolve().map_err(StateError::Secret)?;
                let trimmed = resolved.expose().trim();
                if trimmed.is_empty() {
                    return Err(StateError::EmptyToken);
                }
                Some(SecretString::new(trimmed))
            }
            None => None,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                store,
                env,
                bootstrap_operator_token,
                bootstrap_operator_id: OperatorId::from_seed_bytes(BOOTSTRAP_SEED),
                bootstrap_operator_actor: ActorRef::service(ServiceId::from_seed_bytes(
                    BOOTSTRAP_SEED,
                )),
                default_page_size,
                max_page_size,
                allowed_regions: config.allowed_regions.clone(),
                offboarding_retention_secs: config.offboarding_retention_secs,
                outbound_verification_enabled: config.outbound_verification_enabled,
                outbound_verification_token,
                outbound_verification_tenant: config
                    .outbound_verification_tenant
                    .clone()
                    .filter(|value| !value.trim().is_empty()),
                outbound_verification_environment: config
                    .outbound_verification_environment
                    .clone()
                    .filter(|value| !value.trim().is_empty()),
                migration_hook: None,
                federation: None,
                sudo_mode_enabled: config.sudo_mode_enabled,
                sudo_mode_window_secs: config.sudo_mode_window_secs,
                signup_quarantine_enabled: false,
                advanced_recovery_enabled: false,
            }),
        })
    }

    /// Arm the experimental signup fraud-review-queue admin surface (issue #82, PR 2).
    ///
    /// The boot path is the ONLY caller: it resolves `enabled` from the strict config
    /// feature ladder (the `signup-quarantine` experimental feature enabled AND acknowledged
    /// at the exact version) and installs the SAME bool it installs on the OIDC data plane. A
    /// builder rather than an `AdminConfig` field precisely so an operator cannot arm the
    /// review-queue endpoints from a plain config toggle and bypass the experimental acknowledgment
    /// gate. When false (the default), every review-queue endpoint answers a uniform 404.
    #[must_use]
    pub fn with_signup_quarantine_enabled(mut self, enabled: bool) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.signup_quarantine_enabled = enabled;
        }
        self
    }

    /// Whether the experimental signup fraud-review-queue admin surface is armed (issue #82,
    /// PR 2). Every review-queue handler's first action is to return a uniform 404 when this
    /// is false.
    #[must_use]
    pub fn signup_quarantine_enabled(&self) -> bool {
        self.inner.signup_quarantine_enabled
    }

    /// Arm the experimental advanced-recovery-modes admin surface (issue #82, PR 3).
    ///
    /// The boot path is the ONLY caller: it resolves `enabled` from the strict config feature
    /// ladder (the `advanced-recovery` experimental feature enabled AND acknowledged at the
    /// exact version) and installs the SAME bool it installs on the OIDC data plane. A builder
    /// rather than an `AdminConfig` field precisely so an operator cannot arm the
    /// recovery-approval review-queue endpoints from a plain config toggle and bypass the
    /// experimental acknowledgment gate. When false (the default), every recovery-approval
    /// endpoint answers a uniform 404.
    #[must_use]
    pub fn with_advanced_recovery_enabled(mut self, enabled: bool) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.advanced_recovery_enabled = enabled;
        }
        self
    }

    /// Whether the experimental advanced-recovery-modes admin surface is armed (issue #82,
    /// PR 3). Every recovery-approval handler's first action is to return a uniform 404 when
    /// this is false.
    #[must_use]
    pub fn advanced_recovery_enabled(&self) -> bool {
        self.inner.advanced_recovery_enabled
    }

    /// Share the inbound lazy-migration hook (issue #56) with the management plane, so the
    /// migration-progress endpoint can report this node's circuit-breaker state. The boot
    /// path installs the SAME `Arc` it installs on the OIDC data plane; with no hook
    /// installed the progress endpoint reports the DB counts and no breaker block. Kept a
    /// builder so the many admin tests need not stand a hook up.
    #[must_use]
    pub fn with_migration_hook(mut self, hook: Arc<ironauth_oidc::LazyMigrationHook>) -> Self {
        // The Arc<Inner> is not yet shared at construction time (the caller holds the sole
        // reference right after `new`), so this get_mut succeeds; if it ever did not, the
        // hook is simply not installed rather than panicking.
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.migration_hook = Some(hook);
        }
        self
    }

    /// This node's lazy-migration circuit-breaker state (issue #56), or `None` when no
    /// hook is installed on this node. Reported by the migration-progress endpoint.
    #[must_use]
    pub(crate) fn migration_breaker_state(&self) -> Option<ironauth_oidc::BreakerState> {
        self.inner
            .migration_hook
            .as_ref()
            .map(|hook| hook.breaker_state())
    }

    /// Share the federation runtime (issue #76) with the management plane, so the
    /// per-connector health-diagnostics read reports the live health the OIDC data plane
    /// records into. The boot path installs the SAME `Arc` it installs on the data plane; with
    /// no runtime installed the health read reports every connector as never-exercised. Kept a
    /// builder so the many admin tests need not stand a runtime up.
    #[must_use]
    pub fn with_federation(mut self, runtime: Arc<ironauth_oidc::FederationRuntime>) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.federation = Some(runtime);
        }
        self
    }

    /// This node's live health snapshot for one connector (issue #76), read against the admin
    /// clock seam, or `None` when no federation runtime is installed, the connector has never been
    /// exercised on this node, or its recorded health predates the current `fingerprint`.
    ///
    /// `fingerprint` is the connector's current definition version (its store row `updated_at`
    /// micros): passing it lets the read discount a record left by a PRIOR definition, so the
    /// health surface reflects a reconfiguration promptly instead of reporting a stale state.
    #[must_use]
    pub(crate) fn connector_health(
        &self,
        connector_id: &str,
        fingerprint: i64,
    ) -> Option<ironauth_oidc::ConnectorHealthSnapshot> {
        let now = self.inner.env.clock().now_utc();
        self.inner
            .federation
            .as_ref()?
            .health()
            .snapshot(now, connector_id, fingerprint)
    }

    /// Whether the outbound lazy-migration credential-verification endpoint is
    /// enabled (issue #58). Off by default; the endpoint is a uniform not-found when
    /// this is false, so exposing a credential oracle to a successor system is an
    /// explicit per-deployment opt-in.
    #[must_use]
    pub fn outbound_verification_enabled(&self) -> bool {
        self.inner.outbound_verification_enabled
    }

    /// Match a presented token against the configured outbound verification token
    /// (issue #58), in constant time. Returns `false` when no token is configured
    /// (fail closed: no token, no access), so enabling the endpoint without a token
    /// authorizes nobody.
    #[must_use]
    pub fn match_outbound_verification_token(&self, token: &str) -> bool {
        let Some(configured) = self.inner.outbound_verification_token.as_ref() else {
            return false;
        };
        let configured = configured.expose();
        if configured.is_empty() {
            return false;
        }
        constant_time_eq(token.as_bytes(), configured.as_bytes())
    }

    /// Whether the outbound verification endpoint is authorized for `scope` (issue
    /// #58): the request's path scope must equal the ONE configured
    /// `(tenant, environment)`. Returns `false` when either half is unset (fail
    /// closed: no configured scope, no access), so the shared token can only ever
    /// verify credentials in its one configured environment and a request to any
    /// other tenant or environment is a uniform not-found, never a cross-tenant
    /// oracle.
    #[must_use]
    pub fn outbound_verification_scope_allows(&self, scope: Scope) -> bool {
        let (Some(tenant), Some(environment)) = (
            self.inner.outbound_verification_tenant.as_deref(),
            self.inner.outbound_verification_environment.as_deref(),
        ) else {
            return false;
        };
        tenant == scope.tenant().to_string() && environment == scope.environment().to_string()
    }

    /// Whether `region` is in the operator's configured data-residency region set
    /// (issue #46). Always false when no region set is configured, so a residency
    /// pin can be recorded only against an explicitly allowed value. Governs BOTH a
    /// tenant's `home_region` and a per-environment `region` pin (the same set).
    #[must_use]
    pub fn region_is_allowed(&self, region: &str) -> bool {
        self.inner
            .allowed_regions
            .iter()
            .any(|allowed| allowed == region)
    }

    /// Whether `region` is a permitted tenant `home_region` (issue #46). An alias of
    /// [`AdminState::region_is_allowed`]: the tenant home region and the
    /// per-environment region pin validate against the same configured set.
    #[must_use]
    pub fn home_region_is_allowed(&self, region: &str) -> bool {
        self.region_is_allowed(region)
    }

    /// The configured tenant-offboarding retention window (issue #46): the grace
    /// period during which a soft-deleted tenant can be restored, after which the
    /// terminal hard delete is due. A tunable with a safe default (see
    /// [`ironauth_config::AdminConfig::offboarding_retention_secs`]).
    #[must_use]
    pub fn offboarding_retention(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.inner.offboarding_retention_secs)
    }

    /// Whether admin sudo mode (session privilege separation, issue #73) is active.
    /// When false, the admin mutation freshness guard is a no-op and the surface
    /// behaves exactly as before (the feature is fully inert when off).
    #[must_use]
    pub fn sudo_mode_enabled(&self) -> bool {
        self.inner.sudo_mode_enabled
    }

    /// The admin sudo re-authentication freshness window, in seconds (issue #73): how
    /// long a recorded elevation authorizes admin mutations before a fresh
    /// re-authentication is required.
    #[must_use]
    pub fn sudo_mode_window_secs(&self) -> u64 {
        self.inner.sudo_mode_window_secs
    }

    /// The control-plane store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// The environment seam (clock and entropy).
    #[must_use]
    pub fn env(&self) -> &Env {
        &self.inner.env
    }

    /// The default page size when a caller supplies no `limit`.
    #[must_use]
    pub fn default_page_size(&self) -> u32 {
        self.inner.default_page_size
    }

    /// The maximum page size any list endpoint returns.
    #[must_use]
    pub fn max_page_size(&self) -> u32 {
        self.inner.max_page_size
    }

    /// The well-known bootstrap operator id (the owner of tenants in M1).
    #[must_use]
    pub fn bootstrap_operator_id(&self) -> OperatorId {
        self.inner.bootstrap_operator_id
    }

    /// The current wall-clock time in microseconds since the Unix epoch, from the
    /// environment clock seam. Used so a pre-built response body, the stored row,
    /// and the pagination key all share one deterministic timestamp.
    #[must_use]
    pub fn now_unix_micros(&self) -> i64 {
        match self
            .inner
            .env
            .clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
        {
            Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
            Err(_) => 0,
        }
    }

    /// Match a presented token against the bootstrap operator token, in constant
    /// time. Returns the operator principal on a match.
    pub(crate) fn match_operator(&self, token: &str) -> Option<Principal> {
        let configured = self.inner.bootstrap_operator_token.as_ref()?.expose();
        // Defense in depth: an empty configured token never authenticates.
        // `AdminState::new` already refuses to build with an empty token, so this
        // guard is belt and suspenders against a future construction path.
        if configured.is_empty() {
            return None;
        }
        constant_time_eq(token.as_bytes(), configured.as_bytes()).then_some(Principal::Operator {
            actor: self.inner.bootstrap_operator_actor,
        })
    }

    /// Resolve a management-key token `<mak_id>.<secret>` to a principal.
    ///
    /// The scope is recovered from the token's id half (which declares it in the
    /// clear), then possession of the whole token is proven by its stored hash
    /// WITHIN that scope. Returns `None` for a token that is not a management key,
    /// is malformed, or does not match a live key (all surface as unauthorized).
    ///
    /// # Errors
    ///
    /// [`ApiError::Internal`] on a store failure.
    pub(crate) async fn authenticate_management_key(
        &self,
        token: &str,
    ) -> Result<Option<Principal>, ApiError> {
        if !token.starts_with("mak_") {
            return Ok(None);
        }
        let Some((id_part, _secret)) = token.split_once('.') else {
            return Ok(None);
        };
        let Ok(id) = ManagementKeyId::parse_declared_scope(id_part) else {
            return Ok(None);
        };
        let scope = id.scope();
        let hash = sha256_hex(token.as_bytes());
        if self
            .inner
            .store
            .management()
            .credentials(scope)
            .authenticate(&id, &hash)
            .await?
        {
            let actor = ActorRef::service(ServiceId::from_seed_bytes(id.unique_bytes()));
            Ok(Some(Principal::ManagementKey { scope, actor }))
        } else {
            Ok(None)
        }
    }
}

/// Why the management state could not be built.
#[derive(Debug)]
pub enum StateError {
    /// The bootstrap operator token secret could not be resolved.
    Secret(SecretError),
    /// The bootstrap operator token resolved to an EMPTY value (set-but-empty
    /// env var, empty file, or empty literal). Refused, because an empty
    /// configured token would authenticate an empty presented bearer token as
    /// the operator.
    EmptyToken,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::Secret(source) => {
                write!(f, "cannot resolve admin.bootstrap_operator_token: {source}")
            }
            StateError::EmptyToken => write!(
                f,
                "admin.bootstrap_operator_token resolved to an empty value; refusing to enable \
                 the operator plane"
            ),
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StateError::Secret(source) => Some(source),
            StateError::EmptyToken => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_config::Secret;
    use sqlx::postgres::PgPoolOptions;

    /// A store over a LAZY pool: parses the URL but never connects, so these
    /// tests stay database-free (no method here touches the store).
    fn lazy_store() -> Store {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://ironauth@localhost/ironauth")
            .expect("lazy pool parses the URL");
        Store::from_pool(pool)
    }

    fn config_with_token(token: Option<&str>) -> AdminConfig {
        AdminConfig {
            bootstrap_operator_token: token.map(|value| Secret::Literal(SecretString::new(value))),
            ..AdminConfig::default()
        }
    }

    #[tokio::test]
    async fn new_refuses_an_empty_or_whitespace_bootstrap_token() {
        // An empty token, and a whitespace-only token (which trims to empty and
        // could never match a trimmed presented token), must both fail closed at
        // startup rather than silently disabling or opening the operator plane.
        // AdminState has no Debug, so match rather than expect_err (which would
        // need to format the Ok value).
        for token in ["", "   ", "\t\n "] {
            match AdminState::new(lazy_store(), Env::system(), &config_with_token(Some(token))) {
                Err(err @ StateError::EmptyToken) => {
                    assert!(err.to_string().contains("empty value"), "{err}");
                }
                Err(other) => panic!("expected EmptyToken for {token:?}, got: {other}"),
                Ok(_) => panic!("an empty or whitespace-only bootstrap token must be refused"),
            }
        }
    }

    #[tokio::test]
    async fn a_configured_token_is_trimmed_to_match_the_trimmed_presented_token() {
        // Presented tokens are trimmed, so a configured token with incidental
        // surrounding whitespace must still match its trimmed form (and must not
        // match the untrimmed spelling).
        let state = AdminState::new(
            lazy_store(),
            Env::system(),
            &config_with_token(Some("  op-secret  ")),
        )
        .expect("a token with surrounding whitespace builds after trimming");
        assert!(state.match_operator("op-secret").is_some(), "trimmed match");
        assert!(
            state.match_operator("  op-secret  ").is_none(),
            "the untrimmed spelling must not match"
        );
    }

    #[tokio::test]
    async fn a_non_empty_token_matches_only_itself() {
        let state = AdminState::new(
            lazy_store(),
            Env::system(),
            &config_with_token(Some("op-secret")),
        )
        .expect("non-empty token builds");
        assert!(state.match_operator("op-secret").is_some(), "exact match");
        assert!(state.match_operator("").is_none(), "empty presented token");
        assert!(state.match_operator("wrong").is_none(), "wrong token");
    }

    #[tokio::test]
    async fn an_unset_token_never_matches() {
        let state = AdminState::new(lazy_store(), Env::system(), &config_with_token(None))
            .expect("unset token builds (operator plane unauthorized)");
        assert!(state.match_operator("anything").is_none());
        assert!(state.match_operator("").is_none());
    }

    #[tokio::test]
    async fn default_page_size_is_clamped_to_max_page_size() {
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new("t"))),
            default_page_size: 500,
            max_page_size: 100,
            ..AdminConfig::default()
        };
        let state = AdminState::new(lazy_store(), Env::system(), &config).expect("builds");
        assert_eq!(state.max_page_size(), 100);
        assert_eq!(
            state.default_page_size(),
            100,
            "default is clamped down to the max"
        );
    }
}
