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
    ActorRef, MANAGEMENT_LIST_HARD_CAP, ManagementKeyId, OperatorId, ServiceId, Store,
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
            }),
        })
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
