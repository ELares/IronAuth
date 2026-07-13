// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shared handler state and the credential-resolution logic.
//!
//! [`AdminState`] carries the control-plane [`Store`] (authenticated as
//! `ironauth_control`), the environment seam, the resolved bootstrap operator
//! token, and the page-size configuration. It is the axum router state, so every
//! handler and the [`crate::auth::Principal`] extractor reach it.

use std::sync::Arc;
use std::time::SystemTime;

use ironauth_config::{AdminConfig, SecretError};
use ironauth_env::Env;
use ironauth_store::{ActorRef, ManagementKeyId, OperatorId, ServiceId, Store};

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
    bootstrap_operator_token: Option<String>,
    bootstrap_operator_id: OperatorId,
    bootstrap_operator_actor: ActorRef,
    default_page_size: u32,
    max_page_size: u32,
}

impl AdminState {
    /// Build the management state from a control-plane store, the environment
    /// seam, and the admin config.
    ///
    /// The `store` MUST authenticate as `ironauth_control`, not `ironauth_app`.
    ///
    /// # Errors
    ///
    /// [`StateError::Secret`] if the bootstrap operator token secret cannot be
    /// resolved from its file or environment-variable source.
    pub fn new(store: Store, env: Env, config: &AdminConfig) -> Result<Self, StateError> {
        let bootstrap_operator_token = match &config.bootstrap_operator_token {
            Some(secret) => Some(
                secret
                    .resolve()
                    .map_err(StateError::Secret)?
                    .expose()
                    .to_owned(),
            ),
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
                default_page_size: config.default_page_size.max(1),
                max_page_size: config.max_page_size.max(1),
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
        let configured = self.inner.bootstrap_operator_token.as_deref()?;
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
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::Secret(source) => {
                write!(f, "cannot resolve admin.bootstrap_operator_token: {source}")
            }
        }
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StateError::Secret(source) => Some(source),
        }
    }
}
