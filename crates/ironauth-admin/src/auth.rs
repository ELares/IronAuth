// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential resolution and the two wrong-scope behaviors.
//!
//! A request presents `Authorization: Bearer <token>`. The token is either the
//! config bootstrap operator token (the operator plane) or an environment-scoped
//! management key `mak_...` (the environment plane). Resolution yields a
//! [`Principal`]; the per-endpoint `require_*` methods then enforce scope with
//! the two distinct, both-required behaviors:
//!
//! - a resource-ID probe under a VALID scope for a resource in ANOTHER scope is a
//!   uniform not-found (handled where the resource is resolved, via the store's
//!   scoped parse; the anti-oracle rule);
//! - a credential presented against the WRONG environment or the WRONG plane is a
//!   LOUD [`ApiError::WrongScope`] naming the expected and actual scope.

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use ironauth_store::{ActorRef, EnvironmentId, Scope, TenantId};

use crate::error::ApiError;
use crate::state::AdminState;

/// The authenticated caller of a management request.
#[derive(Debug, Clone, Copy)]
pub enum Principal {
    /// The bootstrap operator (operator plane). Authorizes tenant CRUD and, in
    /// M1, every environment-plane operation (the full operator-plane credential
    /// class lands in M5).
    Operator {
        /// The audit actor: a service actor with the stable operator id.
        actor: ActorRef,
    },
    /// An environment-scoped management key (environment plane).
    ManagementKey {
        /// The `(tenant, environment)` the key is authorized for.
        scope: Scope,
        /// The audit actor: a service actor carrying the key's identity.
        actor: ActorRef,
    },
}

impl Principal {
    /// The audit actor for this principal.
    #[must_use]
    pub fn actor(&self) -> ActorRef {
        match self {
            Principal::Operator { actor } | Principal::ManagementKey { actor, .. } => *actor,
        }
    }

    /// The isolation key for the idempotency store: this credential's actor id.
    #[must_use]
    pub fn credential_ref(&self) -> String {
        self.actor().id_string()
    }

    /// Require the operator plane. A management key here is the LOUD wrong-plane
    /// error naming its scope.
    ///
    /// # Errors
    ///
    /// [`ApiError::WrongScope`] if the caller is a management key.
    pub fn require_operator(&self) -> Result<ActorRef, ApiError> {
        match self {
            Principal::Operator { actor } => Ok(*actor),
            Principal::ManagementKey { scope, .. } => Err(ApiError::WrongScope {
                expected: "plane=operator".to_owned(),
                actual: scope_label(scope),
                message: "this endpoint requires the operator plane; an environment-scoped \
                          management key was presented"
                    .to_owned(),
            }),
        }
    }

    /// Require authorization for exactly `(tenant, environment)`. The operator
    /// passes (M1 operator-plane god-mode); a management key must match exactly,
    /// otherwise the LOUD wrong-environment (or wrong-tenant) error.
    ///
    /// # Errors
    ///
    /// [`ApiError::WrongScope`] if a management key's scope does not match.
    pub fn require_environment(
        &self,
        tenant: TenantId,
        environment: EnvironmentId,
    ) -> Result<ActorRef, ApiError> {
        match self {
            Principal::Operator { actor } => Ok(*actor),
            Principal::ManagementKey { scope, actor } => {
                if scope.tenant() == tenant && scope.environment() == environment {
                    Ok(*actor)
                } else {
                    Err(ApiError::WrongScope {
                        expected: scope_label(scope),
                        actual: scope_label(&Scope::new(tenant, environment)),
                        message: "the presented management key is not authorized for the \
                                  requested environment"
                            .to_owned(),
                    })
                }
            }
        }
    }
}

/// A `tenant=..., environment=...` label for an error's scope fields.
fn scope_label(scope: &Scope) -> String {
    format!(
        "tenant={}, environment={}",
        scope.tenant(),
        scope.environment()
    )
}

/// Extract the `Bearer` token from the `Authorization` header.
fn bearer_token(parts: &Parts) -> Result<String, ApiError> {
    let value = parts
        .headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".to_owned()))?;
    let raw = value
        .to_str()
        .map_err(|_| ApiError::Unauthorized("malformed Authorization header".to_owned()))?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .ok_or_else(|| {
            ApiError::Unauthorized("expected an Authorization: Bearer token".to_owned())
        })?;
    Ok(token.trim().to_owned())
}

impl FromRequestParts<AdminState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AdminState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts)?;
        if let Some(principal) = state.match_operator(&token) {
            return Ok(principal);
        }
        if let Some(principal) = state.authenticate_management_key(&token).await? {
            return Ok(principal);
        }
        Err(ApiError::Unauthorized(
            "invalid or unknown credential".to_owned(),
        ))
    }
}
