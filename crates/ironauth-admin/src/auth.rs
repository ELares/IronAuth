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
        })?
        .trim();
    // An empty token (`Authorization: Bearer ` with nothing after it) is never a
    // valid credential; reject it here so it can never reach a constant-time
    // comparison against a (defensively also non-empty) configured token.
    if token.is_empty() {
        return Err(ApiError::Unauthorized("empty bearer token".to_owned()));
    }
    Ok(token.to_owned())
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
        // The third arm (issue #90, PR 2): a console `at+jwt` from the admin issuer,
        // verified through the hardened JOSE path and mapped to an operator via the
        // fail-closed operator-subject allowlist. It runs after the two service
        // credentials because an `at+jwt` is a compact JWS, unambiguous vs the opaque
        // bootstrap token and the `mak_` key; a non-JWS, a disarmed bridge, or any
        // verification failure returns `None` and falls through to the uniform
        // `Unauthorized` below (no oracle). This resolves IDENTITY only; the
        // per-endpoint `require_*` methods still enforce authorization unchanged.
        if let Some(principal) = state.authenticate_admin_oidc(&token).await? {
            return Ok(principal);
        }
        Err(ApiError::Unauthorized(
            "invalid or unknown credential".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use ironauth_config::{AdminConfig, Secret, SecretString};
    use ironauth_env::Env;
    use ironauth_store::Store;
    use sqlx::postgres::PgPoolOptions;

    /// A management state over a LAZY pool (parses the URL, never connects) and a
    /// non-empty operator token. Every assertion below resolves at the extractor
    /// before any store access, so these tests stay database-free.
    fn state() -> AdminState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://ironauth@localhost/ironauth")
            .expect("lazy pool parses the URL");
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new("op-secret"))),
            ..AdminConfig::default()
        };
        AdminState::new(Store::from_pool(pool), Env::system(), &config).expect("state builds")
    }

    fn parts_with_auth(value: Option<&str>) -> Parts {
        let mut builder = Request::builder().method("GET").uri("/v1/tenants");
        if let Some(value) = value {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        builder.body(()).expect("request builds").into_parts().0
    }

    #[test]
    fn bearer_token_rejects_empty_and_missing_and_accepts_a_value() {
        assert!(matches!(
            bearer_token(&parts_with_auth(Some("Bearer "))),
            Err(ApiError::Unauthorized(_))
        ));
        assert!(matches!(
            bearer_token(&parts_with_auth(None)),
            Err(ApiError::Unauthorized(_))
        ));
        assert_eq!(
            bearer_token(&parts_with_auth(Some("Bearer abc"))).expect("token"),
            "abc"
        );
    }

    #[tokio::test]
    async fn empty_bearer_token_is_unauthorized() {
        let mut parts = parts_with_auth(Some("Bearer "));
        let err = Principal::from_request_parts(&mut parts, &state())
            .await
            .expect_err("an empty bearer token must be rejected");
        assert!(matches!(err, ApiError::Unauthorized(_)), "{err:?}");
    }

    #[tokio::test]
    async fn the_operator_token_authenticates_but_a_wrong_one_does_not() {
        let mut ok = parts_with_auth(Some("Bearer op-secret"));
        let principal = Principal::from_request_parts(&mut ok, &state())
            .await
            .expect("the operator token authenticates");
        assert!(matches!(principal, Principal::Operator { .. }));

        let mut wrong = parts_with_auth(Some("Bearer not-the-token"));
        let err = Principal::from_request_parts(&mut wrong, &state())
            .await
            .expect_err("a wrong non-mak token is unauthorized");
        assert!(matches!(err, ApiError::Unauthorized(_)), "{err:?}");
    }
}
