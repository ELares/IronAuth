// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed management-API errors and their structured JSON rendering.
//!
//! Two error shapes are load-bearing for the isolation contract:
//!
//! - [`ApiError::NotFound`] is the UNIFORM not-found: a malformed identifier, an
//!   absent resource, and a resource in another scope all render identically, so
//!   the API is never an existence oracle (the anti-oracle rule).
//! - [`ApiError::WrongScope`] is the LOUD wrong-scope error: a credential
//!   presented against the wrong environment or the wrong plane fails with a
//!   structured error that names the expected and actual scope, so a
//!   misconfigured client gets a clear signal rather than a silent denial.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{GuardrailViolation, StoreError};
use serde::Serialize;
use utoipa::ToSchema;

/// The structured error body every management error renders to. Stable shape, so
/// generated SDKs can type it from the first endpoint.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorBody {
    /// A stable, machine-readable error type (for example `not_found`,
    /// `wrong_scope`, `idempotency_key_conflict`).
    #[schema(example = "not_found")]
    pub error: String,
    /// A human-readable message. Never carries a secret; for a wrong-scope error
    /// it names only the scope identifiers the caller already presented.
    #[schema(example = "resource not found")]
    pub message: String,
    /// Present only on a wrong-scope error: the scope the credential is
    /// authorized for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_scope: Option<String>,
    /// Present only on a wrong-scope error: the scope the request targeted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_scope: Option<String>,
    /// Present only on a guardrail-violation error (issue #42): the stable code of
    /// every guardrail the request failed, so the caller learns each failure at
    /// once (for example `["custom_domain_required", "https_only_redirect_uris"]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_guardrails: Option<Vec<String>>,
    /// Present only on a sudo-mode re-authentication challenge (issue #73): the maximum
    /// authentication age, in seconds, the mutation requires. Mirrors the RFC 9470
    /// `max_age` challenge parameter (also carried in the `WWW-Authenticate` header), so
    /// the admin SPA learns how fresh a re-authentication it must obtain before
    /// retrying.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u64>,
}

/// A management API error.
#[derive(Debug)]
pub enum ApiError {
    /// The request was malformed (missing required header, invalid cursor, or an
    /// unparseable body). Renders 400.
    BadRequest(String),
    /// No valid credential was presented. Renders 401 with `WWW-Authenticate`.
    Unauthorized(String),
    /// A credential was presented against the wrong environment or the wrong
    /// plane. Renders 403, naming the expected and actual scope. The LOUD half of
    /// the two wrong-scope behaviors.
    WrongScope {
        /// The scope the credential is authorized for.
        expected: String,
        /// The scope the request targeted.
        actual: String,
        /// A human-readable summary.
        message: String,
    },
    /// The resource is not visible in the current scope: absent, deactivated,
    /// malformed identifier, or belonging to another scope, all identical. The
    /// uniform anti-oracle half. Renders 404.
    NotFound,
    /// A named resource already exists (for example a DCR policy name reused within
    /// an environment, issue #31). Distinct from the anti-oracle not-found because a
    /// name collision is a legitimate signal the operator asked to create by name.
    /// Renders 409.
    Conflict(String),
    /// An Idempotency-Key was replayed with a DIFFERENT request. Renders 422.
    IdempotencyKeyConflict,
    /// A well-formed request whose value is semantically rejected by a policy the
    /// request itself cannot satisfy (issue #93): the compatibility wizard rejecting an
    /// algorithm the environment cannot actually sign with, so the column is left
    /// unchanged. Distinct from a plain bad request (a malformed or out-of-set value is
    /// a 400): the value parses and is in the wizard set, but the target environment
    /// cannot honor it. Renders 422.
    Unprocessable(String),
    /// A config write failed one or more typed environment guardrails (issue #42):
    /// for example creating a production environment with no custom domain. Renders
    /// 422 with the stable code of every failed guardrail. Distinct from a plain
    /// bad request because the request is well-formed but violates the environment's
    /// enforced guardrail class.
    GuardrailViolation(Vec<GuardrailViolation>),
    /// Admin sudo mode is on and this mutation needs a RECENT re-authentication that
    /// the acting credential does not have (issue #73): the recorded elevation is
    /// absent or its freshness window has lapsed. Renders a 401 RFC 9470
    /// `insufficient_user_authentication` challenge, carrying the required `max_age`
    /// both in the JSON body and in the `WWW-Authenticate` header, and executes NOTHING.
    /// The elevation derives from a server-recorded re-auth event, never from a
    /// client-supplied header, so a stolen credential alone cannot clear this challenge.
    ReauthRequired {
        /// The maximum authentication age, in seconds, the mutation requires.
        max_age: u64,
    },
    /// An unexpected internal failure. Renders 500; never leaks detail.
    Internal,
}

impl ApiError {
    /// The HTTP status this error renders to.
    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            // A missing credential and the RFC 9470 step-up challenge are both 401 (the
            // challenge carries its requirement in the WWW-Authenticate header and body).
            ApiError::Unauthorized(_) | ApiError::ReauthRequired { .. } => StatusCode::UNAUTHORIZED,
            ApiError::WrongScope { .. } => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::IdempotencyKeyConflict
            | ApiError::GuardrailViolation(_)
            | ApiError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The structured body this error renders to.
    fn body(&self) -> ErrorBody {
        match self {
            ApiError::BadRequest(message) => ErrorBody {
                error: "bad_request".to_owned(),
                message: message.clone(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::Unauthorized(message) => ErrorBody {
                error: "unauthorized".to_owned(),
                message: message.clone(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::WrongScope {
                expected,
                actual,
                message,
            } => ErrorBody {
                error: "wrong_scope".to_owned(),
                message: message.clone(),
                expected_scope: Some(expected.clone()),
                actual_scope: Some(actual.clone()),
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::NotFound => ErrorBody {
                error: "not_found".to_owned(),
                message: "resource not found".to_owned(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::Conflict(message) => ErrorBody {
                error: "conflict".to_owned(),
                message: message.clone(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::IdempotencyKeyConflict => ErrorBody {
                error: "idempotency_key_conflict".to_owned(),
                message: "the Idempotency-Key was reused with a different request".to_owned(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::GuardrailViolation(violations) => ErrorBody {
                error: "guardrail_violation".to_owned(),
                message: guardrail_message(violations),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: Some(violations.iter().map(|v| v.code().to_owned()).collect()),
                max_age: None,
            },
            ApiError::Unprocessable(message) => ErrorBody {
                error: "unprocessable_entity".to_owned(),
                message: message.clone(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
            ApiError::ReauthRequired { max_age } => ErrorBody {
                error: "insufficient_user_authentication".to_owned(),
                message: "a fresh re-authentication is required for this operation".to_owned(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: Some(*max_age),
            },
            ApiError::Internal => ErrorBody {
                error: "internal".to_owned(),
                message: "internal server error".to_owned(),
                expected_scope: None,
                actual_scope: None,
                failed_guardrails: None,
                max_age: None,
            },
        }
    }
}

/// A single-line summary of the failed guardrails, listing each one's message so
/// an operator reading only the message learns every failure.
fn guardrail_message(violations: &[GuardrailViolation]) -> String {
    if violations.is_empty() {
        return "the environment guardrails were violated".to_owned();
    }
    let joined = violations
        .iter()
        .map(GuardrailViolation::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    format!("the environment guardrails were violated: {joined}")
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = serde_json::to_string(&self.body()).unwrap_or_else(|_| {
            "{\"error\":\"internal\",\"message\":\"internal server error\"}".to_owned()
        });
        let mut response = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.into())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        if matches!(self, ApiError::Unauthorized(_)) {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer"),
            );
        }
        // RFC 9470: a sudo-mode challenge carries the structured requirement in the
        // WWW-Authenticate header (the `insufficient_user_authentication` error and the
        // `max_age` the mutation requires), mirroring the step-up (issue #72) contract.
        if let ApiError::ReauthRequired { max_age } = self {
            let challenge = format!(
                "Bearer error=\"insufficient_user_authentication\", \
                 error_description=\"a fresh re-authentication is required for this operation\", \
                 max_age={max_age}"
            );
            if let Ok(value) = header::HeaderValue::from_str(&challenge) {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, value);
            }
        }
        response
    }
}

impl From<crate::provision::ProvisionError> for ApiError {
    fn from(error: crate::provision::ProvisionError) -> Self {
        // Day-one signing-key generation failing is an internal fault (a healthy RNG
        // never fails ES256/RS256 keygen); the detail is logged, never returned.
        tracing::error!(error = %error, "day-one signing key generation failed");
        ApiError::Internal
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            // The uniform not-found is preserved across the boundary.
            StoreError::NotFound => ApiError::NotFound,
            // An invalid invitation org-context (issue #94) is a caller-facing bad
            // request (the admin layer validates it richly up front; this is the
            // store's defense-in-depth guard surfacing).
            StoreError::InvalidOrgContext => {
                ApiError::BadRequest("org_context is not a valid organization id".to_owned())
            }
            // A group create or reparent the organization's hierarchy cannot honor
            // (issue #97). 422 rather than 400 (the value is well formed and names
            // a group the caller can see) and rather than 409 (this is a
            // structural refusal, not a uniqueness collision), matching the
            // config-promotion unresolved-reference precedent.
            //
            // These arms are here, in the ONE central conversion, and not only at
            // the handler call sites: the wildcard below turns any unmapped
            // variant into an opaque 500, so a handler that forgets its explicit
            // arm degrades to the correct 422 instead of a server error on every
            // route. Neither message names a group id, so neither can report
            // anything the caller did not already send.
            StoreError::OrgGroupCycle => ApiError::Unprocessable(
                "the requested parent would create a cycle in the group hierarchy".to_owned(),
            ),
            StoreError::OrgGroupDepthExceeded { max, attempted } => {
                ApiError::Unprocessable(format!(
                    "the requested parent would nest groups {attempted} levels deep, \
                     exceeding the configured maximum of {max}"
                ))
            }
            // Anything else (a database fault, or an idempotency conflict that
            // did not funnel through the re-read path) is an opaque internal
            // error; the detail is logged, never returned. `StoreError` is
            // non-exhaustive, so a wildcard keeps this total.
            other => {
                tracing::error!(error = %other, "management store error");
                ApiError::Internal
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiError, StatusCode};
    use ironauth_store::StoreError;

    #[test]
    fn the_group_hierarchy_refusals_render_as_unprocessable_and_never_as_internal() {
        // `impl From<StoreError> for ApiError` wildcards every unmapped variant to an
        // opaque 500 with a tracing error. A new typed refusal that is added to the
        // store but not mapped here is therefore a SILENT 500 on every route that can
        // produce it, with nothing failing to say so. These two assertions are what
        // make the issue #97 refusals a caller-facing 422 rather than that.
        let cycle: ApiError = StoreError::OrgGroupCycle.into();
        assert_eq!(cycle.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            matches!(&cycle, ApiError::Unprocessable(message) if message.contains("cycle")),
            "the cycle refusal must render a caller-facing message: {cycle:?}"
        );

        let depth: ApiError = StoreError::OrgGroupDepthExceeded {
            max: 8,
            attempted: 11,
        }
        .into();
        assert_eq!(depth.status(), StatusCode::UNPROCESSABLE_ENTITY);
        // The configured bound and the attempted depth ride the message, so an
        // operator learns both the limit and how far past it the request went with no
        // new field on the stable error body.
        assert!(
            matches!(
                &depth,
                ApiError::Unprocessable(message)
                    if message.contains("11") && message.contains('8')
            ),
            "the depth refusal must report both the attempted depth and the bound: {depth:?}"
        );
    }

    #[test]
    fn the_config_and_store_group_depth_ceilings_agree() {
        // The store clamps its `max_group_depth` parameter to its OWN mirror of the
        // ceiling, because `ironauth-store` deliberately has no dependency on the
        // config crate. If the two drifted apart, config load would accept a depth the
        // store then silently clamped, and the operator-visible setting would stop
        // meaning what it says. This crate is the only one that can see both, so the
        // agreement is pinned here (the same arrangement as the list hard cap, which
        // is pinned in the pagination module that consumes it).
        assert_eq!(
            ironauth_config::ORGANIZATIONS_MAX_GROUP_DEPTH_CEILING,
            ironauth_store::ORG_GROUP_MAX_DEPTH_CEILING
        );
        // And an EMPTY config file (the shipped defaults) both loads and lands within
        // the ceiling, so a deployment that never touches the setting boots and its
        // effective bound is the one the store will honor unclamped.
        let shipped = ironauth_config::Config::from_toml_str("", "<inline>")
            .expect("the shipped defaults must load")
            .config;
        assert_eq!(
            shipped.organizations.max_group_depth,
            ironauth_config::ORGANIZATIONS_DEFAULT_MAX_GROUP_DEPTH
        );
        assert!(
            shipped.organizations.max_group_depth <= ironauth_store::ORG_GROUP_MAX_DEPTH_CEILING,
            "the shipped default must not be clamped by the store"
        );
    }
}
