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
use ironauth_store::StoreError;
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
    /// An Idempotency-Key was replayed with a DIFFERENT request. Renders 422.
    IdempotencyKeyConflict,
    /// An unexpected internal failure. Renders 500; never leaks detail.
    Internal,
}

impl ApiError {
    /// The HTTP status this error renders to.
    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::WrongScope { .. } => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::IdempotencyKeyConflict => StatusCode::UNPROCESSABLE_ENTITY,
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
            },
            ApiError::Unauthorized(message) => ErrorBody {
                error: "unauthorized".to_owned(),
                message: message.clone(),
                expected_scope: None,
                actual_scope: None,
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
            },
            ApiError::NotFound => ErrorBody {
                error: "not_found".to_owned(),
                message: "resource not found".to_owned(),
                expected_scope: None,
                actual_scope: None,
            },
            ApiError::IdempotencyKeyConflict => ErrorBody {
                error: "idempotency_key_conflict".to_owned(),
                message: "the Idempotency-Key was reused with a different request".to_owned(),
                expected_scope: None,
                actual_scope: None,
            },
            ApiError::Internal => ErrorBody {
                error: "internal".to_owned(),
                message: "internal server error".to_owned(),
                expected_scope: None,
                actual_scope: None,
            },
        }
    }
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
        response
    }
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            // The uniform not-found is preserved across the boundary.
            StoreError::NotFound => ApiError::NotFound,
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
