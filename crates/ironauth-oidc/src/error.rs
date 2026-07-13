// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OAuth error surfaces for the two endpoints.
//!
//! The authorization endpoint has two distinct error behaviors, and which one
//! applies is a security decision (RFC 6749 4.1.2.1):
//!
//! - If `client_id` or `redirect_uri` is missing or invalid, the server MUST NOT
//!   redirect (an open redirector would leak the code or the error to an
//!   attacker-chosen URI). It renders an error PAGE instead. This is
//!   [`AuthorizeError::Page`].
//! - For every other error, once `client_id` and `redirect_uri` are known good,
//!   the error is returned to the client by redirecting to the validated
//!   `redirect_uri` with `error`, `error_description`, and the echoed `state`.
//!   This is [`AuthorizeError::Redirect`].
//!
//! The token endpoint returns the RFC 6749 5.2 JSON error object with
//! `Cache-Control: no-store`. Its `invalid_grant` is uniform: a bad code, an
//! expired code, a replayed code, and any single binding mismatch (including a
//! wrong `client_id`) all render identically, so the endpoint never says which
//! check failed.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::util::append_query;

/// The authorization-endpoint OAuth error codes this issue emits (RFC 6749
/// 4.1.2.1). The set is intentionally small; more codes land with the surfaces
/// that raise them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzErrorCode {
    /// The request is missing a parameter, or includes an invalid one.
    InvalidRequest,
    /// The `response_type` is not one this server supports (only `code`).
    UnsupportedResponseType,
    /// The server encountered an unexpected condition.
    ServerError,
}

impl AuthzErrorCode {
    /// The wire `error` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AuthzErrorCode::InvalidRequest => "invalid_request",
            AuthzErrorCode::UnsupportedResponseType => "unsupported_response_type",
            AuthzErrorCode::ServerError => "server_error",
        }
    }
}

/// An error at the authorization endpoint.
#[derive(Debug, Clone)]
pub enum AuthorizeError {
    /// Render an error page and NEVER redirect: `client_id` or `redirect_uri` is
    /// missing or invalid, so there is no trusted URI to send the error to.
    Page {
        /// The human-readable reason shown on the page. Never a secret.
        message: String,
    },
    /// Return the error to the client by redirecting to the validated
    /// `redirect_uri`.
    Redirect {
        /// The validated redirect URI to send the error to.
        redirect_uri: String,
        /// The OAuth error code.
        error: AuthzErrorCode,
        /// The human-readable `error_description`. Never a secret.
        description: String,
        /// The `state` value to echo back, if the request carried one.
        state: Option<String>,
    },
}

impl AuthorizeError {
    /// An error-page error (no redirect).
    #[must_use]
    pub fn page(message: impl Into<String>) -> Self {
        AuthorizeError::Page {
            message: message.into(),
        }
    }
}

impl IntoResponse for AuthorizeError {
    fn into_response(self) -> Response {
        match self {
            AuthorizeError::Page { message } => {
                // A minimal, self-contained HTML error page. The message is
                // server-authored (never reflected untrusted input), so it needs
                // no escaping; it names only why the request was refused.
                let body = format!(
                    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
                     <title>Authorization error</title></head><body>\
                     <h1>Authorization request rejected</h1><p>{message}</p></body></html>"
                );
                (
                    StatusCode::BAD_REQUEST,
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    body,
                )
                    .into_response()
            }
            AuthorizeError::Redirect {
                redirect_uri,
                error,
                description,
                state,
            } => {
                let location = append_query(
                    &redirect_uri,
                    &[
                        ("error", Some(error.as_str())),
                        ("error_description", Some(description.as_str())),
                        ("state", state.as_deref()),
                    ],
                );
                redirect_response(&location)
            }
        }
    }
}

/// A `302 Found` redirect to `location`. Built by hand so the exact `Location`
/// string (already percent-encoded) is emitted verbatim.
#[must_use]
pub fn redirect_response(location: &str) -> Response {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// A token-endpoint error (RFC 6749 5.2).
#[derive(Debug, Clone)]
pub enum TokenError {
    /// A required parameter is missing or malformed.
    InvalidRequest(String),
    /// The authorization code is invalid, expired, revoked, replayed, or one of
    /// its bindings did not match (including a wrong `client_id`). Uniform on
    /// purpose: it never says which.
    InvalidGrant,
    /// The `grant_type` is not one this server supports (only
    /// `authorization_code`). This is where ROPC and every other grant land.
    UnsupportedGrantType,
    /// An unexpected server-side condition (for example no signing key for the
    /// target environment). Renders 500.
    ServerError,
}

impl TokenError {
    /// The wire `error` value.
    fn code(&self) -> &'static str {
        match self {
            TokenError::InvalidRequest(_) => "invalid_request",
            TokenError::InvalidGrant => "invalid_grant",
            TokenError::UnsupportedGrantType => "unsupported_grant_type",
            TokenError::ServerError => "server_error",
        }
    }

    /// The HTTP status this error renders to.
    fn status(&self) -> StatusCode {
        match self {
            TokenError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    /// The `error_description`. For `invalid_grant` it is a fixed, generic string
    /// so no binding-specific detail leaks.
    fn description(&self) -> &str {
        match self {
            TokenError::InvalidRequest(message) => message,
            TokenError::InvalidGrant => {
                "the authorization code is invalid, expired, or already used"
            }
            TokenError::UnsupportedGrantType => "the grant type is not supported",
            TokenError::ServerError => "the request could not be processed",
        }
    }
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.code(),
            "error_description": self.description(),
        })
        .to_string();
        (
            self.status(),
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            body,
        )
            .into_response()
    }
}
