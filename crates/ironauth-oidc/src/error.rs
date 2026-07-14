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

use crate::pages;
use crate::response;
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
        /// The RFC 9207 issuer identifier, emitted on EVERY authorization
        /// response, success and error (issue #13). Set from
        /// [`OidcState::issuer_for`](crate::OidcState::issuer_for) once the request
        /// scope is known (which is always the case by the time an error can
        /// redirect, since the `client_id` that fixes the scope is validated
        /// first).
        iss: String,
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
                // A minimal, self-contained HTML error page carrying the full page
                // hardening headers (strict CSP, frame-ancestors none, X-Frame-
                // Options DENY). The message is server-authored, but it is escaped
                // regardless (defense in depth against the error-page injection
                // class) so no reflected value can ever break out of the page.
                pages::secure_html(
                    StatusCode::BAD_REQUEST,
                    pages::notice_page("Authorization request rejected", &message),
                )
            }
            AuthorizeError::Redirect {
                redirect_uri,
                error,
                description,
                state,
                iss,
            } => {
                // The error-response parameter set ALWAYS carries the RFC 9207
                // `iss` (issue #13); the same assembler feeds the fragment and
                // form_post encoders #17 adds, so iss is emitted uniformly on every
                // mode.
                let location = append_query(
                    &redirect_uri,
                    &response::error_params(
                        error.as_str(),
                        description.as_str(),
                        state.as_deref(),
                        &iss,
                    ),
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
    /// Client authentication failed (issue #20): an unknown client, a credential
    /// that did not satisfy the client's registered method, or a mismatched
    /// method. The spec-exact `invalid_client`. `via_basic` records whether the
    /// client attempted authentication via the `Authorization` header, which
    /// mandates a 401 with `WWW-Authenticate` (RFC 6749 5.2).
    InvalidClient {
        /// Whether the client attempted Basic authentication.
        via_basic: bool,
    },
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
            TokenError::InvalidClient { .. } => "invalid_client",
            TokenError::InvalidGrant => "invalid_grant",
            TokenError::UnsupportedGrantType => "unsupported_grant_type",
            TokenError::ServerError => "server_error",
        }
    }

    /// The HTTP status this error renders to. `invalid_client` is 401
    /// (Unauthorized), which RFC 6749 5.2 mandates when the client attempted an
    /// `Authorization`-header credential and permits generally.
    fn status(&self) -> StatusCode {
        match self {
            TokenError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            TokenError::InvalidClient { .. } => StatusCode::UNAUTHORIZED,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    /// The `error_description`. For `invalid_grant` and `invalid_client` it is a
    /// fixed, generic string so no binding-specific or credential detail leaks.
    fn description(&self) -> &str {
        match self {
            TokenError::InvalidRequest(message) => message,
            TokenError::InvalidClient { .. } => "client authentication failed",
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
        let mut response = (
            self.status(),
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            body,
        )
            .into_response();
        // A Basic authentication attempt that failed MUST carry WWW-Authenticate
        // (RFC 6749 5.2). The value is a fixed server constant (no reflected
        // input), so it is safe to set verbatim.
        if let TokenError::InvalidClient { via_basic: true } = self {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Basic realm=\"ironauth\", charset=\"UTF-8\""),
            );
        }
        response
    }
}
