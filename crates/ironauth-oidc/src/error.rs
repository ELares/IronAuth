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
use crate::registry::ResponseMode;
use crate::response;

/// The authorization-endpoint OAuth error codes this issue emits (RFC 6749
/// 4.1.2.1). The set is intentionally small; more codes land with the surfaces
/// that raise them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzErrorCode {
    /// The request is missing a parameter, or includes an invalid one.
    InvalidRequest,
    /// The `response_type` is not one this server supports: it is token-bearing
    /// (structurally unrepresentable), otherwise unknown, or a legacy type not
    /// enabled in this environment (issue #17).
    UnsupportedResponseType,
    /// The authorization server denied the request. Used for the residual
    /// essential-`acr` fail-closed (issue #15): an authentication context that some
    /// method COULD achieve but this session did not, and that the single-method
    /// bootstrap cannot step up to. When NO available method can EVER achieve the
    /// requested context, [`AuthzErrorCode::UnmetAuthenticationRequirements`] is
    /// returned instead (issue #16).
    AccessDenied,
    /// The end user is not authenticated and `prompt=none` forbids showing a login
    /// UI (OIDC Core 3.1.2.6). Returned through the negotiated response mode.
    LoginRequired,
    /// Consent is required but `prompt=none` forbids showing the consent UI (OIDC
    /// Core 3.1.2.6). Returned through the negotiated response mode.
    ConsentRequired,
    /// An interaction is required that is neither a plain login nor consent, and
    /// `prompt=none` forbids it (OIDC Core 3.1.2.6). Returned through the negotiated
    /// response mode.
    InteractionRequired,
    /// Account selection is required but `prompt=none` forbids showing the chooser
    /// (OIDC Core 3.1.2.6). Registered for completeness; the single-session
    /// bootstrap resolves `prompt=none` to login/consent instead.
    AccountSelectionRequired,
    /// The requested authentication context (an essential `acr`) cannot be
    /// satisfied by ANY authentication method this server offers (OIDC Core, the
    /// registered `unmet_authentication_requirements`). Returned through the
    /// negotiated response mode.
    UnmetAuthenticationRequirements,
    /// A requested `resource` (RFC 8707 resource indicator, issue #28) is
    /// malformed (not an absolute URI, or carries a fragment), unknown (no
    /// registered resource server), or disallowed (outside the client's
    /// allowlist, or a no-resource request when the client requires one). RFC 8707
    /// section 2.2. Returned through the negotiated response mode.
    InvalidTarget,
    /// The server encountered an unexpected condition.
    ServerError,
}

impl AuthzErrorCode {
    /// The wire `error` value (the registered OIDC / RFC 6749 error-code strings).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AuthzErrorCode::InvalidRequest => "invalid_request",
            AuthzErrorCode::UnsupportedResponseType => "unsupported_response_type",
            AuthzErrorCode::AccessDenied => "access_denied",
            AuthzErrorCode::LoginRequired => "login_required",
            AuthzErrorCode::ConsentRequired => "consent_required",
            AuthzErrorCode::InteractionRequired => "interaction_required",
            AuthzErrorCode::AccountSelectionRequired => "account_selection_required",
            AuthzErrorCode::UnmetAuthenticationRequirements => "unmet_authentication_requirements",
            AuthzErrorCode::InvalidTarget => "invalid_target",
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
        /// The negotiated response mode the error is delivered by (issue #17): the
        /// same `query`/`fragment`/`form_post` encoder the success response would
        /// have used, so an error travels back the way the client asked for a
        /// result (and `iss` rides it uniformly). Errors raised before a mode can
        /// be negotiated use the safe `query` (or the response type's default)
        /// mode.
        mode: ResponseMode,
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
                mode,
            } => {
                // The error-response parameter set ALWAYS carries the RFC 9207
                // `iss` (issue #13); the SAME assembler feeds the query, fragment,
                // and form_post encoders (issue #17), so iss is emitted uniformly
                // on whatever negotiated mode runs.
                let params = response::error_params(
                    error.as_str(),
                    description.as_str(),
                    state.as_deref(),
                    &iss,
                );
                response::render(mode, &redirect_uri, &params)
            }
        }
    }
}

/// A `303 See Other` redirect to `location`. Built by hand so the exact
/// `Location` string (already percent-encoded) is emitted verbatim.
///
/// `303` (never `302` and never `307`/`308`) is the RFC 9700 status for a
/// credential-bearing redirect: an authorization response carries the code (or a
/// front-channel token) in `location`, and `303` MANDATES that the user agent
/// re-issue the follow-up as a `GET` with no request body. A body-preserving
/// `307`/`308` would replay a credential from the request body to the redirect
/// target, and the legacy `302` leaves the method conversion browser-dependent;
/// `303` closes both.
/// `Referrer-Policy: no-referrer` rides EVERY code-carrying response from this one
/// seam, so the authorization code (which lives in the `Location` query for the
/// `query` response mode) is never leaked onward through the `Referer` header, and
/// `Cache-Control: no-store` keeps it out of shared caches.
#[must_use]
pub fn redirect_response(location: &str) -> Response {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::REFERRER_POLICY, "no-referrer")
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
    /// The requested `scope` is out of policy for this grant (RFC 6749 5.2, issue
    /// #23): for the client-credentials grant, a scope a machine principal may not
    /// request (for example `openid` or `offline_access`). Carries a fixed, generic
    /// description.
    InvalidScope,
    /// A requested `resource` (RFC 8707 resource indicator, issue #28) is
    /// malformed (not an absolute URI, or carries a fragment), unknown (no
    /// registered resource server), or disallowed (outside the client's allowlist,
    /// outside the resources approved at authorization, or a no-resource request
    /// when the client requires one). RFC 8707 section 2.2.
    InvalidTarget,
    /// The `grant_type` is not one this server supports (only
    /// `authorization_code`). This is where ROPC and every other grant land.
    UnsupportedGrantType,
    /// The device-authorization request is still pending human approval (RFC 8628
    /// section 3.5, issue #24): the device code is valid but the user has not yet
    /// approved (or denied) the flow at the verification page. The device keeps
    /// polling at its interval.
    AuthorizationPending,
    /// The device is polling faster than the current interval (RFC 8628 section 3.5,
    /// issue #24): the server has increased the enforced interval for this device
    /// code, and the device must slow its polling.
    SlowDown,
    /// The device-authorization request was denied (RFC 8628 section 3.5, issue #24):
    /// the human explicitly rejected it at the verification page, or the user code was
    /// invalidated after exhausting its failed-match budget.
    AccessDenied,
    /// The device code has expired (RFC 8628 section 3.5, issue #24): its TTL passed
    /// before the flow was approved and redeemed. The device must start a new flow.
    ExpiredToken,
    /// An unexpected server-side condition (for example no signing key for the
    /// target environment). Renders 500.
    ServerError,
    /// The refresh or authorization-code grant would mint an access token whose
    /// scope carries a step-up authentication requirement (an `acr` floor and/or a
    /// max auth age) that the frozen authentication does NOT satisfy (RFC 9470,
    /// issue #72). A refresh whose auth-age window has LAPSED, or a grant whose
    /// recorded `acr` is below the required floor, fails HERE rather than silently
    /// minting an under-qualified token; the client must re-authorize with the
    /// carried `acr_values` / `max_age` to run the step-up. Renders 400 with
    /// `error="insufficient_user_authentication"` (the RFC 9470 challenge error) plus
    /// the `acr_values` and `max_age` the client needs to construct the retry.
    InsufficientUserAuthentication {
        /// The `acr` floor the client must request on the retry authorization, if a
        /// floor applied.
        acr_values: Option<String>,
        /// The maximum authentication age (seconds) the client must request, if an
        /// age bound applied.
        max_age: Option<u64>,
    },
}

impl TokenError {
    /// The wire `error` value.
    fn code(&self) -> &'static str {
        match self {
            TokenError::InvalidRequest(_) => "invalid_request",
            TokenError::InvalidClient { .. } => "invalid_client",
            TokenError::InvalidGrant => "invalid_grant",
            TokenError::InvalidScope => "invalid_scope",
            TokenError::InvalidTarget => "invalid_target",
            TokenError::UnsupportedGrantType => "unsupported_grant_type",
            TokenError::AuthorizationPending => "authorization_pending",
            TokenError::SlowDown => "slow_down",
            TokenError::AccessDenied => "access_denied",
            TokenError::ExpiredToken => "expired_token",
            TokenError::ServerError => "server_error",
            TokenError::InsufficientUserAuthentication { .. } => "insufficient_user_authentication",
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
            TokenError::InvalidScope => "the requested scope is invalid for this grant",
            TokenError::InvalidTarget => {
                "the requested resource is invalid, unknown, or not allowed for this client"
            }
            TokenError::UnsupportedGrantType => "the grant type is not supported",
            TokenError::AuthorizationPending => {
                "the authorization request is still pending user approval"
            }
            TokenError::SlowDown => "polling too frequently; increase the polling interval",
            TokenError::AccessDenied => "the authorization request was denied",
            TokenError::ExpiredToken => "the device code has expired; start a new device flow",
            TokenError::ServerError => "the request could not be processed",
            TokenError::InsufficientUserAuthentication { .. } => {
                "the authentication does not meet the required authentication context; \
                 re-authorize with the indicated acr_values and max_age"
            }
        }
    }
}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        let mut object = serde_json::json!({
            "error": self.code(),
            "error_description": self.description(),
        });
        // RFC 9470: the step-up error carries the acr_values / max_age the client
        // needs to construct the retry authorization request.
        if let TokenError::InsufficientUserAuthentication {
            acr_values,
            max_age,
        } = &self
        {
            if let Some(map) = object.as_object_mut() {
                if let Some(acr) = acr_values {
                    map.insert("acr_values".to_owned(), serde_json::json!(acr));
                }
                if let Some(age) = max_age {
                    map.insert("max_age".to_owned(), serde_json::json!(age));
                }
            }
        }
        let body = object.to_string();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authz_error_codes_render_the_registered_wire_strings() {
        // The registered OIDC / RFC 6749 error-code strings, locked so a rename
        // cannot silently change what a relying party sees (issue #16).
        assert_eq!(AuthzErrorCode::InvalidRequest.as_str(), "invalid_request");
        assert_eq!(
            AuthzErrorCode::UnsupportedResponseType.as_str(),
            "unsupported_response_type"
        );
        assert_eq!(AuthzErrorCode::AccessDenied.as_str(), "access_denied");
        assert_eq!(AuthzErrorCode::LoginRequired.as_str(), "login_required");
        assert_eq!(AuthzErrorCode::ConsentRequired.as_str(), "consent_required");
        assert_eq!(
            AuthzErrorCode::InteractionRequired.as_str(),
            "interaction_required"
        );
        assert_eq!(
            AuthzErrorCode::AccountSelectionRequired.as_str(),
            "account_selection_required"
        );
        assert_eq!(
            AuthzErrorCode::UnmetAuthenticationRequirements.as_str(),
            "unmet_authentication_requirements"
        );
        assert_eq!(AuthzErrorCode::InvalidTarget.as_str(), "invalid_target");
        assert_eq!(AuthzErrorCode::ServerError.as_str(), "server_error");
    }
}
