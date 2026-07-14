// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pushed authorization request endpoint (`POST /par`, RFC 9126, issue #27).
//!
//! PAR lets a client push the COMPLETE authorization request to the provider over
//! the authenticated back channel and receive a single-use `request_uri` reference,
//! which it then hands to `/authorize` in place of the individual parameters. Two
//! properties make it worth the round trip: the request parameters never travel
//! through the browser (no tampering, no leakage), and every request is validated
//! at push time so errors surface early on the back channel.
//!
//! # What this endpoint does
//!
//! 1. **Authenticates the client** with the SAME suite as the token endpoint
//!    ([`client_auth::authenticate_client`]): a public client uses its registered
//!    `none` posture, a confidential client its secret, a `private_key_jwt` client
//!    its assertion. A failure is the spec-exact, opaque `invalid_client`.
//! 2. **Validates the complete authorization request** with EXACTLY the same rules
//!    as `/authorize`, through the ONE shared [`validate_request`] the authorization
//!    endpoint also runs. So a bad `redirect_uri`, a missing PKCE `code_challenge`, a
//!    disabled response type, or a malformed `claims`/`prompt`/`max_age` is rejected
//!    HERE, on the back channel, not later at `/authorize` (RFC 9126 section 2.3).
//! 3. **Stores the validated request** behind a one-time `par_` reference bound to
//!    the authenticated client, and returns the `request_uri` and a short `expires_in`.
//!
//! # What this endpoint does NOT do
//!
//! It never accepts a `request_uri` in the pushed request (RFC 9126 section 2.1: a
//! pushed request cannot itself reference another one), and NOTHING here or at
//! `/authorize` ever dereferences a `request_uri` over the network: a `request_uri`
//! is only ever the stored PAR row, looked up by reference. The by-reference JAR
//! request object (RFC 9101) is a documented non-goal for this issue.

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{ClientId, CorrelationId, PushRequest, PushedRequestId, Scope};
use serde::Deserialize;

use crate::authorize::{AuthRequestError, AuthorizeParams, validate_request};
use crate::client_auth::{
    self, ClientAuthError, ClientAuthInputs, ClientAuthParseError, parse_presented,
};
use crate::error::AuthzErrorCode;
use crate::state::OidcState;
use crate::util::{client_service_actor, epoch_micros};

/// The RFC 9126 / RFC 6755 `request_uri` scheme for a pushed authorization request:
/// the returned reference is `urn:ietf:params:oauth:request_uri:<par_id>`, and the
/// authorization endpoint accepts a `request_uri` ONLY in this exact form (any other
/// value is a request to dereference an external URI, which IronAuth never does).
pub(crate) const PAR_REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// The pushed-authorization-request form (RFC 9126 section 2.1).
///
/// It carries the client-authentication inputs (the same fields the token endpoint
/// consumes) alongside the full set of authorization-request parameters. It is a
/// distinct struct from [`AuthorizeParams`] (like [`TokenParams`](crate::token)) so
/// the two client-auth fields the authorization request lacks (`client_secret`,
/// `client_assertion`) are present; the authorization parameters are copied into a
/// real [`AuthorizeParams`] for the shared validator, so the two paths validate one
/// identical shape. `request_uri` is accepted only to REJECT it (a pushed request
/// cannot reference another); unknown fields are ignored.
#[derive(Debug, Deserialize)]
pub struct ParParams {
    // Client-authentication inputs (identical to the token endpoint).
    /// The client identifier (also an authorization parameter).
    pub client_id: Option<String>,
    /// The client secret for `client_secret_post` authentication.
    pub client_secret: Option<String>,
    /// The JWT client assertion for `private_key_jwt` authentication.
    pub client_assertion: Option<String>,
    /// The RFC 7521 `client_assertion_type` accompanying `client_assertion`.
    pub client_assertion_type: Option<String>,

    // The authorization-request parameters (validated identically to `/authorize`).
    /// The OAuth `response_type`.
    pub response_type: Option<String>,
    /// The OAuth `response_mode`.
    pub response_mode: Option<String>,
    /// The redirect URI the eventual code is returned to.
    pub redirect_uri: Option<String>,
    /// The requested OAuth `scope`.
    pub scope: Option<String>,
    /// Opaque CSRF/round-trip `state`.
    pub state: Option<String>,
    /// The OIDC `nonce`.
    pub nonce: Option<String>,
    /// The PKCE `code_challenge`.
    pub code_challenge: Option<String>,
    /// The PKCE `code_challenge_method`.
    pub code_challenge_method: Option<String>,
    /// The OIDC `prompt` set.
    pub prompt: Option<String>,
    /// The OIDC `max_age`.
    pub max_age: Option<String>,
    /// The OIDC `acr_values`.
    pub acr_values: Option<String>,
    /// The OIDC `claims` request parameter.
    pub claims: Option<String>,
    /// The OIDC `login_hint`.
    pub login_hint: Option<String>,
    /// The OIDC `logout_hint`.
    pub logout_hint: Option<String>,
    /// The OIDC `ui_locales`.
    pub ui_locales: Option<String>,
    /// The OIDC `claims_locales`.
    pub claims_locales: Option<String>,
    /// The OIDC `display`.
    pub display: Option<String>,
    /// A `request_uri` presented at the PAR endpoint is REJECTED (RFC 9126 section
    /// 2.1): a pushed request cannot itself reference another pushed request.
    pub request_uri: Option<String>,
}

impl ParParams {
    /// Build the [`AuthorizeParams`] to validate and store from this pushed form,
    /// binding the request to the AUTHENTICATED `client_id` (so a Basic-authenticated
    /// push, whose form carried no `client_id`, still replays with the right client).
    /// `request_uri` and the internal `emit_auth_time`/`par_resume` markers are always
    /// cleared: a pushed request never references another, and the resume markers are
    /// internal to the interaction round-trip.
    fn into_authorize_params(self, authenticated_client_id: String) -> AuthorizeParams {
        AuthorizeParams {
            request_uri: None,
            response_type: self.response_type,
            response_mode: self.response_mode,
            client_id: Some(authenticated_client_id),
            redirect_uri: self.redirect_uri,
            scope: self.scope,
            state: self.state,
            nonce: self.nonce,
            code_challenge: self.code_challenge,
            code_challenge_method: self.code_challenge_method,
            prompt: self.prompt,
            max_age: self.max_age,
            acr_values: self.acr_values,
            claims: self.claims,
            login_hint: self.login_hint,
            logout_hint: self.logout_hint,
            ui_locales: self.ui_locales,
            claims_locales: self.claims_locales,
            display: self.display,
            emit_auth_time: None,
            par_resume: None,
        }
    }
}

/// `POST /par` (RFC 9126, issue #27).
pub async fn par(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(params): Form<ParParams>,
) -> Response {
    match push(&state, &headers, params).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn push(
    state: &OidcState,
    headers: &HeaderMap,
    params: ParParams,
) -> Result<Response, PushedAuthError> {
    // 1. A pushed request MUST NOT itself carry a request_uri (RFC 9126 section 2.1).
    if params
        .request_uri
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
    {
        return Err(PushedAuthError::InvalidRequest(
            "request_uri is not permitted in a pushed authorization request".to_owned(),
        ));
    }

    // 2. Authenticate the client with the token endpoint's full suite. The scope is
    //    recovered from the presented client identifier (the PAR endpoint has no code
    //    to recover it from), then the reusable seam verifies the credentials.
    let (authenticated_client_id, scope, client_id) = authenticate(state, headers, &params).await?;

    // 3. Load the client record for the shared validator (its registered
    //    redirect_uris and auth_method drive the redirect match and the PKCE
    //    requirement). It was just authenticated, so it exists.
    let Ok(client) = state.store().scoped(scope).clients().get(&client_id).await else {
        return Err(PushedAuthError::ServerError);
    };

    // 4. Validate the COMPLETE authorization request with EXACTLY the same rules as
    //    `/authorize`, through the ONE shared validator. An error surfaces HERE on the
    //    back channel (RFC 9126 section 2.3), not later at `/authorize`.
    let authorize_params = params.into_authorize_params(authenticated_client_id.clone());
    validate_request(state, &client, &authorize_params)
        .map_err(PushedAuthError::from_validation)?;

    // 5. Persist the validated request behind a one-time reference bound to the
    //    authenticated client, with a short, bounded expiry from the clock seam.
    let par_id = PushedRequestId::generate(state.env(), &scope);
    let now = state.now();
    let ttl = state.par_ttl();
    let expires_at = now.checked_add(ttl).unwrap_or(now);
    let request_params =
        serde_json::to_string(&authorize_params).map_err(|_| PushedAuthError::ServerError)?;

    let correlation = CorrelationId::generate(state.env());
    if let Err(error) = state
        .store()
        .scoped(scope)
        .acting(client_service_actor(&client_id), correlation)
        .pushed_authorization_requests()
        .push(
            state.env(),
            PushRequest {
                id: &par_id,
                client_id: &authenticated_client_id,
                request_params: &request_params,
                expires_at_micros: epoch_micros(expires_at),
                created_at_micros: epoch_micros(now),
            },
        )
        .await
    {
        tracing::error!(error = %error, "failed to store a pushed authorization request");
        return Err(PushedAuthError::ServerError);
    }

    // 6. RFC 9126 section 2.2: 201 Created with the request_uri and its lifetime.
    let request_uri = format!("{PAR_REQUEST_URI_PREFIX}{par_id}");
    let body = serde_json::json!({
        "request_uri": request_uri,
        "expires_in": ttl.as_secs(),
    })
    .to_string();
    Ok(created_json(&body))
}

/// Authenticate the pushing client, returning the authenticated `client_id` string,
/// its scope, and the typed identifier.
///
/// The scope is recovered from the PRESENTED client identifier (a Basic userid or a
/// form `client_id`), which the PAR endpoint needs before it can run the scoped
/// authentication seam. The reusable [`client_auth::authenticate_client`] then does
/// the full verification (registered-method enforcement, secret/assertion checks,
/// single-use jti, out-of-band diagnostics) under that scope.
async fn authenticate(
    state: &OidcState,
    headers: &HeaderMap,
    params: &ParParams,
) -> Result<(String, Scope, ClientId), PushedAuthError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let inputs = ClientAuthInputs {
        authorization,
        client_id: params.client_id.as_deref(),
        client_secret: params.client_secret.as_deref(),
        client_assertion: params.client_assertion.as_deref(),
        client_assertion_type: params.client_assertion_type.as_deref(),
    };

    // Peek the presented client identifier to recover the scope. A parse failure is
    // a malformed authentication attempt (no scope exists to record a diagnostic
    // under), mapped uniformly like the token endpoint would.
    let presented = parse_presented(
        inputs.authorization,
        inputs.client_id,
        inputs.client_secret,
        inputs.client_assertion,
        inputs.client_assertion_type,
    )
    .map_err(map_parse_error)?;
    let Ok(scoped) = ClientId::parse_declared_scope(presented.client_id()) else {
        // An unparseable client identifier is the uniform, opaque invalid_client
        // (never an existence oracle), with the 401 driven by a Basic attempt.
        return Err(PushedAuthError::InvalidClient {
            via_basic: presented.via_basic(),
        });
    };
    let scope = scoped.scope();

    let authed = client_auth::authenticate_client(state, scope, inputs)
        .await
        .map_err(|error| match error {
            ClientAuthError::InvalidRequest(message) => {
                PushedAuthError::InvalidRequest(message.to_owned())
            }
            ClientAuthError::InvalidClient { via_basic } => {
                PushedAuthError::InvalidClient { via_basic }
            }
        })?;
    // The authenticated identifier parsed in scope during authentication, so it
    // parses again here; the fallback is unreachable defense in depth.
    let client_id = ClientId::parse_in_scope(&authed.client_id, &scope)
        .map_err(|_| PushedAuthError::ServerError)?;
    Ok((authed.client_id, scope, client_id))
}

/// Map a client-authentication parse error to the PAR endpoint's error, mirroring the
/// token endpoint's mapping (a malformed Basic credential is a 401 `invalid_client`;
/// the rest are `invalid_request` request problems with fixed, generic messages).
fn map_parse_error(error: ClientAuthParseError) -> PushedAuthError {
    match error {
        ClientAuthParseError::MalformedBasic => PushedAuthError::InvalidClient { via_basic: true },
        ClientAuthParseError::MultipleMethods => {
            PushedAuthError::InvalidRequest("more than one client authentication method".to_owned())
        }
        ClientAuthParseError::MissingClientId => {
            PushedAuthError::InvalidRequest("client_id is required".to_owned())
        }
        ClientAuthParseError::ClientIdMismatch => {
            PushedAuthError::InvalidRequest("conflicting client_id".to_owned())
        }
        ClientAuthParseError::UnsupportedAssertionType => {
            PushedAuthError::InvalidRequest("unsupported client_assertion_type".to_owned())
        }
        ClientAuthParseError::MissingAssertion => {
            PushedAuthError::InvalidRequest("client_assertion is required".to_owned())
        }
    }
}

/// A PAR-endpoint error, rendered as the RFC 6749 5.2 JSON error object exactly as
/// the token endpoint's is (RFC 9126 section 2.3), with `Cache-Control: no-store`.
#[derive(Debug, Clone)]
enum PushedAuthError {
    /// A required parameter is missing or malformed (400 `invalid_request`).
    InvalidRequest(String),
    /// Client authentication failed (401 `invalid_client`); `via_basic` mandates the
    /// `WWW-Authenticate: Basic` challenge (RFC 6749 5.2).
    InvalidClient {
        /// Whether the client attempted Basic authentication.
        via_basic: bool,
    },
    /// The authorization request failed validation (400): carries the SAME OAuth code
    /// and description the shared validator produced, so a bad `redirect_uri`, missing
    /// PKCE, etc. surface here identically to `/authorize`.
    Validation {
        /// The OAuth error code from the shared validator.
        code: AuthzErrorCode,
        /// The `error_description` from the shared validator.
        description: String,
    },
    /// An unexpected server-side condition (500 `server_error`).
    ServerError,
}

impl PushedAuthError {
    /// Map a shared-validator error onto a PAR validation error. The PAR endpoint
    /// always returns JSON, so the validator's page/redirect classification is
    /// ignored; only the OAuth code and description carry over.
    fn from_validation(error: AuthRequestError) -> Self {
        PushedAuthError::Validation {
            code: error.code,
            description: error.description,
        }
    }

    /// The wire `error` value.
    fn code(&self) -> &'static str {
        match self {
            PushedAuthError::InvalidRequest(_) => "invalid_request",
            PushedAuthError::InvalidClient { .. } => "invalid_client",
            PushedAuthError::Validation { code, .. } => code.as_str(),
            PushedAuthError::ServerError => "server_error",
        }
    }

    /// The HTTP status. `invalid_client` is 401 (RFC 6749 5.2), a server fault 500,
    /// and every request/validation problem 400.
    fn status(&self) -> StatusCode {
        match self {
            PushedAuthError::InvalidClient { .. } => StatusCode::UNAUTHORIZED,
            PushedAuthError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            PushedAuthError::InvalidRequest(_) | PushedAuthError::Validation { .. } => {
                StatusCode::BAD_REQUEST
            }
        }
    }

    /// The `error_description`. `invalid_client` is a fixed, generic string so no
    /// credential detail leaks.
    fn description(&self) -> &str {
        match self {
            PushedAuthError::InvalidRequest(message)
            | PushedAuthError::Validation {
                description: message,
                ..
            } => message,
            PushedAuthError::InvalidClient { .. } => "client authentication failed",
            PushedAuthError::ServerError => "the request could not be processed",
        }
    }
}

impl IntoResponse for PushedAuthError {
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
        if let PushedAuthError::InvalidClient { via_basic: true } = self {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Basic realm=\"ironauth\", charset=\"UTF-8\""),
            );
        }
        response
    }
}

/// A `201 Created` JSON response (RFC 9126 section 2.2) with the no-store cache
/// headers, mirroring the token endpoint's response discipline.
fn created_json(body: &str) -> Response {
    (
        StatusCode::CREATED,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        body.to_owned(),
    )
        .into_response()
}
