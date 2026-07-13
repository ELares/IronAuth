// SPDX-License-Identifier: MIT OR Apache-2.0

//! The authorization endpoint (`GET`/`POST /authorize`).
//!
//! It issues a single-use authorization code bound to the request's `client_id`,
//! `redirect_uri`, `nonce`, and PKCE `code_challenge`. The order of validation is
//! load-bearing (RFC 6749 4.1.2.1): `client_id` and `redirect_uri` are validated
//! FIRST, before anything is redirected, because an unvalidated redirect target
//! is an open redirector that would leak the code or the error. Only once both
//! are known good does any error travel back by redirect.
//!
//! # Authentication seam
//!
//! A real authorization endpoint issues a code only for an authenticated end user
//! who has consented. The login/session and consent surfaces are separate M2
//! issues; they are not dependencies of this one. So this endpoint models the
//! authenticated subject with a pseudonymous value drawn from the entropy seam and
//! records it (with generated session and consent handles) on the grant. When the
//! login and consent surfaces land, they populate these instead. The code-grant
//! MECHANICS (single use, binding, revocation) this issue owns do not depend on
//! how the subject was established.

use axum::extract::{Form, Query, State};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, Scope, StoreError,
};
use serde::Deserialize;

use crate::error::{AuthorizeError, AuthzErrorCode, redirect_response};
use crate::registry::{PkceMethod, ResponseType};
use crate::state::OidcState;
use crate::util::{append_query, client_service_actor, epoch_micros, redirect_uri_is_valid};

/// The authorization-request parameters. Every field is optional at
/// deserialization so a missing parameter is a validated error (with the correct
/// error behavior) rather than a deserialization failure.
#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    /// The OAuth `response_type` (must be `code`).
    pub response_type: Option<String>,
    /// The client identifier (a `cli_` scoped id declaring its scope).
    pub client_id: Option<String>,
    /// The redirect URI the code is returned to.
    pub redirect_uri: Option<String>,
    /// The requested OAuth `scope` value.
    pub scope: Option<String>,
    /// Opaque CSRF/round-trip state, echoed back verbatim.
    pub state: Option<String>,
    /// The OIDC `nonce`, bound to the code and echoed into the ID token.
    pub nonce: Option<String>,
    /// The PKCE `code_challenge`, bound to the code.
    pub code_challenge: Option<String>,
    /// The PKCE `code_challenge_method` (must be `S256` when a challenge is set).
    pub code_challenge_method: Option<String>,
}

/// `GET /authorize`.
pub async fn authorize_get(
    State(state): State<OidcState>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    handle(&state, params).await
}

/// `POST /authorize`.
pub async fn authorize_post(
    State(state): State<OidcState>,
    Form(params): Form<AuthorizeParams>,
) -> Response {
    handle(&state, params).await
}

/// Run the authorization request, returning the success redirect or an
/// [`AuthorizeError`] (which renders either an error page or an error redirect).
async fn handle(state: &OidcState, params: AuthorizeParams) -> Response {
    match issue_code(state, params).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn issue_code(
    state: &OidcState,
    params: AuthorizeParams,
) -> Result<Response, AuthorizeError> {
    // 1. client_id: present and well formed. A cli_ id declares its own scope, so
    //    it is the routing key to the (tenant, environment) this request lives in.
    let client_id_raw = params
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuthorizeError::page("the client_id parameter is required"))?;
    let client_id = ClientId::parse_declared_scope(client_id_raw)
        .map_err(|_| AuthorizeError::page("the client_id is malformed or unknown"))?;
    let scope = client_id.scope();

    // 2. The client must exist in its declared scope. This lookup is BEFORE any
    //    redirect, so an unknown client renders a page and never redirects. A
    //    store failure here also fails closed to a page (we cannot safely redirect
    //    without a validated client).
    match state.store().scoped(scope).clients().get(&client_id).await {
        Ok(_) => {}
        Err(StoreError::NotFound) => {
            return Err(AuthorizeError::page(
                "the client_id is malformed or unknown",
            ));
        }
        Err(_) => {
            return Err(AuthorizeError::page(
                "the authorization request could not be processed",
            ));
        }
    }

    // 3. redirect_uri: present and syntactically valid. Still BEFORE any redirect.
    //    Strict registered-match is #13; here it must be an absolute http(s) URI
    //    with no fragment so it is safe to redirect to.
    let redirect_uri = params
        .redirect_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuthorizeError::page("the redirect_uri parameter is required"))?;
    if !redirect_uri_is_valid(redirect_uri) {
        return Err(AuthorizeError::page("the redirect_uri is invalid"));
    }

    // From here on, client_id and redirect_uri are validated, so every error is
    // returned to the client by redirecting to redirect_uri.
    let state_echo = params.state.as_deref();
    let redirect_error = |code: AuthzErrorCode, description: &str| AuthorizeError::Redirect {
        redirect_uri: redirect_uri.to_owned(),
        error: code,
        description: description.to_owned(),
        state: state_echo.map(str::to_owned),
    };

    // 4. response_type: present and exactly `code`. A `token`/`id_token` response
    //    type is unrepresentable in the registry, so the implicit flow (an access
    //    token straight from the authorization endpoint) is refused here.
    let response_type = params
        .response_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            redirect_error(AuthzErrorCode::InvalidRequest, "response_type is required")
        })?;
    if ResponseType::parse(response_type).is_none() {
        return Err(redirect_error(
            AuthzErrorCode::UnsupportedResponseType,
            "only the code response_type is supported",
        ));
    }

    // 5. PKCE binding. When a challenge is present, the method must be present and
    //    S256 (plain is unrepresentable). Making PKCE mandatory and S256-only for
    //    every client is #13; here it is a minimal correct binding.
    let (code_challenge, code_challenge_method) = match params.code_challenge.as_deref() {
        Some(challenge) if !challenge.is_empty() => {
            let method = params.code_challenge_method.as_deref().unwrap_or("");
            if PkceMethod::parse(method).is_none() {
                return Err(redirect_error(
                    AuthzErrorCode::InvalidRequest,
                    "code_challenge_method must be S256",
                ));
            }
            (Some(challenge), Some(PkceMethod::S256.as_str()))
        }
        _ => (None, None),
    };

    // 6. Establish the subject and persist the code + grant, then redirect.
    let resolved = Resolved {
        nonce: params.nonce.as_deref().filter(|value| !value.is_empty()),
        oauth_scope: params
            .scope
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        code_challenge,
        code_challenge_method,
        state_echo,
    };
    finalize_issue(state, scope, &client_id, redirect_uri, &resolved).await
}

/// The request fields that survive validation, borrowed for the finalize step.
struct Resolved<'a> {
    nonce: Option<&'a str>,
    oauth_scope: Option<&'a str>,
    code_challenge: Option<&'a str>,
    code_challenge_method: Option<&'a str>,
    state_echo: Option<&'a str>,
}

/// Mint the code and its grant bound to every re-checkable parameter (with a
/// fresh expiry from the clock seam), persist them in one audited transaction,
/// and redirect to the validated `redirect_uri` with the code and echoed state. A
/// store failure here redirects a `server_error` (the `redirect_uri` is valid).
async fn finalize_issue(
    state: &OidcState,
    scope: Scope,
    client_id: &ClientId,
    redirect_uri: &str,
    resolved: &Resolved<'_>,
) -> Result<Response, AuthorizeError> {
    // The authenticated subject (a seam; see the module docs) plus the session
    // and consent handles the grant records.
    let subject = pseudonymous(state, "sub");
    let session_ref = pseudonymous(state, "ses");
    let consent_ref = pseudonymous(state, "con");

    let now = state.now();
    let code_id = AuthorizationCodeId::generate(state.env(), &scope);
    let grant_id = GrantId::generate(state.env(), &scope);
    let expires_at = now.checked_add(state.code_ttl()).unwrap_or(now);

    let issue = IssueCode {
        code_id: &code_id,
        grant_id: &grant_id,
        client_id,
        redirect_uri,
        nonce: resolved.nonce,
        code_challenge: resolved.code_challenge,
        code_challenge_method: resolved.code_challenge_method,
        subject: &subject,
        oauth_scope: resolved.oauth_scope,
        session_ref: Some(&session_ref),
        consent_ref: Some(&consent_ref),
        expires_at_micros: epoch_micros(expires_at),
        created_at_micros: epoch_micros(now),
    };

    // Attribute the issue audit to the client the code is for (stable, derived
    // from the client id), under a fresh per-request correlation id.
    let actor = client_service_actor(client_id);
    let correlation = CorrelationId::generate(state.env());
    if let Err(error) = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .authorization()
        .issue(state.env(), issue)
        .await
    {
        tracing::error!(error = %error, "failed to issue authorization code");
        return Err(AuthorizeError::Redirect {
            redirect_uri: redirect_uri.to_owned(),
            error: AuthzErrorCode::ServerError,
            description: "the authorization request could not be processed".to_owned(),
            state: resolved.state_echo.map(str::to_owned),
        });
    }

    let code = code_id.to_string();
    let location = append_query(
        redirect_uri,
        &[
            ("code", Some(code.as_str())),
            ("state", resolved.state_echo),
        ],
    );
    Ok(redirect_response(&location))
}

/// A pseudonymous, opaque identifier drawn from the entropy seam, prefixed with
/// `prefix` for legibility. Deterministic under a fixed test entropy source.
fn pseudonymous(state: &OidcState, prefix: &str) -> String {
    let mut bytes = [0_u8; 16];
    state.env().entropy().fill_bytes(&mut bytes);
    format!("{prefix}-{}", URL_SAFE_NO_PAD.encode(bytes))
}
