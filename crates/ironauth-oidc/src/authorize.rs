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
//! # Login and consent interaction (issue #20)
//!
//! A code is issued only for an authenticated end user who has consented. After
//! the request is validated, the endpoint resolves the bootstrap session cookie:
//!
//! - No session: it redirects to the login page (or, for `prompt=create`, the
//!   registration page), carrying a `return_to` that resumes this exact request.
//! - A session but no recorded consent for this client: it redirects to the
//!   consent screen, again with a resuming `return_to`.
//! - A session and recorded consent: it issues the code bound to the real subject,
//!   recording the session and consent handles on the grant.
//!
//! The single-use, binding, and revocation mechanics the code grant owns (issue
//! #12) are unchanged; only how the subject and consent are established is real
//! now instead of a seam.

use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, Scope, StoreError,
};
use serde::Deserialize;

use crate::authn;
use crate::claims_request::{ClaimsRequest, ClaimsRequestError};
use crate::error::{AuthorizeError, AuthzErrorCode, redirect_response};
use crate::interaction;
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
    /// The OIDC `prompt`. Only `create` (route to registration) is acted on in the
    /// bootstrap; the rest of the `prompt`/`max_age` semantics build on the session
    /// the bootstrap establishes and are a later milestone.
    pub prompt: Option<String>,
    /// The OIDC `max_age`. Its PRESENCE (including `max_age=0`) requires the ID
    /// token to carry `auth_time` (issue #14). The re-authentication ENFORCEMENT
    /// that `max_age` also implies (a stale session must re-authenticate) is
    /// step-up policy, owned by #16 and M7; only the `auth_time` emission lands
    /// here.
    pub max_age: Option<String>,
    /// The OIDC `acr_values`: the ACR values the client would prefer, most
    /// preferred first. IronAuth attempts to satisfy them but the ID token's `acr`
    /// always reflects the ACHIEVED level (derived from the authentication event),
    /// never a copied-through requested value (issue #14). The
    /// `unmet_authentication_requirements` error when a requested level cannot be
    /// met is owned by #16.
    pub acr_values: Option<String>,
    /// The OIDC `claims` request parameter (issue #15): a JSON object requesting
    /// individual claims for the `id_token` and/or `userinfo` (OIDC Core 5.5). It
    /// is parsed and validated here, frozen onto the code and grant, and applied
    /// later at the token endpoint (`id_token` member) and `UserInfo` (`userinfo`
    /// member). A malformed value is a redirect `invalid_request`.
    pub claims: Option<String>,
}

/// `GET /authorize`.
pub async fn authorize_get(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    handle(&state, &headers, params).await
}

/// `POST /authorize`.
pub async fn authorize_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(params): Form<AuthorizeParams>,
) -> Response {
    handle(&state, &headers, params).await
}

/// Run the authorization request, returning the success redirect, an interaction
/// redirect (login/registration/consent), or an [`AuthorizeError`] (an error page
/// or an error redirect).
async fn handle(state: &OidcState, headers: &HeaderMap, params: AuthorizeParams) -> Response {
    match issue_code(state, headers, params).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

// A linear, numbered validation pipeline (client, redirect, response_type, PKCE,
// claims, gate, acr, issue): each step is short but heavily commented for the
// security rationale, so the whole reads over the line budget. Kept as one
// sequence deliberately, since the ORDER is the security property.
#[allow(clippy::too_many_lines)]
async fn issue_code(
    state: &OidcState,
    headers: &HeaderMap,
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
    //    without a validated client). The record carries the client's
    //    `require_auth_time` registration, which (with `max_age`) decides whether
    //    the ID token must carry `auth_time` (issue #14).
    let client = match state.store().scoped(scope).clients().get(&client_id).await {
        Ok(record) => record,
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
    };

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

    // 5b. The OIDC `claims` request parameter (Core 5.5): parse and validate. A
    //     malformed value is a redirect invalid_request. It is frozen onto the code
    //     and grant (canonical form) below, so the token endpoint can honor its
    //     `id_token` member at mint and UserInfo its `userinfo` member later
    //     (issue #15).
    let (claims_request, claims_canonical) = parse_claims_request(params.claims.as_deref())
        .map_err(|description| redirect_error(AuthzErrorCode::InvalidRequest, description))?;

    // 6. Establish the authenticated subject and their consent. A missing session
    //    or missing consent short-circuits to a LOCAL interaction redirect (never
    //    the client's redirect_uri), carrying a return_to that resumes this exact
    //    request.
    let (session, consent_ref) =
        match resolve_gate(state, headers, scope, &client_id, &params, redirect_uri).await? {
            Gate::Interaction(response) => return Ok(response),
            Gate::Ready {
                session,
                consent_ref,
            } => (session, consent_ref),
        };

    // 6b. Essential acr binding (OIDC Core 5.5.1.1): if the `claims` parameter pins
    //     an essential acr to specific values, the request MUST NOT be silently
    //     downgraded to a lower level. The achieved acr is DERIVED from the recorded
    //     authentication event (issue #14), never from the request; if it is not
    //     among the requested values, the authentication requirement is unmet and
    //     the request fails closed. The full `unmet_authentication_requirements`
    //     surface (and any step-up re-authentication) is issue #16; this fails
    //     closed through today's redirect error path rather than silently
    //     succeeding, leaving a clean seam for #16 to refine the error.
    if !essential_acr_met(&claims_request, &session) {
        return Err(redirect_error(
            AuthzErrorCode::AccessDenied,
            "the requested authentication context (essential acr) cannot be satisfied",
        ));
    }

    // 7. Freeze the authentication context onto the code. auth_time is emitted in
    //    the ID token when the request asked for max_age (present, including
    //    max_age=0) OR the client registered require_auth_time; the value is
    //    always the truthful recorded instant, so it is frozen only when it is
    //    due. The recorded methods are always frozen so amr/acr can be derived.
    //    acr_values is honored as a preference only: the achieved acr comes from
    //    the event, never from the request, so nothing about acr_values is copied
    //    onto the code.
    let max_age_requested = params
        .max_age
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let auth_time_micros =
        (max_age_requested || client.require_auth_time).then_some(session.auth_time_unix_micros);

    // 8. Persist the code + grant bound to every re-checkable parameter and the
    //    real subject/session/consent, then redirect with the code.
    let session_ref = session.session_id.to_string();
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
        subject: &session.subject,
        auth_methods: &session.auth_methods,
        auth_time_micros,
        session_ref: &session_ref,
        consent_ref: &consent_ref,
        claims_request: claims_canonical.as_deref(),
    };
    finalize_issue(state, scope, &client_id, redirect_uri, &resolved).await
}

/// Parse the OIDC `claims` request parameter (Core 5.5), returning the parsed
/// request and its canonical JSON form (both empty/[`None`] when the request
/// carried none). A malformed value yields a short, non-secret description the
/// caller maps to a redirect `invalid_request` (issue #15).
fn parse_claims_request(
    raw: Option<&str>,
) -> Result<(ClaimsRequest, Option<String>), &'static str> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok((ClaimsRequest::default(), None));
    };
    let request = ClaimsRequest::parse(raw).map_err(ClaimsRequestError::as_description)?;
    let canonical = (!request.is_empty()).then(|| request.to_json());
    Ok((request, canonical))
}

/// Whether the request's essential-`acr` binding (Core 5.5.1.1) is met by the
/// session's ACHIEVED authentication context. The achieved `acr` is derived from
/// the recorded authentication event (issue #14), never the request; a voluntary
/// or absent `acr` request is always met (issue #15).
fn essential_acr_met(
    claims_request: &ClaimsRequest,
    session: &interaction::AuthenticatedSession,
) -> bool {
    let achieved = authn::achieved_acr(&authn::parse_methods(&session.auth_methods));
    claims_request.acr_satisfied(achieved)
}

/// The outcome of resolving the login/consent gate: either an interaction is
/// needed (a local redirect to login, registration, or consent) or the request
/// is ready to issue a code for an authenticated, consenting subject.
enum Gate {
    /// A local interaction redirect (never the client's `redirect_uri`).
    Interaction(Response),
    /// An authenticated session with recorded consent for this client.
    Ready {
        /// The resolved session (its subject is recorded on the grant).
        session: interaction::AuthenticatedSession,
        /// The recorded consent handle (referenced by the grant).
        consent_ref: String,
    },
}

/// Resolve the login/consent gate for a validated request. Redirects an
/// unauthenticated user to login (or registration for `prompt=create`), and an
/// authenticated user without consent to the consent screen; otherwise reports the
/// request ready. A consent-store failure is a `server_error` redirect (the
/// `redirect_uri` is already validated).
async fn resolve_gate(
    state: &OidcState,
    headers: &HeaderMap,
    scope: Scope,
    client_id: &ClientId,
    params: &AuthorizeParams,
    redirect_uri: &str,
) -> Result<Gate, AuthorizeError> {
    let cookie = interaction::cookie_header(headers);
    let Some(session) = interaction::resolve_session(state, scope, cookie).await else {
        let return_to = build_authorize_url(params);
        // prompt=create routes an UNAUTHENTICATED user to registration; once a
        // session exists it is ignored, so registration never loops.
        let redirect = if params.prompt.as_deref().map(str::trim) == Some("create") {
            interaction::register_redirect(&return_to)
        } else {
            interaction::login_redirect(&return_to)
        };
        return Ok(Gate::Interaction(redirect));
    };

    let client_id_str = client_id.to_string();
    // Bootstrap limitation tracked in #196 (a hard prerequisite for enabling OIDC,
    // #13): consent is looked up per (subject, client_id) only, so a prior consent
    // for a narrow scope auto-grants any later broader scope. Before enablement this
    // must re-prompt when the requested scope is not a subset of the granted scope.
    match state
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(&session.subject, &client_id_str)
        .await
    {
        Ok(Some(consent_ref)) => Ok(Gate::Ready {
            session,
            consent_ref,
        }),
        Ok(None) => Ok(Gate::Interaction(interaction::consent_redirect(
            &build_authorize_url(params),
        ))),
        Err(_) => Err(AuthorizeError::Redirect {
            redirect_uri: redirect_uri.to_owned(),
            error: AuthzErrorCode::ServerError,
            description: "the authorization request could not be processed".to_owned(),
            state: params.state.as_deref().map(str::to_owned),
        }),
    }
}

/// Reconstruct the canonical `/authorize?...` URL from the request parameters, so
/// an interaction redirect can resume this exact request after login or consent.
/// Built from the raw parameters (percent-encoding each) so the resumed request is
/// byte-for-byte equivalent whether the original arrived as a GET or a POST.
fn build_authorize_url(params: &AuthorizeParams) -> String {
    append_query(
        "/authorize",
        &[
            ("response_type", params.response_type.as_deref()),
            ("client_id", params.client_id.as_deref()),
            ("redirect_uri", params.redirect_uri.as_deref()),
            ("scope", params.scope.as_deref()),
            ("state", params.state.as_deref()),
            ("nonce", params.nonce.as_deref()),
            ("code_challenge", params.code_challenge.as_deref()),
            (
                "code_challenge_method",
                params.code_challenge_method.as_deref(),
            ),
            ("prompt", params.prompt.as_deref()),
            ("max_age", params.max_age.as_deref()),
            ("acr_values", params.acr_values.as_deref()),
            ("claims", params.claims.as_deref()),
        ],
    )
}

/// The request fields that survive validation, borrowed for the finalize step.
struct Resolved<'a> {
    nonce: Option<&'a str>,
    oauth_scope: Option<&'a str>,
    code_challenge: Option<&'a str>,
    code_challenge_method: Option<&'a str>,
    state_echo: Option<&'a str>,
    /// The authenticated end-user subject (a `usr_` id string).
    subject: &'a str,
    /// The recorded authentication method tokens (issue #14), frozen onto the
    /// code so amr/acr derive from the actual login.
    auth_methods: &'a str,
    /// The recorded authentication instant frozen onto the code, present only
    /// when the ID token must carry `auth_time` (issue #14).
    auth_time_micros: Option<i64>,
    /// The authenticating session handle recorded on the grant.
    session_ref: &'a str,
    /// The recorded consent handle recorded on the grant.
    consent_ref: &'a str,
    /// The canonical JSON of the `claims` request parameter (issue #15), frozen
    /// onto the code and grant, or [`None`] when the request carried none.
    claims_request: Option<&'a str>,
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
        subject: resolved.subject,
        oauth_scope: resolved.oauth_scope,
        auth_methods: resolved.auth_methods,
        auth_time_micros: resolved.auth_time_micros,
        session_ref: Some(resolved.session_ref),
        consent_ref: Some(resolved.consent_ref),
        claims_request: resolved.claims_request,
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
