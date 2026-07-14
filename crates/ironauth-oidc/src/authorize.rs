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
    ActorRef, AuthorizationCodeId, ClientId, ClientRecord, ConsumePushedRequest, CorrelationId,
    GrantId, GrantedConsent, IssueCode, PushedRequestId, Scope, ServiceId, StoreError,
    redirect_uri_is_registrable, redirect_uri_matches,
};
use serde::{Deserialize, Serialize};

use crate::authn;
use crate::claims_request::{ClaimsRequest, ClaimsRequestError};
use crate::client_auth::ClientAuthMethod;
use crate::error::{AuthorizeError, AuthzErrorCode};
use crate::hints::InteractionHints;
use crate::interaction;
use crate::par::PAR_REQUEST_URI_PREFIX;
use crate::registry::{PkceMethod, PromptSet, PromptValue, ResponseMode, ResponseType};
use crate::response;
use crate::scope_claims::{assemble_claims, parse_scope_set};
use crate::state::OidcState;
use crate::token_hash;
use crate::tokens::{self, MintRequest};
use crate::util::{append_query, client_service_actor, epoch_micros};

/// The authorization-request parameters. Every field is optional at
/// deserialization so a missing parameter is a validated error (with the correct
/// error behavior) rather than a deserialization failure.
///
/// It also derives [`Serialize`] so a pushed authorization request (RFC 9126, issue
/// #27) can be stored verbatim by the PAR endpoint and replayed here when its
/// `request_uri` is consumed: the pushed request is EXACTLY an `AuthorizeParams`, so
/// the two paths validate one identical shape.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthorizeParams {
    /// The PAR (RFC 9126, issue #27) `request_uri`: a reference to a request the
    /// client already pushed to the PAR endpoint. When present, the authorization
    /// endpoint consumes the referenced request from PAR storage (single use, bound
    /// to the pushing client) and IGNORES the rest of the query. It is accepted ONLY
    /// in the `urn:ietf:params:oauth:request_uri:<id>` form backed by PAR storage:
    /// an external `request_uri` is NEVER dereferenced (a documented non-goal). It is
    /// never itself part of a pushed request (the PAR endpoint rejects it), so it is
    /// [`None`] on every replayed request.
    pub request_uri: Option<String>,
    /// The OAuth `response_type`: `code` always, plus the per-environment legacy
    /// types (`id_token`, `code id_token`, `none`) when enabled (issue #17). It is
    /// an ORDER-INSENSITIVE space-separated set; token-bearing values are
    /// structurally unrepresentable.
    pub response_type: Option<String>,
    /// The OAuth `response_mode` (issue #17): `query`, `fragment`, or `form_post`.
    /// Absent means the response type's default (`query` for `code`/`none`,
    /// `fragment` for the front-channel types). An explicit value is honored only
    /// where spec-legal and enabled in this environment.
    pub response_mode: Option<String>,
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
    /// The OIDC `prompt`: a space-separated SET of `none`, `login`, `consent`,
    /// `select_account`, `create` (issue #16). `none` renders no UI and returns the
    /// matching `*_required` error through the negotiated mode; `login` (and
    /// `max_age`) force fresh authentication; `consent` forces the consent screen;
    /// `select_account` degrades to re-login under the single-session bootstrap;
    /// `create` deep-links to registration. `none` combined with any other value is
    /// `invalid_request`.
    pub prompt: Option<String>,
    /// The OIDC `max_age`: seconds since authentication. Its PRESENCE (including
    /// `max_age=0`, distinguished from absent by an explicit presence check, not a
    /// truthiness test) requires the ID token to carry `auth_time` (issue #14) AND
    /// drives re-authentication (issue #16): a session older than `max_age` must
    /// re-authenticate, and `max_age=0` is treated exactly as `prompt=login`. A
    /// non-integer value is `invalid_request`.
    pub max_age: Option<String>,
    /// The OIDC `acr_values`: the ACR values the client would prefer, most
    /// preferred first. This is a VOLUNTARY preference: IronAuth attempts to satisfy
    /// it but the ID token's `acr` always reflects the ACHIEVED level (issue #14),
    /// and an unsatisfiable `acr_values` is never an error. A BINDING requirement is
    /// expressed only through an essential `acr` in the `claims` parameter, whose
    /// unmet surface is `unmet_authentication_requirements` (issue #16).
    pub acr_values: Option<String>,
    /// The OIDC `claims` request parameter (issue #15): a JSON object requesting
    /// individual claims for the `id_token` and/or `userinfo` (OIDC Core 5.5). It
    /// is parsed and validated here, frozen onto the code and grant, and applied
    /// later at the token endpoint (`id_token` member) and `UserInfo` (`userinfo`
    /// member). A malformed value is a redirect `invalid_request`.
    pub claims: Option<String>,
    /// The OIDC `login_hint`: an identifier to prefill on the hosted login page
    /// (issue #16). Reflected into the login form (escaped); carried across the
    /// interaction round-trip so the login page recovers it.
    pub login_hint: Option<String>,
    /// The OIDC `logout_hint`: accepted and carried for a later logout surface
    /// (issue #16). Never acted on here (no logout endpoint exists yet).
    pub logout_hint: Option<String>,
    /// The OIDC `ui_locales`: the space-separated end-user UI language preference
    /// (issue #16), threaded into the interaction page-rendering context.
    pub ui_locales: Option<String>,
    /// The OIDC `claims_locales`: the space-separated claim-value language
    /// preference (issue #16), threaded into the page-rendering context.
    pub claims_locales: Option<String>,
    /// The OIDC `display` (`page`/`popup`/`touch`/`wap`): the UI presentation hint
    /// (issue #16), threaded into the page-rendering context.
    pub display: Option<String>,
    /// An INTERNAL resume marker (issue #16), NOT a client-facing parameter. When a
    /// login interaction CONSUMES a `max_age` to break the re-auth loop (dropping it
    /// from the resume URL so the fresh authentication is not re-flagged as stale),
    /// it sets this so the resumed request still emits the ID token's `auth_time`
    /// that `max_age` implied. It only ever ADDS the honest `auth_time` claim, so a
    /// forged value is harmless (it can never suppress an interaction or a claim).
    pub emit_auth_time: Option<String>,
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
///
/// A PAR (RFC 9126, issue #27) `request_uri` is resolved FIRST: if the request
/// carries one, the referenced pushed request is consumed from PAR storage (single
/// use, bound to the pushing client) and its parameters REPLACE the presented ones,
/// so the rest of the pipeline runs on the pushed request. A `via_par` flag records
/// that the request arrived through PAR, so the require-PAR gate does not reject it.
async fn handle(state: &OidcState, headers: &HeaderMap, params: AuthorizeParams) -> Response {
    let (params, via_par) = match resolve_pushed_request(state, params).await {
        Ok(resolved) => resolved,
        Err(error) => return error.into_response(),
    };
    match issue_code(state, headers, params, via_par).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

/// Resolve a PAR (RFC 9126, issue #27) `request_uri` to the pushed request it
/// references, or pass a plain request through unchanged.
///
/// When the request carries no `request_uri`, this returns `(params, false)`: a
/// plain authorization request. When it carries one, the reference is accepted ONLY
/// in the `urn:ietf:params:oauth:request_uri:<id>` form backed by PAR storage; an
/// external URI is a uniform `invalid_request` PAGE and is NEVER dereferenced over
/// the network (a documented, test-enforced non-goal). The referenced request is
/// consumed ATOMICALLY exactly once, filtered on the PRESENTED `client_id`, so a
/// reuse, an expiry, or a presentation under a different client all fail closed and
/// none of them burns another client's pending request (RFC 9126 client binding). On
/// success the pushed parameters (an `AuthorizeParams` the PAR endpoint validated and
/// stored) REPLACE the presented ones, and the pipeline runs on them with
/// `via_par = true`.
///
/// Every error here is a PAGE (not a redirect): the pushed request's own
/// `redirect_uri` is gone (consumed or never resolved) and the presented one is not
/// yet validated, so there is no trusted URI to send an error to.
async fn resolve_pushed_request(
    state: &OidcState,
    params: AuthorizeParams,
) -> Result<(AuthorizeParams, bool), AuthorizeError> {
    let Some(request_uri) = params
        .request_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok((params, false));
    };

    // Accept ONLY our PAR urn form. Anything else (an https/http URL, an unknown
    // urn) is a request to dereference an EXTERNAL request_uri, which IronAuth never
    // does: it is a uniform invalid_request, and no fetch is performed.
    let Some(reference) = request_uri.strip_prefix(PAR_REQUEST_URI_PREFIX) else {
        return Err(AuthorizeError::page(
            "the request_uri is invalid, expired, or already used",
        ));
    };

    // The client_id is required alongside a request_uri (RFC 9126 section 4): it is
    // what binds the consume to the pushing client, so a different client cannot use
    // (or burn) the pending request.
    let presented_client = params
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuthorizeError::page("the client_id parameter is required"))?;

    // The reference declares its own scope (a par_ scoped id), exactly as an
    // authorization code does, so the consume runs under that scope with row-level
    // security. A malformed reference is a uniform miss (never an oracle).
    let Ok(par_id) = PushedRequestId::parse_declared_scope(reference) else {
        return Err(AuthorizeError::page(
            "the request_uri is invalid, expired, or already used",
        ));
    };
    let scope = par_id.scope();

    // Attribute the consume audit to the presenting client where it parses in scope,
    // exactly as the code issue/redeem audits are; otherwise a generated service
    // actor (defense in depth against a malformed stored/presented value).
    let actor = match ClientId::parse_in_scope(presented_client, &scope) {
        Ok(id) => client_service_actor(&id),
        Err(_) => ActorRef::service(ServiceId::generate(state.env())),
    };
    let correlation = CorrelationId::generate(state.env());
    let outcome = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .pushed_authorization_requests()
        .consume(state.env(), &par_id, presented_client)
        .await;

    match outcome {
        Ok(ConsumePushedRequest::Consumed { request_params }) => {
            // The stored parameters ARE an AuthorizeParams (validated at push time);
            // deserialize and run the pipeline on them, marked as arriving via PAR.
            let stored: AuthorizeParams = serde_json::from_str(&request_params).map_err(|_| {
                AuthorizeError::page("the authorization request could not be processed")
            })?;
            Ok((stored, true))
        }
        // A miss: absent, expired, already consumed, or presented under a different
        // client_id. Uniform invalid_request; the pending request (if any) is not
        // burned by a mismatched presenter.
        Ok(ConsumePushedRequest::Invalid) => Err(AuthorizeError::page(
            "the request_uri is invalid, expired, or already used",
        )),
        Err(error) => {
            tracing::error!(error = %error, "failed to consume a pushed authorization request");
            Err(AuthorizeError::page(
                "the authorization request could not be processed",
            ))
        }
    }
}

// A linear, numbered validation pipeline (client, require-PAR gate, shared
// request validation, gate, acr, issue): each step is short but heavily commented
// for the security rationale, so the whole reads over the line budget. Kept as one
// sequence deliberately, since the ORDER is the security property.
#[allow(clippy::too_many_lines)]
async fn issue_code(
    state: &OidcState,
    headers: &HeaderMap,
    params: AuthorizeParams,
    via_par: bool,
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
    //    the ID token must carry `auth_time` (issue #14), and its
    //    `require_pushed_authorization_requests` flag (issue #27).
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

    // 2b. require-PAR gate (RFC 9126 sections 5 and 6, issue #27). When the
    //     environment-wide switch OR this client's registration flag requires a
    //     pushed authorization request, a plain (non-PAR) request is rejected with
    //     invalid_request. A request that arrived THROUGH PAR (via_par) satisfies the
    //     requirement and is exempt. This runs BEFORE the redirect_uri is validated,
    //     so it is a PAGE error, never an open-redirector-able redirect.
    if !via_par
        && (state.require_pushed_authorization_requests()
            || client.require_pushed_authorization_requests)
    {
        return Err(AuthorizeError::page(
            "this client requires a pushed authorization request (RFC 9126)",
        ));
    }

    // 3. Validate the authorization request through the ONE shared validator
    //    (redirect_uri exact match, response_type, response-mode negotiation, PKCE,
    //    the `claims` parameter, prompt/max_age). The PAR endpoint (issue #27) runs
    //    the SAME validator at push time, so a pushed request and a plain request are
    //    checked by EXACTLY the same rules and cannot diverge. An error before a
    //    redirect target is validated is a page; after, it rides the negotiated mode.
    let validated = validate_request(state, &client, &params)
        .map_err(|error| error.into_authorize(state.issuer_for(&scope), params.state.as_deref()))?;
    let ValidatedRequest {
        redirect_uri,
        response_type,
        mode,
        nonce,
        code_challenge,
        code_challenge_method,
        claims_request,
        claims_canonical,
        prompt,
        max_age_secs,
        hints,
    } = validated;

    // From here on, client_id and redirect_uri are validated, so every error is
    // returned to the client by redirecting to redirect_uri with the RFC 9207 `iss`
    // (issue #13) through the negotiated mode.
    let iss = state.issuer_for(&scope);
    let state_echo = params.state.as_deref();
    let redirect_error = |code: AuthzErrorCode, description: &str| AuthorizeError::Redirect {
        redirect_uri: redirect_uri.to_owned(),
        error: code,
        description: description.to_owned(),
        state: state_echo.map(str::to_owned),
        iss: iss.clone(),
        mode,
    };

    // 6. Establish the authenticated subject and their consent, applying prompt and
    //    max_age. A missing session, missing consent, or a forced (re-)authentication
    //    short-circuits to a LOCAL interaction redirect (never the client's
    //    redirect_uri), carrying a return_to that resumes this exact request. Under
    //    prompt=none no UI is ever rendered: the matching login_required /
    //    consent_required error is returned through the negotiated mode instead.
    let (session, consent_ref) = match resolve_gate(
        state,
        headers,
        &client_id,
        &params,
        redirect_uri,
        &iss,
        mode,
        prompt,
        max_age_secs,
        &hints,
    )
    .await?
    {
        Gate::Interaction(response) => return Ok(response),
        Gate::Ready {
            session,
            consent_ref,
        } => (session, consent_ref),
    };

    // 6b. Essential acr binding and the unmet-authentication surface (OIDC Core
    //     5.5.1.1, issue #16). A voluntary `acr_values` preference is best-effort:
    //     the achieved acr always reflects the real authentication event (issue #14),
    //     never a copied-through request, and an unsatisfiable `acr_values` is not an
    //     error. An ESSENTIAL acr in the `claims` parameter is binding: if NONE of
    //     its pinned values is achievable by any method the server offers, no
    //     authentication can ever satisfy it, so it is
    //     `unmet_authentication_requirements`; if it is achievable in principle but
    //     not by THIS session (a step-up, unreachable under the single-method
    //     bootstrap, owned by M7), it fails closed via `access_denied` as issue #15
    //     established. Either is delivered by the negotiated mode.
    if let Some((code, description)) = acr_requirement_error(&claims_request, &session.auth_methods)
    {
        return Err(redirect_error(code, description));
    }

    // 7. Freeze the authentication context. auth_time is emitted in the ID token
    //    when the request asked for max_age (present, including max_age=0) OR the
    //    client registered require_auth_time OR a login interaction CONSUMED a
    //    max_age to break the re-auth loop (the emit_auth_time resume marker, issue
    //    #16), so a max_age request still yields auth_time even after the max_age
    //    itself was dropped from the resumed URL. The value is always the truthful
    //    recorded instant, so it is frozen only when it is due. The recorded methods
    //    are always frozen so amr/acr can be derived. acr_values is honored as a
    //    preference only: the achieved acr comes from the event, never the request.
    let auth_time_required =
        max_age_secs.is_some() || client.require_auth_time || params.emit_auth_time.is_some();
    let auth_time_micros = auth_time_required.then_some(session.auth_time_unix_micros);

    let session_ref = session.session_id.to_string();
    let resolved = Resolved {
        nonce,
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

    // 8. Dispatch by response type, consuming the SAME success parameter list
    //    through the negotiated mode encoder (issue #17):
    //    - issues_code (`code`, `code id_token`): persist the code + grant bound to
    //      every re-checkable parameter and the real subject/session/consent;
    //    - front-channel (`id_token`, `code id_token`): mint an ID token through
    //      the token endpoint's exact claim + signing path, carrying `nonce`, and
    //      (hybrid only) `c_hash` of the issued code, never an access token;
    //    - `none`: issue nothing.
    let code = if response_type.issues_code() {
        Some(
            persist_code(
                state,
                scope,
                &client_id,
                redirect_uri,
                &iss,
                mode,
                &resolved,
            )
            .await?,
        )
    } else {
        None
    };
    let id_token = if response_type.is_front_channel() {
        let minted = mint_front_channel_id_token(
            state,
            scope,
            &client_id,
            &iss,
            response_type,
            &resolved,
            code.as_deref(),
        )
        .await
        .map_err(|()| {
            redirect_error(
                AuthzErrorCode::ServerError,
                "the authorization request could not be processed",
            )
        })?;
        Some(minted)
    } else {
        None
    };

    let params = response::success_params(code.as_deref(), id_token.as_deref(), state_echo, &iss);
    Ok(response::render(mode, redirect_uri, &params))
}

/// Resolve the response mode for a request (issue #17). Absent means the response
/// type's default (`query` for `code`/`none`, `fragment` for the front-channel
/// types). An explicit value is honored only where BOTH spec-legal and enabled in
/// this environment; otherwise it returns the `invalid_request` description the
/// caller sends by the type's default mode.
///
/// Spec legality (OAuth 2.0 Multiple Response Type Encoding Practices): `query` is
/// forbidden for a front-channel type (it would place an ID token in the logged,
/// `Referer`-leaked query string); `fragment` and `form_post` are legal for any
/// type. Enablement: `query` is always available, `fragment` rides the
/// front-channel feature, and `form_post` rides its own per-environment toggle.
fn resolve_mode(
    state: &OidcState,
    response_type: ResponseType,
    requested: Option<&str>,
) -> Result<ResponseMode, &'static str> {
    let Some(requested) = requested.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(response_type.default_response_mode());
    };
    let Some(mode) = ResponseMode::parse(requested) else {
        return Err("the requested response_mode is not supported");
    };
    // query would leak a front-channel ID token through the query string.
    if mode == ResponseMode::Query && response_type.is_front_channel() {
        return Err("the query response_mode is not permitted for this response_type");
    }
    if !state.response_mode_enabled(mode) {
        return Err("the requested response_mode is not enabled in this environment");
    }
    Ok(mode)
}

/// Mint the front-channel ID token for the implicit and hybrid flows (issue #17),
/// reusing the token endpoint's EXACT claim assembly and signing path
/// ([`tokens::mint_id_token`]); it never mints an access token. The hybrid flow
/// supplies `c_hash` of the issued `code`; the pure implicit flow has no code and
/// no `c_hash`. A missing signing key or a signing failure is `Err(())`, which the
/// caller maps to a `server_error` returned by the negotiated mode. (Live key
/// serving is inert until issue #194; the logic is fully exercised by tests that
/// provision a key.)
async fn mint_front_channel_id_token(
    state: &OidcState,
    scope: Scope,
    client_id: &ClientId,
    iss: &str,
    response_type: ResponseType,
    resolved: &Resolved<'_>,
    code: Option<&str>,
) -> Result<String, ()> {
    let entry = state.issuer_entry(&scope).await.ok_or(())?;
    let signer = entry.signer(state.now()).ok_or(())?;
    let alg = signer.algorithm();
    // The `sub` is resolved through the ONE shared derivation, so a front-channel
    // ID token's subject can never diverge from what the token endpoint or UserInfo
    // returns for the same client and user.
    let subject = state.resolve_public_subject(resolved.subject);
    let client_id_str = client_id.to_string();
    // c_hash binds the issued code to the hybrid ID token; a pure id_token carries
    // none, and neither ever carries at_hash (no access token is issued here).
    let c_hash = match (response_type, code) {
        (ResponseType::CodeIdToken, Some(code)) => Some(token_hash::c_hash(alg, code)),
        _ => None,
    };
    // OIDC Core 5.4: when NO access token is issued (the pure `id_token` flow), the
    // scope-derived and claims-parameter claims have no `UserInfo` retrieval path,
    // so they MUST be emitted into the ID token itself. The HYBRID flow issues a
    // code (hence an access token at redemption), so its front-channel ID token
    // stays lean with the authoritative claims served from `UserInfo`.
    let extra_claims = if response_type.issues_code() {
        serde_json::Map::new()
    } else {
        front_channel_id_token_claims(state, scope, resolved).await
    };
    let request = MintRequest {
        scope,
        issuer: iss,
        subject: &subject,
        client_id: &client_id_str,
        nonce: resolved.nonce,
        oauth_scope: resolved.oauth_scope,
        auth_methods: resolved.auth_methods,
        auth_time_unix_micros: resolved.auth_time_micros,
        at_hash: None,
        c_hash: c_hash.as_deref(),
        extra_claims: &extra_claims,
    };
    tokens::mint_id_token(state, signer, entry.policy(), &request).map(|(id_token, _jti)| id_token)
}

/// The claims to embed in a PURE front-channel ID token (`response_type=id_token`),
/// per OIDC Core 5.4. Because that flow issues no access token, `UserInfo` is
/// unreachable, so the granted scope's standard claims (`profile`/`email`/…) AND
/// the `claims` request parameter's `id_token` member are released into the ID
/// token itself, through the ONE shared [`assemble_claims`] function so the set can
/// never differ from what `UserInfo` would return elsewhere. Unlike the token
/// endpoint's lean default, the scope-derived claims are ALWAYS included here (not
/// only under `conform_id_token_claims`), since there is no other retrieval path. A
/// store read failure fail-opens to an empty set (logged): the ID token
/// under-claims rather than failing issuance.
async fn front_channel_id_token_claims(
    state: &OidcState,
    scope: Scope,
    resolved: &Resolved<'_>,
) -> serde_json::Map<String, serde_json::Value> {
    let claims_request = resolved
        .claims_request
        .and_then(|raw| ClaimsRequest::parse(raw).ok())
        .unwrap_or_default();
    let bag = match state
        .store()
        .scoped(scope)
        .users()
        .claims_for_subject(resolved.subject)
        .await
    {
        Ok(Some(raw)) => serde_json::from_str(&raw).unwrap_or_default(),
        // No user record, or an unreadable/malformed claim document: under-claim
        // rather than fail issuance.
        Ok(None) => serde_json::Map::new(),
        Err(error) => {
            tracing::warn!(%error, "could not read user claims for the front-channel ID token; omitting them");
            serde_json::Map::new()
        }
    };
    let granted = parse_scope_set(resolved.oauth_scope);
    assemble_claims(&bag, &granted, claims_request.id_token())
}

/// A validated authorization request: the fields that survive the shared
/// [`validate_request`] pipeline, ready for the login/consent gate and issuance.
///
/// The borrows are tied to the [`AuthorizeParams`] the validator was run over.
pub(crate) struct ValidatedRequest<'a> {
    /// The validated, registered `redirect_uri` (borrowed from the request).
    pub(crate) redirect_uri: &'a str,
    /// The parsed, enabled response type.
    pub(crate) response_type: ResponseType,
    /// The negotiated response mode.
    pub(crate) mode: ResponseMode,
    /// The OIDC `nonce`, trimmed to a non-empty value or [`None`].
    pub(crate) nonce: Option<&'a str>,
    /// The validated PKCE `code_challenge` (S256) or [`None`].
    pub(crate) code_challenge: Option<&'a str>,
    /// The PKCE `code_challenge_method` string (`S256`) when a challenge is bound.
    pub(crate) code_challenge_method: Option<&'static str>,
    /// The parsed `claims` request parameter (OIDC Core 5.5).
    pub(crate) claims_request: ClaimsRequest,
    /// The canonical JSON form of the `claims` request parameter, or [`None`].
    pub(crate) claims_canonical: Option<String>,
    /// The parsed `prompt` set.
    pub(crate) prompt: PromptSet,
    /// The parsed `max_age` seconds (present including `max_age=0`), or [`None`].
    pub(crate) max_age_secs: Option<u64>,
    /// The typed interaction-hint seam (login/logout hints, locales, display).
    pub(crate) hints: InteractionHints,
}

/// An error from the shared authorization-request validation, in a NEUTRAL form
/// both the authorization endpoint and the PAR endpoint (issue #27) can render.
///
/// The `/authorize` endpoint renders it through [`AuthRequestError::into_authorize`]
/// (a page before a redirect target is validated, a redirect after); the PAR
/// endpoint renders the SAME `code` and `description` as a back-channel JSON error
/// (RFC 9126 section 2.3), so an error surfaces identically wherever the one
/// validator runs.
pub(crate) struct AuthRequestError {
    /// The OAuth error code.
    pub(crate) code: AuthzErrorCode,
    /// A short, non-secret `error_description`.
    pub(crate) description: String,
    /// When `Some`, the error is redirectable to this validated `redirect_uri`
    /// through this mode (so `/authorize` sends a redirect); when `None`, no redirect
    /// target is validated yet (so `/authorize` renders a page). The PAR endpoint
    /// ignores this classification and always returns JSON.
    pub(crate) redirect: Option<(String, ResponseMode)>,
}

impl AuthRequestError {
    /// A pre-redirect error (no validated redirect target): an `invalid_request`
    /// page at `/authorize`, a JSON `invalid_request` at PAR.
    fn page(description: impl Into<String>) -> Self {
        Self {
            code: AuthzErrorCode::InvalidRequest,
            description: description.into(),
            redirect: None,
        }
    }

    /// A redirectable error: the `redirect_uri` is validated, so `/authorize` sends
    /// the error back through `mode`; PAR still returns JSON.
    fn redirect(
        redirect_uri: &str,
        mode: ResponseMode,
        code: AuthzErrorCode,
        description: impl Into<String>,
    ) -> Self {
        Self {
            code,
            description: description.into(),
            redirect: Some((redirect_uri.to_owned(), mode)),
        }
    }

    /// Render this validation error as an authorization-endpoint [`AuthorizeError`],
    /// given the request's issuer and echoed `state`. A redirectable error becomes a
    /// redirect (carrying the RFC 9207 `iss`, issue #13); a page error becomes an
    /// error page.
    fn into_authorize(self, iss: String, state_echo: Option<&str>) -> AuthorizeError {
        match self.redirect {
            Some((redirect_uri, mode)) => AuthorizeError::Redirect {
                redirect_uri,
                error: self.code,
                description: self.description,
                state: state_echo.map(str::to_owned),
                iss,
                mode,
            },
            None => AuthorizeError::Page {
                message: self.description,
            },
        }
    }
}

/// Validate an authorization request's parameters, the ONE shared validator both
/// `/authorize` and the PAR endpoint (RFC 9126, issue #27) run.
///
/// The steps and their ORDER are the security property, identical to what the
/// authorization endpoint has always enforced (RFC 6749 4.1.2.1, RFC 9700): the
/// `redirect_uri` is validated FIRST (a bad one is a page error, never a redirect),
/// then the response type, response-mode negotiation, the front-channel nonce
/// requirement, PKCE (S256-only, mandatory per the public/confidential policy), the
/// `claims` request parameter, and the `prompt` and `max_age` parameters. Every error is returned as a
/// neutral [`AuthRequestError`] so the two callers render it in their own way (a
/// page/redirect at `/authorize`, a JSON error at PAR) with no divergence.
///
/// This performs NO login/consent gate and issues nothing: it validates only the
/// re-checkable request parameters. The caller supplies the already-resolved
/// [`ClientRecord`] (its `redirect_uris` and `auth_method` drive the redirect match
/// and the PKCE requirement).
pub(crate) fn validate_request<'a>(
    state: &OidcState,
    client: &ClientRecord,
    params: &'a AuthorizeParams,
) -> Result<ValidatedRequest<'a>, AuthRequestError> {
    // 3. redirect_uri: present, a registrable RFC 8252 target, and an EXACT match
    //    against the client's registered set. A failure is a PAGE error (no redirect
    //    target is trusted yet), so it can never be turned into an open redirector.
    let redirect_uri =
        validate_registered_redirect(client, params).map_err(AuthRequestError::page)?;

    // 4. response_type: present, representable, and enabled. A token-bearing value is
    //    structurally unrepresentable (parse returns None), so the implicit
    //    access-token flow is refused; the legacy types are DISABLED by default.
    let response_type_raw = params
        .response_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            // No type at all: no front-channel default is known, so the safe query
            // mode carries the error.
            AuthRequestError::redirect(
                redirect_uri,
                ResponseMode::Query,
                AuthzErrorCode::InvalidRequest,
                "response_type is required",
            )
        })?;
    let Some(response_type) = ResponseType::parse(response_type_raw) else {
        return Err(AuthRequestError::redirect(
            redirect_uri,
            ResponseMode::Query,
            AuthzErrorCode::UnsupportedResponseType,
            "the response_type is not supported",
        ));
    };

    // 4b. Negotiate the response mode (issue #17), delivering any error by the type's
    //     DEFAULT mode (never form_post, so there is no circular dependency).
    let default_mode = response_type.default_response_mode();
    let mode = resolve_mode(state, response_type, params.response_mode.as_deref()).map_err(
        |description| {
            AuthRequestError::redirect(
                redirect_uri,
                default_mode,
                AuthzErrorCode::InvalidRequest,
                description,
            )
        },
    )?;

    // 4c. Enablement: `code` is always enabled; a legacy type not enabled in this
    //     environment is unsupported_response_type, by the negotiated mode.
    if !state.response_type_enabled(response_type) {
        return Err(AuthRequestError::redirect(
            redirect_uri,
            mode,
            AuthzErrorCode::UnsupportedResponseType,
            "the response_type is not enabled in this environment",
        ));
    }

    // 4d. nonce is REQUIRED for a front-channel ID token (OIDC Core 3.2.2.1 /
    //     3.3.2.1): it binds the ID token to this request and defends replay.
    let nonce = params
        .nonce
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if response_type.is_front_channel() && nonce.is_none() {
        return Err(AuthRequestError::redirect(
            redirect_uri,
            mode,
            AuthzErrorCode::InvalidRequest,
            "nonce is required for this response_type",
        ));
    }

    // Steps 5-5d (PKCE, claims, prompt/max_age, hints) run in the tail helper, which
    // assembles the ValidatedRequest. It is split out only to keep this validator
    // within the per-function length budget; the order and semantics are unchanged.
    validate_request_tail(
        state,
        client,
        params,
        redirect_uri,
        response_type,
        mode,
        nonce,
    )
}

/// The tail of the shared validator (steps 5-5d): PKCE, the `claims` request
/// parameter, `prompt`/`max_age`, and the interaction-hint seam. Any error redirects
/// by the already-negotiated `mode`. Split from [`validate_request`] only to satisfy
/// the per-function length budget; it is never called except from there.
fn validate_request_tail<'a>(
    state: &OidcState,
    client: &ClientRecord,
    params: &'a AuthorizeParams,
    redirect_uri: &'a str,
    response_type: ResponseType,
    mode: ResponseMode,
    nonce: Option<&'a str>,
) -> Result<ValidatedRequest<'a>, AuthRequestError> {
    // Every step below delivers its error as an invalid_request redirect by the
    // already-negotiated mode; this closure captures that one shape (both captures are
    // Copy, so it is reusable across the steps).
    let invalid = |description: &'static str| {
        AuthRequestError::redirect(
            redirect_uri,
            mode,
            AuthzErrorCode::InvalidRequest,
            description,
        )
    };

    // 5. PKCE (S256-only, mandatory; see resolve_pkce). A PUBLIC client always
    //    requires PKCE (RFC 9700 2.1.1); a CONFIDENTIAL client follows the
    //    per-environment policy, required by default.
    let is_public = client.auth_method == ClientAuthMethod::None.as_str();
    let pkce_required =
        response_type.issues_code() && (is_public || state.require_pkce_for_confidential());
    let code_challenge = resolve_pkce(params, pkce_required).map_err(invalid)?;
    let code_challenge_method = code_challenge.map(|_| PkceMethod::S256.as_str());

    // 5b. The OIDC `claims` request parameter (Core 5.5): parse and validate.
    let (claims_request, claims_canonical) =
        parse_claims_request(params.claims.as_deref()).map_err(invalid)?;

    // 5c. prompt and max_age (OIDC Core 3.1.2.1, issue #16).
    let prompt = parse_prompt(params.prompt.as_deref()).map_err(invalid)?;
    let max_age_secs = parse_max_age(params.max_age.as_deref()).map_err(invalid)?;

    // 5d. The typed interaction-hint seam (issue #16).
    let hints = InteractionHints::from_request(
        params.login_hint.as_deref(),
        params.logout_hint.as_deref(),
        params.ui_locales.as_deref(),
        params.claims_locales.as_deref(),
        params.display.as_deref(),
    );

    Ok(ValidatedRequest {
        redirect_uri,
        response_type,
        mode,
        nonce,
        code_challenge,
        code_challenge_method,
        claims_request,
        claims_canonical,
        prompt,
        max_age_secs,
        hints,
    })
}

/// Validate the request's `redirect_uri` against the client's registered set
/// (issue #13), BEFORE any redirect. It must be present, a registrable RFC 8252
/// target (a claimed https URL, an http loopback IP literal, or a reverse-domain
/// private-use scheme), and an EXACT-string match of a registered value (the only
/// deviation being the RFC 8252 loopback port exception, inside
/// [`redirect_uri_matches`]). Every failure returns a short, non-secret description
/// the caller renders as an error PAGE, never a redirect, so an unvalidated or
/// unregistered URI can never be turned into an open redirector.
fn validate_registered_redirect<'a>(
    client: &ClientRecord,
    params: &'a AuthorizeParams,
) -> Result<&'a str, &'static str> {
    let redirect_uri = params
        .redirect_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("the redirect_uri parameter is required")?;
    if !redirect_uri_is_registrable(redirect_uri) {
        return Err("the redirect_uri is invalid");
    }
    if !client
        .redirect_uris
        .iter()
        .any(|registered| redirect_uri_matches(registered, redirect_uri))
    {
        return Err("the redirect_uri is not registered for this client");
    }
    Ok(redirect_uri)
}

/// Validate and enforce the PKCE parameters (issue #13, RFC 7636 / RFC 9700),
/// returning the bound `code_challenge` (S256) or `None`.
///
/// S256 is the ONLY accepted method: `plain` is structurally unrepresentable, so
/// any other method (including `plain`) is rejected, and a challenge presented
/// without an explicit S256 method is refused too (RFC 7636 4.3 would default it
/// to the forbidden `plain`). A lone method with no challenge is malformed. When
/// `pkce_required` a missing challenge is refused. On any violation returns the
/// `invalid_request` description the caller sends by redirect.
fn resolve_pkce(
    params: &AuthorizeParams,
    pkce_required: bool,
) -> Result<Option<&str>, &'static str> {
    let named_method = params
        .code_challenge_method
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(method) = named_method {
        if PkceMethod::parse(method).is_none() {
            return Err("code_challenge_method must be S256");
        }
    }
    let code_challenge = match params.code_challenge.as_deref() {
        Some(challenge) if !challenge.is_empty() => {
            // A challenge requires an EXPLICIT S256 method (a defaulted `plain` is
            // forbidden).
            if named_method != Some(PkceMethod::S256.as_str()) {
                return Err("code_challenge_method must be S256");
            }
            // An S256 challenge is BASE64URL(SHA256(v)): exactly 43 unpadded
            // base64url chars (RFC 7636 4.2). Rejecting a malformed challenge here
            // turns a guaranteed-to-fail redemption into an honest, immediate
            // `invalid_request` and refuses a truncated/low-entropy binding.
            if !crate::pkce::code_challenge_is_well_formed(challenge) {
                return Err(
                    "code_challenge must be a 43-character base64url SHA-256 digest (S256)",
                );
            }
            Some(challenge)
        }
        _ => {
            if named_method.is_some() {
                return Err("code_challenge is required with code_challenge_method");
            }
            None
        }
    };
    if pkce_required && code_challenge.is_none() {
        return Err("PKCE is required: a code_challenge (S256) must be provided");
    }
    Ok(code_challenge)
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

/// The authorization error for an unmet essential-`acr` binding (OIDC Core 5.5.1.1,
/// issue #16), or [`None`] when the request's acr requirement is satisfied (or is
/// only a voluntary preference).
///
/// An ESSENTIAL acr with pinned values is binding. If NONE of the pinned values is
/// in the achievable set ([`authn::acr_values_supported`]), no method the server
/// offers can ever satisfy it, so it is `unmet_authentication_requirements`. If a
/// pinned value IS achievable in principle but not by THIS session's achieved acr (a
/// step-up, unreachable under the single-method bootstrap and owned by M7), it fails
/// closed via `access_denied`, preserving issue #15's fail-closed posture. A
/// voluntary or absent acr request is always satisfied (the achieved acr is reported
/// honestly, issue #14), so a preference-only `acr_values` never errors here.
fn acr_requirement_error(
    claims_request: &ClaimsRequest,
    auth_methods: &str,
) -> Option<(AuthzErrorCode, &'static str)> {
    let required = claims_request.essential_acr_values();
    if required.is_empty() {
        // No binding acr requirement: a voluntary/absent acr is best-effort.
        return None;
    }
    let supported = authn::acr_values_supported();
    let achievable = required
        .iter()
        .any(|value| supported.contains(&value.as_str()));
    if !achievable {
        return Some((
            AuthzErrorCode::UnmetAuthenticationRequirements,
            "no available authentication method can satisfy the requested acr",
        ));
    }
    let achieved = authn::achieved_acr(&authn::parse_methods(auth_methods));
    if required.iter().any(|value| value.as_str() == achieved) {
        None
    } else {
        Some((
            AuthzErrorCode::AccessDenied,
            "the requested authentication context (essential acr) cannot be satisfied",
        ))
    }
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

/// Resolve the login/consent gate for a validated request, applying `prompt` and
/// `max_age` (issue #16).
///
/// With no usable session it redirects to login (or registration for
/// `prompt=create`); with a session that `prompt=login`/`select_account`/`max_age`
/// mark stale it forces a fresh login; with a usable session it re-prompts consent
/// for `prompt=consent`, when none is recorded, or when the recorded consent does
/// NOT cover the requested scope (issue #196: a narrow prior consent never
/// auto-grants a broader request), and otherwise reports the request ready. Under
/// `prompt=none` NO UI is ever rendered: the matching `login_required` /
/// `consent_required` error is returned through the negotiated `mode` instead. A
/// consent-store failure is a `server_error` redirect (the `redirect_uri` is
/// already validated).
#[allow(clippy::too_many_arguments)]
async fn resolve_gate(
    state: &OidcState,
    headers: &HeaderMap,
    client_id: &ClientId,
    params: &AuthorizeParams,
    redirect_uri: &str,
    iss: &str,
    mode: ResponseMode,
    prompt: PromptSet,
    max_age_secs: Option<u64>,
    hints: &InteractionHints,
) -> Result<Gate, AuthorizeError> {
    // The scope is the one the client_id declares (fixed at validation).
    let scope = client_id.scope();
    let cookie = interaction::cookie_header(headers);
    let prompt_none = prompt.contains(PromptValue::None);
    // A negotiated-mode redirect error (redirect_uri is already validated), used for
    // the prompt=none surfaces so an interaction need becomes an error, never a page.
    let gate_error = |code: AuthzErrorCode, description: &str| AuthorizeError::Redirect {
        redirect_uri: redirect_uri.to_owned(),
        error: code,
        description: description.to_owned(),
        state: params.state.as_deref().map(str::to_owned),
        iss: iss.to_owned(),
        mode,
    };

    let Some(session) = interaction::resolve_session(state, scope, cookie).await else {
        // No usable session (absent, expired, or cross-scope).
        if prompt_none {
            return Err(gate_error(
                AuthzErrorCode::LoginRequired,
                "authentication is required but prompt=none forbids interaction",
            ));
        }
        // prompt=create routes an UNAUTHENTICATED user to registration; once a
        // session exists it is ignored, so registration never loops (its request is
        // preserved verbatim). The login path CONSUMES the re-auth forcing tokens
        // (login/select_account/max_age) so the fresh login does not re-force and
        // loop.
        let redirect = if prompt.contains(PromptValue::Create) {
            interaction::register_redirect(&preserve_resume_url(params, hints))
        } else {
            interaction::login_redirect(&login_resume_url(params, hints, prompt))
        };
        return Ok(Gate::Interaction(redirect));
    };

    // A session exists. Does prompt or max_age force fresh authentication?
    // select_account has no multi-session chooser in the bootstrap, so it degrades
    // to a forced re-login (the semantics and error codes stay correct).
    let now_micros = epoch_micros(state.now());
    let force_reauth = prompt.contains(PromptValue::Login)
        || prompt.contains(PromptValue::SelectAccount)
        || max_age_forces_reauth(max_age_secs, session.auth_time_unix_micros, now_micros);
    if force_reauth {
        if prompt_none {
            // prompt=none cannot combine with login/select_account (rejected at
            // parse), so a forced re-auth here is a max_age-stale session: the user
            // must re-authenticate, which prompt=none forbids.
            return Err(gate_error(
                AuthzErrorCode::LoginRequired,
                "re-authentication is required but prompt=none forbids interaction",
            ));
        }
        return Ok(Gate::Interaction(interaction::login_redirect(
            &login_resume_url(params, hints, prompt),
        )));
    }

    let client_id_str = client_id.to_string();
    let force_consent = prompt.contains(PromptValue::Consent);
    // Consent is recorded per (subject, client) TOGETHER with the scope it was
    // granted against (issue #196). A recorded consent authorizes a later request
    // only when that request's scope is a SUBSET of the granted scope (see
    // [`consent_covers_scope`]), so a consent for a narrow scope never silently
    // auto-grants a broader (or disjoint) one: an uncovered request is treated as
    // un-consented and re-prompts, exactly as a missing consent does.
    // prompt=consent forces a fresh screen regardless.
    let Ok(recorded) = state
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(&session.subject, &client_id_str)
        .await
    else {
        // A consent-store failure fails closed to a server_error redirect (the
        // redirect_uri is already validated).
        return Err(gate_error(
            AuthzErrorCode::ServerError,
            "the authorization request could not be processed",
        ));
    };

    if consent_covers_scope(recorded.as_ref(), params.scope.as_deref()) && !force_consent {
        // A recorded consent covers the requested scope and none is forced: ready.
        let consent_ref = recorded.expect("a covering consent is recorded").id;
        return Ok(Gate::Ready {
            session,
            consent_ref,
        });
    }

    // Consent is required: none recorded, the recorded one does not cover the
    // requested scope, or prompt=consent forced a fresh screen. Under prompt=none no
    // UI is rendered: the consent_required error goes back through the negotiated
    // mode instead (prompt=none cannot combine with prompt=consent, so a forced
    // screen never reaches here under it).
    if prompt_none {
        return Err(gate_error(
            AuthzErrorCode::ConsentRequired,
            "consent is required but prompt=none forbids interaction",
        ));
    }
    Ok(Gate::Interaction(interaction::consent_redirect(
        &consent_resume_url(params, hints, prompt),
    )))
}

/// Whether a recorded consent covers a request's `scope` (issue #196).
///
/// A consent covers the request only when the request's scope token set is a
/// SUBSET of the consent's granted scope set, both split on ASCII whitespace (the
/// OAuth scope grammar, matching the mint's own [`parse_scope_set`]) with an absent
/// value being the empty set. So a consent recorded for a narrow scope (for example
/// `openid`) does NOT cover a later broader request (`openid profile email`), which
/// must re-prompt; a same-or-narrower request stays covered. A missing consent
/// ([`None`]) covers nothing.
fn consent_covers_scope(recorded: Option<&GrantedConsent>, requested_scope: Option<&str>) -> bool {
    let Some(consent) = recorded else {
        return false;
    };
    let requested = parse_scope_set(requested_scope);
    let granted = parse_scope_set(consent.granted_scope.as_deref());
    requested.is_subset(&granted)
}

/// Parse the `prompt` request parameter into a [`PromptSet`] (issue #16). An absent
/// or blank value is the empty set (no prompt requested); otherwise the value is a
/// space-separated set whose one illegal combination (`none` with any other value)
/// or unrecognized token is a short `invalid_request` description.
fn parse_prompt(raw: Option<&str>) -> Result<PromptSet, &'static str> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => {
            PromptSet::parse(value).map_err(crate::registry::PromptSetError::as_description)
        }
        None => Ok(PromptSet::default()),
    }
}

/// Parse the `max_age` request parameter (issue #16). Returns [`None`] for an
/// absent or blank value, `Some(secs)` for a non-negative integer (including the
/// load-bearing `Some(0)`, which is distinguished from absent by this explicit
/// presence check rather than a truthiness test), and a short `invalid_request`
/// description for a non-integer value.
fn parse_max_age(raw: Option<&str>) -> Result<Option<u64>, &'static str> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => value
            .parse::<u64>()
            .map(Some)
            .map_err(|_| "max_age must be a non-negative integer number of seconds"),
        None => Ok(None),
    }
}

/// Whether `max_age` forces re-authentication of a session recorded at
/// `auth_time_micros`, evaluated at `now_micros` (both epoch microseconds, from the
/// clock seam). Absent `max_age` never forces re-auth. A present `max_age` (INCLUDING
/// `max_age=0`) forces re-auth when the session's authentication is strictly older
/// than the allowed window, so `max_age=0` behaves as `prompt=login` for any session
/// that was not authenticated at this very instant. A future-dated `auth_time` (an
/// artifact of a frozen test clock) yields a negative elapsed time and is never
/// stale.
fn max_age_forces_reauth(
    max_age_secs: Option<u64>,
    auth_time_micros: i64,
    now_micros: i64,
) -> bool {
    let Some(secs) = max_age_secs else {
        return false;
    };
    let elapsed_micros = now_micros.saturating_sub(auth_time_micros);
    let max_micros = i64::try_from(secs)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000_000);
    elapsed_micros > max_micros
}

/// Reconstruct the canonical `/authorize?...` URL from the request parameters, so
/// an interaction redirect can resume this exact request after login or consent.
///
/// The protocol parameters are carried from the RAW request (percent-encoding each)
/// so the resumed request is byte-for-byte equivalent whether the original arrived
/// as a GET or a POST. The NON-security interaction hints (`login_hint`,
/// `logout_hint`, `ui_locales`, `claims_locales`, `display`) are carried from the
/// typed [`InteractionHints`] seam (issue #16), which is their single source of
/// truth across the round-trip, so the interaction pages reconstruct them and a
/// malformed one (an unknown `display`) is simply not carried.
fn build_authorize_url(
    params: &AuthorizeParams,
    hints: &InteractionHints,
    prompt: Option<&str>,
    max_age: Option<&str>,
    emit_auth_time: bool,
) -> String {
    append_query(
        "/authorize",
        &[
            ("response_type", params.response_type.as_deref()),
            ("response_mode", params.response_mode.as_deref()),
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
            ("prompt", prompt),
            ("max_age", max_age),
            ("acr_values", params.acr_values.as_deref()),
            ("claims", params.claims.as_deref()),
            ("login_hint", hints.login_hint()),
            ("logout_hint", hints.logout_hint()),
            ("ui_locales", hints.ui_locales()),
            ("claims_locales", hints.claims_locales()),
            ("display", hints.display_param()),
            ("emit_auth_time", emit_auth_time.then_some("1")),
        ],
    )
}

/// The `/authorize` resume URL to send the user back to AFTER an interaction,
/// preserving the whole request verbatim (`prompt` and `max_age` unchanged). Used
/// where nothing is consumed (the registration deep-link, whose `prompt=create` is
/// already ignored once a session exists).
fn preserve_resume_url(params: &AuthorizeParams, hints: &InteractionHints) -> String {
    build_authorize_url(
        params,
        hints,
        params.prompt.as_deref(),
        params.max_age.as_deref(),
        false,
    )
}

/// The `/authorize` resume URL for a LOGIN interaction, with the re-auth forcing
/// conditions CONSUMED (issue #16): the `login` and `select_account` prompt tokens
/// are dropped and any `max_age` is removed, because the fresh authentication the
/// login performs satisfies every one of them, so the resumed request is not caught
/// in an infinite redirect loop. When a `max_age` is consumed the `emit_auth_time`
/// marker is set so the resumed request still carries the ID token's `auth_time`
/// that `max_age` required.
fn login_resume_url(
    params: &AuthorizeParams,
    hints: &InteractionHints,
    prompt: PromptSet,
) -> String {
    let residual = prompt
        .without(PromptValue::Login)
        .without(PromptValue::SelectAccount)
        .to_param();
    build_authorize_url(
        params,
        hints,
        residual.as_deref(),
        None,
        params.max_age.is_some(),
    )
}

/// The `/authorize` resume URL for a CONSENT interaction, with the `consent` prompt
/// token CONSUMED (issue #16) so the consent just recorded does not re-trigger a
/// consent loop. `max_age` is preserved (a consent step performs no
/// authentication, and a stale `max_age` would already have forced login first).
fn consent_resume_url(
    params: &AuthorizeParams,
    hints: &InteractionHints,
    prompt: PromptSet,
) -> String {
    let residual = prompt.without(PromptValue::Consent).to_param();
    build_authorize_url(
        params,
        hints,
        residual.as_deref(),
        params.max_age.as_deref(),
        false,
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
/// fresh expiry from the clock seam), persist them in one audited transaction, and
/// return the issued code string (the hybrid flow also hashes it into `c_hash`). A
/// store failure is a `server_error` returned by the negotiated `mode` (the
/// `redirect_uri` is valid).
async fn persist_code(
    state: &OidcState,
    scope: Scope,
    client_id: &ClientId,
    redirect_uri: &str,
    iss: &str,
    mode: ResponseMode,
    resolved: &Resolved<'_>,
) -> Result<String, AuthorizeError> {
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
            iss: iss.to_owned(),
            mode,
        });
    }

    Ok(code_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recorded session's `auth_time` (epoch micros) used by the `max_age`
    /// tests, chosen so a session is clearly in the past relative to a `now` after it.
    const AUTH_MICROS: i64 = 1_000_000_000_000_000;

    #[test]
    fn parse_prompt_accepts_the_set_and_rejects_none_combinations() {
        assert!(parse_prompt(None).expect("absent").is_empty());
        assert!(parse_prompt(Some("  ")).expect("blank").is_empty());
        let set = parse_prompt(Some("login consent")).expect("valid");
        assert!(set.contains(PromptValue::Login) && set.contains(PromptValue::Consent));
        assert!(
            parse_prompt(Some("create"))
                .expect("valid")
                .contains(PromptValue::Create)
        );
        assert!(
            parse_prompt(Some("none login")).is_err(),
            "none + other is invalid"
        );
        assert!(
            parse_prompt(Some("bogus")).is_err(),
            "unknown token is invalid"
        );
    }

    #[test]
    fn parse_max_age_distinguishes_zero_from_absent_and_rejects_non_integers() {
        // The integer-falsy trap: max_age=0 is PRESENT (Some(0)); absent is None.
        assert_eq!(parse_max_age(None), Ok(None), "absent max_age");
        assert_eq!(parse_max_age(Some("   ")), Ok(None), "blank is absent");
        assert_eq!(
            parse_max_age(Some("0")),
            Ok(Some(0)),
            "max_age=0 is present"
        );
        assert_eq!(parse_max_age(Some(" 3600 ")), Ok(Some(3600)));
        assert!(parse_max_age(Some("-1")).is_err(), "negative is invalid");
        assert!(
            parse_max_age(Some("soon")).is_err(),
            "non-integer is invalid"
        );
    }

    #[test]
    fn max_age_forces_reauth_guards_the_integer_falsy_trap() {
        let now = AUTH_MICROS + 100 * 1_000_000; // 100 seconds after authentication.
        // Absent max_age never forces re-auth, even for an old session.
        assert!(!max_age_forces_reauth(None, AUTH_MICROS, now));
        // max_age=0 (present) forces re-auth for any session not authenticated at
        // this very instant: it behaves as prompt=login.
        assert!(max_age_forces_reauth(Some(0), AUTH_MICROS, now));
        // A session younger than max_age is fresh; older is stale.
        assert!(!max_age_forces_reauth(Some(3600), AUTH_MICROS, now));
        assert!(max_age_forces_reauth(Some(60), AUTH_MICROS, now));
        // A session authenticated exactly now (or in the frozen-clock future) is
        // never stale, so a re-authenticated max_age=0 request does not loop.
        assert!(!max_age_forces_reauth(Some(0), now, now));
        assert!(!max_age_forces_reauth(Some(0), now + 1, now));
    }

    #[test]
    fn acr_requirement_error_is_unmet_only_when_no_method_can_satisfy() {
        use crate::claims_request::ClaimsRequest;

        // A voluntary acr_values-style request has no essential binding, so it never
        // errors (the achieved acr is reported honestly instead).
        let voluntary =
            ClaimsRequest::parse(r#"{"id_token":{"acr":{"values":["urn:example:high"]}}}"#)
                .expect("parse");
        assert!(acr_requirement_error(&voluntary, "pwd").is_none());

        // An essential acr pinned to a level NO method can achieve is
        // unmet_authentication_requirements.
        let unmet = ClaimsRequest::parse(
            r#"{"id_token":{"acr":{"essential":true,"values":["urn:example:high"]}}}"#,
        )
        .expect("parse");
        assert_eq!(
            acr_requirement_error(&unmet, "pwd").map(|(code, _)| code),
            Some(AuthzErrorCode::UnmetAuthenticationRequirements),
        );

        // An essential acr pinned to the achievable-and-achieved level is satisfied.
        let met = ClaimsRequest::parse(
            r#"{"id_token":{"acr":{"essential":true,"values":["urn:ironauth:acr:pwd"]}}}"#,
        )
        .expect("parse");
        assert!(acr_requirement_error(&met, "pwd").is_none());
    }

    #[test]
    fn consent_covers_scope_enforces_the_subset_rule() {
        // A consent recorded for a NARROW scope does not cover a BROADER request:
        // that is the #196 fix (a narrow prior consent must not auto-grant more).
        let narrow = GrantedConsent {
            id: "con_x".to_owned(),
            granted_scope: Some("openid".to_owned()),
        };
        assert!(!consent_covers_scope(
            Some(&narrow),
            Some("openid profile email")
        ));
        // The same or a narrower (subset) request stays covered.
        assert!(consent_covers_scope(Some(&narrow), Some("openid")));
        assert!(consent_covers_scope(Some(&narrow), None));

        // Set semantics: token ORDER and repeated whitespace do not matter, but a
        // token outside the granted set (address) is never covered.
        let broad = GrantedConsent {
            id: "con_y".to_owned(),
            granted_scope: Some("openid  profile   email".to_owned()),
        };
        assert!(consent_covers_scope(Some(&broad), Some("email openid")));
        assert!(!consent_covers_scope(Some(&broad), Some("openid address")));

        // A missing consent covers nothing; an absent granted_scope is the empty set
        // (covers only an empty request).
        assert!(!consent_covers_scope(None, Some("openid")));
        let unscoped = GrantedConsent {
            id: "con_z".to_owned(),
            granted_scope: None,
        };
        assert!(!consent_covers_scope(Some(&unscoped), Some("openid")));
        assert!(consent_covers_scope(Some(&unscoped), None));
    }
}
