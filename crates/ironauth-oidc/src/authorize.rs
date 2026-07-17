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

use axum::extract::{RawQuery, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    AuthorizationCodeId, ClientId, ClientRecord, ConsumePushedRequest, CorrelationId, GrantId,
    GrantedConsent, IssueCode, PushedRequestId, Scope, SessionId, StoreError, UserId,
    redirect_uri_is_registrable, redirect_uri_matches,
};
use serde::{Deserialize, Serialize};

use crate::authn;
use crate::broker_overlay;
use crate::claims_request::{ClaimsRequest, ClaimsRequestError};
use crate::client_auth::ClientAuthMethod;
use crate::consent::ConsentMode;
use crate::error::{AuthorizeError, AuthzErrorCode};
use crate::hints::InteractionHints;
use crate::interaction;
use crate::par::PAR_REQUEST_URI_PREFIX;
use crate::registry::{PkceMethod, PromptSet, PromptValue, ResponseMode, ResponseType};
use crate::resource;
use crate::response;
use crate::scope_claims::{assemble_claims, parse_scope_set};
use crate::session_mgmt;
use crate::state::{OidcState, ResourceTargetError};
use crate::step_up;
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
    /// An INTERNAL PAR-resume marker (RFC 9126, issue #27), NOT a client-facing
    /// parameter. A `request_uri` is PEEKED (read, not consumed) at every
    /// authorization hop, so its stored parameters are re-read verbatim after each
    /// login/consent interaction. When such an interaction CONSUMES a re-auth/consent
    /// forcing token (issue #16) whose stored value would otherwise re-force forever,
    /// the PAR resume URL sets this marker and carries the reduced `prompt`/`max_age`
    /// (and `emit_auth_time`); on the resumed hop those three fields, and ONLY those,
    /// are taken from the query rather than storage, so the interaction loop is
    /// broken. It can only ever RELAX a forcing token (or ADD the honest
    /// `emit_auth_time`), never widen the request, and it does NOT satisfy the
    /// require-PAR gate (that keys off the unforgeable `request_uri`), so a forged
    /// value is harmless. It is cleared before storage (a pushed request never
    /// carries it), so it is always [`None`] on a replayed request.
    pub par_resume: Option<String>,
    /// The RFC 8707 `resource` indicators (issue #28): the resource server(s) the
    /// eventual access token is for. The wire parameter `resource` MAY appear
    /// multiple times, which a scalar serde field cannot capture, so it is NOT
    /// deserialized from the query/form here (it stays `#[serde(default)]` empty on
    /// that path); the endpoint parses every `resource` value from the raw body and
    /// sets this field. It round-trips through PAR storage as a JSON array (`serde_json`
    /// handles the sequence), so a pushed request replays its resources verbatim.
    #[serde(default)]
    pub resources: Vec<String>,
}

/// `GET /authorize`.
///
/// The raw query is taken (via [`RawQuery`]) rather than a typed
/// `Query<AuthorizeParams>` so the RFC 8707 `resource` parameter, which MAY repeat
/// (issue #28) and cannot be captured by a scalar serde field, is parsed alongside
/// the typed fields from the SAME query string.
pub async fn authorize_get(
    State(state): State<OidcState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let raw = query.unwrap_or_default();
    let Ok(mut params) = serde_urlencoded::from_str::<AuthorizeParams>(&raw) else {
        return AuthorizeError::page("the authorization request could not be processed")
            .into_response();
    };
    params.resources = resource::resources_from_encoded(&raw);
    handle(&state, &headers, params).await
}

/// `POST /authorize`. Parses the raw form body the same way as [`authorize_get`],
/// so a repeated `resource` parameter (issue #28) is captured on the POST path too.
pub async fn authorize_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let Ok(mut params) = serde_urlencoded::from_str::<AuthorizeParams>(&body) else {
        return AuthorizeError::page("the authorization request could not be processed")
            .into_response();
    };
    params.resources = resource::resources_from_encoded(&body);
    handle(&state, &headers, params).await
}

/// Run the authorization request, returning the success redirect, an interaction
/// redirect (login/registration/consent), or an [`AuthorizeError`] (an error page
/// or an error redirect).
///
/// A PAR (RFC 9126, issue #27) `request_uri` is resolved FIRST: if the request
/// carries one, the referenced pushed request is READ (peeked, NOT consumed) from PAR
/// storage and its parameters REPLACE the presented ones, so the rest of the pipeline
/// runs on the pushed request. A [`PushedContext`] records that the request arrived
/// through PAR (so the require-PAR gate does not reject it) and carries the reference
/// forward so the single-use consume happens ATOMICALLY at code issuance.
async fn handle(state: &OidcState, headers: &HeaderMap, params: AuthorizeParams) -> Response {
    let (params, pushed) = match resolve_pushed_request(state, params).await {
        Ok(resolved) => resolved,
        Err(error) => return error.into_response(),
    };
    match issue_code(state, headers, params, pushed.as_ref()).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

/// The context of an authorization request that arrived through a PAR `request_uri`
/// (RFC 9126, issue #27): the reference was PEEKED (validated live and bound to the
/// presenting client) but NOT yet consumed, so a login/consent interaction can
/// re-present it and the single-use consume is deferred to code issuance.
struct PushedContext {
    /// The `par_` reference, for the atomic single-use consume at issuance.
    par_id: PushedRequestId,
    /// The full `request_uri` urn, re-presented verbatim on the interaction resume
    /// URL so the resumed hop resolves to the SAME pushed request.
    request_uri: String,
    /// The client the reference is bound to (the presenting `client_id`): the filter
    /// for BOTH the peek and the issuance-time consume, and the resume URL's
    /// `client_id`.
    presenting_client: String,
}

/// Resolve a PAR (RFC 9126, issue #27) `request_uri` to the pushed request it
/// references, or pass a plain request through unchanged.
///
/// When the request carries no `request_uri`, this returns `(params, None)`: a plain
/// authorization request. When it carries one, the reference is accepted ONLY in the
/// `urn:ietf:params:oauth:request_uri:<id>` form backed by PAR storage; an external
/// URI is a uniform `invalid_request` PAGE and is NEVER dereferenced over the network
/// (a documented, test-enforced non-goal). The referenced request is PEEKED (read,
/// NOT consumed), filtered on the PRESENTED `client_id`, so a forged reference, an
/// expiry, or a presentation under a different client all fail closed and none of
/// them burns another client's pending request (RFC 9126 client binding). Because the
/// peek does not consume, the SAME `request_uri` resolves again on every login/consent
/// resume hop; the single-use consume is deferred to code issuance ([`issue_code`]),
/// so a fresh-login user of a require-PAR client is not rejected mid-interaction.
///
/// On success the pushed parameters (an `AuthorizeParams` the PAR endpoint validated
/// and stored) REPLACE the presented ones (RFC 9126 section 4: the pushed values are
/// authoritative and the inline query is ignored), and a [`PushedContext`] is
/// returned. The ONE documented exception to that precedence is the internal
/// `par_resume` marker (see [`AuthorizeParams::par_resume`]): on a resume WE emitted,
/// the reduced `prompt`/`max_age`/`emit_auth_time` are taken from the query so the
/// issue #16 interaction loop is broken.
///
/// Every error here is a PAGE (not a redirect): the pushed request's own
/// `redirect_uri` is not trusted and the presented one is not yet validated, so there
/// is no trusted URI to send an error to.
async fn resolve_pushed_request(
    state: &OidcState,
    params: AuthorizeParams,
) -> Result<(AuthorizeParams, Option<PushedContext>), AuthorizeError> {
    let Some(request_uri) = params
        .request_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return Ok((params, None));
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
    // what binds the reference to the pushing client, so a different client cannot use
    // (or even reveal) the pending request.
    let Some(presented_client) = params
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        return Err(AuthorizeError::page("the client_id parameter is required"));
    };

    // The reference declares its own scope (a par_ scoped id), exactly as an
    // authorization code does, so the read runs under that scope with row-level
    // security. A malformed reference is a uniform miss (never an oracle).
    let Ok(par_id) = PushedRequestId::parse_declared_scope(reference) else {
        return Err(AuthorizeError::page(
            "the request_uri is invalid, expired, or already used",
        ));
    };
    let scope = par_id.scope();

    // PEEK, do not consume: read the stored parameters if the reference is LIVE
    // (unconsumed, unexpired) and bound to the presenting client. A miss (absent,
    // expired, already consumed, forged, or a different client) is the uniform
    // invalid_request page, and NO outbound fetch is ever performed. Single use is
    // enforced later, atomically, at code issuance.
    let request_params = match state
        .store()
        .scoped(scope)
        .pushed_authorization_requests()
        .read(state.env(), &par_id, &presented_client)
        .await
    {
        Ok(Some(request_params)) => request_params,
        Ok(None) => {
            return Err(AuthorizeError::page(
                "the request_uri is invalid, expired, or already used",
            ));
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to read a pushed authorization request");
            return Err(AuthorizeError::page(
                "the authorization request could not be processed",
            ));
        }
    };

    // The stored parameters ARE an AuthorizeParams (validated at push time).
    let mut stored: AuthorizeParams = serde_json::from_str(&request_params)
        .map_err(|_| AuthorizeError::page("the authorization request could not be processed"))?;

    // RFC 9126 section 4: the pushed values win; the inline query is ignored. The ONE
    // exception is the internal PAR-resume marker: on a login/consent resume WE
    // emitted (par_resume=1), the reduced prompt/max_age and the emit_auth_time marker
    // are authoritative from the query so the issue #16 interaction loop is broken.
    // These only relax a forcing token or add an honest claim; every
    // security-relevant parameter still comes from storage.
    if params.par_resume.as_deref() == Some("1") {
        stored.prompt = params.prompt;
        stored.max_age = params.max_age;
        stored.emit_auth_time = params.emit_auth_time;
    }

    let context = PushedContext {
        par_id,
        request_uri,
        presenting_client: presented_client,
    };
    Ok((stored, Some(context)))
}

/// Atomically consume the pushed request behind `context` at the moment of code
/// issuance (RFC 9126, issue #27), returning whether this call WON the single-use
/// race. The `client_id` filter is inside the atomic consume, so the binding holds and
/// a reference presented under a different client (or already consumed, or expired)
/// wins zero rows and returns `false`. The consume writes its audit row (target =
/// the real `par_id`) in the same transaction, on the winning branch only.
async fn consume_pushed_request(
    state: &OidcState,
    scope: Scope,
    client_id: &ClientId,
    context: &PushedContext,
) -> Result<bool, AuthorizeError> {
    // Attribute the consume audit to the client the code is for, exactly as the code
    // issue audit is (the client_id is validated in scope by this point).
    let actor = client_service_actor(client_id);
    let correlation = CorrelationId::generate(state.env());
    match state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .pushed_authorization_requests()
        .consume(state.env(), &context.par_id, &context.presenting_client)
        .await
    {
        Ok(ConsumePushedRequest::Consumed { .. }) => Ok(true),
        Ok(ConsumePushedRequest::Invalid) => Ok(false),
        Err(error) => {
            tracing::error!(error = %error, "failed to consume a pushed authorization request at issuance");
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
    pushed: Option<&PushedContext>,
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

    // 2a. Tenant/environment quota (issue #50). The quota is charged ONLY here, AFTER
    //     the client has been confirmed to exist in its declared scope, so a spend
    //     draws exclusively on a VERIFIED, real (tenant, environment). A well-formed
    //     but unregistered client_id (whose declared scope is attacker-chosen and
    //     unauthenticated: any random bytes decode to a valid-looking scope) is
    //     rejected by the not-found path above and NEVER reaches a spend. Charging
    //     only a verified scope restores the engine's "an unknown scope is rejected
    //     before it reaches a spend" invariant, so an attacker cannot (a) allocate an
    //     unbounded set of buckets with random scopes (a memory-exhaustion DoS), nor
    //     (b) drain a victim tenant's shared bucket by spoofing the victim's tenant id
    //     with fabricated environments. A denied spend short-circuits with a 429
    //     carrying the RateLimit headers and block signal; nesting means an
    //     environment draws from its tenant too, and the buckets are per-scope, so one
    //     tenant's flood never starves another's login. Under quota (or with no
    //     enforcer installed) the request proceeds untouched.
    if let Some(response) = state.enforce_request_quota(&scope) {
        return Ok(response);
    }

    // 2b. require-PAR gate (RFC 9126 sections 5 and 6, issue #27). When the
    //     environment-wide switch OR this client's registration flag requires a
    //     pushed authorization request, a plain (non-PAR) request is rejected with
    //     invalid_request. A request that arrived THROUGH PAR (a resolved
    //     [`PushedContext`], keyed off the unforgeable `request_uri`) satisfies the
    //     requirement and is exempt, at the FIRST hop and at every login/consent
    //     resume hop alike (the reference is peeked, not consumed, so it resolves
    //     again each time). This runs BEFORE the redirect_uri is validated, so it is a
    //     PAGE error, never an open-redirector-able redirect.
    if pushed.is_none()
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

    // The effective granted scope (issue #21): offline_access is IGNORED on a flow
    // that does not return an authorization code (only the code flow reaches the
    // token endpoint to redeem a refresh token), so it is stripped there and never
    // treated as granted, echoed as granted, or requiring consent. The rest of the
    // request (redirect_uri, response_type, mode, nonce, PKCE, claims, prompt,
    // max_age, hints) was validated by the shared validate_request above (issue #27).
    let requested_scope = params
        .scope
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let effective_scope = effective_granted_scope(requested_scope, response_type.issues_code());

    // 5e. RFC 8707 resource indicators (issue #28): validate the requested resources
    //     and freeze the APPROVED set onto the grant and code as the downscope ceiling
    //     the token/refresh endpoints enforce. Each resource must be a valid absolute
    //     URI (no fragment), on the client's allowlist, and a registered resource
    //     server; a client whose policy REFUSES a no-resource request must name at
    //     least one. Every violation is `invalid_target`, delivered through the
    //     negotiated mode (the redirect_uri is validated by now). This runs before the
    //     login/consent gate so a rejection never triggers an interaction.
    validate_authorize_resources(state, scope, &client_id, &params.resources)
        .await
        .map_err(|code| {
            redirect_error(
                code,
                "the requested resource is invalid, unknown, or not allowed",
            )
        })?;

    // 6. Establish the authenticated subject and their consent, applying prompt and
    //    max_age. A missing session, missing consent, or a forced (re-)authentication
    //    short-circuits to a LOCAL interaction redirect (never the client's
    //    redirect_uri), carrying a return_to that resumes this exact request. Under
    //    prompt=none no UI is ever rendered: the matching login_required /
    //    consent_required error is returned through the negotiated mode instead.
    let (session, consent_ref) = match resolve_gate(
        state,
        headers,
        &client,
        &client_id,
        &params,
        effective_scope.as_deref(),
        redirect_uri,
        &iss,
        mode,
        prompt,
        max_age_secs,
        &hints,
        pushed,
    )
    .await?
    {
        Gate::Interaction(response) => return Ok(response),
        Gate::Ready {
            session,
            consent_ref,
        } => (session, consent_ref),
    };

    // 6b. Step-up authentication (RFC 9470, issue #72). Assemble the effective
    //     authentication requirement from the request `acr_values`/`max_age`, the
    //     per-client floor, the per-scope tenant policy, and any ESSENTIAL `acr` in
    //     the `claims` parameter (OIDC Core 5.5.1.1). If the CURRENT session does not
    //     satisfy it, RUN the required authentication (a second-factor challenge or a
    //     full re-login) rather than silently reusing the session or issuing an
    //     under-qualified token; when the requirement can NEVER be met, fail per RFC
    //     9470 with `unmet_authentication_requirements`. The achieved `acr` always
    //     reflects the real authentication event (issue #14), never a copied-through
    //     request value, so a stepped-up token is honest.
    let (step_up_age_bound, auth_methods_override) = match evaluate_step_up(
        state,
        scope,
        &client,
        effective_scope.as_deref(),
        &params,
        max_age_secs,
        &claims_request,
        &session,
        prompt,
        &hints,
        pushed,
        headers,
    )
    .await
    {
        StepUpOutcome::Satisfied {
            age_bound,
            auth_methods,
        } => (age_bound, auth_methods),
        StepUpOutcome::Interaction(response) => return Ok(response),
        StepUpOutcome::Fail(code, description) => return Err(redirect_error(code, description)),
    };

    // 7. Freeze the authentication context. auth_time is emitted in the ID token
    //    when the request asked for max_age (present, including max_age=0) OR the
    //    client registered require_auth_time OR a login interaction CONSUMED a
    //    max_age to break the re-auth loop (the emit_auth_time resume marker, issue
    //    #16), so a max_age request still yields auth_time even after the max_age
    //    itself was dropped from the resumed URL. The value is always the truthful
    //    recorded instant, so it is frozen only when it is due. The recorded methods
    //    are always frozen so amr/acr can be derived. acr_values is honored as a
    //    preference only: the achieved acr comes from the event, never the request.
    let auth_time_required = max_age_secs.is_some()
        || client.require_auth_time
        || params.emit_auth_time.is_some()
        // A step-up max-age policy (per-client or per-scope, issue #72) also requires
        // freezing auth_time so the refresh path can re-evaluate the window against
        // it; without this a max-age policy would fail closed at the token endpoint
        // even for a session that was fresh at authorization.
        || step_up_age_bound;
    let auth_time_micros = auth_time_required.then_some(session.auth_time_unix_micros);

    let session_ref = session.session_id.to_string();
    // A remembered device that satisfied the tenant baseline MFA floor (issue #71)
    // upgrades the frozen methods to the honest `[<primary>, trusted_device]` token, so
    // the code (and the minted ID/access token) records the trusted-device contribution
    // (acr `mfa_remembered`, no fabricated `mfa` amr). Otherwise the session's recorded
    // methods are frozen verbatim.
    let frozen_auth_methods = auth_methods_override
        .as_deref()
        .unwrap_or(&session.auth_methods);
    let resolved = Resolved {
        nonce,
        oauth_scope: effective_scope.as_deref(),
        code_challenge,
        code_challenge_method,
        state_echo,
        subject: &session.subject,
        auth_methods: frozen_auth_methods,
        auth_time_micros,
        session_ref: &session_ref,
        consent_ref: consent_ref.as_deref(),
        claims_request: claims_canonical.as_deref(),
        granted_resources: &params.resources,
    };

    // 7b. Single-use PAR consume at the moment of issuance (RFC 9126, issue #27).
    //     The `request_uri` was PEEKED (read, not consumed) at every hop so the
    //     login/consent interaction could re-present it. Now that an authenticated,
    //     consenting subject is about to receive a code, consume it ATOMICALLY,
    //     exactly once, with the client_id filter INSIDE the consume (the binding
    //     holds here too). A concurrent or prior issuance (or an expiry) that already
    //     consumed it wins the race and this one fails closed, so a `request_uri`
    //     yields AT MOST ONE code. This runs AFTER the interactive gate (the
    //     sign-before-consume discipline the code redeem uses), so a login or consent
    //     round-trip never burns the pending request; the consume's audit row is
    //     written on the winning branch only.
    if let Some(context) = pushed {
        if !consume_pushed_request(state, scope, &client_id, context).await? {
            return Err(AuthorizeError::page(
                "the request_uri is invalid, expired, or already used",
            ));
        }
    }

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

    // OIDC Session Management 1.0 (issue #39): emit session_state ONLY when session
    // management is enabled for this deployment. It is a one-way keyed digest of the
    // client, the RP origin, and the session (never the session id itself), so the RP
    // can seed its check_session_iframe poll. Off by default: the parameter is absent
    // and the response is byte-identical to before the feature.
    let session_state_value = state.session_management_enabled().then(|| {
        session_mgmt::authorization_session_state(
            state,
            &iss,
            &client_id.to_string(),
            redirect_uri,
            &session_ref,
        )
    });

    let params = response::success_params(
        code.as_deref(),
        id_token.as_deref(),
        state_echo,
        &iss,
        session_state_value.as_deref(),
    );
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

/// Resolve the per-(client, session) `sid` for a FRONT-CHANNEL (implicit / hybrid) ID
/// token (issue #32), from the SSO session that just authenticated this authorization.
///
/// This is the same `ensure_sid` on the same (client, session) pair the token endpoint
/// calls, so the `sid` a client sees on an implicit ID token is IDENTICAL to the one it
/// would see on a code-flow ID token for that session: back-channel logout can target
/// the client either way, and the two flows never disagree about the OP session.
///
/// Fails CLOSED (`Err(())`, a `server_error`): a store failure must not silently emit
/// an ID token with no `sid`, which would look like a success while quietly leaving the
/// client untargetable by back-channel logout.
async fn resolve_front_channel_sid(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    resolved: &Resolved<'_>,
) -> Result<String, ()> {
    let session_id = SessionId::parse_in_scope(resolved.session_ref, &scope).map_err(|_| ())?;
    let now_micros = epoch_micros(state.now());
    state
        .store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(state.env(), &session_id, client_id, now_micros)
        .await
        .map_err(|_| ())
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
    // The per-client `sid` (issue #32), resolved from the SAME authenticating SSO
    // session and through the SAME (client, session) row the token endpoint uses, so an
    // implicit/hybrid ID token carries the SAME sid the code flow would issue for this
    // pair. Discovery advertises backchannel_logout_session_supported unconditionally;
    // omitting sid here would make that advertisement FALSE for every legacy
    // response_type and leave those clients untargetable by back-channel logout.
    //
    // Fails CLOSED: a store error is Err(()) (a server_error through the negotiated
    // response mode), never a silently session-less ID token.
    let sid = resolve_front_channel_sid(state, scope, &client_id_str, resolved).await?;
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
        sid: Some(sid.as_str()),
        at_hash: None,
        c_hash: c_hash.as_deref(),
        extra_claims: &extra_claims,
        // The front channel signs with the environment default (a DCR client, which
        // is the only client carrying a per-client id_token algorithm, registers
        // `response_types = ["code"]` only and so never reaches this path); the
        // `c_hash` above is derived from the same `signer`.
        id_token_signer: None,
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
    // Unverified-client quarantine (issue #31): a quarantined client's EFFECTIVE
    // redirect set is RESTRICTED to its https targets, so a native/loopback or
    // custom-scheme redirect (the higher-interception-risk shapes for an unverified
    // app) is refused at authorize time until an admin verifies the client. This is
    // a PAGE error (it runs before the redirect target is trusted), never a redirect,
    // so it can never be turned into an open redirector. Verification lifts it.
    if client.quarantined && !is_https_redirect(redirect_uri) {
        return Err("the redirect_uri is not permitted for an unverified client");
    }
    Ok(redirect_uri)
}

/// Whether `uri` uses the https scheme (case-insensitive), the only redirect shape
/// a quarantined client may use until it is verified (issue #31).
fn is_https_redirect(uri: &str) -> bool {
    uri.split_once(':')
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
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
/// The outcome of the step-up evaluation (RFC 9470, issue #72).
enum StepUpOutcome {
    /// The current session satisfies the requirement; issue the code. `age_bound` is
    /// true when a max-age step-up requirement applied, so the code MUST freeze
    /// `auth_time` (the refresh path re-evaluates the window against it).
    Satisfied {
        /// Whether a max-age requirement applied (forces freezing `auth_time`).
        age_bound: bool,
        /// An OVERRIDE of the methods to freeze onto the code (issue #71): `Some` when a
        /// remembered device satisfied the tenant baseline MFA floor, carrying the
        /// upgraded `[<primary>, trusted_device]` token so the code (and thus the ID
        /// token) honestly records the trusted-device contribution (acr `mfa_remembered`,
        /// no fabricated `mfa` amr). `None` uses the session's recorded methods verbatim.
        auth_methods: Option<String>,
    },
    /// A local interaction is needed (a second-factor challenge or a full re-login).
    Interaction(Response),
    /// The requirement cannot be met; fail with this authorization error, delivered
    /// through the negotiated response mode.
    Fail(AuthzErrorCode, &'static str),
}

/// Evaluate step-up authentication for a validated, authenticated request (RFC
/// 9470, issue #72).
///
/// Assembles the effective requirement (request `acr_values`/`max_age`, the
/// per-client floor, the per-scope tenant policy, and any essential `acr` from the
/// `claims` parameter), compares it against the CURRENT session's achieved `acr`
/// and recorded `auth_time` (both derived from the real authentication event, issue
/// #14), and either reports the request ready, redirects to run the required
/// authentication, or fails per spec. Under `prompt=none` an interaction need
/// becomes the matching negotiated-mode error rather than a page.
// The step-up composition (explicit floors, the tenant baseline MFA floor, the
// conditional-credential skip, and the remembered-device path, issues #72/#66/#71) reads
// best as one gate: the ORDER of the checks is the security property, so splitting it
// would scatter the precedence across helpers.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn evaluate_step_up(
    state: &OidcState,
    scope: Scope,
    client: &ClientRecord,
    effective_scope: Option<&str>,
    params: &AuthorizeParams,
    max_age_secs: Option<u64>,
    claims_request: &ClaimsRequest,
    session: &interaction::AuthenticatedSession,
    prompt: PromptSet,
    hints: &InteractionHints,
    pushed: Option<&PushedContext>,
    headers: &HeaderMap,
) -> StepUpOutcome {
    let order = state.acr_order();
    // Assemble the requirement from the request, the client floor, and the per-scope
    // policy, then fold in any ESSENTIAL acr from the `claims` parameter (the
    // strongest listed value is the floor).
    // Authorize is the PRIMARY gate and re-runs on every request, so a transient
    // policy-read fault is best-effort here (ignored); the token/refresh path fails
    // closed on it (issue #72 INFO).
    let assembled = step_up::requirement_for_request(
        state,
        scope,
        client,
        effective_scope,
        params.acr_values.as_deref(),
        max_age_secs,
    )
    .await;
    let mut requirement = assembled.requirement;
    let mfa_baseline_required = assembled.mfa_baseline_required;
    let essential = claims_request.essential_acr_values();
    if !essential.is_empty() {
        let essential_join = essential.join(" ");
        requirement.merge_stronger(
            &step_up::requirement_from_acr_values(Some(&essential_join), None, &order),
            &order,
        );
    }

    // Risk-forced step-up (issue #79): when the minimal risk engine scores this login at or
    // above the configured `oidc.risk.require_mfa_at` threshold, RAISE the effective
    // requirement to the MFA floor, so the SAME step-up gate challenges a second factor
    // (the score is available WHEREVER step-up policy is evaluated). It composes with every
    // other source through `merge_stronger`, so a stronger explicit floor still wins, and a
    // session that already achieved MFA is Satisfied. Inert when the engine is off or the
    // threshold is `off`, so this adds nothing on the default posture.
    if state.risk_enabled() {
        if let Ok(risk_subject) = UserId::parse_in_scope(&session.subject, &scope) {
            let risk_ip = crate::abuse::resolved_client_ip(headers);
            let risk_ua = headers
                .get(axum::http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("unknown");
            let risk_ctx = crate::risk::RiskContext {
                ip: risk_ip.as_deref(),
                user_agent: risk_ua,
                headers,
            };
            if crate::risk::forces_step_up(state, scope, &risk_subject, &risk_ctx).await {
                requirement.merge_stronger(
                    &step_up::AuthnRequirement {
                        min_acr: Some(authn::acr_for_mfa().to_owned()),
                        max_auth_age_secs: None,
                    },
                    &order,
                );
            }
        }
    }

    // The subject the overlay lookup, the factor probe, and the trusted-device validation
    // bind to. A session subject that will not parse in scope cannot be probed, so the
    // requirement can never be met here.
    let Ok(subject) = UserId::parse_in_scope(&session.subject, &scope) else {
        return StepUpOutcome::Fail(
            AuthzErrorCode::UnmetAuthenticationRequirements,
            "the requested authentication context cannot be satisfied",
        );
    };

    // Broker overlay (issue #77 PR 2): the session subject's STAMPED org connection may
    // layer an MFA / passkey / max-age policy ON TOP of the (possibly permissive) upstream
    // that authenticated it. It composes through the SAME strongest-wins merge as every
    // other floor, so a stronger client or scope requirement is never weakened. It is
    // enforced HERE, at the single non-bypassable gate that re-runs on every authorization
    // request, so a user cannot skip a federation-callback redirect and reach a code at
    // the unranked federated acr. The stamped org connection id was written FROM the
    // consumed, single-use correlation row (PR 1), never a browser value, so the overlay
    // source is server-authenticated. A store fault FAILS CLOSED: an org's overlay must
    // never be silently skipped because a read blipped.
    match broker_overlay::requirement_for_session_org(state, scope, &subject, &order).await {
        Ok(overlay) => requirement.merge_stronger(&overlay, &order),
        Err(()) => {
            return StepUpOutcome::Fail(
                AuthzErrorCode::UnmetAuthenticationRequirements,
                "the broker overlay policy could not be evaluated",
            );
        }
    }

    let age_bound = requirement.max_auth_age_secs.is_some();

    // The recorded methods drive both the achieved acr (the EXPLICIT step-up floors) and
    // whether a GENUINE second factor was performed (the tenant baseline MFA floor,
    // issue #71).
    let methods = authn::parse_methods(&session.auth_methods);
    let achieved = authn::achieved_acr(&methods);
    let now_micros = epoch_micros(state.now());

    // 1. The EXPLICIT step-up requirement (request acr_values / max_age, client floor,
    //    per-scope policy, essential claims, and the passkey/attested credential-class
    //    floors). A remembered device NEVER satisfies any of these: RFC 9470 / issue #72
    //    ALWAYS overrides a remembered device, and a trusted device can never stand in
    //    for a phishing-resistant passkey. So this is evaluated FIRST and, if it needs a
    //    step-up, the trusted-device path is not even consulted.
    let explicit_step_up = if requirement.is_empty() {
        None
    } else {
        match step_up::evaluate(
            &requirement,
            achieved,
            Some(session.auth_time_unix_micros),
            now_micros,
            &order,
        ) {
            step_up::Satisfaction::Satisfied => None,
            step_up::Satisfaction::NeedsStepUp {
                acr_unmet,
                age_lapsed,
            } => Some((acr_unmet, age_lapsed)),
        }
    };

    // 2. Compose the requirement to remediate. The explicit step-up (if any) is stricter
    //    and takes precedence. Otherwise, when the tenant baseline MFA floor applies and
    //    the login did NOT perform a genuine second factor (issue #71: a bare password or
    //    a PRESENCE-ONLY passkey), a valid remembered-device cookie SATISFIES the baseline
    //    (the second factor is skipped and the token honestly records the trusted-device
    //    contribution), and otherwise a real second factor must be challenged. A UV
    //    passkey and a real TOTP/recovery code already `performed_second_factor`, so they
    //    satisfy the baseline with NO extra prompt (the conditional-credential skip).
    let remediation = if let Some((acr_unmet, age_lapsed)) = explicit_step_up {
        step_up::decide_remediation(state, scope, &subject, &requirement, acr_unmet, age_lapsed)
            .await
    } else if mfa_baseline_required && !authn::performed_second_factor(&methods) {
        // The tenant baseline MFA floor is unmet by a genuine factor. A valid remembered
        // device satisfies it: consume the device (sliding its idle window), UPGRADE the
        // frozen methods to record the honest `[<primary>, TrustedDevice]` contribution
        // (acr `mfa_remembered`, no fabricated `mfa` amr), and issue the code.
        if crate::trusted_device::validate_and_consume(state, scope, &subject, headers)
            .await
            .is_some()
        {
            let upgraded = authn::AuthenticationEvent::with_trusted_device(
                &methods,
                session.auth_time_unix_micros,
            );
            return StepUpOutcome::Satisfied {
                age_bound,
                auth_methods: Some(upgraded.methods_token()),
            };
        }
        // No trusted device: a genuine second factor must be proven. Route through the
        // SAME remediation machinery with a synthetic `mfa` floor, so an enrolled TOTP is
        // a live second-factor challenge, a passkey holder runs the passkey ceremony, and
        // an unenrolled subject is steered to enrollment (or fails closed).
        let mfa_requirement = step_up::AuthnRequirement {
            min_acr: Some(authn::acr_for_mfa().to_owned()),
            max_auth_age_secs: None,
        };
        step_up::decide_remediation(state, scope, &subject, &mfa_requirement, true, false).await
    } else {
        // Every applicable requirement is satisfied by the login as it stands.
        return StepUpOutcome::Satisfied {
            age_bound,
            auth_methods: None,
        };
    };

    // Under prompt=none NO UI is rendered: an interaction need becomes the matching
    // negotiated-mode error (OIDC Core 3.1.2.6, RFC 9470).
    if prompt.contains(PromptValue::None) {
        return match remediation {
            step_up::Remediation::Fail | step_up::Remediation::Enroll => StepUpOutcome::Fail(
                AuthzErrorCode::UnmetAuthenticationRequirements,
                "the requested authentication context cannot be satisfied without interaction",
            ),
            step_up::Remediation::FullReauth => StepUpOutcome::Fail(
                AuthzErrorCode::LoginRequired,
                "re-authentication is required but prompt=none forbids interaction",
            ),
            step_up::Remediation::PasskeyReauth => StepUpOutcome::Fail(
                AuthzErrorCode::LoginRequired,
                "a passkey ceremony is required but prompt=none forbids interaction",
            ),
            step_up::Remediation::SecondFactor => StepUpOutcome::Fail(
                AuthzErrorCode::InteractionRequired,
                "a second-factor step-up is required but prompt=none forbids interaction",
            ),
        };
    }

    match remediation {
        // A full re-login: consume the request's re-auth forcing tokens so the
        // resumed request does not loop, exactly like the max_age gate.
        step_up::Remediation::FullReauth => StepUpOutcome::Interaction(
            interaction::login_redirect(&login_resume_url(params, hints, prompt, pushed)),
        ),
        // A phishing-resistant floor (phr/phrh), or an mfa floor the subject can only
        // reach with a passkey: run the passkey ceremony SPECIFICALLY, never the generic
        // login (a password re-login yields pwd and would loop). Completing the passkey
        // ceremony yields phr, which satisfies the floor, so the resumed request proceeds
        // and the flow TERMINATES.
        step_up::Remediation::PasskeyReauth => StepUpOutcome::Interaction(
            interaction::passkey_reauth_redirect(&login_resume_url(params, hints, prompt, pushed)),
        ),
        // A second-factor challenge against the LIVE session: resume the request
        // verbatim (the acr is elevated by the challenge, so it does not loop).
        step_up::Remediation::SecondFactor => StepUpOutcome::Interaction(
            interaction::mfa_challenge_redirect(&preserve_resume_url(params, hints, pushed), false),
        ),
        // No qualifying factor, but enrollment is allowed: the challenge page
        // surfaces the enrollment prompt.
        step_up::Remediation::Enroll => StepUpOutcome::Interaction(
            interaction::mfa_challenge_redirect(&preserve_resume_url(params, hints, pushed), true),
        ),
        // The requirement can never be met: RFC 9470 unmet_authentication_requirements.
        step_up::Remediation::Fail => StepUpOutcome::Fail(
            AuthzErrorCode::UnmetAuthenticationRequirements,
            "no available authentication method can satisfy the requested authentication context",
        ),
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
        /// The recorded consent handle (referenced by the grant), or [`None`] when
        /// a skipped consent was NOT stored (the no-store performance knob, issue
        /// #21), in which case the grant records no consent reference.
        consent_ref: Option<String>,
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
    client: &ClientRecord,
    client_id: &ClientId,
    params: &AuthorizeParams,
    effective_scope: Option<&str>,
    redirect_uri: &str,
    iss: &str,
    mode: ResponseMode,
    prompt: PromptSet,
    max_age_secs: Option<u64>,
    hints: &InteractionHints,
    pushed: Option<&PushedContext>,
) -> Result<Gate, AuthorizeError> {
    // The scope is the one the client_id declares (fixed at validation).
    let scope = client_id.scope();
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

    let Some(session) = interaction::resolve_session(state, scope, headers).await else {
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
            interaction::register_redirect(&preserve_resume_url(params, hints, pushed))
        } else {
            interaction::login_redirect(&login_resume_url(params, hints, prompt, pushed))
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
            &login_resume_url(params, hints, prompt, pushed),
        )));
    }

    // The session is fresh enough; the remaining gate is consent (issue #21 folds
    // the first-party carve-out, the remembered TTL, and the offline_access rule in).
    resolve_consent_gate(
        state,
        client,
        client_id,
        params,
        effective_scope,
        session,
        prompt,
        hints,
        redirect_uri,
        iss,
        mode,
        pushed,
    )
    .await
}

/// Resolve the consent gate for an authenticated, fresh-enough session (issue #21).
///
/// A trusted first-party client (`implicit` mode or `skip_consent`) is auto-granted,
/// which also satisfies the `offline_access` consent requirement; the skipped consent
/// is recorded unless the no-store knob is off. Otherwise a recorded consent
/// authorizes the request only when it is unexpired (a `remembered` consent lapses
/// after its TTL) AND covers the requested scope as a subset (issue #196), where
/// `offline_access` is part of the check for a web client unless the environment
/// disables it. `prompt=consent` forces a fresh screen; `prompt=none` turns an
/// interaction need into the matching negotiated-mode error.
#[allow(clippy::too_many_arguments)]
async fn resolve_consent_gate(
    state: &OidcState,
    client: &ClientRecord,
    client_id: &ClientId,
    params: &AuthorizeParams,
    effective_scope: Option<&str>,
    session: interaction::AuthenticatedSession,
    prompt: PromptSet,
    hints: &InteractionHints,
    redirect_uri: &str,
    iss: &str,
    mode: ResponseMode,
    pushed: Option<&PushedContext>,
) -> Result<Gate, AuthorizeError> {
    let scope = client_id.scope();
    let prompt_none = prompt.contains(PromptValue::None);
    let gate_error = |code: AuthzErrorCode, description: &str| AuthorizeError::Redirect {
        redirect_uri: redirect_uri.to_owned(),
        error: code,
        description: description.to_owned(),
        state: params.state.as_deref().map(str::to_owned),
        iss: iss.to_owned(),
        mode,
    };
    let client_id_str = client_id.to_string();
    // `prompt=consent` forces a fresh consent screen. A QUARANTINED (unverified,
    // possibly phishing) client ALWAYS re-prompts too (issue #31, FIX 4): consent is
    // shown on EVERY authorization until an admin verifies it. This is what disables
    // the recorded-consent fast path below (`covered && !force_consent`) for a
    // quarantined client, so a PRE-RECORDED consent can never silently auto-authorize
    // it; the first-party carve-out block already refuses its implicit/skip_consent
    // auto-grant. Verification flips `quarantined` off and restores both.
    let force_consent = prompt.contains(PromptValue::Consent) || client.quarantined;
    let consent_mode = ConsentMode::parse(&client.consent_mode);
    // The trusted first-party carve-out: an `implicit`-mode client, or one whose
    // `skip_consent` flag is set, never sees the consent screen and is auto-granted.
    // `prompt=consent` still forces a fresh screen, so it wins over the carve-out.
    //
    // Unverified-client quarantine (issue #31): a quarantined client NEVER gets the
    // first-party carve-out. Its `implicit`/`skip_consent`/first-party trust is
    // IGNORED and consent is ALWAYS shown, until an admin verifies it (which flips
    // `quarantined` off and restores the carve-out).
    let first_party = !client.quarantined
        && (matches!(consent_mode, ConsentMode::Implicit) || client.skip_consent);
    if first_party && !force_consent {
        // Record the skipped consent so an offline grant stays enumerable and
        // revocable per app, UNLESS the no-store performance knob is off.
        let consent_ref = if client.store_skipped_consent {
            match record_skipped_consent(
                state,
                scope,
                &session.subject,
                &client_id_str,
                effective_scope,
                consent_mode,
            )
            .await
            {
                Ok(id) => Some(id),
                Err(()) => {
                    return Err(gate_error(
                        AuthzErrorCode::ServerError,
                        "the authorization request could not be processed",
                    ));
                }
            }
        } else {
            None
        };
        return Ok(Gate::Ready {
            session,
            consent_ref,
        });
    }

    // A recorded consent authorizes a later request only when that request's scope is
    // a SUBSET of the granted scope (issue #196) and it has not lapsed (issue #21).
    let Ok(recorded) = state
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(&session.subject, &client_id_str)
        .await
    else {
        return Err(gate_error(
            AuthzErrorCode::ServerError,
            "the authorization request could not be processed",
        ));
    };
    let now_micros = epoch_micros(state.now());
    let consent_scope =
        consent_check_scope(effective_scope, state.offline_access_requires_consent());
    let covered = recorded
        .as_ref()
        .is_some_and(|consent| !consent_expired(consent, now_micros))
        && consent_covers_scope(recorded.as_ref(), consent_scope.as_deref());
    if covered && !force_consent {
        let consent_ref = recorded.expect("a covering consent is recorded").id;
        return Ok(Gate::Ready {
            session,
            consent_ref: Some(consent_ref),
        });
    }

    // Consent is required: none recorded, the recorded one is expired or does not
    // cover the requested scope, or prompt=consent forced a fresh screen. Under
    // prompt=none no UI is rendered: the consent_required error goes back through the
    // negotiated mode instead.
    if prompt_none {
        return Err(gate_error(
            AuthzErrorCode::ConsentRequired,
            "consent is required but prompt=none forbids interaction",
        ));
    }
    Ok(Gate::Interaction(interaction::consent_redirect(
        &consent_resume_url(params, hints, prompt, pushed),
    )))
}

/// Record a SKIPPED consent for a trusted first-party client (issue #21) and
/// return its `con_` id. A `remembered`-mode client's skipped consent carries the
/// remembered TTL; an `explicit`/`implicit` one never expires. Returns `Err(())` on
/// a store failure so the caller fails closed to a `server_error`.
async fn record_skipped_consent(
    state: &OidcState,
    scope: Scope,
    subject: &str,
    client_id: &str,
    effective_scope: Option<&str>,
    consent_mode: ConsentMode,
) -> Result<String, ()> {
    let expires_at = if consent_mode == ConsentMode::Remembered {
        let now = state.now();
        Some(epoch_micros(
            now.checked_add(state.remembered_consent_ttl())
                .unwrap_or(now),
        ))
    } else {
        None
    };
    let actor = interaction::subject_actor(state, scope, subject);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .consents()
        .grant_with_expiry(state.env(), subject, client_id, effective_scope, expires_at)
        .await
        .map(|id| id.to_string())
        .map_err(|error| {
            tracing::error!(%error, "could not record a skipped first-party consent");
        })
}

/// Whether a recorded consent has passed its expiry at `now_micros` (issue #21). A
/// consent with no expiry (explicit/implicit) never lapses; a `remembered` consent
/// past its TTL is treated as absent so the next authorization re-prompts.
fn consent_expired(consent: &GrantedConsent, now_micros: i64) -> bool {
    consent
        .expires_at_unix_micros
        .is_some_and(|expiry| expiry <= now_micros)
}

/// The scope set to check a recorded consent against (issue #21). Normally the
/// whole effective scope, but when `offline_access` does NOT require consent it is
/// removed from the check so its presence never forces a prompt (the token is still
/// granted offline). Returns the space-separated value, or [`None`] for the empty
/// set.
fn consent_check_scope(
    effective_scope: Option<&str>,
    requires_offline_consent: bool,
) -> Option<String> {
    if requires_offline_consent {
        return effective_scope.map(str::to_owned);
    }
    let filtered: Vec<&str> = effective_scope
        .unwrap_or_default()
        .split_whitespace()
        .filter(|token| *token != "offline_access")
        .collect();
    if filtered.is_empty() {
        None
    } else {
        Some(filtered.join(" "))
    }
}

/// The effective granted scope (issue #21): the requested scope unchanged when the
/// flow issues an authorization code, or with `offline_access` removed when it does
/// not (only the code flow reaches the token endpoint to redeem a refresh token, so
/// `offline_access` is meaningless and IGNORED on a front-channel flow). Returns the
/// space-separated value, or [`None`] for the empty set.
fn effective_granted_scope(requested_scope: Option<&str>, issues_code: bool) -> Option<String> {
    if issues_code {
        return requested_scope.map(str::to_owned);
    }
    let filtered: Vec<&str> = requested_scope
        .unwrap_or_default()
        .split_whitespace()
        .filter(|token| *token != "offline_access")
        .collect();
    if filtered.is_empty() {
        None
    } else {
        Some(filtered.join(" "))
    }
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
///
/// On the PAR path (RFC 9126, issue #27) the resume re-presents the `request_uri` (no
/// overlay): `prompt=create` is stored and re-read verbatim, and it is already ignored
/// once a session exists, so nothing needs relaxing.
fn preserve_resume_url(
    params: &AuthorizeParams,
    hints: &InteractionHints,
    pushed: Option<&PushedContext>,
) -> String {
    match pushed {
        Some(context) => build_par_resume_url(context, params.scope.as_deref(), hints, None),
        None => build_authorize_url(
            params,
            hints,
            params.prompt.as_deref(),
            params.max_age.as_deref(),
            false,
        ),
    }
}

/// The `/authorize` resume URL for a LOGIN interaction, with the re-auth forcing
/// conditions CONSUMED (issue #16): the `login` and `select_account` prompt tokens
/// are dropped and any `max_age` is removed, because the fresh authentication the
/// login performs satisfies every one of them, so the resumed request is not caught
/// in an infinite redirect loop. When a `max_age` is consumed the `emit_auth_time`
/// marker is set so the resumed request still carries the ID token's `auth_time`
/// that `max_age` required.
///
/// On the PAR path (RFC 9126, issue #27) the resume re-presents the unforgeable
/// `request_uri` rather than the expanded parameters. When the login consumed a
/// forcing token (a `login`/`select_account` prompt or a `max_age`) it additionally
/// carries the reduced controls over the `request_uri` (the `par_resume` overlay) so
/// the loop is broken; when there was nothing to consume it stays MINIMAL.
fn login_resume_url(
    params: &AuthorizeParams,
    hints: &InteractionHints,
    prompt: PromptSet,
    pushed: Option<&PushedContext>,
) -> String {
    let residual = prompt
        .without(PromptValue::Login)
        .without(PromptValue::SelectAccount)
        .to_param();
    match pushed {
        Some(context) => {
            // A login relaxes login/select_account and any max_age. Carry the reduced
            // controls ONLY when there is something to relax; otherwise no overlay.
            let controls = (prompt.contains(PromptValue::Login)
                || prompt.contains(PromptValue::SelectAccount)
                || params.max_age.is_some())
            .then_some(ResumeControls {
                prompt: residual.as_deref(),
                max_age: None,
                emit_auth_time: params.max_age.is_some(),
            });
            build_par_resume_url(context, params.scope.as_deref(), hints, controls)
        }
        None => build_authorize_url(
            params,
            hints,
            residual.as_deref(),
            None,
            params.max_age.is_some(),
        ),
    }
}

/// The `/authorize` resume URL for a CONSENT interaction, with the `consent` prompt
/// token CONSUMED (issue #16) so the consent just recorded does not re-trigger a
/// consent loop. `max_age` is preserved (a consent step performs no
/// authentication, and a stale `max_age` would already have forced login first).
///
/// On the PAR path (RFC 9126, issue #27) the resume re-presents the unforgeable
/// `request_uri`. When the request carried `prompt=consent` (which would re-force the
/// screen forever) it carries the reduced controls over the `request_uri` (the
/// `par_resume` overlay, `max_age` preserved); otherwise the recorded consent already
/// breaks the loop, so no overlay is carried.
fn consent_resume_url(
    params: &AuthorizeParams,
    hints: &InteractionHints,
    prompt: PromptSet,
    pushed: Option<&PushedContext>,
) -> String {
    let residual = prompt.without(PromptValue::Consent).to_param();
    match pushed {
        Some(context) => {
            let controls = prompt
                .contains(PromptValue::Consent)
                .then_some(ResumeControls {
                    prompt: residual.as_deref(),
                    max_age: params.max_age.as_deref(),
                    emit_auth_time: false,
                });
            build_par_resume_url(context, params.scope.as_deref(), hints, controls)
        }
        None => build_authorize_url(
            params,
            hints,
            residual.as_deref(),
            params.max_age.as_deref(),
            false,
        ),
    }
}

/// The reduced interaction controls (issue #16) carried on a PAR resume URL behind the
/// `par_resume` marker, present ONLY when an interaction consumed a forcing token that
/// the stored request would otherwise re-force forever.
struct ResumeControls<'a> {
    /// The residual `prompt` after the consumed forcing tokens were dropped.
    prompt: Option<&'a str>,
    /// The `max_age` to carry (a login drops it; a consent preserves it).
    max_age: Option<&'a str>,
    /// Whether to set `emit_auth_time` (a login that dropped a `max_age`).
    emit_auth_time: bool,
}

/// Build the `/authorize` resume URL for a request that arrived via PAR (RFC 9126,
/// issue #27).
///
/// It re-presents the unforgeable `request_uri` and its `client_id`: those are the
/// source of truth for the require-PAR gate and for every security parameter
/// (`redirect_uri`, PKCE, `nonce`, `claims`, the client binding), all re-read from
/// storage on the resumed hop and NEVER trusted from this URL. It additionally carries
/// the `scope` and the interaction hints the login/consent PAGES render and record
/// from (the interaction layer is URL-driven): those are INERT at `/authorize`, where
/// the stored values win (RFC 9126 section 4), but the consent screen must display and
/// record the requested scope, so it rides the resume link. When an interaction
/// consumed a forcing token, `controls` carries the reduced `prompt`/`max_age` (and
/// `emit_auth_time`) behind the `par_resume` marker so the issue #16 loop is broken;
/// otherwise no marker is emitted and the stored `prompt`/`max_age` stand.
fn build_par_resume_url(
    context: &PushedContext,
    scope: Option<&str>,
    hints: &InteractionHints,
    controls: Option<ResumeControls<'_>>,
) -> String {
    let (marker, prompt, max_age, emit_auth_time) = match controls {
        Some(controls) => (
            Some("1"),
            controls.prompt,
            controls.max_age,
            controls.emit_auth_time.then_some("1"),
        ),
        None => (None, None, None, None),
    };
    append_query(
        "/authorize",
        &[
            ("client_id", Some(context.presenting_client.as_str())),
            ("request_uri", Some(context.request_uri.as_str())),
            ("scope", scope),
            ("login_hint", hints.login_hint()),
            ("logout_hint", hints.logout_hint()),
            ("ui_locales", hints.ui_locales()),
            ("claims_locales", hints.claims_locales()),
            ("display", hints.display_param()),
            ("par_resume", marker),
            ("prompt", prompt),
            ("max_age", max_age),
            ("emit_auth_time", emit_auth_time),
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
    /// The recorded consent handle recorded on the grant, or [`None`] when a
    /// skipped consent was not stored (issue #21).
    consent_ref: Option<&'a str>,
    /// The canonical JSON of the `claims` request parameter (issue #15), frozen
    /// onto the code and grant, or [`None`] when the request carried none.
    claims_request: Option<&'a str>,
    /// The RFC 8707 resource audiences approved at this authorization (issue #28),
    /// frozen onto the grant and code as the downscope ceiling. Empty when no
    /// resource was requested.
    granted_resources: &'a [String],
}

/// Validate the RFC 8707 resource indicators on an authorization request (issue #28).
///
/// Each requested resource must be a valid absolute URI (no fragment), on the
/// client's allowlist, AND a registered resource server in scope; a client whose
/// no-resource policy is `refuse` must name at least one resource. Unlike the token
/// endpoint, this does NOT enforce token-format agreement across the requested
/// resources: the authorization step APPROVES resources (which a later token request
/// narrows to one format-consistent subset), it does not mint a token. Returns the
/// [`AuthzErrorCode`] to deliver on failure (`invalid_target` for a policy violation,
/// `server_error` for a store fault); the caller renders it through the negotiated
/// response mode.
///
/// The PAR endpoint (RFC 9126 section 2.3, issue #28) runs this SAME helper at push
/// time so a malformed, unregistered, or disallowed `resource` surfaces `invalid_target`
/// on the back channel, identically to `/authorize`; the two paths cannot diverge.
pub(crate) async fn validate_authorize_resources(
    state: &OidcState,
    scope: Scope,
    client_id: &ClientId,
    resources: &[String],
) -> Result<(), AuthzErrorCode> {
    let policy = state
        .store()
        .scoped(scope)
        .clients()
        .resource_policy(client_id)
        .await
        .map_err(|_| AuthzErrorCode::ServerError)?;
    // Every NAMED resource: a valid indicator, on the client's allowlist.
    if !resource::resources_permitted(resources, &policy) {
        return Err(AuthzErrorCode::InvalidTarget);
    }
    // No resource named: honor the client's no-resource policy (refuse vs default).
    if resources.is_empty() {
        return if policy.require_resource_indicator {
            Err(AuthzErrorCode::InvalidTarget)
        } else {
            Ok(())
        };
    }
    // Every named resource must resolve to a registered resource server.
    match state.validate_resources_registered(&scope, resources).await {
        Ok(()) => Ok(()),
        Err(ResourceTargetError::InvalidTarget) => Err(AuthzErrorCode::InvalidTarget),
        Err(ResourceTargetError::ServerError) => Err(AuthzErrorCode::ServerError),
    }
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
        consent_ref: resolved.consent_ref,
        claims_request: resolved.claims_request,
        granted_resources: resolved.granted_resources,
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
    fn essential_acr_folds_into_the_step_up_requirement() {
        // The essential acr from the `claims` parameter (issue #16) now folds into
        // the step-up requirement (issue #72), evaluated by the step_up primitives.
        use crate::claims_request::ClaimsRequest;
        use crate::step_up;

        let order = step_up::default_acr_order();

        // An essential acr pinned to a level NO method can achieve is unsatisfiable:
        // the floor is not achievable, so the gate fails unmet_authentication_requirements.
        let unmet = ClaimsRequest::parse(
            r#"{"id_token":{"acr":{"essential":true,"values":["urn:example:high"]}}}"#,
        )
        .expect("parse");
        let unmet_req = step_up::requirement_from_acr_values(
            Some(&unmet.essential_acr_values().join(" ")),
            None,
            &order,
        );
        let floor = unmet_req.min_acr.as_deref().expect("a floor");
        assert!(!step_up::floor_is_achievable(floor, &order));

        // An essential acr pinned to the achievable-and-achieved level is satisfied.
        let met = ClaimsRequest::parse(
            r#"{"id_token":{"acr":{"essential":true,"values":["urn:ironauth:acr:pwd"]}}}"#,
        )
        .expect("parse");
        let met_req = step_up::requirement_from_acr_values(
            Some(&met.essential_acr_values().join(" ")),
            None,
            &order,
        );
        assert!(step_up::floor_is_achievable(
            met_req.min_acr.as_deref().expect("a floor"),
            &order
        ));
        assert_eq!(
            step_up::evaluate(&met_req, "urn:ironauth:acr:pwd", Some(0), 0, &order),
            step_up::Satisfaction::Satisfied,
        );
    }

    #[test]
    fn consent_covers_scope_enforces_the_subset_rule() {
        // A consent recorded for a NARROW scope does not cover a BROADER request:
        // that is the #196 fix (a narrow prior consent must not auto-grant more).
        let narrow = GrantedConsent {
            id: "con_x".to_owned(),
            granted_scope: Some("openid".to_owned()),
            expires_at_unix_micros: None,
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
            expires_at_unix_micros: None,
        };
        assert!(consent_covers_scope(Some(&broad), Some("email openid")));
        assert!(!consent_covers_scope(Some(&broad), Some("openid address")));

        // A missing consent covers nothing; an absent granted_scope is the empty set
        // (covers only an empty request).
        assert!(!consent_covers_scope(None, Some("openid")));
        let unscoped = GrantedConsent {
            id: "con_z".to_owned(),
            granted_scope: None,
            expires_at_unix_micros: None,
        };
        assert!(!consent_covers_scope(Some(&unscoped), Some("openid")));
        assert!(consent_covers_scope(Some(&unscoped), None));
    }

    #[test]
    fn offline_access_is_stripped_on_a_non_code_flow() {
        // Acceptance criterion 5: offline_access is IGNORED unless the flow returns
        // an authorization code (only the code flow reaches the token endpoint to
        // redeem a refresh token). It stays on a code flow and is removed otherwise.
        assert_eq!(
            effective_granted_scope(Some("openid offline_access"), true).as_deref(),
            Some("openid offline_access"),
            "a code flow keeps offline_access"
        );
        assert_eq!(
            effective_granted_scope(Some("openid offline_access"), false).as_deref(),
            Some("openid"),
            "a non-code (front-channel) flow strips offline_access"
        );
        // Stripping the only token yields the empty set (None), never an empty
        // string.
        assert_eq!(effective_granted_scope(Some("offline_access"), false), None);
        assert_eq!(effective_granted_scope(None, false), None);
    }

    #[test]
    fn consent_check_scope_honors_the_offline_consent_switch() {
        // With offline_access requiring consent (the default), it stays in the check.
        assert_eq!(
            consent_check_scope(Some("openid offline_access"), true).as_deref(),
            Some("openid offline_access"),
        );
        // With the requirement disabled, offline_access is dropped from the check so
        // its presence never forces a prompt.
        assert_eq!(
            consent_check_scope(Some("openid offline_access"), false).as_deref(),
            Some("openid"),
        );
        assert_eq!(consent_check_scope(Some("offline_access"), false), None);
    }

    #[test]
    fn consent_expiry_is_treated_as_absent_past_the_ttl() {
        // A consent with no expiry never lapses; one whose expiry has passed is
        // expired; one still in the future is not (issue #21).
        let never = GrantedConsent {
            id: "con_a".to_owned(),
            granted_scope: Some("openid".to_owned()),
            expires_at_unix_micros: None,
        };
        assert!(!consent_expired(&never, 1_000));
        let lapsed = GrantedConsent {
            id: "con_b".to_owned(),
            granted_scope: Some("openid".to_owned()),
            expires_at_unix_micros: Some(500),
        };
        assert!(
            consent_expired(&lapsed, 1_000),
            "past the expiry it is absent"
        );
        assert!(
            !consent_expired(&lapsed, 400),
            "before the expiry it is live"
        );
    }
}
