// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OAuth 2.0 Authorization Challenge Endpoint (issue #93, Bet 3, EXPERIMENTAL,
//! draft-ietf-oauth-first-party-apps-03): the browserless first-party native login surface.
//!
//! A first-party NATIVE client (no browser, no redirect) POSTs its `client_id`, `response_type`,
//! optional `scope`/PKCE, and implementation-defined credential params (username, password) to
//! this endpoint. The endpoint drives the SAME login flow engine the browser and headless-API
//! transports drive (a THIRD projection over `create_flow` + `drive`), and on a login that
//! completes in one request it mints a BROWSERLESS authorization code (bound to NO `redirect_uri`)
//! and returns `200 application/json {"authorization_code": "<ac_...>"}`. The client redeems that
//! code at the ORDINARY token endpoint with `grant_type=authorization_code&code=<code>` and NO
//! `redirect_uri`.
//!
//! PR2 scope: MFA / step-up CONTINUITY. When the login flow holds on a second factor, the endpoint
//! returns `400 insufficient_authorization` carrying a rotating opaque `auth_session` plus node
//! derived hints (`otp_required`) instead of a code; the native client resubmits with the
//! `auth_session` and its one time code; the endpoint resumes the SAME flow and either loops (a new
//! `auth_session`) or, on completion, mints the code. High-risk escalation (`redirect_to_web` for
//! the unsatisfiable-headless states) and hardening (per-`auth_session` rate limiting, client-auth
//! parity, `DPoP`) are LATER PRs.
//!
//! The security crux (PR2):
//! - The OAuth params (`client_id`, `scope`, `code_challenge`, `code_challenge_method`) are
//!   stashed into the flow's WRITE ONCE `transient_payload` at creation and sourced back on a
//!   resume, so they are structurally IMMUTABLE across rounds: a resume presenting a wider scope or
//!   a different PKCE challenge has ZERO effect on the bound code, and the code always binds the
//!   flow's ORIGINAL client.
//! - The `auth_session` is `base64url(flow_id.submit_token)` with NO MAC. [`drive`] re-verifies
//!   BOTH halves server side (a scope-forced flow id and a constant time submit token match), so a
//!   tampered, stale, or reused handle only fails the drive (a uniform `invalid_grant`), never
//!   mints. Rotation is free: each rendered step carries a freshly rotated submit token.
//! - Anti-enumeration: a primary factor failure (a wrong password OR an unknown user) maps to the
//!   SAME uniform `insufficient_authorization` with NO `auth_session` and NO hints. ONLY a render
//!   whose state is `MfaChallenge`/`MfaEnroll` gets the `auth_session` + hints, and that state is
//!   reachable ONLY after a genuine primary success, so it discloses only "a second factor is
//!   required" (inherent to step up, exactly what the browser MFA screen already shows).

use std::collections::BTreeMap;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use ironauth_store::{ClientId, ClientRecord, FlowId, Scope};

use crate::authorize::{ChallengeCodeContext, mint_challenge_code, user_is_quarantined};
use crate::flow::model::{Flow, FlowStateTag, Journey, Node, NodeAttributes, NodeGroup, Transport};
use crate::flow::{Continuation, FlowError, Submission, TransportAuth, create_flow, drive};
use crate::interaction::{self, SessionCookies};
use crate::state::OidcState;
use crate::wellknown::parse_scope;

/// The scope-routed Authorization Challenge Endpoint path (issue #93). Scope-routed like every
/// data-plane route, so the login flow runs under the right per-environment scope. The route
/// literal is mounted UNCONDITIONALLY (the handler fails closed to a 404 when the feature is off)
/// so it stays visible to the RFC 9700 endpoint inventory.
pub const AUTHORIZATION_CHALLENGE_PATH: &str =
    "/t/{tenant_id}/e/{environment_id}/authorize-challenge";

/// The `200 application/json` success body: the minted browserless authorization code.
#[derive(Debug, Serialize)]
struct ChallengeSuccess {
    /// The `ac_` authorization code the client redeems at the token endpoint (no `redirect_uri`).
    authorization_code: String,
}

/// The OAuth parameters the challenge binds the code to (issue #93, PR2), stashed into the flow's
/// WRITE ONCE `transient_payload` at creation and sourced back on a resume. Because
/// `transient_payload` is bound only by `FlowRepo::create` (never by any submit), these are
/// structurally immutable across resumption rounds: the mint ALWAYS sources scope, PKCE, and the
/// bound client from HERE, never from a resume request.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChallengeParams {
    /// The client the code binds to (a resume body can never change it).
    client_id: String,
    /// The requested OAuth `scope`, or [`None`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    /// The presented PKCE `code_challenge`, or [`None`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code_challenge: Option<String>,
    /// The presented PKCE `code_challenge_method`, or [`None`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code_challenge_method: Option<String>,
}

/// The `transient_payload` envelope carrying the challenge params (issue #93, PR2), namespaced
/// under `challenge` so the stash is self describing on the row.
#[derive(Debug, Serialize, Deserialize)]
struct ChallengeTransient {
    /// The stashed OAuth params.
    challenge: ChallengeParams,
}

/// `POST /t/{tenant}/e/{env}/authorize-challenge` (issue #93, Bet 3): the browserless first-party
/// login challenge. Fails closed with a uniform 404 when the `first-party-challenge` experimental
/// feature is off. A FRESH request (no `auth_session`) creates and drives a login flow; a request
/// carrying an `auth_session` RESUMES the stashed flow (the MFA / step-up loop). On success returns
/// `200 {"authorization_code": "<ac_...>"}`.
// The FRESH request pipeline is one cohesive decision procedure (fail-closed gate, form parse,
// client + parameter validation, the create + drive, and the completion-to-code mint); the resume
// branch, the completion mint, and the response shaping are extracted as helpers, but the fresh
// pipeline stays inline so its ordered checks read top to bottom.
#[allow(clippy::too_many_lines)]
pub async fn authorize_challenge(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Fail closed: the endpoint answers a uniform 404 until an operator enables AND acknowledges
    // the experiment (the arming bool is resolved from the strict feature ladder at boot).
    if !state.first_party_challenge_enabled() {
        return not_found();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };

    // Parse the urlencoded body as an ORDERED pair list (the idiom the browser flow POST uses, at
    // flow/transport.rs): serde_urlencoded does not support `#[serde(flatten)]` into a map, and the
    // draft's credential params are implementation-defined arbitrary fields, so the known
    // parameters are pulled out and every other field becomes a credential (a flow node value).
    let Ok(pairs) = serde_urlencoded::from_bytes::<Vec<(String, String)>>(&body) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the request body could not be parsed as application/x-www-form-urlencoded",
        );
    };
    let mut client_id_raw: Option<String> = None;
    let mut response_type: Option<String> = None;
    let mut scope_param: Option<String> = None;
    let mut code_challenge_raw: Option<String> = None;
    let mut code_challenge_method: Option<String> = None;
    let mut auth_session: Option<String> = None;
    let mut credentials: BTreeMap<String, Value> = BTreeMap::new();
    for (name, value) in pairs {
        match name.as_str() {
            "client_id" => client_id_raw = Some(value),
            "response_type" => response_type = Some(value),
            "scope" => scope_param = Some(value),
            "code_challenge" => code_challenge_raw = Some(value),
            "code_challenge_method" => code_challenge_method = Some(value),
            // `auth_session` is the draft's continuity handle for the MFA resumption loop: its
            // presence routes the request to the resume branch.
            "auth_session" => auth_session = Some(value),
            // Every other field is an implementation-defined credential param, forwarded to the
            // login flow as a node value under its own name.
            _ => {
                credentials.entry(name).or_insert(Value::String(value));
            }
        }
    }

    // Map the implementation-defined credential params to the login flow's node values. The login
    // executor reads `identifier`/`password`; the MFA executor reads `code`. A client may send
    // `username` (aliased to `identifier`), `otp` (aliased to `code`), or the node names directly,
    // plus any other node the flow collects. The aliases are harmless on the branch that does not
    // read them, so they are applied once for BOTH the fresh and the resume path.
    let mut node_values = credentials;
    if let Some(username) = node_values.remove("username") {
        node_values
            .entry("identifier".to_owned())
            .or_insert(username);
    }
    if let Some(otp) = node_values.remove("otp") {
        node_values.entry("code".to_owned()).or_insert(otp);
    }

    // The request `client_id`, trimmed to a non-empty value, shared by both branches (required on
    // the fresh path, an optional defense-in-depth binding check on the resume path).
    let request_client_id = client_id_raw
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    // RESUME: the continuity handle is present, so continue the stashed flow rather than create a
    // new one. The mint sources scope / PKCE / client from the flow's stored params, never here.
    if let Some(auth_session) = auth_session
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return resume_challenge(
            &state,
            scope,
            &headers,
            auth_session,
            request_client_id,
            node_values,
        )
        .await;
    }

    // FRESH request: full validation of the request params, then create + drive a login flow.

    // response_type MUST be `code` (the draft: the challenge endpoint issues an authorization code).
    let response_type = response_type.as_deref().map_or("", str::trim);
    if response_type != "code" {
        return error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "response_type must be code",
        );
    }

    // Optional PKCE: bind it when present, but reject a non-S256 method (RFC 9700 is S256-only) and
    // a malformed challenge, so a later token-endpoint verify failure is turned into an honest,
    // immediate error here.
    let code_challenge = code_challenge_raw
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    if let Some(challenge) = code_challenge {
        let method = code_challenge_method.as_deref().map_or("", str::trim);
        if method != "S256" {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code_challenge_method must be S256",
            );
        }
        if !crate::pkce::code_challenge_is_well_formed(challenge) {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code_challenge is malformed",
            );
        }
    }

    // Resolve the client from its declared scope and confirm it matches the routed scope. A
    // malformed or unknown client is a uniform `invalid_client` (401), disclosing nothing.
    let Some(client_id_raw) = request_client_id else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        );
    };
    let Ok(client_id) = ClientId::parse_declared_scope(client_id_raw) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "the client_id is malformed or unknown",
        );
    };
    if client_id.scope() != scope {
        return error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "the client_id is malformed or unknown",
        );
    }
    let client = match state.store().scoped(scope).clients().get(&client_id).await {
        Ok(record) => record,
        Err(ironauth_store::StoreError::NotFound) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "the client_id is malformed or unknown",
            );
        }
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the request could not be processed",
            );
        }
    };

    // The challenge endpoint is FIRST-PARTY only (issue #88 `clients.first_party`): a third-party
    // client is `unauthorized_client`. This is the browserless native surface's trust boundary.
    if !client.first_party {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthorized_client",
            "this client is not authorized to use the authorization challenge endpoint",
        );
    }

    // The immutable OAuth params the code binds to, stashed into the flow's WRITE ONCE
    // `transient_payload` so a later resume can source them WITHOUT trusting the resume body.
    let params = ChallengeParams {
        client_id: client_id.to_string(),
        scope: scope_param,
        code_challenge: code_challenge.map(str::to_owned),
        code_challenge_method,
    };
    let Ok(transient) = serde_json::to_value(ChallengeTransient {
        challenge: params.clone(),
    }) else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the request could not be processed",
        );
    };

    // Create a FRESH login flow, carrying the stashed params, and drive its first step.
    let Ok((flow_id, submit_token, _flow)) = create_flow(
        &state,
        scope,
        Transport::Api,
        Journey::Login,
        None,
        Some(&transient),
        None,
        &headers,
    )
    .await
    else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the request could not be processed",
        );
    };
    let submission = Submission {
        node_values,
        transient_payload: None,
    };
    let auth = TransportAuth::Api {
        presented_submit_token: submit_token,
    };
    // A store fault (the only 500-class flow error) or a closed row is a uniform server error.
    let Ok(continuation) = drive(
        &state,
        scope,
        &flow_id,
        Transport::Api,
        auth,
        submission,
        &headers,
    )
    .await
    else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the request could not be processed",
        );
    };

    match continuation {
        // The login completed in one request: mint the browserless code from the stashed params.
        Continuation::Complete { session, .. } => {
            complete_challenge(&state, scope, &client, &client_id, &session, &params).await
        }
        // The login held (a second factor is required, or a validation / primary-factor failure).
        // A step-up render carries the rotating `auth_session` + hints; every other hold is the
        // uniform `auth_session`-free failure (the anti-enumeration surface).
        Continuation::Render { flow, submit_token } => {
            render_step_response(&flow_id, &flow, &submit_token)
        }
        Continuation::Redirect { .. } | Continuation::ConsentDecision { .. } => {
            insufficient_uniform()
        }
    }
}

/// Resume a stashed challenge flow from its `auth_session` (issue #93, PR2), the analogue of the
/// headless `flow_api_submit` (flow/transport.rs). The mint sources scope / PKCE / the bound client
/// from the flow's stored [`ChallengeParams`], NEVER from the resume body; a present but mismatched
/// request `client_id` is a uniform `invalid_client`; a stale, tampered, or completed handle is a
/// uniform `invalid_grant`.
// One ordered decision procedure (decode the handle, load + parse the stashed params, the client
// binding check, resolve the bound client, then the single drive and its continuation map);
// splitting it would scatter the resume's security guards across helpers without making them
// clearer, and each step already reads as one guard.
#[allow(clippy::too_many_lines)]
async fn resume_challenge(
    state: &OidcState,
    scope: Scope,
    headers: &HeaderMap,
    auth_session: &str,
    request_client_id: Option<&str>,
    node_values: BTreeMap<String, Value>,
) -> Response {
    // Decode the opaque handle back into its scope-forced flow id and the presented submit token.
    let Some((flow_id, presented_submit_token)) = decode_auth_session(auth_session, scope) else {
        return invalid_auth_session();
    };

    // Load the row to source the immutable params and the bound client. `load` has no consumed
    // filter, so the params are readable even after completion; `drive` below enforces the single
    // use and expiry latches. A missing row is the uniform stale rejection; a fault is a 500.
    let record = match state.store().scoped(scope).flows().load(&flow_id).await {
        Ok(Some(record)) => record,
        Ok(None) => return invalid_auth_session(),
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the request could not be processed",
            );
        }
    };
    let Some(params) = record
        .transient_payload
        .as_deref()
        .and_then(parse_challenge_params)
    else {
        // A row with no challenge stash was not minted by this endpoint; treat its handle as stale.
        return invalid_auth_session();
    };

    // Resolve the BOUND client (the code binds this regardless of the resume body). Both parse and
    // scope faults are corrupt-row server errors (the value was validated at creation).
    let Ok(client_id) = ClientId::parse_declared_scope(&params.client_id) else {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the request could not be processed",
        );
    };
    if client_id.scope() != scope {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the request could not be processed",
        );
    }
    // Client binding (defense in depth): a resume presenting a DIFFERENT client_id is a uniform
    // `invalid_client`, so a stolen handle cannot even be replayed under another client (and the
    // code binds the stored client regardless). An absent client_id defers to the stored one.
    if let Some(request_client_id) = request_client_id {
        if request_client_id != params.client_id {
            return error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "the client_id is malformed or unknown",
            );
        }
    }
    let client = match state.store().scoped(scope).clients().get(&client_id).await {
        Ok(record) => record,
        Err(ironauth_store::StoreError::NotFound) => {
            return error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "the client_id is malformed or unknown",
            );
        }
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the request could not be processed",
            );
        }
    };
    // Belt-and-suspenders: the first-party trust boundary still holds on a resume.
    if !client.first_party {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthorized_client",
            "this client is not authorized to use the authorization challenge endpoint",
        );
    }

    let submission = Submission {
        node_values,
        transient_payload: None,
    };
    let auth = TransportAuth::Api {
        presented_submit_token,
    };
    let continuation = match drive(
        state,
        scope,
        &flow_id,
        Transport::Api,
        auth,
        submission,
        headers,
    )
    .await
    {
        Ok(continuation) => continuation,
        Err(flow_error) => return map_resume_error(flow_error),
    };

    match continuation {
        // A completed resume: mint the code from the STORED params (never the resume body).
        Continuation::Complete { session, .. } => {
            complete_challenge(state, scope, &client, &client_id, &session, &params).await
        }
        // A held resume: a step-up render loops with a NEW `auth_session`; any other hold is the
        // uniform `auth_session`-free failure.
        Continuation::Render { flow, submit_token } => {
            render_step_response(&flow_id, &flow, &submit_token)
        }
        Continuation::Redirect { .. } | Continuation::ConsentDecision { .. } => {
            insufficient_uniform()
        }
    }
}

/// Mint the browserless authorization code for a completed challenge login (issue #93). Reads back
/// the subject the flow authenticated, replicates the browser consent gate's quarantine escalation
/// (issue #31 / #82: a quarantined client OR user escalates to the browser with `redirect_to_web`
/// rather than an auto-grant), then mints through [`mint_challenge_code`] with scope / PKCE / the
/// bound client sourced from `params`. Shared by the fresh one-shot completion and a resume
/// completion, so BOTH bind the ORIGINAL params.
async fn complete_challenge(
    state: &OidcState,
    scope: Scope,
    client: &ClientRecord,
    client_id: &ClientId,
    session: &SessionCookies,
    params: &ChallengeParams,
) -> Response {
    let Some(authenticated) = interaction::resolve_established_session(state, scope, session).await
    else {
        // The session vanished (revoked/faulted) between establish and read: fail closed.
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the request could not be processed",
        );
    };
    // Replicate the browser consent gate's quarantine checks (issue #31 / #82) that the first-party
    // carve-out honors: the browserless endpoint cannot render a consent screen, so a quarantined
    // client or user ESCALATES to the browser instead of minting. `first_party` is enforced at
    // entry; a challenge carries no `prompt`, so `force_consent` reduces to `client.quarantined`.
    let user_quarantined = if state.signup_quarantine_enabled() {
        match user_is_quarantined(state, scope, &authenticated.subject).await {
            Ok(quarantined) => quarantined,
            // FAIL CLOSED: a store fault on the quarantine read must never silently mint a code for
            // a possibly-quarantined subject; escalate to the browser.
            Err(()) => return redirect_to_web(),
        }
    } else {
        false
    };
    if client.quarantined || user_quarantined {
        return redirect_to_web();
    }
    let session_ref = authenticated.session_id.to_string();
    // auth_time is frozen onto the code only when the client registered require_auth_time (issue
    // #14), matching the browser path's honesty rule. The challenge parses no `max_age`, so there
    // is no step-up-age bound to consume: the requirement stays require_auth_time-only.
    let auth_time_micros = client
        .require_auth_time
        .then_some(authenticated.auth_time_unix_micros);
    let context = ChallengeCodeContext {
        client,
        subject: &authenticated.subject,
        auth_methods: &authenticated.auth_methods,
        auth_time_micros,
        session_ref: &session_ref,
        oauth_scope: params.scope.as_deref(),
        user_quarantined,
        code_challenge: params.code_challenge.as_deref(),
        code_challenge_method: params.code_challenge_method.as_deref(),
    };
    match mint_challenge_code(state, scope, client_id, &context).await {
        Ok(authorization_code) => success(&ChallengeSuccess { authorization_code }),
        Err(()) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the request could not be processed",
        ),
    }
}

/// Map a `Continuation::Render` to the client response (issue #93, PR2). A step-up hold
/// (`MfaChallenge`/`MfaEnroll`) returns `insufficient_authorization` carrying the rotating
/// `auth_session` (built from the freshly rotated submit token) plus the node derived hints; every
/// other render (a primary-factor failure such as a wrong password or an unknown user) stays the
/// UNIFORM `auth_session`-free failure, so a render is never an account existence oracle.
fn render_step_response(flow_id: &FlowId, flow: &Flow, submit_token: &str) -> Response {
    match flow.state {
        FlowStateTag::MfaChallenge | FlowStateTag::MfaEnroll => {
            let auth_session = encode_auth_session(flow_id, submit_token);
            insufficient_with_session(&auth_session, mfa_hints(&flow.ui.nodes))
        }
        _ => insufficient_uniform(),
    }
}

/// The client facing step-up hints for an MFA render (issue #93, PR2), derived STRICTLY from the
/// rendered node set (never from server state), so it discloses only what the rendered form already
/// shows. A Totp `code` input asks for a one time code (`otp_required`); the enroll render also
/// carries the `otpauth://` provisioning field (`otp_enroll_required`).
fn mfa_hints(nodes: &[Node]) -> serde_json::Map<String, Value> {
    let mut otp_required = false;
    let mut otp_enroll_required = false;
    for node in nodes {
        if node.group != NodeGroup::Totp {
            continue;
        }
        if let NodeAttributes::Input { name, .. } = &node.attributes {
            if name == "code" {
                otp_required = true;
            } else if name == "otpauth_uri" {
                otp_enroll_required = true;
            }
        }
    }
    let mut hints = serde_json::Map::new();
    if otp_required {
        hints.insert("otp_required".to_owned(), Value::Bool(true));
    }
    if otp_enroll_required {
        hints.insert("otp_enroll_required".to_owned(), Value::Bool(true));
    }
    hints
}

/// Encode the opaque continuity handle the native client resubmits (issue #93, PR2):
/// `base64url(flow_id.submit_token)` with NO MAC. [`drive`] re-verifies both halves server side, so
/// the handle carries no secret beyond values already issued to this same client; a stale handle
/// encodes a rotated out token and fails the drive. Both halves are drawn from a dotless alphabet
/// (a `flw_` id and a `URL_SAFE_NO_PAD` submit token), so the `.` separator is unambiguous.
fn encode_auth_session(flow_id: &FlowId, submit_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{flow_id}.{submit_token}"))
}

/// Decode a continuity handle into its flow id (scope forced) and the presented submit token
/// (issue #93, PR2). Splits the decoded bytes on the LAST `.` and parses the left as a flow id in
/// `scope`. Returns [`None`] on any malformed input (bad base64, non-UTF-8, no separator, or a
/// foreign/cross-scope id), which the caller maps to the uniform stale rejection.
fn decode_auth_session(raw: &str, scope: Scope) -> Option<(FlowId, String)> {
    let bytes = URL_SAFE_NO_PAD.decode(raw.as_bytes()).ok()?;
    let decoded = String::from_utf8(bytes).ok()?;
    let (flow_raw, submit_token) = decoded.rsplit_once('.')?;
    let flow_id = FlowId::parse_in_scope(flow_raw, &scope).ok()?;
    Some((flow_id, submit_token.to_owned()))
}

/// Parse the stashed [`ChallengeParams`] out of a row's `transient_payload` (issue #93, PR2).
fn parse_challenge_params(payload: &str) -> Option<ChallengeParams> {
    serde_json::from_str::<ChallengeTransient>(payload)
        .ok()
        .map(|transient| transient.challenge)
}

/// Map a resume `drive` error to the client response (issue #93, PR2). Every stale handle case (a
/// rotated out or reused submit token, an unknown / cross scope flow, an expired flow, a completed
/// flow) is the SAME uniform `400 invalid_grant`, so the handle is never an oracle; only a genuine
/// persistence fault is a neutral `500 server_error`.
fn map_resume_error(flow_error: FlowError) -> Response {
    match flow_error {
        FlowError::InvalidSubmission
        | FlowError::MalformedTransientPayload
        | FlowError::NotFound
        | FlowError::Expired
        | FlowError::AlreadyCompleted => invalid_auth_session(),
        FlowError::Store => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the request could not be processed",
        ),
    }
}

/// The uniform failure the endpoint returns for a primary-factor failure (a wrong credential OR an
/// unknown user) and for any non step-up hold: `400 insufficient_authorization` with NO
/// `auth_session` and NO hints, so it can never be an account existence oracle.
fn insufficient_uniform() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "insufficient_authorization",
        "the authorization could not be completed from the submitted credentials",
    )
}

/// The step-up continuation (issue #93, PR2): `400 insufficient_authorization` carrying the
/// rotating opaque `auth_session` the client resubmits plus the node derived hints. Reached ONLY
/// from an `MfaChallenge`/`MfaEnroll` render, which is reachable ONLY after a genuine primary
/// success, so it discloses only "a second factor is required".
fn insufficient_with_session(
    auth_session: &str,
    hints: serde_json::Map<String, Value>,
) -> Response {
    let mut body = serde_json::Map::new();
    body.insert(
        "error".to_owned(),
        Value::String("insufficient_authorization".to_owned()),
    );
    body.insert(
        "error_description".to_owned(),
        Value::String(
            "an additional authentication factor is required to complete the authorization"
                .to_owned(),
        ),
    );
    body.insert(
        "auth_session".to_owned(),
        Value::String(auth_session.to_owned()),
    );
    for (key, value) in hints {
        body.insert(key, value);
    }
    json_no_store(StatusCode::BAD_REQUEST, Value::Object(body))
}

/// The uniform stale / invalid `auth_session` rejection (issue #93, PR2): `400 invalid_grant`. A
/// decode failure, an unknown or cross scope flow, a rotated out or completed flow, and an expired
/// flow ALL land here, so a probe can never distinguish them (no oracle on the handle).
fn invalid_auth_session() -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "auth_session is invalid or expired",
    )
}

/// The uniform not-found the handler returns when the feature is off or the scope is malformed, so
/// a deployment that has not enabled the experiment discloses nothing.
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// The draft's `redirect_to_web` escalation (issue #93): when the interaction cannot be completed
/// headlessly (here: a quarantined client or user, whose consent gate the browserless endpoint
/// cannot satisfy), direct the native client to complete authorization in the browser (where the
/// interactive consent screen and the sensitive-scope strip apply) instead of minting a code. PR3
/// generalizes it (risk-based escalation plus an optional PAR `request_uri`). A `400 application/json
/// {"error": "redirect_to_web"}` with `no-store`.
fn redirect_to_web() -> Response {
    json_no_store(
        StatusCode::BAD_REQUEST,
        serde_json::json!({ "error": "redirect_to_web" }),
    )
}

/// A `200 application/json` success response carrying the minted authorization code, with
/// `Cache-Control: no-store` (the response carries a bearer credential).
fn success(body: &ChallengeSuccess) -> Response {
    let mut response = (StatusCode::OK, Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

/// A JSON error response in the OAuth shape (`{"error": ..., "error_description": ...}`) with the
/// given status and `Cache-Control: no-store`.
fn error(status: StatusCode, code: &str, description: &str) -> Response {
    json_no_store(
        status,
        serde_json::json!({
            "error": code,
            "error_description": description,
        }),
    )
}

/// A JSON response with the given status and `Cache-Control: no-store`, the one builder every
/// challenge response (success, error, the step-up continuation, `redirect_to_web`) routes through.
fn json_no_store(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use ironauth_env::Env;
    use ironauth_store::{EnvironmentId, TenantId};

    use super::{
        ChallengeParams, ChallengeTransient, decode_auth_session, encode_auth_session, mfa_hints,
        parse_challenge_params,
    };
    use crate::flow::model::{InputType, Node, NodeAttributes, NodeGroup};

    /// A Totp `code` input node (present in both the MFA challenge and the enroll render).
    fn code_node() -> Node {
        Node::input(
            NodeGroup::Totp,
            0,
            NodeAttributes::Input {
                name: "code".to_owned(),
                input_type: InputType::Text,
                value: None,
                required: true,
                autocomplete: None,
                disabled: false,
                constraints: None,
            },
            None,
        )
    }

    /// The display only `otpauth_uri` provisioning node the enroll render carries.
    fn otpauth_node() -> Node {
        Node::input(
            NodeGroup::Totp,
            1,
            NodeAttributes::Input {
                name: "otpauth_uri".to_owned(),
                input_type: InputType::Text,
                value: Some("otpauth://totp/example".to_owned()),
                required: false,
                autocomplete: None,
                disabled: true,
                constraints: None,
            },
            None,
        )
    }

    /// A non Totp node, to prove the hint scan ignores everything outside the Totp group.
    fn identifier_node() -> Node {
        Node::input(
            NodeGroup::Default,
            0,
            NodeAttributes::Input {
                name: "code".to_owned(),
                input_type: InputType::Text,
                value: None,
                required: true,
                autocomplete: None,
                disabled: false,
                constraints: None,
            },
            None,
        )
    }

    #[test]
    fn mfa_hints_maps_a_challenge_render_to_otp_required_only() {
        let hints = mfa_hints(&[code_node()]);
        assert_eq!(
            hints.get("otp_required"),
            Some(&serde_json::Value::Bool(true))
        );
        assert!(hints.get("otp_enroll_required").is_none());
    }

    #[test]
    fn mfa_hints_maps_an_enroll_render_to_both_hints() {
        let hints = mfa_hints(&[otpauth_node(), code_node()]);
        assert_eq!(
            hints.get("otp_required"),
            Some(&serde_json::Value::Bool(true))
        );
        assert_eq!(
            hints.get("otp_enroll_required"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn mfa_hints_ignores_non_totp_nodes() {
        // A `code` named node OUTSIDE the Totp group is not a second factor prompt.
        let hints = mfa_hints(&[identifier_node()]);
        assert!(hints.is_empty());
    }

    /// A deterministic env, one throwaway scope, and a generated flow id for the codec tests.
    fn scope_and_flow() -> (ironauth_store::Scope, ironauth_store::FlowId) {
        let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x00C0_FFEE);
        let scope =
            ironauth_store::Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        let flow_id = ironauth_store::FlowId::generate(&env, &scope);
        (scope, flow_id)
    }

    #[test]
    fn auth_session_round_trips() {
        let (scope, flow_id) = scope_and_flow();
        let token = "aVeryLongOpaqueSubmitTokenWithNoDots";
        let handle = encode_auth_session(&flow_id, token);
        let (decoded_id, decoded_token) =
            decode_auth_session(&handle, scope).expect("a valid handle decodes");
        assert_eq!(decoded_id.to_string(), flow_id.to_string());
        assert_eq!(decoded_token, token);
    }

    #[test]
    fn auth_session_rejects_a_non_base64_handle() {
        let (scope, _flow_id) = scope_and_flow();
        assert!(decode_auth_session("not base64 %%%", scope).is_none());
    }

    #[test]
    fn auth_session_rejects_a_handle_with_no_separator() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let (scope, _flow_id) = scope_and_flow();
        // A well formed base64 payload that carries no `.` separator has no submit token half.
        let handle = URL_SAFE_NO_PAD.encode("flowidwithnodot");
        assert!(decode_auth_session(&handle, scope).is_none());
    }

    #[test]
    fn auth_session_rejects_a_cross_scope_flow_id() {
        // A handle minted for one scope must not decode under a DIFFERENT scope (the flow id is
        // scope forced), so a stolen handle cannot be replayed cross tenant.
        let (_scope_a, flow_id) = scope_and_flow();
        let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0BAD_F00D);
        let scope_b =
            ironauth_store::Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        let handle = encode_auth_session(&flow_id, "token");
        assert!(decode_auth_session(&handle, scope_b).is_none());
    }

    #[test]
    fn challenge_params_round_trip_through_the_transient_envelope() {
        let params = ChallengeParams {
            client_id: "cli_example".to_owned(),
            scope: Some("openid profile".to_owned()),
            code_challenge: Some("abc".to_owned()),
            code_challenge_method: Some("S256".to_owned()),
        };
        let payload = serde_json::to_string(&ChallengeTransient {
            challenge: params.clone(),
        })
        .expect("serialize");
        let parsed = parse_challenge_params(&payload).expect("parse");
        assert_eq!(parsed.client_id, params.client_id);
        assert_eq!(parsed.scope, params.scope);
        assert_eq!(parsed.code_challenge, params.code_challenge);
        assert_eq!(parsed.code_challenge_method, params.code_challenge_method);
    }

    #[test]
    fn parse_challenge_params_rejects_a_non_challenge_payload() {
        assert!(parse_challenge_params("{\"other\":1}").is_none());
        assert!(parse_challenge_params("not json").is_none());
    }
}
