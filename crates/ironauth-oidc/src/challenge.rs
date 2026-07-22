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
//! PR1 scope: the version-ack gate + the endpoint skeleton (flag-off 404, flag-on served) + the
//! LOGIN-ONLY happy path. MFA continuity (the `auth_session` resumption loop), high-risk
//! escalation (`redirect_to_web`), and hardening (per-`auth_session` rate limiting, client-auth
//! parity, `DPoP`) are LATER PRs. A `Continuation::Render` (login did not complete: bad credentials
//! or a second factor is required) returns a minimal `insufficient_authorization` here; PR2 builds
//! the real continuation loop.

use std::collections::BTreeMap;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::Value;

use ironauth_store::ClientId;

use crate::authorize::{ChallengeCodeContext, mint_challenge_code};
use crate::flow::model::{Journey, Transport};
use crate::flow::{Continuation, Submission, TransportAuth, create_flow, drive};
use crate::interaction;
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

/// `POST /t/{tenant}/e/{env}/authorize-challenge` (issue #93, Bet 3): the browserless first-party
/// login challenge. Fails closed with a uniform 404 when the `first-party-challenge` experimental
/// feature is off. On success returns `200 {"authorization_code": "<ac_...>"}`.
// One cohesive request pipeline (fail-closed gate, form parse, client + parameter validation, the
// single flow drive, and the completion-to-code mint); splitting it would scatter one endpoint's
// decision procedure across helpers without making it clearer.
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
    let mut code_challenge: Option<String> = None;
    let mut code_challenge_method: Option<String> = None;
    let mut credentials: BTreeMap<String, Value> = BTreeMap::new();
    for (name, value) in pairs {
        match name.as_str() {
            "client_id" => client_id_raw = Some(value),
            "response_type" => response_type = Some(value),
            "scope" => scope_param = Some(value),
            "code_challenge" => code_challenge = Some(value),
            "code_challenge_method" => code_challenge_method = Some(value),
            // `auth_session` is the draft's continuity handle for the MFA resumption loop (PR2). It
            // is accepted here (so a PR1 client that sends it is not rejected on the field alone)
            // but the resumption loop it drives is not built until PR2, so it is otherwise ignored.
            "auth_session" => {}
            // Every other field is an implementation-defined credential param, forwarded to the
            // login flow as a node value under its own name.
            _ => {
                credentials.entry(name).or_insert(Value::String(value));
            }
        }
    }

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
    let code_challenge = code_challenge
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
    let Some(client_id_raw) = client_id_raw
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
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

    // Map the implementation-defined credential params to the login flow's node values. The login
    // executor reads `identifier` and `password`; a client may send `username` (aliased to
    // `identifier`) or `identifier` directly, plus any other node the flow collects.
    let mut node_values = credentials;
    if let Some(username) = node_values.remove("username") {
        node_values
            .entry("identifier".to_owned())
            .or_insert(username);
    }
    let submission = Submission {
        node_values,
        transient_payload: None,
    };

    // Create a FRESH login flow and drive it to completion in ONE request (FORK B: PR1 is
    // login-only, so no `auth_session` resumption is needed). The API-style transport auth matches
    // the flow's fresh submit token.
    let Ok((flow_id, submit_token, _flow)) = create_flow(
        &state,
        scope,
        Transport::Api,
        Journey::Login,
        None,
        None,
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
        // The login completed in one request: read back the subject the flow authenticated (from
        // the session it just established) and mint a browserless authorization code bound to it.
        Continuation::Complete { session, .. } => {
            let Some(authenticated) =
                interaction::resolve_established_session(&state, scope, &session).await
            else {
                // The session vanished (revoked/faulted) between establish and read: fail closed.
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "the request could not be processed",
                );
            };
            let session_ref = authenticated.session_id.to_string();
            // auth_time is frozen onto the code only when the client registered require_auth_time
            // (issue #14), matching the browser path's honesty rule.
            let auth_time_micros = client
                .require_auth_time
                .then_some(authenticated.auth_time_unix_micros);
            let context = ChallengeCodeContext {
                client: &client,
                subject: &authenticated.subject,
                auth_methods: &authenticated.auth_methods,
                auth_time_micros,
                session_ref: &session_ref,
                oauth_scope: scope_param.as_deref(),
                code_challenge,
                code_challenge_method: code_challenge_method.as_deref(),
            };
            match mint_challenge_code(&state, scope, &client_id, &context).await {
                Ok(authorization_code) => success(&ChallengeSuccess { authorization_code }),
                Err(()) => error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "the request could not be processed",
                ),
            }
        }
        // The login did NOT complete: wrong credentials, or a second factor / additional step is
        // required. PR1 is login-only, so this returns a MINIMAL `insufficient_authorization`
        // WITHOUT the `auth_session` continuation handle (PR2 builds the real MFA loop). It never
        // discloses which of "wrong credential" vs "second factor required" occurred.
        Continuation::Render { .. }
        | Continuation::Redirect { .. }
        | Continuation::ConsentDecision { .. } => error(
            StatusCode::BAD_REQUEST,
            "insufficient_authorization",
            "the authorization could not be completed from the submitted credentials",
        ),
    }
}

/// The uniform not-found the handler returns when the feature is off or the scope is malformed, so
/// a deployment that has not enabled the experiment discloses nothing.
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
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
    let body = serde_json::json!({
        "error": code,
        "error_description": description,
    });
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}
