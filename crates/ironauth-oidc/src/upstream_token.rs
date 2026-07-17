// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client-authorized retrieval of a session's captured upstream tokens (issue #77,
//! PR 3): the low-end sibling of the agent token vault.
//!
//! After a brokered login the upstream access and refresh tokens can be persisted,
//! SEALED under the per-tenant envelope and keyed on the session (see the vault in
//! `ironauth-store`). This endpoint hands those tokens back to a downstream client so it
//! can call the upstream API on the user's behalf, behind TWO required checks:
//!
//!   1. SESSION OWNERSHIP: the tokens are looked up BY THE CALLER's OWN session (resolved
//!      from the caller's session cookie), never a client-supplied arbitrary session id.
//!      A caller with no live session, or a session that never captured a token, is the
//!      uniform not-found (the anti-oracle boundary): a foreign `utk_`/`ses_` id can never
//!      be probed, because the endpoint never reads a caller-supplied id.
//!   2. CLIENT CAPABILITY: the REQUESTING client authenticates exactly like a token-
//!      endpoint client (`client_auth`), and an enabled `upstream_token_grants` row must
//!      exist for `(that client, the session's org connection)`. A client with no grant
//!      gets a TYPED `unauthorized_client` denial, never a 500 and never a leak.
//!
//! Both checks run under the scoped, row-level-security-forced repositories, and EVERY
//! read is audited (who read whose session's token, NEVER the token value). The token
//! value flows out ONLY through the redacting [`ironauth_store::UpstreamToken`] newtype,
//! whose `open()` result is written to the HTTP response body and nowhere else.
//!
//! # Deferrals (honest seams)
//!
//! This endpoint does the session-scoped RETRIEVAL machinery. Agent-vault delegation and
//! token exchange to a downstream audience are M13 (out of scope): a retrieved token is
//! returned verbatim to the authorized client, not minted or downscoped here. The grant
//! objects are created through the store repository; a dedicated management HTTP surface
//! for them rides a later slice.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{ActorRef, ClientId, CorrelationId, ServiceId, UserId};
use serde::Deserialize;

use crate::client_auth::{self, ClientAuthError, ClientAuthInputs};
use crate::interaction;
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::wellknown::{not_found, parse_scope};

/// The client-authentication form fields a retrieval request may carry (mirroring the
/// token endpoint): `client_secret_post` credentials, or a JWT client assertion. The
/// Basic credential rides the `Authorization` header instead.
#[derive(Debug, Default, Deserialize)]
#[allow(clippy::struct_field_names)]
struct RetrievalForm {
    /// The `client_id` form field (`client_secret_post` / public).
    client_id: Option<String>,
    /// The `client_secret` form field (`client_secret_post`).
    client_secret: Option<String>,
    /// The RFC 7521 `client_assertion` (a JWT client assertion).
    client_assertion: Option<String>,
    /// The RFC 7521 `client_assertion_type`.
    client_assertion_type: Option<String>,
}

/// POST `/t/{tenant}/e/{env}/federation/upstream-token` (issue #77, PR 3): return the
/// caller's session's captured upstream tokens to an authorized client.
///
/// The handler resolves the scope, authenticates the requesting client, resolves the
/// CALLER's OWN session (session ownership), checks the client capability against the
/// session's org connection, and only then reads and returns the sealed tokens (audited).
/// Every failure is a uniform not-found or a typed denial, never a 500 that leaks state.
// One linear gate (scope -> client auth -> session ownership -> org connection -> grant ->
// read); splitting it would scatter the single security sequence a reviewer must read.
#[allow(clippy::too_many_lines)]
pub async fn retrieve_upstream_token(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    // The federation surface is off unless a runtime is installed, exactly like the
    // authorize/callback legs: a uniform not-found otherwise (no oracle for the feature).
    if state.federation().is_none() {
        return not_found();
    }

    let form: RetrievalForm = serde_urlencoded::from_str(&body).unwrap_or_default();

    // CLIENT CAPABILITY (part 1): authenticate the requesting client exactly like a
    // token-endpoint client. A parse problem is invalid_request; an unknown client or a
    // bad credential is the spec-exact, opaque invalid_client.
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let inputs = ClientAuthInputs {
        authorization,
        client_id: form.client_id.as_deref(),
        client_secret: form.client_secret.as_deref(),
        client_assertion: form.client_assertion.as_deref(),
        client_assertion_type: form.client_assertion_type.as_deref(),
    };
    let authenticated = match client_auth::authenticate_client(&state, scope, inputs).await {
        Ok(client) => client,
        Err(ClientAuthError::InvalidRequest(message)) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(message.to_owned()),
                false,
            );
        }
        Err(ClientAuthError::InvalidClient { via_basic }) => {
            return json_error(StatusCode::UNAUTHORIZED, "invalid_client", None, via_basic);
        }
    };
    let Ok(client_id) = ClientId::parse_in_scope(&authenticated.client_id, &scope) else {
        // The seam already parsed it in scope to authenticate; this cannot realistically
        // fail, but fail closed to the uniform not-found rather than 500.
        return not_found();
    };

    // SESSION OWNERSHIP: resolve the CALLER's OWN session from their cookie. A caller with
    // no live session is the uniform not-found (never a client-supplied session id).
    let Some(session) = interaction::resolve_session(&state, scope, &headers).await else {
        return not_found();
    };
    let Ok(subject) = UserId::parse_in_scope(&session.subject, &scope) else {
        return not_found();
    };

    // The session's org connection: the organization the session's user was provisioned
    // under (issue #77 PR 1 stamped it). A session with no org binding captured no
    // brokered tokens, so it is the uniform not-found.
    let Ok(Some(org_connection_id)) = state
        .store()
        .scoped(scope)
        .users()
        .org_connection(&subject)
        .await
    else {
        return not_found();
    };

    // The grant-authorized org connection's CONNECTOR. The token read below is filtered on
    // BOTH the session AND this connector, so a client granted for this org connection can
    // never read a token captured while the same session was routed through a DIFFERENT org
    // connection that happens to share a connector (a coherence gap if an operator ever maps
    // two org connections onto one shared connector with different grant policies). A missing
    // binding is the uniform not-found.
    let Ok(org_connection) = state
        .store()
        .scoped(scope)
        .org_connections()
        .get(&org_connection_id)
        .await
    else {
        return not_found();
    };
    let connector_id = org_connection.connector_id;

    // CLIENT CAPABILITY (part 2): an ENABLED grant must exist for (this client, the
    // session's org connection). Absent means a TYPED unauthorized_client denial, never a
    // leak of whether a token exists for the session.
    match state
        .store()
        .scoped(scope)
        .upstream_token_grants()
        .is_authorized(&client_id.to_string(), &org_connection_id.to_string())
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return json_error(
                StatusCode::FORBIDDEN,
                "unauthorized_client",
                Some("the client is not authorized to retrieve upstream tokens".to_owned()),
                false,
            );
        }
        Err(_) => return not_found(),
    }

    // Read the caller's own session's captured tokens under the scoped, RLS-forced repo,
    // auditing the read. A session with no captured token is the uniform not-found. The
    // audit actor is the requesting client (derived from its own id), so the trail shows
    // WHO read WHOSE session's token, never the value.
    let actor = ActorRef::service(ServiceId::from_seed_bytes(client_id.unique_bytes()));
    let correlation = CorrelationId::generate(state.env());
    let Ok(Some(material)) = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .upstream_tokens()
        .read_for_session(state.env(), &session.session_id, &connector_id)
        .await
    else {
        return not_found();
    };

    // The token value leaves the process ONLY here: open() the redacting newtype straight
    // into the JSON body. The expiry is rendered as a relative expires_in from the clock
    // seam so the client need not reason about the server's wall clock.
    let now_micros = epoch_micros(state.now());
    success_body(material, now_micros)
}

/// The `200 OK` retrieval response body: the upstream access token, the refresh token
/// when one was captured, and the non-secret metadata. The token values come straight
/// from [`ironauth_store::UpstreamToken::open`] (its one sanctioned exit) into the JSON
/// body and are never logged. `material` is consumed so the plaintext never outlives it.
fn success_body(material: ironauth_store::UpstreamTokenMaterial, now_micros: i64) -> Response {
    let ironauth_store::UpstreamTokenMaterial {
        connector_id: _,
        access_token,
        refresh_token,
        access_expires_at_unix_micros,
        token_scope,
    } = material;

    let access_bytes = access_token.open();
    let access = String::from_utf8_lossy(&access_bytes).into_owned();
    let mut object = serde_json::Map::new();
    object.insert("access_token".to_owned(), serde_json::Value::String(access));
    object.insert(
        "token_type".to_owned(),
        serde_json::Value::String("Bearer".to_owned()),
    );
    if let Some(expires_at) = access_expires_at_unix_micros {
        let expires_in_secs = (expires_at - now_micros).max(0) / 1_000_000;
        object.insert(
            "expires_in".to_owned(),
            serde_json::Value::Number(expires_in_secs.into()),
        );
    }
    if !token_scope.is_empty() {
        object.insert("scope".to_owned(), serde_json::Value::String(token_scope));
    }
    if let Some(refresh) = refresh_token {
        let refresh_bytes = refresh.open();
        let refresh = String::from_utf8_lossy(&refresh_bytes).into_owned();
        object.insert(
            "refresh_token".to_owned(),
            serde_json::Value::String(refresh),
        );
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        serde_json::Value::Object(object).to_string(),
    )
        .into_response()
}

/// A typed JSON error response (issue #77, PR 3): `{"error": "<code>", ...}`, with an
/// optional operator-safe description and, for a Basic auth failure, the RFC 6749 6750
/// `WWW-Authenticate: Basic` challenge. The token value never appears in any error.
fn json_error(
    status: StatusCode,
    code: &str,
    description: Option<String>,
    via_basic: bool,
) -> Response {
    let mut object = serde_json::Map::new();
    object.insert(
        "error".to_owned(),
        serde_json::Value::String(code.to_owned()),
    );
    if let Some(description) = description {
        object.insert(
            "error_description".to_owned(),
            serde_json::Value::String(description),
        );
    }
    let body = serde_json::Value::Object(object).to_string();
    let mut response = (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response();
    if via_basic {
        if let Ok(value) = header::HeaderValue::from_str("Basic") {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
    }
    response
}
