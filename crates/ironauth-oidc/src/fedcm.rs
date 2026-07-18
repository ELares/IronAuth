// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IdP-side FedCM (W3C Federated Credential Management) READ surface (issue #83,
//! EXPLORATORY), behind the `fedcm` experimental feature flag.
//!
//! FedCM is the browser-mediated replacement for third-party-cookie iframes: a
//! relying party calls `navigator.credentials.get({identity: ...})` and the browser,
//! not the RP, drives the IdP fetches. This module serves the READ surface (PR 1):
//!
//! - `GET /.well-known/web-identity` (origin-level): the FedCM provider config
//!   pointer, naming the SINGLE designated env's path-scoped config URL (Fork A1);
//! - `GET /t/{t}/e/{e}/fedcm/config.json`: the W3C FedCM config (endpoint locations +
//!   branding), for the designated env only;
//! - `GET /t/{t}/e/{e}/fedcm/accounts`: the browser's credentialed account read,
//!   answered ONLY from the OP session (issue #32); no session is an EMPTY,
//!   UNCACHEABLE response, so a logged-out browser is never served account data.
//!
//! The credential-issuing `POST /t/{t}/e/{e}/fedcm/assertion` endpoint is PR 2.
//!
//! Every handler fails CLOSED: its FIRST action is a uniform 404 when the feature is
//! off ([`OidcState::fedcm_enabled`]), so with the flag off ZERO behavior changes and
//! discovery advertises nothing. Redirect flows are UNAFFECTED either way.
//!
//! Security posture (the FedCM spec's crux for the accounts endpoint):
//!
//! - **`Sec-Fetch-Dest: webidentity` is REQUIRED** on every FedCM fetch. It is a
//!   FORBIDDEN header name (page script cannot set or forge it), so this gate makes
//!   the endpoints answer ONLY the browser's FedCM machinery, never a page `fetch`.
//! - The accounts response is **credentialed** (the `SameSite` `__Host-` session cookie
//!   is the sole authenticator; no client-supplied origin or account is ever trusted)
//!   and **uncacheable** (`Cache-Control: no-store`), so a stale populated body can
//!   never be replayed to a logged-out browser.
//! - The account `id` is the per-ENV PUBLIC subject (through the ONE subject function,
//!   [`OidcState::resolve_public_subject`]), never the raw local user id.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value};

use crate::interaction::resolve_session;
use crate::state::OidcState;
use crate::wellknown::{cacheable_response, not_found, parse_scope};

/// The `Sec-Fetch-Dest` fetch-metadata request header (no `http` constant exists for
/// it, so the lowercase name is used directly; `HeaderMap` lookups are
/// case-insensitive). It is a FORBIDDEN header name: page script cannot set or forge
/// it, so its value is authored solely by the user agent (mirror `interaction.rs`).
const SEC_FETCH_DEST: &str = "sec-fetch-dest";

/// The exact `Sec-Fetch-Dest` value the browser sends on a FedCM fetch.
const WEB_IDENTITY_DEST: &str = "webidentity";

/// The `Cache-Control` max-age for the FedCM well-known and config documents, in
/// seconds. Five minutes, matching the WebAuthn related-origins document: long enough
/// that a browser fetching it mid-flow does not re-hit the origin repeatedly, short
/// enough that a config change propagates quickly. The strong `ETag` still lets a
/// client revalidate cheaply with `If-None-Match`.
const FEDCM_DOCUMENT_MAX_AGE_SECS: u64 = 300;

/// Whether the request carries `Sec-Fetch-Dest: webidentity` (case-insensitive). A
/// FedCM fetch always does; a plain page `fetch`/`XMLHttpRequest` cannot set the
/// forbidden header, so a missing or different value means this is NOT a browser FedCM
/// request and the handler refuses it.
fn is_fedcm_fetch(headers: &HeaderMap) -> bool {
    headers
        .get(SEC_FETCH_DEST)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|dest| dest.eq_ignore_ascii_case(WEB_IDENTITY_DEST))
}

/// The uniform refusal for a request that is not a browser FedCM fetch (missing or
/// wrong `Sec-Fetch-Dest`): a plain `400`, disclosing nothing about the account or
/// the configured env. Distinct from the flag-off `404` so the two cases are
/// separable, but it still never leaks data.
fn not_a_fedcm_request() -> Response {
    (StatusCode::BAD_REQUEST, "not a FedCM request\n").into_response()
}

/// An UNCACHEABLE `application/json` response (`Cache-Control: no-store`), for the
/// accounts endpoint. The accounts body is credentialed and must NEVER be cached, so a
/// logged-out browser can never be served a stale populated body.
fn uncacheable_json(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        body,
    )
        .into_response()
}

/// `GET /.well-known/web-identity`: the origin-level FedCM provider config pointer
/// (issue #83, Fork A1). Returns `{"provider_urls": ["{base}/t/{t}/e/{e}/fedcm/config.json"]}`
/// for the single designated env, or a uniform `404` when the feature is off or no env
/// is designated (disclosing nothing on an origin not using FedCM). Uncredentialed and
/// cacheable, exactly like the WebAuthn related-origins well-known.
pub(crate) async fn well_known(State(state): State<OidcState>, headers: HeaderMap) -> Response {
    if !state.fedcm_enabled() {
        return not_found();
    }
    if !is_fedcm_fetch(&headers) {
        return not_a_fedcm_request();
    }
    let Some(body) = state.fedcm_wellknown_document() else {
        return not_found();
    };
    cacheable_response(
        &headers,
        "application/json",
        FEDCM_DOCUMENT_MAX_AGE_SECS,
        &body,
    )
}

/// `GET /t/{t}/e/{e}/fedcm/config.json`: the W3C FedCM config document (issue #83).
/// Served ONLY for the designated FedCM env (a valid but non-designated `(t,e)` is a
/// uniform `404`, keeping the origin single-env for the experiment). Uncredentialed and
/// cacheable. `404` when the feature is off.
pub(crate) async fn config(
    State(state): State<OidcState>,
    axum::extract::Path((tenant_id, environment_id)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !state.fedcm_enabled() {
        return not_found();
    }
    if !is_fedcm_fetch(&headers) {
        return not_a_fedcm_request();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    // Single-env-per-origin (Fork A1): only the designated env serves a config.
    if state.fedcm_designated_scope() != Some(scope) {
        return not_found();
    }
    let body = state.fedcm_config_document(&scope);
    cacheable_response(
        &headers,
        "application/json",
        FEDCM_DOCUMENT_MAX_AGE_SECS,
        &body,
    )
}

/// `GET /t/{t}/e/{e}/fedcm/accounts`: the browser's credentialed account read (issue
/// #83), answered ONLY from the OP session (issue #32).
///
/// - a valid session for the designated env yields a single-element `accounts` array
///   (Fork D) whose `id` is the per-ENV PUBLIC subject (never the raw user id) and
///   whose `name`/`email`/`picture` come from the sealed PII opened server-side;
/// - NO session yields an EMPTY `{"accounts": []}` body, so a logged-out browser is
///   never served account data;
///
/// Both are `Cache-Control: no-store` (never cacheable). `404` when the feature is off
/// or the scope is not the designated FedCM env; a plain `400` when the request is not
/// a browser FedCM fetch (missing `Sec-Fetch-Dest`).
pub(crate) async fn accounts(
    State(state): State<OidcState>,
    axum::extract::Path((tenant_id, environment_id)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if !state.fedcm_enabled() {
        return not_found();
    }
    if !is_fedcm_fetch(&headers) {
        return not_a_fedcm_request();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    if state.fedcm_designated_scope() != Some(scope) {
        return not_found();
    }

    // Answer ONLY from the credentialed OP session cookie. No session (absent,
    // expired, revoked, rotated, cross-scope, or a failed binding) is an EMPTY,
    // uncacheable body: never an account, never a leak. No client-supplied origin or
    // account is read here.
    let Some(session) = resolve_session(&state, scope, &headers).await else {
        return uncacheable_json(StatusCode::OK, r#"{"accounts":[]}"#.to_owned());
    };

    // The account id is the per-ENV PUBLIC subject through the ONE subject function
    // (pairwise if configured), so it matches what UserInfo / the redirect flow emit
    // for this env and never discloses the raw local user id.
    let public_subject = state.resolve_public_subject(&session.subject);

    // Open the sealed PII server-side through the exact UserInfo seam. An absent or
    // unreadable claim document yields an empty claim bag (the account still resolves
    // with its id), never an error that would leak the account's existence.
    let claim_bag = match state
        .store()
        .scoped(scope)
        .users()
        .claims_for_subject(&session.subject)
        .await
    {
        Ok(raw) => raw
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|value| match value {
                Value::Object(object) => Some(object),
                _ => None,
            })
            .unwrap_or_default(),
        // A store fault fails closed to an empty (uncacheable) response, never a leak.
        Err(_) => return uncacheable_json(StatusCode::OK, r#"{"accounts":[]}"#.to_owned()),
    };

    let body = build_accounts_body(&public_subject, &claim_bag);
    uncacheable_json(StatusCode::OK, body)
}

/// Build the single-account FedCM accounts body from the public subject and the opened
/// claim bag. FedCM's account requires `id`, `name`, and `email`; `name`/`email` come
/// from the claims (empty string when the account carries none), and `picture` is
/// included only when present. The `id` is the per-env public subject.
fn build_accounts_body(public_subject: &str, claims: &Map<String, Value>) -> String {
    let string_claim = |key: &str| -> String {
        claims
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let mut account = Map::new();
    account.insert("id".to_owned(), Value::String(public_subject.to_owned()));
    account.insert("name".to_owned(), Value::String(string_claim("name")));
    account.insert("email".to_owned(), Value::String(string_claim("email")));
    if let Some(picture) = claims.get("picture").and_then(Value::as_str) {
        account.insert("picture".to_owned(), Value::String(picture.to_owned()));
    }
    let document = serde_json::json!({ "accounts": [Value::Object(account)] });
    // Infallible: a serde_json::Value always serializes.
    serde_json::to_string(&document).unwrap_or_else(|_| r#"{"accounts":[]}"#.to_owned())
}
