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
//! - `POST /t/{t}/e/{e}/fedcm/assertion`: the credential-issuing ID assertion
//!   endpoint (PR 2), which mints an ID token DIRECTLY to a relying party.
//!
//! ## The ID assertion endpoint's NO-BYPASS proof
//!
//! The assertion endpoint is the security crux: FedCM must NOT be a consent or
//! validation bypass relative to the redirect (`/authorize` -> `/token`) flow. It
//! issues the assertion DIRECTLY (there is no later token-endpoint `client_secret`
//! re-check), so the browser-set UNFORGEABLE `Origin`, the `SameSite` session
//! cookie, and `Sec-Fetch-Dest: webidentity` are the SOLE RP-authentication factors
//! and are enforced EXACT-match strict. Every redirect-flow check maps to the SAME
//! primitive here, so no check the redirect flow performs is skipped:
//!
//! | Redirect-flow check | Primitive | Assertion-endpoint reuse |
//! |---|---|---|
//! | client exists in scope | [`ironauth_store::ClientRepo::get`] | same call in the designated scope; unknown/cross-tenant -> reject |
//! | RP identity binding | `validate_registered_redirect` (exact string) | request `Origin` must EXACT-match an origin derived from the client's registered `https` `redirect_uris` ([`crate::state::origin_of`], Fork B1) -- the SAME registration data |
//! | consent honored | [`ironauth_store::ConsentRepo::granted_ref`] + [`crate::authorize::consent_covers_scope`]/[`crate::authorize::consent_expired`] | SAME `(subject, client_id)` consent read and the SAME first-party carve-out / quarantine rule; unmet -> FedCM error, never a token |
//! | audience binding | `MintRequest.client_id` | identical `aud = client_id` |
//! | subject derivation | [`OidcState::resolve_public_subject`] | identical (the ONE subject function) |
//! | signing / issuer | `sign_jws_with_policy` + per-env issuer registry | identical, via [`crate::tokens::mint_id_token`] -- NEVER a parallel/looser mint |
//! | replay defense | (redirect: single-use code) | single-use `(scope, client_id, nonce)` latch, reserve-then-consume (migration 0063) |
//!
//! The `redirect_uri` round-trip the redirect flow relies on is REPLACED by the
//! browser-mediated `Origin` match plus the browser's own FedCM mediation, so the
//! only checks FedCM omits are the ones the browser itself performs.
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

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{ClientId, ClientRecord, CorrelationId, FedcmNonceId, StoreError, UserId};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::authorize::{consent_covers_scope, consent_expired};
use crate::consent::ConsentMode;
use crate::interaction::{AuthenticatedSession, resolve_session};
use crate::state::{OidcState, origin_of};
use crate::tokens::{self, MintRequest};
use crate::util::{client_service_actor, epoch_micros};
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

/// A cacheable FedCM document response (the well-known pointer or the config document)
/// carrying `Vary: Sec-Fetch-Dest`. These documents are `Cache-Control: public,
/// max-age=...` AND the handler branches on `Sec-Fetch-Dest` (a non-FedCM fetch gets a
/// `400` instead of the document), so the `Vary` stops a shared cache from serving a
/// stored variant across that gate. The shared [`cacheable_response`] cannot carry it: it
/// also serves the JWKS/discovery/related-origins documents, which do NOT gate on
/// `Sec-Fetch-Dest`, so the header is added ONLY here.
fn cacheable_fedcm_document(headers: &HeaderMap, body: &str) -> Response {
    let mut response = cacheable_response(
        headers,
        "application/json",
        FEDCM_DOCUMENT_MAX_AGE_SECS,
        body,
    );
    response.headers_mut().insert(
        header::VARY,
        header::HeaderValue::from_static(SEC_FETCH_DEST),
    );
    response
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
    cacheable_fedcm_document(&headers, &body)
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
    cacheable_fedcm_document(&headers, &body)
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

// ---------------------------------------------------------------------------
// The ID assertion endpoint (the credential-issuing surface, PR 2).

/// The identity scope a FedCM ID assertion represents. FedCM carries no OAuth
/// `scope` parameter (the browser requests an identity credential), so consent is
/// checked against the minimal `openid` identity scope EXACTLY as the redirect flow
/// would for the same client (a recorded consent covering `openid` or broader is
/// honored; a narrower one, or none, re-prompts, which FedCM surfaces as a refusal).
const FEDCM_ASSERTION_SCOPE: &str = "openid";

/// The form body of a FedCM id-assertion request (`application/x-www-form-urlencoded`,
/// posted by the browser's FedCM machinery). `disclosure_text_shown` and `params` are
/// carried by the spec but not consumed here (single-account, no extra params in the
/// experiment); every security-relevant field is validated below.
#[derive(Debug, Deserialize)]
pub(crate) struct AssertionForm {
    /// The relying party's `client_id` (the ID token audience).
    client_id: Option<String>,
    /// The account id the browser got from the accounts endpoint (must equal the OP
    /// session's per-env public subject).
    account_id: Option<String>,
    /// The RP-supplied single-use `nonce`, echoed into the minted token and consumed
    /// against the replay latch.
    nonce: Option<String>,
    /// Whether the browser showed the disclosure text (carried by the spec; recorded
    /// only implicitly by the issuance audit, never trusted for a decision).
    #[allow(dead_code)]
    disclosure_text_shown: Option<String>,
}

/// The UNIFORM refusal for any id-assertion request that fails a validation check
/// (unknown/disabled client, account mismatch, origin mismatch, replayed nonce,
/// consent unmet, or a malformed body): a single `400` with a generic FedCM error
/// body, carrying NO CORS headers, so the browser surfaces a generic failure and the
/// response is an ORACLE for NONE of the individual checks. Distinct from the flag-off
/// `404`, the non-FedCM-fetch `400`, and a server fault `500`.
fn assertion_refused() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        r#"{"error":{"code":"access_denied"}}"#,
    )
        .into_response()
}

/// A server-fault refusal for the id-assertion endpoint (a store or signer failure):
/// a `500` with no token and no CORS, so a fault fails CLOSED and never mints.
fn assertion_server_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        r#"{"error":{"code":"server_error"}}"#,
    )
        .into_response()
}

/// The client's registered `https` redirect-URI ORIGINS (Fork B1): the exact-match
/// set the assertion endpoint binds the RP `Origin` against. Derived from the SAME
/// `redirect_uris` registration data the redirect flow's exact-string match trusts,
/// through the SAME [`origin_of`] canonicalizer (scheme + host + port, default port
/// dropped, case-normalized). Non-`https` redirect targets are excluded: a FedCM RP is
/// a secure web origin.
fn client_https_origins(client: &ClientRecord) -> Vec<String> {
    client
        .redirect_uris
        .iter()
        .filter_map(|uri| origin_of(uri))
        .filter(|origin| origin.starts_with("https://"))
        .collect()
}

/// Whether the request `Origin` (a FORBIDDEN, browser-authored, unforgeable header)
/// EXACT-matches one of the client's registered `https` redirect-URI origins. Both
/// sides are canonicalized through [`origin_of`], so `https://rp.example:443` and
/// `https://rp.example` compare equal, but a different host or port never does. An
/// absent or unparseable `Origin` is a MISMATCH (fail closed): the RP-origin binding is
/// the sole RP-authentication factor and can never be bypassed by omitting the header.
fn origin_matches_client(client: &ClientRecord, request_origin: Option<&str>) -> bool {
    let Some(normalized) = request_origin.and_then(origin_of) else {
        return false;
    };
    client_https_origins(client)
        .iter()
        .any(|origin| origin == &normalized)
}

/// Whether the redirect flow's consent discipline is SATISFIED for this `(client,
/// subject)`, reusing the SAME primitives as [`crate::authorize::resolve_consent_gate`]
/// so FedCM can never be a consent bypass:
///
/// - a QUARANTINED (unverified, issue #31) client NEVER satisfies FedCM consent. The
///   redirect flow forces a fresh consent screen on EVERY authorization for a
///   quarantined client (`resolve_consent_gate` sets `force_consent = ... ||
///   client.quarantined`, which disables BOTH its first-party carve-out AND its
///   recorded-consent fast path, so a pre-recorded consent can never silently
///   auto-authorize it). FedCM cannot render that screen, so the exact analog is to
///   REFUSE. This mirrors the SAME `client.quarantined` field the redirect flow reads,
///   for BOTH the carve-out and the recorded-consent path;
/// - a QUARANTINED USER (issue #82, PR 2) likewise NEVER satisfies FedCM consent, the
///   analog of the redirect flow routing a quarantined SUBJECT to the consent screen.
///   Gated on the experimental signup-quarantine flag; bounded to the openid identity
///   assertion (no access/refresh token, no client scope);
/// - otherwise the trusted first-party carve-out (an `implicit`-mode or `skip_consent`
///   client) is auto-granted;
/// - otherwise a recorded, UNEXPIRED consent whose granted scope COVERS the `openid`
///   identity scope authorizes issuance; a narrower, expired, or absent consent does
///   not.
///
/// Returns `Err(())` on a store fault so the caller fails CLOSED (never mints on an
/// unreadable consent state).
async fn fedcm_consent_satisfied(
    state: &OidcState,
    scope: ironauth_store::Scope,
    client: &ClientRecord,
    subject: &str,
) -> Result<bool, ()> {
    // A QUARANTINED (unverified) client NEVER satisfies FedCM consent. The redirect
    // flow forces a fresh consent screen for a quarantined client on EVERY
    // authorization (resolve_consent_gate's `force_consent || client.quarantined`,
    // which disables both the first-party carve-out and the recorded-consent fast
    // path); FedCM cannot render that screen, so its exact analog is to REFUSE. This
    // is the SAME `client.quarantined` rule the redirect flow uses (issue #31), so a
    // pre-recorded consent can never silently auto-authorize an unverified client.
    if client.quarantined {
        return Ok(false);
    }
    // A QUARANTINED USER (issue #82, PR 2) likewise NEVER satisfies FedCM consent, the exact
    // analog of the redirect flow routing a quarantined subject to the consent SCREEN (which
    // disables its first-party carve-out so an un-consented app is always shown consent).
    // FedCM cannot render that screen, so refuse, mirroring the `client.quarantined` line
    // right above. This is bounded to the openid identity assertion (no access/refresh token,
    // no client scope), but it keeps FedCM consistent with the "no silent auto-grant for a
    // quarantined SUBJECT" discipline the redirect flow enforces. Gated on the experimental
    // signup-quarantine flag, so when the feature is off the read never runs and behavior is
    // byte-identical. A subject that fails to parse is treated as not quarantined; a store
    // fault fails CLOSED (`Err(())`), the same posture as the recorded-consent read below.
    if state.signup_quarantine_enabled() {
        if let Ok(subject_id) = UserId::parse_in_scope(subject, &scope) {
            if state
                .store()
                .scoped(scope)
                .users()
                .is_quarantined(&subject_id)
                .await
                .map_err(|_| ())?
            {
                return Ok(false);
            }
        }
    }
    // The first-party carve-out, byte-for-byte the redirect flow's rule (issue #21,
    // #31): implicit/skip_consent is auto-granted (the client is not quarantined here,
    // that case already returned above).
    let consent_mode = ConsentMode::parse(&client.consent_mode);
    let first_party = matches!(consent_mode, ConsentMode::Implicit) || client.skip_consent;
    if first_party {
        return Ok(true);
    }
    // Otherwise honor a recorded consent EXACTLY as the redirect flow does: read the
    // same (subject, client_id) row and require it to be unexpired AND to cover the
    // requested (identity) scope.
    let client_id_str = client.id.to_string();
    let recorded = state
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(subject, &client_id_str)
        .await
        .map_err(|_| ())?;
    let now_micros = epoch_micros(state.now());
    let covered = recorded
        .as_ref()
        .is_some_and(|consent| !consent_expired(consent, now_micros))
        && consent_covers_scope(recorded.as_ref(), Some(FEDCM_ASSERTION_SCOPE));
    Ok(covered)
}

/// `POST /t/{t}/e/{e}/fedcm/assertion`: the FedCM ID assertion endpoint (issue #83),
/// the credential-issuing surface. It mints an ID token DIRECTLY to a relying party,
/// under the SAME validation discipline as the redirect flow (see the module-level
/// no-bypass proof). The checks run in this order, each failing to the SAME uniform
/// refusal (no oracle):
///
/// 1. the `fedcm` flag is on (else a uniform `404`);
/// 2. `Sec-Fetch-Dest: webidentity` is present (else a plain `400`, a non-FedCM fetch);
/// 3. the path scope is the single designated FedCM env (else `404`);
/// 4. the body carries `client_id`, `account_id`, and `nonce`;
/// 5. the OP session resolves from the `SameSite` cookie (issue #32);
/// 6. `account_id` EQUALS the session's per-env public subject (no assertion for
///    another account);
/// 7. the `client_id` is a registered client in the designated scope
///    ([`ironauth_store::ClientRepo::get`]);
/// 8. the request `Origin` EXACT-matches one of the client's registered `https`
///    redirect-URI origins (Fork B1);
/// 9. consent is satisfied for `(client, subject)` (the redirect flow's rule; unmet
///    never mints, and a quarantined client is refused);
/// 10. the single-use `(scope, client_id, nonce)` latch reserves-and-consumes (a
///     replayed nonce is rejected, migration 0063). This runs AFTER the consent gate,
///     so a refused request never BURNS a fresh nonce: a nonce is consumed only for a
///     request that goes on to mint;
/// 11. the ID token is minted through [`tokens::mint_id_token`] (`aud = client_id`,
///     `sub = resolve_public_subject(session.subject)`, `iss` = the per-env issuer,
///     `nonce` echoed, the per-env signing policy) and the issuance is audited.
///
/// On success the response is `{"token": "<jwt>"}` with `Cache-Control: no-store` and
/// the FedCM-required CORS (`Access-Control-Allow-Origin: <the validated RP origin>`,
/// `Access-Control-Allow-Credentials: true`, `Vary: Origin`), so the browser can read
/// the assertion. An error carries NO CORS.
pub(crate) async fn assertion(
    State(state): State<OidcState>,
    axum::extract::Path((tenant_id, environment_id)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<AssertionForm>,
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
    // Single-env-per-origin (Fork A1): only the designated env issues assertions.
    if state.fedcm_designated_scope() != Some(scope) {
        return not_found();
    }

    // 4. The required body params. A missing/blank client_id, account_id, or nonce is
    //    the uniform refusal (no oracle for which field).
    let (Some(client_id_raw), Some(account_id), Some(nonce)) = (
        non_empty(form.client_id.as_deref()),
        non_empty(form.account_id.as_deref()),
        non_empty(form.nonce.as_deref()),
    ) else {
        return assertion_refused();
    };

    // 5. The OP session, from the SameSite session cookie ONLY (issue #32). No session
    //    -> refuse (never mint from an unauthenticated browser).
    let Some(session) = resolve_session(&state, scope, &headers).await else {
        return assertion_refused();
    };

    // 6. Account binding: the browser-supplied account_id MUST equal the value the
    //    accounts endpoint returned for THIS session (its per-env public subject),
    //    through the ONE subject function. A mismatch means the browser is asking for
    //    an assertion about an account other than the logged-in session's own subject.
    let public_subject = state.resolve_public_subject(&session.subject);
    if account_id != public_subject {
        return assertion_refused();
    }

    // 7. Client validation: the client_id must parse to the designated scope and be a
    //    registered client there. `ClientRepo::get` fails closed to NotFound for an
    //    unknown or cross-scope client (the SAME lookup the redirect flow uses), so an
    //    unknown/disabled/cross-tenant client is the uniform refusal, no oracle.
    let Ok(client_id) = ClientId::parse_declared_scope(client_id_raw) else {
        return assertion_refused();
    };
    let client = match state.store().scoped(scope).clients().get(&client_id).await {
        Ok(record) => record,
        Err(StoreError::NotFound) => return assertion_refused(),
        Err(_) => return assertion_server_error(),
    };

    // 8. RP origin binding (Fork B1): the browser-set, unforgeable `Origin` MUST
    //    exact-match a registered https redirect-uri origin. This is the sole
    //    RP-authentication factor (FedCM issues directly, with no token-endpoint
    //    client re-check), so it is enforced as strictly as the exact-match redirect.
    let request_origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if !origin_matches_client(&client, request_origin) {
        return assertion_refused();
    }

    // 9. Consent: honor the SAME consent discipline as the redirect flow. Unmet
    //    consent NEVER silently mints (the no-consent-bypass requirement), and a
    //    quarantined client is refused (the redirect flow's forced re-prompt). This
    //    runs BEFORE the nonce is consumed, so a refused request does not burn a nonce.
    match fedcm_consent_satisfied(&state, scope, &client, &session.subject).await {
        Ok(true) => {}
        Ok(false) => return assertion_refused(),
        Err(()) => return assertion_server_error(),
    }

    // 10. Nonce / replay: reserve-then-consume the single-use (scope, client_id, nonce)
    //     latch (migration 0063), only AFTER every refusal gate above has passed, so a
    //     refused (or quarantine/consent-blocked) request never BURNS a fresh nonce. A
    //     freshly reserved AND freshly consumed nonce passes; ANY re-presentation of the
    //     same (client_id, nonce) collides on reserve and is rejected as a replay. A
    //     store fault fails closed to a server error. The consume stays single-use and
    //     atomic and precedes the mint: a token is issued only for a freshly-consumed
    //     nonce, and a replay is still refused.
    let nonce_id = FedcmNonceId::generate(state.env(), &scope);
    let expires_at_micros = epoch_micros(
        state
            .now()
            .checked_add(state.code_ttl())
            .unwrap_or_else(|| state.now()),
    );
    let nonces = state.store().scoped(scope).fedcm_nonces();
    let Ok(reserved) = nonces
        .reserve(&nonce_id, &client_id, nonce, expires_at_micros)
        .await
    else {
        return assertion_server_error();
    };
    let now_micros = epoch_micros(state.now());
    let Ok(consumed) = nonces.consume(&client_id, nonce, now_micros).await else {
        return assertion_server_error();
    };
    if !(reserved && consumed) {
        return assertion_refused();
    }

    // 11. Mint the ID token through the EXACT redirect-flow minting core, and audit.
    let Some(token) =
        mint_assertion(&state, scope, &client, &session, &public_subject, nonce).await
    else {
        return assertion_server_error();
    };

    // Audit the issuance (who = the session subject, which client), targeting the
    // consumed nonce; the token value is NEVER recorded. A failed audit fails closed:
    // an assertion that cannot be recorded is not returned.
    let actor = client_service_actor(&client_id);
    let correlation = CorrelationId::generate(state.env());
    if state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .fedcm_nonces()
        .record_assertion_issued(state.env(), &nonce_id, &client_id, &public_subject)
        .await
        .is_err()
    {
        return assertion_server_error();
    }

    assertion_success(&token, request_origin)
}

/// Mint the FedCM ID assertion through the token endpoint's EXACT claim + signing path
/// ([`tokens::mint_id_token`], the identical core the redirect flow's front channel
/// uses), so a FedCM-minted assertion can never diverge from what the redirect flow
/// mints for the same `(client, subject, nonce)`: `aud = client_id`, `sub` the per-env
/// public subject through the ONE subject function, `iss` the per-env issuer, `nonce`
/// echoed, `amr`/`acr`/`auth_time` derived from the recorded authentication event, and
/// a per-(client, session) `sid` so the assertion is back-channel-logout-targetable
/// like any other token. Returns [`None`] on a missing signer or a signing/store fault,
/// so the caller fails CLOSED. There is NO parallel or looser mint.
async fn mint_assertion(
    state: &OidcState,
    scope: ironauth_store::Scope,
    client: &ClientRecord,
    session: &AuthenticatedSession,
    public_subject: &str,
    nonce: &str,
) -> Option<String> {
    let entry = state.issuer_entry(&scope).await?;
    let signer = entry.signer(state.now())?;
    let issuer = state.issuer_for(&scope);
    let client_id_str = client.id.to_string();
    // The per-(client, session) sid, resolved from the SAME authenticating SSO session
    // through the SAME (client, session) row the token endpoint uses (issue #32). Fails
    // closed: a store error or a no-longer-live session yields None (never a
    // silently session-less assertion).
    let now_micros = epoch_micros(state.now());
    let sid = state
        .store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(state.env(), &session.session_id, &client_id_str, now_micros)
        .await
        .ok()?;
    // auth_time is emitted under the SAME rule as a token-endpoint ID token: only when
    // the client registered require_auth_time (FedCM carries no max_age request).
    let auth_time_unix_micros = client
        .require_auth_time
        .then_some(session.auth_time_unix_micros);
    let extra_claims = serde_json::Map::new();
    let request = MintRequest {
        scope,
        issuer: &issuer,
        subject: public_subject,
        client_id: &client_id_str,
        nonce: Some(nonce),
        // FedCM issues no access token, so there is no granted OAuth scope to echo.
        oauth_scope: None,
        auth_methods: &session.auth_methods,
        auth_time_unix_micros,
        sid: Some(sid.as_str()),
        at_hash: None,
        c_hash: None,
        extra_claims: &extra_claims,
        // Signs with the environment default (FedCM never negotiates a per-client
        // id_token algorithm), exactly as the front channel does.
        id_token_signer: None,
        // FedCM mints an ID token only, never a DPoP-bound access token (issue #368).
        confirmation: None,
    };
    tokens::mint_id_token(state, signer, entry.policy(), &request)
        .ok()
        .map(|(token, _jti)| token)
}

/// The `200 OK` id-assertion success response: `{"token": "<jwt>"}`, `Cache-Control:
/// no-store`, plus the FedCM-required CORS so the browser can read the token. The
/// `Access-Control-Allow-Origin` echoes the EXACT (validated) RP `Origin` the browser
/// sent -- never a wildcard and never a reflected-but-unvalidated value, since the
/// origin was already exact-matched against the client's registered origins -- and
/// `Access-Control-Allow-Credentials: true` is required because the FedCM fetch is
/// credentialed. `Vary: Origin` keeps a shared cache from crossing the per-origin gate.
fn assertion_success(token: &str, request_origin: Option<&str>) -> Response {
    let body = serde_json::json!({ "token": token }).to_string();
    let mut response = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json".to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        body,
    )
        .into_response();
    // The RP origin was validated against the client's registered origins above, so
    // echoing it here is a known-good value, not a reflected one. It is always present
    // on a success path (the origin match already required it).
    if let Some(origin) = request_origin {
        if let Ok(value) = header::HeaderValue::from_str(origin) {
            let headers = response.headers_mut();
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                header::HeaderValue::from_static("true"),
            );
            headers.insert(header::VARY, header::HeaderValue::from_static("Origin"));
        }
    }
    response
}

/// A trimmed, non-empty view of an optional string field, or [`None`] when it is
/// absent or blank (so a blank required field is treated as missing).
fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}
