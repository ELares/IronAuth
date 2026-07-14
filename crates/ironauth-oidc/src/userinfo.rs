// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `UserInfo` endpoint (`GET`/`POST /userinfo`, OIDC Core 5.3).
//!
//! `UserInfo` returns the authenticated end user's claims for a presented access
//! token. The endpoint is small but every edge is a security decision:
//!
//! - **Bearer, header only.** The access token is taken ONLY from the
//!   `Authorization: Bearer` header (RFC 6750 2.1). A token presented in the query
//!   string is refused with an `invalid_request` challenge, never honored: a
//!   query-string credential leaks into logs, proxies, and the `Referer` header.
//! - **Spec-exact challenges** (RFC 6750 3.1). A MISSING token is a `401` with a
//!   bare `Bearer` challenge and NO error code; an invalid/expired/revoked/unknown
//!   token is a `401` `invalid_token`; a token that lacks the `openid` scope is a
//!   `403` `insufficient_scope` carrying the `scope` attribute; a malformed request
//!   (a query token) is a `400` `invalid_request`.
//! - **`sub` is byte-identical to the ID token's.** `UserInfo` resolves the token to
//!   its local subject and derives `sub` through the ONE shared subject function
//!   ([`OidcState::resolve_public_subject`]), the same call the ID token used, so
//!   the two can never diverge (including for pairwise subjects when they land).
//! - **CORS for registered SPA origins, on this endpoint ONLY.** A browser SPA
//!   calling `UserInfo` cross-origin needs CORS; the authorization endpoint never
//!   gets it. Only an exactly-registered origin is echoed back; an unregistered
//!   origin receives no CORS headers.
//!
//! # How a token is resolved
//!
//! The access token is a signed `at+jwt` JWS whose authoritative state lives in
//! the store (grant-chain revocation cannot be expressed in the JWT itself). So
//! resolution uses BOTH halves:
//!
//! 1. The `jti` is read from the token's payload as an opaque handle and parsed for
//!    its embedded `(tenant, environment)` scope.
//! 2. The store resolves that `jti` back to its grant, SCOPE-BOUND (row-level
//!    security beneath), yielding the local subject, the client, and the live
//!    state. A token from another environment does not resolve; a revoked grant is
//!    rejected. This is the IDOR and revocation gate.
//! 3. The token is then cryptographically verified through the ONE hardened verify
//!    path against the environment's keys, issuer, and the resolved client as the
//!    audience, which enforces the signature and `exp`/`iss`/`aud`. Only a token
//!    that passes both halves builds a response.
//!
//! The `jti` read in step 1 is only a lookup handle: a forged one misses the store
//! (step 2) and a tampered payload fails verification (step 3), so nothing trusts
//! it before it is authenticated.

use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_store::{AccessTokenResolution, IssuedTokenId};
use serde_json::{Map, Value};

use crate::claims_request::ClaimsRequest;
use crate::scope_claims::{assemble_claims, parse_scope_set};
use crate::state::OidcState;

/// The realm named in every `WWW-Authenticate` challenge.
const REALM: &str = "ironauth";

/// The scope `UserInfo` requires the access token to carry (OIDC Core 5.3.1): a
/// token issued without `openid` is not a `UserInfo` credential.
const REQUIRED_SCOPE: &str = "openid";

/// A defensive cap on the raw token size before the unverified `jti` peek. The
/// hardened verify path caps again; this bounds the cheap pre-parse.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// `GET /userinfo`.
pub async fn userinfo_get(
    State(state): State<OidcState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(&state, &headers, query.as_deref()).await
}

/// `POST /userinfo`. The body is ignored: the access token is taken only from the
/// `Authorization` header (a form-body token would be an off-header credential).
pub async fn userinfo_post(
    State(state): State<OidcState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(&state, &headers, query.as_deref()).await
}

/// `OPTIONS /userinfo`: the CORS preflight a browser SPA sends before a
/// cross-origin `UserInfo` call. A registered origin gets the full preflight
/// response; an unregistered (or absent) origin gets a bare `204` with no CORS
/// headers, so the browser blocks the call.
pub async fn userinfo_preflight(State(state): State<OidcState>, headers: HeaderMap) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Some(origin) = registered_origin(&state, &headers) {
        let out = response.headers_mut();
        set_cors_origin(out, &origin);
        out.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        out.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization, Content-Type"),
        );
        out.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
    }
    response
}

/// Run the request and layer CORS on the result. CORS is applied to EVERY outcome
/// (success or challenge) for a registered origin, so a browser SPA can read the
/// response and its challenge; the authorization endpoint never calls this.
async fn respond(state: &OidcState, headers: &HeaderMap, query: Option<&str>) -> Response {
    let mut response = match resolve(state, headers, query).await {
        Ok(claims) => success(&claims),
        Err(error) => error.into_response(),
    };
    if let Some(origin) = registered_origin(state, headers) {
        let out = response.headers_mut();
        set_cors_origin(out, &origin);
    }
    response
}

/// Resolve the presented token and build the released claim set, or the precise
/// challenge to return.
async fn resolve(
    state: &OidcState,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<Map<String, Value>, UserInfoError> {
    // A token in the query string is refused outright (RFC 6750 2.3 is discouraged
    // and here disallowed): it leaks through logs, proxies, and Referer.
    if query_carries_access_token(query) {
        return Err(UserInfoError::InvalidRequest(
            "the access token must be presented in the Authorization header, not the query string",
        ));
    }

    // The access token, taken ONLY from the Authorization header.
    let token = bearer_token(headers)?;

    // 1. Read the jti (an opaque handle) and recover its embedded scope. A token
    //    whose payload is unreadable, or whose jti is not a scoped token id, is a
    //    uniform invalid_token.
    let jti_raw = peek_jti(&token).ok_or(UserInfoError::InvalidToken)?;
    let jti =
        IssuedTokenId::parse_declared_scope(&jti_raw).map_err(|_| UserInfoError::InvalidToken)?;
    let scope = jti.scope();

    // 2. Resolve the jti to its grant, SCOPE-BOUND: a token from another
    //    environment does not resolve here (IDOR), and a revoked grant is rejected.
    let resolution: AccessTokenResolution = state
        .store()
        .scoped(scope)
        .authorization()
        .resolve_access_token(&jti)
        .await
        .map_err(|_| UserInfoError::ServerError)?
        .ok_or(UserInfoError::InvalidToken)?;
    if !resolution.active {
        // The grant chain was revoked (for example a code reuse): the token is no
        // longer valid at UserInfo.
        return Err(UserInfoError::InvalidToken);
    }

    // 3. Cryptographically verify the token against the environment keys, issuer,
    //    and the resolved client as the audience: signature, exp, iss, aud. This
    //    is where an expired, tampered, or forged token is rejected.
    let verified = state
        .verify_access_token(&scope, &resolution.client_id, &token)
        .await
        .map_err(|()| UserInfoError::InvalidToken)?;

    // The granted scope drives which claim sets are released (Core 5.4). UserInfo
    // requires the openid scope (Core 5.3.1); its absence is insufficient_scope.
    let granted = parse_scope_set(verified.claims().get("scope").and_then(Value::as_str));
    if !granted.contains(REQUIRED_SCOPE) {
        return Err(UserInfoError::InsufficientScope);
    }

    // The claims request parameter's userinfo member (frozen onto the grant at
    // authorization). A stored value is already canonical; tolerate any anomaly by
    // treating it as no request rather than failing the response.
    let claims_request = resolution
        .claims_request
        .as_deref()
        .and_then(|raw| ClaimsRequest::parse(raw).ok())
        .unwrap_or_default();

    // The user's stored standard-claim document (empty when the user has none, or
    // is absent). Released selectively by scope and the claims request.
    let bag = user_claim_bag(state, &scope, &resolution.subject).await?;
    let mut released = assemble_claims(&bag, &granted, claims_request.userinfo());

    // sub is ALWAYS present and derived through the ONE shared subject function,
    // exactly as the ID token derived it, so the two are byte-identical (including
    // pairwise, once it lands). It can never be shadowed by stored claim data.
    let sub = state.resolve_public_subject(&resolution.subject);
    released.insert("sub".to_owned(), Value::String(sub));

    Ok(released)
}

/// Read the user's stored standard-claim document as a JSON object. An absent user,
/// an empty document, or an unparseable one all yield an empty object (no claims to
/// release), never an error: `UserInfo` still returns `sub`.
async fn user_claim_bag(
    state: &OidcState,
    scope: &ironauth_store::Scope,
    subject: &str,
) -> Result<Map<String, Value>, UserInfoError> {
    let raw = state
        .store()
        .scoped(*scope)
        .users()
        .claims_for_subject(subject)
        .await
        .map_err(|_| UserInfoError::ServerError)?;
    Ok(raw
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| match value {
            Value::Object(object) => Some(object),
            _ => None,
        })
        .unwrap_or_default())
}

/// Whether the raw query string carries an `access_token` parameter (RFC 6750 2.3),
/// which `UserInfo` refuses.
fn query_carries_access_token(query: Option<&str>) -> bool {
    let Some(query) = query else { return false };
    query.split('&').any(|pair| {
        let key = pair.split('=').next().unwrap_or("");
        key == "access_token"
    })
}

/// Extract the Bearer access token from the `Authorization` header, ONLY.
///
/// Returns [`UserInfoError::MissingToken`] (a bare `401` with no error code) when
/// there is no usable Bearer credential: no `Authorization` header at all, an
/// unsupported scheme (e.g. `Basic`), or an empty `Bearer` value. RFC 6750 3 says a
/// request that "attempted using an unsupported authentication method" gets the
/// bare challenge, not an error code, so the client is told to retry with a Bearer
/// token rather than handed a `400`. A genuinely malformed header (non-visible
/// bytes) or more than one `Authorization` header is [`UserInfoError::InvalidRequest`].
fn bearer_token(headers: &HeaderMap) -> Result<String, UserInfoError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(first) = values.next() else {
        return Err(UserInfoError::MissingToken);
    };
    if values.next().is_some() {
        return Err(UserInfoError::InvalidRequest(
            "more than one Authorization header",
        ));
    }
    let value = first
        .to_str()
        .map_err(|_| UserInfoError::InvalidRequest("malformed Authorization header"))?;
    // The scheme is case-insensitive (RFC 7235); the token itself is not decoded. A
    // non-Bearer scheme or an empty Bearer value is "no usable authentication
    // information", so it maps to the bare challenge (MissingToken), not an error.
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or(UserInfoError::MissingToken)?;
    Ok(token.to_owned())
}

/// Read the `jti` from a compact JWS payload WITHOUT verifying it, as a lookup
/// handle. Bounded and total: an oversized token, a non-three-segment shape, a
/// non-base64url payload, non-object claims, or a missing or non-string `jti` all
/// yield [`None`]. Nothing here is trusted; the token is authenticated afterward.
fn peek_jti(token: &str) -> Option<String> {
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value
        .as_object()?
        .get("jti")?
        .as_str()
        .map(ToOwned::to_owned)
}

/// The request `Origin` header value, if it is an exactly-registered SPA origin.
fn registered_origin(state: &OidcState, headers: &HeaderMap) -> Option<String> {
    let origin = headers.get(header::ORIGIN)?.to_str().ok()?;
    if state.is_registered_spa_origin(origin) {
        Some(origin.to_owned())
    } else {
        None
    }
}

/// Set the CORS allow-origin (echoing a registered origin, never a wildcard) and
/// `Vary: Origin` on a response. The origin came from the registered set, so it is
/// a known-good, non-reflected value.
fn set_cors_origin(headers: &mut HeaderMap, origin: &str) {
    if let Ok(value) = HeaderValue::from_str(origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
}

/// A `200 OK` `UserInfo` response: the claims JSON, `no-store` cached.
fn success(claims: &Map<String, Value>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Value::Object(claims.clone()).to_string(),
    )
        .into_response()
}

/// A `UserInfo` failure, each mapping to a spec-exact RFC 6750 3.1 challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserInfoError {
    /// No access token was presented: `401` with a bare `Bearer` challenge and NO
    /// error code (RFC 6750 3.1).
    MissingToken,
    /// The token is invalid, expired, revoked, or unknown: `401` `invalid_token`.
    InvalidToken,
    /// The token is valid but lacks the `openid` scope: `403` `insufficient_scope`
    /// carrying the required `scope` attribute.
    InsufficientScope,
    /// The request itself is malformed (a query-string token, a bad Authorization
    /// header): `400` `invalid_request`.
    InvalidRequest(&'static str),
    /// An unexpected server-side condition: `500`, no challenge.
    ServerError,
}

impl IntoResponse for UserInfoError {
    fn into_response(self) -> Response {
        // The challenge values are fixed server constants (no reflected input), so
        // building the header from them cannot inject.
        let (status, challenge) = match self {
            UserInfoError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                Some(format!("Bearer realm=\"{REALM}\"")),
            ),
            UserInfoError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                Some(format!(
                    "Bearer realm=\"{REALM}\", error=\"invalid_token\", \
                     error_description=\"the access token is invalid, expired, or revoked\""
                )),
            ),
            UserInfoError::InsufficientScope => (
                StatusCode::FORBIDDEN,
                Some(format!(
                    "Bearer realm=\"{REALM}\", error=\"insufficient_scope\", \
                     scope=\"{REQUIRED_SCOPE}\", \
                     error_description=\"the access token lacks the openid scope\""
                )),
            ),
            UserInfoError::InvalidRequest(_) => (
                StatusCode::BAD_REQUEST,
                Some(format!(
                    "Bearer realm=\"{REALM}\", error=\"invalid_request\""
                )),
            ),
            UserInfoError::ServerError => (StatusCode::INTERNAL_SERVER_ERROR, None),
        };
        let mut response = status.into_response();
        if let Some(challenge) = challenge {
            if let Ok(value) = HeaderValue::from_str(&challenge) {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, value);
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn query_access_token_is_detected() {
        assert!(query_carries_access_token(Some("access_token=abc")));
        assert!(query_carries_access_token(Some("foo=1&access_token=abc")));
        assert!(!query_carries_access_token(Some("foo=1&bar=2")));
        assert!(!query_carries_access_token(None));
        // A parameter merely containing the substring is not a match.
        assert!(!query_carries_access_token(Some("my_access_token=abc")));
    }

    #[test]
    fn bearer_token_requires_a_single_bearer_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), Err(UserInfoError::MissingToken));

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer tok-123"),
        );
        assert_eq!(bearer_token(&headers).as_deref(), Ok("tok-123"));

        // A non-Bearer scheme is an unsupported authentication method, so it gets
        // the bare challenge (MissingToken), not an error code (RFC 6750 3).
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer_token(&headers), Err(UserInfoError::MissingToken));

        // An empty Bearer value carries no usable credential, so likewise the bare
        // challenge rather than a 400.
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert_eq!(bearer_token(&headers), Err(UserInfoError::MissingToken));

        // Two Authorization headers are ambiguous: a genuinely malformed request.
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer other"),
        );
        assert!(matches!(
            bearer_token(&headers),
            Err(UserInfoError::InvalidRequest(_))
        ));
    }

    #[test]
    fn peek_jti_reads_the_handle_without_verifying() {
        // header.payload.signature with payload = {"jti":"tok_abc","sub":"x"}.
        let payload = URL_SAFE_NO_PAD.encode(json!({"jti":"tok_abc","sub":"x"}).to_string());
        let token = format!("aaa.{payload}.sig");
        assert_eq!(peek_jti(&token).as_deref(), Some("tok_abc"));

        // A two-segment (non-JWS) shape, and a payload with no jti, yield None.
        assert_eq!(peek_jti("aaa.bbb"), None);
        let no_jti = URL_SAFE_NO_PAD.encode(json!({"sub":"x"}).to_string());
        assert_eq!(peek_jti(&format!("h.{no_jti}.s")), None);
    }

    #[test]
    fn challenges_are_spec_exact() {
        let www = |error: UserInfoError| {
            error
                .into_response()
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap().to_owned())
        };
        // A missing token carries a bare Bearer challenge with NO error code.
        let missing = www(UserInfoError::MissingToken).expect("challenge");
        assert_eq!(missing, "Bearer realm=\"ironauth\"");
        assert!(
            !missing.contains("error="),
            "missing token names no error code"
        );

        assert!(
            www(UserInfoError::InvalidToken)
                .unwrap()
                .contains("error=\"invalid_token\"")
        );

        let scope = www(UserInfoError::InsufficientScope).unwrap();
        assert!(scope.contains("error=\"insufficient_scope\""));
        assert!(
            scope.contains("scope=\"openid\""),
            "carries the scope attribute"
        );

        assert!(
            www(UserInfoError::InvalidRequest("x"))
                .unwrap()
                .contains("error=\"invalid_request\"")
        );

        // A server error carries no Bearer challenge.
        assert!(www(UserInfoError::ServerError).is_none());
    }

    #[test]
    fn status_codes_match_the_spec() {
        assert_eq!(
            UserInfoError::MissingToken.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            UserInfoError::InvalidToken.into_response().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            UserInfoError::InsufficientScope.into_response().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            UserInfoError::InvalidRequest("x").into_response().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            UserInfoError::ServerError.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
