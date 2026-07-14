// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OAuth 2.0 Token Introspection endpoint (`POST /introspect`, RFC 7662).
//!
//! Introspection lets an authorized caller (a resource server, or a client acting as
//! one) ask the authorization server whether a presented token is currently active,
//! and read its standard metadata. Every edge here is a privacy decision:
//!
//! - **Client authentication is REQUIRED** (RFC 7662 section 2.1). The endpoint
//!   delegates to the SAME client-auth suite the token endpoint uses
//!   ([`crate::client_auth::authenticate_client_self_scoped`]), so a request that is
//!   unauthenticated or badly authenticated gets a `401` and learns NOTHING about any
//!   token (RFC 7662 section 4: the token-scanning-oracle defense). The only thing a
//!   `401` discloses is that client authentication failed.
//! - **Every not-active token looks identical.** An unknown, malformed, expired,
//!   revoked, cross-tenant, or wrong-format token all return the SAME `200
//!   {"active":false}`, so an authenticated caller cannot tell one not-active cause
//!   from another (no state oracle among token states).
//! - **The active response is byte-consistent with the token's real claims.** For an
//!   `at+jwt` the metadata comes from the VERIFIED token (a tampered payload fails the
//!   signature and reads as not-active); for an opaque or refresh token it comes from
//!   the authoritative store row. A revoked grant flips `active` to `false` even while
//!   the `at+jwt` signature still verifies (issue #12/#21), so introspection observes
//!   revocation the store records.
//! - **Cross-tenant isolation.** The token is resolved ONLY within the AUTHENTICATED
//!   client's `(tenant, environment)` scope (recovered from its own `client_id`). A
//!   token whose embedded scope is a different tenant/environment never resolves, so
//!   it reads as `active:false` and leaks nothing across the tenant boundary.
//!
//! # The pluggable response serializer (RFC 9701 forward design)
//!
//! Response construction goes through the [`IntrospectionSerializer`] seam so the RFC
//! 9701 signed-JWT introspection response can slot in later (M16) WITHOUT touching
//! this endpoint's resolve logic: the endpoint builds a typed [`IntrospectionClaims`]
//! and hands it to the serializer the state carries. Only the plain-JSON serializer
//! ([`JsonIntrospectionSerializer`], RFC 7662 section 2.2) is implemented now; M16
//! wires a signed-JWT serializer through
//! [`OidcState::with_introspection_serializer`](crate::OidcState::with_introspection_serializer)
//! and this file does not change.

use std::sync::Arc;

use axum::extract::{Form, State};
use axum::http::HeaderMap;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_jose::VerifiedToken;
use ironauth_store::{IssuedTokenId, RefreshTokenId, Scope};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::client_auth::{ClientAuthInputs, ClientAuthMethod, authenticate_client_self_scoped};
use crate::state::OidcState;
use crate::token_credential::{self, PresentedTokenKind, opaque_handle, peek_claim, peek_jti};
use crate::tokens::{OPAQUE_ACCESS_TOKEN_PREFIX, OPAQUE_REFRESH_TOKEN_PREFIX};

/// The RFC 6749 5.1 token type reported for an access token (`Bearer`). Refresh
/// tokens carry no RFC 6749 5.1 token type, so their introspection omits the field.
const BEARER_TOKEN_TYPE: &str = "Bearer";

/// The typed introspection result the endpoint builds and the serializer renders.
///
/// It carries `active` plus the RFC 7662 section 2.2 standard metadata IronAuth
/// discloses, each optional so a not-applicable field (an `aud`/`token_type` for a
/// refresh token) is simply omitted. A [`inactive`](IntrospectionClaims::inactive)
/// response carries ONLY `active: false`, exactly as RFC 7662 requires, so no
/// not-active state is distinguishable from another.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntrospectionClaims {
    /// Whether the token is currently active (RFC 7662 section 2.2). The one field
    /// always present.
    pub active: bool,
    /// The granted OAuth `scope` value, when the token carries one.
    pub scope: Option<String>,
    /// The OAuth client the token was issued to.
    pub client_id: Option<String>,
    /// The token's subject, derived through the ONE shared subject function so it is
    /// byte-identical to the ID token's / `UserInfo`'s `sub`.
    pub sub: Option<String>,
    /// The token type (`Bearer` for an access token; omitted for a refresh token).
    pub token_type: Option<String>,
    /// Expiry, in seconds since the Unix epoch.
    pub exp: Option<i64>,
    /// Issuance, in seconds since the Unix epoch.
    pub iat: Option<i64>,
    /// The audience(s) the token targets (issue #28): a resource server (or several,
    /// RFC 8707), or the client id for the no-resource case. EMPTY means no audience
    /// (a refresh token). Serialized as a single JSON STRING for one audience (the
    /// common case, byte-identical to the pre-#28 wire form) or a JSON ARRAY for
    /// several (RFC 7662 permits either).
    pub aud: Vec<String>,
}

impl IntrospectionClaims {
    /// The uniform not-active response: `{"active": false}` and nothing else.
    #[must_use]
    pub fn inactive() -> Self {
        Self::default()
    }
}

/// A serialized introspection response: the wire body and the media type to serve it
/// under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedIntrospection {
    /// The `Content-Type` the body is served under.
    pub content_type: &'static str,
    /// The response body.
    pub body: String,
}

/// The pluggable introspection-response serializer seam (issue #22).
///
/// The endpoint resolves the token into a typed [`IntrospectionClaims`] and hands it
/// here, so a future RFC 9701 signed-JWT introspection response (M16) slots in as a
/// new implementor WITHOUT touching the endpoint's resolve or authentication logic.
/// Only [`JsonIntrospectionSerializer`] (RFC 7662 section 2.2 plain JSON) ships now.
pub trait IntrospectionSerializer: Send + Sync {
    /// Render the introspection claims into a wire body and its media type.
    fn serialize(&self, claims: &IntrospectionClaims) -> SerializedIntrospection;
}

/// The RFC 7662 section 2.2 plain-JSON introspection serializer (the only one this
/// build ships). Emits `active` always, and every other field only when present, so
/// a not-active response is exactly `{"active":false}`.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonIntrospectionSerializer;

impl IntrospectionSerializer for JsonIntrospectionSerializer {
    fn serialize(&self, claims: &IntrospectionClaims) -> SerializedIntrospection {
        let mut object = Map::new();
        object.insert("active".to_owned(), Value::Bool(claims.active));
        insert_str(&mut object, "scope", claims.scope.as_deref());
        insert_str(&mut object, "client_id", claims.client_id.as_deref());
        insert_str(&mut object, "sub", claims.sub.as_deref());
        insert_str(&mut object, "token_type", claims.token_type.as_deref());
        insert_i64(&mut object, "exp", claims.exp);
        insert_i64(&mut object, "iat", claims.iat);
        insert_aud(&mut object, &claims.aud);
        SerializedIntrospection {
            content_type: "application/json",
            body: Value::Object(object).to_string(),
        }
    }
}

/// Insert a string field only when present (RFC 7662: omit an absent claim, never
/// emit `null`).
fn insert_str(object: &mut Map<String, Value>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        object.insert(name.to_owned(), Value::String(value.to_owned()));
    }
}

/// Insert a numeric field only when present.
fn insert_i64(object: &mut Map<String, Value>, name: &str, value: Option<i64>) {
    if let Some(value) = value {
        object.insert(name.to_owned(), Value::from(value));
    }
}

/// Insert the `aud` claim in its RFC 7662 shape (issue #28): OMITTED when empty, a
/// single JSON STRING for exactly one audience (byte-identical to the pre-#28 wire
/// form, so a single-audience token still reports `"aud":"..."`), or a JSON ARRAY for
/// several (a multi-resource token per RFC 8707 / RFC 9068).
fn insert_aud(object: &mut Map<String, Value>, audiences: &[String]) {
    match audiences {
        [] => {}
        [single] => {
            object.insert("aud".to_owned(), Value::String(single.clone()));
        }
        many => {
            object.insert(
                "aud".to_owned(),
                Value::Array(many.iter().cloned().map(Value::String).collect()),
            );
        }
    }
}

/// The introspection request parameters (form-encoded, RFC 7662 section 2.1).
///
/// `client_secret` is a client credential, so it is redacted from `Debug`.
#[derive(Deserialize)]
pub struct IntrospectParams {
    /// The token to introspect (REQUIRED).
    pub token: Option<String>,
    /// An optional NON-authoritative hint at the token type; the actual format is
    /// determined from the token's own shape, so a wrong hint changes nothing.
    pub token_type_hint: Option<String>,
    /// The client identifier (for `client_secret_post` / public clients).
    pub client_id: Option<String>,
    /// The client secret for `client_secret_post` authentication.
    pub client_secret: Option<String>,
    /// The JWT client assertion for `private_key_jwt` authentication.
    pub client_assertion: Option<String>,
    /// The RFC 7521 `client_assertion_type` accompanying `client_assertion`.
    pub client_assertion_type: Option<String>,
}

impl std::fmt::Debug for IntrospectParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectParams")
            .field("has_token", &self.token.is_some())
            .field("token_type_hint", &self.token_type_hint)
            .field("client_id", &self.client_id)
            .field("has_client_secret", &self.client_secret.is_some())
            .field("has_client_assertion", &self.client_assertion.is_some())
            .finish_non_exhaustive()
    }
}

/// `POST /introspect` (RFC 7662).
pub async fn introspect(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(params): Form<IntrospectParams>,
) -> Response {
    // 1. REQUIRE client authentication (RFC 7662 section 2.1). A failure is a 401/400
    //    that leaks nothing about any token (RFC 7662 section 4). The scope is
    //    recovered from the authenticated client's own id: the token is resolved ONLY
    //    within it, so a token from another tenant/environment can never leak here.
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let inputs = ClientAuthInputs {
        authorization,
        client_id: params.client_id.as_deref(),
        client_secret: params.client_secret.as_deref(),
        client_assertion: params.client_assertion.as_deref(),
        client_assertion_type: params.client_assertion_type.as_deref(),
    };
    // Introspection REQUIRES client authentication (RFC 7662 section 2.1). Any failure
    // (missing OR bad credentials) is a uniform 401 that leaks NOTHING about any token
    // (section 4, the token-scanning-oracle defense), stricter than the token
    // endpoint's invalid_request/invalid_client split so an unauthenticated probe never
    // even reaches the token lookup.
    let Ok((client, scope)) = authenticate_client_self_scoped(&state, inputs).await else {
        return unauthorized();
    };

    // A CONFIDENTIAL client is required (RFC 7662 section 2.1). A `client_id` is NOT a
    // secret: it appears in the clear in front-channel authorize URLs, so a public
    // `none` client presenting only its id has proven nothing, and letting it read a
    // token's active state and metadata would make section 4's "client authentication
    // REQUIRED" a non-barrier for any tenant that has a public client. A public `none`
    // client (or a caller presenting only a `client_id`) therefore gets the SAME
    // uniform 401 a missing/bad credential returns, leaking nothing, leaving only a
    // client that verified a real secret / assertion able to introspect. (Contrast
    // `/revoke`, which RFC 7009 explicitly allows public clients to call: it is
    // owner-scoped via the foreign-client no-op and returns no data, so it keeps
    // accepting `none`.)
    if client.auth_method == ClientAuthMethod::None {
        return unauthorized();
    }

    // 2. token is REQUIRED. Its absence is a plain request error (not a token oracle).
    let Some(token) = params
        .token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return crate::error::TokenError::InvalidRequest("token is required".to_owned())
            .into_response();
    };

    // 3. Resolve the token within the authenticated client's scope. Any not-active
    //    cause collapses to the uniform inactive response. This is DELIBERATELY
    //    fail-closed: a genuine transient STORE ERROR in a resolve also reads as
    //    `active:false` (the resolves swallow it with `.ok()?`), asymmetric with
    //    `/revoke` (which surfaces a 500 on a store fault). Never AUTHORIZE a token on
    //    a database blip, and every not-active cause staying byte-identical preserves
    //    the RFC 7662 section 4 anti-oracle uniformity: routing a store error to a
    //    distinguishable status would itself be an oracle. Intentional; see the
    //    per-resolve `.ok()?` notes.
    let claims = resolve(&state, scope, token)
        .await
        .unwrap_or_else(IntrospectionClaims::inactive);

    // 4. Render through the pluggable serializer (RFC 9701 seam) and cache nothing.
    let serialized = state.introspection_serializer().serialize(&claims);
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, serialized.content_type),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        serialized.body,
    )
        .into_response()
}

/// Resolve the presented token to its active claims, or [`None`] for every not-active
/// cause (which the caller maps to the uniform inactive response). Dispatches on the
/// token's self-describing format and runs the SCOPE-BOUND, RLS-forced resolve for it.
async fn resolve(state: &OidcState, scope: Scope, token: &str) -> Option<IntrospectionClaims> {
    match token_credential::classify(token) {
        PresentedTokenKind::Refresh => resolve_refresh(state, scope, token).await,
        PresentedTokenKind::OpaqueAccess => resolve_opaque(state, scope, token).await,
        PresentedTokenKind::JwtAccess => resolve_jwt(state, scope, token).await,
    }
}

/// Resolve an `at+jwt` access token (issue #29): recover its `jti` and confirm it is
/// a genuinely issued, still-live grant, then cryptographically verify the token, so
/// a tampered payload or a revoked grant reads as not-active.
async fn resolve_jwt(state: &OidcState, scope: Scope, token: &str) -> Option<IntrospectionClaims> {
    // The jti is only a lookup handle; parse it IN the authenticated client's scope,
    // so a token whose embedded scope is another tenant/environment never resolves.
    let jti_raw = peek_jti(token)?;
    let jti = IssuedTokenId::parse_in_scope(&jti_raw, &scope).ok()?;

    // The store is the revocation authority: a revoked grant flips active to false
    // even while the signature still verifies.
    let resolution = state
        .store()
        .scoped(scope)
        .authorization()
        .resolve_access_token(&jti)
        .await
        .ok()??;
    if !resolution.active {
        return None;
    }

    // Verify the signature/exp/iss against the token's OWN audience (peeked, then
    // signature-confirmed): a tampered aud fails the signature and reads not-active.
    // RFC 7519 permits `aud` to be EITHER a single string OR an array of strings, and
    // issue #28 (resource indicators, RFC 8707) will mint multi-audience tokens, so
    // accept both shapes and verify against ANY member. `verify_access_token` binds a
    // single `&str` audience (the JOSE policy already enforces exact array membership),
    // so a multi-aud token is verified member by member; this never weakens the
    // binding, since the token verifies only if one of its real, signed audiences is
    // the expected one.
    let audiences = peek_audiences(token)?;
    let verified = verify_any_audience(state, &scope, &audiences, token).await?;
    let claims = verified.claims();
    Some(IntrospectionClaims {
        active: true,
        scope: claims
            .get("scope")
            .and_then(Value::as_str)
            .map(str::to_owned),
        client_id: claims
            .get("client_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        sub: claims.subject().map(str::to_owned),
        token_type: Some(BEARER_TOKEN_TYPE.to_owned()),
        exp: claims.expiration(),
        iat: claims.issued_at(),
        // Report the token's FULL signed audience set (RFC 7662 section 2.2: the `aud`
        // is the token's intended audience, so under-reporting it could make an RS that
        // relies on introspection wrongly reject a valid multi-resource token). The
        // audiences were signature-confirmed (a member of them is what `verify_any_
        // audience` bound), and the serializer collapses a one-element vec to a bare
        // string (byte-identical to the pre-#28 single-audience wire form) and emits an
        // array for several, exactly the shape the opaque path reports.
        aud: claims.audiences().to_vec(),
    })
}

/// The token's peeked (unverified) `aud` claim as the list of candidate audiences to
/// verify against. RFC 7519 permits `aud` to be a single string OR an array of
/// strings, so this returns a one-element list for a string, the string members for
/// an array, and [`None`] when `aud` is absent, is neither a string nor an array, or
/// is an array with no string member (each of which reads as not-active). The values
/// are only lookup candidates: the signature re-checks whichever one verifies, so a
/// tampered `aud` still fails and reads not-active.
fn peek_audiences(token: &str) -> Option<Vec<String>> {
    match peek_claim(token, "aud")? {
        Value::String(single) => Some(vec![single]),
        Value::Array(members) => {
            let auds: Vec<String> = members
                .into_iter()
                .filter_map(|value| match value {
                    Value::String(member) => Some(member),
                    _ => None,
                })
                .collect();
            (!auds.is_empty()).then_some(auds)
        }
        _ => None,
    }
}

/// Verify the token against ANY of its candidate audiences, returning the first that
/// verifies. `verify_access_token` binds a single `&str` audience, so a multi-audience
/// token (RFC 7519 / RFC 8707) is verified member by member; [`None`] if none verify.
/// This does not weaken the binding: the token still has to carry the presented
/// audience among its signed `aud` members for the JOSE policy to accept it.
async fn verify_any_audience(
    state: &OidcState,
    scope: &Scope,
    audiences: &[String],
    token: &str,
) -> Option<VerifiedToken> {
    for audience in audiences {
        if let Ok(verified) = state.verify_access_token(scope, audience, token).await {
            return Some(verified);
        }
    }
    None
}

/// Resolve an opaque `ira_at_` access token (issue #29) through the digest-only store
/// resolve, the SAME internal authority `UserInfo` uses. Absent, expired, revoked, or
/// cross-scope all resolve to nothing (the uniform not-active).
async fn resolve_opaque(
    state: &OidcState,
    scope: Scope,
    token: &str,
) -> Option<IntrospectionClaims> {
    // Confirm the token's declared scope matches the authenticated client's scope
    // before the digest lookup (defense in depth; the RLS-scoped digest lookup would
    // also miss a foreign token).
    let handle = opaque_handle(token, OPAQUE_ACCESS_TOKEN_PREFIX)?;
    IssuedTokenId::parse_in_scope(handle, &scope).ok()?;

    let active = state
        .store()
        .scoped(scope)
        .authorization()
        .resolve_opaque_access_token(token, epoch_micros(state))
        .await
        .ok()??;
    Some(IntrospectionClaims {
        active: true,
        scope: active.scope.clone(),
        client_id: Some(active.client_id.clone()),
        // The opaque row stores the LOCAL subject; derive the public sub through the
        // ONE shared function so it is byte-identical to the ID token's / UserInfo's.
        sub: Some(state.resolve_public_subject(&active.subject)),
        token_type: Some(BEARER_TOKEN_TYPE.to_owned()),
        exp: Some(active.expires_at_unix_micros.div_euclid(1_000_000)),
        iat: Some(active.issued_at_unix_micros.div_euclid(1_000_000)),
        // The FULL recorded audience set (issue #28): an opaque token carries no
        // self-contained claims, so its audiences are recorded on the row and
        // reported here exactly as minted (a single string, or an array).
        aud: active.audiences,
    })
}

/// Resolve a refresh token (`ira_rt_`, issue #21). Active only while its family and
/// grant are live, it has not been rotated away (superseded), and neither its idle
/// timeout nor its family hard cap has passed.
async fn resolve_refresh(
    state: &OidcState,
    scope: Scope,
    token: &str,
) -> Option<IntrospectionClaims> {
    let handle = opaque_handle(token, OPAQUE_REFRESH_TOKEN_PREFIX)?;
    RefreshTokenId::parse_in_scope(handle, &scope).ok()?;

    let resolution = state
        .store()
        .scoped(scope)
        .refresh()
        .load(token)
        .await
        .ok()??;
    let now = epoch_micros(state);
    let live = resolution.active
        && !resolution.rotated
        && resolution.idle_expires_at_unix_micros > now
        && resolution.family_absolute_expires_at_unix_micros > now;
    if !live {
        return None;
    }
    Some(IntrospectionClaims {
        active: true,
        scope: resolution.scope.clone(),
        client_id: Some(resolution.client_id.clone()),
        sub: Some(state.resolve_public_subject(&resolution.subject)),
        // A refresh token carries no RFC 6749 5.1 token type and no audience.
        token_type: None,
        exp: Some(resolution.idle_expires_at_unix_micros.div_euclid(1_000_000)),
        iat: Some(resolution.issued_at_unix_micros.div_euclid(1_000_000)),
        aud: Vec::new(),
    })
}

/// The uniform RFC 7662 section 2.3 unauthorized response: a `401 invalid_client`
/// with a `Basic` challenge and a body that reveals NOTHING about any token (the
/// section 4 token-scanning-oracle defense). Returned for EVERY client-auth failure,
/// so a missing credential and a bad one are indistinguishable, and neither reaches
/// the token lookup.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (
                header::WWW_AUTHENTICATE,
                "Basic realm=\"ironauth\", charset=\"UTF-8\"",
            ),
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        r#"{"error":"invalid_client"}"#,
    )
        .into_response()
}

/// Now, in microseconds since the Unix epoch, from the environment clock seam (never
/// the raw system clock), for the opaque/refresh resolves' expiry comparison.
fn epoch_micros(state: &OidcState) -> i64 {
    state
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|delta| i64::try_from(delta.as_micros()).ok())
        .unwrap_or(i64::MAX)
}

/// The default introspection serializer (plain JSON), shared by every state that did
/// not install a custom one.
#[must_use]
pub(crate) fn default_serializer() -> Arc<dyn IntrospectionSerializer> {
    Arc::new(JsonIntrospectionSerializer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_response_carries_only_active_false() {
        let body = JsonIntrospectionSerializer.serialize(&IntrospectionClaims::inactive());
        assert_eq!(body.content_type, "application/json");
        assert_eq!(body.body, r#"{"active":false}"#);
    }

    #[test]
    fn active_response_omits_absent_fields_and_keeps_present_ones() {
        let claims = IntrospectionClaims {
            active: true,
            scope: Some("openid profile".to_owned()),
            client_id: Some("cli_x".to_owned()),
            sub: Some("usr_abc".to_owned()),
            token_type: Some("Bearer".to_owned()),
            exp: Some(1_300),
            iat: Some(1_000),
            aud: vec!["cli_x".to_owned()],
        };
        let value: Value =
            serde_json::from_str(&JsonIntrospectionSerializer.serialize(&claims).body).unwrap();
        assert_eq!(value["active"], Value::Bool(true));
        assert_eq!(value["scope"], "openid profile");
        assert_eq!(value["client_id"], "cli_x");
        assert_eq!(value["sub"], "usr_abc");
        assert_eq!(value["token_type"], "Bearer");
        assert_eq!(value["exp"], 1_300);
        assert_eq!(value["iat"], 1_000);
        assert_eq!(value["aud"], "cli_x");

        // A refresh-shaped active response omits aud and token_type entirely (never
        // emitted as null).
        let refresh = IntrospectionClaims {
            active: true,
            scope: None,
            client_id: Some("cli_x".to_owned()),
            sub: Some("usr_abc".to_owned()),
            token_type: None,
            exp: Some(9),
            iat: Some(1),
            aud: Vec::new(),
        };
        let value: Value =
            serde_json::from_str(&JsonIntrospectionSerializer.serialize(&refresh).body).unwrap();
        assert!(value.get("aud").is_none(), "aud omitted, not null");
        assert!(value.get("token_type").is_none(), "token_type omitted");
        assert!(value.get("scope").is_none(), "absent scope omitted");
    }
}
