// SPDX-License-Identifier: MIT OR Apache-2.0

//! The UserInfo endpoint end to end, against a real Postgres (issue #15).
//!
//! Covers the acceptance criteria: GET and POST with header Bearer auth (and a
//! query-string token refused), the spec-exact RFC 6750 challenges for missing,
//! malformed, expired, and revoked tokens, a `sub` byte-identical to the ID
//! token's, the scope-to-claims mapping with the lean-ID-token default and the
//! `conformIdTokenClaims` override, the `claims` request parameter end to end, the
//! fail-closed essential-`acr` binding, and CORS for a registered SPA origin only.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Harness, REDIRECT_URI, SEED_PASSWORD, enc, form, json, location_param};
use ironauth_config::OidcConfig;
use serde_json::Value;
use std::time::Duration;

/// The standard-claim document the seeded UserInfo user carries.
const CLAIMS_JSON: &str = r#"{
    "name": "Ada Lovelace",
    "given_name": "Ada",
    "family_name": "Lovelace",
    "email": "ada@example.test",
    "email_verified": true,
    "phone_number": "+15550100",
    "address": { "locality": "London", "country": "GB" }
}"#;

/// Drive authorize + token for a fresh consenting user with the given `scope` and
/// optional `claims` request parameter, returning `(subject, access_token,
/// id_token)`. The user carries [`CLAIMS_JSON`].
async fn issue_tokens(
    harness: &Harness,
    scope: &str,
    claims_param: Option<&str>,
) -> (String, String, String) {
    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user_with_claims(&unique_identifier(harness), SEED_PASSWORD, CLAIMS_JSON)
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;

    let mut query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}",
        enc(REDIRECT_URI),
        enc(scope),
    );
    if let Some(claims) = claims_param {
        query.push_str("&claims=");
        query.push_str(&enc(claims));
    }
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::FOUND, "authorize should redirect: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");

    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
    ]);
    let (status, _, body) = harness.token(&exchange).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let value = json(&body);
    let access = value["access_token"].as_str().expect("access_token").to_owned();
    let id = value["id_token"].as_str().expect("id_token").to_owned();
    (subject, access, id)
}

/// A unique login handle drawn from the deterministic entropy stream.
fn unique_identifier(harness: &Harness) -> String {
    use std::fmt::Write as _;
    let mut suffix = [0_u8; 8];
    harness.env().entropy().fill_bytes(&mut suffix);
    let id = suffix.iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:02x}");
        acc
    });
    format!("userinfo-{id}@example.test")
}

/// A UserInfo request with an optional Bearer token, Origin, and raw query.
async fn userinfo(
    harness: &Harness,
    method: &str,
    bearer: Option<&str>,
    origin: Option<&str>,
    query: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let uri = query.map_or_else(|| "/userinfo".to_owned(), |q| format!("/userinfo?{q}"));
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    harness
        .send(builder.body(Body::empty()).expect("request builds"))
        .await
}

/// Decode a JWS payload segment's claims (unverified: for reading a claim in a
/// test only).
fn payload_claims(token: &str) -> serde_json::Map<String, Value> {
    let segment = token.split('.').nth(1).expect("payload segment");
    let bytes = URL_SAFE_NO_PAD.decode(segment).expect("base64url payload");
    serde_json::from_slice(&bytes).expect("claims json")
}

/// The `WWW-Authenticate` header value of a response.
fn challenge(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

#[tokio::test]
async fn get_and_post_return_claims_and_sub_matches_the_id_token() {
    let harness = Harness::start().await;
    let (_subject, access, id_token) = issue_tokens(&harness, "openid profile email", None).await;
    let id_sub = payload_claims(&id_token)["sub"].as_str().expect("id sub").to_owned();

    for method in ["GET", "POST"] {
        let (status, headers, body) = userinfo(&harness, method, Some(&access), None, None).await;
        assert_eq!(status, StatusCode::OK, "{method} userinfo: {body}");
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );
        let claims = json(&body);
        // sub is present and BYTE-IDENTICAL to the ID token's (shared derivation).
        assert_eq!(claims["sub"].as_str(), Some(id_sub.as_str()), "{method}");
        // profile + email claim sets are released; address (scope not granted) is not.
        assert_eq!(claims["name"], "Ada Lovelace", "{method}");
        assert_eq!(claims["given_name"], "Ada", "{method}");
        assert_eq!(claims["email"], "ada@example.test", "{method}");
        assert_eq!(claims["email_verified"], true, "{method}");
        assert!(claims.get("address").is_none(), "address not granted: {method}");
        assert!(claims.get("phone_number").is_none(), "phone not granted: {method}");
    }
}

#[tokio::test]
async fn the_default_id_token_stays_lean_and_userinfo_carries_the_scope_claims() {
    // Spec-conform default: the ID token carries NO scope-derived claims; they are
    // served from UserInfo instead.
    let harness = Harness::start().await;
    let (_subject, access, id_token) = issue_tokens(&harness, "openid email", None).await;
    let id_claims = payload_claims(&id_token);
    assert!(id_claims.get("email").is_none(), "lean ID token: no email");

    let (status, _, body) = userinfo(&harness, "GET", Some(&access), None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(json(&body)["email"], "ada@example.test");
}

#[tokio::test]
async fn conform_override_copies_scope_claims_into_the_id_token() {
    // The per-environment override places the scope-derived claims in the ID token
    // too (documented non-conform). UserInfo still returns them.
    let config = OidcConfig {
        conform_id_token_claims: true,
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    let (_subject, access, id_token) = issue_tokens(&harness, "openid email", None).await;
    let id_claims = payload_claims(&id_token);
    assert_eq!(id_claims["email"], "ada@example.test", "override copies email into the ID token");
    // sub is still the required protocol claim, never shadowed.
    assert!(id_claims["sub"].as_str().is_some_and(|s| s.starts_with("usr_")));

    let (status, _, body) = userinfo(&harness, "GET", Some(&access), None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(json(&body)["email"], "ada@example.test");
}

#[tokio::test]
async fn a_missing_token_is_401_with_a_bare_bearer_challenge() {
    let harness = Harness::start().await;
    let (status, headers, _) = userinfo(&harness, "GET", None, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let www = challenge(&headers).expect("challenge");
    assert_eq!(www, "Bearer realm=\"ironauth\"");
    assert!(!www.contains("error="), "a missing token names no error code");
}

#[tokio::test]
async fn a_malformed_token_is_401_invalid_token() {
    let harness = Harness::start().await;
    let (status, headers, _) = userinfo(&harness, "GET", Some("not-a-jwt"), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(challenge(&headers).unwrap().contains("error=\"invalid_token\""));
}

#[tokio::test]
async fn a_query_string_token_is_refused_invalid_request() {
    let harness = Harness::start().await;
    let (_subject, access, _) = issue_tokens(&harness, "openid", None).await;
    // The token is presented ONLY in the query string (no Authorization header).
    let query = format!("access_token={}", enc(&access));
    let (status, headers, _) = userinfo(&harness, "GET", None, None, Some(&query)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(challenge(&headers).unwrap().contains("error=\"invalid_request\""));
}

#[tokio::test]
async fn an_expired_token_is_401_invalid_token() {
    let harness = Harness::start().await;
    let (_subject, access, _) = issue_tokens(&harness, "openid profile", None).await;
    // The default access token lives 300s; advance well past exp + the verify skew.
    harness.clock().advance(Duration::from_secs(600));
    let (status, headers, _) = userinfo(&harness, "GET", Some(&access), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(challenge(&headers).unwrap().contains("error=\"invalid_token\""));
}

#[tokio::test]
async fn a_token_whose_grant_was_revoked_is_401_invalid_token() {
    // Reusing the code after the grace window revokes the grant chain (RFC 9700),
    // which flips the access token inactive at UserInfo.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user_with_claims(&unique_identifier(&harness), SEED_PASSWORD, CLAIMS_JSON)
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope=openid",
        enc(REDIRECT_URI),
    );
    let (_, headers, _) = harness.authorize_with_cookie(&query, &cookie).await;
    let code = location_param(&headers, "code").expect("code");
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
    ]);
    let (status, _, body) = harness.token(&exchange).await;
    assert_eq!(status, StatusCode::OK, "first exchange: {body}");
    let access = json(&body)["access_token"].as_str().expect("access").to_owned();

    // The token works before revocation.
    let (status, _, _) = userinfo(&harness, "GET", Some(&access), None, None).await;
    assert_eq!(status, StatusCode::OK, "token valid before revoke");

    // Reuse the code past the 10s grace window: revokes the grant chain.
    harness.clock().advance(Duration::from_secs(30));
    let (status, _, _) = harness.token(&exchange).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "reuse is invalid_grant");

    // The access token is now inactive at UserInfo.
    let (status, headers, _) = userinfo(&harness, "GET", Some(&access), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(challenge(&headers).unwrap().contains("error=\"invalid_token\""));
}

#[tokio::test]
async fn a_token_without_the_openid_scope_is_403_insufficient_scope() {
    let harness = Harness::start().await;
    // Granted profile but NOT openid: the token is not a UserInfo credential.
    let (_subject, access, _) = issue_tokens(&harness, "profile", None).await;
    let (status, headers, _) = userinfo(&harness, "GET", Some(&access), None, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let www = challenge(&headers).expect("challenge");
    assert!(www.contains("error=\"insufficient_scope\""));
    assert!(www.contains("scope=\"openid\""), "carries the scope attribute");
}

#[tokio::test]
async fn the_claims_parameter_is_honored_end_to_end() {
    let harness = Harness::start().await;
    // openid only (no profile/email scope), but the claims parameter requests name
    // and email for userinfo, email for the id_token, and an unsatisfiable website.
    let claims = r#"{
        "userinfo": { "name": null, "email": { "essential": true }, "website": null },
        "id_token": { "email": null }
    }"#;
    let (_subject, access, id_token) = issue_tokens(&harness, "openid", Some(claims)).await;

    // The id_token member placed email in the ID token even in spec-conform mode.
    assert_eq!(payload_claims(&id_token)["email"], "ada@example.test");

    let (status, _, body) = userinfo(&harness, "GET", Some(&access), None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let claims = json(&body);
    // The userinfo member released name and email despite no profile/email scope.
    assert_eq!(claims["name"], "Ada Lovelace");
    assert_eq!(claims["email"], "ada@example.test");
    // The unsatisfiable voluntary claim (website, absent from the user) is omitted.
    assert!(claims.get("website").is_none(), "unsatisfiable voluntary claim omitted");
    // A claim neither scope nor request selected is absent.
    assert!(claims.get("phone_number").is_none());
}

#[tokio::test]
async fn an_essential_acr_that_cannot_be_met_fails_closed_at_authorize() {
    // The bootstrap can only achieve the password ACR. An essential acr pinned to
    // a level it cannot reach must NOT silently downgrade: the request fails closed
    // (issue #15), surfaced through the authorize redirect error path (issue #16
    // refines the exact code).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;

    let claims = r#"{"id_token":{"acr":{"essential":true,"values":["urn:example:high"]}}}"#;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope=openid&state=xyz&claims={}",
        enc(REDIRECT_URI),
        enc(claims),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::FOUND, "fails closed by redirect: {body}");
    let location = headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("location");
    assert!(location.contains("error=access_denied"), "fail-closed error: {location}");
    assert!(location.contains("state=xyz"), "echoes state");
    // No code was issued.
    assert!(location_param(&headers, "code").is_none(), "no code on a failed auth");
}

#[tokio::test]
async fn an_achievable_essential_acr_succeeds() {
    // Pinning the essential acr to the level the bootstrap DOES achieve succeeds.
    let harness = Harness::start().await;
    let claims = r#"{"id_token":{"acr":{"essential":true,"values":["urn:ironauth:acr:pwd"]}}}"#;
    let (_subject, access, _) = issue_tokens(&harness, "openid", Some(claims)).await;
    let (status, _, _) = userinfo(&harness, "GET", Some(&access), None, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn cors_is_present_for_a_registered_origin_and_absent_otherwise() {
    const REGISTERED: &str = "https://spa.example";
    const UNREGISTERED: &str = "https://evil.example";
    let config = OidcConfig {
        userinfo_cors_origins: vec![REGISTERED.to_owned()],
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    let (_subject, access, _) = issue_tokens(&harness, "openid email", None).await;

    // Preflight for the registered origin: 204 with the CORS headers.
    let (status, headers, _) =
        userinfo(&harness, "OPTIONS", None, Some(REGISTERED), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some(REGISTERED),
    );
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_METHODS).is_some());
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_HEADERS).is_some());

    // Preflight for an unregistered origin: 204 with NO CORS headers.
    let (status, headers, _) =
        userinfo(&harness, "OPTIONS", None, Some(UNREGISTERED), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

    // Actual GET from the registered origin: the response echoes the origin.
    let (status, headers, _) =
        userinfo(&harness, "GET", Some(&access), Some(REGISTERED), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
        Some(REGISTERED),
    );

    // Actual GET from an unregistered origin: no CORS header (the browser blocks).
    let (status, headers, _) =
        userinfo(&harness, "GET", Some(&access), Some(UNREGISTERED), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
}
