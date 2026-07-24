// SPDX-License-Identifier: MIT OR Apache-2.0

//! `DPoP` (RFC 9449) proof-of-possession at the resource server (`GET`/`POST
//! /userinfo`, issue #368 resource-server verify), over a real database
//! (`DATABASE_URL`).
//!
//! A `DPoP`-bound access token (its `cnf.jkt` / `dpop_jkt` set) presented at
//! `userinfo` MUST be accompanied by a valid `DPoP` proof over the userinfo `htu`,
//! the request method, and the `ath` of THAT token, whose key thumbprint equals the
//! token's binding, and whose `jti` is fresh. Every failure is the uniform `401`
//! `invalid_token` with a `WWW-Authenticate: DPoP` challenge. An unbound token works
//! as a plain bearer, byte-identical to before, and is refused under the `DPoP`
//! scheme.

mod common;

use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, SEED_PASSWORD, enc, form, json,
    location_param,
};
use ironauth_config::{OidcConfig, TokenFormat as ConfigTokenFormat};
use ironauth_jose::SigningKey;
use ironauth_jose::access_token_hash;
use ironauth_jose::dpop_test_util::{sign_proof, sign_proof_with_ath};

/// The standard-claim document the seeded user carries (so a 200 releases claims too).
const CLAIMS_JSON: &str = r#"{ "name": "Ada Lovelace", "email": "ada@example.test" }"#;

/// A fixed Ed25519 client proof key (the client's ephemeral `DPoP` key).
fn proof_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("dpop-rs".to_owned()), &[9_u8; 32]).expect("ed25519")
}

/// A DIFFERENT Ed25519 key, whose thumbprint does not match the bound token.
fn other_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("dpop-rs-other".to_owned()), &[11_u8; 32]).expect("ed25519")
}

/// The deployment-root token-endpoint `htu` a compliant client signs at issuance.
fn token_htu() -> String {
    format!("{}/token", common::ISSUER_BASE)
}

/// The deployment-root userinfo `htu` a compliant client signs at the resource server
/// (`{issuer_base}/userinfo`, NOT the per-environment issuer).
fn userinfo_htu() -> String {
    format!("{}/userinfo", common::ISSUER_BASE)
}

/// The whole-seconds `iat`, read from the harness clock so the proof is fresh at
/// `state.now()`.
fn now_secs(harness: &Harness) -> u64 {
    harness
        .state()
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
    format!("dpop-rs-{id}@example.test")
}

/// The token-endpoint form for a PKCE public-client code exchange.
fn token_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

/// Drive authorize for a fresh consenting user with the `openid` scope, returning the
/// authorization code.
async fn authenticated_code(harness: &Harness, client_id: &str) -> String {
    let subject = harness
        .seed_user_with_claims(&unique_identifier(harness), SEED_PASSWORD, CLAIMS_JSON)
        .await;
    harness.grant_consent(&subject, client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid profile email"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    location_param(&headers, "code").expect("code in redirect")
}

/// `POST /token` with the given form body and an optional `DPoP` proof header.
async fn token_with_dpop(
    harness: &Harness,
    form_body: &str,
    dpop: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(proof) = dpop {
        builder = builder.header("DPoP", proof);
    }
    let (status, _headers, body) = harness
        .send(
            builder
                .body(Body::from(form_body.to_owned()))
                .expect("request builds"),
        )
        .await;
    (status, body)
}

/// Mint a genuinely `DPoP`-BOUND access token via the PR2 issuance path (a code
/// exchange accompanied by a valid proof), returning the bound access token. Works
/// for both the at+jwt and opaque environment defaults.
async fn bound_access_token(harness: &Harness, key: &SigningKey) -> String {
    let client = harness.client_id().to_string();
    let code = authenticated_code(harness, &client).await;
    let proof = sign_proof(
        key,
        "POST",
        &token_htu(),
        now_secs(harness),
        "jti-issue-bind",
    );
    let (status, body) = token_with_dpop(harness, &token_form(&code, &client), Some(&proof)).await;
    assert_eq!(status, StatusCode::OK, "bound exchange: {body}");
    assert_eq!(json(&body)["token_type"], "DPoP", "bound exchange is DPoP");
    json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned()
}

/// Mint an UNBOUND (plain bearer) access token via a code exchange with NO proof.
async fn unbound_access_token(harness: &Harness) -> String {
    let client = harness.client_id().to_string();
    let code = authenticated_code(harness, &client).await;
    let (status, body) = token_with_dpop(harness, &token_form(&code, &client), None).await;
    assert_eq!(status, StatusCode::OK, "bearer exchange: {body}");
    assert_eq!(json(&body)["token_type"], "Bearer", "no proof stays Bearer");
    json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned()
}

/// A `userinfo` request with a raw `Authorization` value and an optional `DPoP`
/// proof header.
async fn userinfo(
    harness: &Harness,
    method: &str,
    authorization: Option<&str>,
    dpop: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder().method(method).uri("/userinfo");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    if let Some(proof) = dpop {
        builder = builder.header("DPoP", proof);
    }
    harness
        .send(builder.body(Body::empty()).expect("request builds"))
        .await
}

/// The `WWW-Authenticate` header value of a response.
fn challenge(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Assert a response is the uniform `DPoP` rejection: `401` `invalid_token` with a
/// `DPoP`-scheme `WWW-Authenticate` challenge (RFC 9449 7.1).
fn assert_dpop_rejected(status: StatusCode, headers: &HeaderMap, context: &str) {
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{context}: expected 401");
    let www = challenge(headers).unwrap_or_else(|| panic!("{context}: no challenge"));
    assert!(
        www.starts_with("DPoP "),
        "{context}: DPoP scheme challenge: {www}"
    );
    assert!(
        www.contains("error=\"invalid_token\""),
        "{context}: uniform invalid_token: {www}"
    );
}

/// An OIDC config whose environment default access-token format is opaque.
fn opaque_config() -> OidcConfig {
    OidcConfig {
        default_access_token_format: ConfigTokenFormat::Opaque,
        ..OidcConfig::default()
    }
}

// --- The happy path: a bound token with a valid proof, GET and POST ---

#[tokio::test]
async fn a_bound_at_jwt_with_a_valid_dpop_proof_succeeds_on_get_and_post() {
    let harness = Harness::start().await;
    let key = proof_key();
    let access = bound_access_token(&harness, &key).await;
    let ath = access_token_hash(&access);

    for (index, method) in ["GET", "POST"].into_iter().enumerate() {
        let jti = format!("jti-ok-{index}");
        let proof = sign_proof_with_ath(
            &key,
            method,
            &userinfo_htu(),
            now_secs(&harness),
            &jti,
            &ath,
        );
        let (status, _headers, body) = userinfo(
            &harness,
            method,
            Some(&format!("DPoP {access}")),
            Some(&proof),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{method} bound userinfo: {body}");
        let claims = json(&body);
        assert!(claims["sub"].as_str().is_some(), "{method}: sub present");
        assert_eq!(claims["email"], "ada@example.test", "{method}");
    }
}

#[tokio::test]
async fn a_bound_opaque_token_with_a_valid_dpop_proof_succeeds() {
    let harness = Harness::start_with(opaque_config()).await;
    let key = proof_key();
    let access = bound_access_token(&harness, &key).await;
    assert!(access.starts_with("ira_at_"), "opaque default: {access}");
    let ath = access_token_hash(&access);

    let proof = sign_proof_with_ath(
        &key,
        "GET",
        &userinfo_htu(),
        now_secs(&harness),
        "jti-opaque-ok",
        &ath,
    );
    let (status, _headers, body) = userinfo(
        &harness,
        "GET",
        Some(&format!("DPoP {access}")),
        Some(&proof),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bound opaque userinfo: {body}");
    assert_eq!(json(&body)["email"], "ada@example.test");
}

// --- The rejections ---

#[tokio::test]
async fn a_bound_token_presented_as_bearer_is_rejected() {
    // RFC 9449 7.1: a bound token must NEVER be accepted as a bearer (no downgrade).
    let harness = Harness::start().await;
    let key = proof_key();
    let access = bound_access_token(&harness, &key).await;

    let (status, headers, _body) =
        userinfo(&harness, "GET", Some(&format!("Bearer {access}")), None).await;
    assert_dpop_rejected(status, &headers, "bound as bearer");
}

#[tokio::test]
async fn a_bound_token_with_no_proof_header_is_rejected() {
    let harness = Harness::start().await;
    let key = proof_key();
    let access = bound_access_token(&harness, &key).await;

    let (status, headers, _body) =
        userinfo(&harness, "GET", Some(&format!("DPoP {access}")), None).await;
    assert_dpop_rejected(status, &headers, "bound, DPoP scheme, no proof");
}

#[tokio::test]
async fn a_proof_with_the_wrong_key_is_rejected() {
    // The proof validates on its own but its thumbprint does not match the token's cnf.
    let harness = Harness::start().await;
    let key = proof_key();
    let access = bound_access_token(&harness, &key).await;
    let ath = access_token_hash(&access);

    let wrong = other_key();
    let proof = sign_proof_with_ath(
        &wrong,
        "GET",
        &userinfo_htu(),
        now_secs(&harness),
        "jti-wrong-key",
        &ath,
    );
    let (status, headers, _body) = userinfo(
        &harness,
        "GET",
        Some(&format!("DPoP {access}")),
        Some(&proof),
    )
    .await;
    assert_dpop_rejected(status, &headers, "wrong proof key");
}

#[tokio::test]
async fn a_proof_with_the_wrong_ath_is_rejected() {
    // The ath is the hash of a DIFFERENT token, so it does not bind this presentation.
    let harness = Harness::start().await;
    let key = proof_key();
    let access = bound_access_token(&harness, &key).await;
    let wrong_ath = access_token_hash("some-other-access-token");

    let proof = sign_proof_with_ath(
        &key,
        "GET",
        &userinfo_htu(),
        now_secs(&harness),
        "jti-wrong-ath",
        &wrong_ath,
    );
    let (status, headers, _body) = userinfo(
        &harness,
        "GET",
        Some(&format!("DPoP {access}")),
        Some(&proof),
    )
    .await;
    assert_dpop_rejected(status, &headers, "wrong ath");
}

#[tokio::test]
async fn a_proof_with_a_missing_ath_is_rejected() {
    // A proof with NO ath cannot satisfy the resource-server ath binding.
    let harness = Harness::start().await;
    let key = proof_key();
    let access = bound_access_token(&harness, &key).await;

    // sign_proof omits the ath claim entirely.
    let proof = sign_proof(
        &key,
        "GET",
        &userinfo_htu(),
        now_secs(&harness),
        "jti-no-ath",
    );
    let (status, headers, _body) = userinfo(
        &harness,
        "GET",
        Some(&format!("DPoP {access}")),
        Some(&proof),
    )
    .await;
    assert_dpop_rejected(status, &headers, "missing ath");
}

#[tokio::test]
async fn a_proof_with_the_wrong_htu_is_rejected() {
    // A proof bound to the token endpoint htu (or any other) does not cover userinfo.
    let harness = Harness::start().await;
    let key = proof_key();
    let access = bound_access_token(&harness, &key).await;
    let ath = access_token_hash(&access);

    let proof = sign_proof_with_ath(
        &key,
        "GET",
        &token_htu(),
        now_secs(&harness),
        "jti-wrong-htu",
        &ath,
    );
    let (status, headers, _body) = userinfo(
        &harness,
        "GET",
        Some(&format!("DPoP {access}")),
        Some(&proof),
    )
    .await;
    assert_dpop_rejected(status, &headers, "wrong htu");
}

#[tokio::test]
async fn a_proof_with_the_wrong_htm_is_rejected() {
    // A proof signed for POST presented on a GET request does not match the method.
    let harness = Harness::start().await;
    let key = proof_key();
    let access = bound_access_token(&harness, &key).await;
    let ath = access_token_hash(&access);

    let proof = sign_proof_with_ath(
        &key,
        "POST",
        &userinfo_htu(),
        now_secs(&harness),
        "jti-wrong-htm",
        &ath,
    );
    let (status, headers, _body) = userinfo(
        &harness,
        "GET",
        Some(&format!("DPoP {access}")),
        Some(&proof),
    )
    .await;
    assert_dpop_rejected(status, &headers, "wrong htm");
}

#[tokio::test]
async fn a_proof_with_a_stale_iat_is_rejected() {
    // A proof whose iat has aged beyond the freshness leeway (but while the access
    // token itself is still valid) is stale. Signed fresh, then presented after the
    // clock advances past the leeway window but well within the token's 300s life, so
    // the ONLY reason the presentation fails is the stale proof, not an expired token.
    let harness = Harness::start().await;
    let key = proof_key();
    let access = bound_access_token(&harness, &key).await;
    let ath = access_token_hash(&access);

    let iat = now_secs(&harness);
    let proof = sign_proof_with_ath(&key, "GET", &userinfo_htu(), iat, "jti-stale", &ath);
    // Advance past the 60s leeway (the token still lives 300s), so the proof is stale.
    harness.clock().advance(Duration::from_secs(120));
    let (status, headers, _body) = userinfo(
        &harness,
        "GET",
        Some(&format!("DPoP {access}")),
        Some(&proof),
    )
    .await;
    assert_dpop_rejected(status, &headers, "stale iat");
}

#[tokio::test]
async fn a_replayed_proof_jti_is_rejected_on_the_second_use() {
    // The DB-backed replay store: the FIRST presentation of a proof succeeds and the
    // SECOND, identical presentation (same key and jti inside the window) is refused.
    let harness = Harness::start().await;
    let key = proof_key();
    let access = bound_access_token(&harness, &key).await;
    let ath = access_token_hash(&access);
    let proof = sign_proof_with_ath(
        &key,
        "GET",
        &userinfo_htu(),
        now_secs(&harness),
        "jti-replay",
        &ath,
    );

    let (first, _headers, body) = userinfo(
        &harness,
        "GET",
        Some(&format!("DPoP {access}")),
        Some(&proof),
    )
    .await;
    assert_eq!(first, StatusCode::OK, "first presentation: {body}");

    let (second, headers, _body) = userinfo(
        &harness,
        "GET",
        Some(&format!("DPoP {access}")),
        Some(&proof),
    )
    .await;
    assert_dpop_rejected(second, &headers, "replayed jti");
}

// --- Unbound tokens are unchanged, and refused under the DPoP scheme ---

#[tokio::test]
async fn an_unbound_token_as_bearer_succeeds_unchanged() {
    let harness = Harness::start().await;
    let access = unbound_access_token(&harness).await;

    for method in ["GET", "POST"] {
        let (status, _headers, body) =
            userinfo(&harness, method, Some(&format!("Bearer {access}")), None).await;
        assert_eq!(status, StatusCode::OK, "{method} unbound bearer: {body}");
        assert_eq!(json(&body)["email"], "ada@example.test", "{method}");
    }
}

#[tokio::test]
async fn an_unbound_token_presented_under_the_dpop_scheme_is_rejected() {
    // The DPoP scheme requires a bound token; a DPoP-scheme presentation of an unbound
    // token is refused even with an otherwise well-formed proof.
    let harness = Harness::start().await;
    let key = proof_key();
    let access = unbound_access_token(&harness).await;
    let ath = access_token_hash(&access);
    let proof = sign_proof_with_ath(
        &key,
        "GET",
        &userinfo_htu(),
        now_secs(&harness),
        "jti-unbound-dpop",
        &ath,
    );

    let (status, headers, _body) = userinfo(
        &harness,
        "GET",
        Some(&format!("DPoP {access}")),
        Some(&proof),
    )
    .await;
    assert_dpop_rejected(status, &headers, "unbound under DPoP scheme");

    // And with no proof at all: still refused (the scheme itself is the mismatch).
    let (status, headers, _body) =
        userinfo(&harness, "GET", Some(&format!("DPoP {access}")), None).await;
    assert_dpop_rejected(status, &headers, "unbound under DPoP scheme, no proof");
}
