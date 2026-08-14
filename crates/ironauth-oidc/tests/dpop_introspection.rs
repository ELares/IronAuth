// SPDX-License-Identifier: MIT OR Apache-2.0

//! `DPoP` binding as seen through RFC 7662 token introspection (RFC 9449 section 6.2,
//! issue #124 acceptance criterion 6), over a real database (`DATABASE_URL`).
//!
//! Introspection is where a RESOURCE SERVER learns what a token is. It is the only
//! place an opaque token's binding is observable at all (an opaque token carries no
//! claims), and it is the place a resource server that does not verify JWTs itself
//! learns whether a proof is required. RFC 9449 section 6.2 therefore requires the
//! `cnf` binding as a top-level response member and requires that a `token_type`
//! member, if present, carry `DPoP`.
//!
//! Before issue #124 this endpoint reported `token_type: "Bearer"` for every access
//! token and never emitted `cnf`, so a sender-constrained token read to a resource
//! server as a plain bearer token it could accept from any holder. These tests pin
//! the whole path end to end: proof at the token endpoint, binding recorded, binding
//! reported.

mod common;

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Harness, REDIRECT_URI, enc, form, json, location_param};
use ironauth_config::{OidcConfig, TokenFormat as ConfigTokenFormat};
use ironauth_jose::SigningKey;
use ironauth_jose::dpop_test_util::{jkt_of, sign_proof};
use ironauth_oidc::ClientAuthMethod;
use serde_json::Value;

/// A fixed Ed25519 client proof key (the client's ephemeral `DPoP` key).
fn proof_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("dpop-introspect".to_owned()), &[7_u8; 32]).expect("ed25519")
}

/// The `Authorization: Basic` header value for `client_secret_basic`.
fn basic(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// The token-endpoint `htu` a compliant client signs: the DEPLOYMENT-ROOT
/// `token_endpoint` discovery advertises, which is what a real client posts to.
fn expected_htu() -> String {
    format!("{}/token", common::ISSUER_BASE)
}

/// The whole-seconds `iat` a fresh proof carries, read from the harness clock.
fn now_secs(harness: &Harness) -> u64 {
    harness
        .state()
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Drive authorize plus a code exchange for a CONFIDENTIAL client, optionally
/// carrying a `DPoP` proof, and return the token response.
///
/// One client plays both roles here on purpose: it holds the proof key AND it
/// authenticates to `/introspect`. Introspection resolves within the authenticated
/// client's `(tenant, environment)` scope rather than per client, so this is the
/// smallest fixture that exercises the real path, and it keeps the reported
/// thumbprint attributable to a key the test itself generated.
async fn issue(harness: &Harness, client_id: &str, secret: &str, jti: Option<&str>) -> Value {
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}",
        enc(REDIRECT_URI),
        enc("openid profile"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");

    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
    ]);
    let mut builder = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, basic(client_id, secret));
    if let Some(jti) = jti {
        let proof = sign_proof(
            &proof_key(),
            "POST",
            &expected_htu(),
            now_secs(harness),
            jti,
        );
        builder = builder.header("DPoP", proof);
    }
    let (status, _, body) = harness
        .send(builder.body(Body::from(exchange)).expect("request builds"))
        .await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    json(&body)
}

/// `POST /introspect` as the authenticated confidential client.
async fn introspect(harness: &Harness, token: &str, client_id: &str, secret: &str) -> Value {
    let request = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, basic(client_id, secret))
        .body(Body::from(form(&[("token", token)])))
        .expect("request builds");
    let (status, _, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::OK, "introspect: {body}");
    json(&body)
}

/// A bound `at+jwt` introspects with its `cnf.jkt` and a `DPoP` `token_type`.
#[tokio::test]
async fn a_bound_jwt_access_token_introspects_with_its_binding() {
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client = client_id.to_string();
    let tokens = issue(&harness, &client, &secret, Some("jti-introspect-jwt")).await;
    assert_eq!(tokens["token_type"], "DPoP", "the exchange was bound");
    let access = tokens["access_token"].as_str().expect("access_token");

    let body = introspect(&harness, access, &client, &secret).await;
    assert_eq!(body["active"], true, "the token is active: {body}");
    assert_eq!(
        body["cnf"]["jkt"].as_str(),
        Some(jkt_of(&proof_key()).as_str()),
        "introspection reports the proof key thumbprint"
    );
    // RFC 9449 section 6.2: if token_type is present it MUST be DPoP. Reporting
    // Bearer would tell the resource server to accept this token from any holder.
    assert_eq!(body["token_type"], "DPoP");
}

/// A bound OPAQUE access token introspects with its `cnf.jkt`.
///
/// This is the case that matters most: an opaque token carries no claims, so a
/// resource server holding one has NO other way to discover that a proof is
/// required. If introspection omits the binding, the binding may as well not exist.
#[tokio::test]
async fn a_bound_opaque_access_token_introspects_with_its_binding() {
    let harness = Harness::start_with(OidcConfig {
        default_access_token_format: ConfigTokenFormat::Opaque,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client = client_id.to_string();
    let tokens = issue(&harness, &client, &secret, Some("jti-introspect-opaque")).await;
    assert_eq!(tokens["token_type"], "DPoP", "the exchange was bound");
    let access = tokens["access_token"].as_str().expect("access_token");
    assert!(
        access.starts_with("ira_at_"),
        "this case needs an opaque token, got {access}"
    );

    let body = introspect(&harness, access, &client, &secret).await;
    assert_eq!(body["active"], true, "the token is active: {body}");
    assert_eq!(
        body["cnf"]["jkt"].as_str(),
        Some(jkt_of(&proof_key()).as_str()),
        "the row's recorded jkt reaches the resource server"
    );
    assert_eq!(body["token_type"], "DPoP");
}

/// A bound refresh token reports its `cnf` and still no `token_type`.
#[tokio::test]
async fn a_bound_refresh_token_introspects_with_its_binding() {
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client = client_id.to_string();
    let tokens = issue(&harness, &client, &secret, Some("jti-introspect-refresh")).await;
    let refresh = tokens["refresh_token"].as_str().expect("refresh_token");

    let body = introspect(&harness, refresh, &client, &secret).await;
    assert_eq!(body["active"], true, "the token is active: {body}");
    assert_eq!(
        body["cnf"]["jkt"].as_str(),
        Some(jkt_of(&proof_key()).as_str()),
        "the bound family's jkt is reported"
    );
    assert!(
        body.get("token_type").is_none(),
        "a refresh token carries no RFC 6749 5.1 token type: {body}"
    );
}

/// An UNBOUND exchange is unchanged: `Bearer`, and no `cnf` at all.
///
/// The companion to the bound cases. Without it, always emitting a `cnf` and always
/// saying `DPoP` would pass every other test in this file while breaking every
/// ordinary bearer client.
#[tokio::test]
async fn an_unbound_token_still_introspects_as_a_plain_bearer() {
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client = client_id.to_string();
    let tokens = issue(&harness, &client, &secret, None).await;
    assert_eq!(tokens["token_type"], "Bearer", "the exchange was unbound");
    let access = tokens["access_token"].as_str().expect("access_token");

    let body = introspect(&harness, access, &client, &secret).await;
    assert_eq!(body["active"], true, "the token is active: {body}");
    assert_eq!(body["token_type"], "Bearer");
    assert!(
        body.get("cnf").is_none(),
        "an unbound token must carry no cnf: {body}"
    );
}

/// A signature-valid token whose `cnf` is MALFORMED reads not-active, never unbound.
///
/// The alternative, treating an unparseable `cnf` as absent, would report a token
/// this server itself marked key-bound as a plain `Bearer` with no `cnf`: the exact
/// downgrade the binding prevents, reached by a server bug rather than an attacker.
/// Failing closed is the correct answer to "I cannot state this token's binding".
///
/// Synthesized the way the multi-audience guard in `revocation_introspection` is: a
/// real minted token's claims (whose `jti` keys a live store row) re-signed with the
/// SAME key and `jti` but a `cnf` whose `jkt` is a number rather than a string, so the
/// signature verifies and the store row resolves and only the parse fails.
#[tokio::test]
async fn a_malformed_cnf_reads_not_active_rather_than_unbound() {
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client = client_id.to_string();
    let tokens = issue(&harness, &client, &secret, Some("jti-malformed-cnf")).await;
    let access = tokens["access_token"].as_str().expect("access_token");

    // The unmodified token introspects active, so the fixture is not vacuous and the
    // refusal below is attributable to the cnf and nothing else.
    let before = introspect(&harness, access, &client, &secret).await;
    assert_eq!(
        before["active"], true,
        "the fixture token is active: {before}"
    );

    let segment = access.split('.').nth(1).expect("payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .expect("base64url payload");
    let mut claims: serde_json::Map<String, Value> =
        serde_json::from_slice(&bytes).expect("claims json");
    claims.insert("cnf".to_owned(), serde_json::json!({ "jkt": 5 }));
    let forged = harness.sign_at_jwt(&Value::Object(claims)).await;

    let body = introspect(&harness, &forged, &client, &secret).await;
    assert_eq!(
        body,
        serde_json::json!({ "active": false }),
        "an unparseable cnf reads not-active, and leaks nothing else: {body}"
    );
}

/// The binding introspection reports is the one the TOKEN ENDPOINT stated, for the
/// same token, in the same exchange.
///
/// Both surfaces answer "is this sender-constrained", a resource server may see
/// either, and they read two different code paths (a minted-in-hand boolean at the
/// token endpoint, a resolved-from-storage confirmation at introspection). This is
/// the assertion that fails if they ever drift apart.
#[tokio::test]
async fn the_two_surfaces_agree_on_the_token_type() {
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client = client_id.to_string();

    for (jti, expected) in [(Some("jti-agree-bound"), "DPoP"), (None, "Bearer")] {
        let tokens = issue(&harness, &client, &secret, jti).await;
        let access = tokens["access_token"].as_str().expect("access_token");
        let body = introspect(&harness, access, &client, &secret).await;
        assert_eq!(
            tokens["token_type"], expected,
            "token endpoint disagrees for jti={jti:?}"
        );
        assert_eq!(
            body["token_type"], tokens["token_type"],
            "introspection must report the same type the token endpoint did"
        );
    }
}
