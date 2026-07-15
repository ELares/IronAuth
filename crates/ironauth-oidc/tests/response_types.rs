// SPDX-License-Identifier: MIT OR Apache-2.0

//! The legacy response types, `form_post`, and `none`, disabled by default, end to
//! end against a real Postgres (issue #17).
//!
//! Covers the acceptance criteria that need the LIVE authorization endpoint over
//! the store and a provisioned signing key (the registry structural lock, the
//! response-mode negotiation, and the `form_post` escaping/CSP/no-store are
//! unit-tested database-free in the `registry`, `response`, and `pages` modules):
//!
//! - `id_token` and `code id_token` produce spec-exact fragment responses (nonce
//!   required, `c_hash` correct for the hybrid, and NO `at_hash`, since the
//!   authorization endpoint never issues an access token).
//! - `response_type=none` redirects with `state` and `iss` and issues nothing.
//! - Every legacy type is DISABLED by default: requesting one is
//!   `unsupported_response_type`, delivered by the negotiated mode.
//! - `form_post` returns an auto-submitting form whose code never appears in a URL
//!   or a `Location` header.
//! - The default response modes match the spec and illegal `response_mode`
//!   combinations are rejected.
//!
//! The ID tokens are read back through the ONE hardened verify path, so a token
//! that fails to verify fails the test before any claim is inspected.

mod common;

use axum::http::{StatusCode, header};
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location,
    location_fragment_param, location_param,
};
use ironauth_config::OidcConfig;
use ironauth_jose::{JwsAlgorithm, verify};
use serde_json::Value;

/// A config that enables every legacy response type and the `form_post` mode (the
/// certification-run posture, issue #17). The harness client is public, so PKCE
/// stays mandatory for the flows that issue a code; the confidential relaxation is
/// irrelevant here but kept for parity with the default harness.
fn legacy_enabled() -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        enable_response_type_id_token: true,
        enable_response_type_code_id_token: true,
        enable_response_type_none: true,
        enable_response_mode_form_post: true,
        ..OidcConfig::default()
    }
}

/// Verify a front-channel ID token through the one hardened verify path and return
/// its claims as a JSON object.
fn verified_claims(harness: &Harness, audience: &str, id_token: &str) -> Value {
    let policy = harness.policy(audience);
    let verified = verify(id_token, &policy, &common::verify_clock()).expect("id token verifies");
    Value::Object(verified.claims().raw().clone())
}

#[tokio::test]
async fn id_token_flow_returns_a_fragment_id_token_with_nonce_and_no_hashes() {
    // Acceptance 1: the implicit id_token flow. The default mode is fragment, the
    // ID token carries the nonce, and it carries NEITHER c_hash (no code) NOR
    // at_hash (no access token is ever issued from /authorize).
    let harness = Harness::start_with(legacy_enabled()).await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;

    // A public client needs no PKCE for a flow that issues no code.
    let query = format!(
        "response_type=id_token&client_id={client_id}&redirect_uri={}&nonce=n-front&state=s-front",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "fragment redirect: {body}");

    let location = location(&headers).expect("Location present");
    assert!(
        location.starts_with(&format!("{REDIRECT_URI}#")),
        "the response is a fragment, not a query: {location}"
    );
    // Nothing leaks into the query component.
    assert!(
        location_param(&headers, "id_token").is_none(),
        "the id_token is in the fragment, never the query"
    );

    let id_token = location_fragment_param(&headers, "id_token").expect("id_token in fragment");
    assert_eq!(
        location_fragment_param(&headers, "state").as_deref(),
        Some("s-front")
    );
    assert_eq!(
        location_fragment_param(&headers, "iss").as_deref(),
        Some(harness.issuer()),
        "RFC 9207 iss rides the fragment too"
    );
    // No code is issued in the pure implicit flow.
    assert!(location_fragment_param(&headers, "code").is_none());

    let claims = verified_claims(&harness, &client_id, &id_token);
    assert_eq!(claims["iss"], Value::String(harness.issuer().to_owned()));
    assert_eq!(claims["aud"], Value::String(client_id.clone()));
    assert_eq!(claims["nonce"], "n-front");
    for absent in ["c_hash", "at_hash"] {
        assert!(
            claims.get(absent).is_none(),
            "{absent} must be absent from an implicit id_token: {claims}"
        );
    }
}

#[tokio::test]
async fn pure_id_token_emits_scope_and_claims_parameter_claims_into_the_id_token() {
    // OIDC Core 5.4: the pure implicit `id_token` flow issues NO access token, so
    // UserInfo is unreachable and the scope-derived claims (and the claims-parameter
    // `id_token` member) MUST be carried IN the ID token itself. A lean ID token
    // here would strand a client that requested `email`/`profile`.
    let harness = Harness::start_with(legacy_enabled()).await;
    let client_id = harness.client_id().to_string();

    // Seed a user WITH standard claims, consent it to the client, and authenticate
    // as that user (compose the claims-bearing subject the generic cookie helper
    // does not seed).
    let claims_json = r#"{"email":"ada@example.test","email_verified":true,"name":"Ada Lovelace","address":{"country":"UK"}}"#;
    let subject = harness
        .seed_user_with_claims("ada@example.test", common::SEED_PASSWORD, claims_json)
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;

    // Grant `email` and `profile` but NOT `address`.
    let query = format!(
        "response_type=id_token&client_id={client_id}&redirect_uri={}&nonce=n-claims&state=s&\
         scope={}",
        enc(REDIRECT_URI),
        enc("openid email profile"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "fragment redirect: {body}");

    let id_token = location_fragment_param(&headers, "id_token").expect("id_token in fragment");
    let claims = verified_claims(&harness, &client_id, &id_token);
    // The granted scopes' claims are IN the ID token (no UserInfo to fall back to).
    assert_eq!(
        claims["email"],
        Value::String("ada@example.test".to_owned()),
        "email (granted) must be in the pure id_token: {claims}"
    );
    assert_eq!(claims["email_verified"], Value::Bool(true));
    assert_eq!(
        claims["name"],
        Value::String("Ada Lovelace".to_owned()),
        "a profile claim (granted) must be in the pure id_token: {claims}"
    );
    // A claim whose scope was NOT granted stays out (allowlist release).
    assert!(
        claims.get("address").is_none(),
        "address (scope not granted) must not appear: {claims}"
    );
}

#[tokio::test]
async fn hybrid_code_id_token_carries_a_correct_c_hash_and_a_redeemable_code() {
    // Acceptance 1: the hybrid flow returns a code AND a front-channel ID token
    // carrying c_hash(code) but NO at_hash, in the fragment. The code is a real,
    // redeemable authorization code.
    let harness = Harness::start_with(legacy_enabled()).await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;

    // The public client requires PKCE for the code-issuing hybrid flow.
    let query = format!(
        "response_type={}&client_id={client_id}&redirect_uri={}&nonce=n-hyb&state=s-hyb&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc("code id_token"),
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "hybrid fragment redirect: {body}"
    );

    let code = location_fragment_param(&headers, "code").expect("code in fragment");
    let id_token = location_fragment_param(&headers, "id_token").expect("id_token in fragment");
    assert_eq!(
        location_fragment_param(&headers, "iss").as_deref(),
        Some(harness.issuer())
    );

    let claims = verified_claims(&harness, &client_id, &id_token);
    assert_eq!(claims["nonce"], "n-hyb");
    // c_hash is the left-half hash of the issued code under the ID token's alg
    // (EdDSA -> SHA-512), computed independently here.
    let expected_c_hash = ironauth_oidc::c_hash(JwsAlgorithm::EdDsa, &code);
    assert_eq!(
        claims["c_hash"], expected_c_hash,
        "c_hash binds the issued code"
    );
    assert!(
        claims.get("at_hash").is_none(),
        "a hybrid id_token never carries at_hash (no access token is issued)"
    );

    // The issued code is a genuine authorization code: it redeems at the token
    // endpoint (with the PKCE verifier) for a token-endpoint ID token + access
    // token.
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _h, body) = harness.token(&exchange).await;
    assert_eq!(status, StatusCode::OK, "hybrid code redeems: {body}");
    assert!(json(&body)["access_token"].is_string());
    // The token-endpoint ID token carries the same nonce and, per issue #14, no
    // c_hash (the token endpoint never emits one).
    let token_id_token = json(&body)["id_token"]
        .as_str()
        .expect("id_token")
        .to_owned();
    let token_claims = verified_claims(&harness, &client_id, &token_id_token);
    assert_eq!(token_claims["nonce"], "n-hyb");
    assert!(token_claims.get("c_hash").is_none());
}

#[tokio::test]
async fn response_type_none_redirects_with_state_and_iss_and_issues_nothing() {
    // Acceptance 2: none redirects (query, its default) echoing state and iss, and
    // issues no code and no token.
    let harness = Harness::start_with(legacy_enabled()).await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;

    let query = format!(
        "response_type=none&client_id={client_id}&redirect_uri={}&state=s-none",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "none redirect: {body}");
    // Default mode for none is query.
    let location = location(&headers).expect("Location");
    assert!(
        location.starts_with(&format!("{REDIRECT_URI}?")),
        "none uses the query mode by default: {location}"
    );
    assert_eq!(location_param(&headers, "state").as_deref(), Some("s-none"));
    assert_eq!(
        location_param(&headers, "iss").as_deref(),
        Some(harness.issuer())
    );
    // Nothing is issued.
    assert!(location_param(&headers, "code").is_none(), "no code");
    assert!(
        location_param(&headers, "id_token").is_none(),
        "no id_token"
    );
    assert!(!location.contains('#'), "no fragment payload either");
}

#[tokio::test]
async fn form_post_returns_an_auto_submitting_form_and_never_puts_the_code_in_a_url() {
    // Acceptance 5: form_post returns a 200 auto-submitting form with the right
    // headers and a strict CSP; the code lives only in a hidden field, never in a
    // URL, a Location header, or a query string.
    let harness = Harness::start_with(legacy_enabled()).await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;

    // A hostile state proves the hidden-field values are escaped.
    let hostile_state = "\"><script>alert(1)</script>";
    let query = format!(
        "response_type=code&response_mode=form_post&client_id={client_id}&redirect_uri={}&\
         state={}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc(hostile_state),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::OK, "form_post is a 200 page: {body}");
    assert!(
        headers.get(header::LOCATION).is_none(),
        "form_post never sets a Location header"
    );
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=UTF-8")
    );
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert!(
        headers.get(header::CONTENT_SECURITY_POLICY).is_some(),
        "a strict CSP is attached"
    );

    // The form posts to the exact redirect_uri, and carries the code as a hidden
    // field.
    assert!(
        body.contains(&format!("action=\"{REDIRECT_URI}\"")),
        "the form action is the redirect_uri: {body}"
    );
    let code = common::form_field(&body, "code").expect("code hidden field");
    assert!(!code.is_empty(), "a code is issued");
    // The code never appears in any URL-shaped context.
    assert!(
        !body.contains(&format!("{REDIRECT_URI}?code=")),
        "the code is never placed in a URL: {body}"
    );
    // The hostile state is escaped, not executed.
    assert!(
        !body.contains("<script>alert(1)"),
        "the reflected state is escaped: {body}"
    );
    // iss rides the form too.
    assert_eq!(
        common::form_field(&body, "iss").as_deref(),
        Some(harness.issuer())
    );
}

#[tokio::test]
async fn a_legacy_type_disabled_by_default_is_unsupported_response_type() {
    // Acceptance 3: with the DEFAULT config (no legacy enabled), requesting a legacy
    // type is unsupported_response_type. id_token's default mode is fragment, so the
    // error is delivered in the fragment.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=id_token&client_id={client_id}&redirect_uri={}&nonce=n&state=s",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "error redirect: {body}");
    assert_eq!(
        location_fragment_param(&headers, "error").as_deref(),
        Some("unsupported_response_type"),
        "a disabled legacy type is unsupported"
    );
    assert_eq!(
        location_fragment_param(&headers, "iss").as_deref(),
        Some(harness.issuer())
    );
    assert!(
        location_fragment_param(&headers, "id_token").is_none(),
        "nothing is issued for a disabled type"
    );
}

#[tokio::test]
async fn a_token_bearing_response_type_is_always_unsupported() {
    // The implicit access-token flow is structurally unrepresentable: even in the
    // certification posture (every legacy type enabled) response_type=token, and any
    // token-bearing combination, is unsupported_response_type. Delivered by the safe
    // query mode (no front-channel default is known for an unrepresentable type).
    let harness = Harness::start_with(legacy_enabled()).await;
    let client_id = harness.client_id().to_string();
    for response_type in ["token", "id_token token", "code token"] {
        let query = format!(
            "response_type={}&client_id={client_id}&redirect_uri={}&nonce=n&state=s",
            enc(response_type),
            enc(REDIRECT_URI),
        );
        let (status, headers, body) = harness.authorize(&query).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{response_type}: {body}");
        assert_eq!(
            location_param(&headers, "error").as_deref(),
            Some("unsupported_response_type"),
            "{response_type} must be unsupported"
        );
        // Never issues anything, in query OR fragment.
        for param in ["code", "id_token", "token", "access_token"] {
            assert!(location_param(&headers, param).is_none(), "{param}");
            assert!(
                location_fragment_param(&headers, param).is_none(),
                "{param}"
            );
        }
    }
}

#[tokio::test]
async fn a_front_channel_type_requires_nonce() {
    // Acceptance 1/6: nonce is REQUIRED for id_token and code id_token; its absence
    // is invalid_request, delivered by the negotiated (fragment) mode.
    let harness = Harness::start_with(legacy_enabled()).await;
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=id_token&client_id={client_id}&redirect_uri={}&state=s",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness
        .authorize_with_cookie(&query, &harness.authenticated_cookie().await)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "error redirect: {body}");
    assert_eq!(
        location_fragment_param(&headers, "error").as_deref(),
        Some("invalid_request"),
        "a missing nonce for a front-channel type is invalid_request"
    );
    assert!(location_fragment_param(&headers, "id_token").is_none());
}

#[tokio::test]
async fn query_response_mode_is_rejected_for_a_front_channel_type() {
    // Acceptance 6: a front-channel type MUST NOT accept the query response mode
    // (it would place an id_token in the query string). The error is invalid_request,
    // delivered by the type's default (fragment) mode.
    let harness = Harness::start_with(legacy_enabled()).await;
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=id_token&response_mode=query&client_id={client_id}&redirect_uri={}&\
         nonce=n&state=s",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "error redirect: {body}");
    assert_eq!(
        location_fragment_param(&headers, "error").as_deref(),
        Some("invalid_request"),
        "query is illegal for a front-channel type"
    );
    // The illegal request never places anything in the query string.
    assert!(location_param(&headers, "id_token").is_none());
    assert!(location_param(&headers, "error").is_none());
}

#[tokio::test]
async fn form_post_is_rejected_when_not_enabled() {
    // Acceptance 6: form_post is a per-environment capability. With it disabled
    // (the default harness), requesting it is invalid_request, delivered by the
    // (query) default mode for the code type.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=code&response_mode=form_post&client_id={client_id}&redirect_uri={}&\
         state=s&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "error redirect: {body}");
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_request"),
        "form_post is not enabled by default"
    );
}

#[tokio::test]
async fn form_post_delivers_a_front_channel_id_token_in_the_form_body_only() {
    // form_post is legal for any type: a front-channel id_token can be delivered by
    // form_post, and it still never appears in a URL.
    let harness = Harness::start_with(legacy_enabled()).await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;
    let query = format!(
        "response_type=id_token&response_mode=form_post&client_id={client_id}&redirect_uri={}&\
         nonce=n-fp&state=s-fp",
        enc(REDIRECT_URI),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::OK, "form_post page: {body}");
    assert!(headers.get(header::LOCATION).is_none());
    let id_token = common::form_field(&body, "id_token").expect("id_token hidden field");
    let claims = verified_claims(&harness, &client_id, &id_token);
    assert_eq!(claims["nonce"], "n-fp");
    assert_eq!(common::form_field(&body, "state").as_deref(), Some("s-fp"));
}
