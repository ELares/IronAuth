// SPDX-License-Identifier: MIT OR Apache-2.0

//! The conditional ID-token claims end to end, against a real Postgres (issue
//! #14): the REQUIRED claims, the exact `nonce` echo, honest `acr`/`amr` derived
//! from the recorded authentication event, `auth_time` emitted only when due and
//! always truthful (including `max_age=0` and the `require_auth_time` client),
//! and the absence of `at_hash`/`c_hash`/`azp` from a token-endpoint ID token.
//!
//! The claims are read back through the ONE hardened verify path, so a token that
//! fails to verify fails the test before any claim is inspected.

mod common;

use axum::http::StatusCode;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
};
use ironauth_jose::verify;
use serde_json::Value;

/// The recorded `auth_time` (epoch microseconds) the claim tests pin the session
/// to, chosen distinct from the frozen harness clock so a copied-through or a
/// clock-derived value would be caught.
const RECORDED_AUTH_MICROS: i64 = 1_700_000_123_000_000;
/// The same instant in epoch seconds, which is what the `auth_time` claim carries.
const RECORDED_AUTH_SECS: i64 = 1_700_000_123;

/// Build the authorization query for `client_id`, appending any extra pre-encoded
/// `key=value` fragments (`nonce`, `max_age`, `acr_values`).
fn authorize_query(client_id: &str, extra: &[&str]) -> String {
    // The harness client is public, so PKCE is mandatory (issue #13): bind the RFC
    // 7636 Appendix B S256 challenge and redeem with its verifier.
    let mut query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    );
    for fragment in extra {
        query.push('&');
        query.push_str(fragment);
    }
    query
}

/// The standard token-exchange form for a public client's code (with the PKCE
/// verifier the authorize request bound a challenge for).
fn token_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

/// Drive authorize (with `cookie`) then token, and return the verified ID token
/// claims as a JSON object.
async fn id_token_claims(
    harness: &Harness,
    client_id: &str,
    extra: &[&str],
    cookie: &str,
) -> Value {
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(client_id, extra), cookie)
        .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "authorize should redirect: {body}"
    );
    let code = location_param(&headers, "code").expect("code in redirect");

    let (status, _, body) = harness.token(&token_form(&code, client_id)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let id_token = json(&body)["id_token"]
        .as_str()
        .expect("id_token present")
        .to_owned();

    let policy = harness.policy(client_id);
    let verified = verify(&id_token, &policy, &common::verify_clock()).expect("id token verifies");
    Value::Object(verified.claims().raw().clone())
}

/// A cookie for a fresh consenting subject of `client_id`, with the recorded
/// `pwd` authentication event pinned to [`RECORDED_AUTH_MICROS`].
async fn consenting_cookie(harness: &Harness, client_id: &str) -> String {
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, client_id).await;
    harness
        .session_cookie_at(&subject, "pwd", RECORDED_AUTH_MICROS)
        .await
}

#[tokio::test]
async fn required_claims_and_honest_acr_amr_are_present_hashes_and_azp_absent() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = consenting_cookie(&harness, &client_id).await;

    let claims = id_token_claims(&harness, &client_id, &["nonce=n-abc"], &cookie).await;

    // REQUIRED claims (OIDC Core errata set 2): iss, sub, aud, exp, iat.
    assert_eq!(claims["iss"], Value::String(harness.issuer().to_owned()));
    assert!(
        claims["sub"]
            .as_str()
            .is_some_and(|s| s.starts_with("usr_"))
    );
    assert_eq!(claims["aud"], Value::String(client_id.clone()));
    assert!(claims["iat"].is_number());
    assert!(claims["exp"].is_number());

    // nonce echoed EXACTLY.
    assert_eq!(claims["nonce"], "n-abc");

    // acr/amr DERIVED from the recorded pwd authentication event.
    assert_eq!(claims["amr"], serde_json::json!(["pwd"]));
    assert_eq!(claims["acr"], "urn:ironauth:acr:pwd");

    // A token-endpoint ID token carries neither hash and no azp; and with no
    // max_age and a non-require_auth_time client, no auth_time.
    for absent in ["at_hash", "c_hash", "azp", "auth_time"] {
        assert!(
            claims.get(absent).is_none(),
            "{absent} must be absent from a token-endpoint ID token: {claims}"
        );
    }
}

#[tokio::test]
async fn nonce_is_absent_when_the_request_carried_none() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = consenting_cookie(&harness, &client_id).await;

    let claims = id_token_claims(&harness, &client_id, &[], &cookie).await;
    assert!(
        claims.get("nonce").is_none(),
        "no nonce requested, so none is emitted"
    );
}

#[tokio::test]
async fn auth_time_is_emitted_and_truthful_when_max_age_is_requested() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = consenting_cookie(&harness, &client_id).await;

    // max_age requested: auth_time is present and equals the RECORDED instant
    // (in seconds), not the frozen harness clock and not a request value.
    let claims = id_token_claims(&harness, &client_id, &["max_age=3600"], &cookie).await;
    assert_eq!(claims["auth_time"], RECORDED_AUTH_SECS);
}

#[tokio::test]
async fn auth_time_is_emitted_for_max_age_zero() {
    // max_age=0 still requests auth_time, and it is the truthful recorded instant.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = consenting_cookie(&harness, &client_id).await;

    let claims = id_token_claims(&harness, &client_id, &["max_age=0"], &cookie).await;
    assert_eq!(claims["auth_time"], RECORDED_AUTH_SECS);
}

#[tokio::test]
async fn auth_time_is_emitted_for_a_require_auth_time_client_without_max_age() {
    // A client that registered require_auth_time gets auth_time even with no
    // max_age request.
    let harness = Harness::start().await;
    let client = harness.create_client_requiring_auth_time().await;
    let client_id = client.to_string();
    let cookie = consenting_cookie(&harness, &client_id).await;

    let claims = id_token_claims(&harness, &client_id, &[], &cookie).await;
    assert_eq!(claims["auth_time"], RECORDED_AUTH_SECS);
}

#[tokio::test]
async fn requesting_acr_values_yields_the_achieved_acr_never_the_requested_value() {
    // The client asks for a high, unsatisfiable ACR. The bootstrap can only
    // achieve the password level, so the acr claim is the ACHIEVED value, never
    // the requested one copied through.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = consenting_cookie(&harness, &client_id).await;

    let requested = "urn:example:acr:super-high";
    let claims = id_token_claims(
        &harness,
        &client_id,
        &[&format!("acr_values={}", enc(requested))],
        &cookie,
    )
    .await;
    assert_eq!(claims["acr"], "urn:ironauth:acr:pwd");
    assert_ne!(
        claims["acr"], requested,
        "the requested acr is never copied through"
    );
}
