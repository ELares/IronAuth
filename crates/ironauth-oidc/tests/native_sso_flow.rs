// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native SSO end to end, through the real endpoints (issue #133, PROTOTYPE).
//!
//! `tests/native_sso.rs` drives the binding rules directly and answers what they accept. This
//! file answers the questions that one cannot: whether the endpoints REACH them, whether the
//! unarmed posture is genuinely unchanged, and whether revoking a session severs the set.
//!
//! Needs a database.

mod common;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Harness, form, json};
use ironauth_oidc::native_sso::{DEVICE_SECRET_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE};

const EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const DEVICE_SSO: &str = "device_sso";

/// The claims of a compact JWS, without verifying it. Test-side inspection only.
fn payload(token: &str) -> serde_json::Value {
    let raw = token.split('.').nth(1).expect("a payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(raw).expect("base64url")).expect("json")
}

/// Redeem a code and return the whole token response.
async fn redeem(h: &Harness, client_id: &str, code: &str) -> (StatusCode, String) {
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client_id),
        ("redirect_uri", common::REDIRECT_URI),
    ]);
    let (status, _headers, response) = h.token(&body).await;
    (status, response)
}

/// Present a (ID token, device secret) pair at the exchange as `client_id`.
async fn present_pair(
    h: &Harness,
    client_id: &str,
    id_token: &str,
    device_secret: &str,
) -> (StatusCode, String) {
    let body = form(&[
        ("grant_type", EXCHANGE_GRANT),
        ("subject_token", id_token),
        ("subject_token_type", ID_TOKEN_TOKEN_TYPE),
        ("actor_token", device_secret),
        ("actor_token_type", DEVICE_SECRET_TOKEN_TYPE),
        ("client_id", client_id),
    ]);
    let (status, _headers, response) = h.token(&body).await;
    (status, response)
}

#[tokio::test]
async fn an_unarmed_deployment_issues_no_device_secret_and_no_binding() {
    // THE POSTURE THAT MATTERS MOST. Every ID token this deployment has ever issued must stay
    // unbound, because `ds_hash` is the only thing that makes the exchange's relaxed subject
    // type safe. If the claim appeared without the flag, every existing token would be one
    // half of a redeemable pair.
    let h = Harness::start().await;
    let client_id = h.client_id().to_string();
    let code = h
        .issue_authenticated_code_with_scope(&client_id, DEVICE_SSO)
        .await;
    let (status, response) = redeem(&h, &client_id, &code).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let body = json(&response);
    assert!(
        body.get("device_secret").is_none(),
        "an unarmed deployment must return no device secret even when device_sso was granted: \
         {response}"
    );
    let claims = payload(body["id_token"].as_str().expect("an id token"));
    assert!(
        claims.get("ds_hash").is_none(),
        "and its ID token must carry no binding: {claims}"
    );
}

#[tokio::test]
async fn an_unarmed_exchange_refuses_an_id_token_subject() {
    // The other half of the unarmed posture: the exchange's ordinary refusal is untouched.
    let h = Harness::start().await;
    let client_id = h.client_id().to_string();
    let code = h
        .issue_authenticated_code_with_scope(&client_id, DEVICE_SSO)
        .await;
    let (_status, response) = redeem(&h, &client_id, &code).await;
    let id_token = json(&response)["id_token"]
        .as_str()
        .expect("an id token")
        .to_owned();

    let (status, response) = present_pair(&h, &client_id, &id_token, "any-secret").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an ID token is not an exchangeable subject on an unarmed deployment: {response}"
    );
    assert_eq!(json(&response)["error"], "invalid_request", "{response}");
}

#[tokio::test]
async fn an_armed_deployment_returns_a_bound_pair_and_a_sibling_redeems_it() {
    // THE FEATURE. App A signs in and receives a device secret; its ID token carries the hash
    // of that secret; app B presents the pair and gets its own tokens for the same person.
    let mut h = Harness::start().await;
    h.install_native_sso();
    let app_a = h.client_id().to_string();
    let code = h
        .issue_authenticated_code_with_scope(&app_a, DEVICE_SSO)
        .await;
    let (status, response) = redeem(&h, &app_a, &code).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let body = json(&response);
    let device_secret = body["device_secret"]
        .as_str()
        .expect("an armed deployment returns a device secret for device_sso")
        .to_owned();
    let id_token = body["id_token"].as_str().expect("an id token").to_owned();
    let claims = payload(&id_token);
    assert!(
        claims.get("ds_hash").is_some(),
        "the ID token carries the binding: {claims}"
    );

    // The SIBLING. A different client presents app A's ID token with the secret.
    let (app_b, _secret) = h
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await;
    let (status, response) = present_pair(&h, &app_b.to_string(), &id_token, &device_secret).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a sibling redeems the pair for its own tokens: {response}"
    );
    let issued = json(&response);
    assert!(
        issued["access_token"].as_str().is_some(),
        "and receives an access token: {response}"
    );
}

#[tokio::test]
async fn neither_half_of_the_pair_works_alone() {
    // THE WHOLE SECURITY ARGUMENT. A stolen ID token is inert without the secret, and a stolen
    // secret is inert without the token it was issued beside.
    let mut h = Harness::start().await;
    h.install_native_sso();
    let app_a = h.client_id().to_string();
    let code = h
        .issue_authenticated_code_with_scope(&app_a, DEVICE_SSO)
        .await;
    let (_status, response) = redeem(&h, &app_a, &code).await;
    let body = json(&response);
    let device_secret = body["device_secret"].as_str().expect("a secret").to_owned();
    let id_token = body["id_token"].as_str().expect("an id token").to_owned();

    // The ID token with a WRONG secret.
    let (status, response) = present_pair(&h, &app_a, &id_token, "not-the-secret").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(json(&response)["error"], "invalid_grant", "{response}");

    // The secret with an ID token from a DIFFERENT sign-in, which carries a different binding.
    let other_code = h
        .issue_authenticated_code_with_scope(&app_a, DEVICE_SSO)
        .await;
    let (_status, other) = redeem(&h, &app_a, &other_code).await;
    let other_id_token = json(&other)["id_token"]
        .as_str()
        .expect("an id token")
        .to_owned();
    let (status, response) = present_pair(&h, &app_a, &other_id_token, &device_secret).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a secret does not open another sign-in's token: {response}"
    );
    assert_eq!(json(&response)["error"], "invalid_grant", "{response}");

    // And the ID token subject presented WITHOUT the actor type at all, which is the request
    // the ordinary shape rule refuses and which the relaxation must not admit.
    let alone = form(&[
        ("grant_type", EXCHANGE_GRANT),
        ("subject_token", &id_token),
        ("subject_token_type", ID_TOKEN_TOKEN_TYPE),
        ("client_id", &app_a),
    ]);
    let (status, _headers, response) = h.token(&alone).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(
        json(&response)["error"],
        "invalid_request",
        "an ID token subject with no device secret stays refused by the shape rule: {response}"
    );
}

#[tokio::test]
async fn a_scope_without_device_sso_gets_no_secret_even_when_armed() {
    // The scope is the client's request for the feature. Armed but unasked-for must mint
    // nothing, or every code exchange on the deployment would start handing out family
    // credentials.
    let mut h = Harness::start().await;
    h.install_native_sso();
    let client_id = h.client_id().to_string();
    let code = h
        .issue_authenticated_code_with_scope(&client_id, "profile")
        .await;
    let (status, response) = redeem(&h, &client_id, &code).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(
        json(&response).get("device_secret").is_none(),
        "no device_sso in the granted scope means no secret: {response}"
    );
    let claims = payload(json(&response)["id_token"].as_str().expect("an id token"));
    assert!(
        claims.get("ds_hash").is_none(),
        "and no binding on the ID token: {claims}"
    );
}
