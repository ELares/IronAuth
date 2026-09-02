// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native SSO end to end, through the real endpoints (issue #133, PROTOTYPE).
//!
//! `tests/native_sso.rs` drives the binding rules directly and answers what they accept. This
//! file answers what that one cannot: whether the endpoints REACH them, whether the unarmed
//! posture is genuinely unchanged, whether a sibling can actually redeem, and whether ending
//! the session severs the set.
//!
//! # Why every client here is confidential
//!
//! The harness's default client is PUBLIC, and a public client always requires PKCE at
//! `/authorize`, so the non-PKCE code helpers cannot drive it: the first version of this file
//! used `h.client_id()` and every test panicked on its first line with `PKCE is required`.
//! Token exchange also requires a confidential client and a registered grant type. So both apps
//! are built the way `tests/token_exchange.rs` builds its exchanging client.
//!
//! Needs a database.

mod common;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Harness, REDIRECT_URI, form, json};
use ironauth_oidc::native_sso::{DEVICE_SECRET_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE};
use ironauth_oidc::{ClientAuthMethod, GrantType};
use ironauth_store::ClientId;

const EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const DEVICE_SSO: &str = "device_sso";

/// An HTTP Basic credential for a confidential client.
fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// The claims of a compact JWS, without verifying it. Test-side inspection only.
fn payload(token: &str) -> serde_json::Value {
    let raw = token.split('.').nth(1).expect("a payload");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(raw).expect("base64url")).expect("json")
}

/// A confidential client registered for the code grant AND the exchange.
async fn family_app(h: &Harness) -> (ClientId, String) {
    let (id, secret) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    h.set_client_grant_types(
        &id,
        &format!("authorization_code {}", GrantType::TOKEN_EXCHANGE_URN),
    )
    .await;
    (id, secret)
}

/// Sign in as `client`, granting `scope`, and return the whole token response.
async fn sign_in(
    h: &Harness,
    client: &ClientId,
    secret: &str,
    scope: &str,
) -> (StatusCode, String) {
    let code = h
        .issue_authenticated_code_with_scope(&client.to_string(), scope)
        .await;
    let (status, _headers, response) = h
        .token_with_auth(
            &form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT_URI),
            ]),
            Some(&basic(&client.to_string(), secret)),
        )
        .await;
    (status, response)
}

/// Present a (ID token, device secret) pair at the exchange as `client`.
async fn present_pair(
    h: &Harness,
    client: &ClientId,
    secret: &str,
    id_token: &str,
    device_secret: &str,
) -> (StatusCode, String) {
    let (status, _headers, response) = h
        .token_with_auth(
            &form(&[
                ("grant_type", EXCHANGE_GRANT),
                ("subject_token", id_token),
                ("subject_token_type", ID_TOKEN_TOKEN_TYPE),
                ("actor_token", device_secret),
                ("actor_token_type", DEVICE_SECRET_TOKEN_TYPE),
            ]),
            Some(&basic(&client.to_string(), secret)),
        )
        .await;
    (status, response)
}

#[tokio::test]
async fn an_unarmed_deployment_issues_no_device_secret_and_no_binding() {
    // THE POSTURE THAT MATTERS MOST, and it is a guard on MAIN's behaviour rather than evidence
    // about the feature: it passes with the whole prototype deleted, deliberately. Every ID
    // token this deployment has ever issued must stay unbound, because `ds_hash` is the only
    // thing that makes the exchange's relaxed subject type safe. If the claim appeared without
    // the flag, every existing token would be one half of a redeemable pair.
    let h = Harness::start().await;
    let (app, secret) = family_app(&h).await;
    let (status, response) = sign_in(&h, &app, &secret, &format!("openid {DEVICE_SSO}")).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let body = json(&response);
    assert!(
        body.get("device_secret").is_none(),
        "an unarmed deployment returns no device secret even when device_sso was granted: \
         {response}"
    );
    let claims = payload(body["id_token"].as_str().expect("an id token"));
    assert!(
        claims.get("ds_hash").is_none(),
        "and its ID token carries no binding: {claims}"
    );
}

#[tokio::test]
async fn an_unarmed_exchange_refuses_an_id_token_subject() {
    // The other half of the unarmed posture, also a main-behaviour guard.
    let h = Harness::start().await;
    let (app, secret) = family_app(&h).await;
    let (_status, response) = sign_in(&h, &app, &secret, &format!("openid {DEVICE_SSO}")).await;
    let id_token = json(&response)["id_token"]
        .as_str()
        .expect("an id token")
        .to_owned();

    let (status, response) = present_pair(&h, &app, &secret, &id_token, "any-secret").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an ID token is not an exchangeable subject on an unarmed deployment: {response}"
    );
    assert_eq!(json(&response)["error"], "invalid_request", "{response}");
}

#[tokio::test]
async fn an_armed_deployment_returns_a_bound_pair_and_a_sibling_redeems_it() {
    // THE FEATURE, and the only test here that demonstrates it working.
    let mut h = Harness::start().await;
    h.install_native_sso();
    let (app_a, secret_a) = family_app(&h).await;
    let (status, response) = sign_in(
        &h,
        &app_a,
        &secret_a,
        &format!("openid profile {DEVICE_SSO}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let body = json(&response);
    let device_secret = body["device_secret"]
        .as_str()
        .expect("an armed deployment returns a device secret for device_sso")
        .to_owned();
    let id_token = body["id_token"].as_str().expect("an id token").to_owned();
    assert!(
        payload(&id_token).get("ds_hash").is_some(),
        "the ID token carries the binding"
    );

    // The SIBLING: a different app in the family.
    let (app_b, secret_b) = family_app(&h).await;
    let (status, response) = present_pair(&h, &app_b, &secret_b, &id_token, &device_secret).await;
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

    // `device_sso` is NOT inherited. A sibling that could inherit it would mint a further
    // secret from a bootstrap, and one sign-in would fan out into an unbounded family of
    // independent thirty-day credentials.
    let granted = issued["scope"].as_str().unwrap_or_default();
    assert!(
        !granted.split_whitespace().any(|s| s == DEVICE_SSO),
        "the bootstrap must not carry device_sso forward: {response}"
    );
    assert!(
        granted.split_whitespace().any(|s| s == "profile"),
        "but it does inherit what the sign-in was actually granted: {response}"
    );
}

#[tokio::test]
async fn neither_half_of_the_pair_works_alone() {
    // THE WHOLE SECURITY ARGUMENT. A stolen ID token is inert without the secret, and a stolen
    // secret is inert without the token it was issued beside.
    let mut h = Harness::start().await;
    h.install_native_sso();
    let (app_a, secret_a) = family_app(&h).await;
    let (_status, response) = sign_in(&h, &app_a, &secret_a, &format!("openid {DEVICE_SSO}")).await;
    let body = json(&response);
    let device_secret = body["device_secret"].as_str().expect("a secret").to_owned();
    let id_token = body["id_token"].as_str().expect("an id token").to_owned();

    // The ID token with a WRONG secret.
    let (status, response) = present_pair(&h, &app_a, &secret_a, &id_token, "not-it").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(json(&response)["error"], "invalid_grant", "{response}");

    // The secret with an ID token from a DIFFERENT sign-in, carrying a different binding.
    let (_status, other) = sign_in(&h, &app_a, &secret_a, &format!("openid {DEVICE_SSO}")).await;
    let other_id_token = json(&other)["id_token"]
        .as_str()
        .expect("an id token")
        .to_owned();
    let (status, response) =
        present_pair(&h, &app_a, &secret_a, &other_id_token, &device_secret).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a secret does not open another sign-in's token: {response}"
    );
    assert_eq!(json(&response)["error"], "invalid_grant", "{response}");

    // And the ID token subject presented WITHOUT the actor type, which is the request the
    // ordinary shape rule refuses and which the joint relaxation must not admit.
    let (status, _headers, response) = h
        .token_with_auth(
            &form(&[
                ("grant_type", EXCHANGE_GRANT),
                ("subject_token", &id_token),
                ("subject_token_type", ID_TOKEN_TOKEN_TYPE),
            ]),
            Some(&basic(&app_a.to_string(), &secret_a)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(
        json(&response)["error"],
        "invalid_request",
        "an ID token subject with no device secret stays refused: {response}"
    );
}

#[tokio::test]
async fn a_scope_without_device_sso_gets_no_secret_even_when_armed() {
    // The scope is the client's request for the feature. Armed but unasked-for must mint
    // nothing, or every code exchange on the deployment would hand out family credentials.
    let mut h = Harness::start().await;
    h.install_native_sso();
    let (app, secret) = family_app(&h).await;
    let (status, response) = sign_in(&h, &app, &secret, "openid profile").await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(
        json(&response).get("device_secret").is_none(),
        "no device_sso in the granted scope means no secret: {response}"
    );
    assert!(
        payload(json(&response)["id_token"].as_str().expect("an id token"))
            .get("ds_hash")
            .is_none(),
        "and no binding on the ID token"
    );
}

#[tokio::test]
async fn ending_the_session_severs_the_sso_set() {
    // THE REVOCATION CRITERION, which the first version of this file claimed in its header and
    // did not test at all.
    //
    // It is driven through an ADMIN session revocation rather than through RP-initiated logout,
    // and that is the point. The explicit sweep runs only on logout; every other way a session
    // ends touches no row in the device-secret table. What severs the set on those paths is the
    // session join inside `redeem`, so revoking by a route the sweep never sees is the case
    // that distinguishes a real control from a remembered one.
    let mut h = Harness::start().await;
    h.install_native_sso();
    let (app_a, secret_a) = family_app(&h).await;
    let (_status, response) = sign_in(&h, &app_a, &secret_a, &format!("openid {DEVICE_SSO}")).await;
    let body = json(&response);
    let device_secret = body["device_secret"].as_str().expect("a secret").to_owned();
    let id_token = body["id_token"].as_str().expect("an id token").to_owned();

    // It redeems while the session is live, so the refusal below is attributable.
    let (app_b, secret_b) = family_app(&h).await;
    let (status, before) = present_pair(&h, &app_b, &secret_b, &id_token, &device_secret).await;
    assert_eq!(status, StatusCode::OK, "live before revocation: {before}");

    let subject = payload(&id_token)["sub"].as_str().expect("sub").to_owned();
    h.revoke_every_session_for(&subject).await;

    let (status, after) = present_pair(&h, &app_b, &secret_b, &id_token, &device_secret).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the set is severed the moment the session ends, by ANY route: {after}"
    );
    assert_eq!(json(&after)["error"], "invalid_grant", "{after}");
}
