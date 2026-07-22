// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OAuth 2.0 Authorization Challenge Endpoint (issue #93, Bet 3, PR1,
//! draft-ietf-oauth-first-party-apps-03), against a real Postgres.
//!
//! PR1 = the SPINE: the version-ack gate, the endpoint skeleton (flag-off 404, flag-on served),
//! and the LOGIN-ONLY happy path (a first-party native client submits credentials, the endpoint
//! drives the login flow to completion in one request, mints a BROWSERLESS authorization code, and
//! the ordinary token endpoint redeems it with NO `redirect_uri`). This suite also pins the
//! token-endpoint FORK A regression: a browser authorization code path is byte-identical (a normal
//! code with a `redirect_uri` still redeems, a browser code without a `redirect_uri` is still
//! rejected), and a browserless code presented WITH a `redirect_uri` is rejected.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, REDIRECT_URI, form, json};
use ironauth_oidc::ClientAuthMethod;

/// The identifier and password the suite's first-party user is seeded with.
const IDENTIFIER: &str = "native@example.test";
const PASSWORD: &str = "correct horse battery staple";

/// POST an `application/x-www-form-urlencoded` body to the scope-routed challenge endpoint.
async fn challenge(harness: &Harness, body: &str) -> (StatusCode, String) {
    let scope = harness.scope();
    let uri = format!(
        "/t/{}/e/{}/authorize-challenge",
        scope.tenant(),
        scope.environment()
    );
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))
        .expect("request builds");
    let (status, _headers, response) = harness.send(request).await;
    (status, response)
}

/// A challenge form for a login-only credential submission.
fn challenge_form(client_id: &str, username: &str, password: &str) -> String {
    form(&[
        ("client_id", client_id),
        ("response_type", "code"),
        ("username", username),
        ("password", password),
    ])
}

/// Start a harness with the challenge feature armed and a first-party seeded user, returning the
/// harness and the first-party client id string.
async fn armed_harness() -> (Harness, String) {
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    let client_id = *harness.client_id();
    harness.set_client_first_party(&client_id, true).await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;
    (harness, client_id.to_string())
}

#[tokio::test]
async fn happy_path_challenge_mints_a_code_the_token_endpoint_redeems() {
    let (harness, client_id) = armed_harness().await;

    // The native client submits credentials; the endpoint drives login to completion in one
    // request and returns a browserless authorization code.
    let (status, body) =
        challenge(&harness, &challenge_form(&client_id, IDENTIFIER, PASSWORD)).await;
    assert_eq!(status, StatusCode::OK, "challenge should succeed: {body}");
    let code = json(&body)["authorization_code"]
        .as_str()
        .expect("authorization_code in the response")
        .to_owned();
    assert!(code.starts_with("ac_"), "an authorization code: {code}");

    // The ordinary token endpoint redeems it with NO redirect_uri (a public client presents only
    // its client_id).
    let redeem = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("client_id", &client_id),
    ]);
    let (status, _headers, response) = harness.token(&redeem).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token exchange should succeed: {response}"
    );
    assert!(
        json(&response)["access_token"].is_string(),
        "an access token: {response}"
    );
    assert!(
        json(&response)["id_token"].is_string(),
        "an id token: {response}"
    );
}

#[tokio::test]
async fn flag_off_is_a_uniform_404() {
    // The SAME request with the feature NOT armed is a uniform 404 (nothing is served until an
    // operator enables AND acknowledges the experiment).
    let harness = Harness::start().await;
    let client_id = *harness.client_id();
    harness.set_client_first_party(&client_id, true).await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (status, _body) = challenge(
        &harness,
        &challenge_form(&client_id.to_string(), IDENTIFIER, PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "flag-off must be a 404");
}

#[tokio::test]
async fn a_non_first_party_client_is_rejected() {
    // The client is NOT classified first-party, so the challenge endpoint refuses it.
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    let client_id = *harness.client_id();
    // Deliberately NOT set_client_first_party.
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (status, body) = challenge(
        &harness,
        &challenge_form(&client_id.to_string(), IDENTIFIER, PASSWORD),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "non-first-party is rejected: {body}"
    );
    assert_eq!(json(&body)["error"], "unauthorized_client");
}

#[tokio::test]
async fn response_type_must_be_code() {
    let (harness, client_id) = armed_harness().await;
    let body = form(&[
        ("client_id", &client_id),
        ("response_type", "token"),
        ("username", IDENTIFIER),
        ("password", PASSWORD),
    ]);
    let (status, response) = challenge(&harness, &body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "response_type token is rejected: {response}"
    );
    assert_eq!(json(&response)["error"], "unsupported_response_type");
}

#[tokio::test]
async fn wrong_credentials_do_not_complete() {
    // A wrong password does not complete the login: PR1 returns a minimal insufficient_authorization
    // (never a code, never an oracle of which credential was wrong).
    let (harness, client_id) = armed_harness().await;
    let (status, body) = challenge(
        &harness,
        &challenge_form(&client_id, IDENTIFIER, "wrong-password"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "wrong credentials do not complete: {body}"
    );
    assert_eq!(json(&body)["error"], "insufficient_authorization");
}

// ---------------------------------------------------------------------------------------------
// Token-endpoint FORK A regression: the browser authorization-code path stays byte-identical, and
// the browserless discriminator is enforced symmetrically.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_normal_browser_code_still_redeems_with_its_redirect_uri() {
    // The shipped browser path is UNCHANGED: a code issued with a redirect_uri redeems exactly as
    // before when the token request presents that redirect_uri. A confidential client (as in the
    // client-auth suite) keeps the exchange to client auth + the redirect_uri binding, no PKCE.
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Post)
        .await;
    let client_id = client.to_string();
    let code = harness.issue_authenticated_code(&client_id).await;

    let redeem = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("client_secret", &secret),
    ]);
    let (status, _headers, response) = harness.token(&redeem).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "browser code still redeems: {response}"
    );
    assert!(json(&response)["access_token"].is_string());
}

#[tokio::test]
async fn a_browser_code_without_a_redirect_uri_is_still_rejected() {
    // A browser code carries a redirect_uri binding, so a token request that omits it is a
    // mismatch (invalid_grant), exactly as before FORK A.
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Post)
        .await;
    let client_id = client.to_string();
    let code = harness.issue_authenticated_code(&client_id).await;

    let redeem = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("client_id", &client_id),
        ("client_secret", &secret),
    ]);
    let (status, _headers, response) = harness.token(&redeem).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "missing redirect_uri is rejected: {response}"
    );
    assert_eq!(json(&response)["error"], "invalid_grant");
}

#[tokio::test]
async fn a_browserless_code_with_a_redirect_uri_is_rejected() {
    // A browserless first-party code carries NO redirect_uri, so a token request that PRESENTS one
    // is a mismatch (invalid_grant), symmetric with the two-direction PKCE rule.
    let (harness, client_id) = armed_harness().await;
    let (status, body) =
        challenge(&harness, &challenge_form(&client_id, IDENTIFIER, PASSWORD)).await;
    assert_eq!(status, StatusCode::OK, "challenge should succeed: {body}");
    let code = json(&body)["authorization_code"]
        .as_str()
        .expect("authorization_code")
        .to_owned();

    let redeem = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
    ]);
    let (status, _headers, response) = harness.token(&redeem).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a browserless code with a redirect_uri is rejected: {response}"
    );
    assert_eq!(json(&response)["error"], "invalid_grant");
}

// ---------------------------------------------------------------------------------------------
// Consent-gate escalation: the browserless endpoint cannot render an interactive consent screen,
// so a quarantined client (#31) or a quarantined user (#82) is escalated to the browser with
// redirect_to_web rather than silently auto-granted a code (the security-lens HIGH).
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_quarantined_first_party_client_is_escalated_to_the_browser() {
    // #31 consent-gate bypass regression: a first-party client that is ALSO quarantined (unverified)
    // cannot be silently auto-granted a code. The browser path forces an interactive consent screen
    // on EVERY authorization until an admin verifies the client; the browserless endpoint cannot
    // render one, so it escalates with redirect_to_web and mints NOTHING.
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    let client_id = *harness.client_id();
    harness.set_client_first_party(&client_id, true).await;
    harness.set_client_quarantined(&client_id, true).await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (status, body) = challenge(
        &harness,
        &challenge_form(&client_id.to_string(), IDENTIFIER, PASSWORD),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a quarantined client is escalated, not auto-granted: {body}"
    );
    assert_eq!(json(&body)["error"], "redirect_to_web");
    assert!(
        json(&body)["authorization_code"].is_null(),
        "no code is minted for a quarantined client: {body}"
    );
}

#[tokio::test]
async fn a_quarantined_user_is_escalated_and_gets_no_offline_refresh() {
    // #82 consent-gate bypass regression: a QUARANTINED user requesting offline_access cannot obtain
    // a code (and therefore no long-lived offline refresh family) through the browserless endpoint.
    // The browser path strips sensitive scopes UNCONDITIONALLY for a quarantined user; the
    // browserless endpoint cannot render the consent/strip surface, so it escalates with
    // redirect_to_web. No code is minted, so the offline refresh family is unreachable via this path.
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    harness.also_enable_signup_quarantine();
    let client_id = *harness.client_id();
    harness.set_client_first_party(&client_id, true).await;
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;
    harness.set_user_quarantined(&subject, true).await;

    let body = form(&[
        ("client_id", &client_id.to_string()),
        ("response_type", "code"),
        ("scope", "openid offline_access"),
        ("username", IDENTIFIER),
        ("password", PASSWORD),
    ]);
    let (status, resp) = challenge(&harness, &body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a quarantined user is escalated, not auto-granted: {resp}"
    );
    assert_eq!(json(&resp)["error"], "redirect_to_web");
    assert!(
        json(&resp)["authorization_code"].is_null(),
        "no code is minted for a quarantined user, so no offline refresh family is reachable: {resp}"
    );
}
