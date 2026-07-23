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
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
};
use ironauth_config::OidcConfig;
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, code_at};
use ironauth_oidc::ClientAuthMethod;
use ironauth_oidc::flow::create_flow;
use ironauth_oidc::flow::model::{Journey, Transport};
use ironauth_store::{ClientId, UserState};

/// The identifier and password the suite's first-party user is seeded with.
const IDENTIFIER: &str = "native@example.test";
const PASSWORD: &str = "correct horse battery staple";
/// The TOTP seed the harness `seed_active_totp` enrolls, so a real code is reproducible.
const TOTP_SEED: [u8; 20] = [0x0A; 20];

/// A denylisted client IP that scores the risk engine HIGH (drives a post-primary-success Block).
const DENYLISTED_IP: &str = "203.0.113.9";
/// A clean client IP (no risk signal), for the wrong-password control.
const CLEAN_IP: &str = "198.51.100.7";

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

/// POST a challenge body carrying the non-forgeable peer-IP header (issue #31) the risk engine
/// resolves, so an IP-based signal sees a stable client address in the in-process router.
async fn challenge_from_ip(harness: &Harness, body: &str, ip: &str) -> (StatusCode, String) {
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
        .header("x-ironauth-peer-ip", ip)
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

/// Like [`armed_harness`] but the seeded user is enrolled in an ACTIVE TOTP factor and the tenant
/// baseline demands MFA, so a correct primary factor HOLDS on the second-factor challenge (the PR2
/// step-up loop) rather than completing in one request.
async fn armed_mfa_harness() -> (Harness, String) {
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    let client_id = *harness.client_id();
    harness.set_client_first_party(&client_id, true).await;
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;
    harness.seed_active_totp(&subject).await;
    harness.set_tenant_min_class("mfa").await;
    (harness, client_id.to_string())
}

/// The current app-clock wall time in whole seconds (the TOTP step basis).
fn now_secs(harness: &Harness) -> u64 {
    harness
        .clock()
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs()
}

/// A real TOTP code for the seeded factor at the current app-clock time.
fn totp_code(harness: &Harness) -> String {
    code_at(
        &TOTP_SEED,
        TotpParams::authenticator_default(),
        now_secs(harness),
    )
}

/// Drive the FRESH first hop (identifier + password) and return the `auth_session` continuity
/// handle the step-up render carries. Asserts the hop is a `400 insufficient_authorization` with an
/// `auth_session` and the `otp_required` hint.
async fn first_hop_auth_session(harness: &Harness, client_id: &str) -> String {
    let (status, body) = challenge(harness, &challenge_form(client_id, IDENTIFIER, PASSWORD)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the primary factor holds on the second factor: {body}"
    );
    assert_eq!(json(&body)["error"], "insufficient_authorization");
    assert_eq!(json(&body)["otp_required"], true, "the otp hint: {body}");
    json(&body)["auth_session"]
        .as_str()
        .unwrap_or_else(|| panic!("an auth_session in the step-up render: {body}"))
        .to_owned()
}

/// Forge the opaque continuity handle the endpoint decodes: `base64url(flow_id.submit_token)`. Used
/// by the adversarial regression probes to hand a NON challenge-endpoint flow to the resume branch.
fn forge_auth_session(flow_id: &str, submit_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{flow_id}.{submit_token}"))
}

/// The `amr` tokens carried in an id token's payload (decoded, unverified: the suite only needs to
/// read the honest method set the mint recorded).
fn id_token_amr(id_token: &str) -> Vec<String> {
    let payload = id_token.split('.').nth(1).expect("a jwt payload segment");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("decode the payload");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("parse the claims");
    claims["amr"]
        .as_array()
        .map(|array| {
            array
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// POST a JSON body to the public headless flow-create route for `journey`, returning the raw
/// status and body (no success assertion, so a rejection is observable).
async fn flow_api_create(
    harness: &Harness,
    journey: &str,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let scope = harness.scope();
    let uri = format!(
        "/t/{}/e/{}/flow/api/{journey}",
        scope.tenant(),
        scope.environment()
    );
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request builds");
    let (status, _headers, response) = harness.send(request).await;
    (status, response)
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

/// An `/authorize` query for the browser control leg (PKCE + the harness `redirect_uri`).
fn authorize_query(client_id: &str, scope: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc(scope),
    )
}

#[tokio::test]
async fn the_challenge_and_browser_escalate_the_same_quarantined_user_through_the_shared_core() {
    // #365: the browserless challenge endpoint and the browser `/authorize` gate now make the
    // consent decision in ONE place (`consent_core::decide`), so they can never diverge again (the
    // #93 Bet 3 bypass). Prove it end to end on the SAME first-party carve-out client: a quarantined
    // user is ESCALATED (never silently auto-granted) on BOTH surfaces, while a non-quarantined user
    // is auto-granted on both. If either surface hand-mirrored its own decision, one of these four
    // assertions would drift.
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    harness.also_enable_signup_quarantine();
    let client_id = *harness.client_id();
    harness.set_client_first_party(&client_id, true).await;
    // `skip_consent` makes the BROWSER carve-out eligible (the challenge trusts a first-party client
    // wholesale); with it set, absent quarantine BOTH surfaces silently auto-grant, so a quarantine
    // is the ONLY thing that can escalate either. That is exactly the shared-core property under test.
    harness
        .configure_client_policy(&client_id, "explicit", true, false, None)
        .await;
    let client_id_str = client_id.to_string();
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;

    // Control, a non-quarantined user: the challenge mints a code, and the browser silently grants.
    let (status, body) = challenge(
        &harness,
        &challenge_form(&client_id_str, IDENTIFIER, PASSWORD),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the challenge mints for a clean user: {body}"
    );
    assert!(
        json(&body)["authorization_code"].is_string(),
        "a code is minted for a clean user: {body}"
    );
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id_str, "openid profile"), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "browser authorize: {body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "the browser silently grants a clean user (the carve-out): {body}"
    );

    // Quarantine the SAME user: the shared core now escalates it on BOTH surfaces.
    harness.set_user_quarantined(&subject, true).await;

    // The challenge cannot render a consent screen, so it escalates with redirect_to_web and mints
    // nothing (the `NeedsInteractiveConsent` mapping).
    let (status, body) = challenge(
        &harness,
        &challenge_form(&client_id_str, IDENTIFIER, PASSWORD),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the challenge escalates a quarantined user: {body}"
    );
    assert_eq!(json(&body)["error"], "redirect_to_web");
    assert!(
        json(&body)["authorization_code"].is_null(),
        "no code is minted for a quarantined user: {body}"
    );

    // The browser makes the SAME decision: no silent grant, routed to the consent screen instead.
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id_str, "openid profile"), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "browser authorize: {body}");
    assert!(
        location_param(&headers, "code").is_none(),
        "the browser does NOT silently grant a quarantined user (same core decision): {body}"
    );
}

// ---------------------------------------------------------------------------------------------
// PR2: MFA / step-up continuity. A held second factor returns a rotating opaque `auth_session`
// plus hints; the native client resubmits with the handle and its one time code; the endpoint
// resumes the SAME flow and loops or (on completion) mints the code. The OAuth params are sourced
// from the flow's stashed, WRITE-ONCE `transient_payload`, so they are immutable across rounds.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn step_up_completes_and_the_token_endpoint_redeems_the_resumed_code() {
    let (harness, client_id) = armed_mfa_harness().await;

    // First hop: the correct password holds on the second factor with a continuity handle.
    let auth_session = first_hop_auth_session(&harness, &client_id).await;

    // Resume with the handle and a REAL TOTP code (a fresh step, distinct from the seeded
    // activation): the endpoint resumes the flow and mints the browserless code.
    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = totp_code(&harness);
    let (status, body) = challenge(
        &harness,
        &form(&[("auth_session", &auth_session), ("otp", &code)]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the resumed step-up mints a code: {body}"
    );
    let authorization_code = json(&body)["authorization_code"]
        .as_str()
        .expect("authorization_code")
        .to_owned();
    assert!(
        authorization_code.starts_with("ac_"),
        "an authorization code: {authorization_code}"
    );

    // The ordinary token endpoint redeems it with NO redirect_uri (a browserless first-party code).
    let redeem = form(&[
        ("grant_type", "authorization_code"),
        ("code", &authorization_code),
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
    let id_token = json(&response)["id_token"]
        .as_str()
        .expect("an id token")
        .to_owned();
    // The MFA is provably reflected in the token: the amr carries the second factor (never a
    // fabricated one) alongside the primary, so the step-up genuinely happened before the mint.
    let amr = id_token_amr(&id_token);
    assert!(
        amr.iter().any(|method| method == "otp" || method == "mfa"),
        "the resumed step-up token reflects the second factor in amr, got {amr:?}"
    );
    assert!(
        amr.iter().any(|method| method == "pwd"),
        "the primary factor is still reflected in amr, got {amr:?}"
    );
}

#[tokio::test]
async fn the_resume_hop_auth_session_rotates_away_from_the_first_hop() {
    // Rotation: each render carries a freshly rotated submit token, so a wrong-code loop hop's
    // handle differs from the first hop's.
    let (harness, client_id) = armed_mfa_harness().await;
    let first = first_hop_auth_session(&harness, &client_id).await;

    let (status, body) = challenge(
        &harness,
        &form(&[("auth_session", &first), ("otp", "000000")]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a wrong code loops: {body}"
    );
    let second = json(&body)["auth_session"]
        .as_str()
        .expect("a new auth_session on the loop")
        .to_owned();
    assert_ne!(
        first, second,
        "the resume-hop handle rotates away from the first hop"
    );
}

#[tokio::test]
async fn a_wrong_otp_loops_with_a_new_auth_session() {
    // A wrong second factor re-renders the step-up loop with a NEW handle, never a code and never
    // an oracle of whether the code was close.
    let (harness, client_id) = armed_mfa_harness().await;
    let auth_session = first_hop_auth_session(&harness, &client_id).await;

    let (status, body) = challenge(
        &harness,
        &form(&[("auth_session", &auth_session), ("otp", "000000")]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a wrong code does not complete: {body}"
    );
    assert_eq!(json(&body)["error"], "insufficient_authorization");
    assert_eq!(
        json(&body)["otp_required"],
        true,
        "still asking for the code: {body}"
    );
    assert!(
        json(&body)["auth_session"].as_str().is_some(),
        "a fresh handle to retry with: {body}"
    );
    assert!(
        json(&body)["authorization_code"].is_null(),
        "no code on a wrong code: {body}"
    );
}

#[tokio::test]
async fn a_replayed_first_hop_auth_session_is_rejected_after_a_successful_resume() {
    // Stale rejection: once a handle's flow has completed (or its token rotated out), replaying the
    // handle is the uniform invalid_grant, never a second code.
    let (harness, client_id) = armed_mfa_harness().await;
    let auth_session = first_hop_auth_session(&harness, &client_id).await;

    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = totp_code(&harness);
    let (status, body) = challenge(
        &harness,
        &form(&[("auth_session", &auth_session), ("otp", &code)]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the first resume mints a code: {body}"
    );

    // Replaying the SAME handle now hits the completed flow: a uniform invalid_grant.
    let (status, replay) = challenge(
        &harness,
        &form(&[("auth_session", &auth_session), ("otp", &code)]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a replayed handle is rejected: {replay}"
    );
    assert_eq!(json(&replay)["error"], "invalid_grant");
    assert!(
        json(&replay)["authorization_code"].is_null(),
        "no second code on replay: {replay}"
    );
}

#[tokio::test]
async fn a_resume_under_a_different_client_is_rejected() {
    // Client binding (defense in depth): a resume presenting a DIFFERENT client_id than the one the
    // flow was created for is a uniform invalid_client, so a stolen handle cannot be replayed under
    // another client (and the code binds the ORIGINAL client regardless).
    let (harness, client_id) = armed_mfa_harness().await;
    // A second, distinct first-party client in the same scope.
    let (other_client, _secret) = harness
        .create_confidential_client(ClientAuthMethod::Post)
        .await;
    harness.set_client_first_party(&other_client, true).await;
    let other_client_id = other_client.to_string();

    let auth_session = first_hop_auth_session(&harness, &client_id).await;
    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = totp_code(&harness);
    let (status, body) = challenge(
        &harness,
        &form(&[
            ("auth_session", &auth_session),
            ("otp", &code),
            ("client_id", &other_client_id),
        ]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a cross-client resume is rejected: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_client");
    assert!(
        json(&body)["authorization_code"].is_null(),
        "no code for a cross-client resume: {body}"
    );
}

#[tokio::test]
async fn a_resume_cannot_escalate_the_bound_scope_or_pkce() {
    // The invariant: the OAuth params are stashed WRITE-ONCE at flow creation, so a resume adding
    // scopes and swapping the PKCE challenge has ZERO effect on the bound code. The minted code
    // binds the ORIGINAL "openid" scope and the ORIGINAL code_challenge, proved via the token
    // endpoint (the original verifier still validates, and no offline refresh family is bound).
    let (harness, client_id) = armed_mfa_harness().await;

    // First hop binds the ORIGINAL scope "openid" and a real PKCE challenge.
    let (status, body) = challenge(
        &harness,
        &form(&[
            ("client_id", &client_id),
            ("response_type", "code"),
            ("scope", "openid"),
            ("code_challenge", PKCE_CHALLENGE),
            ("code_challenge_method", "S256"),
            ("username", IDENTIFIER),
            ("password", PASSWORD),
        ]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the primary factor holds: {body}"
    );
    let auth_session = json(&body)["auth_session"]
        .as_str()
        .expect("an auth_session")
        .to_owned();

    // Resume tries to WIDEN the scope and SWAP the PKCE challenge. Both are ignored by the mint.
    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = totp_code(&harness);
    let (status, body) = challenge(
        &harness,
        &form(&[
            ("auth_session", &auth_session),
            ("otp", &code),
            ("scope", "openid profile email offline_access"),
            (
                "code_challenge",
                "tOtAlLyDiFfErEnTcHaLlEnGeVaLuE0000000000000",
            ),
            ("code_challenge_method", "S256"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the resume completes: {body}");
    let authorization_code = json(&body)["authorization_code"]
        .as_str()
        .expect("authorization_code")
        .to_owned();

    // The ORIGINAL code_challenge is bound: the ORIGINAL verifier validates. Had the resume's
    // swapped challenge been bound, this verifier would be rejected.
    let redeem = form(&[
        ("grant_type", "authorization_code"),
        ("code", &authorization_code),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _headers, response) = harness.token(&redeem).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the original PKCE verifier validates: {response}"
    );
    // The ORIGINAL scope "openid" is bound EXACTLY, never the resume's widened
    // "openid profile email offline_access": the write-once params ignored the resume body, so the
    // sensitive offline_access scope was never bound onto the code.
    assert_eq!(
        json(&response)["scope"],
        "openid",
        "the bound scope is the original: {response}"
    );
}

#[tokio::test]
async fn a_primary_failure_is_indistinguishable_from_an_unknown_user() {
    // Anti-enumeration: a wrong password AND an unknown user both map to the SAME uniform
    // insufficient_authorization with NO auth_session and NO hints, distinct from the MFA response
    // (which carries the handle + otp_required only after a genuine primary success).
    let (harness, client_id) = armed_mfa_harness().await;

    let (wrong_status, wrong_body) = challenge(
        &harness,
        &challenge_form(&client_id, IDENTIFIER, "not-the-password"),
    )
    .await;
    let (unknown_status, unknown_body) = challenge(
        &harness,
        &challenge_form(&client_id, "ghost@example.test", PASSWORD),
    )
    .await;

    assert_eq!(wrong_status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown_status, StatusCode::BAD_REQUEST);
    for body in [&wrong_body, &unknown_body] {
        assert_eq!(json(body)["error"], "insufficient_authorization");
        assert!(
            json(body)["auth_session"].is_null(),
            "no continuity handle on a primary failure: {body}"
        );
        assert!(
            json(body)["otp_required"].is_null(),
            "no otp hint on a primary failure: {body}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// PR3 escalation: the redirect_to_web escalation is GENERALIZED to the unsatisfiable-headless holds,
// but a risk Block and a locked/fenced account STAY the uniform insufficient_authorization at
// IdentifierPassword (the anti-enumeration invariant): a hard deny is byte-identical to a wrong
// password and is NEVER a browser handoff. These pin that A.1 boundary end to end (OWNER decision R1).
// ---------------------------------------------------------------------------------------------

/// An armed challenge harness whose risk engine BLOCKS a login from [`DENYLISTED_IP`] after a
/// successful primary verify (issue #79 `block_on_high` + an IP denylist), with the #64 failure
/// throttle off so the wrong-password control is a clean uniform failure rather than a throttle.
async fn armed_block_harness() -> (Harness, String) {
    let mut config = OidcConfig::default();
    config.risk.enabled = true;
    config.risk.new_device_enabled = false;
    config.risk.impossible_travel_enabled = false;
    config.risk.ip_reputation_enabled = true;
    config.risk.velocity_enabled = false;
    config.risk.block_on_high = true;
    config.risk.ip_denylist = vec![DENYLISTED_IP.to_owned()];
    config.regulation.enabled = false;
    let mut harness = Harness::start_store_backed_with(config).await;
    harness.enable_first_party_challenge();
    let client_id = *harness.client_id();
    harness.set_client_first_party(&client_id, true).await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;
    (harness, client_id.to_string())
}

#[tokio::test]
async fn a_risk_block_stays_the_uniform_failure_and_is_never_redirect_to_web() {
    // A.1 (OWNER R1): a risk Block is consumed AFTER a successful primary verify and produces the
    // SAME uniform render a wrong password does, on IdentifierPassword. render_step_response maps
    // IdentifierPassword to the uniform failure, so the CORRECT password from a denylisted IP is a
    // uniform insufficient_authorization, byte-identical to a wrong password and NEVER
    // redirect_to_web (routing a Block to the browser would reintroduce a credential-validity
    // oracle: a hard deny is not a browser handoff).
    let (harness, client_id) = armed_block_harness().await;

    // The CORRECT password from a denylisted IP: the risk engine blocks post-verify.
    let (block_status, block_body) = challenge_from_ip(
        &harness,
        &challenge_form(&client_id, IDENTIFIER, PASSWORD),
        DENYLISTED_IP,
    )
    .await;
    // The control: a WRONG password from a clean IP (an ordinary primary failure).
    let (wrong_status, wrong_body) = challenge_from_ip(
        &harness,
        &challenge_form(&client_id, IDENTIFIER, "not-the-password"),
        CLEAN_IP,
    )
    .await;

    assert_eq!(block_status, StatusCode::BAD_REQUEST, "block: {block_body}");
    assert_eq!(
        json(&block_body)["error"],
        "insufficient_authorization",
        "a Block stays the uniform failure, not redirect_to_web: {block_body}"
    );
    assert_ne!(
        json(&block_body)["error"],
        "redirect_to_web",
        "a Block must NEVER escalate to the browser (no credential-validity oracle): {block_body}"
    );
    assert!(
        json(&block_body)["authorization_code"].is_null(),
        "a Block mints nothing: {block_body}"
    );
    assert!(
        json(&block_body)["auth_session"].is_null(),
        "a Block carries no continuity handle: {block_body}"
    );
    // The anti-enumeration invariant: byte-identical to a wrong password.
    assert_eq!(
        block_status, wrong_status,
        "a Block and a wrong password share a status"
    );
    assert_eq!(
        block_body, wrong_body,
        "a Block is byte-identical to a wrong password: block={block_body} wrong={wrong_body}"
    );
}

#[tokio::test]
async fn a_locked_account_stays_the_uniform_failure_and_is_never_redirect_to_web() {
    // A.1 (OWNER R1): a locked/fenced account (login.rs: `!can_authenticate()`) renders the SAME
    // uniform failure at IdentifierPassword after spending the timing-uniform Argon2 op. A correct
    // password against a blocked account is therefore a uniform insufficient_authorization, NEVER
    // redirect_to_web and never a code.
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    let client_id = *harness.client_id();
    harness.set_client_first_party(&client_id, true).await;
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;
    harness.set_user_state(&subject, UserState::Blocked).await;

    let (status, body) = challenge(
        &harness,
        &challenge_form(&client_id.to_string(), IDENTIFIER, PASSWORD),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "locked: {body}");
    assert_eq!(
        json(&body)["error"],
        "insufficient_authorization",
        "a locked account stays uniform, not redirect_to_web: {body}"
    );
    assert_ne!(
        json(&body)["error"],
        "redirect_to_web",
        "a locked account must NEVER escalate to the browser: {body}"
    );
    assert!(
        json(&body)["authorization_code"].is_null(),
        "a locked account mints nothing: {body}"
    );
    assert!(
        json(&body)["auth_session"].is_null(),
        "a locked account carries no continuity handle: {body}"
    );
}

#[tokio::test]
async fn a_garbage_auth_session_is_a_uniform_invalid_grant() {
    // A structurally invalid handle (bad base64 / no flow) is the SAME uniform stale rejection as a
    // rotated-out one, so the handle is never an oracle.
    let (harness, _client_id) = armed_mfa_harness().await;
    let (status, body) = challenge(
        &harness,
        &form(&[("auth_session", "!!!not-a-handle!!!"), ("otp", "123456")]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a garbage handle is rejected: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
}

// ---------------------------------------------------------------------------------------------
// PR2 security review (HIGH): auth_session provenance. The `challenge` transient_payload namespace
// is SERVER-ONLY, so a client cannot seed a forged stash through the public flow-create API and
// hand the flow to the resume branch; and the resume branch binds the flow to the LOGIN journey.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_public_flow_create_rejects_the_reserved_challenge_namespace() {
    // A client that could seed a top-level `challenge` transient stash through the public headless
    // flow-create API would forge the continuity handle's provenance. The create edge rejects it
    // with a uniform 400 BEFORE any flow exists, so the attacker cannot even seed the stash.
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    harness.enable_flows();
    let client_id = harness.client_id().to_string();

    let (status, body) = flow_api_create(
        &harness,
        "login",
        serde_json::json!({
            "transient_payload": {
                "challenge": {
                    "client_id": client_id,
                    "scope": "openid offline_access",
                    "code_challenge": PKCE_CHALLENGE,
                    "code_challenge_method": "S256",
                }
            }
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the reserved challenge namespace is refused at create: {body}"
    );
}

#[tokio::test]
async fn a_foreign_flow_without_a_challenge_stash_cannot_be_resumed() {
    // Even a plainly-created public flow API login flow (no stash, which the create edge allows)
    // cannot be resumed through the challenge endpoint: with no `challenge` stash to source the
    // bound params from, the handle is the uniform stale rejection, never a mint.
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    harness.enable_flows();
    let cid = *harness.client_id();
    harness.set_client_first_party(&cid, true).await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (status, created) = flow_api_create(&harness, "login", serde_json::json!({})).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a plain login flow is created: {created}"
    );
    let flow_id = json(&created)["flow"]["id"]
        .as_str()
        .expect("flow id")
        .to_owned();
    let submit_token = json(&created)["submit_token"]
        .as_str()
        .expect("submit token")
        .to_owned();

    let auth_session = forge_auth_session(&flow_id, &submit_token);
    let (status, resp) = challenge(
        &harness,
        &form(&[
            ("auth_session", &auth_session),
            ("username", IDENTIFIER),
            ("password", PASSWORD),
        ]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a foreign flow with no challenge stash is rejected: {resp}"
    );
    assert_eq!(json(&resp)["error"], "invalid_grant");
    assert!(
        json(&resp)["authorization_code"].is_null(),
        "no code is minted from a foreign flow: {resp}"
    );
}

#[tokio::test]
async fn a_resume_against_a_non_login_journey_is_rejected() {
    // Defense in depth (Part 2): even if a `challenge` stash ever reached a NON-login flow, the
    // resume branch binds the flow to the LOGIN journey, so the login-only mint can never drive a
    // Registration / Recovery / Custom journey. White-box: seed a Registration flow carrying a
    // challenge stash directly (a client can no longer seed one through the public API), then try
    // to resume it. The journey binding rejects it uniform, before the stash is ever read.
    let (harness, client_id) = armed_mfa_harness().await;

    let stash = serde_json::json!({
        "challenge": {
            "client_id": client_id,
            "scope": "openid",
            "code_challenge": PKCE_CHALLENGE,
            "code_challenge_method": "S256",
        }
    });
    let (flow_id, submit_token, _flow) = create_flow(
        harness.state(),
        harness.scope(),
        Transport::Api,
        Journey::Registration,
        None,
        Some(&stash),
        None,
        &HeaderMap::new(),
    )
    .await
    .expect("seed a registration flow with a challenge stash");

    let auth_session = forge_auth_session(&flow_id.to_string(), &submit_token);
    let (status, resp) = challenge(
        &harness,
        &form(&[("auth_session", &auth_session), ("otp", "000000")]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-login journey is rejected on resume: {resp}"
    );
    assert_eq!(json(&resp)["error"], "invalid_grant");
    assert!(
        json(&resp)["authorization_code"].is_null(),
        "no code is minted from a non-login journey: {resp}"
    );
}

// ---------------------------------------------------------------------------------------------
// PR4: client-auth parity + per-auth_session rate-limit (the closer). A CONFIDENTIAL first-party
// client must present its registered token-endpoint credential on BOTH a fresh request AND every
// resume hop (the browserless analogue of the token endpoint); a public `none` client is unchanged;
// and a thin fail-OPEN L1 cap (reusing the #64 regulation budget) throttles request spray.
// ---------------------------------------------------------------------------------------------

/// A standard-padded `Basic` credential of `client_id:client_secret` (RFC 6749 2.3.1).
fn basic_header(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// POST a challenge body with an optional `Authorization` header AND an optional non-forgeable
/// peer-IP header, returning the FULL response (status, headers, body) so a test can assert the
/// `RateLimit-*` headers on a 429 and the client-auth outcome. The PR1 `challenge` helper drops
/// the headers and takes no `Authorization`, so PR4 adds this variant (the harness gap).
async fn challenge_full(
    harness: &Harness,
    body: &str,
    authorization: Option<&str>,
    ip: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let scope = harness.scope();
    let uri = format!(
        "/t/{}/e/{}/authorize-challenge",
        scope.tenant(),
        scope.environment()
    );
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    if let Some(ip) = ip {
        builder = builder.header("x-ironauth-peer-ip", ip);
    }
    let request = builder
        .body(Body::from(body.to_owned()))
        .expect("request builds");
    harness.send(request).await
}

/// An armed challenge harness whose first-party client is CONFIDENTIAL (registered for `method`),
/// returning the harness, the client id string, and the plaintext secret.
async fn armed_confidential_harness(method: ClientAuthMethod) -> (Harness, String, String) {
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    let (client, secret) = harness.create_confidential_client(method).await;
    harness.set_client_first_party(&client, true).await;
    harness.seed_user(IDENTIFIER, PASSWORD).await;
    (harness, client.to_string(), secret)
}

/// Like [`armed_confidential_harness`] but the seeded user has an ACTIVE TOTP factor and the tenant
/// demands MFA, so a correct primary factor HOLDS on the second factor (the resume loop).
async fn armed_confidential_mfa_harness(method: ClientAuthMethod) -> (Harness, String, String) {
    let mut harness = Harness::start().await;
    harness.enable_first_party_challenge();
    let (client, secret) = harness.create_confidential_client(method).await;
    harness.set_client_first_party(&client, true).await;
    let subject = harness.seed_user(IDENTIFIER, PASSWORD).await;
    harness.seed_active_totp(&subject).await;
    harness.set_tenant_min_class("mfa").await;
    (harness, client.to_string(), secret)
}

#[tokio::test]
async fn a_confidential_client_with_a_valid_post_secret_completes_fresh_and_redeems() {
    // AC1 (client_secret_post): a confidential first-party client presenting its valid secret on a
    // fresh request completes the login, mints the browserless code, and redeems it at the token
    // endpoint (which re-authenticates the same client and binds the code to it).
    let (harness, client_id, secret) = armed_confidential_harness(ClientAuthMethod::Post).await;
    let body = form(&[
        ("client_id", &client_id),
        ("response_type", "code"),
        ("username", IDENTIFIER),
        ("password", PASSWORD),
        ("client_secret", &secret),
    ]);
    let (status, _headers, resp) = challenge_full(&harness, &body, None, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "valid post secret completes: {resp}"
    );
    let code = json(&resp)["authorization_code"]
        .as_str()
        .expect("authorization_code")
        .to_owned();

    let redeem = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("client_id", &client_id),
        ("client_secret", &secret),
    ]);
    let (status, _headers, tr) = harness.token(&redeem).await;
    assert_eq!(status, StatusCode::OK, "token redemption: {tr}");
    assert!(
        json(&tr)["access_token"].is_string(),
        "an access token: {tr}"
    );
}

#[tokio::test]
async fn a_confidential_client_with_a_valid_basic_secret_completes_fresh() {
    // AC1 (client_secret_basic): the SAME fresh completion, with the secret in the `Authorization:
    // Basic` header instead of the form body.
    let (harness, client_id, secret) = armed_confidential_harness(ClientAuthMethod::Basic).await;
    let body = challenge_form(&client_id, IDENTIFIER, PASSWORD);
    let auth = basic_header(&client_id, &secret);
    let (status, _headers, resp) = challenge_full(&harness, &body, Some(&auth), None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "valid basic secret completes: {resp}"
    );
    assert!(
        json(&resp)["authorization_code"].as_str().is_some(),
        "a browserless code: {resp}"
    );
}

#[tokio::test]
async fn a_confidential_client_presents_client_auth_on_every_resume_hop() {
    // AC1 (resume): a confidential client that holds on the second factor resumes by presenting its
    // client-auth AGAIN on the resume hop and mints the code. The resume body carries no client_id;
    // the parity seam sources the bound client from the flow and the secret from the resume body.
    let (harness, client_id, secret) = armed_confidential_mfa_harness(ClientAuthMethod::Post).await;
    let fresh = form(&[
        ("client_id", &client_id),
        ("response_type", "code"),
        ("username", IDENTIFIER),
        ("password", PASSWORD),
        ("client_secret", &secret),
    ]);
    let (status, _headers, resp) = challenge_full(&harness, &fresh, None, None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "holds on the second factor: {resp}"
    );
    let auth_session = json(&resp)["auth_session"]
        .as_str()
        .expect("an auth_session")
        .to_owned();

    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = totp_code(&harness);
    let resume = form(&[
        ("auth_session", &auth_session),
        ("otp", &code),
        ("client_secret", &secret),
    ]);
    let (status, _headers, resp) = challenge_full(&harness, &resume, None, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the resume presenting client-auth mints a code: {resp}"
    );
    assert!(
        json(&resp)["authorization_code"].as_str().is_some(),
        "a code on the authenticated resume: {resp}"
    );
}

#[tokio::test]
async fn a_confidential_client_without_a_valid_secret_is_rejected_on_fresh() {
    // AC2 (fresh): an absent AND a wrong secret are BOTH a uniform 401 invalid_client on the fresh
    // request, so a confidential client never creates a flow or spends a password verify without
    // proving its credential.
    let (harness, client_id, _secret) = armed_confidential_harness(ClientAuthMethod::Post).await;

    // Absent secret.
    let absent = challenge_form(&client_id, IDENTIFIER, PASSWORD);
    let (status, _headers, resp) = challenge_full(&harness, &absent, None, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "absent secret rejected: {resp}"
    );
    assert_eq!(json(&resp)["error"], "invalid_client");
    assert!(
        json(&resp)["authorization_code"].is_null(),
        "no code without client-auth: {resp}"
    );

    // Wrong secret.
    let wrong = form(&[
        ("client_id", &client_id),
        ("response_type", "code"),
        ("username", IDENTIFIER),
        ("password", PASSWORD),
        ("client_secret", "not-the-secret"),
    ]);
    let (status, _headers, resp) = challenge_full(&harness, &wrong, None, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "wrong secret rejected: {resp}"
    );
    assert_eq!(json(&resp)["error"], "invalid_client");
}

#[tokio::test]
async fn a_confidential_resume_without_a_valid_secret_is_rejected() {
    // AC2 (resume, THE key assertion): a resume with a STRUCTURALLY VALID auth_session and a real
    // OTP but an absent (then wrong) secret is STILL a uniform 401 invalid_client. Client-auth is
    // enforced on every step-up hop, so a stolen handle cannot drive a confidential login.
    let (harness, client_id, secret) = armed_confidential_mfa_harness(ClientAuthMethod::Post).await;
    let fresh = form(&[
        ("client_id", &client_id),
        ("response_type", "code"),
        ("username", IDENTIFIER),
        ("password", PASSWORD),
        ("client_secret", &secret),
    ]);
    let (status, _headers, resp) = challenge_full(&harness, &fresh, None, None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "holds on the second factor: {resp}"
    );
    let auth_session = json(&resp)["auth_session"]
        .as_str()
        .expect("an auth_session")
        .to_owned();

    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = totp_code(&harness);

    // Absent secret on the resume: rejected even though the handle and OTP are valid.
    let absent = form(&[("auth_session", &auth_session), ("otp", &code)]);
    let (status, _headers, resp) = challenge_full(&harness, &absent, None, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a resume without the secret is rejected: {resp}"
    );
    assert_eq!(json(&resp)["error"], "invalid_client");
    assert!(
        json(&resp)["authorization_code"].is_null(),
        "no code on an unauthenticated resume: {resp}"
    );

    // Wrong secret on the resume: same rejection (the handle is not consumed by a rejected resume,
    // so it is still valid here).
    let wrong = form(&[
        ("auth_session", &auth_session),
        ("otp", &code),
        ("client_secret", "not-the-secret"),
    ]);
    let (status, _headers, resp) = challenge_full(&harness, &wrong, None, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a resume with a wrong secret is rejected: {resp}"
    );
    assert_eq!(json(&resp)["error"], "invalid_client");
}

#[tokio::test]
async fn a_public_client_still_works_with_no_client_auth_on_fresh_and_resume() {
    // AC3 (regression): a public `none` first-party client is UNCHANGED. It drives the fresh hop
    // and the resume hop with NO client-auth material (the parity gate is method-aware and skips
    // it), completing the step-up and minting the code exactly as before PR4.
    let (harness, client_id) = armed_mfa_harness().await;
    let auth_session = first_hop_auth_session(&harness, &client_id).await;

    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = totp_code(&harness);
    let (status, body) = challenge(
        &harness,
        &form(&[("auth_session", &auth_session), ("otp", &code)]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a public client resumes with no client-auth: {body}"
    );
    assert!(
        json(&body)["authorization_code"].as_str().is_some(),
        "a code for the public client: {body}"
    );
}

#[tokio::test]
async fn rapid_fresh_challenges_from_one_client_and_ip_are_rate_limited() {
    // AC4 (fresh cap): the thin L1 cap throttles fresh flow-creation spray keyed on the client and
    // resolved IP. The default regulation soft threshold is 5, so the 6th fresh request in the
    // window is a uniform 429 carrying the standard RateLimit headers (never an oracle). The first
    // five complete (a public client with correct credentials mints a code each time).
    let (harness, client_id) = armed_harness().await;
    let body = challenge_form(&client_id, IDENTIFIER, PASSWORD);
    for n in 1..=5 {
        let (status, _headers, resp) = challenge_full(&harness, &body, None, Some(CLEAN_IP)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "fresh request {n} is under the cap: {resp}"
        );
    }
    let (status, headers, resp) = challenge_full(&harness, &body, None, Some(CLEAN_IP)).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the 6th fresh request is capped: {resp}"
    );
    assert_eq!(json(&resp)["error"], "rate_limited");
    assert!(
        headers.get("ratelimit").is_some(),
        "the structured RateLimit header is stamped: {headers:?}"
    );
    assert!(
        headers.get("retry-after").is_some(),
        "the Retry-After header is stamped: {headers:?}"
    );
}

#[tokio::test]
async fn rapid_resumes_on_one_auth_session_are_rate_limited() {
    // AC4 (resume cap): rapid resume hammering on ONE auth_session is capped. The counter keys on
    // the STABLE flow_id (the handle rotates each hop, the flow_id does not), so every resume shares
    // one bucket regardless of the drive outcome; the 6th (past the soft threshold) is a uniform 429
    // with the RateLimit headers.
    let (harness, client_id) = armed_mfa_harness().await;
    let auth_session = first_hop_auth_session(&harness, &client_id).await;
    for _ in 1..=5 {
        let (status, _headers, _resp) = challenge_full(
            &harness,
            &form(&[("auth_session", &auth_session), ("otp", "000000")]),
            None,
            None,
        )
        .await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "a resume under the cap is not yet throttled"
        );
    }
    let (status, headers, resp) = challenge_full(
        &harness,
        &form(&[("auth_session", &auth_session), ("otp", "000000")]),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the 6th resume on one auth_session is capped: {resp}"
    );
    assert_eq!(json(&resp)["error"], "rate_limited");
    assert!(
        headers.get("ratelimit").is_some(),
        "the structured RateLimit header is stamped: {headers:?}"
    );
}

#[tokio::test]
async fn otp_brute_force_on_one_auth_session_is_bounded() {
    // AC5: OTP guessing on a single auth_session, following the rotating handle each hop, is BOUNDED
    // (the in-flow second-factor regulation and the L1 cap both refuse after the threshold). The
    // response is a uniform failure and NEVER a code.
    let (harness, client_id) = armed_mfa_harness().await;
    let mut handle = first_hop_auth_session(&harness, &client_id).await;
    let mut bounded = false;
    for _ in 0..12 {
        let (status, _headers, resp) = challenge_full(
            &harness,
            &form(&[("auth_session", &handle), ("otp", "000000")]),
            None,
            None,
        )
        .await;
        assert!(
            json(&resp)["authorization_code"].is_null(),
            "a wrong otp never mints a code: {resp}"
        );
        if status == StatusCode::TOO_MANY_REQUESTS {
            bounded = true;
            break;
        }
        if let Some(next) = json(&resp)["auth_session"].as_str() {
            handle = next.to_owned();
        }
    }
    assert!(
        bounded,
        "the otp brute force is bounded by a uniform throttle after the threshold"
    );
}

// ---------------------------------------------------------------------------------------------
// PR4 2-lens security review regressions (both live-confirmed, now fixed):
//  MEDIUM 1 - the malformed-credential 400 path fingerprinted a confidential client's type and
//             existence. FIXED by collapsing InvalidRequest into the uniform 401 invalid_client.
//  MEDIUM 2 - the resume rate-limit keyed purely on the cleartext flow_id let a forged-handle spray
//             lock a victim out of their own resume. FIXED by adding the resolved peer IP to the key.
// ---------------------------------------------------------------------------------------------

/// The JWT-bearer assertion type; presented WITHOUT an assertion it is a malformed client-auth
/// attempt that `parse_presented` maps to the seam's `InvalidRequest`, reached only when the parity
/// seam is CALLED (a confidential client).
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[tokio::test]
async fn a_malformed_credential_on_a_confidential_client_is_uniform_invalid_client() {
    // MEDIUM 1 (fixed): the SAME malformed body (a `client_assertion_type` with no assertion) sent
    // to a CONFIDENTIAL first-party client must now be BYTE-IDENTICAL to the response for an UNKNOWN
    // client (401 invalid_client, same body), so it cannot fingerprint that a client_id exists and
    // is confidential. It must NOT be the old 400 invalid_request, and it must NOT be distinguishable
    // from the unknown-client rejection.
    let (harness, conf_id, _secret) = armed_confidential_harness(ClientAuthMethod::Post).await;
    // A well-formed, in-scope, but NON-existent client id.
    let unknown_id = ClientId::generate(harness.env(), &harness.scope()).to_string();

    let malformed = |cid: &str| {
        form(&[
            ("client_id", cid),
            ("response_type", "code"),
            ("username", IDENTIFIER),
            ("password", PASSWORD),
            ("client_assertion_type", JWT_BEARER),
        ])
    };

    let (conf_status, _h, conf_body) =
        challenge_full(&harness, &malformed(&conf_id), None, None).await;
    let (unknown_status, _h, unknown_body) =
        challenge_full(&harness, &malformed(&unknown_id), None, None).await;

    // The confidential-malformed response is a uniform 401 invalid_client (NOT the old 400).
    assert_eq!(
        conf_status,
        StatusCode::UNAUTHORIZED,
        "a malformed credential on a confidential client is a uniform 401, not a 400: {conf_body}"
    );
    assert_eq!(json(&conf_body)["error"], "invalid_client");
    assert_ne!(
        json(&conf_body)["error"],
        "invalid_request",
        "the 400 invalid_request fingerprint is closed: {conf_body}"
    );
    // The fingerprint is closed: confidential-malformed is BYTE-IDENTICAL to unknown-client.
    assert_eq!(
        conf_status, unknown_status,
        "confidential-malformed shares the unknown-client status"
    );
    assert_eq!(
        conf_body, unknown_body,
        "confidential-malformed is byte-identical to unknown-client (no existence/type oracle): \
         conf={conf_body} unknown={unknown_body}"
    );
    assert!(
        json(&conf_body)["authorization_code"].is_null(),
        "a malformed credential mints nothing: {conf_body}"
    );
}

#[tokio::test]
async fn a_request_field_cannot_downgrade_a_confidential_client_to_public() {
    // The parity gate keys on the REGISTERED method, so no request field can coerce a confidential
    // client into the public `none` path (a confused-deputy downgrade). A confidential client with
    // NO secret plus fields naming `none` / an empty secret is still a uniform 401 invalid_client.
    let (harness, conf_id, _secret) = armed_confidential_harness(ClientAuthMethod::Post).await;
    let body = form(&[
        ("client_id", &conf_id),
        ("response_type", "code"),
        ("username", IDENTIFIER),
        ("password", PASSWORD),
        // Attempted downgrade vectors (all ignored: the method is the REGISTERED one).
        ("token_endpoint_auth_method", "none"),
        ("client_auth_method", "none"),
        ("auth_method", "none"),
        ("client_secret", ""),
    ]);
    let (status, _h, resp) = challenge_full(&harness, &body, None, None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a confidential client cannot be downgraded to public via a request field: {resp}"
    );
    assert_eq!(json(&resp)["error"], "invalid_client");
    assert!(json(&resp)["authorization_code"].is_null());
}

#[tokio::test]
async fn a_forged_handle_spray_does_not_lock_out_a_victims_resume() {
    // MEDIUM 2 (fixed): the resume rate-limit key now includes the resolved peer IP, so an attacker
    // who observed a victim's (un-MAC'd) handle and forges decodable handles (same cleartext
    // flow_id, garbage submit token) charges only the ATTACKER's {flow_id, attacker_ip} bucket. The
    // victim's own {flow_id, victim_ip} bucket is untouched, so the victim's genuine resume still
    // succeeds.
    const VICTIM_IP: &str = "198.51.100.7";
    const ATTACKER_IP: &str = "203.0.113.55";

    let (harness, client_id) = armed_mfa_harness().await;
    let victim_handle = first_hop_auth_session(&harness, &client_id).await;

    // The attacker recovers the stable flow_id in the clear (no MAC) and sprays forged handles from
    // its OWN IP, saturating its own bucket (soft threshold 5, so the 6th is a 429).
    let decoded = String::from_utf8(
        URL_SAFE_NO_PAD
            .decode(victim_handle.as_bytes())
            .expect("handle is plain base64url"),
    )
    .expect("utf8");
    let (flow_id, _submit) = decoded.rsplit_once('.').expect("flow_id.submit_token");
    let mut attacker_saw_429 = false;
    for i in 0..8 {
        let forged = forge_auth_session(flow_id, &format!("garbage-submit-{i}"));
        let (status, _h, body) = challenge_full(
            &harness,
            &form(&[("auth_session", &forged), ("otp", "000000")]),
            None,
            Some(ATTACKER_IP),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            attacker_saw_429 = true;
        }
        assert!(
            json(&body)["authorization_code"].is_null(),
            "a forged handle never mints a code: {body}"
        );
    }
    assert!(
        attacker_saw_429,
        "the attacker's own {{flow_id, attacker_ip}} bucket saturates"
    );

    // The VICTIM presents their genuine handle and a correct OTP from a DIFFERENT IP: their bucket
    // is untouched by the attacker's spray, so the resume succeeds and mints the code.
    harness.clock().advance(std::time::Duration::from_secs(90));
    let code = totp_code(&harness);
    let (victim_status, _h, victim_body) = challenge_full(
        &harness,
        &form(&[("auth_session", &victim_handle), ("otp", &code)]),
        None,
        Some(VICTIM_IP),
    )
    .await;
    assert_eq!(
        victim_status,
        StatusCode::OK,
        "the victim's legitimate resume is NOT locked out by the attacker's forged-handle spray: \
         {victim_body}"
    );
    assert!(
        json(&victim_body)["authorization_code"]
            .as_str()
            .is_some_and(|code| code.starts_with("ac_")),
        "the victim's resume mints the browserless code: {victim_body}"
    );
}
