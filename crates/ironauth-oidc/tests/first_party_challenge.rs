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
use common::{Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, form, json};
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, code_at};
use ironauth_oidc::ClientAuthMethod;

/// The identifier and password the suite's first-party user is seeded with.
const IDENTIFIER: &str = "native@example.test";
const PASSWORD: &str = "correct horse battery staple";
/// The TOTP seed the harness `seed_active_totp` enrolls, so a real code is reproducible.
const TOTP_SEED: [u8; 20] = [0x0A; 20];

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
    assert!(
        json(&response)["id_token"].is_string(),
        "an id token: {response}"
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
