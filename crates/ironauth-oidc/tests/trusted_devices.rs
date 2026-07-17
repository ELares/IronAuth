// SPDX-License-Identifier: MIT OR Apache-2.0

//! Trusted devices (remember-device 2FA) and the conditional-credential skip end to
//! end (issue #71), against a real Postgres.
//!
//! These pin the acceptance-critical crux the surveyed field does not ship:
//!
//! - a REMEMBERED device (a completed multi-factor login that remembered this browser)
//!   SKIPS the second factor on a subsequent login while STILL requiring primary
//!   authentication, and the token honestly records the trusted-device contribution
//!   (`acr` `mfa_remembered`, and `amr` that NEVER claims `mfa`/`otp` from the cookie
//!   alone);
//! - revocation takes effect SERVER-SIDE immediately: a replayed cookie after revocation
//!   FAILS (a server-side state check, not merely a signature);
//! - an explicit step-up `acr` floor (RFC 9470 / issue #72) ALWAYS overrides a remembered
//!   device: a step-up challenge is never satisfied by a trusted-device cookie;
//! - a device cookie for user A can never skip for user B (subject-bound);
//! - a TAMPERED cookie is rejected (the secret digest AND the server-side row are checked).

mod common;

use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location,
    location_param, named_cookie_pair,
};
use ironauth_config::OidcConfig;
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, base32_decode, code_at, verify};
use serde_json::{Value, json};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use std::time::{Duration, UNIX_EPOCH};

const ACR_MFA: &str = "urn:ironauth:acr:mfa";
const ACR_MFA_REMEMBERED: &str = "urn:ironauth:acr:mfa_remembered";
const TRUSTED_DEVICE_COOKIE: &str = "__Host-ironauth_trusted_device";

/// A harness with the remember-device feature ON (the tenant DECIDES, so a completed
/// multi-factor login always remembers the device) and TOTP enabled.
async fn harness() -> Harness {
    Harness::start_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        trusted_devices_enabled: true,
        // The tenant decides (no user checkbox), so a completed multi-factor login always
        // remembers the device; the user still sees and can revoke it.
        trusted_device_user_opt_in: false,
        ..OidcConfig::default()
    })
    .await
}

fn now_secs(h: &Harness) -> u64 {
    h.clock()
        .now_utc()
        .duration_since(UNIX_EPOCH)
        .expect("after epoch")
        .as_secs()
}

fn now_micros(h: &Harness) -> i64 {
    i64::try_from(now_secs(h)).expect("in range") * 1_000_000
}

fn authorize_query(client_id: &str, scope: &str, extra: &[&str]) -> String {
    let mut query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc(scope),
    );
    for fragment in extra {
        query.push('&');
        query.push_str(fragment);
    }
    query
}

fn token_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

async fn post_json(h: &Harness, path: &str, cookie: &str, body: &Value) -> (StatusCode, Value) {
    let (status, _headers, response) = h
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, cookie)
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let value = if response.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Value::Null)
    };
    (status, value)
}

/// Drive a TOTP enrollment to ACTIVE for `subject` and return the opened seed together
/// with the `tot_` credential id (so a test can later remove the factor).
async fn enroll_active_totp(h: &Harness, subject: &str) -> (Vec<u8>, String) {
    let scope = h.scope();
    let base = format!(
        "/t/{}/e/{}/account/mfa",
        scope.tenant(),
        scope.environment()
    );
    let (_id, cookie) = h.session_with_id(subject, "pwd", 0).await;
    let (status, begun) = post_json(h, &format!("{base}/totp/enroll"), &cookie, &json!({})).await;
    assert_eq!(status, StatusCode::CREATED, "enroll begin: {begun:?}");
    let credential_id = begun["credential_id"]
        .as_str()
        .expect("credential_id")
        .to_owned();
    let seed = base32_decode(begun["secret"].as_str().expect("secret")).expect("decode secret");
    let code = code_at(&seed, TotpParams::authenticator_default(), now_secs(h));
    let (status, activated) = post_json(
        h,
        &format!("{base}/totp/verify-enrollment"),
        &cookie,
        &json!({ "credential_id": credential_id, "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "activate: {activated:?}");
    (seed, credential_id)
}

/// Complete a full multi-factor login for `subject` from a fresh password session and
/// return the remember-device cookie the completed MFA planted. Mirrors the real flow:
/// a password session is challenged for the second factor (the tenant baseline MFA
/// floor), the TOTP is proven, and the device is remembered.
async fn login_and_remember(h: &Harness, subject: &str, seed: &[u8], client: &str) -> String {
    let cookie = h.session_cookie_at(subject, "pwd", now_micros(h)).await;
    let query = authorize_query(client, "openid", &[]);
    let (status, headers, body) = h.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let loc = location(&headers).expect("a Location");
    assert!(
        loc.starts_with("/login/mfa"),
        "the tenant baseline MFA floor challenges a pwd-only session, got {loc}"
    );
    let return_to = location_param(&headers, "return_to").expect("return_to");
    // Advance the clock a full TOTP period so the challenge code lands in a fresh
    // time-step distinct from the one the enrollment consumed (single-use anti-replay).
    h.clock().advance(Duration::from_secs(60));
    let code = code_at(seed, TotpParams::authenticator_default(), now_secs(h));
    let challenge = form(&[("code", &code), ("return_to", &return_to)]);
    let (status, headers, _) = h.post_form("/login/mfa", &challenge, Some(&cookie)).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the challenge upgrades the session"
    );
    named_cookie_pair(&headers, TRUSTED_DEVICE_COOKIE)
        .expect("a completed multi-factor login remembers the device")
}

/// The flagship acceptance test: on a remembered device WITHIN policy, a subsequent
/// login SKIPS the second factor, and the token HONESTLY records the trusted-device
/// path (acr `mfa_remembered`, amr with no fabricated `mfa`/`otp`).
#[tokio::test]
async fn a_remembered_device_skips_the_second_factor_and_the_token_is_honest() {
    let h = harness().await;
    let client = h.client_id().to_string();
    h.configure_client_policy(h.client_id(), "explicit", true, false, None)
        .await;
    h.set_tenant_min_class("mfa").await;
    let subject = h.seed_unique_user().await;
    let (seed, _) = enroll_active_totp(&h, &subject).await;

    // First login: a completed multi-factor login remembers the device.
    let device_cookie = login_and_remember(&h, &subject, &seed, &client).await;

    // A SUBSEQUENT login from the same device: a fresh password-only session PLUS the
    // remembered-device cookie. Primary authentication still happened (the password
    // session), but the second factor is SKIPPED, so a code is issued directly.
    let session = h.session_cookie_at(&subject, "pwd", now_micros(&h)).await;
    let combined = format!("{session}; {device_cookie}");
    let query = authorize_query(&client, "openid", &[]);
    let (status, headers, body) = h.authorize_with_cookie(&query, &combined).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "authorize with the remembered device: {body}"
    );
    let loc = location(&headers).expect("a Location");
    assert!(
        !loc.starts_with("/login/mfa"),
        "a remembered device must SKIP the second factor, got {loc}"
    );
    let code = location_param(&headers, "code").expect("a code (the second factor was skipped)");

    // The token honestly reflects the trusted-device path: acr `mfa_remembered` (distinct
    // from and weaker than a genuine `mfa`), and amr that carries ONLY the primary factor.
    let (status, _, body) = h.token(&token_form(&code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    let id_token = json(&body)["id_token"]
        .as_str()
        .expect("id_token")
        .to_owned();
    let verified =
        verify(&id_token, &h.policy(&client), &common::verify_clock()).expect("verifies");
    let claims = Value::Object(verified.claims().raw().clone());
    assert_eq!(
        claims["acr"],
        json!(ACR_MFA_REMEMBERED),
        "the remembered-device token carries the honest mfa_remembered acr"
    );
    let amr: Vec<&str> = claims["amr"]
        .as_array()
        .expect("amr")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        amr.contains(&"pwd"),
        "amr records the primary factor: {amr:?}"
    );
    assert!(
        !amr.contains(&"mfa") && !amr.contains(&"otp"),
        "a remembered-device login must NEVER claim mfa/otp from the cookie alone: {amr:?}"
    );
}

/// Revocation takes effect SERVER-SIDE immediately: after the user revokes the device, a
/// replayed cookie FAILS (the second factor is challenged again).
#[tokio::test]
async fn revocation_is_immediate_and_a_replayed_cookie_fails_server_side() {
    let h = harness().await;
    let client = h.client_id().to_string();
    h.configure_client_policy(h.client_id(), "explicit", true, false, None)
        .await;
    h.set_tenant_min_class("mfa").await;
    let subject = h.seed_unique_user().await;
    let (seed, _) = enroll_active_totp(&h, &subject).await;
    let device_cookie = login_and_remember(&h, &subject, &seed, &client).await;

    // The device appears in the account list, and the user revokes it.
    let account_cookie = h.session_cookie_at(&subject, "pwd", now_micros(&h)).await;
    let scope = h.scope();
    let base = format!(
        "/t/{}/e/{}/account/trusted-devices",
        scope.tenant(),
        scope.environment()
    );
    let (status, listed) = get_json(&h, &base, &account_cookie).await;
    assert_eq!(status, StatusCode::OK);
    let devices = listed["trusted_devices"].as_array().expect("devices");
    assert_eq!(
        devices.len(),
        1,
        "the remembered device appears in the M6 device list: {listed}"
    );
    let device_id = devices[0]["id"].as_str().expect("device id").to_owned();

    let (status, revoked) = post_json(
        &h,
        &format!("{base}/revoke"),
        &account_cookie,
        &json!({ "device_id": device_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "revoke: {revoked:?}");
    assert_eq!(revoked["revoked"], json!(true));

    // Replay the SAME device cookie after revocation: it FAILS server-side, so the second
    // factor is challenged again (not skipped by a still-valid signature).
    let session = h.session_cookie_at(&subject, "pwd", now_micros(&h)).await;
    let combined = format!("{session}; {device_cookie}");
    let (status, headers, _) = h
        .authorize_with_cookie(&authorize_query(&client, "openid", &[]), &combined)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location(&headers).expect("loc").starts_with("/login/mfa"),
        "a replayed cookie after revocation must FAIL (the second factor is challenged again)"
    );
}

/// An explicit step-up `acr` floor (RFC 9470 / issue #72) ALWAYS overrides a remembered
/// device: a scope that requires `mfa` is NOT satisfied by a trusted-device cookie.
#[tokio::test]
async fn a_step_up_acr_floor_overrides_a_remembered_device() {
    let h = harness().await;
    let client = h.client_id().to_string();
    h.configure_client_policy(h.client_id(), "explicit", true, false, None)
        .await;
    h.set_tenant_min_class("mfa").await;
    // payments:write additionally requires an EXPLICIT mfa acr floor (a step-up).
    h.set_scope_step_up_policy("payments:write", Some(ACR_MFA), None)
        .await;
    let subject = h.seed_unique_user().await;
    let (seed, _) = enroll_active_totp(&h, &subject).await;
    let device_cookie = login_and_remember(&h, &subject, &seed, &client).await;

    // The remembered device satisfies the tenant BASELINE mfa, but the EXPLICIT step-up
    // floor on payments:write is never satisfied by a cookie: the login is challenged.
    let session = h.session_cookie_at(&subject, "pwd", now_micros(&h)).await;
    let combined = format!("{session}; {device_cookie}");
    let query = authorize_query(&client, "openid payments:write", &[]);
    let (status, headers, _) = h.authorize_with_cookie(&query, &combined).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location(&headers).expect("loc").starts_with("/login/mfa"),
        "a step-up acr challenge must OVERRIDE a remembered device"
    );
}

/// A device cookie for user A can never skip for user B (subject-bound), and a TAMPERED
/// cookie is rejected (the secret digest and the server-side row are both checked).
#[tokio::test]
async fn a_stolen_or_tampered_device_cookie_does_not_skip() {
    let h = harness().await;
    let client = h.client_id().to_string();
    h.configure_client_policy(h.client_id(), "explicit", true, false, None)
        .await;
    h.set_tenant_min_class("mfa").await;
    let alice = h.seed_unique_user().await;
    let (seed, _) = enroll_active_totp(&h, &alice).await;
    let alice_device = login_and_remember(&h, &alice, &seed, &client).await;

    // Cross-account: Bob presents Alice's device cookie. It is subject-bound, so Bob is
    // still challenged for a second factor.
    let bob = h.seed_unique_user().await;
    let bob_session = h.session_cookie_at(&bob, "pwd", now_micros(&h)).await;
    let combined = format!("{bob_session}; {alice_device}");
    let (status, headers, _) = h
        .authorize_with_cookie(&authorize_query(&client, "openid", &[]), &combined)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location(&headers).expect("loc").starts_with("/login/mfa"),
        "a device cookie for user A must never skip for user B"
    );

    // Tampered: flip the last character of Alice's device secret, so its digest no longer
    // matches the stored row. Alice is challenged again (the secret digest is checked, not
    // just the signature).
    let mut tampered = alice_device.clone();
    let last = tampered.pop().unwrap_or('a');
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    let alice_session = h.session_cookie_at(&alice, "pwd", now_micros(&h)).await;
    let combined = format!("{alice_session}; {tampered}");
    let (status, headers, _) = h
        .authorize_with_cookie(&authorize_query(&client, "openid", &[]), &combined)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location(&headers).expect("loc").starts_with("/login/mfa"),
        "a tampered device cookie must be rejected server-side"
    );
}

/// A password change INVALIDATES the subject's remembered devices per tenant policy, so a
/// replayed cookie after the change fails and the second factor is challenged again.
#[tokio::test]
async fn a_password_change_invalidates_trusted_devices() {
    let h = harness().await;
    let client = h.client_id().to_string();
    h.configure_client_policy(h.client_id(), "explicit", true, false, None)
        .await;
    h.set_tenant_min_class("mfa").await;
    let identifier = format!("pwchange-{}@example.test", now_micros(&h));
    let subject = h
        .seed_user(&identifier, "correct horse battery staple")
        .await;
    let (seed, _) = enroll_active_totp(&h, &subject).await;
    let device_cookie = login_and_remember(&h, &subject, &seed, &client).await;

    // Change the password through the self-service surface.
    let account_cookie = h.session_cookie_at(&subject, "pwd", now_micros(&h)).await;
    let scope = h.scope();
    let path = format!(
        "/t/{}/e/{}/account/password",
        scope.tenant(),
        scope.environment()
    );
    let (status, changed) = post_json(
        &h,
        &path,
        &account_cookie,
        &json!({
            "current_password": "correct horse battery staple",
            "new_password": "an entirely different long passphrase 42",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "password change: {changed:?}");
    assert_eq!(
        changed["trusted_devices_revoked"],
        json!(1),
        "the change revokes the device"
    );

    // The remembered device no longer skips.
    let session = h.session_cookie_at(&subject, "pwd", now_micros(&h)).await;
    let combined = format!("{session}; {device_cookie}");
    let (status, headers, _) = h
        .authorize_with_cookie(&authorize_query(&client, "openid", &[]), &combined)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location(&headers).expect("loc").starts_with("/login/mfa"),
        "a password change must invalidate the remembered device"
    );
}

/// The account device list matches exactly what `validate` accepts (INFO-3, issue #71): a
/// device past its idle window but still within its absolute max-age is NOT shown as live,
/// because a subsequent skip attempt would be rejected.
#[tokio::test]
async fn the_account_list_hides_a_device_past_its_idle_window() {
    let h = harness().await;
    let client = h.client_id().to_string();
    h.configure_client_policy(h.client_id(), "explicit", true, false, None)
        .await;
    h.set_tenant_min_class("mfa").await;
    let subject = h.seed_unique_user().await;
    let (seed, _) = enroll_active_totp(&h, &subject).await;
    let _device_cookie = login_and_remember(&h, &subject, &seed, &client).await;

    let scope = h.scope();
    let base = format!(
        "/t/{}/e/{}/account/trusted-devices",
        scope.tenant(),
        scope.environment()
    );

    // Freshly remembered: the device is live and listed.
    let account_cookie = h.session_cookie_at(&subject, "pwd", now_micros(&h)).await;
    let (status, listed) = get_json(&h, &base, &account_cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        listed["trusted_devices"].as_array().expect("devices").len(),
        1,
        "the freshly remembered device is live: {listed}"
    );

    // Advance PAST the idle window (default 7 days) but WITHIN the absolute max-age
    // (default 30 days). The device is now idle-expired, so `validate` would reject it and
    // the account list must not report it as live.
    h.clock().advance(Duration::from_secs(8 * 24 * 60 * 60));
    let account_cookie = h.session_cookie_at(&subject, "pwd", now_micros(&h)).await;
    let (status, listed) = get_json(&h, &base, &account_cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        listed["trusted_devices"]
            .as_array()
            .expect("devices")
            .is_empty(),
        "a device past its idle window must not be listed as live: {listed}"
    );
}

/// Removing an MFA factor (here the subject's TOTP) INVALIDATES the subject's remembered
/// devices (reason `FactorChange`, issue #71), so a replayed cookie after the removal fails
/// and the second factor is challenged again.
#[tokio::test]
async fn an_mfa_factor_removal_invalidates_trusted_devices() {
    let h = harness().await;
    let client = h.client_id().to_string();
    h.configure_client_policy(h.client_id(), "explicit", true, false, None)
        .await;
    h.set_tenant_min_class("mfa").await;
    let subject = h.seed_unique_user().await;
    let (seed, totp_id) = enroll_active_totp(&h, &subject).await;
    let device_cookie = login_and_remember(&h, &subject, &seed, &client).await;

    // Remove the TOTP second factor through the self-service surface.
    let account_cookie = h.session_cookie_at(&subject, "pwd", now_micros(&h)).await;
    let scope = h.scope();
    let path = format!(
        "/t/{}/e/{}/account/mfa/totp/remove",
        scope.tenant(),
        scope.environment()
    );
    let (status, removed) = post_json(
        &h,
        &path,
        &account_cookie,
        &json!({ "credential_id": totp_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "totp remove: {removed:?}");
    assert_eq!(removed["removed"], json!(true), "the factor is removed");

    // The remembered device no longer skips: the replayed cookie fails server-side and the
    // second factor is challenged again.
    let session = h.session_cookie_at(&subject, "pwd", now_micros(&h)).await;
    let combined = format!("{session}; {device_cookie}");
    let (status, headers, _) = h
        .authorize_with_cookie(&authorize_query(&client, "openid", &[]), &combined)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location(&headers).expect("loc").starts_with("/login/mfa"),
        "an MFA factor removal must invalidate the remembered device"
    );
}

async fn get_json(h: &Harness, path: &str, cookie: &str) -> (StatusCode, Value) {
    let (status, _headers, body) = h.get_with_cookie(path, Some(cookie)).await;
    let value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body).unwrap_or(Value::Null)
    };
    (status, value)
}
