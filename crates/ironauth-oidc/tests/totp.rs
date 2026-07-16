// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TOTP second-factor and recovery-code HTTP surface (issue #69), against a
//! real Postgres.
//!
//! The store tests pin the data-model invariants; these pin the end-to-end flow an
//! authenticated end user experiences:
//!
//! - enrollment activates ONLY after a valid current code; a wrong code leaves the
//!   factor pending (no active factor), and a valid code activates it and returns
//!   the one-time recovery codes;
//! - a verified code is single-use: replaying it is the uniform invalid-code error;
//! - a recovery code is usable IN PLACE OF the second factor, single-use;
//! - the per-tenant factor order demonstrably changes the orchestration plan across
//!   two deployment configs;
//! - the endpoints fail closed with a 404 when TOTP is disabled.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_config::OidcConfig;
use ironauth_env::Clock;
use ironauth_jose::{TotpParams, base32_decode, code_at};
use serde_json::{Value, json};
use std::time::{Duration, UNIX_EPOCH};

fn base(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/account/mfa",
        scope.tenant(),
        scope.environment()
    )
}

async fn post_json(
    harness: &Harness,
    path: &str,
    cookie: &str,
    body: &Value,
) -> (StatusCode, Value) {
    let (status, _headers, response) = harness
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
    (status, parse(&response))
}

async fn get(harness: &Harness, path: &str, cookie: &str) -> (StatusCode, Value) {
    let (status, _headers, response) = harness
        .send(
            Request::builder()
                .method("GET")
                .uri(path)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await;
    (status, parse(&response))
}

fn parse(body: &str) -> Value {
    if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body).unwrap_or(Value::Null)
    }
}

/// The current whole-second Unix time on the harness's deterministic clock.
fn now_secs(harness: &Harness) -> u64 {
    harness
        .clock()
        .now_utc()
        .duration_since(UNIX_EPOCH)
        .expect("after epoch")
        .as_secs()
}

/// Drive an enrollment to ACTIVE and return the cookie, the recovery codes, and the
/// opened seed (captured from the provisioning secret) so a test can compute a fresh
/// code at a later clock time.
async fn enroll_active(harness: &Harness, subject: &str) -> EnrolledFactor {
    let (_id, cookie) = harness.session_with_id(subject, "pwd", 0).await;
    let base = base(harness);

    let (status, begun) =
        post_json(harness, &format!("{base}/totp/enroll"), &cookie, &json!({})).await;
    assert_eq!(status, StatusCode::CREATED, "enroll begin: {begun:?}");
    let credential_id = begun["credential_id"]
        .as_str()
        .expect("credential_id")
        .to_owned();
    let secret = begun["secret"].as_str().expect("secret");
    let seed = base32_decode(secret).expect("decode secret");

    // A WRONG code does NOT activate the factor (an abandoned enrollment).
    let (status, _) = post_json(
        harness,
        &format!("{base}/totp/verify-enrollment"),
        &cookie,
        &json!({ "credential_id": credential_id, "code": "000001" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a wrong code must not activate"
    );

    // The VALID current code activates the factor and returns the recovery codes.
    let code = code_at(
        &seed,
        TotpParams::authenticator_default(),
        now_secs(harness),
    );
    let (status, activated) = post_json(
        harness,
        &format!("{base}/totp/verify-enrollment"),
        &cookie,
        &json!({ "credential_id": credential_id, "code": code }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "valid code activates: {activated:?}"
    );
    assert_eq!(activated["activated"], json!(true));
    let recovery: Vec<String> = activated["recovery_codes"]
        .as_array()
        .expect("recovery codes")
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(recovery.len(), 10, "the default recovery-code count");
    EnrolledFactor {
        cookie,
        recovery,
        seed,
    }
}

/// The result of driving an enrollment to active.
struct EnrolledFactor {
    cookie: String,
    recovery: Vec<String>,
    seed: Vec<u8>,
}

#[tokio::test]
async fn enrollment_requires_a_valid_code_then_activates() {
    let harness = Harness::start().await;
    let subject = harness
        .seed_user("ada@example.test", "correct horse battery")
        .await;
    let factor = enroll_active(&harness, &subject).await;
    let cookie = factor.cookie;
    // The active factor now shows up in the credential list as a TOTP factor.
    let scope = harness.scope();
    let (status, creds) = get(
        &harness,
        &format!(
            "/t/{}/e/{}/account/credentials",
            scope.tenant(),
            scope.environment()
        ),
        &cookie,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let has_active_totp = creds["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["type"] == "totp" && c["status"] == "active");
    assert!(has_active_totp, "the activated factor is listed: {creds:?}");
}

#[tokio::test]
async fn a_verified_code_is_single_use_and_a_replay_is_rejected() {
    let harness = Harness::start().await;
    let subject = harness
        .seed_user("bob@example.test", "correct horse battery")
        .await;
    let factor = enroll_active(&harness, &subject).await;
    let cookie = factor.cookie;
    let base = base(&harness);

    // Advance one period so the second-factor verify uses a FRESH code (the code that
    // activated the factor already consumed its step).
    harness.clock().advance(Duration::from_secs(30));
    let code = code_at(
        &factor.seed,
        TotpParams::authenticator_default(),
        now_secs(&harness),
    );

    // The fresh code verifies as a second factor with an honest amr.
    let (status, body) = post_json(
        &harness,
        &format!("{base}/totp/verify"),
        &cookie,
        &json!({ "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a fresh code verifies: {body:?}");
    assert_eq!(body["amr"], json!(["otp", "mfa"]));

    // Replaying the SAME code is refused with the uniform invalid-code response
    // (single-use is a hard store invariant).
    let (status, body) = post_json(
        &harness,
        &format!("{base}/totp/verify"),
        &cookie,
        &json!({ "code": code }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a replay is refused: {body:?}"
    );
    assert_eq!(body["error"], json!("invalid_code"));

    // A wrong code is likewise the uniform invalid-code response.
    let (status, _) = post_json(
        &harness,
        &format!("{base}/totp/verify"),
        &cookie,
        &json!({ "code": "000002" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_recovery_code_is_usable_in_place_of_the_second_factor_and_single_use() {
    let harness = Harness::start().await;
    let subject = harness
        .seed_user("carol@example.test", "correct horse battery")
        .await;
    let factor = enroll_active(&harness, &subject).await;
    let cookie = factor.cookie;
    let recovery = factor.recovery;
    let base = base(&harness);
    let code = recovery[0].clone();

    // Redeem a recovery code IN PLACE OF the second factor.
    let (status, body) = post_json(
        &harness,
        &format!("{base}/recovery-codes/redeem"),
        &cookie,
        &json!({ "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "recovery redeem: {body:?}");
    assert_eq!(body["redeemed"], json!(true));
    assert_eq!(body["recovery_codes_remaining"], json!(9));
    assert_eq!(body["amr"], json!(["kba", "mfa"]));

    // The SAME code cannot be redeemed twice (single-use).
    let (status, body) = post_json(
        &harness,
        &format!("{base}/recovery-codes/redeem"),
        &cookie,
        &json!({ "code": code }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a spent code is refused: {body:?}"
    );
}

#[tokio::test]
async fn regeneration_invalidates_prior_recovery_codes() {
    let harness = Harness::start().await;
    let subject = harness
        .seed_user("dave@example.test", "correct horse battery")
        .await;
    let factor = enroll_active(&harness, &subject).await;
    let cookie = factor.cookie;
    let recovery = factor.recovery;
    let base = base(&harness);

    // Regenerate the set: the prior codes are invalidated.
    let (status, body) = post_json(
        &harness,
        &format!("{base}/recovery-codes"),
        &cookie,
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "regenerate: {body:?}");
    let fresh: Vec<String> = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(fresh.len(), 10);
    assert_ne!(fresh[0], recovery[0], "a regenerated set is fresh");

    // A code from the OLD set no longer redeems.
    let (status, _) = post_json(
        &harness,
        &format!("{base}/recovery-codes/redeem"),
        &cookie,
        &json!({ "code": recovery[0] }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a prior code is invalidated"
    );
    // A code from the NEW set does redeem.
    let (status, _) = post_json(
        &harness,
        &format!("{base}/recovery-codes/redeem"),
        &cookie,
        &json!({ "code": fresh[0] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a fresh code redeems");
}

#[tokio::test]
async fn per_tenant_factor_order_changes_the_orchestration_plan() {
    // Two deployment configs with OPPOSITE factor orders demonstrably produce
    // opposite plans (the per-tenant orchestration the acceptance criteria require).
    let passkey_first = Harness::start_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        mfa_factor_order: vec!["passkey".to_owned(), "totp".to_owned()],
        ..OidcConfig::default()
    })
    .await;
    let totp_first = Harness::start_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        mfa_factor_order: vec!["totp".to_owned(), "passkey".to_owned()],
        ..OidcConfig::default()
    })
    .await;

    for (harness, expected) in [
        (&passkey_first, vec!["passkey", "totp"]),
        (&totp_first, vec!["totp", "passkey"]),
    ] {
        let subject = harness
            .seed_user("erin@example.test", "correct horse battery")
            .await;
        let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
        let (status, plan) = get(harness, &format!("{}/plan", base(harness)), &cookie).await;
        assert_eq!(status, StatusCode::OK, "plan: {plan:?}");
        let order: Vec<&str> = plan["factors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["factor"].as_str().unwrap())
            .collect();
        assert_eq!(
            order, expected,
            "the plan honors the per-tenant factor order"
        );
    }
}

#[tokio::test]
async fn the_endpoints_fail_closed_when_totp_is_disabled() {
    let harness = Harness::start_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        totp_enabled: false,
        ..OidcConfig::default()
    })
    .await;
    let subject = harness
        .seed_user("frank@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let (status, _) = post_json(
        &harness,
        &format!("{}/totp/enroll", base(&harness)),
        &cookie,
        &json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a disabled deployment exposes no surface"
    );
}
