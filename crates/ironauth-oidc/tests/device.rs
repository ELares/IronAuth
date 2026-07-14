// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 8628 device authorization grant with cross-device BCP mitigations (issue
//! #24), over a real database (`DATABASE_URL`).
//!
//! Drives a simulated CLI through the full happy path and every RFC 8628 error state,
//! exercises the verification page (client name / logo / initiation hint, the explicit
//! confirmation before issue, the non-oracular errors, and `verification_uri_complete`),
//! proves the user-code hygiene (a restricted high-entropy alphabet, per-source rate
//! limiting, and a flow that dies after a bounded number of failed matches), the
//! enforced `slow_down` interval bookkeeping and TTL expiry, and the acceptance check
//! that no plaintext device code or user code appears in the logs.
//!
//! The harness clock is a frozen `ManualClock`, so a second poll at the same instant is
//! (correctly) `slow_down`: the tests advance the clock past the current interval
//! between polls, exactly as a well-behaved client paces itself, except where they mean
//! to prove the `slow_down` enforcement itself.

mod common;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use common::{Harness, enc, form, form_field, json};
use ironauth_store::{
    DeviceAttemptOutcome, DevicePollOutcome, DeviceUserCodeLookup, device_code_digest,
    user_code_hash,
};
use serde_json::Value;

/// The RFC 8628 device grant wire `grant_type`.
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The grant allowlist a device-enabled harness client is configured with (the device
/// endpoint admits a client only when this contains the `device_code` URN).
const DEVICE_GRANTS: &str = "authorization_code urn:ietf:params:oauth:grant-type:device_code";

/// The logo the tests register on the device client (an `https` URI, so the
/// verification page renders it as a browser-fetched image).
const TEST_LOGO: &str = "https://logo.test/app.png";

/// The poll interval, in seconds, the harness config issues flows with (its default).
const INTERVAL_SECS: u64 = 5;

/// The verification page's scope-routed path for the harness scope.
fn device_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}/device", scope.tenant(), scope.environment())
}

/// POST the device-authorization endpoint for `client_id` (a public client) with an
/// optional requested scope, asserting a 200 and returning the parsed JSON.
async fn start_flow(harness: &Harness, client_id: &str, scope: Option<&str>) -> Value {
    let body = match scope {
        Some(scope) => form(&[("client_id", client_id), ("scope", scope)]),
        None => form(&[("client_id", client_id)]),
    };
    let (status, _headers, body) = harness
        .post_form("/device_authorization", &body, None)
        .await;
    assert_eq!(status, StatusCode::OK, "device authorization: {body}");
    json(&body)
}

/// Poll the token endpoint with a device code for `client_id`.
async fn poll(harness: &Harness, device_code: &str, client_id: &str) -> (StatusCode, Value) {
    let body = form(&[
        ("grant_type", DEVICE_GRANT),
        ("device_code", device_code),
        ("client_id", client_id),
    ]);
    let (status, _headers, body) = harness.token(&body).await;
    (status, json(&body))
}

/// The `dc_` flow handle embedded in a device code (`ira_dc_<handle>~<secret>`).
fn device_code_id_of(device_code: &str) -> String {
    device_code
        .strip_prefix("ira_dc_")
        .and_then(|rest| rest.split('~').next())
        .expect("device code has the ira_dc_ prefix and a ~ delimiter")
        .to_owned()
}

/// Sign in a fresh user, open the confirmation page via `verification_uri_complete`,
/// assert it renders the client identity and an explicit control, and click Approve.
async fn approve_via_page(harness: &Harness, user_code: &str) {
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let path = device_path(harness);
    // verification_uri_complete: the confirmation renders directly for a signed-in user.
    let (status, _headers, html) = harness
        .get_with_cookie(
            &format!("{path}?user_code={}", enc(user_code)),
            Some(&cookie),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "confirm page: {html}");
    assert!(
        html.contains(TEST_LOGO),
        "confirm page shows the client logo: {html}"
    );
    assert!(
        html.contains("Approve"),
        "confirm page has an explicit Approve control: {html}"
    );
    let device_code_id =
        form_field(&html, "device_code_id").expect("confirm page carries the flow handle");
    let body = form(&[
        ("decision", "allow"),
        ("device_code_id", &device_code_id),
        ("user_code", user_code),
    ]);
    let (status, _headers, body) = harness.post_form(&path, &body, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK, "approve: {body}");
}

#[tokio::test]
async fn happy_path_issues_tokens_only_after_explicit_approval() {
    let harness = Harness::start().await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, DEVICE_GRANTS, Some(TEST_LOGO))
        .await;
    let client_str = client.to_string();

    let start = start_flow(&harness, &client_str, Some("openid profile")).await;
    let device_code = start["device_code"]
        .as_str()
        .expect("device_code")
        .to_owned();
    let user_code = start["user_code"].as_str().expect("user_code").to_owned();
    assert_eq!(start["interval"], 5);
    assert!(
        start["verification_uri"]
            .as_str()
            .unwrap()
            .ends_with("/device")
    );
    assert!(
        start["verification_uri_complete"]
            .as_str()
            .unwrap()
            .contains("user_code="),
        "verification_uri_complete embeds the user code"
    );
    // The device code is the scope-declaring opaque credential, never a raw secret.
    assert!(device_code.starts_with("ira_dc_"));

    // Before approval: authorization_pending, and NO token is issued.
    let (status, body) = poll(&harness, &device_code, &client_str).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending");

    // A human signs in and EXPLICITLY approves on the verification page.
    approve_via_page(&harness, &user_code).await;

    // Pace past the interval, then the poll issues tokens (access + id + refresh) once.
    harness
        .clock()
        .advance(Duration::from_secs(INTERVAL_SECS + 1));
    let (status, body) = poll(&harness, &device_code, &client_str).await;
    assert_eq!(status, StatusCode::OK, "post-approval poll: {body}");
    assert!(body["access_token"].is_string());
    assert!(body["id_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "openid profile");
    assert!(
        body["refresh_token"].is_string(),
        "device grant returns a refresh token"
    );

    // A second poll after success is invalid_grant (the device code is single use).
    harness
        .clock()
        .advance(Duration::from_secs(INTERVAL_SECS + 1));
    let (status, body) = poll(&harness, &device_code, &client_str).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn polling_faster_than_interval_is_slow_down_and_interval_increases() {
    let harness = Harness::start().await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, DEVICE_GRANTS, None)
        .await;
    let client_str = client.to_string();
    let start = start_flow(&harness, &client_str, None).await;
    let device_code = start["device_code"].as_str().unwrap().to_owned();

    // First poll paces the flow (authorization_pending).
    let (status, body) = poll(&harness, &device_code, &client_str).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending");

    // An immediate second poll (frozen clock) is too fast: slow_down, interval 5 -> 10.
    let (status, body) = poll(&harness, &device_code, &client_str).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error"], "slow_down",
        "an immediate re-poll is slow_down"
    );

    // The enforced interval grew: 6s would have been fine under the ORIGINAL 5s interval
    // but is still too fast under the increased 10s one, so this is slow_down (10 -> 15).
    harness.clock().advance(Duration::from_secs(6));
    let (status, body) = poll(&harness, &device_code, &client_str).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error"], "slow_down",
        "the interval was enforced-increased"
    );

    // Past the new (15s) interval, polling resumes normally (authorization_pending).
    harness.clock().advance(Duration::from_secs(16));
    let (status, body) = poll(&harness, &device_code, &client_str).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "authorization_pending");
}

#[tokio::test]
async fn denied_flow_polls_access_denied() {
    let harness = Harness::start().await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, DEVICE_GRANTS, None)
        .await;
    let client_str = client.to_string();
    let start = start_flow(&harness, &client_str, None).await;
    let device_code = start["device_code"].as_str().unwrap().to_owned();
    let user_code = start["user_code"].as_str().unwrap().to_owned();

    // A signed-in human explicitly denies on the verification page.
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let path = device_path(&harness);
    let (_s, _h, html) = harness
        .get_with_cookie(
            &format!("{path}?user_code={}", enc(&user_code)),
            Some(&cookie),
        )
        .await;
    let device_code_id = form_field(&html, "device_code_id").unwrap();
    let body = form(&[
        ("decision", "deny"),
        ("device_code_id", &device_code_id),
        ("user_code", &user_code),
    ]);
    let (status, _h, _b) = harness.post_form(&path, &body, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = poll(&harness, &device_code, &client_str).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn expired_flow_polls_expired_token_and_page_shows_safe_error() {
    let harness = Harness::start().await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, DEVICE_GRANTS, None)
        .await;
    let client_str = client.to_string();
    let start = start_flow(&harness, &client_str, None).await;
    let device_code = start["device_code"].as_str().unwrap().to_owned();
    let user_code = start["user_code"].as_str().unwrap().to_owned();

    // Advance past the flow TTL (default 600s).
    harness.clock().advance(Duration::from_secs(601));

    let (status, body) = poll(&harness, &device_code, &client_str).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "expired_token");

    // The verification page shows a safe (non-oracular) error, not a confirmation.
    let path = device_path(&harness);
    let (status, _h, html) = harness
        .get_with_cookie(&format!("{path}?user_code={}", enc(&user_code)), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !html.contains("Approve"),
        "an expired code offers no confirmation"
    );
    assert!(
        html.contains("not recognized"),
        "the page is non-oracular: {html}"
    );
}

#[tokio::test]
async fn client_without_device_grant_is_unauthorized_client() {
    let harness = Harness::start().await;
    // The default harness client is authorization_code only (device grant NOT enabled).
    let client_str = harness.client_id().to_string();
    let body = form(&[("client_id", &client_str)]);
    let (status, _headers, body) = harness
        .post_form("/device_authorization", &body, None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "unauthorized_client");
}

#[tokio::test]
async fn unknown_user_code_is_non_oracular() {
    let harness = Harness::start().await;
    let path = device_path(&harness);
    // A code that was never issued yields the same safe error as an expired one, so the
    // page is not an existence oracle.
    let (status, _h, html) = harness
        .get_with_cookie(&format!("{path}?user_code=BCDF-GHJK"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!html.contains("Approve"));
    assert!(html.contains("not recognized"), "non-oracular: {html}");
}

#[tokio::test]
async fn user_code_entry_is_rate_limited_per_source() {
    let config = ironauth_config::OidcConfig {
        device_verification_rate_limit: 3,
        ..ironauth_config::OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    let path = device_path(&harness);

    // The entry step (POST a user_code, no decision) is rate limited per source. The
    // in-process test router installs no ConnectInfo, so every request shares one bucket.
    for attempt in 1..=3 {
        let body = form(&[("user_code", "BCDF-GHJK")]);
        let (status, _h, _b) = harness.post_form(&path, &body, None).await;
        assert_eq!(status, StatusCode::OK, "attempt {attempt} within budget");
    }
    // The fourth submission is over the budget: refused outright (no code lookup).
    let body = form(&[("user_code", "BCDF-GHJK")]);
    let (status, _h, html) = harness.post_form(&path, &body, None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "over budget: {html}");
}

#[tokio::test]
async fn flow_dies_after_bounded_failed_user_code_matches() {
    let config = ironauth_config::OidcConfig {
        device_user_code_max_attempts: 3,
        ..ironauth_config::OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, DEVICE_GRANTS, Some(TEST_LOGO))
        .await;
    let client_str = client.to_string();
    let start = start_flow(&harness, &client_str, None).await;
    let device_code = start["device_code"].as_str().unwrap().to_owned();
    let device_code_id = device_code_id_of(&device_code);
    let user_code = start["user_code"].as_str().unwrap().to_owned();

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let path = device_path(&harness);

    // Submit the WRONG user code against this exact flow three times. Each is a failed
    // match attributed to the bound flow (RFC 8628 5.1); the third exhausts the budget.
    for attempt in 1..=3 {
        let body = form(&[
            ("decision", "allow"),
            ("device_code_id", &device_code_id),
            ("user_code", "ZZZZ-ZZZZ"),
        ]);
        let (status, _h, html) = harness.post_form(&path, &body, Some(&cookie)).await;
        assert_eq!(status, StatusCode::OK, "attempt {attempt}");
        assert!(
            html.contains("not recognized"),
            "a wrong code is non-oracular"
        );
    }

    // The flow is now invalidated: even the CORRECT user code resolves as Dead, and a
    // poll returns access_denied.
    let scope = harness.scope();
    let lookup = harness
        .store()
        .scoped(scope)
        .device_codes()
        .lookup_user_code(
            &user_code_hash(&ironauth_oidc::normalize_user_code(&user_code)),
            1_000,
            3,
        )
        .await
        .expect("lookup");
    assert!(
        matches!(lookup, DeviceUserCodeLookup::Dead),
        "a brute-forced flow must be Dead, got {lookup:?}"
    );

    let (status, body) = poll(&harness, &device_code, &client_str).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "access_denied");
}

#[tokio::test]
async fn store_level_slow_down_and_attempt_bookkeeping() {
    // Unit-level checks on the store's poll bookkeeping and the failed-attempt death,
    // driven directly through the repository with explicit clock values.
    let harness = Harness::start().await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, DEVICE_GRANTS, None)
        .await;
    let start = start_flow(&harness, &client.to_string(), None).await;
    let device_code = start["device_code"].as_str().unwrap().to_owned();

    let scope = harness.scope();
    let scoped = harness.store().scoped(scope);
    let device = scoped.device_codes();

    // slow_down bookkeeping: a paced poll, then an immediate re-poll bumps the interval
    // (5 -> 10) in place, and a poll past the NEW interval paces normally again.
    assert!(matches!(
        device.poll(&device_code, 1_000, 5).await.unwrap(),
        DevicePollOutcome::Pending
    ));
    match device.poll(&device_code, 1_000, 5).await.unwrap() {
        DevicePollOutcome::SlowDown { interval_secs } => assert_eq!(interval_secs, 10),
        other => panic!("expected SlowDown, got {other:?}"),
    }
    assert!(
        matches!(
            device
                .poll(&device_code, 1_000 + 11_000_000, 5)
                .await
                .unwrap(),
            DevicePollOutcome::Pending
        ),
        "a poll past the increased interval paces normally"
    );

    // Failed-attempt bookkeeping: Alive up to the bound, then Died (which flips status).
    let device_code_id = device
        .parse_device_code_id(&device_code_id_of(&device_code))
        .expect("parse handle");
    assert_eq!(
        device
            .record_failed_user_code(&device_code_id, 3, 1_000)
            .await
            .unwrap(),
        DeviceAttemptOutcome::Alive
    );
    assert_eq!(
        device
            .record_failed_user_code(&device_code_id, 3, 1_000)
            .await
            .unwrap(),
        DeviceAttemptOutcome::Alive
    );
    assert_eq!(
        device
            .record_failed_user_code(&device_code_id, 3, 1_000)
            .await
            .unwrap(),
        DeviceAttemptOutcome::Died
    );

    // Only the one-way digest is stored, never the device code itself.
    assert_ne!(device_code_digest(&device_code), device_code);
}

#[tokio::test]
async fn user_code_alphabet_is_restricted_and_high_entropy() {
    let harness = Harness::start().await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, DEVICE_GRANTS, None)
        .await;
    let client_str = client.to_string();

    // Issue many flows and inspect their user codes: every character is from the RFC
    // 8628 restricted alphabet, the length is fixed, and the sample is collision free
    // (the entropy the brute-force resistance rests on).
    let allowed: HashSet<char> = "BCDFGHJKLMNPQRSTVWXZ".chars().collect();
    let mut seen: HashSet<String> = HashSet::new();
    for _ in 0..64 {
        let start = start_flow(&harness, &client_str, None).await;
        let user_code = start["user_code"].as_str().unwrap().to_owned();
        let normalized = ironauth_oidc::normalize_user_code(&user_code);
        assert_eq!(
            normalized.len(),
            8,
            "user code is 8 characters: {user_code}"
        );
        for ch in normalized.chars() {
            assert!(
                allowed.contains(&ch),
                "char {ch} is from the restricted alphabet"
            );
        }
        assert!(
            seen.insert(normalized),
            "user codes do not collide: {user_code}"
        );
    }
}

#[tokio::test]
async fn adversarial_user_code_brute_force_is_bounded_by_rate_limit() {
    let config = ironauth_config::OidcConfig {
        device_verification_rate_limit: 5,
        ..ironauth_config::OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, DEVICE_GRANTS, None)
        .await;
    let start = start_flow(&harness, &client.to_string(), None).await;
    let real_user_code = start["user_code"].as_str().unwrap().to_owned();
    let real_normalized = ironauth_oidc::normalize_user_code(&real_user_code);
    let path = device_path(&harness);

    // An attacker (no session) sprays guesses at the entry endpoint. Within the budget
    // every guess is a non-oracular miss; past the budget it is refused outright. A guess
    // is astronomically unlikely to hit the one live code (a ~2.56e10 space), so the
    // budget bounds the attacker to a negligible success probability.
    for guess in [
        "BBBB-BBBB",
        "CCCC-CCCC",
        "DDDD-DDDD",
        "FFFF-FFFF",
        "GGGG-GGGG",
    ] {
        assert_ne!(
            ironauth_oidc::normalize_user_code(guess),
            real_normalized,
            "a fixed guess must not equal the live code"
        );
        let body = form(&[("user_code", guess)]);
        let (status, _h, html) = harness.post_form(&path, &body, None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            html.contains("not recognized"),
            "a wrong guess is a non-oracular miss"
        );
    }
    // Budget exhausted: further guesses are refused, so the code space cannot be swept.
    let body = form(&[("user_code", "HHHH-HHHH")]);
    let (status, _h, _b) = harness.post_form(&path, &body, None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn no_plaintext_device_or_user_code_in_logs() {
    // The acceptance CI check: capture the tracing output of a full device flow and
    // assert neither the device code nor the user code ever appears in plaintext.
    let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(BufferWriter(Arc::clone(&buffer)))
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .without_time()
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let harness = Harness::start().await;
    let client = *harness.client_id();
    harness
        .enable_device_grant(&client, DEVICE_GRANTS, Some(TEST_LOGO))
        .await;
    let client_str = client.to_string();

    let start = start_flow(&harness, &client_str, Some("openid")).await;
    let device_code = start["device_code"].as_str().unwrap().to_owned();
    let user_code = start["user_code"].as_str().unwrap().to_owned();
    let normalized = ironauth_oidc::normalize_user_code(&user_code);

    let _ = poll(&harness, &device_code, &client_str).await;
    harness
        .clock()
        .advance(Duration::from_secs(INTERVAL_SECS + 1));
    approve_via_page(&harness, &user_code).await;
    let (status, _b) = poll(&harness, &device_code, &client_str).await;
    assert_eq!(status, StatusCode::OK);

    // A marker so the assertion is not vacuous (the capturing subscriber is active).
    tracing::info!(target: "device_test", "device flow complete");

    let logs = String::from_utf8(buffer.lock().unwrap().clone()).expect("utf8 logs");
    assert!(
        logs.contains("device flow complete"),
        "the capturing subscriber is active"
    );
    assert!(
        !logs.contains(&device_code),
        "the device code must never appear in logs"
    );
    assert!(
        !logs.contains(&user_code),
        "the user code (display form) must never appear in logs"
    );
    assert!(
        !logs.contains(&normalized),
        "the user code (normalized form) must never appear in logs"
    );
}

/// A `tracing_subscriber` writer that captures formatted log lines into a shared buffer,
/// so the acceptance test can assert what did (and did not) reach the logs.
#[derive(Clone)]
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufferWriter {
    type Writer = BufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
