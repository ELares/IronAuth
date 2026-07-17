// SPDX-License-Identifier: MIT OR Apache-2.0

//! The minimal risk engine end to end (issue #79), against a real Postgres.
//!
//! These pin the acceptance-critical behavior the surveyed open-source field does not
//! ship free:
//!
//! - a policy "require MFA at MED or above" FORCES step-up when a MED signal fires, and
//!   NOT at LOW (the score feeds the #72 step-up seam);
//! - every decision record enumerates its contributing signals and is reconstructable
//!   from the audit trail;
//! - a new-device login triggers a notification with device/UA/geo context, and the
//!   "this wasn't me" path revokes the sessions and marks the credentials for review;
//! - a BLOCK action returns a response indistinguishable from an ordinary login failure;
//! - the engine runs with ZERO IronCache and ZERO third-party services (null providers);
//! - each signal is driven (new device, impossible travel, velocity flood, IP deny).

mod common;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, PKCE_CHALLENGE, REDIRECT_URI, form, location, set_cookie_pair};
use ironauth_config::OidcConfig;
use ironauth_oidc::{
    GeoIpProvider, GeoLocation, IpReputation, IpReputationProvider, NewDeviceNotice,
    VerificationPurpose, VerificationSender,
};

/// A recording verification sender that captures the new-device notifications delivered
/// through the seam (owned copies, since the message borrows).
#[derive(Debug, Default)]
struct RecordingSender {
    notices: Mutex<Vec<NewDeviceRecord>>,
}

#[derive(Debug, Clone)]
struct NewDeviceRecord {
    recipient: String,
    user_agent: String,
    location_hint: String,
    disavowal_link: String,
}

impl VerificationSender for RecordingSender {
    fn send(&self, _scope: ironauth_store::Scope, _purpose: VerificationPurpose, _recipient: &str) {
    }

    fn deliver_new_device_notice(&self, message: &NewDeviceNotice<'_>) {
        self.notices.lock().expect("lock").push(NewDeviceRecord {
            recipient: message.recipient.to_owned(),
            user_agent: message.user_agent.to_owned(),
            location_hint: message.location_hint.to_owned(),
            disavowal_link: message.disavowal_link.to_owned(),
        });
    }
}

/// A fixture `GeoIP` provider that maps two test IPs to two far-apart coordinates (San
/// Francisco and London), for the impossible-travel signal.
#[derive(Debug)]
struct FixtureGeoIp;

impl GeoIpProvider for FixtureGeoIp {
    fn locate(&self, ip: &str) -> Option<GeoLocation> {
        match ip {
            "198.51.100.1" => Some(GeoLocation {
                latitude: 37.7749,
                longitude: -122.4194,
                asn: Some(64500),
            }),
            "198.51.100.2" => Some(GeoLocation {
                latitude: 51.5074,
                longitude: -0.1278,
                asn: Some(64501),
            }),
            _ => None,
        }
    }
}

/// A stub IP-reputation provider that flags one IP as suspect.
#[derive(Debug)]
struct StubReputation;

impl IpReputationProvider for StubReputation {
    fn reputation(&self, ip: &str) -> IpReputation {
        if ip == "198.51.100.9" {
            IpReputation::Suspect
        } else {
            IpReputation::Neutral
        }
    }
}

/// A base config with the risk engine enabled and every signal off, so a test opts in to
/// exactly the signals it drives. Off-by-default `require_mfa_at` and store-backed sealing.
fn risk_base() -> OidcConfig {
    let mut config = OidcConfig::default();
    config.risk.enabled = true;
    config.risk.new_device_enabled = false;
    config.risk.impossible_travel_enabled = false;
    config.risk.ip_reputation_enabled = false;
    config.risk.velocity_enabled = false;
    config
}

/// Drive an unauthenticated authorize to obtain a valid `return_to` for the login page.
async fn return_to(harness: &Harness) -> String {
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256&state=xyz"
    );
    let (_, headers, _) = harness.authorize(&query).await;
    let login_location = location(&headers).expect("login redirect");
    let (_, _, login_html) = harness.get_with_cookie(&login_location, None).await;
    common::form_field(&login_html, "return_to").expect("return_to field")
}

/// POST `/login` with a fixed peer IP header (the non-forgeable #31 header the risk engine
/// resolves), so the IP-based signals see a stable client address in the in-process router.
async fn post_login_with_ip(
    harness: &Harness,
    body: &str,
    ip: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let request = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-ironauth-peer-ip", ip)
        .body(Body::from(body.to_owned()))
        .expect("request builds");
    harness.send(request).await
}

/// The most recent risk decision's parsed signals JSON for a subject.
async fn latest_decision_json(harness: &Harness, subject: &str) -> serde_json::Value {
    let scoped = harness.store().scoped(harness.scope());
    let id = scoped.users().parse_id(subject).expect("parse subject");
    let decision = scoped
        .risk()
        .latest_decision(&id)
        .await
        .expect("read decision")
        .expect("a decision was recorded");
    serde_json::from_str(&decision.signals_json).expect("signals json")
}

// ---------------------------------------------------------------------------
// Acceptance: require MFA at MED forces step-up, and LOW does not
// ---------------------------------------------------------------------------

/// The authorize outcome for a pwd session under a "require MFA at MED" risk policy, with
/// the new-device signal either on (MED) or off (LOW). Returns the `Location` redirect.
async fn authorize_under_risk(new_device_on: bool) -> String {
    let mut config = risk_base();
    "med".clone_into(&mut config.risk.require_mfa_at);
    config.risk.new_device_enabled = new_device_on;
    config.trusted_devices_enabled = true;
    let harness = Harness::start_store_backed_with(config).await;
    let client_id = *harness.client_id();
    let client = client_id.to_string();
    harness
        .configure_client_policy(&client_id, "explicit", true, false, None)
        .await;
    let subject = harness.seed_unique_user().await;
    // An enrolled TOTP so a forced MFA floor routes to the second-factor challenge.
    harness.seed_active_totp(&subject).await;
    let cookie = harness.session_cookie_at(&subject, "pwd", 0).await;
    let query = format!(
        "response_type=code&client_id={client}&redirect_uri={REDIRECT_URI}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256&state=xyz"
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize redirects: {body}");
    location(&headers).expect("a Location")
}

#[tokio::test]
async fn require_mfa_at_med_forces_step_up_on_a_med_signal() {
    // A MED score (a new device) at a "require MFA at MED" threshold forces the second
    // factor: the pwd session is routed to the step-up challenge, not issued a code.
    let loc = authorize_under_risk(true).await;
    assert!(
        loc.starts_with("/login/mfa"),
        "a MED risk score must force step-up, got {loc}"
    );
}

#[tokio::test]
async fn a_low_score_does_not_force_step_up() {
    // With the same "require MFA at MED" threshold but the signal disabled (a LOW score),
    // the pwd session proceeds straight to the code, no step-up.
    let loc = authorize_under_risk(false).await;
    assert!(
        loc.starts_with(REDIRECT_URI),
        "a LOW risk score must not force step-up (a code is issued), got {loc}"
    );
    assert!(
        loc.contains("code="),
        "the authorization code is issued, got {loc}"
    );
}

// ---------------------------------------------------------------------------
// Acceptance: the decision record enumerates signals and is reconstructable
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_decision_enumerates_its_signals_and_is_reconstructable_from_the_audit_trail() {
    let mut config = risk_base();
    config.risk.new_device_enabled = true;
    config.trusted_devices_enabled = true;
    let harness = Harness::start_store_backed_with(config).await;
    let subject = harness
        .seed_user("reconstruct@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;
    let body = form(&[
        ("identifier", "reconstruct@example.test"),
        ("password", "correct-horse-battery"),
        ("return_to", &return_to),
    ]);
    let (status, _headers, _body) = harness.post_form("/login", &body, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the login succeeds");

    // The persisted decision enumerates each contributing signal with its value.
    let json = latest_decision_json(&harness, &subject).await;
    assert_eq!(json["score"], "med", "a new device scores MED");
    let signals = json["signals"].as_array().expect("signals array");
    assert!(
        signals.iter().any(|s| s["name"] == "new_device"),
        "the decision enumerates the new_device signal: {json}"
    );
    assert!(
        signals.iter().all(|s| s.get("value").is_some()),
        "every signal carries a value: {json}"
    );

    // A sampled decision is reconstructable from the AUDIT TRAIL alone: a risk.decision
    // audit row carries the score and action in its operator-safe detail.
    let row: (String,) = sqlx::query_as(
        "SELECT detail FROM audit_log WHERE action = 'risk.decision' ORDER BY occurred_at DESC \
         LIMIT 1",
    )
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("a risk.decision audit row exists");
    assert!(
        row.0.contains("score=") && row.0.contains("action="),
        "the audit detail reconstructs the decision, got {}",
        row.0
    );
}

// ---------------------------------------------------------------------------
// Acceptance: new-device notification + "this wasn't me" revoke and flag
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_new_device_login_notifies_and_this_wasnt_me_revokes_and_flags() {
    let mut config = risk_base();
    config.risk.new_device_enabled = true;
    config.risk.notify_on_new_device = true;
    config.trusted_devices_enabled = true;
    let mut harness = Harness::start_store_backed_with(config).await;
    let recorder = Arc::new(RecordingSender::default());
    harness.install_verification_sender(recorder.clone());

    let subject = harness
        .seed_user("notify@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;
    let body = form(&[
        ("identifier", "notify@example.test"),
        ("password", "correct-horse-battery"),
        ("return_to", &return_to),
    ]);
    let (status, headers, _body) = harness.post_form("/login", &body, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the login succeeds");
    let session_cookie = set_cookie_pair(&headers).expect("a session cookie");

    // The new-device notification was delivered with the device/UA/geo context and a
    // single-use "this wasn't me" link.
    let notice = {
        let notices = recorder.notices.lock().expect("lock");
        assert_eq!(notices.len(), 1, "exactly one new-device notification");
        notices[0].clone()
    };
    assert_eq!(notice.recipient, "notify@example.test");
    assert!(!notice.user_agent.is_empty(), "the UA context is present");
    assert!(
        !notice.location_hint.is_empty(),
        "the geo context is present"
    );
    assert!(
        notice
            .disavowal_link
            .contains("/risk/disavow?token=ira_dis_"),
        "the link carries a disavowal token, got {}",
        notice.disavowal_link
    );

    // Before the disavowal the credentials are NOT flagged for review.
    let scoped = harness.store().scoped(harness.scope());
    let subject_id = scoped.users().parse_id(&subject).expect("subject");
    assert!(
        !scoped
            .risk()
            .credentials_flagged_for_review(&subject_id)
            .await
            .expect("read flag"),
        "credentials are not flagged before the disavowal"
    );

    // Follow the "this wasn't me" path.
    let token = notice
        .disavowal_link
        .split("token=")
        .nth(1)
        .expect("token in link")
        .to_owned();
    let disavow_body = form(&[("token", &token)]);
    let (status, _h, done) = harness
        .post_form("/risk/disavow", &disavow_body, None)
        .await;
    assert_eq!(status, StatusCode::OK, "the disavowal page renders");
    assert!(done.contains("secured"), "a confirmation page is shown");

    // The credentials are now flagged for review, and the session in question is revoked.
    let scoped = harness.store().scoped(harness.scope());
    assert!(
        scoped
            .risk()
            .credentials_flagged_for_review(&subject_id)
            .await
            .expect("read flag"),
        "the this-wasn't-me path marks the credentials for review"
    );
    // The revoked session no longer authorizes: a fresh authorize with the dead cookie is
    // sent back to the login page instead of issuing a code.
    let client = harness.client_id().to_string();
    let query = format!(
        "response_type=code&client_id={client}&redirect_uri={REDIRECT_URI}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256&state=xyz"
    );
    let (_s, headers, _b) = harness.authorize_with_cookie(&query, &session_cookie).await;
    let loc = location(&headers).unwrap_or_default();
    assert!(
        loc.starts_with("/login"),
        "the revoked session must not authorize, got {loc}"
    );

    // The disavowal token is SINGLE-USE: a replay flags and revokes nothing new (the
    // credentials stay flagged, but no error and no double action).
    let (status, _h, _b) = harness
        .post_form("/risk/disavow", &disavow_body, None)
        .await;
    assert_eq!(status, StatusCode::OK, "a replayed token is uniform");
}

// ---------------------------------------------------------------------------
// Acceptance: a BLOCK is indistinguishable from an ordinary login failure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_blocked_login_is_indistinguishable_from_an_ordinary_failure() {
    let mut config = risk_base();
    config.risk.ip_reputation_enabled = true;
    config.risk.block_on_high = true;
    config.risk.ip_denylist = vec!["203.0.113.9".to_owned()];
    // Disable the #64 failure throttle so the control (wrong password) is a clean
    // failed-login page, not a throttle.
    config.regulation.enabled = false;
    let harness = Harness::start_store_backed_with(config).await;
    let subject = harness
        .seed_user("block@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;

    // A CORRECT password from a denylisted IP: the risk engine BLOCKS with a uniform
    // failure (no session), evaluated after a successful password verification.
    let blocked_body = form(&[
        ("identifier", "block@example.test"),
        ("password", "correct-horse-battery"),
        ("return_to", &return_to),
    ]);
    let (block_status, block_headers, block_body) =
        post_login_with_ip(&harness, &blocked_body, "203.0.113.9").await;

    // The SAME identifier with a WRONG password: an ordinary login failure.
    let wrong_body = form(&[
        ("identifier", "block@example.test"),
        ("password", "wrong-password-guess"),
        ("return_to", &return_to),
    ]);
    let (fail_status, _fh, fail_body) = harness.post_form("/login", &wrong_body, None).await;

    assert_eq!(
        block_status, fail_status,
        "a block and an ordinary failure share a status code"
    );
    assert_eq!(
        block_body, fail_body,
        "a block is byte-identical to an ordinary login failure"
    );
    // A block sets NO session cookie (the login did not proceed).
    assert!(
        set_cookie_pair(&block_headers).is_none(),
        "a blocked login establishes no session"
    );

    // The block is still recorded and audited (reconstructable), with the block action.
    let json = latest_decision_json(&harness, &subject).await;
    assert_eq!(json["action"], "block", "the decision records the block");
    assert_eq!(json["score"], "high", "an IP deny scores HIGH");
}

// ---------------------------------------------------------------------------
// Acceptance: the engine runs with zero IronCache and zero third-party services
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_engine_runs_with_zero_third_party_services() {
    // Every signal is enabled but NO GeoIP or IP-reputation provider is installed (the
    // null defaults), and there is no IronCache: the login still succeeds and a decision
    // is recorded, so the engine runs complete on the relational store alone.
    let mut config = OidcConfig::default();
    config.risk.enabled = true;
    config.risk.new_device_enabled = true;
    config.risk.impossible_travel_enabled = true;
    config.risk.ip_reputation_enabled = true;
    config.risk.velocity_enabled = true;
    config.trusted_devices_enabled = true;
    let harness = Harness::start_store_backed_with(config).await;
    let subject = harness
        .seed_user("zero@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;
    let body = form(&[
        ("identifier", "zero@example.test"),
        ("password", "correct-horse-battery"),
        ("return_to", &return_to),
    ]);
    let (status, _h, _b) = harness.post_form("/login", &body, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the login succeeds");
    // A decision was recorded through the null-provider path (impossible travel inert).
    let json = latest_decision_json(&harness, &subject).await;
    assert!(
        json.get("score").is_some(),
        "a decision was recorded: {json}"
    );
}

// ---------------------------------------------------------------------------
// Each signal driven: impossible travel, velocity flood, IP suspect
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_impossible_travel_login_scores_high() {
    let mut config = risk_base();
    config.risk.impossible_travel_enabled = true;
    let mut harness = Harness::start_store_backed_with(config).await;
    harness.install_geoip_provider(Arc::new(FixtureGeoIp));
    harness
        .seed_user("travel@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;
    let body = form(&[
        ("identifier", "travel@example.test"),
        ("password", "correct-horse-battery"),
        ("return_to", &return_to),
    ]);
    // First login from San Francisco records the login geo.
    let (status, _h, _b) = post_login_with_ip(&harness, &body, "198.51.100.1").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    // Second login from London with no clock advance is an instantaneous transatlantic
    // jump: superhuman velocity, HIGH.
    let subject = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier("travel@example.test")
        .await
        .expect("lookup")
        .expect("present")
        .id
        .to_string();
    let (status, _h, _b) = post_login_with_ip(&harness, &body, "198.51.100.2").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let json = latest_decision_json(&harness, &subject).await;
    assert_eq!(
        json["score"], "high",
        "impossible travel scores HIGH: {json}"
    );
    let signals = json["signals"].as_array().expect("signals");
    assert!(
        signals.iter().any(|s| s["name"] == "impossible_travel"),
        "the impossible_travel signal is enumerated: {json}"
    );
}

#[tokio::test]
async fn a_velocity_flood_raises_the_score() {
    let mut config = risk_base();
    config.risk.velocity_enabled = true;
    config.risk.velocity_med_threshold = 3;
    config.risk.velocity_high_threshold = 5;
    // Disable the #64 failure throttle so the flood accumulates without a 429.
    config.regulation.enabled = false;
    let harness = Harness::start_store_backed_with(config).await;
    let subject = harness
        .seed_user("flood@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;
    let wrong = form(&[
        ("identifier", "flood@example.test"),
        ("password", "wrong-guess"),
        ("return_to", &return_to),
    ]);
    // Flood failed attempts (each counts against the per-account velocity counter).
    for _ in 0..6 {
        let (status, _h, _b) = harness.post_form("/login", &wrong, None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a wrong password is a plain failure"
        );
    }
    // A subsequent successful login sees a flooded velocity counter and scores HIGH.
    let right = form(&[
        ("identifier", "flood@example.test"),
        ("password", "correct-horse-battery"),
        ("return_to", &return_to),
    ]);
    let (status, _h, _b) = harness.post_form("/login", &right, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "the login succeeds");
    let json = latest_decision_json(&harness, &subject).await;
    assert_eq!(
        json["score"], "high",
        "a velocity flood scores HIGH: {json}"
    );
}

#[tokio::test]
async fn a_suspect_ip_provider_verdict_scores_med() {
    let mut config = risk_base();
    config.risk.ip_reputation_enabled = true;
    let mut harness = Harness::start_store_backed_with(config).await;
    harness.install_ip_reputation_provider(Arc::new(StubReputation));
    let subject = harness
        .seed_user("suspect@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;
    let body = form(&[
        ("identifier", "suspect@example.test"),
        ("password", "correct-horse-battery"),
        ("return_to", &return_to),
    ]);
    let (status, _h, _b) = post_login_with_ip(&harness, &body, "198.51.100.9").await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the login proceeds (suspect notifies, not blocks)"
    );
    let json = latest_decision_json(&harness, &subject).await;
    assert_eq!(json["score"], "med", "a suspect IP scores MED: {json}");
}

// ---------------------------------------------------------------------------
// Adversarial: a notification flood is bounded (notifications gate behind auth)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_notification_flood_via_failed_attempts_is_bounded() {
    // A new-device notification is delivered ONLY after a SUCCESSFUL primary
    // authentication, so an attacker WITHOUT the password cannot flood the victim with
    // notifications: a storm of wrong-password attempts sends ZERO notices and is
    // throttled by the #64 regulation.
    let mut config = risk_base();
    config.risk.new_device_enabled = true;
    config.risk.notify_on_new_device = true;
    config.trusted_devices_enabled = true;
    let mut harness = Harness::start_store_backed_with(config).await;
    let recorder = Arc::new(RecordingSender::default());
    harness.install_verification_sender(recorder.clone());
    harness
        .seed_user("flood2@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;
    let wrong = form(&[
        ("identifier", "flood2@example.test"),
        ("password", "wrong-guess"),
        ("return_to", &return_to),
    ]);
    let mut throttled = false;
    for _ in 0..12 {
        let (status, _h, _b) = harness.post_form("/login", &wrong, None).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            throttled = true;
            break;
        }
    }
    assert!(
        throttled,
        "a wrong-password storm is throttled by the #64 regulation"
    );
    assert_eq!(
        recorder.notices.lock().expect("lock").len(),
        0,
        "no notification is sent for failed attempts (notifications gate behind auth)"
    );
}
