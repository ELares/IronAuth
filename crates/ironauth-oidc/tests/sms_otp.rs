// SPDX-License-Identifier: MIT OR Apache-2.0

//! The guarded SMS-OTP factor HTTP surface (issue #70), against a real Postgres.
//!
//! These pin the six acceptance-critical behaviors:
//!
//! - SMS is OFF by default; enabling requires an explicit country allowlist, and a send
//!   to a non-allowlisted country is refused with a UNIFORM response;
//! - a simulated PUMPING pattern (a burst of sends to clustered numbers with near-zero
//!   verification) trips the conversion alarm and AUTO-THROTTLES the affected route while
//!   a healthy route keeps sending;
//! - VELOCITY caps enforce per-number / per-tenant limits with cooldowns;
//! - an account protected by TOTP cannot be DOWNGRADED to SMS-only verification without
//!   the explicit tenant-configured downgrade setting;
//! - codes are single-use, TTL-bound, HASHED at rest, attempt-limited, reissue-invalidated;
//! - `amr` reports `sms`.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_oidc::{Argon2Params, HashingPool, SESSION_COOKIE, SmsOtpMessage, SmsSender};
use ironauth_store::EmailFactorPurpose;
use serde_json::{Value, json};

/// A recording SMS sender: captures every DELIVERED code (a suppressed / refused send is
/// never delivered, so it never appears here).
#[derive(Debug, Default)]
struct RecordingSms {
    sent: Mutex<Vec<(String, String, String)>>, // (recipient, route, code)
}

impl SmsSender for RecordingSms {
    fn send(&self, message: &SmsOtpMessage<'_>) {
        self.sent.lock().expect("lock").push((
            message.recipient.to_owned(),
            message.route_key.to_owned(),
            message.code.to_owned(),
        ));
    }
}

/// The relaxed-velocity config: SMS on, tiny velocity windows and generous caps so a test
/// that legitimately sends several times (advancing the clock 2s between sends) is not
/// tripped by the guard, while the conversion sample floor is small so the pumping alarm
/// is reachable in a handful of sends.
fn sms_config() -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        sms_otp_enabled: true,
        sms_send_cooldown_secs: 1,
        sms_per_number_window_secs: 1,
        sms_per_number_send_cap: 50,
        sms_per_tenant_window_secs: 1,
        sms_per_tenant_send_cap: 10_000,
        sms_per_route_window_secs: 1,
        sms_per_route_send_cap: 10_000,
        sms_conversion_min_samples: 5,
        sms_conversion_alarm_threshold_percent: 30,
        ..OidcConfig::default()
    }
}

fn base(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}", scope.tenant(), scope.environment())
}

async fn post_json(harness: &Harness, path: &str, body: &Value) -> (StatusCode, Value) {
    let (status, _headers, response) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let parsed = serde_json::from_str(&response).unwrap_or(Value::Null);
    (status, parsed)
}

async fn verify_full(
    harness: &Harness,
    path: &str,
    body: &Value,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let (status, headers, response) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let parsed = serde_json::from_str(&response).unwrap_or(Value::Null);
    (status, headers, parsed)
}

fn last_code(sender: &RecordingSms, recipient: &str) -> String {
    sender
        .sent
        .lock()
        .expect("lock")
        .iter()
        .rev()
        .find(|(to, _, _)| to == recipient)
        .map(|(_, _, code)| code.clone())
        .expect("a code was delivered")
}

fn delivered_to(sender: &RecordingSms, recipient: &str) -> bool {
    sender
        .sent
        .lock()
        .expect("lock")
        .iter()
        .any(|(to, _, _)| to == recipient)
}

/// Whether the response sets the primary `__Host-ironauth_session` cookie.
fn sets_session_cookie(headers: &axum::http::HeaderMap) -> bool {
    headers.get_all(header::SET_COOKIE).iter().any(|value| {
        value
            .to_str()
            .unwrap_or_default()
            .starts_with(SESSION_COOKIE)
    })
}

/// Advance past the tiny velocity windows, send an SMS-OTP code for `purpose`, then verify
/// the DELIVERED code for that same `purpose`. Returns the verify response so a test can
/// assert whether it established a primary session.
async fn send_then_verify_purpose(
    harness: &Harness,
    sender: &RecordingSms,
    base: &str,
    phone: &str,
    purpose: &str,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    harness.clock().advance(Duration::from_secs(2));
    let (status, _) = post_json(
        harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": purpose }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the send is acked for {purpose}");
    let code = last_code(sender, phone);
    verify_full(
        harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": phone, "purpose": purpose, "code": code }),
    )
    .await
}

/// A harness with SMS enabled (downgrade `allow_downgrade`) for country `1`, the #64
/// regulation OFF (so cross-purpose verify attempts do not throttle one another and this
/// isolates the factor-downgrade semantics), a recording sender, and a seeded US-mobile
/// user PROTECTED by an active TOTP factor.
async fn protected_account(allow_downgrade: bool) -> (Harness, Arc<RecordingSms>, String) {
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        regulation: RegulationConfig {
            enabled: false,
            ..RegulationConfig::default()
        },
        ..sms_config()
    })
    .await;
    let sender = Arc::new(RecordingSms::default());
    harness.install_sms_sender(sender.clone());
    harness.enable_sms(allow_downgrade, &["1"]).await;
    let phone = "+14155550100".to_owned();
    let subject = harness
        .seed_user(&phone, "correct horse battery staple")
        .await;
    harness.seed_active_totp(&subject).await;
    (harness, sender, phone)
}

/// A harness with SMS enabled for country `1`, a recording sender, and a seeded user
/// whose identifier is a US mobile number.
async fn setup() -> (Harness, Arc<RecordingSms>, String) {
    let mut harness = Harness::start_store_backed_with(sms_config()).await;
    let sender = Arc::new(RecordingSms::default());
    harness.install_sms_sender(sender.clone());
    harness.enable_sms(false, &["1"]).await;
    let phone = "+14155550100".to_owned();
    harness
        .seed_user(&phone, "correct horse battery staple")
        .await;
    (harness, sender, phone)
}

#[tokio::test]
async fn off_by_default_then_enabled_with_allowlist() {
    // A fresh scope with SMS mounted but NOT enabled per-tenant: a send is UNIFORMLY
    // acknowledged but nothing is delivered (off by default, no allowlist).
    let mut harness = Harness::start_store_backed_with(sms_config()).await;
    let sender = Arc::new(RecordingSms::default());
    harness.install_sms_sender(sender.clone());
    let phone = "+14155550100".to_owned();
    harness.seed_user(&phone, "pw pw pw pw pw pw").await;
    let base = base(&harness);

    let (status, body) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the ack is uniform");
    assert!(
        !delivered_to(&sender, &phone),
        "SMS off by default: no delivery"
    );

    // Now enable SMS with a country allowlist of exactly `1`. Advance past the tiny
    // per-number cooldown window so this send is not tripped by the earlier one.
    harness.enable_sms(false, &["1"]).await;
    harness.clock().advance(Duration::from_secs(2));
    let (status, enabled_body) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        delivered_to(&sender, &phone),
        "an allowlisted send delivers"
    );
    // The acknowledgment body is byte-identical whether or not a send actually went out.
    assert_eq!(
        body, enabled_body,
        "the ack must not distinguish enabled state"
    );
}

#[tokio::test]
async fn a_non_allowlisted_country_is_refused_uniformly() {
    let (harness, sender, allowlisted) = setup().await;
    let base = base(&harness);
    // A UK number: the tenant allowlist has only country `1`, so this is refused.
    let uk = "+447700900123".to_owned();
    harness.seed_user(&uk, "pw pw pw pw pw pw").await;

    let (allow_status, allow_body) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": allowlisted, "purpose": "login" }),
    )
    .await;
    let (deny_status, deny_body) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": uk, "purpose": "login" }),
    )
    .await;

    // Byte-identical response for an allowlisted and a non-allowlisted destination.
    assert_eq!(allow_status, deny_status);
    assert_eq!(
        allow_body, deny_body,
        "a non-allowlisted country must be non-enumerating"
    );
    // But the non-allowlisted number received NO text.
    assert!(delivered_to(&sender, &allowlisted));
    assert!(
        !delivered_to(&sender, &uk),
        "a non-allowlisted send is refused (no delivery)"
    );
}

#[tokio::test]
async fn full_lifecycle_signs_in_with_the_sms_amr() {
    let (harness, sender, phone) = setup().await;
    let base = base(&harness);
    let (status, _) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = last_code(&sender, &phone);

    let (status, headers, body) = verify_full(
        &harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": phone, "purpose": "login", "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the fresh code verifies: {body:?}");
    assert_eq!(body["amr"], json!(["sms"]), "amr reports sms honestly");
    let set_cookie = headers.get_all(header::SET_COOKIE).iter().any(|value| {
        value
            .to_str()
            .unwrap_or_default()
            .starts_with(SESSION_COOKIE)
    });
    assert!(
        set_cookie,
        "a session cookie is set on a successful SMS sign-in"
    );
}

#[tokio::test]
async fn reissue_invalidates_the_predecessor_and_code_is_hashed_and_single_use() {
    let (harness, sender, phone) = setup().await;
    let base = base(&harness);

    // First send.
    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    let first = last_code(&sender, &phone);

    // The code is stored HASHED at rest (an Argon2id PHC string, never the plaintext).
    let scope = harness.scope();
    let subject = harness
        .store()
        .scoped(scope)
        .users()
        .by_identifier(&phone)
        .await
        .expect("lookup")
        .expect("user")
        .id;
    let active = harness
        .store()
        .scoped(scope)
        .sms_otp()
        .resolve_active(&subject, EmailFactorPurpose::Login, 0)
        .await
        .expect("resolve")
        .expect("active code");
    assert!(
        active.code_hash.starts_with("$argon2"),
        "code hashed at rest"
    );
    assert!(
        !active.code_hash.contains(&first),
        "plaintext code absent from the hash"
    );

    // Reissue (advance past the tiny velocity windows, still well within the code TTL).
    harness.clock().advance(Duration::from_secs(2));
    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    let second = last_code(&sender, &phone);
    assert_ne!(first, second);

    // The PREDECESSOR no longer verifies (reissue invalidation, not mere expiry).
    let (status, _, _) = verify_full(
        &harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": phone, "purpose": "login", "code": first }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the reissued code invalidates the predecessor"
    );

    // The fresh code verifies once (single-use), and a replay fails.
    let (status, _, _) = verify_full(
        &harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": phone, "purpose": "login", "code": second }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = verify_full(
        &harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": phone, "purpose": "login", "code": second }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a consumed code is single-use"
    );
}

#[tokio::test]
async fn the_code_dies_after_the_attempt_budget() {
    // Disable the #64 abuse throttle so this isolates the per-CODE attempt counter (a
    // distinct mechanism): the code must die after its own budget, independent of any
    // request-rate throttle, exactly as the email-OTP suite does.
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        regulation: RegulationConfig {
            enabled: false,
            ..RegulationConfig::default()
        },
        ..sms_config()
    })
    .await;
    let sender = Arc::new(RecordingSms::default());
    harness.install_sms_sender(sender.clone());
    harness.enable_sms(false, &["1"]).await;
    let phone = "+14155550100".to_owned();
    harness
        .seed_user(&phone, "correct horse battery staple")
        .await;
    let base = base(&harness);
    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    let code = last_code(&sender, &phone);
    // The default budget is 5 wrong guesses.
    for _ in 0..5 {
        let (status, _, _) = verify_full(
            &harness,
            &format!("{base}/otp/sms/verify"),
            &json!({ "identifier": phone, "purpose": "login", "code": "000000" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // The correct code no longer verifies: the code spent its budget and died.
    let (status, _, _) = verify_full(
        &harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": phone, "purpose": "login", "code": code }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an over-attempted code must not verify"
    );
}

#[tokio::test]
async fn velocity_caps_throttle_per_number_and_per_tenant() {
    // Tight caps and the DEFAULT (frozen-clock) cooldown, so a rapid burst trips.
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        sms_otp_enabled: true,
        sms_per_tenant_send_cap: 3,
        sms_per_tenant_window_secs: 3600,
        ..OidcConfig::default()
    })
    .await;
    let sender = Arc::new(RecordingSms::default());
    harness.install_sms_sender(sender.clone());
    harness.enable_sms(false, &["1"]).await;
    let base = base(&harness);

    // The per-number cooldown (one send per window) trips on the SECOND send to one
    // number under the frozen clock.
    let phone = "+14155550100";
    harness.seed_user(phone, "pw pw pw pw pw pw").await;
    let (first, _) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    assert_eq!(first, StatusCode::OK);
    let (second, _) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    assert_eq!(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        "a second rapid send to one number trips the per-number cooldown"
    );

    // The per-tenant cap (3) trips on a burst across DISTINCT numbers (velocity is
    // existence-independent, so unknown numbers still count).
    let mut saw_tenant_throttle = false;
    for n in 0..6 {
        let (status, _) = post_json(
            &harness,
            &format!("{base}/otp/sms/send"),
            &json!({ "identifier": format!("+1415555020{n}"), "purpose": "login" }),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            saw_tenant_throttle = true;
            break;
        }
    }
    assert!(
        saw_tenant_throttle,
        "a per-tenant send burst must be throttled"
    );
}

#[tokio::test]
async fn a_pumped_route_auto_throttles_while_a_healthy_route_keeps_sending() {
    // The acceptance-critical pumping defense. A cheap hashing pool keeps the burst fast.
    let mut harness = Harness::start_store_backed_with(sms_config()).await;
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(pool);
    let sender = Arc::new(RecordingSms::default());
    harness.install_sms_sender(sender.clone());
    // Allowlist both the pumped route (country 1) and the healthy route (country 44).
    harness.enable_sms(false, &["1", "44"]).await;
    let base = base(&harness);

    // A HEALTHY UK user: a send that DOES get verified (keeps the 44 route converting).
    let healthy = "+447700900123".to_owned();
    harness.seed_user(&healthy, "pw pw pw pw pw pw").await;
    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": healthy, "purpose": "login" }),
    )
    .await;
    let healthy_code = last_code(&sender, &healthy);
    let (status, _, _) = verify_full(
        &harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": healthy, "purpose": "login", "code": healthy_code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the healthy route converts");

    // PUMP the country-1 route: a burst of sends to distinct US mobiles, NEVER verified.
    // Six sends (>= the sample floor of 5) at 0 percent conversion trip the alarm.
    for n in 0..6 {
        let phone = format!("+141555510{n:02}");
        harness.seed_user(&phone, "pw pw pw pw pw pw").await;
        harness.clock().advance(Duration::from_secs(2));
        let (status, _) = post_json(
            &harness,
            &format!("{base}/otp/sms/send"),
            &json!({ "identifier": phone, "purpose": "login" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // The country-1 route is now AUTO-THROTTLED: a NEW send to a fresh US mobile is
    // refused (no delivery), WITHOUT any operator intervention.
    let victim = "+14155559999".to_owned();
    harness.seed_user(&victim, "pw pw pw pw pw pw").await;
    harness.clock().advance(Duration::from_secs(2));
    let (status, _) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": victim, "purpose": "login" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the ack stays uniform even when the route is throttled"
    );
    assert!(
        !delivered_to(&sender, &victim),
        "the pumped route is auto-throttled: the send is refused (no delivery)"
    );

    // The route-stats row records the throttle, and an audit row was written.
    let scope = harness.scope();
    let stat = harness
        .store()
        .scoped(scope)
        .sms_otp()
        .route_stat("1")
        .await
        .expect("route stat")
        .expect("route 1 has stats");
    assert!(stat.alarm_active, "the low-conversion alarm is latched");
    assert!(
        stat.throttled_until_unix_micros.is_some(),
        "the route carries a throttle horizon"
    );

    // The HEALTHY country-44 route keeps sending: a fresh UK send still delivers.
    let healthy2 = "+447700900555".to_owned();
    harness.seed_user(&healthy2, "pw pw pw pw pw pw").await;
    harness.clock().advance(Duration::from_secs(2));
    let (status, _) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": healthy2, "purpose": "login" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        delivered_to(&sender, &healthy2),
        "a healthy route keeps sending while another route is throttled"
    );
}

#[tokio::test]
async fn sms_cannot_downgrade_an_account_protected_by_totp() {
    let (harness, sender, phone) = setup().await;
    let base = base(&harness);
    let subject = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier(&phone)
        .await
        .expect("lookup")
        .expect("user")
        .id
        .to_string();
    // Protect the account with an ACTIVE TOTP factor.
    harness.seed_active_totp(&subject).await;

    // A login SMS is sent and the correct code presented, but the tenant has NOT opted
    // into the downgrade path, so the login is REFUSED (no session).
    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    let code = last_code(&sender, &phone);
    let (status, headers, _) = verify_full(
        &harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": phone, "purpose": "login", "code": code }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "SMS must not downgrade a TOTP-protected account without an explicit downgrade path"
    );
    assert!(
        !headers.contains_key(header::SET_COOKIE),
        "no session cookie is set on a blocked downgrade"
    );
}

#[tokio::test]
async fn an_explicit_downgrade_path_permits_sms_for_a_totp_account() {
    let mut harness = Harness::start_store_backed_with(sms_config()).await;
    let sender = Arc::new(RecordingSms::default());
    harness.install_sms_sender(sender.clone());
    // Enable SMS WITH the explicit factor-downgrade opt-in.
    harness.enable_sms(true, &["1"]).await;
    let phone = "+14155550100".to_owned();
    let subject = harness.seed_user(&phone, "pw pw pw pw pw pw").await;
    harness.seed_active_totp(&subject).await;
    let base = base(&harness);

    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    let code = last_code(&sender, &phone);
    let (status, _, body) = verify_full(
        &harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": phone, "purpose": "login", "code": code }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the explicit downgrade path permits SMS: {body:?}"
    );
    assert_eq!(body["amr"], json!(["sms"]));
}

#[tokio::test]
async fn a_send_when_the_factor_is_globally_disabled_is_not_found() {
    // The deployment kill switch (default) returns a uniform 404.
    let harness = Harness::start_store_backed().await;
    let base = base(&harness);
    let (status, _) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": "+14155550100", "purpose": "login" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "SMS is off by default at the deployment level"
    );
}

#[tokio::test]
async fn no_purpose_mints_a_primary_session_for_a_totp_protected_account() {
    // Adversarial review HIGH-1: the no-silent-downgrade invariant must hold for EVERY
    // purpose, not only `login` / `recovery`. On a TOTP-protected account WITHOUT the
    // downgrade opt-in, NO purpose may mint a primary session: `login` / `recovery` /
    // `register` are blocked, and `mfa` / `verify_address` are non-session-establishing
    // possession proofs. The pre-fix code fell through EVERY purpose to a full primary
    // session, so `mfa` / `verify_address` / `register` each took over the account.
    let (harness, sender, phone) = protected_account(false).await;
    let base = base(&harness);

    for purpose in ["login", "recovery", "register", "mfa", "verify_address"] {
        let (_status, headers, body) =
            send_then_verify_purpose(&harness, &sender, &base, &phone, purpose).await;
        assert!(
            !sets_session_cookie(&headers),
            "purpose {purpose} must not set the primary session cookie on a protected \
             account without the downgrade opt-in: {body:?}"
        );
        assert_ne!(
            body["authenticated"],
            json!(true),
            "purpose {purpose} must not return an authenticated primary session on a \
             protected account without the downgrade opt-in: {body:?}"
        );
    }
}

#[tokio::test]
async fn the_downgrade_opt_in_restores_login_and_recovery_but_verify_address_is_never_a_session() {
    // HIGH-1 complement: WITH the explicit downgrade opt-in, `login` and `recovery` mint a
    // session again (the documented downgrade path), but `verify_address` is a possession
    // proof that NEVER mints a session, regardless of the opt-in.
    let (harness, sender, phone) = protected_account(true).await;
    let base = base(&harness);

    for purpose in ["login", "recovery"] {
        let (status, headers, body) =
            send_then_verify_purpose(&harness, &sender, &base, &phone, purpose).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the opt-in permits the {purpose} downgrade: {body:?}"
        );
        assert_eq!(body["amr"], json!(["sms"]), "amr honestly reports sms");
        assert_eq!(body["authenticated"], json!(true));
        assert!(
            sets_session_cookie(&headers),
            "{purpose} mints a session under the downgrade opt-in"
        );
    }

    let (status, headers, body) =
        send_then_verify_purpose(&harness, &sender, &base, &phone, "verify_address").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["verified"],
        json!(true),
        "verify_address proves control"
    );
    assert_ne!(
        body["authenticated"],
        json!(true),
        "verify_address never claims an authenticated login: {body:?}"
    );
    assert!(
        !sets_session_cookie(&headers),
        "verify_address never mints a session even under the downgrade opt-in: {body:?}"
    );
}

#[tokio::test]
async fn a_blocked_downgrade_consumes_the_proven_code_and_is_not_a_fast_path() {
    // Adversarial review LOW: the downgrade BLOCK must not short-circuit faster than a real
    // verify attempt (a factor-possession timing oracle). The fixed block runs the SAME
    // resolve + Argon2 compare + single durable write a real attempt runs; the observable,
    // non-flaky proof is that a blocked verify with the CORRECT code CONSUMES it (the old
    // early-return skipped resolve/consume entirely). We also confirm no session leaks.
    let (harness, sender, phone) = protected_account(false).await;
    let base = base(&harness);
    let subject = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_identifier(&phone)
        .await
        .expect("lookup")
        .expect("user")
        .id;

    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    let code = last_code(&sender, &phone);
    let (status, headers, _) = verify_full(
        &harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": phone, "purpose": "login", "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the downgrade is blocked");
    assert!(
        !sets_session_cookie(&headers),
        "no session leaks on a blocked downgrade"
    );

    // The proven code was consumed by the block path (equal work, no timing shortcut): it
    // no longer resolves and a replay is still refused.
    let active = harness
        .store()
        .scoped(harness.scope())
        .sms_otp()
        .resolve_active(&subject, EmailFactorPurpose::Login, 0)
        .await
        .expect("resolve");
    assert!(
        active.is_none(),
        "a blocked downgrade consumes the proven code (it ran the full resolve + consume, \
         not a fast short-circuit)"
    );
    let (replay, _, _) = verify_full(
        &harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": phone, "purpose": "login", "code": code }),
    )
    .await;
    assert_eq!(
        replay,
        StatusCode::UNAUTHORIZED,
        "the consumed code cannot be replayed"
    );
}

#[tokio::test]
async fn a_send_is_uniform_present_vs_absent_even_under_hashing_pool_back_pressure() {
    // Adversarial review MEDIUM-2: under a shedding per-tenant Argon2 pool, the KNOWN path
    // must NOT surface a distinct rejection while the unknown path returns the uniform ack
    // (a present-vs-absent enumeration oracle). We install a pool that deterministically
    // faults every hash (an invalid parameter triple maps to a pool rejection), standing in
    // for any pool shed, and assert BOTH a real allowlisted recipient and an unknown one
    // return the identical uniform 200 ack (never a distinct 429/503/500 for the real one).
    let mut harness = Harness::start_store_backed_with(sms_config()).await;
    // An invalid Argon2 triple (memory below 8*parallelism) faults every real hash to a
    // typed pool rejection; `verify_absent` verifies a FIXED dummy hash independent of these
    // params, so the absent path still returns its uniform ack.
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(0, 0, 0),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(pool);
    let sender = Arc::new(RecordingSms::default());
    harness.install_sms_sender(sender.clone());
    harness.enable_sms(false, &["1"]).await;
    let known = "+14155550100".to_owned();
    harness.seed_user(&known, "pw pw pw pw pw pw").await;
    let unknown = "+14155550111".to_owned(); // allowlisted country, no account
    let base = base(&harness);

    let (known_status, known_body) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": known, "purpose": "login" }),
    )
    .await;
    harness.clock().advance(Duration::from_secs(2));
    let (unknown_status, unknown_body) = post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": unknown, "purpose": "login" }),
    )
    .await;

    assert_eq!(
        known_status,
        StatusCode::OK,
        "a real recipient must return the uniform ack under pool back-pressure, not a \
         distinct rejection: {known_body:?}"
    );
    assert_eq!(known_status, unknown_status);
    assert_eq!(
        known_body, unknown_body,
        "present and absent sends are byte-identical even when the hashing pool sheds"
    );
    // The pool faulted, so neither send actually delivered a code.
    assert!(!delivered_to(&sender, &known));
    assert!(!delivered_to(&sender, &unknown));
}

#[tokio::test]
async fn a_code_past_its_ttl_is_refused_even_when_correct() {
    // Adversarial review coverage gap: an explicit TTL-EXPIRY verify. A correct code
    // presented after the code TTL (default 300s) must be refused.
    let (harness, sender, phone) = setup().await;
    let base = base(&harness);
    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": phone, "purpose": "login" }),
    )
    .await;
    let code = last_code(&sender, &phone);
    // Advance past the SMS OTP code TTL on the manual clock.
    harness.clock().advance(Duration::from_secs(301));
    let (status, _, _) = verify_full(
        &harness,
        &format!("{base}/otp/sms/verify"),
        &json!({ "identifier": phone, "purpose": "login", "code": code }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a correct code past its TTL must not verify"
    );
}

#[tokio::test]
async fn a_throttled_route_resumes_after_the_conversion_window_rolls() {
    // Adversarial review coverage gap: a throttle-LIFT / resume test. After the throttle
    // horizon lapses AND the conversion window rolls (counters reset -> a now-healthy
    // route), sends resume.
    let mut harness = Harness::start_store_backed_with(sms_config()).await;
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(pool);
    let sender = Arc::new(RecordingSms::default());
    harness.install_sms_sender(sender.clone());
    harness.enable_sms(false, &["1"]).await;
    let base = base(&harness);

    // Pump the country-1 route to a throttle (>= the 5-sample floor at 0 percent).
    for n in 0..6 {
        let phone = format!("+141555510{n:02}");
        harness.seed_user(&phone, "pw pw pw pw pw pw").await;
        harness.clock().advance(Duration::from_secs(2));
        let (status, _) = post_json(
            &harness,
            &format!("{base}/otp/sms/send"),
            &json!({ "identifier": phone, "purpose": "login" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    // The route is throttled: a fresh send does not deliver.
    let blocked = "+14155557000".to_owned();
    harness.seed_user(&blocked, "pw pw pw pw pw pw").await;
    harness.clock().advance(Duration::from_secs(2));
    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": blocked, "purpose": "login" }),
    )
    .await;
    assert!(!delivered_to(&sender, &blocked), "the route is throttled");

    // Advance past BOTH the throttle horizon and the conversion window (both 3600s on the
    // defaults): the counters reset, the route is healthy, and sending resumes.
    harness.clock().advance(Duration::from_secs(3700));
    let resumed = "+14155557001".to_owned();
    harness.seed_user(&resumed, "pw pw pw pw pw pw").await;
    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": resumed, "purpose": "login" }),
    )
    .await;
    assert!(
        delivered_to(&sender, &resumed),
        "after the window rolls the throttle lifts and sending resumes"
    );
}

#[tokio::test]
async fn a_still_pumping_route_re_throttles_after_the_throttle_lapses_within_the_window() {
    // Adversarial review LOW-3: with `throttle_secs < conversion_window_secs`, a route that
    // is STILL pumping when its throttle lapses must RE-THROTTLE on the next send rather
    // than pumping freely until the window rolls. The re-arm (clearing the latched alarm
    // when the throttle lapses) is the fix; without it `auto_throttle_route` (WHERE
    // alarm_active = false) can never re-fire and the route pumps freely.
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        sms_route_throttle_secs: 5,
        sms_conversion_window_secs: 3600,
        ..sms_config()
    })
    .await;
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(pool);
    let sender = Arc::new(RecordingSms::default());
    harness.install_sms_sender(sender.clone());
    harness.enable_sms(false, &["1"]).await;
    let base = base(&harness);

    // Pump the route to a throttle.
    for n in 0..6 {
        let phone = format!("+141555511{n:02}");
        harness.seed_user(&phone, "pw pw pw pw pw pw").await;
        harness.clock().advance(Duration::from_secs(2));
        post_json(
            &harness,
            &format!("{base}/otp/sms/send"),
            &json!({ "identifier": phone, "purpose": "login" }),
        )
        .await;
    }
    let blocked = "+14155558000".to_owned();
    harness.seed_user(&blocked, "pw pw pw pw pw pw").await;
    harness.clock().advance(Duration::from_secs(2));
    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": blocked, "purpose": "login" }),
    )
    .await;
    assert!(!delivered_to(&sender, &blocked), "the route is throttled");

    // Advance PAST the 5s throttle but well within the 3600s window (the misconfig ratio).
    harness.clock().advance(Duration::from_secs(10));
    // The first post-lapse send gets through (throttle lapsed) and re-arms + re-throttles
    // the still-pumping route.
    let relapse = "+14155558001".to_owned();
    harness.seed_user(&relapse, "pw pw pw pw pw pw").await;
    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": relapse, "purpose": "login" }),
    )
    .await;
    assert!(
        delivered_to(&sender, &relapse),
        "the send at the throttle-lapse instant gets through"
    );
    // The still-pumping route re-throttled by construction: the NEXT send is refused, not
    // pumping freely. Without the re-arm this send would deliver.
    let refused = "+14155558002".to_owned();
    harness.seed_user(&refused, "pw pw pw pw pw pw").await;
    harness.clock().advance(Duration::from_secs(2));
    post_json(
        &harness,
        &format!("{base}/otp/sms/send"),
        &json!({ "identifier": refused, "purpose": "login" }),
    )
    .await;
    assert!(
        !delivered_to(&sender, &refused),
        "a still-pumping route re-throttles on the next send after the throttle lapses"
    );
}
