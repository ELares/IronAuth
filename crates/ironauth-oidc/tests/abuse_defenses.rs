// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential-abuse defenses through the full HTTP path (issue #64), against a real
//! Postgres.
//!
//! Pins the two security-critical acceptance criteria: (1) ANTI-ENUMERATION UNIFORMITY,
//! login and registration are byte-identical (status AND body) for a present and an
//! absent identifier, including the closed-registration send-suppression path; and (2)
//! ACCOUNT-DoS RESISTANCE, failed-password spray against a victim throttles ONLY the
//! victim's PASSWORD path, never their RECOVERY path (Keycloak CVE-2024-1722), and never
//! another identifier's path.

mod common;

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::{Harness, PKCE_CHALLENGE, REDIRECT_URI, form, form_field};
use ironauth_config::{OidcConfig, RegulationConfig};
use ironauth_env::Env;
use ironauth_store::{AbuseSubject, AuthPath};

/// The `retry-after` header value in whole seconds, if present.
fn retry_after(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

/// The `x-ratelimit-remaining` header value, if present.
fn remaining(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// The current clock-seam time in microseconds since the Unix epoch.
fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// A minimal authorization query that routes an unauthenticated request to `/login`.
fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={REDIRECT_URI}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256&state=xyz"
    )
}

/// Drive an unauthenticated authorize to obtain a valid `return_to` for the interaction
/// pages (login / register / recover).
async fn return_to(harness: &Harness) -> String {
    let client_id = harness.client_id().to_string();
    let (_, headers, _) = harness.authorize(&authorize_query(&client_id)).await;
    let login_location = common::location(&headers).expect("login redirect");
    let (_, _, login_html) = harness.get_with_cookie(&login_location, None).await;
    form_field(&login_html, "return_to").expect("return_to field")
}

#[tokio::test]
async fn login_is_byte_identical_for_present_and_absent_identifiers() {
    let harness = Harness::start().await;
    harness
        .seed_user("present@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;

    // A wrong password for a PRESENT account.
    let present = form(&[
        ("identifier", "present@example.test"),
        ("password", "wrong-password-guess"),
        ("return_to", &return_to),
    ]);
    let (present_status, _h, present_body) = harness.post_form("/login", &present, None).await;

    // The SAME password for an ABSENT account.
    let absent = form(&[
        ("identifier", "absent@example.test"),
        ("password", "wrong-password-guess"),
        ("return_to", &return_to),
    ]);
    let (absent_status, _h, absent_body) = harness.post_form("/login", &absent, None).await;

    assert_eq!(
        present_status, absent_status,
        "present and absent identifiers must share a status code"
    );
    // The body differs only by the reflected (identical-length here) identifier prefill;
    // the message and structure are identical. Compare with the identifier normalized out.
    let present_norm = present_body.replace("present@example.test", "X");
    let absent_norm = absent_body.replace("absent@example.test", "X");
    assert_eq!(
        present_norm, absent_norm,
        "present and absent login responses must be byte-identical modulo the prefilled handle"
    );
    assert_eq!(present_status, StatusCode::OK);
}

#[tokio::test]
async fn password_spray_throttles_the_password_path_but_not_recovery() {
    let harness = Harness::start().await;
    harness
        .seed_user("victim@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;

    // Spray wrong passwords at the victim's PASSWORD path. The default soft threshold is
    // 5, so after enough failures a further attempt is throttled (429). The ManualClock
    // does not advance, so the failures accumulate in one window.
    let spray = form(&[
        ("identifier", "victim@example.test"),
        ("password", "wrong-guess"),
        ("return_to", &return_to),
    ]);
    let mut throttled = false;
    for _ in 0..12 {
        let (status, _h, _b) = harness.post_form("/login", &spray, None).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            throttled = true;
            break;
        }
    }
    assert!(
        throttled,
        "sustained failed-password spray must throttle the password path"
    );

    // The victim's RECOVERY path is governed INDEPENDENTLY: a recovery request still
    // succeeds (the uniform 200 acknowledgment), so the owner is never locked out of
    // every path.
    let recover = form(&[
        ("identifier", "victim@example.test"),
        ("return_to", &return_to),
    ]);
    let (recover_status, _h, _b) = harness.post_form("/recover", &recover, None).await;
    assert_eq!(
        recover_status,
        StatusCode::OK,
        "the recovery path must stay open under password spray"
    );

    // A DIFFERENT identifier's password path is also unthrottled (per-identifier keying):
    // the victim's spray does not bleed onto another account.
    let other = form(&[
        ("identifier", "bystander@example.test"),
        ("password", "wrong-guess"),
        ("return_to", &return_to),
    ]);
    let (other_status, _h, _b) = harness.post_form("/login", &other, None).await;
    assert_eq!(
        other_status,
        StatusCode::OK,
        "another identifier's password path must be unaffected by the victim's spray"
    );
}

#[tokio::test]
async fn recovery_is_byte_identical_for_present_and_absent_identifiers() {
    let harness = Harness::start().await;
    harness
        .seed_user("known@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;

    let present = form(&[
        ("identifier", "known@example.test"),
        ("return_to", &return_to),
    ]);
    let (present_status, _h, present_body) = harness.post_form("/recover", &present, None).await;

    let absent = form(&[
        ("identifier", "nobody@example.test"),
        ("return_to", &return_to),
    ]);
    let (absent_status, _h, absent_body) = harness.post_form("/recover", &absent, None).await;

    assert_eq!(present_status, absent_status);
    assert_eq!(
        present_body, absent_body,
        "recovery must return the same acknowledgment for a present and an absent identifier"
    );
    assert_eq!(present_status, StatusCode::OK);
}

#[tokio::test]
async fn closed_registration_is_uniform_for_present_and_absent_identifiers() {
    // Closed-registration send suppression (issue #64, the Logto pattern): with
    // registration closed, a send to an unknown address is suppressed but the response is
    // identical to a known address, so registration is not an enumeration oracle.
    let config = OidcConfig {
        enabled: true,
        regulation: RegulationConfig {
            registration_closed: true,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    harness
        .seed_user("member@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;

    let present = form(&[
        ("identifier", "member@example.test"),
        ("password", "some-password-value"),
        ("return_to", &return_to),
    ]);
    let (present_status, _h, present_body) = harness.post_form("/register", &present, None).await;

    let absent = form(&[
        ("identifier", "stranger@example.test"),
        ("password", "some-password-value"),
        ("return_to", &return_to),
    ]);
    let (absent_status, _h, absent_body) = harness.post_form("/register", &absent, None).await;

    assert_eq!(present_status, absent_status);
    assert_eq!(
        present_body, absent_body,
        "closed registration must return the same acknowledgment for a present and an absent \
         identifier"
    );
    assert_eq!(present_status, StatusCode::OK);
    // Sanity: it is the uniform acknowledgment, not the account-created redirect.
    assert!(
        present_body.contains("Check your email"),
        "closed registration returns the uniform acknowledgment"
    );
}

#[tokio::test]
async fn login_escalation_delay_doubles_and_caps_and_is_not_frozen() {
    // The escalation ACTUALLY escalates (issue #64 HIGH-1): each further failed attempt
    // (throttled OR allowed) is recorded, so the counter keeps CLIMBING and the
    // `Retry-After` DOUBLES per failure up to `max_delay`. The regression this pins is the
    // frozen-counter bug where a throttled attempt was never recorded, so the counter stuck
    // at the soft threshold and `Retry-After` was pinned flat at the base delay forever.
    let harness = Harness::start().await; // defaults: soft=5, base=1, max=60, window=300
    harness
        .seed_user("climber@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;

    let spray = form(&[
        ("identifier", "climber@example.test"),
        ("password", "wrong-guess"),
        ("return_to", &return_to),
    ]);

    // The ManualClock does not advance, so every failure lands in one window. Drive well
    // past the cap and record the Retry-After stamped on each throttled response.
    let mut throttled_delays = Vec::new();
    for _ in 0..14 {
        let (status, headers, _body) = harness.post_form("/login", &spray, None).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            throttled_delays.push(retry_after(&headers).expect("throttled carries Retry-After"));
        }
    }

    // Soft threshold 5: the first five failures are allowed, then every further failure is
    // throttled with a DOUBLING delay capped at max_delay (60): 1, 2, 4, 8, 16, 32, 60, 60...
    assert_eq!(
        throttled_delays,
        vec![1, 2, 4, 8, 16, 32, 60, 60, 60],
        "the escalating Retry-After must double per failure and cap at max_delay, not freeze"
    );
    // The defining regression assertion: the delay is NOT pinned flat at the base (1s).
    assert!(
        throttled_delays.iter().any(|&d| d > 1),
        "a frozen counter would pin Retry-After at the base delay (1s); it must climb"
    );
}

#[tokio::test]
async fn hard_lockout_is_reachable_and_confined_to_the_password_path() {
    // With the opt-in hard lockout on, the per-account counter must CLIMB to its threshold
    // (previously it froze at the soft threshold, so a lockout ban was unreachable), and the
    // auto-placed ban must be confined to the PASSWORD path (issue #64 HIGH-1 + account-DoS
    // safety): the passkey and recovery paths stay open.
    let config = OidcConfig {
        enabled: true,
        regulation: RegulationConfig {
            hard_lockout: true,
            hard_lockout_threshold: 8,
            soft_threshold: 5,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    let account = harness
        .seed_user("locked@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;

    let spray = form(&[
        ("identifier", "locked@example.test"),
        ("password", "wrong-guess"),
        ("return_to", &return_to),
    ]);
    // Eight failed attempts drives the per-account counter to the threshold and auto-places
    // the lockout ban.
    for _ in 0..8 {
        harness.post_form("/login", &spray, None).await;
    }

    // The password-path ban is now actually placed on the account (reachable at last).
    let subjects = [AbuseSubject::account(account.clone())];
    let now = now_micros(harness.env());
    assert!(
        harness
            .store()
            .scoped(harness.scope())
            .abuse()
            .active_ban(&subjects, AuthPath::Password, now)
            .await
            .expect("ban check")
            .is_some(),
        "the hard-lockout ban must be reachable and placed on the password path"
    );
    // ...but it is CONFINED to the password path: passkey and recovery are untouched.
    for path in [AuthPath::Passkey, AuthPath::Recovery] {
        assert!(
            harness
                .store()
                .scoped(harness.scope())
                .abuse()
                .active_ban(&subjects, path, now)
                .await
                .expect("ban check")
                .is_none(),
            "the hard-lockout ban must NOT govern the {path:?} path"
        );
    }
    // And the recovery surface still answers (the owner is not locked out of every path).
    let recover = form(&[
        ("identifier", "locked@example.test"),
        ("return_to", &return_to),
    ]);
    let (recover_status, _h, _b) = harness.post_form("/recover", &recover, None).await;
    assert_eq!(
        recover_status,
        StatusCode::OK,
        "recovery stays open even under hard lockout"
    );
}

#[tokio::test]
async fn hard_lockout_response_is_uniform_for_a_banned_present_and_a_throttled_absent_identifier() {
    // The avoidable enumeration leak is closed (issue #64 MEDIUM-3): with hard lockout on, a
    // banned PRESENT account and a throttled ABSENT identifier must return the SAME throttled
    // response shape (status, body, and Retry-After header), so the response never
    // distinguishes them. Only the onset (documented as inherent to hard lockout) may differ.
    let config = OidcConfig {
        enabled: true,
        regulation: RegulationConfig {
            hard_lockout: true,
            hard_lockout_threshold: 8,
            soft_threshold: 5,
            ..RegulationConfig::default()
        },
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    harness
        .seed_user("present@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;

    // Drive BOTH identifiers well past the cap and past the account threshold: the present
    // account ends up banned, the absent identifier ends up escalation-throttled at the cap.
    let mut present_last = None;
    let mut absent_last = None;
    for _ in 0..14 {
        let present = form(&[
            ("identifier", "present@example.test"),
            ("password", "wrong-guess"),
            ("return_to", &return_to),
        ]);
        present_last = Some(harness.post_form("/login", &present, None).await);
        let absent = form(&[
            ("identifier", "absent@example.test"),
            ("password", "wrong-guess"),
            ("return_to", &return_to),
        ]);
        absent_last = Some(harness.post_form("/login", &absent, None).await);
    }

    let (present_status, present_headers, present_body) = present_last.unwrap();
    let (absent_status, absent_headers, absent_body) = absent_last.unwrap();

    assert_eq!(present_status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(absent_status, StatusCode::TOO_MANY_REQUESTS);
    // The Retry-After header shape is identical (both at the cap): a banned present account
    // is not distinguishable from a throttled absent identifier by the throttle delay.
    assert_eq!(
        retry_after(&present_headers),
        retry_after(&absent_headers),
        "the banned present and throttled absent Retry-After must match"
    );
    assert_eq!(
        remaining(&present_headers),
        remaining(&absent_headers),
        "the rate-limit remaining header must match"
    );
    // The body is byte-identical modulo the reflected identifier prefill.
    let present_norm = present_body.replace("present@example.test", "X");
    let absent_norm = absent_body.replace("absent@example.test", "X");
    assert_eq!(
        present_norm, absent_norm,
        "the banned present and throttled absent bodies must be byte-identical modulo the handle"
    );
}

#[tokio::test]
async fn a_successful_login_clears_the_throttle() {
    // A legitimate user who fumbled a few times and then enters the CORRECT password is not
    // punished for the rest of the window (issue #64 LOW-6): the success resets the
    // identifier/IP/account failure counters, so their accumulated failures do not carry
    // over and the very next failure is treated as a fresh first attempt, not a throttle.
    let harness = Harness::start().await; // soft=5, so the 6th consecutive failure throttles
    harness
        .seed_user("typist@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;

    let wrong = form(&[
        ("identifier", "typist@example.test"),
        ("password", "wrong-guess"),
        ("return_to", &return_to),
    ]);
    // FOUR wrong attempts (counter -> 4, still under the soft threshold and allowed).
    for _ in 0..4 {
        let (status, _h, _b) = harness.post_form("/login", &wrong, None).await;
        assert_eq!(status, StatusCode::OK, "under the soft threshold: allowed");
    }

    // The CORRECT password on the fifth attempt is still allowed (counter -> 5, at the soft
    // threshold, not yet throttled), succeeds, and RESETS the counter to zero.
    let right = form(&[
        ("identifier", "typist@example.test"),
        ("password", "correct-horse-battery"),
        ("return_to", &return_to),
    ]);
    let (status, _h, _b) = harness.post_form("/login", &right, None).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the correct password succeeds (a redirect) and clears the counter"
    );

    // The counter is back at zero: it now takes a FULL fresh run of soft-threshold failures
    // to throttle again. Without the reset, the counter would already be at 5, so the very
    // first of these would be the 6th failure and throttle immediately.
    for _ in 0..5 {
        let (status, _h, _b) = harness.post_form("/login", &wrong, None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "after a success the throttle is relaxed: a fresh run of failures is allowed again"
        );
    }
    // Only the sixth fresh failure throttles, confirming the counter truly reset to zero.
    let (status, _h, _b) = harness.post_form("/login", &wrong, None).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the throttle re-engages only after a full fresh run, proving the reset"
    );
}

#[tokio::test]
async fn regulation_denies_when_its_security_layer_fails_closed() {
    // The fail-CLOSED security cells DENY on a backend failure (issue #64 MEDIUM-5): with the
    // envelope master key missing, the per-identifier counter and the durable ban check both
    // error, and the pre-verify regulation must refuse the attempt (429), never ADMIT it.
    let harness = Harness::start().await;
    harness
        .seed_user("present@example.test", "correct-horse-battery")
        .await;
    let return_to = return_to(&harness).await;

    // A router whose data-plane store has no master key: the identifier-keyed counter and
    // the ban check fail closed.
    let router = harness.router_without_master_key();
    let attempt = form(&[
        ("identifier", "present@example.test"),
        ("password", "wrong-guess"),
        ("return_to", &return_to),
    ]);
    let request = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(attempt))
        .expect("request builds");
    let (status, _headers, _body) = common::send_through(router, request).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "a fail-closed security-layer backend error must DENY (throttle), not admit"
    );
}
