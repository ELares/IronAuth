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

use axum::http::StatusCode;
use common::{Harness, PKCE_CHALLENGE, REDIRECT_URI, form, form_field};
use ironauth_config::{OidcConfig, RegulationConfig};

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
