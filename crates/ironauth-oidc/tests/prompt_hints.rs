// SPDX-License-Identifier: MIT OR Apache-2.0

//! `prompt`, `max_age`, and the interaction-hint plumbing, end to end against a
//! real Postgres and driven through the full HTTP/protocol path (issue #16):
//!
//! - `prompt=none` renders NO UI and returns `login_required` / `consent_required`
//!   through the negotiated response mode, or issues the code when nothing is
//!   needed;
//! - `prompt=login` re-authenticates despite a valid session, and `prompt=consent`
//!   re-prompts consent even when consent is recorded;
//! - `max_age=0` forces re-authentication for a session that is not fresh, while an
//!   ABSENT `max_age` does not (the integer-falsy trap);
//! - `login_hint` prefills the login form;
//! - `none` combined with any other prompt value is `invalid_request`.
//!
//! These need the live authorization endpoint over the store, so they connect to
//! Postgres.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{Harness, PKCE_CHALLENGE, REDIRECT_URI, enc, form_field, location, location_param};

/// Build the authorization query for the harness public client (PKCE is mandatory,
/// so the S256 challenge rides every request), appending any extra pre-encoded
/// `key=value` fragments (`prompt`, `max_age`, `login_hint`).
fn authorize_query(client_id: &str, extra: &[&str]) -> String {
    let mut query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&state=xyz&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid profile"),
    );
    for fragment in extra {
        query.push('&');
        query.push_str(fragment);
    }
    query
}

#[tokio::test]
async fn prompt_none_with_no_session_returns_login_required_through_the_response_mode() {
    // Acceptance 1: prompt=none never renders UI; a missing session is login_required
    // delivered by redirect to the validated redirect_uri (the query mode here).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    let (status, headers, body) = harness
        .authorize(&authorize_query(&client_id, &["prompt=none"]))
        .await;
    assert_eq!(status, StatusCode::FOUND, "error redirect: {body}");
    let loc = location(&headers).expect("location");
    assert!(
        loc.starts_with(REDIRECT_URI),
        "delivered to the redirect_uri, not a page: {loc}"
    );
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("login_required"),
    );
    assert_eq!(location_param(&headers, "state").as_deref(), Some("xyz"));
    assert!(
        location_param(&headers, "iss").is_some(),
        "iss rides the error"
    );
}

#[tokio::test]
async fn prompt_none_without_consent_returns_consent_required() {
    // Acceptance 1: an authenticated session that has NOT consented is
    // consent_required under prompt=none (no consent screen is rendered).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    // A session but no recorded consent for this client.
    let cookie = harness.session_cookie(&subject).await;

    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &["prompt=none"]), &cookie)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("consent_required"),
    );
}

#[tokio::test]
async fn prompt_none_with_session_and_consent_issues_the_code() {
    // Acceptance 1: with a usable session AND recorded consent, prompt=none issues
    // the code silently (no interaction was needed).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;

    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &["prompt=none"]), &cookie)
        .await;
    assert_eq!(status, StatusCode::FOUND, "code redirect: {body}");
    let loc = location(&headers).expect("location");
    assert!(loc.starts_with(REDIRECT_URI), "code to redirect_uri: {loc}");
    assert!(
        location_param(&headers, "code").is_some(),
        "a code is issued"
    );
    assert!(location_param(&headers, "error").is_none(), "no error");
}

#[tokio::test]
async fn prompt_login_re_authenticates_despite_a_valid_session() {
    // Acceptance 3: prompt=login forces fresh authentication (a LOCAL login redirect)
    // even though the session is valid and consent is recorded.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;

    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &["prompt=login"]), &cookie)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let loc = location(&headers).expect("location");
    assert!(
        loc.starts_with("/login?return_to="),
        "prompt=login forces a fresh login: {loc}"
    );
}

#[tokio::test]
async fn prompt_consent_re_prompts_even_when_consent_is_recorded() {
    // Acceptance 3: prompt=consent forces the consent screen even though consent is
    // already recorded for this client.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;

    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &["prompt=consent"]), &cookie)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let loc = location(&headers).expect("location");
    assert!(
        loc.starts_with("/consent?return_to="),
        "prompt=consent re-prompts consent: {loc}"
    );
}

#[tokio::test]
async fn max_age_zero_forces_reauth_but_absent_max_age_does_not() {
    // Acceptance 2: the integer-falsy trap. A session authenticated at the epoch,
    // then observed 100 seconds later, is stale under max_age=0 (forces re-auth like
    // prompt=login) but fine when max_age is ABSENT. A naive `if max_age` would treat
    // 0 as absent; the presence check distinguishes them.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;

    // Advance the clock so the epoch-authenticated session is 100 seconds old.
    harness.clock().advance(Duration::from_secs(100));

    // max_age=0 present: forces a fresh login.
    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &["max_age=0"]), &cookie)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let loc = location(&headers).expect("location");
    assert!(
        loc.starts_with("/login?return_to="),
        "max_age=0 forces re-authentication: {loc}"
    );

    // max_age ABSENT: the same session issues the code (no re-auth).
    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &[]), &cookie)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location_param(&headers, "code").is_some(),
        "an absent max_age never forces re-auth"
    );

    // A generous max_age that the session is well within also issues the code.
    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &["max_age=3600"]), &cookie)
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location_param(&headers, "code").is_some(),
        "a session younger than max_age is not stale"
    );
}

#[tokio::test]
async fn max_age_zero_with_no_session_is_login_required_under_prompt_none() {
    // max_age=0 combined with prompt=none and no session is login_required (no UI).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    let (status, headers, _) = harness
        .authorize(&authorize_query(&client_id, &["prompt=none", "max_age=0"]))
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("login_required"),
    );
}

#[tokio::test]
async fn login_hint_prefills_the_login_form() {
    // Acceptance 5: login_hint prefills the identifier on the hosted login page,
    // reflected through the escaper. It rides the interaction round-trip via the
    // resuming return_to.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let hint = "ada@example.test";

    let (status, headers, _) = harness
        .authorize(&authorize_query(
            &client_id,
            &[&format!("login_hint={}", enc(hint))],
        ))
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let login_location = location(&headers).expect("login redirect");
    assert!(login_location.starts_with("/login?return_to="));

    let (status, _, login_html) = harness.get_with_cookie(&login_location, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        form_field(&login_html, "identifier").as_deref(),
        Some(hint),
        "the login_hint prefills the identifier: {login_html}"
    );
}

#[tokio::test]
async fn a_hostile_login_hint_is_reflected_escaped() {
    // login_hint is untrusted and reflected into the identifier attribute, so it must
    // be HTML-escaped (the reflected-parameter injection class).
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let hostile = "\"><script>alert(1)</script>";

    let (_s, headers, _b) = harness
        .authorize(&authorize_query(
            &client_id,
            &[&format!("login_hint={}", enc(hostile))],
        ))
        .await;
    let login_location = location(&headers).expect("login redirect");
    let (status, _, html) = harness.get_with_cookie(&login_location, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !html.contains("\"><script>alert(1)"),
        "the login_hint must not break out of the attribute: {html}"
    );
    assert!(
        html.contains("&lt;script&gt;alert(1)"),
        "the login_hint is escaped"
    );
}

#[tokio::test]
async fn prompt_none_combined_with_login_is_invalid_request() {
    // Acceptance 1: `none` with any other value is invalid_request (OIDC Core
    // 3.1.2.1), delivered through the negotiated mode to the validated redirect_uri.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    let (status, headers, _) = harness
        .authorize(&authorize_query(
            &client_id,
            &[&format!("prompt={}", enc("none login"))],
        ))
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_request"),
    );
    assert!(
        location_param(&headers, "iss").is_some(),
        "iss rides the error"
    );
}

#[tokio::test]
async fn an_essential_acr_no_method_can_meet_is_unmet_authentication_requirements() {
    // Acceptance 6: an essential acr pinned to a level NO available method can
    // achieve is unmet_authentication_requirements, delivered through the negotiated
    // response mode. A session and consent exist, so the failure is the acr binding,
    // not an interaction need.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;

    let claims = r#"{"id_token":{"acr":{"essential":true,"values":["urn:example:super-high"]}}}"#;
    let (status, headers, _) = harness
        .authorize_with_cookie(
            &authorize_query(&client_id, &[&format!("claims={}", enc(claims))]),
            &cookie,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("unmet_authentication_requirements"),
    );
    assert!(
        location_param(&headers, "code").is_none(),
        "no code is issued"
    );
}

#[tokio::test]
async fn a_voluntary_unsatisfiable_acr_values_still_issues_the_code() {
    // Acceptance 6 boundary: a VOLUNTARY acr_values preference is best-effort, so an
    // unsatisfiable one is NOT unmet_authentication_requirements; the code is issued
    // and the achieved acr is reported honestly (issue #14). This is the contract the
    // unmet surface must not violate.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;

    let (status, headers, _) = harness
        .authorize_with_cookie(
            &authorize_query(
                &client_id,
                &[&format!("acr_values={}", enc("urn:example:super-high"))],
            ),
            &cookie,
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location_param(&headers, "code").is_some(),
        "a voluntary acr_values never fails closed"
    );
    assert!(location_param(&headers, "error").is_none());
}

#[tokio::test]
async fn prompt_create_still_deep_links_to_registration() {
    // Acceptance 4: prompt=create routes an unauthenticated user to registration,
    // folded into the new prompt SET model.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    let (status, headers, _) = harness
        .authorize(&authorize_query(&client_id, &["prompt=create"]))
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let loc = location(&headers).expect("register redirect");
    assert!(
        loc.starts_with("/register?return_to="),
        "prompt=create deep-links to registration: {loc}"
    );
}
