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
use base64::Engine as _;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, SEED_PASSWORD, enc, form, form_field,
    json, location, location_param, set_cookie_pair,
};

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
    assert_eq!(status, StatusCode::SEE_OTHER, "error redirect: {body}");
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
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("consent_required"),
    );
}

#[tokio::test]
async fn prompt_none_with_a_narrower_recorded_consent_returns_consent_required() {
    // Scope-aware consent under prompt=none (issue #196): a recorded consent whose
    // granted scope is NOT a superset of the requested scope does NOT silently
    // auto-grant. The request asks for `openid profile`, but only `openid` was
    // consented, so prompt=none returns consent_required through the negotiated
    // response mode (an error redirect to the validated redirect_uri), never a
    // consent page and never a code.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    // A NARROW prior consent (openid only) and a session, but the request wants the
    // broader `openid profile`.
    harness
        .grant_consent_scoped(&subject, &client_id, Some("openid"))
        .await;
    let cookie = harness.session_cookie(&subject).await;

    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &["prompt=none"]), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "error redirect: {body}");
    let loc = location(&headers).expect("location");
    assert!(
        loc.starts_with(REDIRECT_URI),
        "delivered to the redirect_uri, never a consent page: {loc}"
    );
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("consent_required"),
        "a broader request than the recorded consent is consent_required under prompt=none"
    );
    assert!(
        location_param(&headers, "code").is_none(),
        "no code is issued when consent does not cover the request"
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
    assert_eq!(status, StatusCode::SEE_OTHER, "code redirect: {body}");
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
    let loc = location(&headers).expect("location");
    assert!(
        loc.starts_with("/consent?return_to="),
        "prompt=consent re-prompts consent: {loc}"
    );
}

#[tokio::test]
async fn prompt_login_round_trip_issues_a_code_and_does_not_loop() {
    // Regression for the forced-interaction loop: prompt=login must force ONE fresh
    // login and then COMPLETE, not redirect to /login again forever. The login
    // consumes the login token on the resume URL, so the resumed request issues the
    // code rather than re-forcing the interaction.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user("relogin@example.test", SEED_PASSWORD)
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;

    // 1. prompt=login with a valid, consented session still forces a login redirect.
    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &["prompt=login"]), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let login_location = location(&headers).expect("login redirect");
    assert!(
        login_location.starts_with("/login?return_to="),
        "{login_location}"
    );

    // 2. GET /login, round-trip its return_to, POST the credentials.
    let (_s, _h, login_html) = harness.get_with_cookie(&login_location, None).await;
    let return_to = form_field(&login_html, "return_to").expect("login return_to");
    let login_body = form(&[
        ("identifier", "relogin@example.test"),
        ("password", SEED_PASSWORD),
        ("return_to", &return_to),
    ]);
    let (status, headers, body) = harness.post_form("/login", &login_body, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "login post: {body}");
    let fresh_cookie = set_cookie_pair(&headers).expect("fresh session cookie");
    let resume = location(&headers).expect("resume after login");

    // 3. The resumed authorize ISSUES THE CODE (it does not loop back to /login).
    let (status, headers, _) = harness.get_with_cookie(&resume, Some(&fresh_cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let final_location = location(&headers).expect("final redirect");
    assert!(
        final_location.starts_with(REDIRECT_URI) && location_param(&headers, "code").is_some(),
        "prompt=login completes after one re-auth, not a loop: {final_location}"
    );
}

#[tokio::test]
async fn prompt_consent_round_trip_issues_a_code_and_does_not_loop() {
    // Regression: prompt=consent must force ONE fresh consent and then COMPLETE, not
    // redirect to /consent again forever after the user allows.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user("reconsent@example.test", SEED_PASSWORD)
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;

    // 1. prompt=consent forces a consent redirect even though consent is recorded.
    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &["prompt=consent"]), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let consent_location = location(&headers).expect("consent redirect");
    assert!(
        consent_location.starts_with("/consent?return_to="),
        "{consent_location}"
    );

    // 2. GET /consent, allow, resume.
    let (_s, _h, consent_html) = harness
        .get_with_cookie(&consent_location, Some(&cookie))
        .await;
    let return_to = form_field(&consent_html, "return_to").expect("consent return_to");
    let consent_body = form(&[("decision", "allow"), ("return_to", &return_to)]);
    let (status, headers, body) = harness
        .post_form("/consent", &consent_body, Some(&cookie))
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "consent post: {body}");
    let resume = location(&headers).expect("resume after consent");

    // 3. The resumed authorize ISSUES THE CODE (no loop back to /consent).
    let (status, headers, _) = harness.get_with_cookie(&resume, Some(&cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location_param(&headers, "code").is_some(),
        "prompt=consent completes after one re-consent, not a loop: {:?}",
        location(&headers)
    );
}

#[tokio::test]
async fn max_age_zero_round_trip_completes_under_an_advancing_clock() {
    // Regression for the production loop the frozen test clock hid: with a real,
    // ADVANCING clock, max_age=0 forces ONE re-auth and then COMPLETES, and the ID
    // token still carries auth_time even though max_age is consumed on the resume.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let subject = harness
        .seed_user("maxage0@example.test", SEED_PASSWORD)
        .await;
    harness.grant_consent(&subject, &client_id).await;
    let cookie = harness.session_cookie(&subject).await;

    // Advance so the existing session is not authenticated at this very instant.
    harness.clock().advance(Duration::from_secs(30));

    // 1. max_age=0 forces a login redirect.
    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &["max_age=0"]), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let login_location = location(&headers).expect("login redirect");
    assert!(
        login_location.starts_with("/login?return_to="),
        "{login_location}"
    );

    // 2. Log in, with real request latency modeled by advancing the clock.
    let (_s, _h, login_html) = harness.get_with_cookie(&login_location, None).await;
    let return_to = form_field(&login_html, "return_to").expect("login return_to");
    harness.clock().advance(Duration::from_secs(1));
    let login_body = form(&[
        ("identifier", "maxage0@example.test"),
        ("password", SEED_PASSWORD),
        ("return_to", &return_to),
    ]);
    let (status, headers, body) = harness.post_form("/login", &login_body, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "login post: {body}");
    let fresh_cookie = set_cookie_pair(&headers).expect("fresh session cookie");
    let resume = location(&headers).expect("resume after login");
    // The resume consumed max_age and carries the emit_auth_time marker.
    assert!(
        !resume.contains("max_age"),
        "max_age is consumed on the resume: {resume}"
    );
    assert!(
        resume.contains("emit_auth_time"),
        "auth_time emission is preserved on the resume: {resume}"
    );

    // 3. The resume arrives a moment after the login (clock advances again) and
    //    ISSUES THE CODE rather than looping back to /login.
    harness.clock().advance(Duration::from_secs(1));
    let (status, headers, _) = harness.get_with_cookie(&resume, Some(&fresh_cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let code = location_param(&headers, "code").expect("code issued, not a loop");

    // 4. The ID token still carries auth_time (max_age required it).
    let token_body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _h, body) = harness.token(&token_body).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let id_token = json(&body)["id_token"]
        .as_str()
        .expect("id_token")
        .to_owned();
    let payload = id_token
        .split('.')
        .nth(1)
        .expect("id_token payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("claims json");
    assert!(
        claims.get("auth_time").is_some(),
        "auth_time is emitted for a consumed max_age=0: {claims}"
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
    assert_eq!(status, StatusCode::SEE_OTHER);
    let loc = location(&headers).expect("location");
    assert!(
        loc.starts_with("/login?return_to="),
        "max_age=0 forces re-authentication: {loc}"
    );

    // max_age ABSENT: the same session issues the code (no re-auth).
    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &[]), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        location_param(&headers, "code").is_some(),
        "an absent max_age never forces re-auth"
    );

    // A generous max_age that the session is well within also issues the code.
    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&client_id, &["max_age=3600"]), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
    let loc = location(&headers).expect("register redirect");
    assert!(
        loc.starts_with("/register?return_to="),
        "prompt=create deep-links to registration: {loc}"
    );
}
