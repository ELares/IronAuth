// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signup fraud review queue at the authorize path (issue #82, PR 2), against a real
//! Postgres. Pins the limited-privilege crux: a QUARANTINED account CAN authenticate, but it
//! is never SILENTLY authorized (the first-party / `skip_consent` carve-out is disabled, so
//! an un-consented app always routes to the consent screen) and it NEVER receives a SENSITIVE
//! scope (`offline_access` and the configured denylist are stripped from the grant at the
//! shared authorize choke point, so a token minted for it carries none). A non-quarantined
//! account on the SAME flow is auto-granted and keeps `offline_access`, proving the behavior is
//! quarantine-scoped and flag-off is a zero change.

mod common;

use axum::http::StatusCode;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, form_field, location,
    location_param,
};
use ironauth_config::{DisposableEmailConfig, OidcConfig, RegistrationAbuseConfig};
use ironauth_jose::verify;

const REG_PASSWORD: &str = "correct horse battery staple";

fn relaxed_pkce_config() -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    }
}

/// A config whose register path BLOCKS a `mailinator.com` signup (a disposable-domain block),
/// the risk decision the fraud queue converts into a quarantine when the flag is on.
fn disposable_block_config() -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        registration_abuse: RegistrationAbuseConfig {
            disposable_email: DisposableEmailConfig {
                mode: "block".to_owned(),
                denylist: vec!["mailinator.com".to_owned()],
                allowlist: Vec::new(),
            },
            ..RegistrationAbuseConfig::default()
        },
        ..OidcConfig::default()
    }
}

/// Drive an unauthenticated authorize to obtain a valid `return_to` for the register page.
async fn register_return_to(harness: &Harness) -> String {
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256&prompt=create",
        enc(REDIRECT_URI),
    );
    let (_s, headers, _b) = harness.authorize(&query).await;
    let register_location = location(&headers).expect("register redirect");
    let (_s, _h, html) = harness.get_with_cookie(&register_location, None).await;
    form_field(&html, "return_to").expect("register return_to")
}

/// Count the quarantined users and open quarantine cases in the harness scope.
async fn quarantine_counts(harness: &Harness) -> (i64, i64) {
    let scope = harness.scope();
    let quarantined: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM users WHERE tenant_id = $1 AND environment_id = $2 \
         AND quarantined = true",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("count quarantined users");
    let cases: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM signup_quarantines WHERE tenant_id = $1 AND environment_id = $2 \
         AND state = 'pending'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("count open cases");
    (quarantined, cases)
}

/// Mark `subject` quarantined directly (the only way to quarantine an already-registered
/// account: the flag is set at signup INSERT and otherwise cleared only by an admin, so a
/// test sets it out of band through the owner pool).
async fn quarantine(harness: &Harness, subject: &str) {
    sqlx::query("UPDATE users SET quarantined = true WHERE id = $1")
        .bind(subject)
        .execute(harness.db().owner_pool())
        .await
        .expect("quarantine the user");
}

fn authorize_query(client_id: &str, scope: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc(scope),
    )
}

/// Drive `/authorize` (as `cookie`) and, if it routes to consent, approve and resume,
/// returning the issued authorization code. Panics if no code is ever issued.
async fn authorize_through_consent(harness: &Harness, cookie: &str, query: &str) -> String {
    let (status, headers, body) = harness.authorize_with_cookie(query, cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let loc = location(&headers).expect("a redirect");
    if let Some(code) = location_param(&headers, "code") {
        return code;
    }
    assert!(
        loc.starts_with("/consent"),
        "an un-consented authorization routes to consent: {loc}"
    );
    let (_s, _h, html) = harness.get_with_cookie(&loc, Some(cookie)).await;
    let return_to = form_field(&html, "return_to").expect("consent return_to");
    let allow = form(&[("decision", "allow"), ("return_to", &return_to)]);
    let (status, headers, body) = harness.post_form("/consent", &allow, Some(cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "consent post: {body}");
    let resume = location(&headers).expect("resume after consent");
    let (status, headers, body) = harness.get_with_cookie(&resume, Some(cookie)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "resume: {body}");
    location_param(&headers, "code").expect("a code after consent")
}

/// The `scope` claim of the access token a code exchange mints.
async fn granted_scope(harness: &Harness, client_id: &str, code: &str) -> String {
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _h, body) = harness.token(&exchange).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("json");
    let access = value["access_token"].as_str().expect("access_token");
    let policy = harness.policy(client_id);
    let verified = verify(access, &policy, &common::verify_clock()).expect("access verifies");
    verified
        .claims()
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned()
}

#[tokio::test]
async fn a_quarantined_account_authenticates_but_offline_access_is_stripped() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_signup_quarantine(&relaxed_pkce_config());
    let client_id = harness.client_id().to_string();

    // A NON-quarantined account on this flow KEEPS offline_access (the baseline).
    let normal = harness.seed_unique_user().await;
    let normal_cookie = harness.session_cookie(&normal).await;
    let code = authorize_through_consent(
        &harness,
        &normal_cookie,
        &authorize_query(&client_id, "openid profile offline_access"),
    )
    .await;
    let normal_scope = granted_scope(&harness, &client_id, &code).await;
    assert!(
        normal_scope
            .split_whitespace()
            .any(|s| s == "offline_access"),
        "a normal account keeps offline_access: {normal_scope}"
    );

    // A QUARANTINED account authenticates (a code IS issued) but offline_access is stripped
    // from the grant, so the minted token carries only the non-sensitive scopes.
    let quarantined = harness.seed_unique_user().await;
    quarantine(&harness, &quarantined).await;
    let cookie = harness.session_cookie(&quarantined).await;
    let code = authorize_through_consent(
        &harness,
        &cookie,
        &authorize_query(&client_id, "openid profile offline_access"),
    )
    .await;
    let scope = granted_scope(&harness, &client_id, &code).await;
    assert!(
        scope.split_whitespace().any(|s| s == "openid"),
        "a quarantined account still gets basic identity: {scope}"
    );
    assert!(
        !scope.split_whitespace().any(|s| s == "offline_access"),
        "a quarantined account NEVER gets offline_access: {scope}"
    );
}

#[tokio::test]
async fn a_quarantined_account_is_denied_the_silent_first_party_carveout() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_signup_quarantine(&relaxed_pkce_config());
    let client_id = harness.client_id().to_string();
    // Turn the harness client into a trusted first-party (skip_consent) client: a normal
    // account is auto-granted with NO consent screen.
    harness
        .configure_client_policy(harness.client_id(), "explicit", true, false, None)
        .await;
    let query = authorize_query(&client_id, "openid profile");

    // A NON-quarantined account is SILENTLY granted a code (the carve-out applies).
    let normal = harness.seed_unique_user().await;
    let normal_cookie = harness.session_cookie(&normal).await;
    let (status, headers, body) = harness.authorize_with_cookie(&query, &normal_cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "a normal account with a skip_consent client is silently granted a code"
    );

    // A QUARANTINED account gets NO silent grant: it is routed to the consent screen instead
    // (the carve-out is disabled), then completes there.
    let quarantined = harness.seed_unique_user().await;
    quarantine(&harness, &quarantined).await;
    let cookie = harness.session_cookie(&quarantined).await;
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert!(
        location_param(&headers, "code").is_none(),
        "a quarantined account is NEVER silently granted, even for a skip_consent client"
    );
    assert!(
        location(&headers)
            .expect("redirect")
            .starts_with("/consent"),
        "a quarantined account is routed to the consent screen"
    );
    // It can still complete through the screen (it CAN authenticate).
    let code = authorize_through_consent(&harness, &cookie, &query).await;
    assert!(
        !code.is_empty(),
        "the quarantined account completes consent"
    );
}

#[tokio::test]
async fn the_register_hook_quarantines_a_risky_signup_when_the_flag_is_on() {
    // Flag ON: a disposable-domain signup the register path would BLOCK is instead
    // QUARANTINED -- the account is created (recoverable) with a session, plus a pending
    // review-queue case, rather than lost.
    let mut harness = Harness::start_store_backed_with(disposable_block_config()).await;
    harness.enable_signup_quarantine(&disposable_block_config());
    let return_to = register_return_to(&harness).await;

    let (before_q, before_c) = quarantine_counts(&harness).await;
    assert_eq!((before_q, before_c), (0, 0), "no quarantine state yet");

    let body = form(&[
        ("identifier", "bot@mailinator.com"),
        ("password", REG_PASSWORD),
        ("return_to", &return_to),
    ]);
    let (status, headers, page) = harness.post_form("/register", &body, None).await;
    // The account is created and a session is established (the quarantined account CAN
    // authenticate), so the response is a redirect that SETS a session cookie -- not the
    // 200 re-render a block produces.
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "quarantine creates a session: {page}"
    );
    assert!(
        common::set_cookie_pair(&headers).is_some(),
        "a quarantined signup is logged in with limited privileges"
    );
    let (after_q, after_c) = quarantine_counts(&harness).await;
    assert_eq!(after_q, 1, "the account was created quarantined");
    assert_eq!(after_c, 1, "a pending review-queue case was opened");
}

#[tokio::test]
async fn the_register_hook_is_inert_when_the_flag_is_off() {
    // Flag OFF (default): the disposable-domain signup is BLOCKED exactly as before -- a 200
    // re-render, no session, no account, and NO quarantine state (zero behavior change).
    let harness = Harness::start_store_backed_with(disposable_block_config()).await;
    let return_to = register_return_to(&harness).await;

    let body = form(&[
        ("identifier", "bot@mailinator.com"),
        ("password", REG_PASSWORD),
        ("return_to", &return_to),
    ]);
    let (status, headers, _page) = harness.post_form("/register", &body, None).await;
    assert_eq!(status, StatusCode::OK, "a block re-renders the form (200)");
    assert!(
        common::set_cookie_pair(&headers).is_none(),
        "a blocked signup establishes no session"
    );
    let (quarantined, cases) = quarantine_counts(&harness).await;
    assert_eq!(
        (quarantined, cases),
        (0, 0),
        "with the flag off the quarantine path never runs"
    );
}
