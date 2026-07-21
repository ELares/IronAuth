// SPDX-License-Identifier: MIT OR Apache-2.0

//! The consent-lockdown unverified-sensitive-scope gate at the authorize path (issue #88, PR
//! 3), against a real Postgres. Pins the hardening crux: an UNVERIFIED (quarantined) client
//! that is NOT classified first-party is BLOCKED from an authorization request whose effective
//! scope intersects the sensitive denylist (`access_denied` at the validated `redirect_uri`,
//! no code issued), rather than proceeding to consent and minting the sensitive scope. The two
//! escapes both already exist -- verify the client (which lifts `quarantined`) or mark it
//! first-party -- so the gate defaults ON. A non-sensitive scope on the same client is NOT
//! blocked (it routes to consent as before), and turning the gate off restores the prior
//! proceed-to-consent behavior. The block fires AHEAD of the recorded-consent fast path, so a
//! client that recorded a covering grant while still verified is still blocked once it becomes
//! quarantined.

mod common;

use axum::http::StatusCode;
use common::{
    Harness, PKCE_CHALLENGE, REDIRECT_URI, enc, form, form_field, location, location_param,
};
use ironauth_config::{ConsentLockdownConfig, OidcConfig};

const SENSITIVE_SCOPE: &str = "openid profile offline_access";
const NON_SENSITIVE_SCOPE: &str = "openid profile";

fn gate_off_config() -> OidcConfig {
    OidcConfig {
        consent_lockdown: ConsentLockdownConfig {
            gate_unverified_sensitive_scopes: false,
        },
        ..OidcConfig::default()
    }
}

fn authorize_query(client_id: &str, scope: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc(scope),
    )
}

/// Drive `/authorize` (as `cookie`), approve consent if the request routes to the screen, and
/// return the issued authorization code. Panics if no code is ever issued. Used to RECORD a
/// covering consent so the recorded-consent fast path can be probed.
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

/// Assert an authorize response is the lockdown BLOCK: an `access_denied` redirect to the
/// validated `redirect_uri` with NO code issued.
fn assert_blocked(headers: &axum::http::HeaderMap) {
    let loc = location(headers).expect("a redirect");
    assert!(
        loc.starts_with(REDIRECT_URI),
        "the block redirects to the validated redirect_uri: {loc}"
    );
    assert_eq!(
        location_param(headers, "error").as_deref(),
        Some("access_denied"),
        "the block returns access_denied: {loc}"
    );
    assert!(
        location_param(headers, "code").is_none(),
        "the block issues NO code: {loc}"
    );
}

/// Assert an authorize response is NOT the lockdown block: it carries no error and routes to
/// the consent screen (proceeds exactly as before the gate).
fn assert_proceeds_to_consent(headers: &axum::http::HeaderMap) {
    let loc = location(headers).expect("a redirect");
    assert!(
        location_param(headers, "error").is_none(),
        "the request is NOT blocked: {loc}"
    );
    assert!(
        loc.starts_with("/consent"),
        "the request proceeds to the consent screen: {loc}"
    );
}

#[tokio::test]
async fn unverified_third_party_sensitive_scope_is_blocked() {
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    // An unverified (quarantined), third-party (not first_party) client.
    harness.set_client_quarantined(harness.client_id(), true).await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_blocked(&headers);
}

#[tokio::test]
async fn unverified_third_party_non_sensitive_scope_is_not_blocked() {
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    harness.set_client_quarantined(harness.client_id(), true).await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    // No sensitive scope requested: the gate does not fire and the (quarantined) client still
    // routes to the consent screen as before.
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_proceeds_to_consent(&headers);
}

#[tokio::test]
async fn unverified_first_party_sensitive_scope_is_not_blocked() {
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    // Quarantined but explicitly classified FIRST-PARTY: the carve-out exempts it from the
    // gate even for a sensitive scope.
    harness.set_client_quarantined(harness.client_id(), true).await;
    harness.set_client_first_party(harness.client_id(), true).await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_proceeds_to_consent(&headers);
}

#[tokio::test]
async fn verified_third_party_sensitive_scope_is_not_blocked() {
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    // A VERIFIED (non-quarantined) client is the escape: the gate keys off `quarantined`, so a
    // verified client requesting a sensitive scope proceeds normally.
    harness.set_client_quarantined(harness.client_id(), false).await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_proceeds_to_consent(&headers);
}

#[tokio::test]
async fn gate_off_restores_the_prior_proceed_behavior() {
    // Regression guard: with the gate turned OFF, an unverified client requesting a sensitive
    // scope is NOT blocked and proceeds to consent exactly as before the lockdown existed.
    let harness = Harness::start_store_backed_with(gate_off_config()).await;
    let client_id = harness.client_id().to_string();
    harness.set_client_quarantined(harness.client_id(), true).await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_proceeds_to_consent(&headers);
}

#[tokio::test]
async fn the_block_fires_before_the_recorded_consent_fast_path() {
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;

    // 1. While the client is VERIFIED, the user grants consent covering the sensitive scope, so
    //    a covering recorded consent exists (the fast path would auto-authorize a later
    //    request).
    harness.set_client_quarantined(harness.client_id(), false).await;
    let code =
        authorize_through_consent(&harness, &cookie, &authorize_query(&client_id, SENSITIVE_SCOPE))
            .await;
    assert!(!code.is_empty(), "a code is issued for the verified client");

    // 2. The client is now quarantined. Despite the prior covering grant, the lockdown BLOCKS a
    //    fresh authorization for the sensitive scope: the gate fires ahead of the
    //    recorded-consent fast path, so the recorded consent can never let a now-quarantined
    //    client through.
    harness.set_client_quarantined(harness.client_id(), true).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_blocked(&headers);
}
