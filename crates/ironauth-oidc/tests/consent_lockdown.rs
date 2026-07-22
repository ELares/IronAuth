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
            ..ConsentLockdownConfig::default()
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
    harness
        .set_client_quarantined(harness.client_id(), true)
        .await;

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
    harness
        .set_client_quarantined(harness.client_id(), true)
        .await;

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
    harness
        .set_client_quarantined(harness.client_id(), true)
        .await;
    harness
        .set_client_first_party(harness.client_id(), true)
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_proceeds_to_consent(&headers);
}

#[tokio::test]
async fn the_block_fires_before_the_skip_consent_carve_out() {
    // A quarantined, non-first-party client with skip_consent set must still be blocked for a
    // sensitive scope: the lockdown gate sits ahead of the skip_consent carve-out, so a
    // consent-skipping unverified client cannot silently obtain the sensitive scope.
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    harness
        .set_client_quarantined(harness.client_id(), true)
        .await;
    harness
        .configure_client_policy(harness.client_id(), "explicit", true, false, None)
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_blocked(&headers);
}

#[tokio::test]
async fn the_block_fires_before_the_implicit_consent_mode_carve_out() {
    // Same ordering property for consent_mode=implicit (the auto-grant first-party UX): an
    // unverified, non-first-party client cannot use implicit consent to skip the lockdown for a
    // sensitive scope.
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    harness
        .set_client_quarantined(harness.client_id(), true)
        .await;
    harness
        .configure_client_policy(harness.client_id(), "implicit", false, false, None)
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_blocked(&headers);
}

#[tokio::test]
async fn verified_third_party_sensitive_scope_is_not_blocked() {
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    // A VERIFIED (non-quarantined) client is the escape: the gate keys off `quarantined`, so a
    // verified client requesting a sensitive scope proceeds normally.
    harness
        .set_client_quarantined(harness.client_id(), false)
        .await;

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
    harness
        .set_client_quarantined(harness.client_id(), true)
        .await;

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
    harness
        .set_client_quarantined(harness.client_id(), false)
        .await;
    let code = authorize_through_consent(
        &harness,
        &cookie,
        &authorize_query(&client_id, SENSITIVE_SCOPE),
    )
    .await;
    assert!(!code.is_empty(), "a code is issued for the verified client");

    // 2. The client is now quarantined. Despite the prior covering grant, the lockdown BLOCKS a
    //    fresh authorization for the sensitive scope: the gate fires ahead of the
    //    recorded-consent fast path, so the recorded consent can never let a now-quarantined
    //    client through.
    harness
        .set_client_quarantined(harness.client_id(), true)
        .await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_blocked(&headers);
}

// ===========================================================================
// PR 4: the third-party admin-consent gate.
//
// A THIRD-PARTY (not first_party) client must be ADMIN PRE-AUTHORIZED for its requested scope
// before it can obtain user consent. A covering pre-authorization SKIPS the user consent screen
// (the admin grant is the consent of record, the Microsoft model); an uncovered third-party
// request is a terminal "requires administrator approval" (access_denied, no user self-consent).
// The gate is ON by default in production; the harness defaults it OFF for the general third-party
// fixture (see `Harness::enable_third_party_admin_consent`) and each test below turns it ON.
// ===========================================================================

/// The `consent.skip` audit rows (`detail`, `target_id`) in the harness scope, read from the store.
async fn consent_skip_audit(harness: &Harness) -> Vec<(String, String)> {
    harness
        .store()
        .scoped(harness.scope())
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .filter(|row| row.action == "consent.skip")
        .map(|row| (row.detail.unwrap_or_default(), row.target_id))
        .collect()
}

#[tokio::test]
async fn a_covering_admin_pre_authorization_skips_the_user_consent_screen() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_third_party_admin_consent();
    let client_id = harness.client_id().to_string();
    // A THIRD-PARTY client (the seed is not first_party) admin-pre-authorized for the scope.
    harness
        .set_client_admin_grant(harness.client_id(), Some(NON_SENSITIVE_SCOPE))
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    // The covering pre-authorization SKIPS the consent screen and issues a code directly.
    assert!(
        location_param(&headers, "code").is_some(),
        "a covered request issues a code without a consent screen: {:?}",
        location(&headers)
    );
    // It audits consent.skip with detail admin_preauthorized, targeting the client.
    let skips = consent_skip_audit(&harness).await;
    assert_eq!(
        skips,
        vec![("admin_preauthorized".to_string(), client_id)],
        "one consent.skip audit row naming the admin pre-authorization"
    );
}

#[tokio::test]
async fn a_covered_but_quarantined_client_still_sees_the_consent_screen() {
    // The admin pre-authorization grants ALLOWANCE, not consent-screen invisibility. A
    // quarantined (unverified) client that is admin-pre-authorized for the scope is let through
    // (not a terminal) but STILL shows the user a fresh consent screen, preserving the issue #31
    // "a quarantined client always re-prompts" property. No silent code, no consent.skip audit.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_third_party_admin_consent();
    let client_id = harness.client_id().to_string();
    harness
        .set_client_admin_grant(harness.client_id(), Some(NON_SENSITIVE_SCOPE))
        .await;
    harness
        .set_client_quarantined(harness.client_id(), true)
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_proceeds_to_consent(&headers);
    assert!(
        location_param(&headers, "code").is_none(),
        "a quarantined client is not silently auto-authorized even when admin-pre-authorized"
    );
    assert!(
        consent_skip_audit(&harness).await.is_empty(),
        "no consent.skip is audited when the consent screen is shown"
    );
}

#[tokio::test]
async fn a_covered_client_for_a_quarantined_user_still_sees_the_consent_screen() {
    // The mirror for a quarantined USER (issue #82): a covering admin pre-authorization does not
    // silently auto-authorize a quarantined user; the consent screen is still shown.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_third_party_admin_consent();
    harness.also_enable_signup_quarantine();
    let client_id = harness.client_id().to_string();
    harness
        .set_client_admin_grant(harness.client_id(), Some(NON_SENSITIVE_SCOPE))
        .await;

    let subject = harness.seed_unique_user().await;
    harness.set_user_quarantined(&subject, true).await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_proceeds_to_consent(&headers);
    assert!(
        location_param(&headers, "code").is_none(),
        "a quarantined user is not silently auto-authorized even when the client is pre-authorized"
    );
}

#[tokio::test]
async fn a_third_party_client_without_a_pre_authorization_is_a_terminal() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_third_party_admin_consent();
    let client_id = harness.client_id().to_string();

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_blocked(&headers);
}

#[tokio::test]
async fn the_admin_gate_dominates_a_prior_recorded_user_consent() {
    let mut harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;

    // A covering USER consent is recorded (while the gate is off): the recorded-consent fast path
    // would auto-authorize a later request.
    harness
        .grant_consent_scoped(&subject, &client_id, Some(NON_SENSITIVE_SCOPE))
        .await;

    // Now the third-party admin-consent gate is ON and NO admin pre-authorization exists. Despite
    // the covering user consent, the request is a terminal: the admin gate sits AHEAD of the
    // recorded-consent fast path.
    harness.enable_third_party_admin_consent();
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_blocked(&headers);
}

#[tokio::test]
async fn a_narrower_pre_authorization_does_not_cover_a_broader_request() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_third_party_admin_consent();
    let client_id = harness.client_id().to_string();
    // Pre-authorized only for `openid`; the request asks for `openid profile`.
    harness
        .set_client_admin_grant(harness.client_id(), Some("openid"))
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_blocked(&headers);
}

#[tokio::test]
async fn a_first_party_client_is_never_gated_by_the_admin_consent_gate() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_third_party_admin_consent();
    let client_id = harness.client_id().to_string();
    // A FIRST-PARTY client with no admin pre-authorization: exempt from the gate, so it proceeds
    // to the ordinary consent screen.
    harness
        .set_client_first_party(harness.client_id(), true)
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_proceeds_to_consent(&headers);
}

#[tokio::test]
async fn with_the_knob_off_a_third_party_client_proceeds_as_before() {
    // The gate is OFF (the harness default): a third-party client with no admin pre-authorization
    // proceeds to the consent screen exactly as before PR 4 existed.
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_proceeds_to_consent(&headers);
}

#[tokio::test]
async fn the_terminal_holds_under_prompt_none() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_third_party_admin_consent();
    let client_id = harness.client_id().to_string();

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "{}&prompt=none",
        authorize_query(&client_id, NON_SENSITIVE_SCOPE)
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    // A non-approvable terminal is access_denied even under prompt=none (NOT consent_required):
    // there is no user interaction that could satisfy it.
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("access_denied"),
        "prompt=none still yields the access_denied terminal: {:?}",
        location(&headers)
    );
}

#[tokio::test]
async fn a_store_fault_on_the_gate_read_fails_closed_to_server_error() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_third_party_admin_consent();
    let client_id = harness.client_id().to_string();

    // Break the data-plane read of the pre-authorization table, so the gate's store read errors.
    sqlx::query("REVOKE SELECT ON client_admin_grants FROM ironauth_app")
        .execute(harness.db().owner_pool())
        .await
        .expect("revoke app read");

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("server_error"),
        "a store fault on the gate read fails closed: {:?}",
        location(&headers)
    );
}

#[tokio::test]
async fn the_unverified_sensitive_block_still_fires_ahead_of_the_admin_gate() {
    // With BOTH gates on and a COVERING admin pre-authorization for a sensitive scope, a
    // quarantined third-party client is STILL blocked by the PR 3 sensitive-scope gate, which sits
    // ahead of the PR 4 admin gate: the pre-authorization can never let an unverified client
    // obtain a sensitive scope.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_third_party_admin_consent();
    let client_id = harness.client_id().to_string();
    harness
        .set_client_quarantined(harness.client_id(), true)
        .await;
    harness
        .set_client_admin_grant(harness.client_id(), Some(SENSITIVE_SCOPE))
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_blocked(&headers);
}

#[tokio::test]
async fn the_first_party_carve_out_audits_a_skipped_consent_when_not_stored() {
    // The audit-completeness fix (issue #88, PR 4): a first-party carve-out with
    // store_skipped_consent = false auto-grants WITHOUT persisting a consent row, and must now
    // write exactly one consent.skip audit row naming the client.
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    // implicit/skip_consent carve-out, but the no-store knob is off.
    harness
        .configure_client_policy(harness.client_id(), "explicit", true, false, None)
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "the carve-out auto-grants a code: {:?}",
        location(&headers)
    );
    let skips = consent_skip_audit(&harness).await;
    assert_eq!(
        skips,
        vec![("first_party_carveout".to_string(), client_id)],
        "one consent.skip audit row for the un-stored first-party carve-out"
    );
}

#[tokio::test]
async fn the_stored_first_party_carve_out_still_audits_exactly_one_consent_grant() {
    // The store_skipped_consent = true path is UNCHANGED: it persists the consent (one
    // consent.grant audit row) and writes NO consent.skip, so there is no double-audit.
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    harness
        .configure_client_policy(harness.client_id(), "explicit", true, true, None)
        .await;

    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(&client_id, NON_SENSITIVE_SCOPE), &cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert!(
        location_param(&headers, "code").is_some(),
        "a code is issued"
    );

    let rows = harness
        .store()
        .scoped(harness.scope())
        .audit()
        .list()
        .await
        .expect("audit list");
    let grants = rows.iter().filter(|r| r.action == "consent.grant").count();
    let skips = rows.iter().filter(|r| r.action == "consent.skip").count();
    assert_eq!(grants, 1, "exactly one consent.grant");
    assert_eq!(skips, 0, "no consent.skip when the consent is stored");
}
