// SPDX-License-Identifier: MIT OR Apache-2.0

//! The refresh-token grant end to end (issue #21), against a real Postgres: the
//! graduated rotation policy (public/unbound rotate every refresh, confidential
//! under the TTL threshold do not), reuse detection over the HTTP surface, the
//! `offline_access` consent rule for web clients with its trusted first-party
//! carve-out, and the three per-client consent modes.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Harness, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location, location_param};
use ironauth_oidc::ClientAuthMethod;

/// A standard-padded Basic credential of `client_id:client_secret`.
fn basic_header(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// The authorization-code token exchange form WITH PKCE (a public client always
/// requires PKCE), so the harness's default public client can be driven through the
/// exchange.
fn code_form_pkce(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

/// The refresh-token grant form for a public client (`client_id` in the body, no
/// secret).
fn refresh_form(refresh_token: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ])
}

/// Exchange a fresh code for the harness's default PUBLIC client and return the
/// issued refresh token.
async fn public_refresh_token(harness: &Harness) -> (String, String) {
    let client_id = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let (status, _, body) = harness.token(&code_form_pkce(&code, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "code exchange: {body}");
    let refresh = json(&body)["refresh_token"]
        .as_str()
        .expect("a refresh token is issued for the code flow")
        .to_owned();
    (client_id, refresh)
}

#[tokio::test]
async fn a_public_client_rotates_the_refresh_token_on_every_refresh() {
    // Acceptance criterion 3: a public (sender-unbound) client rotates on EVERY
    // refresh.
    let harness = Harness::start().await;
    let (client_id, r0) = public_refresh_token(&harness).await;

    let (status, _, body) = harness.token(&refresh_form(&r0, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "first refresh: {body}");
    let value = json(&body);
    assert_eq!(value["token_type"], "Bearer");
    assert!(value["access_token"].is_string(), "a fresh access token");
    let r1 = value["refresh_token"]
        .as_str()
        .expect("rotated refresh token");
    assert_ne!(r1, r0, "a public client rotates the refresh token");

    // A second refresh rotates again.
    let (status, _, body) = harness.token(&refresh_form(r1, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "second refresh: {body}");
    let r2 = json(&body)["refresh_token"]
        .as_str()
        .expect("rotated again")
        .to_owned();
    assert_ne!(r2, r1, "every refresh rotates for a public client");
}

#[tokio::test]
async fn a_confidential_client_under_the_ttl_threshold_keeps_the_same_refresh_token() {
    // Acceptance criterion 3: a confidential client rotates ONLY once past the TTL
    // threshold (default 70%). A just-issued token (0% elapsed) is refreshed WITHOUT
    // rotation: a fresh access token, the SAME refresh token.
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let auth = basic_header(&client_id, &secret);

    let code = harness.issue_authenticated_code(&client_id).await;
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
    ]);
    let (status, _, body) = harness.token_with_auth(&exchange, Some(&auth)).await;
    assert_eq!(status, StatusCode::OK, "code exchange: {body}");
    let r0 = json(&body)["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned();

    let refresh = form(&[("grant_type", "refresh_token"), ("refresh_token", &r0)]);
    let (status, _, body) = harness.token_with_auth(&refresh, Some(&auth)).await;
    assert_eq!(status, StatusCode::OK, "refresh: {body}");
    let value = json(&body);
    assert!(value["access_token"].is_string(), "a fresh access token");
    assert_eq!(
        value["refresh_token"].as_str(),
        Some(r0.as_str()),
        "a confidential client under the threshold keeps the same refresh token"
    );
}

#[tokio::test]
async fn a_reused_refresh_token_outside_grace_is_invalid_grant_and_revokes_the_family() {
    // Acceptance criterion 1 (end to end): a superseded refresh token presented
    // beyond the grace window is invalid_grant, revokes the whole family, and emits
    // the typed reuse event exactly once.
    let harness = Harness::start().await;
    let (client_id, r0) = public_refresh_token(&harness).await;

    // Rotate R0 -> R1 (frozen clock).
    let (status, _, body) = harness.token(&refresh_form(&r0, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "rotate: {body}");
    let r1 = json(&body)["refresh_token"]
        .as_str()
        .expect("rotated")
        .to_owned();

    // Advance past the default 10-second grace and replay the superseded R0.
    harness.clock().advance(Duration::from_secs(30));
    let (status, _, body) = harness.token(&refresh_form(&r0, &client_id)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "reuse: {body}");
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert_eq!(
        harness.count_audit_action("refresh_token.reuse").await,
        1,
        "exactly one typed reuse event"
    );

    // The reuse revoked the WHOLE family: the once-live successor R1 no longer
    // refreshes.
    let (status, _, body) = harness.token(&refresh_form(&r1, &client_id)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the successor is dead after the family revoke: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert_eq!(
        harness.count_audit_action("refresh_token.reuse").await,
        1,
        "the dead-successor refresh finds an already-revoked family, so no new reuse event"
    );
}

#[tokio::test]
async fn concurrent_refreshes_within_grace_both_succeed() {
    // Acceptance criterion 2 (end to end): two presentations of the same token within
    // the grace window both succeed (multi-tab / retry), without locking the user out.
    let harness = Harness::start().await;
    let (client_id, r0) = public_refresh_token(&harness).await;

    // First refresh rotates R0.
    let (status, _, body) = harness.token(&refresh_form(&r0, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "first: {body}");
    // A second presentation of the SAME R0 within the (frozen-clock) grace window is a
    // benign concurrent refresh: it succeeds and hands out a fresh token.
    let (status, _, body) = harness.token(&refresh_form(&r0, &client_id)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "within-grace concurrent refresh: {body}"
    );
    assert!(json(&body)["refresh_token"].is_string());
    assert_eq!(
        harness.count_audit_action("refresh_token.reuse").await,
        0,
        "a within-grace concurrent refresh never trips reuse detection"
    );
}

/// Authorize (as an authenticated subject) with an explicit scope and cookie,
/// returning the response.
async fn authorize_scope(
    harness: &Harness,
    client_id: &str,
    scope: &str,
    cookie: &str,
) -> (StatusCode, String, Option<String>) {
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}",
        enc(REDIRECT_URI),
        enc(scope),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, cookie).await;
    let loc = location(&headers);
    let code = location_param(&headers, "code");
    let _ = body;
    (status, loc.unwrap_or_default(), code)
}

#[tokio::test]
async fn offline_access_on_a_web_client_requires_explicit_consent() {
    // Acceptance criterion 5: a web (explicit-consent) client requesting
    // offline_access must consent to it; a prior consent that does NOT cover
    // offline_access re-prompts, and one that does issues the code.
    let harness = Harness::start().await;
    let (client, _secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();

    // A subject who consented to `openid` only.
    let subject = harness.seed_unique_user().await;
    harness
        .grant_consent_scoped(&subject, &client_id, Some("openid"))
        .await;
    let cookie = harness.session_cookie(&subject).await;

    // Requesting offline_access on top is NOT covered: re-prompt to consent.
    let (status, loc, code) =
        authorize_scope(&harness, &client_id, "openid offline_access", &cookie).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        code.is_none(),
        "no code is issued without offline_access consent"
    );
    assert!(
        loc.starts_with("/consent?return_to="),
        "offline_access on a web client routes to consent: {loc}"
    );

    // A subject who consented to offline_access proceeds straight to a code.
    let consented = harness.seed_unique_user().await;
    harness
        .grant_consent_scoped(&consented, &client_id, Some("openid offline_access"))
        .await;
    let cookie = harness.session_cookie(&consented).await;
    let (status, _loc, code) =
        authorize_scope(&harness, &client_id, "openid offline_access", &cookie).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        code.is_some(),
        "a covering offline_access consent issues the code"
    );
}

#[tokio::test]
async fn a_trusted_first_party_client_skips_offline_access_consent() {
    // Acceptance criterion 5: the trusted first-party carve-out. An implicit-mode
    // client auto-grants, so offline_access needs no consent screen.
    let harness = Harness::start().await;
    let (client, _secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    harness
        .configure_client_policy(&client, "implicit", false, true, None)
        .await;

    // No prior consent at all.
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, _loc, code) =
        authorize_scope(&harness, &client_id, "openid offline_access", &cookie).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        code.is_some(),
        "a first-party client is auto-granted, offline_access included"
    );
}

#[tokio::test]
async fn consent_mode_explicit_prompts_and_implicit_auto_grants_with_the_store_knob() {
    // Acceptance criterion 6: explicit mode prompts (no covering consent); implicit
    // mode auto-grants and, per the no-store knob, either DOES or does NOT persist a
    // consent row.
    let harness = Harness::start().await;

    // Explicit (the default): an un-consented request re-prompts.
    let (explicit, _s) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let explicit_id = explicit.to_string();
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, loc, code) = authorize_scope(&harness, &explicit_id, "openid", &cookie).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(code.is_none(), "explicit mode prompts");
    assert!(loc.starts_with("/consent?return_to="), "to consent: {loc}");

    // Implicit + store_skipped_consent = true: auto-grant AND persist a consent row.
    let (implicit_store, _s) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let implicit_store_id = implicit_store.to_string();
    harness
        .configure_client_policy(&implicit_store, "implicit", false, true, None)
        .await;
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, _loc, code) =
        authorize_scope(&harness, &implicit_store_id, "openid", &cookie).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(code.is_some(), "implicit mode auto-grants");
    assert!(
        harness
            .store()
            .scoped(harness.scope())
            .consents()
            .granted_ref(&subject, &implicit_store_id)
            .await
            .expect("read consent")
            .is_some(),
        "the skipped consent is persisted with the store knob on"
    );

    // Implicit + store_skipped_consent = false: auto-grant, persist NOTHING (the Ory
    // Hydra performance knob).
    let (implicit_nostore, _s) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let implicit_nostore_id = implicit_nostore.to_string();
    harness
        .configure_client_policy(&implicit_nostore, "implicit", false, false, None)
        .await;
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, _loc, code) =
        authorize_scope(&harness, &implicit_nostore_id, "openid", &cookie).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        code.is_some(),
        "implicit mode auto-grants even without storing"
    );
    assert!(
        harness
            .store()
            .scoped(harness.scope())
            .consents()
            .granted_ref(&subject, &implicit_nostore_id)
            .await
            .expect("read consent")
            .is_none(),
        "no consent row is stored with the no-store knob"
    );
}

#[tokio::test]
async fn a_remembered_consent_lapses_after_its_ttl() {
    // Acceptance criterion 6: a remembered consent is honored until its TTL, then the
    // next authorization re-prompts.
    let harness = Harness::start().await;
    let (client, _s) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    harness
        .configure_client_policy(&client, "remembered", false, true, None)
        .await;

    // A consent that expires 100 seconds after the epoch (the frozen clock).
    let subject = harness.seed_unique_user().await;
    harness
        .grant_consent_with_expiry(&subject, &client_id, Some("openid"), Some(100_000_000))
        .await;
    let cookie = harness.session_cookie(&subject).await;

    // Within the TTL: the remembered consent covers the request, so a code issues.
    let (status, _loc, code) = authorize_scope(&harness, &client_id, "openid", &cookie).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(code.is_some(), "a live remembered consent issues the code");

    // Past the TTL: the consent has lapsed, so the next authorization re-prompts.
    harness.clock().advance(Duration::from_secs(200));
    let (status, loc, code) = authorize_scope(&harness, &client_id, "openid", &cookie).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(code.is_none(), "an expired remembered consent re-prompts");
    assert!(loc.starts_with("/consent?return_to="), "to consent: {loc}");
}
