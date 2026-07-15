// SPDX-License-Identifier: MIT OR Apache-2.0

//! The refresh-token grant end to end (issue #21), against a real Postgres: the
//! graduated rotation policy (public/unbound rotate every refresh, confidential
//! under the TTL threshold do not), reuse detection over the HTTP surface, the
//! `offline_access` consent rule for web clients with its trusted first-party
//! carve-out, and the three per-client consent modes.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{
    Harness, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location, location_param, send_through,
};
use ironauth_config::OidcConfig;
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::{ActorRef, ServiceId};

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
async fn concurrent_refreshes_within_grace_both_succeed_and_converge() {
    // Acceptance criterion 2 (end to end), hardened (issue #21 adversarial FIX 1): two
    // presentations of the same token within the grace window both succeed (multi-tab
    // / retry), without locking the user out, AND the family converges on exactly one
    // live leaf. The within-grace loser gets a fresh ACCESS token but NO new refresh
    // token (RFC 6749 5.1 makes it optional): minting a second leaf would fork the
    // family, so the field is omitted instead.
    let harness = Harness::start().await;
    let (client_id, r0) = public_refresh_token(&harness).await;
    let family = harness
        .resolve_refresh(&r0)
        .await
        .expect("r0 recorded")
        .family_id;
    assert_eq!(
        harness.count_live_refresh_leaves(&family).await,
        1,
        "one live leaf at issuance"
    );

    // First refresh rotates R0 -> R1 (the winner). R1 is the family's live leaf.
    let (status, _, body) = harness.token(&refresh_form(&r0, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "first: {body}");
    let r1 = json(&body)["refresh_token"]
        .as_str()
        .expect("winner rotates")
        .to_owned();
    assert_eq!(
        harness.count_live_refresh_leaves(&family).await,
        1,
        "after the rotate the successor is the one live leaf"
    );

    // A second presentation of the SAME R0 within the (frozen-clock) grace window is a
    // benign concurrent refresh: it succeeds with a fresh access token but hands out NO
    // new refresh token, so the family does NOT fork.
    let (status, _, body) = harness.token(&refresh_form(&r0, &client_id)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "within-grace concurrent refresh: {body}"
    );
    let value = json(&body);
    assert!(
        value["access_token"].is_string(),
        "the loser still gets a fresh access token (no lockout)"
    );
    assert!(
        value.get("refresh_token").is_none(),
        "the within-grace loser mints no new refresh leaf, so refresh_token is omitted"
    );
    assert_eq!(
        harness.count_live_refresh_leaves(&family).await,
        1,
        "the family CONVERGES on exactly one live leaf, never forks"
    );

    // The one live leaf is the winner's successor R1: it still refreshes.
    let (status, _, body) = harness.token(&refresh_form(&r1, &client_id)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the one live leaf still works: {body}"
    );
    assert_eq!(
        harness.count_audit_action("refresh_token.reuse").await,
        0,
        "a within-grace concurrent refresh never trips reuse detection"
    );
}

#[tokio::test]
async fn a_confidential_client_rotates_once_past_the_ttl_threshold() {
    // Issue #21 adversarial FIX 2: the confidential rotate-PAST-70%-TTL branch of
    // decide_rotate, exercised end to end (the store test drives `rotate` as an
    // explicit bool; the other HTTP test only covers 0% elapsed = no rotation). A
    // short 1000-second idle TTL puts the default 70% threshold at a clean t=700s: a
    // refresh just below it does NOT rotate (pinning the boundary from below), and one
    // past it DOES.
    let harness = Harness::start_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        refresh_idle_ttl_secs: 1000,
        ..OidcConfig::default()
    })
    .await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let auth = basic_header(&client_id, &secret);

    // Exchange a code -> r0 (issued at t=0, idle 1000s, so the rotation threshold is
    // t=700s).
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

    // Just BELOW the threshold (t=600 < 700): a refresh does NOT rotate; the SAME
    // refresh token comes back and r0 stays live (unrotated).
    harness.clock().advance(Duration::from_secs(600));
    let refresh = form(&[("grant_type", "refresh_token"), ("refresh_token", &r0)]);
    let (status, _, body) = harness.token_with_auth(&refresh, Some(&auth)).await;
    assert_eq!(status, StatusCode::OK, "below-threshold refresh: {body}");
    assert_eq!(
        json(&body)["refresh_token"].as_str(),
        Some(r0.as_str()),
        "below the 70% threshold a confidential client does NOT rotate"
    );
    assert!(
        !harness
            .resolve_refresh(&r0)
            .await
            .expect("r0 recorded")
            .rotated,
        "r0 is still live below the threshold"
    );

    // Cross the threshold (advance to t=800 > 700): the next refresh DOES rotate; a
    // NEW refresh token is returned and r0 becomes superseded.
    harness.clock().advance(Duration::from_secs(200));
    let (status, _, body) = harness.token_with_auth(&refresh, Some(&auth)).await;
    assert_eq!(status, StatusCode::OK, "past-threshold refresh: {body}");
    let r1 = json(&body)["refresh_token"]
        .as_str()
        .expect("rotated token")
        .to_owned();
    assert_ne!(
        r1, r0,
        "past the 70% threshold a confidential client rotates"
    );
    assert!(
        harness
            .resolve_refresh(&r0)
            .await
            .expect("r0 recorded")
            .rotated,
        "the past-threshold rotation supersedes r0"
    );
}

#[tokio::test]
async fn the_reuse_event_has_a_locked_siem_facing_shape() {
    // Issue #21 adversarial FIX 3: a shape-lock snapshot of the SIEM-facing
    // refresh_token.reuse audit row, so its shape cannot drift silently (an explicit
    // sub-AC of the issue). Drives a genuine reuse (rotate, then replay the superseded
    // token beyond grace) and locks the whole envelope: the action verb, the client
    // service-actor, the target (the family id), the correlation, and the reuse
    // instant from the clock seam.
    let harness = Harness::start().await;
    let (client_id, r0) = public_refresh_token(&harness).await;
    let family = harness
        .resolve_refresh(&r0)
        .await
        .expect("r0 recorded")
        .family_id;

    // Rotate R0, then advance past the grace window and replay the superseded R0.
    let (status, _, _) = harness.token(&refresh_form(&r0, &client_id)).await;
    assert_eq!(status, StatusCode::OK);
    harness.clock().advance(Duration::from_secs(30));
    let (status, _, body) = harness.token(&refresh_form(&r0, &client_id)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "reuse: {body}");

    // Exactly one reuse row; lock its full shape.
    let reuse_rows: Vec<_> = harness
        .store()
        .scoped(harness.scope())
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .filter(|row| row.action == "refresh_token.reuse")
        .collect();
    assert_eq!(reuse_rows.len(), 1, "exactly one reuse event");
    let row = &reuse_rows[0];

    // action: the stable dotted verb the OCSF/SIEM mapping keys on.
    assert_eq!(row.action, "refresh_token.reuse");
    // actor: the client's stable service-actor (svc_), derived from the client id
    // exactly as the token endpoint attributes it.
    let expected_actor = ActorRef::service(ServiceId::from_seed_bytes(
        harness.client_id().unique_bytes(),
    ));
    assert_eq!(
        row.actor, expected_actor,
        "attributed to the client service-actor"
    );
    assert_eq!(row.actor.kind_str(), "service");
    assert!(row.actor.id_string().starts_with("svc_"));
    // target: the family id (the revocation spine), a rff_ scoped id.
    assert_eq!(row.target_kind, "rff", "target kind is the refresh family");
    assert_eq!(
        row.target_id,
        family.to_string(),
        "target is the reused family"
    );
    // correlation: a req_ id links the row to the causing request.
    assert!(
        row.correlation_id.to_string().starts_with("req_"),
        "correlated to the causing request"
    );
    // the reuse was recorded at the (advanced) clock instant, from the seam.
    assert_eq!(
        row.occurred_at_unix_micros, 30_000_000,
        "reuse instant from the clock seam"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_refreshes_within_grace_converge_on_one_live_leaf() {
    // Issue #21 adversarial FIX 4 (the HTTP-layer regression guard for FIX 1): fire N
    // TRUE-parallel refreshes of the SAME token within the grace window through routers
    // sharing one store pool. All succeed (no lockout); exactly ONE is the atomic-
    // rotate winner and returns a new refresh token; the rest return only a fresh
    // access token; the family ends with EXACTLY ONE live leaf and NO reuse event. This
    // is a faithful stand-in for N stateless nodes racing on the same database.
    const RACERS: usize = 8;

    let harness = Harness::start().await;
    let (client_id, r0) = public_refresh_token(&harness).await;
    let family = harness
        .resolve_refresh(&r0)
        .await
        .expect("r0 recorded")
        .family_id;

    // Fire RACERS concurrent refreshes at once, each through a cloned router.
    let mut tasks = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let router = harness.router();
        let body = refresh_form(&r0, &client_id);
        tasks.push(tokio::spawn(async move {
            let request = Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("request builds");
            send_through(router, request).await
        }));
    }

    let mut ok = 0_usize;
    let mut with_refresh = 0_usize;
    let mut winner = None;
    for task in tasks {
        let (status, _headers, body) = task.await.expect("task joins");
        assert_eq!(
            status,
            StatusCode::OK,
            "every within-grace parallel refresh succeeds: {body}"
        );
        let value = json(&body);
        assert!(
            value["access_token"].is_string(),
            "each racer gets a fresh access token"
        );
        ok += 1;
        if let Some(rt) = value.get("refresh_token").and_then(|v| v.as_str()) {
            with_refresh += 1;
            winner = Some(rt.to_owned());
        }
    }
    assert_eq!(ok, RACERS, "all parallel refreshes succeed (no lockout)");
    assert_eq!(
        with_refresh, 1,
        "exactly one winner mints a new refresh token; every loser omits it"
    );

    // The family CONVERGES on exactly one live leaf, the winner's successor.
    assert_eq!(
        harness.count_live_refresh_leaves(&family).await,
        1,
        "N parallel within-grace refreshes converge on one live leaf, never fork"
    );
    let winner = winner.expect("one winner produced a refresh token");
    assert!(
        harness
            .resolve_refresh(&winner)
            .await
            .expect("winner recorded")
            .active,
        "the one live leaf is the winner's successor"
    );
    assert_eq!(
        harness.count_audit_action("refresh_token.reuse").await,
        0,
        "a within-grace parallel refresh never trips reuse detection"
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
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
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(code.is_some(), "a live remembered consent issues the code");

    // Past the TTL: the consent has lapsed, so the next authorization re-prompts.
    harness.clock().advance(Duration::from_secs(200));
    let (status, loc, code) = authorize_scope(&harness, &client_id, "openid", &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(code.is_none(), "an expired remembered consent re-prompts");
    assert!(loc.starts_with("/consent?return_to="), "to consent: {loc}");
}

/// Issue a LIVE `offline_access` refresh token for a fresh, active user against a
/// trusted first-party (implicit-consent) confidential client, returning
/// `(subject, client_id, secret, refresh_token)`. The `offline_access` family
/// SURVIVES an RP logout / session cascade by construction (issue #21), so it is
/// exactly the token a lifecycle fence must still stop from minting (issue #52).
async fn offline_refresh_token_for_new_user(harness: &Harness) -> (String, String, String, String) {
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    // A trusted first-party client auto-grants, so offline_access needs no consent
    // screen and the code issues straight away.
    harness
        .configure_client_policy(&client, "implicit", false, true, None)
        .await;
    let subject = harness.seed_unique_user().await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, _loc, code) =
        authorize_scope(harness, &client_id, "openid offline_access", &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let code = code.expect("a first-party offline_access authorization issues a code");
    let auth = basic_header(&client_id, &secret);
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
    ]);
    let (status, _, body) = harness.token_with_auth(&exchange, Some(&auth)).await;
    assert_eq!(status, StatusCode::OK, "offline code exchange: {body}");
    let refresh = json(&body)["refresh_token"]
        .as_str()
        .expect("an offline_access code exchange issues a refresh token")
        .to_owned();
    (subject, client_id, secret, refresh)
}

#[tokio::test]
async fn a_fenced_user_cannot_mint_new_tokens_through_a_surviving_offline_token() {
    // Issue #52 (the milestone-core fence-completeness property): block/disable/delete
    // must stop a user from obtaining new tokens by ANY path, including a SURVIVING
    // offline_access refresh family (which the block/disable cascade deliberately
    // leaves live, issue #21). Without the refresh-grant's user-lifecycle re-check a
    // blocked user keeps minting fresh access tokens through that token, so the account
    // is not actually fenced. The refresh grant re-checks the subject's lifecycle and
    // fails closed BEFORE minting.
    let harness = Harness::start().await;
    let (subject, client_id, secret, refresh) = offline_refresh_token_for_new_user(&harness).await;
    let auth = basic_header(&client_id, &secret);
    let refresh_body = form(&[("grant_type", "refresh_token"), ("refresh_token", &refresh)]);

    // NORMAL active user: the offline token refreshes and mints a fresh access token.
    // A confidential client under the rotation threshold (frozen clock, 0% elapsed)
    // keeps the SAME refresh token, so it stays live for the fence checks below.
    let (status, _, body) = harness.token_with_auth(&refresh_body, Some(&auth)).await;
    assert_eq!(status, StatusCode::OK, "active user refresh: {body}");
    assert!(
        json(&body)["access_token"].is_string(),
        "a normal active user's offline refresh mints an access token"
    );
    assert_eq!(
        json(&body)["refresh_token"].as_str(),
        Some(refresh.as_str()),
        "the confidential client keeps the same refresh token under the threshold"
    );

    // BLOCKED: the same offline token now mints NOTHING.
    harness
        .set_user_state(&subject, ironauth_store::UserState::Blocked)
        .await;
    let (status, _, body) = harness.token_with_auth(&refresh_body, Some(&auth)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "blocked user refresh: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        json(&body).get("access_token").is_none(),
        "a blocked user's refresh mints no access token"
    );

    // DISABLED (a distinct, non-authenticatable state): still fenced.
    harness
        .set_user_state(&subject, ironauth_store::UserState::Disabled)
        .await;
    let (status, _, body) = harness.token_with_auth(&refresh_body, Some(&auth)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "disabled user refresh: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        json(&body).get("access_token").is_none(),
        "a disabled user's refresh mints no access token"
    );

    // DELETED (a soft-delete tombstone that reads as absent): still fenced, fail closed.
    harness.delete_user(&subject).await;
    let (status, _, body) = harness.token_with_auth(&refresh_body, Some(&auth)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "deleted user refresh: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_grant");
    assert!(
        json(&body).get("access_token").is_none(),
        "a deleted user's refresh mints no access token"
    );

    // A SEPARATE, untouched active user's offline token still refreshes: the fence is
    // targeted, not a blanket break of the refresh grant.
    let (_other, other_client, other_secret, other_refresh) =
        offline_refresh_token_for_new_user(&harness).await;
    let other_body = form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", &other_refresh),
    ]);
    let (status, _, body) = harness
        .token_with_auth(
            &other_body,
            Some(&basic_header(&other_client, &other_secret)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "untouched user refresh: {body}");
    assert!(
        json(&body)["access_token"].is_string(),
        "a normal active user's refresh is unaffected by another user's fence"
    );
}
