// SPDX-License-Identifier: MIT OR Apache-2.0

//! RP-Initiated Logout (OIDC RP-Initiated Logout 1.0, issue #33), end to end over the
//! live `end_session` endpoint against a real Postgres. These pin what a relying party
//! and an attacker actually observe:
//!
//! - a verifiable `id_token_hint` ends the SSO session synchronously (the hydra#4070
//!   race: the very next authorization request no longer authenticates), clears the
//!   cookie, and redirects ONLY on an exact registered `post_logout_redirect_uri` match,
//!   echoing `state`;
//! - an EXPIRED hint still validates for logout targeting;
//! - a near-miss or unregistered `post_logout_redirect_uri` NEVER redirects (no open
//!   redirector), and an unverifiable / absent hint renders a confirmation prompt and
//!   changes nothing until a same-origin POST confirms it;
//! - `offline_access` families survive the logout, and a foreign tenant's session is
//!   untouched.

mod common;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location, location_param,
};
use ironauth_config::OidcConfig;
use ironauth_oidc::SESSION_COOKIE;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, NewRefreshFamily, NewSession,
    RefreshFamilyId, RefreshTokenId, Scope, SessionId, refresh_token_digest,
};
use serde_json::Value;
use std::time::Duration;

/// Re-sign `hint`'s claims with the environment's LIVE signing key after DROPPING the
/// `sid` claim: a validly-signed, correctly-audienced `id_token_hint` that carries no
/// cryptographic tie to any specific session.
async fn hint_without_sid(harness: &Harness, hint: &str) -> String {
    let segment = hint.split('.').nth(1).expect("payload segment");
    let bytes = URL_SAFE_NO_PAD.decode(segment).expect("base64url payload");
    let mut claims: serde_json::Map<String, Value> =
        serde_json::from_slice(&bytes).expect("claims json");
    claims.remove("sid");
    assert!(!claims.contains_key("sid"), "the sid claim is dropped");
    harness.sign_at_jwt(&Value::Object(claims)).await
}

const SELF_ORIGIN: &str = "https://issuer.test";

/// The authorization query for `client_id` (public harness clients require PKCE).
fn authorize_query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&state=xyz&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
    )
}

/// Drive authorize + token for `client_id` with `cookie` and return the RAW id token
/// (the string an RP later presents as `id_token_hint`).
async fn mint_id_token(harness: &Harness, client_id: &str, cookie: &str) -> String {
    let (status, headers, body) = harness
        .authorize_with_cookie(&authorize_query(client_id), cookie)
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");
    let token_form = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _, body) = harness.token(&token_form).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    json(&body)["id_token"]
        .as_str()
        .expect("id_token present")
        .to_owned()
}

/// A consenting cookie session for the harness client, and its session id.
async fn seeded_session(harness: &Harness) -> (SessionId, String) {
    let subject = harness.seed_unique_user().await;
    harness
        .grant_consent(&subject, &harness.client_id().to_string())
        .await;
    harness.session_with_id(&subject, "pwd", 0).await
}

/// `GET /end_session?{query}` with the browser's session cookie.
async fn get_end_session(
    harness: &Harness,
    query: &str,
    cookie: &str,
) -> (StatusCode, HeaderMap, String) {
    harness
        .get_with_cookie(&format!("/end_session?{query}"), Some(cookie))
        .await
}

/// `POST /end_session` with a form body, an optional cookie, and optional CSRF headers
/// (Origin / Sec-Fetch-Site) for the confirmation-submit path.
async fn post_end_session(
    harness: &Harness,
    body: &str,
    cookie: Option<&str>,
    origin: Option<&str>,
    fetch_site: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/end_session")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    if let Some(site) = fetch_site {
        builder = builder.header("sec-fetch-site", site);
    }
    harness
        .send(
            builder
                .body(Body::from(body.to_owned()))
                .expect("request builds"),
        )
        .await
}

/// Whether the harness session still authenticates the authorization endpoint (a live
/// session issues a code; a dead one bounces to `/login`).
async fn session_still_authenticates(harness: &Harness, cookie: &str) -> bool {
    let (status, headers, _) = harness
        .authorize_with_cookie(&authorize_query(&harness.client_id().to_string()), cookie)
        .await;
    let location = location(&headers).unwrap_or_default();
    status == StatusCode::SEE_OTHER && location.contains("code=")
}

/// Assert a response cleared the session cookie (`Max-Age=0`).
fn assert_cookie_cleared(headers: &HeaderMap) {
    let set_cookie = headers
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        set_cookie.contains(SESSION_COOKIE) && set_cookie.contains("Max-Age=0"),
        "logout must clear the session cookie: {set_cookie}"
    );
}

#[tokio::test]
async fn verifiable_hint_ends_the_session_clears_the_cookie_and_redirects_with_state() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_session_id, cookie) = seeded_session(&harness).await;
    harness
        .register_post_logout_redirects(harness.client_id(), &["https://client.test/after"])
        .await;

    let hint = mint_id_token(&harness, &client_id, &cookie).await;

    // Baseline: the session authenticates.
    assert!(session_still_authenticates(&harness, &cookie).await);

    let query = format!(
        "id_token_hint={}&post_logout_redirect_uri={}&state=abc123",
        enc(&hint),
        enc("https://client.test/after"),
    );
    let (status, headers, body) = get_end_session(&harness, &query, &cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "redirect on exact match: {body}"
    );
    let loc = location(&headers).expect("location");
    assert!(
        loc.starts_with("https://client.test/after"),
        "redirect to the registered uri: {loc}"
    );
    assert_eq!(
        location_param(&headers, "state").as_deref(),
        Some("abc123"),
        "state round-trips to the redirect target"
    );
    assert_cookie_cleared(&headers);

    // The race regression (hydra#4070): the session is dead in Postgres BEFORE the
    // response, so a fresh authorization no longer authenticates, and prompt=none is
    // login_required rather than a silent re-login.
    assert!(
        !session_still_authenticates(&harness, &cookie).await,
        "the SSO session must be dead immediately after logout"
    );
    let (status, headers, body) = harness
        .authorize_with_cookie(
            &format!("{}&prompt=none", authorize_query(&client_id)),
            &cookie,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "prompt=none error redirect: {body}"
    );
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("login_required"),
        "an immediate silent re-auth after logout is login_required"
    );
}

#[tokio::test]
async fn an_expired_hint_still_validates_for_logout_targeting() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_session_id, cookie) = seeded_session(&harness).await;
    let hint = mint_id_token(&harness, &client_id, &cookie).await;

    // Age the hint far past its exp (the session runs to the year 2100, so it stays
    // live; only the id token expires). A normal verify would now reject it as Expired;
    // RP-Initiated Logout accepts it for TARGETING (allow_expired), nothing else relaxed.
    harness
        .clock()
        .advance(Duration::from_secs(100 * 24 * 3600));

    let query = format!("id_token_hint={}", enc(&hint));
    let (status, headers, body) = get_end_session(&harness, &query, &cookie).await;
    // No registered post-logout uri, so a neutral logged-out page, cookie cleared.
    assert_eq!(status, StatusCode::OK, "logged-out page: {body}");
    assert_cookie_cleared(&headers);
    assert!(
        !session_still_authenticates(&harness, &cookie).await,
        "an expired hint still ends the session it targets"
    );
}

#[tokio::test]
async fn a_near_miss_post_logout_uri_is_rejected_without_redirecting() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    harness
        .register_post_logout_redirects(harness.client_id(), &["https://client.test/after"])
        .await;

    // Case change, trailing slash, and an extra path segment are all NON-matches under
    // exact string comparison (RFC 9700 section 2.1); none may redirect. Each case gets
    // its own session so the "still ended" assertion is independent.
    for near_miss in [
        "https://client.test/After",
        "https://client.test/after/",
        "https://client.test/after/extra",
        "https://client.test/other",
    ] {
        let (_id, cookie) = seeded_session(&harness).await;
        let hint = mint_id_token(&harness, &client_id, &cookie).await;
        let query = format!(
            "id_token_hint={}&post_logout_redirect_uri={}&state=zz",
            enc(&hint),
            enc(near_miss),
        );
        let (status, headers, body) = get_end_session(&harness, &query, &cookie).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a near-miss uri gets the logged-out page, never a redirect ({near_miss}): {body}"
        );
        assert!(
            location(&headers).is_none(),
            "no Location header for a non-matching post_logout_redirect_uri ({near_miss})"
        );
        // The session is still ended (logout succeeds; only the redirect is withheld).
        assert!(!session_still_authenticates(&harness, &cookie).await);
    }
}

#[tokio::test]
async fn an_attacker_supplied_unregistered_uri_never_becomes_an_open_redirect() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_session_id, cookie) = seeded_session(&harness).await;
    // The client registered NO post-logout uris at all.
    let hint = mint_id_token(&harness, &client_id, &cookie).await;

    let query = format!(
        "id_token_hint={}&post_logout_redirect_uri={}&state=zz",
        enc(&hint),
        enc("https://evil.example/steal"),
    );
    let (status, headers, body) = get_end_session(&harness, &query, &cookie).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "no redirect to an attacker uri: {body}"
    );
    assert!(
        location(&headers).is_none(),
        "an unregistered post_logout_redirect_uri is never honored"
    );
    assert_cookie_cleared(&headers);
}

#[tokio::test]
async fn an_unverifiable_hint_on_get_renders_a_confirmation_and_changes_nothing() {
    let harness = Harness::start().await;
    let (_session_id, cookie) = seeded_session(&harness).await;

    // A garbage (unverifiable) hint is NOT attributable, so a GET must NOT end the
    // session: it shows a confirmation prompt (CSRF defense).
    let query = format!("id_token_hint={}", enc("not.a.jwt"));
    let (status, headers, body) = get_end_session(&harness, &query, &cookie).await;
    assert_eq!(status, StatusCode::OK, "confirmation page: {body}");
    assert!(
        body.contains("Sign out") && body.contains("<form"),
        "an unattributable logout renders a confirmation form: {body}"
    );
    assert!(
        location(&headers).is_none() && headers.get(header::SET_COOKIE).is_none(),
        "the confirmation page performs NO state change (no redirect, no cookie clear)"
    );
    assert!(
        session_still_authenticates(&harness, &cookie).await,
        "an unverifiable-hint GET must not end the session"
    );
}

#[tokio::test]
async fn a_bare_get_with_no_hint_renders_a_confirmation_and_changes_nothing() {
    let harness = Harness::start().await;
    let (_session_id, cookie) = seeded_session(&harness).await;

    let (status, _headers, body) = get_end_session(&harness, "", &cookie).await;
    assert_eq!(status, StatusCode::OK, "confirmation page: {body}");
    assert!(
        body.contains("Sign out"),
        "a no-hint GET confirms first: {body}"
    );
    assert!(
        session_still_authenticates(&harness, &cookie).await,
        "a no-hint GET must not end the session"
    );
}

#[tokio::test]
async fn a_same_origin_confirmation_post_ends_the_session() {
    let harness = Harness::start().await;
    let (_session_id, cookie) = seeded_session(&harness).await;

    // The confirmation submit: a same-origin POST with no verifiable hint ends the
    // browser's cookie session and renders the logged-out page.
    let (status, headers, body) = post_end_session(
        &harness,
        "",
        Some(&cookie),
        Some(SELF_ORIGIN),
        Some("same-origin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "logged-out page: {body}");
    assert_cookie_cleared(&headers);
    assert!(
        !session_still_authenticates(&harness, &cookie).await,
        "a confirmed logout ends the session"
    );
}

/// Start a harness with Front-Channel Logout 1.0 enabled (issue #39). `enabled: true`
/// keeps the OIDC provider mounted; the front-channel flag arms the feature.
async fn frontchannel_harness() -> Harness {
    Harness::start_with(OidcConfig {
        enabled: true,
        frontchannel_logout_enabled: true,
        ..OidcConfig::default()
    })
    .await
}

#[tokio::test]
async fn check_session_iframe_is_mounted_and_framable_only_when_enabled() {
    // Issue #39: with session management OFF (the default) the check_session_iframe is
    // NOT mounted (a uniform 404). With it enabled the iframe is served with the
    // deliberate framing carve-out: no X-Frame-Options, and a CSP that does not deny
    // framing, so an RP can embed it cross-origin.
    let off = Harness::start().await;
    let (status, _headers, _body) = off.get_with_cookie("/connect/check_session", None).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "check_session_iframe is unmounted by default"
    );

    let on = Harness::start_with(OidcConfig {
        enabled: true,
        session_management_enabled: true,
        ..OidcConfig::default()
    })
    .await;
    let (status, headers, body) = on.get_with_cookie("/connect/check_session", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "check_session_iframe served: {body}"
    );
    assert!(
        headers.get(header::X_FRAME_OPTIONS).is_none(),
        "the iframe must be framable: no X-Frame-Options"
    );
    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        !csp.contains("frame-ancestors"),
        "the carve-out must not deny framing: {csp}"
    );
    assert!(
        body.contains("addEventListener") && body.contains("check_session"),
        "serves the session-management iframe: {body}"
    );
}

#[tokio::test]
async fn frontchannel_logout_renders_the_rp_iframe_with_iss_and_own_sid() {
    // Issue #39: with the feature enabled and the client opted in with
    // frontchannel_logout_session_required, a confirmed logout renders the
    // front-channel logout page with a hidden iframe pointing at the RP's registered
    // frontchannel_logout_uri, carrying iss and the RP's OWN sid.
    let harness = frontchannel_harness().await;
    let client_id = harness.client_id().to_string();
    let (_session_id, cookie) = seeded_session(&harness).await;
    // Minting an id token creates the per-(client, session) sid the front-channel
    // iframe will carry.
    let hint = mint_id_token(&harness, &client_id, &cookie).await;
    let sid = {
        let segment = hint.split('.').nth(1).expect("payload");
        let bytes = URL_SAFE_NO_PAD.decode(segment).expect("b64");
        let claims: Value = serde_json::from_slice(&bytes).expect("claims");
        claims["sid"].as_str().expect("sid").to_owned()
    };
    harness
        .register_frontchannel_logout(
            harness.client_id(),
            Some("https://rp.test/frontchannel"),
            true,
        )
        .await;

    // A same-origin confirmation POST ends the session and renders the front-channel
    // page.
    let (status, headers, body) = post_end_session(
        &harness,
        "",
        Some(&cookie),
        Some(SELF_ORIGIN),
        Some("same-origin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "front-channel logout page: {body}");
    assert_cookie_cleared(&headers);
    // Exactly one RP iframe, carrying the registered URI, iss, and the RP's OWN sid.
    assert!(
        body.contains("<iframe") && body.contains("https://rp.test/frontchannel"),
        "renders the RP logout iframe: {body}"
    );
    assert!(body.contains("iss="), "the iframe carries iss: {body}");
    assert!(
        body.contains(&format!("sid={sid}")),
        "the iframe carries the RP's OWN sid: {body}"
    );
    // The page keeps its anti-clickjacking posture and scopes frame-src to the RP.
    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(csp.contains("frame-ancestors 'none'"), "csp: {csp}");
    assert!(csp.contains("frame-src https://rp.test"), "csp: {csp}");
    assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
}

#[tokio::test]
async fn frontchannel_logout_off_by_default_renders_the_neutral_page() {
    // Issue #39: with the feature DISABLED (the default) a confirmed logout renders the
    // plain logged-out page even when a client registered a frontchannel_logout_uri:
    // the environment flag must also be on. No iframe is emitted.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_session_id, cookie) = seeded_session(&harness).await;
    let _hint = mint_id_token(&harness, &client_id, &cookie).await;
    harness
        .register_frontchannel_logout(
            harness.client_id(),
            Some("https://rp.test/frontchannel"),
            true,
        )
        .await;

    let (status, headers, body) = post_end_session(
        &harness,
        "",
        Some(&cookie),
        Some(SELF_ORIGIN),
        Some("same-origin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "neutral page: {body}");
    assert_cookie_cleared(&headers);
    assert!(
        !body.contains("<iframe"),
        "no front-channel iframe when the feature is off: {body}"
    );
}

#[tokio::test]
async fn a_cross_origin_confirmation_post_is_forbidden_and_changes_nothing() {
    let harness = Harness::start().await;
    let (_session_id, cookie) = seeded_session(&harness).await;

    // A cross-site POST (logout-CSRF) is refused before any state change.
    let (status, _headers, _body) = post_end_session(
        &harness,
        "",
        Some(&cookie),
        Some("https://evil.example"),
        Some("cross-site"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-site logout is blocked"
    );
    assert!(
        session_still_authenticates(&harness, &cookie).await,
        "a blocked logout must not end the session"
    );
}

#[tokio::test]
async fn offline_access_families_survive_an_rp_logout() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (session_id, cookie) = seeded_session(&harness).await;
    let scope = harness.scope();

    // Two refresh families bound to the SAME SSO session: one session-bound
    // (offline=false), one offline_access (offline=true).
    let subject = harness.seed_unique_user().await;
    let bound_grant = seed_grant(&harness, scope, &subject, &session_id).await;
    let bound = open_family(&harness, scope, &bound_grant, &subject, false).await;
    let offline_grant = seed_grant(&harness, scope, &subject, &session_id).await;
    let offline = open_family(&harness, scope, &offline_grant, &subject, true).await;

    let hint = mint_id_token(&harness, &client_id, &cookie).await;
    let query = format!("id_token_hint={}", enc(&hint));
    let (status, _headers, body) = get_end_session(&harness, &query, &cookie).await;
    assert_eq!(status, StatusCode::OK, "logged-out page: {body}");

    assert!(
        family_revoked(&harness, scope, &bound).await,
        "the session-bound family is revoked with the logout"
    );
    assert!(
        !family_revoked(&harness, scope, &offline).await,
        "an offline_access family SURVIVES an RP logout (hard_kill is never set here)"
    );
}

#[tokio::test]
async fn a_logout_never_reaches_a_foreign_tenants_session() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_session_id, cookie) = seeded_session(&harness).await;

    // A live session in a DIFFERENT tenant/environment.
    let foreign_scope = harness.provision_foreign_scope().await;
    let foreign_session = create_foreign_session(&harness, foreign_scope).await;

    let hint = mint_id_token(&harness, &client_id, &cookie).await;
    let query = format!("id_token_hint={}", enc(&hint));
    let (status, _headers, _body) = get_end_session(&harness, &query, &cookie).await;
    assert_eq!(status, StatusCode::OK);

    // The harness session is gone; the foreign session is untouched.
    assert!(!session_still_authenticates(&harness, &cookie).await);
    assert!(
        harness
            .store()
            .scoped(foreign_scope)
            .sessions()
            .get(&foreign_session, 0, 0)
            .await
            .expect("read foreign session")
            .is_some(),
        "a logout in one tenant must never revoke another tenant's session"
    );
}

#[tokio::test]
async fn only_spec_parameters_are_accepted_a_proprietary_one_is_ignored() {
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_session_id, cookie) = seeded_session(&harness).await;
    harness
        .register_post_logout_redirects(harness.client_id(), &["https://client.test/after"])
        .await;
    let hint = mint_id_token(&harness, &client_id, &cookie).await;

    // A Cognito-style proprietary `logout_uri` is neither required nor honored: the
    // logout behaves exactly as if it were absent (the standard post_logout_redirect_uri
    // still drives the redirect, and the proprietary param never becomes one).
    let query = format!(
        "id_token_hint={}&post_logout_redirect_uri={}&logout_uri={}",
        enc(&hint),
        enc("https://client.test/after"),
        enc("https://evil.example/proprietary"),
    );
    let (status, headers, body) = get_end_session(&harness, &query, &cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "still redirects on the spec param: {body}"
    );
    let loc = location(&headers).expect("location");
    assert!(
        loc.starts_with("https://client.test/after"),
        "the proprietary logout_uri is ignored, the registered spec uri wins: {loc}"
    );
}

#[tokio::test]
async fn an_attackers_valid_hint_cannot_log_out_a_co_scoped_victim() {
    // The #33 logout-CSRF: an attacker mints their OWN valid id_token, then lures a
    // co-scoped VICTIM (same client, same environment) into a top-level GET to
    // /end_session carrying the ATTACKER's token. The victim's SameSite=Lax session
    // cookie rides along, but the target is bound to the hint's own `sid` (the attacker's
    // session), so the victim's session MUST survive.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    let (_victim_id, victim_cookie) = seeded_session(&harness).await;
    let (_attacker_id, attacker_cookie) = seeded_session(&harness).await;
    let attacker_hint = mint_id_token(&harness, &client_id, &attacker_cookie).await;

    // The victim is authenticated before the attack.
    assert!(
        session_still_authenticates(&harness, &victim_cookie).await,
        "the victim starts authenticated"
    );

    // The exact reviewer probe: the victim's browser follows the crafted link.
    let query = format!("id_token_hint={}", enc(&attacker_hint));
    let (_status, _headers, _body) = get_end_session(&harness, &query, &victim_cookie).await;

    assert!(
        session_still_authenticates(&harness, &victim_cookie).await,
        "an attacker's valid hint must NEVER end a co-scoped victim's session"
    );
}

#[tokio::test]
async fn an_attackers_registered_redirect_never_carries_the_victims_browser_away() {
    // The phishing tail of the same chain: even with an attacker-registered exact
    // post_logout_redirect_uri, the victim's browser (a different session than the hint's
    // `sid`) is NOT redirected and its cookie is NOT cleared, so the crafted link cannot
    // navigate the victim away or drop their cookie.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    harness
        .register_post_logout_redirects(harness.client_id(), &["https://attacker.test/land"])
        .await;

    let (_victim_id, victim_cookie) = seeded_session(&harness).await;
    let (_attacker_id, attacker_cookie) = seeded_session(&harness).await;
    let attacker_hint = mint_id_token(&harness, &client_id, &attacker_cookie).await;

    let query = format!(
        "id_token_hint={}&post_logout_redirect_uri={}&state=attackerstate",
        enc(&attacker_hint),
        enc("https://attacker.test/land"),
    );
    let (status, headers, body) = get_end_session(&harness, &query, &victim_cookie).await;

    assert_ne!(
        status,
        StatusCode::SEE_OTHER,
        "the victim's browser must not be redirected: {body}"
    );
    assert!(
        location(&headers).is_none(),
        "no Location to the attacker's landing page"
    );
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "the victim's cookie must not be cleared"
    );
    assert!(
        session_still_authenticates(&harness, &victim_cookie).await,
        "the victim survives the attacker's redirect chain"
    );
}

#[tokio::test]
async fn a_verifiable_hint_with_no_sid_degrades_to_the_confirmation_prompt() {
    // A validly-signed, correctly-audienced hint that carries NO `sid` has no tie to any
    // specific session. On the attributed GET path it must NOT end the presenting cookie
    // session (that would be logout-CSRF); it degrades to the same confirmation prompt an
    // unattributable logout gets, changing nothing.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();
    let (_session_id, cookie) = seeded_session(&harness).await;
    let hint = mint_id_token(&harness, &client_id, &cookie).await;
    let sidless = hint_without_sid(&harness, &hint).await;

    let query = format!("id_token_hint={}", enc(&sidless));
    let (status, headers, body) = get_end_session(&harness, &query, &cookie).await;
    assert_eq!(status, StatusCode::OK, "confirmation page: {body}");
    assert!(
        body.contains("Sign out") && body.contains("<form"),
        "a sid-less hint renders the confirmation form: {body}"
    );
    assert!(
        location(&headers).is_none() && headers.get(header::SET_COOKIE).is_none(),
        "the confirmation page performs NO state change (no redirect, no cookie clear)"
    );
    assert!(
        session_still_authenticates(&harness, &cookie).await,
        "a sid-less hint on GET must not end the session without confirmation"
    );
}

// ---- store-assisted helpers (offline families and a foreign session) ----

/// Seed a grant bound to `session` (mirrors the store session suite).
async fn seed_grant(
    harness: &Harness,
    scope: Scope,
    subject: &str,
    session: &SessionId,
) -> GrantId {
    let env = harness.env();
    let code_id = AuthorizationCodeId::generate(env, &scope);
    let grant_id = GrantId::generate(env, &scope);
    let client_id = ClientId::generate(env, &scope);
    let session_text = session.to_string();
    harness
        .store()
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .authorization()
        .issue(
            env,
            IssueCode {
                code_id: &code_id,
                grant_id: &grant_id,
                client_id: &client_id,
                redirect_uri: "https://client.test/cb",
                nonce: None,
                code_challenge: None,
                code_challenge_method: None,
                subject,
                oauth_scope: Some("openid"),
                auth_methods: "pwd",
                auth_time_micros: None,
                session_ref: Some(&session_text),
                consent_ref: None,
                claims_request: None,
                granted_resources: &[],
                expires_at_micros: common::FAR_FUTURE_MICROS,
                created_at_micros: 0,
            },
        )
        .await
        .expect("issue code");
    grant_id
}

/// Open a refresh family rooted at `grant_id` (session-bound or `offline_access`).
async fn open_family(
    harness: &Harness,
    scope: Scope,
    grant_id: &GrantId,
    subject: &str,
    offline: bool,
) -> RefreshFamilyId {
    let env = harness.env();
    let family_id = RefreshFamilyId::generate(env, &scope);
    let jti = RefreshTokenId::generate(env, &scope);
    let digest = refresh_token_digest(&format!("ira_rt_{jti}~seed"));
    harness
        .store()
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .refresh()
        .issue(
            env,
            NewRefreshFamily {
                family_id: &family_id,
                token_jti: &jti,
                token_digest: &digest,
                grant_id,
                subject,
                client_id: "cli_family",
                scope: Some("openid"),
                auth_methods: "pwd",
                offline,
                created_at_unix_micros: 0,
                idle_expires_at_unix_micros: common::FAR_FUTURE_MICROS,
                absolute_expires_at_unix_micros: common::FAR_FUTURE_MICROS,
            },
        )
        .await
        .expect("open family");
    family_id
}

/// Whether a refresh family is revoked, read through the fleet surface.
async fn family_revoked(harness: &Harness, scope: Scope, family: &RefreshFamilyId) -> bool {
    harness
        .store()
        .scoped(scope)
        .refresh_family_fleet()
        .get(family)
        .await
        .expect("read family")
        .expect("family exists")
        .revoked_at_unix_micros
        .is_some()
}

/// Create a live session directly in a foreign scope (a different tenant/environment).
async fn create_foreign_session(harness: &Harness, scope: Scope) -> SessionId {
    let env = harness.env();
    let subject = ironauth_store::UserId::generate(env, &scope).to_string();
    let session_id = SessionId::generate(env, &scope);
    harness
        .store()
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .sessions()
        .rotate(
            env,
            &session_id,
            None,
            NewSession {
                subject: &subject,
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: common::FAR_FUTURE_MICROS,
                absolute_expires_micros: common::FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("create foreign session");
    session_id
}
