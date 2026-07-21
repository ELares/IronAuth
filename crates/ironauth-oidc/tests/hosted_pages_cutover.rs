// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hosted-pages cutover (issue #85, PR 3), against a real Postgres.
//!
//! PR 3 wires `hosted_pages.enabled` as the live-surface gate that retargets the `/authorize`
//! interaction redirects onto the flow browser page. These pin the cutover seam and its safety
//! properties:
//!
//! - OFF (the default, and flows-on-but-pages-off, and pages-on-but-flows-off): the `/authorize`
//!   login and registration interaction redirects target the bootstrap `/login` and `/register`,
//!   byte-identical to before the cutover;
//! - ON (both `hosted_pages.enabled` and `flows.enabled`): the same redirects retarget onto the
//!   scope-routed flow browser page (`/t/{tenant}/e/{env}/flow/{journey}?return_to=...`);
//! - the retargeted `return_to` stays `parse_resume`-validated at flow creation, so a hostile
//!   external `return_to` at the landing is rejected (the #84 open-redirect defense holds through
//!   the retarget);
//! - end to end with the cutover on, a `/authorize` login lands on the flow page, completes the
//!   login through the flow engine (minting the session with the SAME cookie/CSRF/CSP), and the
//!   resumed request issues a code that exchanges for tokens;
//! - consent (issue #88) ALSO retargets onto the scope-routed flow consent page with the cutover
//!   on, rendering the consent screen as flow-contract nodes and recording the decision through
//!   the flow engine (the bootstrap `/consent` remains the OFF fallback).

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location,
    location_param, set_cookie_pair,
};
use ironauth_config::OidcConfig;
use ironauth_oidc::{Argon2Params, HashingPool, SESSION_COOKIE};

const IDENTIFIER: &str = "cutover@example.test";
const PASSWORD: &str = "correct-horse-battery-staple";

/// A store-backed harness (public client, PKCE-optional for confidential) with a cheap
/// deterministic Argon2 pool so the login POST is fast. The caller arms the cutover posture.
async fn harness() -> Harness {
    let mut harness = Harness::start_store_backed_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await;
    let pool = Arc::new(HashingPool::new(
        harness.env().clone(),
        Argon2Params::new(8, 1, 1),
        1,
        64,
        None,
    ));
    harness.install_hashing_pool(pool);
    harness
}

/// The authorization query for the harness public client (PKCE mandatory for a public client),
/// with an optional `prompt`.
fn authorize_query(client_id: &str, prompt: Option<&str>) -> String {
    use std::fmt::Write as _;
    let mut query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}&state=xyz&nonce=n-1&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid profile"),
    );
    if let Some(prompt) = prompt {
        let _ = write!(query, "&prompt={prompt}");
    }
    query
}

/// The scope-routed flow browser page path for a journey, as the cutover retargets to.
fn flow_page_prefix(harness: &Harness, journey: &str) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/flow/{journey}",
        scope.tenant(),
        scope.environment()
    )
}

/// Extract the hidden `flow` id from a rendered flow browser page.
fn hidden_flow_id(html: &str) -> String {
    let marker = "name=\"flow\"";
    let idx = html.find(marker).expect("a hidden flow field");
    let after = &html[idx..];
    let value_marker = "value=\"";
    let vidx = after.find(value_marker).expect("a flow value") + value_marker.len();
    let rest = &after[vidx..];
    let end = rest.find('"').expect("value end");
    rest[..end].to_owned()
}

/// POST the flow browser form with the given `Sec-Fetch-Site` (the CSRF signal), so the same
/// origin gate on the flow POST is exercised exactly as a real browser drives it.
async fn post_flow(
    harness: &Harness,
    path: &str,
    form_body: &str,
    fetch_site: &str,
) -> (StatusCode, HeaderMap, String) {
    harness
        .send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("Sec-Fetch-Site", fetch_site)
                .body(Body::from(form_body.to_owned()))
                .expect("request builds"),
        )
        .await
}

// ------------------------------------------------------------------------------------------
// OFF (the default and the two half-armed postures): the redirect is UNCHANGED (bootstrap).
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn off_by_default_the_authorize_login_redirect_targets_the_bootstrap_login() {
    let harness = harness().await;
    let client_id = harness.client_id().to_string();
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (status, headers, body) = harness.authorize(&authorize_query(&client_id, None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let loc = location(&headers).expect("login redirect");
    assert!(
        loc.starts_with("/login?return_to="),
        "OFF (default): the login redirect is the UNCHANGED bootstrap /login: {loc}"
    );

    // prompt=create still routes to the bootstrap /register.
    let (status, headers, body) = harness
        .authorize(&authorize_query(&client_id, Some("create")))
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let loc = location(&headers).expect("register redirect");
    assert!(
        loc.starts_with("/register?return_to="),
        "OFF (default): the registration redirect is the UNCHANGED bootstrap /register: {loc}"
    );
}

#[tokio::test]
async fn flows_on_but_pages_off_still_targets_the_bootstrap_login() {
    // Arming ONLY the headless flow API (native SDK exposure) must NOT cut the browser login UI
    // over: the two toggles are independent and only `hosted_pages.enabled` retargets the redirect.
    let mut harness = harness().await;
    harness.enable_flows();
    let client_id = harness.client_id().to_string();
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (status, headers, body) = harness.authorize(&authorize_query(&client_id, None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let loc = location(&headers).expect("login redirect");
    assert!(
        loc.starts_with("/login?return_to="),
        "flows-on/pages-off: the login redirect is still the bootstrap /login: {loc}"
    );
}

#[tokio::test]
async fn pages_on_but_flows_off_is_inert_and_targets_the_bootstrap_login() {
    // The hosted pages render THROUGH the flow engine, so arming the pages WITHOUT the flow engine
    // is inert: the cutover predicate requires both, so the redirect stays on the bootstrap /login
    // rather than a flow surface that would answer a uniform 404.
    let mut harness = harness().await;
    harness.arm_hosted_pages_without_flows();
    let client_id = harness.client_id().to_string();
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (status, headers, body) = harness.authorize(&authorize_query(&client_id, None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let loc = location(&headers).expect("login redirect");
    assert!(
        loc.starts_with("/login?return_to="),
        "pages-on/flows-off is inert: the login redirect is still the bootstrap /login: {loc}"
    );
}

// ------------------------------------------------------------------------------------------
// ON (the cutover): the redirect retargets onto the scope-routed flow browser page.
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_cutover_retargets_the_login_redirect_to_the_scope_routed_flow_page() {
    let mut harness = harness().await;
    harness.enable_hosted_pages_cutover();
    let client_id = harness.client_id().to_string();
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let (status, headers, body) = harness.authorize(&authorize_query(&client_id, None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let loc = location(&headers).expect("login redirect");
    let prefix = format!("{}?return_to=", flow_page_prefix(&harness, "login"));
    assert!(
        loc.starts_with(&prefix),
        "ON: the login redirect retargets onto the scope-routed flow login page: {loc}"
    );
    // The return_to is a validated LOCAL /authorize resume (never an external URL).
    let return_to = location_param(&headers, "return_to").expect("return_to");
    assert!(
        return_to.starts_with("/authorize?"),
        "the retargeted return_to is a local /authorize resume: {return_to}"
    );
}

#[tokio::test]
async fn the_cutover_retargets_the_registration_redirect_to_the_scope_routed_flow_page() {
    let mut harness = harness().await;
    harness.enable_hosted_pages_cutover();
    let client_id = harness.client_id().to_string();

    let (status, headers, body) = harness
        .authorize(&authorize_query(&client_id, Some("create")))
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let loc = location(&headers).expect("register redirect");
    let prefix = format!("{}?return_to=", flow_page_prefix(&harness, "registration"));
    assert!(
        loc.starts_with(&prefix),
        "ON: prompt=create retargets onto the scope-routed flow registration page: {loc}"
    );
}

#[tokio::test]
async fn the_retargeted_return_to_stays_validated_no_open_redirect() {
    // The cutover changes WHERE the user lands, NOT the open-redirect defense: the flow GET
    // re-validates the return_to through parse_resume at flow creation, so a hostile external
    // return_to at the landing is rejected rather than rendered (the #84 fix holds).
    let mut harness = harness().await;
    harness.enable_hosted_pages_cutover();

    let hostile = enc("https://evil.test/authorize?client_id=x");
    let path = format!(
        "{}?return_to={hostile}",
        flow_page_prefix(&harness, "login")
    );
    let (status, _headers, body) = harness.get_with_cookie(&path, None).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an external return_to at the flow login landing is rejected, never rendered: {body}"
    );
    assert!(
        status.is_client_error(),
        "the rejection is a client error, not a redirect to the external target: {status}"
    );
}

#[tokio::test]
async fn the_retargeted_flow_login_post_enforces_the_same_origin_csrf_gate() {
    // The CSRF primitive is unchanged by the cutover: the flow login POST is 403'd on a positive
    // cross-site signal, exactly as the bootstrap login POST is.
    let mut harness = harness().await;
    harness.enable_hosted_pages_cutover();
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    let return_to = format!("/authorize?client_id={}", harness.client_id());
    let get_path = format!(
        "{}?return_to={}",
        flow_page_prefix(&harness, "login"),
        enc(&return_to)
    );
    let (status, _h, html) = harness.get_with_cookie(&get_path, None).await;
    assert_eq!(status, StatusCode::OK, "the flow login renders: {html}");
    let flow_id = hidden_flow_id(&html);
    let body = form(&[
        ("flow", &flow_id),
        ("identifier", IDENTIFIER),
        ("password", PASSWORD),
    ]);

    let (status, _h, _b) = post_flow(
        &harness,
        &flow_page_prefix(&harness, "login"),
        &body,
        "cross-site",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a cross-site flow login POST is refused by the same-origin gate"
    );
}

#[tokio::test]
async fn end_to_end_authorize_flow_login_to_token_with_the_cutover_on() {
    let mut harness = harness().await;
    harness.enable_hosted_pages_cutover();
    let client_id = harness.client_id().to_string();
    harness.seed_user(IDENTIFIER, PASSWORD).await;

    // 1. Unauthenticated authorize -> 303 onto the scope-routed flow login page.
    let (status, headers, body) = harness.authorize(&authorize_query(&client_id, None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let flow_login = location(&headers).expect("flow login redirect");
    assert!(
        flow_login.starts_with(&flow_page_prefix(&harness, "login")),
        "the login lands on the flow page: {flow_login}"
    );

    // 2. GET the flow login page (a full themed document served under the flow CSP).
    let (status, page_headers, html) = harness.get_with_cookie(&flow_login, None).await;
    assert_eq!(status, StatusCode::OK, "flow login renders: {html}");
    let csp = page_headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .expect("the flow login carries a CSP")
        .to_owned();
    assert!(
        csp.contains("default-src 'none'") && !csp.contains("unsafe-inline"),
        "the flow login CSP is strict and carries no unsafe-inline: {csp}"
    );
    let flow_id = hidden_flow_id(&html);

    // 3. POST the credentials through the flow engine (same-origin) -> session + resume.
    let login_body = form(&[
        ("flow", &flow_id),
        ("identifier", IDENTIFIER),
        ("password", PASSWORD),
    ]);
    let (status, headers, body) = post_flow(
        &harness,
        &flow_page_prefix(&harness, "login"),
        &login_body,
        "same-origin",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "flow login completes: {body}"
    );
    let cookie = set_cookie_pair(&headers).expect("the flow login mints the session cookie");
    assert!(
        cookie.contains(SESSION_COOKIE),
        "the minted cookie is the session cookie: {cookie}"
    );
    let resume = location(&headers).expect("resume after the flow login");
    assert!(
        resume.starts_with("/authorize?"),
        "the flow login resumes the original /authorize: {resume}"
    );

    // 4. Resume /authorize with the session -> consent retargets to the scope-routed flow
    //    consent page (issue #88), which renders the consent nodes and, on an allow, records the
    //    grant and resumes the original /authorize.
    let (_s, headers, _b) = harness.get_with_cookie(&resume, Some(&cookie)).await;
    let consent_location = location(&headers).expect("consent redirect");
    assert!(
        consent_location.starts_with(&flow_page_prefix(&harness, "consent")),
        "consent retargets to the flow consent page with the cutover on: {consent_location}"
    );
    let (_s, _h, consent_html) = harness
        .get_with_cookie(&consent_location, Some(&cookie))
        .await;
    let consent_flow_id = hidden_flow_id(&consent_html);
    let consent_body = form(&[("flow", &consent_flow_id), ("decision", "allow")]);
    // The consent allow records the grant for the AUTHENTICATED subject, so the POST carries the
    // session cookie (plus the same-origin CSRF signal), exactly as a real browser would.
    let (_s, headers, _b) = harness
        .send(
            Request::builder()
                .method("POST")
                .uri(flow_page_prefix(&harness, "consent"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("Sec-Fetch-Site", "same-origin")
                .header(header::COOKIE, &cookie)
                .body(Body::from(consent_body))
                .expect("request builds"),
        )
        .await;
    let resume = location(&headers).expect("resume after consent");
    assert!(
        resume.starts_with("/authorize?"),
        "the consent allow resumes the original /authorize: {resume}"
    );

    // 5. The resumed request issues the code, which exchanges for tokens.
    let (_s, headers, _b) = harness.get_with_cookie(&resume, Some(&cookie)).await;
    let code = location_param(&headers, "code").expect("authorization code");
    let token_body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _h, body) = harness.token(&token_body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the token exchange succeeds: {body}"
    );
    assert!(
        json(&body)["access_token"].is_string(),
        "an access token is minted end to end through the flow login: {body}"
    );
}
