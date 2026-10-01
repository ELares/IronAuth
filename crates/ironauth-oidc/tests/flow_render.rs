// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hosted flow render app (issue #85, PR 1), against a real Postgres.
//!
//! These pin the render-app wiring that only the flow browser transport exercises when
//! `flows.enabled` is on (still flag-off by default, so no live behavior change):
//!
//! - a flow browser page is a FULL themed document over `pages::document` (doctype, the
//!   served same-origin stylesheet link) served under the flow CSP with `style-src 'self'`
//!   and NO `unsafe-inline`;
//! - the ONE served stylesheet is same-origin `text/css` and answers only under the flag;
//! - the flag-off posture is preserved: the stylesheet route 404s and the bootstrap `/login`
//!   is UNTOUCHED (no cutover in this PR, no `pages.css` link on the bootstrap page).

mod common;

use axum::http::{StatusCode, header};
use common::Harness;

fn stylesheet_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}/pages.css", scope.tenant(), scope.environment())
}

fn browser_login_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!("/t/{}/e/{}/flow/login", scope.tenant(), scope.environment())
}

#[tokio::test]
async fn a_flow_browser_page_is_a_full_themed_document_under_the_flow_csp() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_flows();

    let (status, headers, body) = harness
        .get_with_cookie(&browser_login_path(&harness), None)
        .await;
    assert_eq!(status, StatusCode::OK, "the flow login renders: {body}");

    // A full server-rendered document, not the old bare form.
    assert!(
        body.starts_with("<!doctype html>"),
        "a full document: {body}"
    );
    assert!(
        body.contains("<form method=\"post\""),
        "the login form renders"
    );
    // The ONE served same-origin stylesheet is linked (no external host).
    let expected_link = format!(
        "<link rel=\"stylesheet\" href=\"/t/{}/e/{}/pages.css\">",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    assert!(
        body.contains(&expected_link),
        "the served stylesheet is linked: {body}"
    );

    // The flow CSP opens exactly style-src 'self' and carries NO unsafe-inline.
    let csp = headers
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(csp.contains("default-src 'none'"), "strict CSP: {csp}");
    assert!(
        csp.contains("style-src 'self'"),
        "style-src for the stylesheet: {csp}"
    );
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "framing denied: {csp}"
    );
    assert!(!csp.contains("unsafe-inline"), "no unsafe-inline: {csp}");

    // Defense-in-depth framing header, same as every hardened page.
    assert_eq!(
        headers
            .get(header::X_FRAME_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
}

#[tokio::test]
async fn the_served_stylesheet_is_same_origin_css() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_flows();

    let (status, headers, body) = harness
        .get_with_cookie(&stylesheet_path(&harness), None)
        .await;
    assert_eq!(status, StatusCode::OK, "the stylesheet is served");
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/css; charset=utf-8")
    );
    assert!(!body.is_empty(), "the stylesheet has content");
    // A network capture shows no external requests: no remote host, no CDN, no url().
    assert!(
        !body.contains("http://"),
        "no external host in the stylesheet"
    );
    assert!(
        !body.contains("https://"),
        "no external host in the stylesheet"
    );
    assert!(
        !body.contains("url("),
        "no external url() reference in the stylesheet"
    );
}

#[tokio::test]
async fn with_the_flag_off_the_stylesheet_404s_and_the_bootstrap_login_is_untouched() {
    // A store-backed harness WITHOUT enable_flows(): the render-app surfaces answer 404.
    let harness = Harness::start_store_backed().await;

    let (status, _h, _b) = harness
        .get_with_cookie(&stylesheet_path(&harness), None)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the stylesheet route 404s when flows are off"
    );

    // The bootstrap /login page is UNTOUCHED: it renders and carries NO pages.css link (no
    // cutover in this PR). Build a valid /authorize resume so parse_resume admits it.
    let resume = format!("/authorize?client_id={}", harness.client_id());
    let login_path = format!("/login?return_to={}", urlencoding_lite(&resume));
    let (status, _h, login) = harness.get_with_cookie(&login_path, None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the bootstrap /login still renders: {login}"
    );
    assert!(
        login.contains("identifier"),
        "the bootstrap login form is untouched"
    );
    assert!(
        !login.contains("pages.css"),
        "the bootstrap login does NOT adopt the flow stylesheet (no cutover): {login}"
    );
}

/// A minimal percent-encoder for the `return_to` query value (the test only needs to encode
/// a local `/authorize?...` string).
fn urlencoding_lite(raw: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

/// Persisted browser flows retain the callback origin without weakening style
/// or framing policy. An unregistered path on that origin grants nothing.
#[tokio::test]
async fn hosted_flow_csp_admits_only_the_registered_resume_callback() {
    for webauthn_enabled in [false, true] {
        let mut harness = Harness::start_store_backed_with(ironauth_config::OidcConfig {
            webauthn_enabled,
            ..Default::default()
        })
        .await;
        harness.enable_flows();
        for (redirect, allowed) in [
            (common::REDIRECT_URI, true),
            ("https://client.test/unregistered", false),
            ("https://attacker.test/cb", false),
        ] {
            let resume = format!(
                "/authorize?response_type=code&client_id={}&redirect_uri={}",
                harness.client_id(),
                common::enc(redirect),
            );
            let path = format!(
                "{}?return_to={}",
                browser_login_path(&harness),
                common::enc(&resume)
            );
            let (status, headers, body) = harness.get_with_cookie(&path, None).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
            assert!(csp.contains("default-src 'none'"));
            assert!(csp.contains("style-src 'self'"));
            assert!(csp.contains("frame-ancestors 'none'"));
            assert!(!csp.contains("unsafe-inline"));
            assert_eq!(
                csp.contains("form-action 'self' https://client.test;"),
                allowed
            );
            if !allowed {
                assert!(csp.contains("form-action 'self';"));
            }
            assert!(!csp.contains("attacker.test"));
            assert_eq!(headers[header::CACHE_CONTROL], "no-store");
            assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
            // This initial flow has no passkey node group. Enabling WebAuthn
            // alone must not add an executable script or nonce to that page.
            assert!(!csp.contains("'nonce-"));
        }
    }
}

#[tokio::test]
async fn hosted_flow_refuses_a_resume_from_another_scope() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_flows();
    let other_scope = ironauth_store::Scope::new(
        ironauth_store::TenantId::generate(harness.env()),
        ironauth_store::EnvironmentId::generate(harness.env()),
    );
    assert_ne!(harness.scope(), other_scope);
    let other_client = ironauth_store::ClientId::generate(harness.env(), &other_scope);
    let resume = format!(
        "/authorize?client_id={}&redirect_uri={}",
        other_client,
        common::enc(common::REDIRECT_URI)
    );
    let path = format!(
        "{}?return_to={}",
        browser_login_path(&harness),
        common::enc(&resume)
    );
    let (status, headers, _) = harness.get_with_cookie(&path, None).await;
    assert!(!status.is_success());
    let policy = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(!policy.contains("https://client.test"));
}
