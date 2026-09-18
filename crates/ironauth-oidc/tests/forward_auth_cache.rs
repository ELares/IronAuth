// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bounded-TTL decision cache on the forward-auth surface (issue #154 criterion 6).
//!
//! > Cached decisions respect bounded TTLs; a rule change takes effect within TTL plus the
//! > invalidation SLO, and cache outage falls back to full evaluation.
//!
//! The engine's own tests in `rules.rs` pin the cache mechanics (TTL expiry, generation-keyed
//! invalidation on a rule change, and a failing store falling through to full evaluation).
//! What they cannot see is the WIRING: that the config field reaches the runtime, that the
//! runtime's evaluation actually goes through a cache, and that the check endpoint answers
//! identically either way. The TTL-crossing behaviour itself is driven with a frozen clock in
//! the `forward_auth` module's unit tests; this file drives the whole chain over HTTP with
//! the cache installed and, as the control, with the shipped default (off).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, send_through};
use ironauth_config::{
    AccessActionConfig, AccessRuleConfig, FORWARD_DECISION_HEADER, FORWARD_DECISION_HONORED,
    ForwardAuthConfig,
};
use ironauth_oidc::forward_auth_rules::ForwardAuthRuntime;
use ironauth_oidc::oidc_router;

/// An allow-everything rule, the simplest surface on which "the answer is identical with and
/// without a cache" can be asserted.
fn allow_all(decision_cache_ttl_secs: Option<u64>) -> ForwardAuthConfig {
    ForwardAuthConfig {
        enabled: true,
        decision_cache_ttl_secs,
        rules: vec![AccessRuleConfig {
            name: "allow-all".to_owned(),
            action: AccessActionConfig::Allow,
            ..AccessRuleConfig::default()
        }],
        ..ForwardAuthConfig::default()
    }
}

/// One authenticated check through the real router, answered as a proxy would send it.
async fn check(
    harness: &Harness,
    runtime: &std::sync::Arc<ForwardAuthRuntime>,
) -> (StatusCode, String) {
    let router = oidc_router(
        harness
            .state()
            .clone()
            .with_forward_auth(std::sync::Arc::clone(runtime)),
    );
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/forward-auth",
        scope.tenant(),
        scope.environment()
    );
    let cookie = harness.session_cookie_at("alice", "pwd", 0).await;

    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header(FORWARD_DECISION_HEADER, FORWARD_DECISION_HONORED)
        .header("x-forwarded-method", "GET")
        .header("x-forwarded-host", "app.example.com")
        .header("x-forwarded-uri", "/app")
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .expect("request builds");
    let (status, _, body) = send_through(router, request).await;
    (status, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_configured_decision_cache_serves_repeated_checks_identically() {
    let harness = Harness::start_store_backed().await;

    let runtime = std::sync::Arc::new(
        ForwardAuthRuntime::from_config(&allow_all(Some(3600)), &[], harness.env().clock_arc())
            .expect("the rule converts")
            .expect("forward-auth is enabled"),
    );
    assert!(
        runtime.forward_auth().decision_cache_enabled(),
        "a configured TTL must install the cache, or the field is decoration"
    );

    // The same authenticated check twice: the second is served from the cache, and the proxy
    // cannot tell the two answers apart.
    let (first_status, first_body) = check(&harness, &runtime).await;
    let (second_status, second_body) = check(&harness, &runtime).await;
    assert_eq!(first_status, StatusCode::OK, "{first_body}");
    assert_eq!(second_status, StatusCode::OK, "{second_body}");
    assert_eq!(
        first_body, second_body,
        "caching must not change the answer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_decision_cache_stays_off_without_configuration() {
    let harness = Harness::start_store_backed().await;

    let runtime = std::sync::Arc::new(
        ForwardAuthRuntime::from_config(&allow_all(None), &[], harness.env().clock_arc())
            .expect("the rule converts")
            .expect("forward-auth is enabled"),
    );
    assert!(
        !runtime.forward_auth().decision_cache_enabled(),
        "the shipped default evaluates every check from the rules"
    );

    let (status, body) = check(&harness, &runtime).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
