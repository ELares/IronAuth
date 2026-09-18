// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decision traces and dry-run on the forward-auth surface (issue #154 criterion 5).
//!
//! > Decision traces and dry-run answer "why was this denied" for a failing request,
//! > asserted on trace content, and dry-run never enforces.
//!
//! The engine's own tests in `rules.rs` pin the trace CONTENT (`explain` shares the walk
//! with `decide`, `the_trace_agrees_with_the_decision_on_every_corpus_row`). What they
//! cannot see is the SURFACE: that a failing check tells the proxy why, and that a
//! hypothetical request can be rehearsed without enforcing anything. This file drives both
//! over HTTP against a real database.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, send_through};
use ironauth_config::{
    AccessActionConfig, AccessRuleConfig, FORWARD_DECISION_HEADER, FORWARD_DECISION_HONORED,
    FORWARD_EXPLANATION_HEADER, ForwardAuthConfig,
};
use ironauth_oidc::forward_auth_rules::ForwardAuthRuntime;
use ironauth_oidc::oidc_router;
use serde_json::Value;

/// An allow rule for `/public`, and a deny for `/private` AFTER it, so the deny's trace
/// shows the allow was tried first. ORDER IS THE POLICY, so the deny is what decides
/// `/private`.
fn public_private_rules() -> ForwardAuthConfig {
    ForwardAuthConfig {
        enabled: true,
        rules: vec![
            AccessRuleConfig {
                name: "allow-public".to_owned(),
                action: AccessActionConfig::Allow,
                path_prefix: Some("/public".to_owned()),
                ..AccessRuleConfig::default()
            },
            AccessRuleConfig {
                name: "deny-private".to_owned(),
                action: AccessActionConfig::Deny,
                path_prefix: Some("/private".to_owned()),
                ..AccessRuleConfig::default()
            },
        ],
        ..ForwardAuthConfig::default()
    }
}

/// A router with the rules installed.
fn router_for(harness: &Harness, cfg: &ForwardAuthConfig) -> axum::Router {
    let runtime = ForwardAuthRuntime::from_config(cfg, &[], harness.env().clock_arc())
        .expect("the rules convert")
        .expect("forward-auth is enabled");
    oidc_router(
        harness
            .state()
            .clone()
            .with_forward_auth(std::sync::Arc::new(runtime)),
    )
}

/// One check request, exactly as a proxy would send it, for the given original URI.
async fn check(
    router: &axum::Router,
    scope: &ironauth_store::Scope,
    uri: &str,
) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri(format!(
            "/t/{}/e/{}/forward-auth",
            scope.tenant(),
            scope.environment()
        ))
        .header(FORWARD_DECISION_HEADER, FORWARD_DECISION_HONORED)
        .header("x-forwarded-method", "GET")
        .header("x-forwarded-host", "app.example.com")
        .header("x-forwarded-uri", uri)
        .body(Body::empty())
        .expect("request builds");
    let (status, headers, _body) = send_through(router.clone(), request).await;
    let explanation = headers
        .get(FORWARD_EXPLANATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    (status, explanation)
}

/// The dry-run answer for the same original URI.
async fn dry_run(
    router: &axum::Router,
    scope: &ironauth_store::Scope,
    uri: &str,
) -> (StatusCode, Value) {
    let body = serde_json::json!({
        "method": "GET",
        "headers": [
            {"name": "x-forwarded-method", "value": "GET"},
            {"name": "x-forwarded-host", "value": "app.example.com"},
            {"name": "x-forwarded-uri", "value": uri},
        ],
    })
    .to_string();
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "/t/{}/e/{}/forward-auth/dry-run",
            scope.tenant(),
            scope.environment()
        ))
        .header(FORWARD_DECISION_HEADER, FORWARD_DECISION_HONORED)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("request builds");
    let (status, _, body) = send_through(router.clone(), request).await;
    let parsed = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body).expect("dry-run answers json")
    };
    (status, parsed)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_check_tells_the_proxy_which_rule_denied() {
    let harness = Harness::start_store_backed().await;
    let router = router_for(&harness, &public_private_rules());
    let scope = harness.scope();

    let (status, explanation) = check(&router, &scope, "/private/pay").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        explanation, "denied by rule deny-private",
        "the check response must carry WHY it was denied"
    );

    // The control: an allowed request carries its own reason, and a rule that was tried
    // and did not match is visible in the trace, not in the one-liner.
    let (status, explanation) = check(&router, &scope, "/public/page").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(explanation, "allowed by rule allow-public");
}

#[tokio::test(flavor = "multi_thread")]
async fn dry_run_answers_the_question_with_the_full_trace() {
    let harness = Harness::start_store_backed().await;
    let router = router_for(&harness, &public_private_rules());
    let scope = harness.scope();

    let (status, answer) = dry_run(&router, &scope, "/private/pay").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["decision"]["action"], "deny");
    assert_eq!(answer["decision"]["matched"], "deny-private");
    assert_eq!(
        answer["reason"], "denied by rule deny-private",
        "the one-line answer is asserted on trace content, and the trace below explains it"
    );

    // THE TRACE, ASSERTED ON CONTENT: the allow rule was tried and failed at its path
    // criterion, the deny rule matched, and nothing followed it.
    let rules = answer["trace"]["rules"].as_array().expect("trace rules");
    assert_eq!(rules.len(), 2, "{answer}");
    assert_eq!(rules[0]["rule"], "allow-public");
    assert_eq!(rules[0]["outcome"]["failed"]["criterion_index"], 0);
    assert!(
        rules[0]["outcome"]["failed"]["criterion"]
            .as_str()
            .expect("criterion rendering")
            .contains("/public"),
        "the failing criterion is rendered: {answer}"
    );
    assert_eq!(rules[1]["rule"], "deny-private");
    assert_eq!(rules[1]["outcome"], "matched");
}

#[tokio::test(flavor = "multi_thread")]
async fn dry_run_never_enforces() {
    let harness = Harness::start_store_backed().await;
    let router = router_for(&harness, &public_private_rules());
    let scope = harness.scope();

    // A request the LIVE path refuses, rehearsed through the dry-run: the answer is JSON,
    // not a verdict, and the check path still refuses afterwards.
    let (status, answer) = dry_run(&router, &scope, "/private/pay").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["decision"]["action"], "deny");
    assert_eq!(answer["trace"]["rules"][1]["outcome"], "matched");

    let (status, _) = check(&router, &scope, "/private/pay").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the rehearsal changed nothing about the enforcement path"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dry_run_answers_an_unmatched_request_with_the_failing_criteria() {
    let harness = Harness::start_store_backed().await;
    let router = router_for(&harness, &public_private_rules());
    let scope = harness.scope();

    let (status, answer) = dry_run(&router, &scope, "/other/thing").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["decision"]["action"], "deny");
    assert_eq!(answer["decision"]["matched"], Value::Null);
    assert!(
        answer["reason"]
            .as_str()
            .expect("reason")
            .contains("no rule matched"),
        "the reason names the fall-through: {answer}"
    );
    // BOTH rules were tried and each failed at its path criterion.
    for entry in answer["trace"]["rules"].as_array().expect("trace") {
        assert_eq!(
            entry["outcome"]["failed"]["criterion_index"], 0,
            "each rule stops at its path criterion: {answer}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dry_run_from_an_untrusted_hop_is_refused() {
    let harness = Harness::start_store_backed().await;
    let router = router_for(&harness, &public_private_rules());
    let scope = harness.scope();

    let body = serde_json::json!({
        "method": "GET",
        "headers": [
            {"name": "x-forwarded-method", "value": "GET"},
            {"name": "x-forwarded-host", "value": "app.example.com"},
            {"name": "x-forwarded-uri", "value": "/private/pay"},
        ],
    })
    .to_string();
    // NO FORWARD_DECISION_HEADER: the request did not arrive through the trusted chain.
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "/t/{}/e/{}/forward-auth/dry-run",
            scope.tenant(),
            scope.environment()
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("request builds");
    let (status, _, _) = send_through(router, request).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the trace is configuration knowledge and must not be an oracle for a direct caller"
    );
}
