// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environments as first-class typed objects through the management API (issue
//! #42): the typed kind and its derived guardrails on the environment view, the
//! unknown-kind rejection, the production custom-domain guardrail as a structured
//! error, and unbounded environment creation with no count gate.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

#[tokio::test]
async fn a_dev_environment_view_exposes_its_kind_and_relaxed_guardrails() {
    let harness = Harness::start(50).await;
    let (tenant, _first) = harness.create_tenant("Acme", "k-tenant").await;

    let (status, response) = harness
        .create_environment_typed(&tenant, "development", "dev", None, "k-dev")
        .await;
    assert_eq!(status, StatusCode::CREATED, "create dev: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");

    assert_eq!(view["kind"], "dev");
    assert_eq!(view["guardrail_class"], "non-production");
    // Non-production relaxes: insecure loopback redirects allowed, hosted pages
    // carry a noindex marker, and a visible environment banner is shown (AC6).
    let g = &view["guardrails"];
    assert_eq!(g["allow_insecure_redirect_uris"], true);
    assert_eq!(g["require_https_redirect_uris"], false);
    assert_eq!(g["require_custom_domain"], false);
    assert_eq!(g["one_time_view_secrets"], false);
    assert_eq!(g["hosted_pages_noindex"], true);
    assert_eq!(g["show_environment_banner"], true);
    // A non-production environment omits the custom domain when none is set.
    assert!(view.get("custom_domain").is_none() || view["custom_domain"].is_null());
}

#[tokio::test]
async fn a_prod_environment_hard_requires_a_custom_domain_and_hardens_guardrails() {
    let harness = Harness::start(50).await;
    let (tenant, _first) = harness.create_tenant("Acme", "k-tenant").await;

    // Creating a prod environment with NO custom domain fails structurally,
    // listing the failed guardrail (AC4). The request is well-formed, so this is a
    // 422 guardrail violation, not a 400 bad request.
    let (status, response) = harness
        .create_environment_typed(&tenant, "production", "prod", None, "k-prod-nodomain")
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "prod without a domain is rejected: {response}"
    );
    let body: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(body["error"], "guardrail_violation");
    let codes: Vec<&str> = body["failed_guardrails"]
        .as_array()
        .expect("failed_guardrails is a list")
        .iter()
        .map(|v| v.as_str().expect("code string"))
        .collect();
    assert!(
        codes.contains(&"custom_domain_required"),
        "the failed guardrail is named: {codes:?}"
    );

    // With a custom domain configured, the prod environment is created and its
    // view exposes the hard production guardrails.
    let (status, response) = harness
        .create_environment_typed(
            &tenant,
            "production",
            "prod",
            Some("auth.acme.example"),
            "k-prod-domain",
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create prod: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["kind"], "prod");
    assert_eq!(view["guardrail_class"], "production");
    assert_eq!(view["custom_domain"], "auth.acme.example");
    let g = &view["guardrails"];
    assert_eq!(g["allow_insecure_redirect_uris"], false);
    assert_eq!(g["require_https_redirect_uris"], true);
    assert_eq!(g["require_custom_domain"], true);
    assert_eq!(g["one_time_view_secrets"], true);
    assert_eq!(g["hosted_pages_noindex"], false);
    assert_eq!(g["show_environment_banner"], false);
}

#[tokio::test]
async fn an_unknown_kind_is_rejected_as_a_bad_request() {
    let harness = Harness::start(50).await;
    let (tenant, _first) = harness.create_tenant("Acme", "k-tenant").await;

    // A typo or a synonym is rejected, never coerced to a default.
    for bad in ["production", "prd", "PROD", "test"] {
        let (status, response) = harness
            .create_environment_typed(&tenant, "x", bad, None, &format!("k-{bad}"))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "unknown kind {bad:?} is a bad request: {response}"
        );
        let body: Value = serde_json::from_str(&response).expect("json");
        assert_eq!(body["error"], "bad_request");
    }
}

#[tokio::test]
async fn a_get_returns_the_stored_kind_and_domain() {
    let harness = Harness::start(50).await;
    let (tenant, _first) = harness.create_tenant("Acme", "k-tenant").await;
    let (status, response) = harness
        .create_environment_typed(
            &tenant,
            "staging",
            "staging",
            Some("staging.acme.example"),
            "k-staging",
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    let created: Value = serde_json::from_str(&response).expect("json");
    let env_id = created["id"].as_str().expect("id");

    let (status, _, response) = harness
        .get(&format!("/v1/tenants/{tenant}/environments/{env_id}"))
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    // Staging is a non-production kind, but it may still carry a custom domain.
    assert_eq!(view["kind"], "staging");
    assert_eq!(view["guardrail_class"], "non-production");
    assert_eq!(view["custom_domain"], "staging.acme.example");
}

#[tokio::test]
async fn fifty_plus_environments_create_with_no_count_gate() {
    let harness = Harness::start(200).await;
    let (tenant, _first) = harness.create_tenant("Acme", "k-tenant").await;

    // Creating 55 environments under one tenant all succeed: no billing or count
    // gate (AC5). The first environment came with the tenant, so this is 56 total.
    for i in 0..55 {
        let (status, response) = harness
            .create_environment_typed(&tenant, &format!("env-{i}"), "dev", None, &format!("k-{i}"))
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "environment {i} is created with no gate: {response}"
        );
    }
}
