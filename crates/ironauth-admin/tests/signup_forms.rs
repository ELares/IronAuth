// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment, per-client signup form management endpoint over HTTP (issue #87, PR 1).
//!
//! The operator set / get / delete lifecycle keyed on the authorize client id, and the fail-fast
//! write validation surfaced as precise, operator-safe 400s: an unknown field step, and a field
//! that references a trait when the environment has no active trait schema to validate against.
//! Sudo mode is off in the default harness, so these isolate the endpoint behavior.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::{EnvironmentId, Scope, TenantId};

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn signup_form_path(tenant: &str, environment: &str, client: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/applications/{client}/signup-form")
}

#[tokio::test]
async fn set_get_delete_lifecycle_for_an_empty_form() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = signup_form_path(&tenant, &env, &client);

    // An empty form (no fields) needs no active trait schema and is stored as-is.
    let (status, _, body) = harness.put(&path, "{\"fields\":[]}").await;
    assert_eq!(status, StatusCode::OK, "set empty form: {body}");
    assert!(
        body.contains(&client),
        "the response names the client: {body}"
    );

    // GET reads it back.
    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "get form: {body}");
    assert!(body.contains("\"fields\":[]"), "empty fields: {body}");

    // DELETE removes it, and a subsequent GET is a uniform not-found.
    let (status, _, _) = harness.delete(&path).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete form");
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the form is gone");
}

#[tokio::test]
async fn an_unknown_field_step_is_a_precise_bad_request() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = signup_form_path(&tenant, &env, &client);

    let body = r#"{"fields":[{"trait_pointer":"/email","required":true,"order":0,"step":"whenever","rules":{},"label_message_id":1070}]}"#;
    let (status, _, response) = harness.put(&path, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown step: {response}");
    assert!(response.contains("whenever"), "names the step: {response}");
}

#[tokio::test]
async fn a_field_referencing_a_trait_with_no_active_schema_is_a_precise_bad_request() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = signup_form_path(&tenant, &env, &client);

    // A field that references a trait, but the environment has no active trait schema to validate
    // against: a precise, value-free 400 (nothing is stored).
    let body = r#"{"fields":[{"trait_pointer":"/email","required":true,"order":0,"step":"signup","rules":{},"label_message_id":1070}]}"#;
    let (status, _, response) = harness.put(&path, body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "no active schema: {response}"
    );
    assert!(
        response.contains("trait schema"),
        "explains the missing schema: {response}"
    );

    // The rejected write stored nothing.
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "nothing was stored");
}

#[tokio::test]
async fn a_malformed_client_id_is_a_uniform_not_found() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = signup_form_path(&tenant, &env, "cli_not-a-real-id");
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "malformed client id is a uniform not-found"
    );
}
