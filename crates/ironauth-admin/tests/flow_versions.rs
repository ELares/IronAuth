// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment custom-journey version management endpoint over HTTP (issue #92, PR 5).
//!
//! The operator create (POST, append-only) / list / get / pin lifecycle, and the two properties
//! the 2-lens review required:
//!
//! - **POST is idempotent on the key.** createFlowVersion APPENDS a server-assigned version, so it
//!   is a POST that REQUIRES an Idempotency-Key: a retry with the SAME key returns the SAME version
//!   (no duplicate is appended); the same key reused with a DIFFERENT body is a 422; a NEW key
//!   appends the next version.
//! - **Load-valid write validation.** A load-invalid artifact is a precise 400 and nothing is
//!   stored. pinFlowVersion likewise requires an Idempotency-Key and replays on retry.

mod common;

use common::Harness;

use axum::http::StatusCode;

/// A minimal load-valid journey artifact wrapped in the request envelope, with `id` set to `id`.
fn create_body(id: &str) -> String {
    serde_json::json!({
        "artifact": {
            "schema_version": "ironauth.journey/v1",
            "id": id,
            "engine_version": 1,
            "entry": "primary",
            "steps": [
                {"id": "primary", "kind": "identifier_password", "node_group": "password"},
                {"id": "done", "kind": "terminal"}
            ],
            "transitions": [{"from": "primary", "to": "done"}]
        }
    })
    .to_string()
}

fn versions_path(tenant: &str, environment: &str, journey: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/journeys/{journey}/versions")
}

fn version_from(body: &str) -> i64 {
    let value: serde_json::Value = serde_json::from_str(body).expect("json body");
    value["version"].as_i64().expect("version number")
}

#[tokio::test]
async fn create_is_idempotent_on_the_key_and_appends_on_a_new_key() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = versions_path(&tenant, &env, "login_basic");

    // First create with key "v1": version 1.
    let (status, _, body) = harness.post(&path, "v1", &create_body("login_basic")).await;
    assert_eq!(status, StatusCode::OK, "create v1: {body}");
    assert_eq!(version_from(&body), 1, "the first version is 1: {body}");

    // A RETRY with the SAME key and body REPLAYS: the SAME version, no duplicate appended.
    let (status, _, replay) = harness.post(&path, "v1", &create_body("login_basic")).await;
    assert_eq!(status, StatusCode::OK, "retry replay: {replay}");
    assert_eq!(
        version_from(&replay),
        1,
        "the retry returns the SAME version"
    );
    assert_eq!(body, replay, "the replay is byte-identical");

    // The registry holds exactly ONE version (no duplicate from the retry).
    let (status, _, list) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "list: {list}");
    let versions: serde_json::Value = serde_json::from_str(&list).expect("list json");
    assert_eq!(
        versions.as_array().expect("array").len(),
        1,
        "exactly one version after a retried create: {list}"
    );

    // The SAME key with a DIFFERENT body is a 422 (a key reused for a different request).
    let (status, _, conflict) = harness
        .post(&path, "v1", &create_body("different_id"))
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "same key, different body is 422: {conflict}"
    );

    // A NEW key APPENDS the next version.
    let (status, _, body2) = harness.post(&path, "v2", &create_body("login_basic")).await;
    assert_eq!(status, StatusCode::OK, "create v2: {body2}");
    assert_eq!(version_from(&body2), 2, "a new key appends version 2");
}

#[tokio::test]
async fn a_load_invalid_artifact_is_a_precise_bad_request() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = versions_path(&tenant, &env, "broken");

    // A journey whose transition targets an undeclared step does not compile: a precise 400.
    let body = serde_json::json!({
        "artifact": {
            "schema_version": "ironauth.journey/v1",
            "id": "broken",
            "engine_version": 1,
            "entry": "primary",
            "steps": [
                {"id": "primary", "kind": "identifier_password", "node_group": "password"},
                {"id": "done", "kind": "terminal"}
            ],
            "transitions": [{"from": "primary", "to": "nowhere"}]
        }
    })
    .to_string();
    let (status, _, response) = harness.post(&path, "b1", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "load-invalid: {response}");

    // Nothing was stored.
    let (status, _, list) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "list: {list}");
    assert_eq!(list.trim(), "[]", "a rejected artifact leaves no version");
}

#[tokio::test]
async fn create_requires_the_idempotency_key() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = versions_path(&tenant, &env, "login_basic");

    // A POST with NO Idempotency-Key (empty key) is a 400: the header is required on every POST.
    let (status, _, response) = harness.post(&path, "", &create_body("login_basic")).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the Idempotency-Key is required: {response}"
    );
}

#[tokio::test]
async fn pin_is_idempotent_and_reports_the_pinned_version() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = versions_path(&tenant, &env, "login_basic");

    // Author two versions.
    harness.post(&path, "v1", &create_body("login_basic")).await;
    harness.post(&path, "v2", &create_body("login_basic")).await;

    // Pin version 1: the response reports it pinned.
    let pin_path = format!("{path}/1/pin");
    let (status, _, body) = harness.post(&pin_path, "p1", "").await;
    assert_eq!(status, StatusCode::OK, "pin v1: {body}");
    let pinned: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(pinned["version"].as_i64(), Some(1));
    assert_eq!(
        pinned["pinned"].as_bool(),
        Some(true),
        "reports pinned: {body}"
    );

    // A retry with the same key replays the same response.
    let (status, _, replay) = harness.post(&pin_path, "p1", "").await;
    assert_eq!(status, StatusCode::OK, "pin retry: {replay}");
    assert_eq!(body, replay, "the pin replay is byte-identical");

    // Pinning a version that does not exist is a uniform not-found.
    let (status, _, _) = harness.post(&format!("{path}/9/pin"), "p9", "").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "pinning an absent version is 404"
    );
}
