// SPDX-License-Identifier: MIT OR Apache-2.0

//! Idempotency-Key replay: replaying a POST returns the ORIGINAL response
//! without re-executing the mutation, verified against the audit log (a replay
//! writes NO second audit row). A key reused with a different request is a 422,
//! and a POST without the key is a 400.

mod common;

use axum::http::StatusCode;
use common::{Harness, assert_rate_limit_headers};
use ironauth_store::{EnvironmentId, Scope, TenantId};
use serde_json::Value;

#[tokio::test]
async fn replay_returns_original_and_writes_no_second_audit_row() {
    let harness = Harness::start(50).await;
    let body = serde_json::json!({ "display_name": "Acme" }).to_string();

    // First request: creates the tenant and its first environment.
    let (status, headers, first) = harness.post("/v1/tenants", "idem-1", &body).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    assert_rate_limit_headers(&headers);
    let first_value: Value = serde_json::from_str(&first).expect("json");
    let tenant_id = first_value["tenant"]["id"]
        .as_str()
        .expect("tenant id")
        .to_owned();
    let environment_id = first_value["environment"]["id"]
        .as_str()
        .expect("env id")
        .to_owned();

    // Replay: same key, same body. Returns the ORIGINAL response verbatim.
    let (status, headers, replayed) = harness.post("/v1/tenants", "idem-1", &body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "replay keeps the original status"
    );
    assert_rate_limit_headers(&headers);
    assert_eq!(
        replayed, first,
        "replay returns the original response byte for byte"
    );

    // Only one tenant exists: the mutation did not run twice.
    let (_, _, list) = harness.get("/v1/tenants?limit=50").await;
    let list_value: Value = serde_json::from_str(&list).expect("json");
    assert_eq!(
        list_value["items"].as_array().expect("items").len(),
        1,
        "the replay created no second tenant"
    );

    // The audit log carries exactly ONE tenant.create row for this scope: the
    // replay wrote no second audit row. Read it through the control store, in the
    // scope the operator-plane create audited to (new tenant, new first env).
    let scope = Scope::new(
        TenantId::parse(&tenant_id).expect("tenant id parses"),
        EnvironmentId::parse(&environment_id).expect("env id parses"),
    );
    let audit = harness
        .control_store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit list");
    let creates: Vec<_> = audit
        .iter()
        .filter(|row| row.action == "tenant.create")
        .collect();
    assert_eq!(
        creates.len(),
        1,
        "exactly one tenant.create audit row after an idempotent replay"
    );
}

#[tokio::test]
async fn same_key_different_request_is_unprocessable() {
    let harness = Harness::start(50).await;
    let (status, _, _) = harness
        .post(
            "/v1/tenants",
            "idem-shared",
            &serde_json::json!({ "display_name": "First" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _, body) = harness
        .post(
            "/v1/tenants",
            "idem-shared",
            &serde_json::json!({ "display_name": "Second" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let value: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(value["error"], "idempotency_key_conflict");
}

#[tokio::test]
async fn a_management_key_replay_never_repeats_or_stores_the_secret() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "mk-tenant").await;
    let path = format!("/v1/tenants/{tenant}/environments/{env}/keys");
    let body = serde_json::json!({ "display_name": "ci-terraform" }).to_string();

    // First creation: 201 WITH the secret present exactly once.
    let (status, _, first) = harness.post(&path, "mk-1", &body).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let first_value: Value = serde_json::from_str(&first).expect("json");
    let secret = first_value["secret"]
        .as_str()
        .expect("the secret is present on the first creation")
        .to_owned();
    assert!(!secret.is_empty(), "the secret is a real token");
    assert_eq!(
        first_value["secret_already_issued"],
        Value::Bool(false),
        "first creation is not a replay"
    );

    // Replay: same key, same body. Returns 200 with the NO-SECRET view.
    let (status, _, replay) = harness.post(&path, "mk-1", &body).await;
    assert_eq!(status, StatusCode::OK, "a key replay is 200: {replay}");
    let replay_value: Value = serde_json::from_str(&replay).expect("json");
    assert!(
        replay_value.get("secret").is_none(),
        "the replay omits the secret: {replay}"
    );
    assert_eq!(
        replay_value["secret_already_issued"],
        Value::Bool(true),
        "the replay marks the secret already issued"
    );
    assert_eq!(
        replay_value["id"], first_value["id"],
        "the replay names the same key id"
    );
    // The stored idempotency body IS what a replay returns verbatim, so the
    // absence of the secret here proves the secret never touched the database.
    assert!(
        !replay.contains(&secret),
        "the one-time secret must never appear in the stored replay body"
    );
}

#[tokio::test]
async fn post_without_idempotency_key_is_a_bad_request() {
    let harness = Harness::start(50).await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/tenants")
        .header(
            axum::http::header::AUTHORIZATION,
            common::bearer(common::OPERATOR_TOKEN),
        )
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({ "display_name": "NoKey" }).to_string(),
        ))
        .expect("request builds");
    let (status, _, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let value: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(value["error"], "bad_request");
}
