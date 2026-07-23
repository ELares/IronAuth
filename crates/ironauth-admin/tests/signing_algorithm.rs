// SPDX-License-Identifier: MIT OR Apache-2.0

//! The compatibility wizard write through and interop surface (issue #93, Bet 2).
//!
//! Drives the two management endpoints against a real database with a store-backed
//! data-plane issuer registry installed (so the layer-2 signable check is live):
//!
//! - a valid, signable algorithm round-trips through the reader,
//! - the two-layer validation rejects an out-of-set algorithm (400) and one the
//!   environment cannot sign (422), leaving the column unchanged,
//! - a client absent in scope is the uniform 404,
//! - the Idempotency-Key replays the original response and conflicts on reuse with a
//!   different body,
//! - the interop GET surfaces the pinned matrix rows.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::ClientId;

/// Build a fully provisioned environment (all three day-one algorithms) with a seeded
/// DCR client whose recorded algorithm starts at `EdDSA`.
async fn provisioned_client(h: &Harness) -> (ironauth_store::Scope, ClientId) {
    let scope = h.seed_scope().await;
    h.provision_all_algorithms(scope).await;
    let client = h.seed_quarantined_dcr_client(scope).await;
    (scope, client)
}

/// The signing-algorithm endpoint path for a client.
fn path(scope: ironauth_store::Scope, client: &ClientId) -> String {
    format!(
        "/v1/tenants/{}/environments/{}/clients/{client}/signing-algorithm",
        scope.tenant(),
        scope.environment()
    )
}

#[tokio::test]
async fn put_a_signable_algorithm_round_trips_through_the_reader() {
    let h = Harness::start_with_signing_registry(50).await;
    let (scope, client) = provisioned_client(&h).await;
    assert_eq!(
        h.client_signing_alg(scope, &client).await.as_deref(),
        Some("EdDSA"),
        "the seed records EdDSA"
    );

    let (status, _, body) = h
        .put_with_key(&path(scope, &client), "k-1", r#"{"algorithm":"RS256"}"#)
        .await;
    assert_eq!(status, StatusCode::OK, "PUT RS256: {body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(value["id_token_signed_response_alg"], "RS256");
    assert_eq!(value["client_id"], client.to_string());

    assert_eq!(
        h.client_signing_alg(scope, &client).await.as_deref(),
        Some("RS256"),
        "the write through round-trips through the reader"
    );
}

#[tokio::test]
async fn put_an_out_of_set_algorithm_is_a_400_and_leaves_the_column_unchanged() {
    let h = Harness::start_with_signing_registry(50).await;
    let (scope, client) = provisioned_client(&h).await;

    // PS256 (a real JOSE alg outside the wizard set), `none`, and a garbage value are all
    // rejected at layer 1 with a 400, and none touches the column.
    for (idx, alg) in ["PS256", "none", "ES384", "not-an-alg", ""]
        .iter()
        .enumerate()
    {
        let payload = format!("{{\"algorithm\":{}}}", serde_json::to_string(alg).unwrap());
        let key = format!("k-out-{idx}");
        let (status, _, body) = h.put_with_key(&path(scope, &client), &key, &payload).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "PUT {alg:?} must be rejected at layer 1: {body}"
        );
    }

    assert_eq!(
        h.client_signing_alg(scope, &client).await.as_deref(),
        Some("EdDSA"),
        "an out-of-set algorithm leaves the column unchanged"
    );
}

#[tokio::test]
async fn put_an_algorithm_the_environment_cannot_sign_is_a_422_unchanged() {
    // A legacy environment with ONLY its EdDSA day-one key: RS256 is in the wizard set
    // (passes layer 1) but the environment cannot sign it, so layer 2 rejects it with a
    // 422 and the column is left unchanged.
    let h = Harness::start_with_signing_registry(50).await;
    let scope = h.seed_scope().await;
    h.provision_eddsa_only(scope).await;
    let client = h.seed_quarantined_dcr_client(scope).await;

    let (status, _, body) = h
        .put_with_key(
            &path(scope, &client),
            "k-legacy",
            r#"{"algorithm":"RS256"}"#,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "RS256 is not signable in an EdDSA-only environment: {body}"
    );
    assert_eq!(
        h.client_signing_alg(scope, &client).await.as_deref(),
        Some("EdDSA"),
        "a non-signable algorithm leaves the column unchanged"
    );

    // EdDSA itself (the one signable algorithm) is accepted, proving the 422 above is the
    // signability check and not a blanket rejection.
    let (status, _, body) = h
        .put_with_key(
            &path(scope, &client),
            "k-legacy-ok",
            r#"{"algorithm":"EdDSA"}"#,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "EdDSA is signable here: {body}");
}

#[tokio::test]
async fn put_for_a_client_absent_in_scope_is_not_found() {
    let h = Harness::start_with_signing_registry(50).await;
    let scope = h.seed_scope().await;
    h.provision_all_algorithms(scope).await;
    // A well-formed, in-scope client id that resolves to no client (never seeded).
    let missing = Harness::fresh_client_id(scope);
    let path = format!(
        "/v1/tenants/{}/environments/{}/clients/{missing}/signing-algorithm",
        scope.tenant(),
        scope.environment()
    );
    let (status, _, body) = h
        .put_with_key(&path, "k-missing", r#"{"algorithm":"RS256"}"#)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "absent client is 404: {body}"
    );
}

#[tokio::test]
async fn idempotency_key_replays_the_original_and_conflicts_on_reuse() {
    let h = Harness::start_with_signing_registry(50).await;
    let (scope, client) = provisioned_client(&h).await;
    let uri = path(scope, &client);

    let (status, _, first) = h
        .put_with_key(&uri, "k-idem", r#"{"algorithm":"RS256"}"#)
        .await;
    assert_eq!(status, StatusCode::OK, "first PUT: {first}");

    // Same key, same body: the stored response is replayed verbatim.
    let (status, _, replay) = h
        .put_with_key(&uri, "k-idem", r#"{"algorithm":"RS256"}"#)
        .await;
    assert_eq!(status, StatusCode::OK, "replay: {replay}");
    assert_eq!(
        replay, first,
        "the original response is replayed byte for byte"
    );

    // Same key, DIFFERENT body: a key reused for a different request is a 422 conflict.
    let (status, _, body) = h
        .put_with_key(&uri, "k-idem", r#"{"algorithm":"ES256"}"#)
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "reusing the key with a different body conflicts: {body}"
    );

    // The replay did not re-execute: the column is still the original RS256.
    assert_eq!(
        h.client_signing_alg(scope, &client).await.as_deref(),
        Some("RS256")
    );
}

#[tokio::test]
async fn put_requires_the_idempotency_key() {
    let h = Harness::start_with_signing_registry(50).await;
    let (scope, client) = provisioned_client(&h).await;
    // The harness `put` sends NO Idempotency-Key; the endpoint requires it (400).
    let (status, _, body) = h
        .put(&path(scope, &client), r#"{"algorithm":"RS256"}"#)
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a missing Idempotency-Key is a 400: {body}"
    );
}

#[tokio::test]
async fn get_recommendations_returns_the_matrix_including_the_pinned_rows() {
    let h = Harness::start_with_signing_registry(50).await;
    let (status, _, body) = h.get("/v1/interop/signing-recommendations").await;
    assert_eq!(status, StatusCode::OK, "GET recommendations: {body}");
    let rows: Vec<serde_json::Value> = serde_json::from_str(&body).expect("json array");
    assert_eq!(rows.len(), 7, "one row per verifier");

    let aws = rows
        .iter()
        .find(|r| r["verifier"] == "aws_api_gateway")
        .expect("aws row");
    assert_eq!(aws["recommended"], "RS256");
    assert_eq!(
        aws["reason"],
        "AWS API Gateway JWT authorizers verify RS256, not EdDSA"
    );

    let modern = rows
        .iter()
        .find(|r| r["verifier"] == "modern_jose")
        .expect("modern jose row");
    assert_eq!(modern["recommended"], "EdDSA");
    assert_eq!(
        modern["reason"],
        "modern JOSE libraries verify Ed25519; smaller and faster than RSA"
    );
    // Every recommended value stays within the three provisioned algorithms.
    for row in &rows {
        let rec = row["recommended"].as_str().expect("recommended string");
        assert!(
            ["EdDSA", "ES256", "RS256"].contains(&rec),
            "recommended {rec} is outside the wizard set"
        );
    }
}
