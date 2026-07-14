// SPDX-License-Identifier: MIT OR Apache-2.0

//! Dynamic Client Registration abuse-control management surface (issue #31), over a
//! real database.
//!
//! Drives the operator-plane endpoints that back the #31 controls through the live
//! management router: authoring a named, reusable policy (create / list / idempotent
//! replay / duplicate-name conflict / invalid-primitive rejection); minting an initial
//! access token that carries a resolved policy-chain snapshot (the plaintext returned
//! exactly once, an idempotent replay omitting it, an unknown policy name and an
//! out-of-range lifetime both a clean 400); and reading and verifying a dynamically
//! registered client's quarantine state (a management verify lifts the quarantine,
//! idempotently, and the not-found probes are anti-oracle 404s).

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::{Value, json};

/// Parse a JSON response body.
fn body_json(text: &str) -> Value {
    serde_json::from_str(text).expect("response body is JSON")
}

/// A single `force` primitive object, the canonical policy-engine shape.
fn force_primitive(property: &str, value: &str) -> Value {
    json!({ "kind": "force", "property": property, "value": value })
}

#[tokio::test]
async fn policy_create_list_replay_and_conflict() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let policies_path = format!("/v1/tenants/{tenant}/environments/{environment}/dcr/policies");

    // Create a policy: 201 with a pol_ id and the primitives echoed.
    let request = json!({
        "name": "force-private-key-jwt",
        "primitives": [force_primitive("token_endpoint_auth_method", "private_key_jwt")]
    })
    .to_string();
    let (status, _headers, created) = h.post(&policies_path, "pol-key-1", &request).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let created = body_json(&created);
    assert!(
        created["id"].as_str().expect("id").starts_with("pol_"),
        "a policy id is returned"
    );
    assert_eq!(created["name"], "force-private-key-jwt");
    assert_eq!(
        created["primitives"][0]["property"],
        "token_endpoint_auth_method"
    );

    // Idempotent replay: the SAME key and body returns the original response byte for
    // byte, keeping its original 201 status (a policy carries no once-only secret to
    // omit, unlike the token/key endpoints that replay as 200).
    let (status, _headers, replay) = h.post(&policies_path, "pol-key-1", &request).await;
    assert_eq!(status, StatusCode::CREATED, "idempotent replay: {replay}");
    assert_eq!(body_json(&replay)["id"], created["id"]);

    // List: the policy appears.
    let (status, _headers, list) = h.get(&policies_path).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let list = body_json(&list);
    let names: Vec<&str> = list["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert!(
        names.contains(&"force-private-key-jwt"),
        "the created policy is listed: {names:?}"
    );

    // A DIFFERENT request reusing the same NAME (a fresh key) is a 409 conflict.
    let dup = json!({
        "name": "force-private-key-jwt",
        "primitives": [force_primitive("application_type", "web")]
    })
    .to_string();
    let (status, _headers, conflict) = h.post(&policies_path, "pol-key-2", &dup).await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(body_json(&conflict)["error"], "conflict");
}

#[tokio::test]
async fn policy_rejects_a_malformed_primitive() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let policies_path = format!("/v1/tenants/{tenant}/environments/{environment}/dcr/policies");

    // A primitive with an unknown kind is not a valid policy object: a clean 400,
    // caught by the OIDC policy engine at create time (one source of truth for shape).
    let request = json!({
        "name": "bogus",
        "primitives": [{ "kind": "obliterate", "property": "x" }]
    })
    .to_string();
    let (status, _headers, body) = h.post(&policies_path, "pol-bad", &request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn initial_access_token_mint_and_replay() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let policies_path = format!("/v1/tenants/{tenant}/environments/{environment}/dcr/policies");
    let iat_path =
        format!("/v1/tenants/{tenant}/environments/{environment}/dcr/initial-access-tokens");

    // Author a policy the token will attach by name.
    let policy = json!({
        "name": "p1",
        "primitives": [force_primitive("token_endpoint_auth_method", "private_key_jwt")]
    })
    .to_string();
    let (status, _headers, _body) = h.post(&policies_path, "p1-key", &policy).await;
    assert_eq!(status, StatusCode::CREATED);

    // Mint a token attaching that policy: 201 with the plaintext token, shown once.
    let mint = json!({
        "policy_names": ["p1"],
        "expires_in_secs": 3600,
        "max_uses": 5
    })
    .to_string();
    let (status, _headers, created) = h.post(&iat_path, "iat-key", &mint).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let created = body_json(&created);
    assert!(
        created["id"].as_str().expect("id").starts_with("iat_"),
        "a token id is returned"
    );
    let token = created["token"].as_str().expect("plaintext token");
    assert!(
        token.starts_with("ira_iat_"),
        "the plaintext bearer token is returned once: {token}"
    );
    assert_eq!(created["token_already_issued"], false);
    assert_eq!(created["max_uses"], 5);

    // Idempotent replay: the SAME key returns HTTP 200 and OMITS the plaintext (it was
    // never stored), flagging token_already_issued.
    let (status, _headers, replay) = h.post(&iat_path, "iat-key", &mint).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    let replay = body_json(&replay);
    assert_eq!(replay["id"], created["id"]);
    assert!(
        replay["token"].is_null(),
        "an idempotent replay never repeats the plaintext token"
    );
    assert_eq!(replay["token_already_issued"], true);
}

#[tokio::test]
async fn initial_access_token_rejects_unknown_policy_and_bad_lifetime() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let iat_path =
        format!("/v1/tenants/{tenant}/environments/{environment}/dcr/initial-access-tokens");

    // An unknown policy name is a clean 400 (no token minted).
    let unknown = json!({ "policy_names": ["ghost"], "expires_in_secs": 3600 }).to_string();
    let (status, _headers, body) = h.post(&iat_path, "iat-unknown", &unknown).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A zero lifetime is out of range.
    let zero = json!({ "policy_names": [], "expires_in_secs": 0 }).to_string();
    let (status, _headers, body) = h.post(&iat_path, "iat-zero", &zero).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A lifetime beyond the one-year cap is out of range.
    let too_long = json!({ "policy_names": [], "expires_in_secs": 31_536_001_u64 }).to_string();
    let (status, _headers, body) = h.post(&iat_path, "iat-long", &too_long).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn verify_lifts_quarantine_through_the_management_api() {
    let h = Harness::start(50).await;
    let scope = h.seed_scope().await;
    let client_id = h.seed_quarantined_dcr_client(scope).await;
    let base = format!(
        "/v1/tenants/{}/environments/{}/clients/{client_id}",
        scope.tenant(),
        scope.environment()
    );
    let verify_path = format!("{base}/verify");

    // Before: the client reads back quarantined and unverified.
    let (status, _headers, before) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{before}");
    let before = body_json(&before);
    assert_eq!(before["quarantined"], true);
    assert_eq!(before["verified"], false);
    assert!(before["verified_at_unix_ms"].is_null());

    // Verify lifts the quarantine and records the verification time.
    let (status, _headers, verified) = h.post(&verify_path, "verify-key", "").await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    let verified = body_json(&verified);
    assert_eq!(verified["quarantined"], false);
    assert_eq!(verified["verified"], true);
    assert!(verified["verified_at_unix_ms"].is_i64());

    // After: the change is durable when read back.
    let (status, _headers, after) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{after}");
    let after = body_json(&after);
    assert_eq!(after["quarantined"], false);
    assert_eq!(after["verified"], true);

    // An idempotent replay of the verify returns the original response.
    let (status, _headers, replay) = h.post(&verify_path, "verify-key", "").await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(body_json(&replay)["verified"], true);
}

#[tokio::test]
async fn get_and_verify_are_anti_oracle_and_operator_gated() {
    let h = Harness::start(50).await;
    let scope = h.seed_scope().await;
    let missing = Harness::fresh_client_id(scope);
    let base = format!(
        "/v1/tenants/{}/environments/{}/clients/{missing}",
        scope.tenant(),
        scope.environment()
    );

    // A well-formed, in-scope id that resolves to no client is a uniform 404 (no
    // existence oracle), for both the read and the verify.
    let (status, _headers, _body) = h.get(&base).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _headers, _body) = h.post(&format!("{base}/verify"), "v-missing", "").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A request without the operator credential is rejected before any store access.
    let (status, _headers, _body) = h.get_as(&base, "not-a-real-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
