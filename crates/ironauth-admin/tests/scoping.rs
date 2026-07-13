// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two distinct wrong-scope behaviors, both required:
//!
//! - (b) LOUD: a management key against the wrong environment or the wrong plane
//!   fails with a structured error naming the expected and actual scope;
//! - (a) UNIFORM: a resource-ID probe under a valid scope for a resource in
//!   another scope is the same not-found as an absent resource (the anti-oracle).

mod common;

use axum::http::StatusCode;
use common::{Harness, assert_rate_limit_headers};
use ironauth_env::Env;
use ironauth_store::EnvironmentId;
use serde_json::Value;

// The parallel a1/a2/b1 scope names are intentional and clearer than contrived
// distinct ones for a cross-scope test.
#[allow(clippy::similar_names)]
#[tokio::test]
async fn management_key_against_wrong_environment_or_plane_fails_loud() {
    let harness = Harness::start(50).await;

    // Tenant A with two environments; a key scoped to the FIRST.
    let (tenant_a, env_a1) = harness.create_tenant("Acme", "k-a").await;
    let env_a2 = harness
        .create_environment(&tenant_a, "staging", "k-a2")
        .await;
    let (tenant_b, env_b1) = harness.create_tenant("Beta", "k-b").await;
    let secret = harness.create_key(&tenant_a, &env_a1, "ci", "k-key").await;

    // Matching scope: the key reads its own environment.
    let (status, headers, body) = harness
        .get_as(
            &format!("/v1/tenants/{tenant_a}/environments/{env_a1}"),
            &secret,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "key reads its own environment: {body}"
    );
    assert_rate_limit_headers(&headers);

    // Wrong environment (sibling of the same tenant): LOUD 403 naming scopes.
    let (status, headers, body) = harness
        .get_as(
            &format!("/v1/tenants/{tenant_a}/environments/{env_a2}"),
            &secret,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_rate_limit_headers(&headers);
    let value: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(value["error"], "wrong_scope");
    assert!(
        value["expected_scope"].as_str().unwrap().contains(&env_a1),
        "expected scope names the key's environment: {body}"
    );
    assert!(
        value["actual_scope"].as_str().unwrap().contains(&env_a2),
        "actual scope names the requested environment: {body}"
    );

    // Wrong tenant: LOUD 403.
    let (status, _, body) = harness
        .get_as(
            &format!("/v1/tenants/{tenant_b}/environments/{env_b1}"),
            &secret,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["error"],
        "wrong_scope"
    );

    // Wrong plane: an operator-plane endpoint refuses the management key, LOUD.
    let (status, _, body) = harness
        .post_as(
            "/v1/tenants",
            &secret,
            "wrong-plane",
            &serde_json::json!({ "display_name": "X" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let value: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(value["error"], "wrong_scope");
    assert_eq!(value["expected_scope"], "plane=operator");
}

#[allow(clippy::similar_names)]
#[tokio::test]
async fn cross_scope_resource_probes_are_uniform_not_found() {
    let harness = Harness::start(50).await;
    let env = Env::system();

    let (tenant_a, env_a1) = harness.create_tenant("Acme", "k-a").await;
    let (tenant_b, env_b1) = harness.create_tenant("Beta", "k-b").await;

    // A cross-tenant environment probe (env_b1 belongs to tenant B) under tenant
    // A is a uniform not-found: the tenant filter is the anti-oracle.
    let (status_cross, _, body_cross) = harness
        .get(&format!("/v1/tenants/{tenant_a}/environments/{env_b1}"))
        .await;
    assert_eq!(status_cross, StatusCode::NOT_FOUND, "{body_cross}");

    // A genuinely absent (well-formed) environment id under tenant A is the SAME
    // not-found, so there is no existence oracle.
    let absent = EnvironmentId::generate(&env).to_string();
    let (status_absent, headers_absent, body_absent) = harness
        .get(&format!("/v1/tenants/{tenant_a}/environments/{absent}"))
        .await;
    assert_eq!(status_absent, StatusCode::NOT_FOUND, "{body_absent}");
    assert_rate_limit_headers(&headers_absent);
    assert_eq!(
        body_cross, body_absent,
        "a cross-scope probe is byte-identical to an absent one"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&body_absent).unwrap()["error"],
        "not_found"
    );

    // A management-key id minted in another scope is a uniform not-found when
    // fetched under this scope (the IDOR anti-oracle at the key resource).
    harness
        .create_key(&tenant_a, &env_a1, "own", "own-key")
        .await;
    let foreign_secret = harness
        .create_key(&tenant_b, &env_b1, "foreign", "foreign-key")
        .await;
    // The key id is the token's part before the '.'.
    let foreign_id = foreign_secret.split('.').next().expect("mak id");
    let (status, _, body) = harness
        .get(&format!(
            "/v1/tenants/{tenant_a}/environments/{env_a1}/keys/{foreign_id}"
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-scope key probe: {body}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["error"],
        "not_found"
    );
}

#[tokio::test]
async fn deleting_a_tenant_cascades_to_its_environments_and_keys() {
    let harness = Harness::start(50).await;
    let (tenant, env1) = harness.create_tenant("Acme", "t-1").await;
    // A second environment with its own key, so the cascade must reach EVERY
    // environment of the tenant, not just the audit scope's oldest one.
    let env2 = harness.create_environment(&tenant, "staging", "t-2").await;
    let key1 = harness.create_key(&tenant, &env1, "k1", "kk-1").await;
    let key2 = harness.create_key(&tenant, &env2, "k2", "kk-2").await;

    let (status, _, body) = harness.delete(&format!("/v1/tenants/{tenant}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // The tenant's environments no longer list.
    let (status, _, list) = harness
        .get(&format!("/v1/tenants/{tenant}/environments"))
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let value: Value = serde_json::from_str(&list).expect("json");
    assert_eq!(
        value["items"].as_array().expect("items").len(),
        0,
        "a deleted tenant lists no environments: {list}"
    );

    // Each environment is now a 404.
    for env in [&env1, &env2] {
        let (status, _, body) = harness
            .get(&format!("/v1/tenants/{tenant}/environments/{env}"))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "env {env}: {body}");
    }

    // Both previously-minted keys fail authentication (401), in every environment.
    for (key, env) in [(&key1, &env1), (&key2, &env2)] {
        let (status, _, body) = harness
            .get_as(&format!("/v1/tenants/{tenant}/environments/{env}"), key)
            .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a deleted tenant's key must not authenticate: {body}"
        );
    }
}

#[tokio::test]
async fn deleting_an_environment_cascades_to_its_keys() {
    let harness = Harness::start(50).await;
    let (tenant, env1) = harness.create_tenant("Acme", "e-1").await;
    let env2 = harness.create_environment(&tenant, "staging", "e-2").await;
    let key2 = harness.create_key(&tenant, &env2, "k2", "ek-2").await;

    let (status, _, body) = harness
        .delete(&format!("/v1/tenants/{tenant}/environments/{env2}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // The deleted environment is a 404; its sibling stays live.
    let (status, _, body) = harness
        .get(&format!("/v1/tenants/{tenant}/environments/{env2}"))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, _, body) = harness
        .get(&format!("/v1/tenants/{tenant}/environments/{env1}"))
        .await;
    assert_eq!(status, StatusCode::OK, "the sibling stays live: {body}");

    // The key minted in the deleted environment fails authentication.
    let (status, _, body) = harness
        .get_as(&format!("/v1/tenants/{tenant}/environments/{env2}"), &key2)
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a deleted environment's key must not authenticate: {body}"
    );

    // The tenant is still live and still lists its remaining environment.
    let (status, _, list) = harness
        .get(&format!("/v1/tenants/{tenant}/environments"))
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let value: Value = serde_json::from_str(&list).expect("json");
    assert_eq!(
        value["items"].as_array().expect("items").len(),
        1,
        "the surviving environment still lists: {list}"
    );
}
