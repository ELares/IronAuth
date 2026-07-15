// SPDX-License-Identifier: MIT OR Apache-2.0

//! The four-level resource model as public APIs (issue #41), driven end to end
//! through the management router over a real database: organization CRUD and
//! pagination, cross-tenant and wrong-scope isolation, idempotent creation, the
//! operator-plane read surface, and the resource-type classification catalog.

mod common;

use axum::http::StatusCode;
use common::{Harness, assert_rate_limit_headers};
use serde_json::Value;

#[tokio::test]
async fn organization_crud_and_list_round_trip() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "k-tenant").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");

    // Create three organizations.
    let mut created_ids = Vec::new();
    for i in 0..3 {
        let body = serde_json::json!({ "display_name": format!("org-{i}") }).to_string();
        let (status, headers, response) = harness.post(&base, &format!("k-org-{i}"), &body).await;
        assert_eq!(status, StatusCode::CREATED, "create org: {response}");
        assert_rate_limit_headers(&headers);
        let value: Value = serde_json::from_str(&response).expect("json");
        assert_eq!(value["display_name"], format!("org-{i}"));
        assert_eq!(value["tenant_id"], tenant);
        assert_eq!(value["environment_id"], environment);
        assert_eq!(value["active"], true);
        let id = value["id"].as_str().expect("id").to_owned();
        assert!(id.starts_with("org_"), "organization id is typed: {id}");
        created_ids.push(id);
    }

    // Get one back.
    let (status, _, response) = harness.get(&format!("{base}/{}", created_ids[0])).await;
    assert_eq!(status, StatusCode::OK, "get org: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(value["id"], created_ids[0]);

    // List returns all three (a page larger than the set).
    let (status, _, response) = harness.get(&format!("{base}?limit=50")).await;
    assert_eq!(status, StatusCode::OK, "list orgs: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    let items = value["items"].as_array().expect("items");
    assert_eq!(items.len(), 3);

    // Delete one; it then reads as not-found (a deactivated org is absent).
    let (status, _, _) = harness.delete(&format!("{base}/{}", created_ids[0])).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = harness.get(&format!("{base}/{}", created_ids[0])).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // List now returns the two survivors.
    let (_, _, response) = harness.get(&format!("{base}?limit=50")).await;
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(value["items"].as_array().expect("items").len(), 2);
}

#[tokio::test]
async fn organization_delete_is_idempotent_in_effect_and_a_repeat_is_404() {
    // The documented contract: delete is idempotent IN EFFECT (the row is retained,
    // the org reads as absent), but NOT in status code. The first delete of a live
    // org is a 204; a repeat delete of an already-deactivated org is the uniform
    // not-found, the same 404 the get returns, so delete is no existence oracle.
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "k-tenant").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": "org" }).to_string();
    let (status, _, response) = harness.post(&base, "k-org", &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    let id = serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // First delete deactivates the live org: 204.
    let (status, _, _) = harness.delete(&format!("{base}/{id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "first delete deactivates");

    // The org now reads as absent, and a repeat delete is the same uniform 404.
    let (status, _, _) = harness.get(&format!("{base}/{id}")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a deactivated org reads as absent"
    );
    let (status, _, _) = harness.delete(&format!("{base}/{id}")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a repeat delete of an already-deactivated org is the uniform not-found"
    );
}

#[tokio::test]
async fn organization_list_paginates_with_a_cursor() {
    let harness = Harness::start(2).await;
    let (tenant, environment) = harness.create_tenant("Acme", "k-tenant").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    for i in 0..5 {
        let body = serde_json::json!({ "display_name": format!("org-{i}") }).to_string();
        let (status, _, _) = harness.post(&base, &format!("k-{i}"), &body).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    // Walk the pages, collecting ids; no loss or duplication, page size honored.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let path = match &cursor {
            Some(c) => format!("{base}?limit=2&cursor={c}"),
            None => format!("{base}?limit=2"),
        };
        let (status, _, response) = harness.get(&path).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let value: Value = serde_json::from_str(&response).expect("json");
        for item in value["items"].as_array().expect("items") {
            seen.push(item["id"].as_str().expect("id").to_owned());
        }
        match value.get("next_cursor").and_then(Value::as_str) {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 5, "every organization is seen exactly once");
}

#[tokio::test]
async fn organization_create_requires_a_live_parent_environment() {
    let harness = Harness::start(50).await;
    let (tenant, _environment) = harness.create_tenant("Acme", "k-tenant").await;
    // A syntactically valid but never-created environment id under a real tenant:
    // the containment precondition refuses with a clean not-found.
    let bogus_env = ironauth_store::EnvironmentId::generate(&ironauth_env::Env::system());
    let base = format!("/v1/tenants/{tenant}/environments/{bogus_env}/organizations");
    let body = serde_json::json!({ "display_name": "orphan" }).to_string();
    let (status, _, response) = harness.post(&base, "k-orphan", &body).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an org under a nonexistent environment is refused: {response}"
    );
}

#[tokio::test]
async fn organization_cross_tenant_id_is_uniform_not_found() {
    let harness = Harness::start(50).await;
    let (tenant_a, env_a) = harness.create_tenant("A", "k-a").await;
    let (tenant_b, env_b) = harness.create_tenant("B", "k-b").await;

    // Create an organization in tenant A.
    let base_a = format!("/v1/tenants/{tenant_a}/environments/{env_a}/organizations");
    let body = serde_json::json!({ "display_name": "secret-org" }).to_string();
    let (status, _, response) = harness.post(&base_a, "k-org", &body).await;
    assert_eq!(status, StatusCode::CREATED);
    let org_a = serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // Present A's organization id under tenant B's path: the id embeds A's scope,
    // so it does not parse in B's scope. Uniform not-found, no existence oracle.
    let (status, _, _) = harness
        .get(&format!(
            "/v1/tenants/{tenant_b}/environments/{env_b}/organizations/{org_a}"
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A well-formed but absent id in B's own scope is the SAME not-found (baseline).
    let absent = ironauth_store::OrganizationId::generate(
        &ironauth_env::Env::system(),
        &ironauth_store::Scope::new(
            ironauth_store::TenantId::parse(&tenant_b).expect("tenant"),
            ironauth_store::EnvironmentId::parse(&env_b).expect("env"),
        ),
    );
    let (status, _, _) = harness
        .get(&format!(
            "/v1/tenants/{tenant_b}/environments/{env_b}/organizations/{absent}"
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn organization_management_key_must_match_the_environment() {
    let harness = Harness::start(50).await;
    let (tenant, env_a) = harness.create_tenant("A", "k-a").await;
    let env_b = harness
        .create_environment(&tenant, "staging", "k-envb")
        .await;
    // A key scoped to (tenant, env_a).
    let key = harness.create_key(&tenant, &env_a, "ci", "k-key").await;

    // The key creates an org in its OWN environment: allowed.
    let base_a = format!("/v1/tenants/{tenant}/environments/{env_a}/organizations");
    let body = serde_json::json!({ "display_name": "in-a" }).to_string();
    let (status, _, response) = harness.post_as(&base_a, &key, "k-a-org", &body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "key in its own env: {response}"
    );

    // The SAME key presented against a sibling environment fails LOUD (wrong scope),
    // never the silent not-found: a mis-scoped credential is an operator error.
    let base_b = format!("/v1/tenants/{tenant}/environments/{env_b}/organizations");
    let (status, _, response) = harness.post_as(&base_b, &key, "k-b-org", &body).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "key against a sibling env is wrong-scope: {response}"
    );
}

#[tokio::test]
async fn organization_create_is_idempotent() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "k-tenant").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": "once" }).to_string();

    let (s1, _, r1) = harness.post(&base, "same-key", &body).await;
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, _, r2) = harness.post(&base, "same-key", &body).await;
    assert_eq!(
        s2,
        StatusCode::CREATED,
        "replay returns the original status"
    );
    assert_eq!(r1, r2, "replay returns the original body verbatim");

    // Exactly one organization exists (the replay executed nothing).
    let (_, _, list) = harness.get(&format!("{base}?limit=50")).await;
    let value: Value = serde_json::from_str(&list).expect("json");
    assert_eq!(value["items"].as_array().expect("items").len(), 1);
}

#[tokio::test]
async fn operator_plane_is_a_documented_read_surface() {
    let harness = Harness::start(50).await;
    // Creating a tenant self-bootstraps the operator row.
    harness.create_tenant("Acme", "k-tenant").await;

    let (status, headers, response) = harness.get("/v1/operators").await;
    assert_eq!(status, StatusCode::OK, "list operators: {response}");
    assert_rate_limit_headers(&headers);
    let value: Value = serde_json::from_str(&response).expect("json");
    let items = value["items"].as_array().expect("items");
    assert!(!items.is_empty(), "the bootstrap operator is listed");
    let operator_id = items[0]["id"].as_str().expect("id").to_owned();
    assert!(operator_id.starts_with("op_"), "operator id is typed");

    // Get the operator by id.
    let (status, _, response) = harness.get(&format!("/v1/operators/{operator_id}")).await;
    assert_eq!(status, StatusCode::OK, "get operator: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(value["id"], operator_id);

    // An unknown operator id is not-found.
    let unknown = ironauth_store::OperatorId::generate(&ironauth_env::Env::system());
    let (status, _, _) = harness.get(&format!("/v1/operators/{unknown}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn operator_plane_rejects_a_management_key() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "k-tenant").await;
    let key = harness
        .create_key(&tenant, &environment, "ci", "k-key")
        .await;
    // A management key is not the operator plane: a LOUD wrong-plane 403.
    let (status, _, _) = harness.get_as("/v1/operators", &key).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn resource_type_catalog_classifies_every_type() {
    let harness = Harness::start(50).await;
    let (status, headers, response) = harness.get("/v1/resource-types").await;
    assert_eq!(status, StatusCode::OK, "resource types: {response}");
    assert_rate_limit_headers(&headers);
    let value: Value = serde_json::from_str(&response).expect("json");
    let items = value["items"].as_array().expect("items");
    assert!(!items.is_empty());

    // Every item carries a name, a level, and one of the three classes.
    let mut classes = std::collections::BTreeSet::new();
    let mut by_name = std::collections::BTreeMap::new();
    for item in items {
        let name = item["name"].as_str().expect("name").to_owned();
        let class = item["classification"].as_str().expect("classification");
        assert!(item["level"].as_str().is_some(), "level present for {name}");
        assert!(
            matches!(class, "promotable" | "runtime" | "environment-identity"),
            "unexpected classification {class} for {name}"
        );
        classes.insert(class.to_owned());
        by_name.insert(name, class.to_owned());
    }

    // The four levels are classified as the model declares, and all three classes
    // are represented (the catalog the snapshot/promotion engines consume).
    assert_eq!(
        by_name.get("organization").map(String::as_str),
        Some("runtime")
    );
    assert_eq!(
        by_name.get("environment").map(String::as_str),
        Some("environment-identity")
    );
    assert_eq!(by_name.get("operator").map(String::as_str), Some("runtime"));
    assert_eq!(
        by_name.get("client").map(String::as_str),
        Some("promotable")
    );
    assert_eq!(classes.len(), 3, "all three classes appear: {classes:?}");
}

#[tokio::test]
async fn resource_type_catalog_needs_a_credential() {
    let harness = Harness::start(50).await;
    // No Authorization header: rejected at the extractor.
    let (status, _, _) = harness
        .send(
            axum::http::Request::builder()
                .method("GET")
                .uri("/v1/resource-types")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
