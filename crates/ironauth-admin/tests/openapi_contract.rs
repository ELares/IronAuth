// SPDX-License-Identifier: MIT OR Apache-2.0

//! Database-free OpenAPI contract tests: the generated spec is OpenAPI 3.1 with
//! stable operation ids and the required cross-cutting parameters, and the
//! committed artifact matches the generated one (the drift check at test level,
//! complementing scripts/openapi-check.sh).

use ironauth_admin::{management_openapi, openapi_json};
use serde_json::Value;

/// The committed artifact, embedded at compile time.
const COMMITTED: &str = include_str!("../../../docs/openapi/management.json");

fn spec() -> Value {
    serde_json::to_value(management_openapi()).expect("openapi serializes")
}

#[test]
fn spec_is_openapi_3_1() {
    assert_eq!(spec()["openapi"], "3.1.0");
}

#[test]
fn operation_ids_are_the_stable_set() {
    let doc = spec();
    let mut ids: Vec<String> = doc["paths"]
        .as_object()
        .expect("paths")
        .values()
        .flat_map(|path| path.as_object().expect("methods").values())
        .filter_map(|op| op.get("operationId").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        vec![
            "createEnvironment",
            "createManagementKey",
            "createTenant",
            "deleteEnvironment",
            "deleteManagementKey",
            "deleteTenant",
            "getEnvironment",
            "getManagementKey",
            "getTenant",
            "listEnvironments",
            "listManagementKeys",
            "listTenants",
        ]
    );
}

#[test]
fn error_schema_and_bearer_scheme_are_present() {
    let doc = spec();
    assert!(
        doc["components"]["schemas"]["ErrorBody"].is_object(),
        "the typed error body is a documented schema"
    );
    assert_eq!(
        doc["components"]["securitySchemes"]["bearer"]["scheme"], "bearer",
        "the bearer security scheme is declared"
    );
}

#[test]
fn every_list_endpoint_documents_cursor_pagination() {
    let doc = spec();
    for op in ["listTenants", "listEnvironments", "listManagementKeys"] {
        let params = find_operation(&doc, op)["parameters"]
            .as_array()
            .unwrap_or_else(|| panic!("{op} has parameters"));
        let names: Vec<&str> = params.iter().filter_map(|p| p["name"].as_str()).collect();
        assert!(
            names.contains(&"cursor"),
            "{op} must offer a cursor param: {names:?}"
        );
        assert!(
            names.contains(&"limit"),
            "{op} must offer a limit param: {names:?}"
        );
    }
}

#[test]
fn every_post_documents_the_idempotency_key_header() {
    let doc = spec();
    for op in ["createTenant", "createEnvironment", "createManagementKey"] {
        let params = find_operation(&doc, op)["parameters"]
            .as_array()
            .unwrap_or_else(|| panic!("{op} has parameters"));
        let has_idempotency = params.iter().any(|p| {
            p["name"].as_str() == Some("Idempotency-Key") && p["in"].as_str() == Some("header")
        });
        assert!(
            has_idempotency,
            "{op} must document the Idempotency-Key header"
        );
    }
}

#[test]
fn documented_paths_are_the_expected_set() {
    // The router is wired by hand (utoipa-axum, which would fuse the router and
    // the spec into one builder, pulls the unmaintained `paste` crate that cargo
    // deny rejects). This pins the exact (method, path) set the spec documents, so
    // a hand-wired route whose path disagrees with its `#[utoipa::path]` is caught
    // here rather than drifting silently.
    let doc = spec();
    let mut documented: Vec<String> = doc["paths"]
        .as_object()
        .expect("paths")
        .iter()
        .flat_map(|(path, methods)| {
            methods
                .as_object()
                .expect("methods")
                .keys()
                .map(move |method| format!("{} {path}", method.to_uppercase()))
        })
        .collect();
    documented.sort();
    assert_eq!(
        documented,
        vec![
            "DELETE /v1/tenants/{tenant_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/keys/{key_id}",
            "GET /v1/tenants",
            "GET /v1/tenants/{tenant_id}",
            "GET /v1/tenants/{tenant_id}/environments",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/keys",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/keys/{key_id}",
            "POST /v1/tenants",
            "POST /v1/tenants/{tenant_id}/environments",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/keys",
        ]
    );
}

#[test]
fn committed_artifact_matches_generated_spec() {
    // The same byte content scripts/openapi-check.sh regenerates and diffs.
    assert_eq!(
        openapi_json(),
        COMMITTED,
        "docs/openapi/management.json is stale; run scripts/openapi-check.sh"
    );
}

/// Find an operation object by its operationId across all paths and methods.
fn find_operation<'a>(doc: &'a Value, operation_id: &str) -> &'a Value {
    doc["paths"]
        .as_object()
        .expect("paths")
        .values()
        .flat_map(|path| path.as_object().expect("methods").values())
        .find(|op| op.get("operationId").and_then(Value::as_str) == Some(operation_id))
        .unwrap_or_else(|| panic!("operation {operation_id} not found"))
}
