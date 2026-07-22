// SPDX-License-Identifier: MIT OR Apache-2.0

//! Database-free OpenAPI contract tests: the generated spec is OpenAPI 3.1 with
//! stable operation ids and the required cross-cutting parameters, and the
//! committed artifact matches the generated one (the drift check at test level,
//! complementing scripts/openapi-check.sh).

use std::collections::BTreeSet;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ironauth_admin::{AdminState, management_openapi, management_router, openapi_json};
use ironauth_config::{AdminConfig, Secret, SecretString};
use ironauth_env::Env;
use ironauth_store::Store;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

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
#[allow(clippy::too_many_lines)]
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
            "applyConfigPromotion",
            "approveRecoveryApproval",
            "approveSignupQuarantine",
            "bulkRevokeSessions",
            "createBan",
            "createConnector",
            "createDcrInitialAccessToken",
            "createDcrPolicy",
            "createEnvironment",
            "createInvitation",
            "createManagementKey",
            "createOrganization",
            "createTenant",
            "createUser",
            "deleteBrandFavicon",
            "deleteBrandLogo",
            "deleteClientAdminConsent",
            "deleteConnector",
            "deleteEnvironment",
            "deleteLocale",
            "deleteManagementKey",
            "deleteOrganization",
            "deleteSignupForm",
            "deleteTenant",
            "deleteUser",
            "elevateAdminSudo",
            "exportConfigSnapshot",
            "exportIdentities",
            "extendSignupQuarantine",
            "getClientAdminConsent",
            "getClientAuthDiagnostics",
            "getConnector",
            "getConnectorCapabilities",
            "getConnectorHealth",
            "getDcrClient",
            "getDiagnosticsWarnings",
            "getEnvironment",
            "getFlowObservation",
            "getInvitation",
            "getLocale",
            "getManagementKey",
            "getMds3Health",
            "getMigrationProgress",
            "getMigrationRun",
            "getOperator",
            "getOrganization",
            "getPolicyDecisionTraces",
            "getRefreshFamily",
            "getSession",
            "getSignupForm",
            "getTenant",
            "getUser",
            "liftBan",
            "linkUserExternalId",
            "listBans",
            "listConnectors",
            "listDcrPolicies",
            "listEnvironments",
            "listInvitations",
            "listManagementKeys",
            "listMigrationRunViolations",
            "listMigrationRuns",
            "listOperators",
            "listOrganizations",
            "listRecoveryApprovals",
            "listRefreshFamilies",
            "listResourceTypes",
            "listSessions",
            "listSignupQuarantines",
            "listTenants",
            "listUsers",
            "planConfigPromotion",
            "postFlowDryRun",
            "probePasswordHashing",
            "rejectRecoveryApproval",
            "rejectSignupQuarantine",
            "resendInvitation",
            "restoreTenant",
            "resumeTenant",
            "revokeInvitation",
            "revokeSession",
            "revokeUserSessions",
            "setBrandFavicon",
            "setBrandLogo",
            "setClientAdminConsent",
            "setLocale",
            "setSignupForm",
            "setUserState",
            "suspendTenant",
            "unlinkUserExternalId",
            "updateConnector",
            "updateUser",
            "verifyDcrClient",
            "verifyMigrationCredential",
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
    for op in [
        "listOperators",
        "listTenants",
        "listEnvironments",
        "listOrganizations",
        "listManagementKeys",
        "listConnectors",
        "listDcrPolicies",
        "listSessions",
        "listRefreshFamilies",
        "listUsers",
        "listInvitations",
        "listSignupQuarantines",
        "listRecoveryApprovals",
        "listMigrationRuns",
        "listMigrationRunViolations",
    ] {
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
    for op in [
        "createTenant",
        "createEnvironment",
        "createOrganization",
        "createManagementKey",
        "createDcrPolicy",
        "createDcrInitialAccessToken",
        "createConnector",
        "verifyDcrClient",
        "revokeSession",
        "bulkRevokeSessions",
        "revokeUserSessions",
        "suspendTenant",
        "resumeTenant",
        "restoreTenant",
        "createUser",
        "setUserState",
        "createInvitation",
        "revokeInvitation",
        "resendInvitation",
        "approveSignupQuarantine",
        "rejectSignupQuarantine",
        "extendSignupQuarantine",
        "approveRecoveryApproval",
        "rejectRecoveryApproval",
    ] {
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
#[allow(clippy::too_many_lines)] // an exhaustive pinned (method, path) list reads clearest inline
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
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/admin-consent",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/signup-form",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/favicon",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/logo",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/keys/{key_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/locales/{locale}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/external-id",
            "GET /v1/operators",
            "GET /v1/operators/{operator_id}",
            "GET /v1/resource-types",
            "GET /v1/tenants",
            "GET /v1/tenants/{tenant_id}",
            "GET /v1/tenants/{tenant_id}/environments",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/abuse/bans",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/admin-consent",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/signup-form",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/config/snapshot",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/connectors",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}/capabilities",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}/health",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/dcr/policies",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/client-auth",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/flow/{flow_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/policy-traces",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/warnings",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/export",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/invitations",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/keys",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/keys/{key_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/locales/{locale}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs/{run_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs/{run_id}/violations",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/migration/progress",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/refresh-families",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/refresh-families/{family_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/sessions",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/sessions/{session_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/users",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/webauthn/mds3/health",
            "PATCH /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
            "POST /v1/tenants",
            "POST /v1/tenants/{tenant_id}/environments",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/abuse/bans",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/abuse/bans/lift",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/admin/sudo/elevate",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/verify",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/config/promotion/apply",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/config/promotion/plan",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/connectors",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/dcr/initial-access-tokens",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/dcr/policies",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/flow/dry-run",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/invitations",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}/resend",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}/revoke",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/keys",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/migration/verify-credential",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/password-hashing/probe",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals/{flow_id}/approve",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals/{flow_id}/reject",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/sessions/revoke",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/sessions/{session_id}/revoke",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/approve",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/extend",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/reject",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/users",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/sessions/revoke",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/state",
            "POST /v1/tenants/{tenant_id}/restore",
            "POST /v1/tenants/{tenant_id}/resume",
            "POST /v1/tenants/{tenant_id}/suspend",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/admin-consent",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/signup-form",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/favicon",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/logo",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/locales/{locale}",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/external-id",
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

/// The served routes match the documented routes, checked DB-FREE by driving
/// requests through `management_router` itself (not just inspecting the spec).
///
/// A shared declarative route table (the ideal, so router and spec derive from
/// one source) is impractical with axum's typed per-path handlers, so this uses
/// the sanctioned fallback: for each documented `(method, path)` an unauthenticated
/// probe with placeholder path params must reject at the `Principal` extractor
/// with 401 (BEFORE any `Path` extraction or store access, which is why it stays
/// database-free over a lazy, never-connected pool), and the count of served
/// `(method, path)` pairs over the documented paths must equal the documented
/// count.
///
/// Guarantees: every documented route is actually wired and auth-gated, and no
/// documented path serves an undocumented method (that would be a served 401,
/// bumping the count). NOT caught here: a brand-new served path outside the
/// documented set (axum does not expose its route table to enumerate), and the
/// deliberately-served-and-undocumented `GET /openapi.json`. Those are guarded by
/// `documented_paths_are_the_expected_set`, `scripts/openapi-check.sh` (spec
/// drift), and the fact that a new route needs a `#[utoipa::path]` to appear in
/// the spec at all.
#[tokio::test]
async fn served_routes_match_documented_routes() {
    let router = db_free_router();
    let documented = documented_method_paths();
    assert_eq!(documented.len(), 94, "the documented route count is pinned");

    // The OUTBOUND lazy-migration endpoint (issue #58) is the one documented route
    // that is NOT gated by the management `Principal` at 401. It is DISABLED BY
    // DEFAULT and scope-bound: its enablement gate is evaluated BEFORE the bearer
    // check, so an unauthenticated probe against the default (disabled) config is a
    // uniform 404, indistinguishable from an absent route. That is the intended
    // posture (a disabled credential oracle reveals nothing), so it is asserted as a
    // 404 here rather than a 401.
    let outbound =
        "/v1/tenants/{tenant_id}/environments/{environment_id}/migration/verify-credential";

    // 1. Every documented (method, path) is wired. The management-gated routes reject
    //    an unauthenticated probe at the `Principal` extractor with 401 (BEFORE any DB
    //    access); the disabled-by-default outbound endpoint is a uniform 404.
    for (method, path) in &documented {
        let status = probe(&router, method, &concrete_path(path)).await;
        let expected = if path == outbound {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::UNAUTHORIZED
        };
        assert_eq!(
            status, expected,
            "{method} {path} must be served with its documented posture (got {status})"
        );
    }

    // 2. No documented path serves an extra method: probe every documented path
    //    with every real method and count the ones that are served (not 404/405). The
    //    outbound path is EXCLUDED (disabled by default, so every method is a uniform
    //    404 and it cannot be probed for an extra method this way), so the expected
    //    served count is the documented count minus its one documented pair.
    let paths: BTreeSet<&String> = documented
        .iter()
        .map(|(_, path)| path)
        .filter(|path| path.as_str() != outbound)
        .collect();
    let mut served = 0_usize;
    for path in &paths {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            let status = probe(&router, method, &concrete_path(path)).await;
            if status != StatusCode::NOT_FOUND && status != StatusCode::METHOD_NOT_ALLOWED {
                served += 1;
            }
        }
    }
    let outbound_pairs = documented
        .iter()
        .filter(|(_, path)| path == outbound)
        .count();
    assert_eq!(
        served,
        documented.len() - outbound_pairs,
        "served (method, path) pairs over the documented paths (excluding the disabled-by-default \
         outbound endpoint) must equal the documented count"
    );
}

/// Build the management router over a LAZY pool: the URL is parsed but no
/// connection is ever opened, and every probe below rejects at the extractor
/// before touching the store, so the test is database-free.
fn db_free_router() -> Router {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://ironauth@localhost/ironauth")
        .expect("lazy pool parses the URL");
    let config = AdminConfig {
        bootstrap_operator_token: Some(Secret::Literal(SecretString::new("t"))),
        ..AdminConfig::default()
    };
    let state =
        AdminState::new(Store::from_pool(pool), Env::system(), &config).expect("state builds");
    management_router(state)
}

/// Every documented `(METHOD, path)` pair from the spec.
fn documented_method_paths() -> Vec<(String, String)> {
    let doc = spec();
    let mut out = Vec::new();
    for (path, methods) in doc["paths"].as_object().expect("paths") {
        for method in methods.as_object().expect("methods").keys() {
            out.push((method.to_uppercase(), path.clone()));
        }
    }
    out
}

/// Substitute each `{param}` path segment with a concrete placeholder so the
/// router matches (the value is irrelevant: auth rejects before `Path` parsing).
fn concrete_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.starts_with('{') {
                "x"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Drive one unauthenticated request through a clone of the router and return its
/// status. The router is `Clone`; oneshot consumes it, so each probe clones.
async fn probe(router: &Router, method: &str, path: &str) -> StatusCode {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .expect("request builds");
    router
        .clone()
        .oneshot(request)
        .await
        .expect("router is infallible")
        .status()
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
