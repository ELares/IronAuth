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

/// The published body schema must not contradict its own server (issue #98, PR 15).
///
/// `SetClientAllowedScopesRequest.allowed_scopes` is `Option<Option<T>>` under the
/// `named_field` seam, and utoipa reads the OUTER `Option` as "optional field" the way
/// it does everywhere else. Without an explicit `required = true` the document carries
/// no `required` array at all, so a generated client would let a caller omit a key the
/// server answers 400 for (`tests/client_scopes.rs`
/// `an_absent_allowed_scopes_key_is_a_400_and_is_not_the_explicit_null` drives that 400
/// over HTTP). Pinned here because the failure is SILENT in every other lane: the spec
/// regenerates cleanly either way, the freshness gate stays green, and only a code
/// generator downstream ever notices.
#[test]
fn the_set_allowed_scopes_body_declares_its_required_field() {
    let doc = spec();
    let schema = &doc["components"]["schemas"]["SetClientAllowedScopesRequest"];
    let required: Vec<&str> = schema["required"]
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert_eq!(
        required,
        vec!["allowed_scopes"],
        "the body's one field is documented as REQUIRED, matching the server's 400"
    );

    // And the value stays NULLABLE, which is the other half of the shape: the explicit
    // clear is `{"allowed_scopes": null}`. A required key with a nullable value, never
    // an optional key. Collapsing either half would delete the distinction the whole
    // body is built on.
    let kinds = &schema["properties"]["allowed_scopes"]["type"];
    assert!(
        kinds
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value == "null")),
        "a present `null` is the documented clear: {kinds}"
    );
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
            "abandonMigrationRun",
            "activateTraitSchemaVersion",
            "addOrgGroupMember",
            "addUserIdentifier",
            "allowSmsCountry",
            "applyConfigPromotion",
            "applyIdentifierUniqueness",
            "approveRecoveryApproval",
            "approveSignupQuarantine",
            "assignOrgGroupRole",
            "assignOrgMembershipRole",
            "assignOrgRolePermission",
            "authorizeUserImpersonation",
            "authzenEvaluation",
            "authzenEvaluations",
            "bulkRevokeSessions",
            "clearOrgDefaultRole",
            "createBan",
            "createConnector",
            "createDcrInitialAccessToken",
            "createDcrPolicy",
            "createEnvironment",
            "createFlowVersion",
            "createIdentityImport",
            "createInvitation",
            "createLogStream",
            "createManagementKey",
            "createMembership",
            "createOrgGroup",
            "createOrgRole",
            "createOrganization",
            "createOrganizationApiKey",
            "createPermission",
            "createProjectGrant",
            "createRoutingRule",
            "createServiceAccountApiKey",
            "createTenant",
            "createTraitMigrationJob",
            "createTraitSchemaVersion",
            "createUser",
            "createUserPersonalAccessToken",
            "createWebhookEndpoint",
            "deleteBrand",
            "deleteBrandFavicon",
            "deleteBrandLogo",
            "deleteClientAdminConsent",
            "deleteConnector",
            "deleteEnvironment",
            "deleteLocale",
            "deleteLogStream",
            "deleteManagementKey",
            "deleteMembership",
            "deleteOrgGroup",
            "deleteOrgRole",
            "deleteOrganization",
            "deleteOutboundVerification",
            "deletePermission",
            "deleteSecret",
            "deleteSignupForm",
            "deleteTenant",
            "deleteUser",
            "deleteVariable",
            "deleteWebhookEndpoint",
            "denySmsCountry",
            "disableOrganization",
            "elevateAdminSudo",
            "enableOrganization",
            "exportConfigSnapshot",
            "exportIdentities",
            "exportUsage",
            "extendSignupQuarantine",
            "getActiveTraitSchema",
            "getAuthzenConfiguration",
            "getBrand",
            "getClientAdminConsent",
            "getClientAllowedScopes",
            "getClientAuthDiagnostics",
            "getClientServiceAccount",
            "getConnector",
            "getConnectorCapabilities",
            "getConnectorHealth",
            "getDcrClient",
            "getDiagnosticsWarnings",
            "getEnvironment",
            "getFlowObservation",
            "getFlowVersion",
            "getIdentifierUniqueness",
            "getInvitation",
            "getLocale",
            "getManagementKey",
            "getMds3Health",
            "getMigrationProgress",
            "getMigrationRun",
            "getOperator",
            "getOrgGroup",
            "getOrgMembershipEffectiveRoles",
            "getOrgRole",
            "getOrganization",
            "getOutboundVerification",
            "getPermission",
            "getPolicyDecisionTraces",
            "getRefreshFamily",
            "getResourceServer",
            "getRiskDecision",
            "getSecret",
            "getSession",
            "getSigningRecommendations",
            "getSignupForm",
            "getSmsOtpConfig",
            "getTenant",
            "getTraitMigrationJob",
            "getTraitSchemaVersion",
            "getUser",
            "getUserRiskPosture",
            "getUserTraits",
            "getVariable",
            "liftBan",
            "linkUserExternalId",
            "listBans",
            "listBrands",
            "listConnectors",
            "listDcrPolicies",
            "listEnvironments",
            "listFlowVersions",
            "listInvitations",
            "listLogStreamDeadLetters",
            "listLogStreams",
            "listManagementKeys",
            "listMemberships",
            "listMigrationRunViolations",
            "listMigrationRuns",
            "listOperators",
            "listOrgGroupMembers",
            "listOrgGroupRoles",
            "listOrgGroups",
            "listOrgMembershipRoles",
            "listOrgRolePermissions",
            "listOrgRoles",
            "listOrganizationApiKeys",
            "listOrganizations",
            "listPermissions",
            "listProjectGrants",
            "listQueueDepths",
            "listRecoveryApprovals",
            "listRefreshFamilies",
            "listResourceServers",
            "listResourceTypes",
            "listRoutingRules",
            "listSecrets",
            "listServiceAccountApiKeys",
            "listSessions",
            "listSignupQuarantines",
            "listSmsAllowlist",
            "listStepUpPolicies",
            "listTenants",
            "listTraitSchemaVersions",
            "listUserConsents",
            "listUserIdentifiers",
            "listUserPersonalAccessTokens",
            "listUsers",
            "listVariables",
            "listWebhookDeadLetters",
            "listWebhookDeliveryAttempts",
            "listWebhookEndpoints",
            "pauseWebhookEndpoint",
            "pinFlowVersion",
            "planConfigPromotion",
            "postFlowDryRun",
            "probePasswordHashing",
            "publishUsage",
            "purgeTenant",
            "readEventFeed",
            "rejectRecoveryApproval",
            "rejectSignupQuarantine",
            "removeOrgGroupMember",
            "removeStepUpPolicy",
            "removeUserIdentifier",
            "replayLogStreamDeadLetters",
            "replayWebhookDeadLetters",
            "resendInvitation",
            "restoreTenant",
            "resumeIdentityImport",
            "resumeTenant",
            "resumeWebhookEndpoint",
            "revokeInvitation",
            "revokeOrganizationApiKey",
            "revokeServiceAccountApiKey",
            "revokeSession",
            "revokeUserConsent",
            "revokeUserPersonalAccessToken",
            "revokeUserSessions",
            "rotateOrganizationApiKey",
            "rotateServiceAccountApiKey",
            "rotateUserPersonalAccessToken",
            "rotateWebhookEndpointSecret",
            "setAutoLinkPosture",
            "setBrand",
            "setBrandFavicon",
            "setBrandLogo",
            "setClientAdminConsent",
            "setClientAllowedScopes",
            "setClientParRequirement",
            "setClientSigningAlgorithm",
            "setLocale",
            "setOrgDefaultRole",
            "setOrgGroupParent",
            "setOutboundVerification",
            "setSecret",
            "setSignupForm",
            "setSmsOtpConfig",
            "setStepUpPolicy",
            "setUserState",
            "setVariable",
            "setWebhookEventTypes",
            "suspendTenant",
            "unassignOrgGroupRole",
            "unassignOrgMembershipRole",
            "unassignOrgRolePermission",
            "unlinkUserExternalId",
            "updateConnector",
            "updateOrgGroup",
            "updateOrgRole",
            "updatePermission",
            "updateResourceServerPermissionClaims",
            "updateUser",
            "verifyDcrClient",
            "verifyMigrationCredential",
            "verifyRoutingRuleDomain",
            "withdrawProjectGrant",
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
        "listOrgRoles",
        "listOrgGroups",
        "listOrgGroupMembers",
        "listOrgGroupRoles",
        "listOrgMembershipRoles",
        "listOrgRolePermissions",
        "listPermissions",
        "listResourceServers",
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
        "createFlowVersion",
        "pinFlowVersion",
        "createTraitSchemaVersion",
        "activateTraitSchemaVersion",
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
        "createOrgRole",
        "createOrgGroup",
        "addOrgGroupMember",
        "assignOrgGroupRole",
        "assignOrgMembershipRole",
        "assignOrgRolePermission",
        "createPermission",
        // Issue #345 added the header to `revokeUserConsent`. The sweep that found it
        // also found SEVEN operations that already documented the header and were
        // pinned by nothing, so they are added too: an operation can lose the header
        // without any test noticing, which is the same defect one step earlier.
        //
        // The last five document it as OPTIONAL rather than required, which is a
        // deliberate per-route choice for operations that are safe to repeat. This
        // assertion is that the header is DOCUMENTED, not that it is mandatory, so
        // pinning them here keeps the documentation from silently disappearing without
        // making any claim about whether a caller must send it.
        "revokeUserConsent",
        "createIdentityImport",
        "createMembership",
        "applyConfigPromotion",
        "elevateAdminSudo",
        "planConfigPromotion",
        "probePasswordHashing",
        "resumeIdentityImport",
        // The organization state toggles, added with their Idempotency-Key handling.
        "disableOrganization",
        "enableOrganization",
        // The abuse-ban routes, added with their Idempotency-Key handling.
        "createBan",
        "liftBan",
        // Implemented all along, documented by nothing: both routes call
        // `required_key`, so the published spec omitted a header they REFUSE without.
        "addUserIdentifier",
        "applyIdentifierUniqueness",
        "abandonMigrationRun",
        "rotateWebhookEndpointSecret",
        "pauseWebhookEndpoint",
        "resumeWebhookEndpoint",
        "createWebhookEndpoint",
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
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/favicon",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/logo",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/keys/{key_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/locales/{locale}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/log-streams/{stream_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/migration/outbound-verification",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/api-keys/{key_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/default-role",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/members/{membership_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/roles/{role_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/roles/{role_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/project-grants/{grant_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions/{permission_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/permissions/{permission_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/secrets/{name}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/service-accounts/{service_account_id}/api-keys/{key_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/allowlist/{country_code}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/step-up-policies/{scope_token}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/external-id",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/identifiers/{identifier_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/personal-access-tokens/{key_id}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/variables/{name}",
            "DELETE /v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}",
            "GET /v1/interop/signing-recommendations",
            "GET /v1/operators",
            "GET /v1/operators/{operator_id}",
            "GET /v1/resource-types",
            "GET /v1/tenants",
            "GET /v1/tenants/{tenant_id}",
            "GET /v1/tenants/{tenant_id}/environments",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/.well-known/authzen-configuration",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/abuse/bans",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/admin-consent",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/signup-form",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/brands",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/allowed-scopes",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/service-account",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/config/snapshot",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/connectors",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}/capabilities",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}/health",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/dcr/policies",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/client-auth",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/flow/{flow_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/policy-traces",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/risk/decisions/{decision_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/risk/users/{user_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/warnings",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/events",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/export",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/identifier-uniqueness",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/invitations",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/journeys/{journey_id}/versions",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/journeys/{journey_id}/versions/{version}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/keys",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/keys/{key_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/locales/{locale}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/log-streams",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/log-streams/{stream_id}/dead-letters",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs/{run_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs/{run_id}/violations",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/migration/outbound-verification",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/migration/progress",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/api-keys",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/members",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/roles",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/effective-roles",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/roles",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/project-grants",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/permissions",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/permissions/{permission_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/queues",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/refresh-families",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/refresh-families/{family_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/resource-servers",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/resource-servers/{resource_server_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/routing-rules",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/secrets",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/secrets/{name}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/service-accounts/{service_account_id}/api-keys",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/sessions",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/sessions/{session_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/allowlist",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/config",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/step-up-policies",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/active",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/migrations/{job_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/{version}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/usage",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/users",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/consents",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/identifiers",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/personal-access-tokens",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/traits",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/variables",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/variables/{name}",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/webauthn/mds3/health",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/attempts",
            "GET /v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/dead-letters",
            "PATCH /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}",
            "PATCH /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}",
            "PATCH /v1/tenants/{tenant_id}/environments/{environment_id}/permissions/{permission_id}",
            "PATCH /v1/tenants/{tenant_id}/environments/{environment_id}/resource-servers/{resource_server_id}",
            "PATCH /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
            "POST /v1/tenants",
            "POST /v1/tenants/{tenant_id}/environments",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/abuse/bans",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/abuse/bans/lift",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/access/v1/evaluation",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/access/v1/evaluations",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/admin/sudo/elevate",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/verify",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/config/promotion/apply",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/config/promotion/plan",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/connectors",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/dcr/initial-access-tokens",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/dcr/policies",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/flow/dry-run",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/identifier-uniqueness/apply",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/imports",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/imports/{run_id}",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/invitations",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}/resend",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}/revoke",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/journeys/{journey_id}/versions",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/journeys/{journey_id}/versions/{version}/pin",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/keys",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/log-streams",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/log-streams/{stream_id}/dead-letters/replay",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs/{run_id}/abandon",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/migration/verify-credential",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/api-keys",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/api-keys/{key_id}/rotate",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/disable",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/enable",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/members",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/roles",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/roles",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/project-grants",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/password-hashing/probe",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/permissions",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals/{flow_id}/approve",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/recovery-approvals/{flow_id}/reject",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/routing-rules",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/routing-rules/{rule_id}/verify-domain",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/service-accounts/{service_account_id}/api-keys",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/service-accounts/{service_account_id}/api-keys/{key_id}/rotate",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/sessions/revoke",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/sessions/{session_id}/revoke",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/approve",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/extend",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/signup-quarantine/{user_id}/reject",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/step-up-policies",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/migrations",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/{version}/activate",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/usage/publish",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/users",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/consents/{client_id}/revoke",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/identifiers",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/impersonation",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/personal-access-tokens",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/personal-access-tokens/{key_id}/rotate",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/sessions/revoke",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/state",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/pause",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/replay",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/resume",
            "POST /v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/rotate-secret",
            "POST /v1/tenants/{tenant_id}/purge",
            "POST /v1/tenants/{tenant_id}/restore",
            "POST /v1/tenants/{tenant_id}/resume",
            "POST /v1/tenants/{tenant_id}/suspend",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/admin-consent",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/applications/{client_id}/signup-form",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/auto-link-posture",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/favicon",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/brands/{slug}/logo",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/allowed-scopes",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/par-requirement",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/signing-algorithm",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/locales/{locale}",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/migration/outbound-verification",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/default-role",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/parent",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/secrets/{name}",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/allowlist/{country_code}",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/sms-otp/config",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/external-id",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/variables/{name}",
            "PUT /v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/event-types",
        ]
    );
}

/// No PRIVATE RUST MODULE PATH leaks into the published contract (issue #425).
///
/// Every `description` in this document is a rustdoc comment lifted verbatim by
/// utoipa, so a rustdoc intra-doc link written as ``[`crate::some::private::Path`]``
/// ships to every consumer of the spec and to the generated TypeScript with it. That
/// is not merely untidy: `crate::` names a module tree no API consumer can see or
/// resolve, so it reads as a broken reference in the one artifact that is supposed to
/// be self-contained. One such link shipped before this test existed and nothing
/// caught it, because there is no rustdoc lane in the local gate or in CI.
///
/// Scoped to the `crate::`-prefixed form deliberately. A bare type name in a link is
/// a legible cross-reference to a schema this same document defines; a private module
/// path is not.
#[test]
fn no_private_rust_module_path_reaches_the_published_contract() {
    let mut offenders = Vec::new();
    collect_descriptions(&spec(), "", &mut offenders);
    let leaked: Vec<&(String, String)> = offenders
        .iter()
        .filter(|(_, text)| text.contains("crate::"))
        .collect();
    assert!(
        leaked.is_empty(),
        "a private Rust module path reached the published spec; write the reference \
         without the `crate::` prefix: {leaked:?}"
    );
}

/// Every `description` string in the document, with the JSON pointer that reaches it,
/// so a failure names WHERE the offending text lives rather than only that it exists.
fn collect_descriptions(node: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "description" {
                    if let Some(text) = value.as_str() {
                        out.push((format!("{path}/description"), text.to_owned()));
                    }
                }
                collect_descriptions(value, &format!("{path}/{key}"), out);
            }
        }
        Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                collect_descriptions(value, &format!("{path}/{index}"), out);
            }
        }
        _ => {}
    }
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
    assert_eq!(
        documented.len(),
        229,
        "the documented route count is pinned"
    );

    // The OUTBOUND lazy-migration endpoint (issue #58, re-homed by #250) is the one
    // documented route that is NOT gated by the management `Principal` at 401: every
    // refusal on it is the uniform 404, indistinguishable from an absent route, because
    // a 401 would tell an unauthenticated prober which environments have an outbound
    // migration armed. So it is asserted as a 404 here rather than a 401.
    //
    // What this sweep does NOT say, stated because it used to be cited as if it did:
    // it says NOTHING about the ORDER in which that 404 is reached. This router carries
    // no master key, so the secret read short-circuits before it issues a query and a
    // handler that read the secret BEFORE the bearer answers the same 404 over the same
    // never-connected pool. MEASURED: exactly that mutant survives this file and the
    // whole crate suite. The order is pinned by
    // `the_outbound_bearer_check_runs_before_any_database_access` below, which counts
    // connections rather than statuses.
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

/// The outbound verify endpoint reads the BEARER before it touches the database, pinned
/// by COUNTING CONNECTIONS rather than by reading a status (issue #250).
///
/// # Why a status assertion cannot pin this, measured rather than argued
///
/// The order is the whole anti-enumeration property: a request with no credential must
/// be refused before it can make the endpoint issue a query, so an unauthenticated
/// prober cannot make the server work on its behalf and cannot learn anything from how
/// long that work took. Every existing witness for it was a 404, and a 404 is exactly
/// what a REORDERED handler answers too. Mutating `verify_credential` to read the secret
/// first compiled and survived the entire `ironauth-admin` suite (392 tests over 46
/// binaries), because `db_free_router` builds a store with no master key, so
/// `open_value_under_platform_key_at_uniform_cost` returns at `Store::master` before any
/// query and `stored_outbound_token` collapses the error to `None`.
///
/// So this drives a router whose store DOES carry a master key, over a lazy pool aimed
/// at a socket that accepts connections and counts them, and asserts the two halves
/// together:
///
/// * a request with NO bearer answers the uniform not-found having opened ZERO
///   connections. That is the property.
/// * a request WITH a (garbage) bearer opens at least one. That is the ANTI-VACUITY
///   CONTROL, and it is not optional: without it the first assertion is satisfied by any
///   route that never reaches the store for any reason at all, including a route that
///   does not exist.
///
/// The socket accepts and then says nothing, so the second probe ends at the pool's
/// acquire timeout and the endpoint answers its uniform not-found there too, which is
/// the fail-closed behaviour `stored_outbound_token` documents.
#[tokio::test]
async fn the_outbound_bearer_check_runs_before_any_database_access() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a probe socket");
    let port = listener.local_addr().expect("probe socket address").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    // Accept and HOLD: a client that completes a TCP handshake and then waits is what
    // makes "a connection was attempted" observable without a database anywhere.
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    counter.fetch_add(1, Ordering::SeqCst);
                    held.push(stream);
                }
                Err(_) => break,
            }
        }
    });

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(750))
        .connect_lazy(&format!("postgres://ironauth@127.0.0.1:{port}/ironauth"))
        .expect("lazy pool parses the URL");
    let config = AdminConfig {
        bootstrap_operator_token: Some(Secret::Literal(SecretString::new("t"))),
        ..AdminConfig::default()
    };
    // WITH a master key, which is the difference from `db_free_router` and the reason
    // this test can see the order at all.
    let master = Arc::new(ironauth_jose::MasterKey::generate(
        "master-order-probe",
        &ironauth_env::FixedEntropy::new(0x4f52_4452),
    ));
    let state = AdminState::new(
        Store::from_pool(pool).with_master_key(master),
        Env::system(),
        &config,
    )
    .expect("state builds");
    let router = management_router(state);

    // WELL-FORMED ids, which is load bearing rather than cosmetic: a malformed path id
    // is itself the uniform not-found, refused by pure parsing before the store is
    // reached, so a placeholder like `ten_x` would make BOTH probes answer 404 with zero
    // connections and the control below would go red for a reason that has nothing to do
    // with the order. They name no rows, and cannot: this pool reaches no database.
    let tenant = ironauth_store::TenantId::generate(&Env::system());
    let environment = ironauth_store::EnvironmentId::generate(&Env::system());
    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/migration/verify-credential");
    let path = path.as_str();
    let body = r#"{"identifier":"probe@example.test","password":"probe"}"#;

    // 1. No bearer: refused before anything, so the pool was never asked for a
    //    connection.
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "an unauthenticated probe is the uniform not-found"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "a request with no bearer must be refused BEFORE any database access: the pool \
         opened a connection, so the secret read now runs before the bearer check"
    );

    // 2. A garbage bearer: the control. It gets past the bearer check, so it DOES reach
    //    the store, which is what makes the zero above attributable to the order.
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(
            axum::http::header::AUTHORIZATION,
            "Bearer garbage-bearer-not-a-real-token-x",
        )
        .body(Body::from(body))
        .expect("request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "an unreachable store fails CLOSED to the same uniform not-found"
    );
    assert!(
        accepted.load(Ordering::SeqCst) >= 1,
        "the control probe must actually reach the store, or the assertion above measures \
         nothing: no connection was ever attempted"
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
