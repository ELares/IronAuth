// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every documented management operation declares the permission it requires (issue #102).
//!
//! # Why this pin exists before the enforcement it guards
//!
//! Delegated administration restricts what a management credential may do. The dangerous
//! failure is not a wrong permission on a route, it is a route with NO permission: it defaults
//! to allowed, nothing goes red, and the gap is invisible until somebody audits 198 operations
//! by hand. That is the same shape as every dormant-layer defect in this tree, and adding
//! routes is continuous.
//!
//! So the classification lands FIRST, as a total function over the operation set, and the
//! enforcement rolls out behind it. A route added tomorrow fails this test until somebody
//! decides what authority it needs.
//!
//! # The UNCLASSIFIED list is deliberate, explicit, and meant to shrink
//!
//! Classifying 198 operations correctly is not a mechanical exercise: several of them are
//! read-and-write pairs on the same resource, and a few (the migration credential surface) sit
//! on the boundary between configuration and credential authority. Guessing in bulk would
//! produce a table that looks complete and is wrong in ways nobody can see.
//!
//! So an operation is either CLASSIFIED or on the explicit unclassified list, and the test
//! asserts the two together cover the documented set EXACTLY. An operation on neither fails.
//! An operation on both fails. The unclassified list is a debt with a number attached, which is
//! the same device `scoped-table-registration` uses for its two documented exceptions.
//!
//! Until an operation is classified it is UNRESTRICTED, which is what it is today, so this pin
//! takes no authority from anyone. What it removes is the ability to add a route without
//! deciding.

use std::collections::BTreeSet;

use ironauth_admin::ManagementPermission;
use serde_json::Value;

/// The published management API document.
fn spec() -> Value {
    let raw = include_str!("../../../docs/openapi/management.json");
    serde_json::from_str(raw).expect("the committed OpenAPI artifact parses")
}

/// Every documented operation id.
fn documented_operations() -> BTreeSet<String> {
    spec()["paths"]
        .as_object()
        .expect("paths")
        .values()
        .flat_map(|path| path.as_object().expect("methods").values())
        .filter_map(|op| op.get("operationId").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

/// Operations whose required permission is DECIDED.
///
/// Started with the credential surface because it is the one that can escalate: a key able to
/// mint or revoke keys can reach every other authority, so it must not be reachable by a
/// credential granted ordinary configuration rights. That is why `WriteCredentials` is a
/// separate permission rather than part of `WriteConfig`.
const CLASSIFIED: &[(&str, ManagementPermission)] = &[
    (
        "createManagementKey",
        ManagementPermission::WriteCredentials,
    ),
    (
        "deleteManagementKey",
        ManagementPermission::WriteCredentials,
    ),
    ("getManagementKey", ManagementPermission::Read),
    ("listManagementKeys", ManagementPermission::Read),
];

/// Operations not yet classified. This list is DEBT and is meant to shrink to nothing.
///
/// Every entry is currently unrestricted, which is exactly its behaviour before issue #102, so
/// nothing here is a regression. Removing an entry means deciding its authority, not changing
/// what it does today.
const UNCLASSIFIED: &[&str] = &[
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
    "createMembership",
    "createOrgGroup",
    "createOrgRole",
    "createOrganization",
    "createPermission",
    "createTenant",
    "createTraitMigrationJob",
    "createTraitSchemaVersion",
    "createUser",
    "createWebhookEndpoint",
    "deleteBrand",
    "deleteBrandFavicon",
    "deleteBrandLogo",
    "deleteClientAdminConsent",
    "deleteConnector",
    "deleteEnvironment",
    "deleteLocale",
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
    "extendSignupQuarantine",
    "getActiveTraitSchema",
    "getBrand",
    "getClientAdminConsent",
    "getClientAllowedScopes",
    "getClientAuthDiagnostics",
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
    "listOrganizations",
    "listPermissions",
    "listQueueDepths",
    "listRecoveryApprovals",
    "listRefreshFamilies",
    "listResourceServers",
    "listResourceTypes",
    "listSecrets",
    "listSessions",
    "listSignupQuarantines",
    "listSmsAllowlist",
    "listStepUpPolicies",
    "listTenants",
    "listTraitSchemaVersions",
    "listUserConsents",
    "listUserIdentifiers",
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
    "purgeTenant",
    "rejectRecoveryApproval",
    "rejectSignupQuarantine",
    "removeOrgGroupMember",
    "removeStepUpPolicy",
    "removeUserIdentifier",
    "replayWebhookDeadLetters",
    "resendInvitation",
    "restoreTenant",
    "resumeIdentityImport",
    "resumeTenant",
    "resumeWebhookEndpoint",
    "revokeInvitation",
    "revokeSession",
    "revokeUserConsent",
    "revokeUserSessions",
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
];

#[test]
fn every_documented_operation_is_classified_or_explicitly_deferred() {
    let documented = documented_operations();
    let classified: BTreeSet<String> = CLASSIFIED.iter().map(|(id, _)| (*id).to_owned()).collect();
    let deferred: BTreeSet<String> = UNCLASSIFIED.iter().map(|id| (*id).to_owned()).collect();

    let both: Vec<&String> = classified.intersection(&deferred).collect();
    assert!(
        both.is_empty(),
        "an operation is both classified and deferred, so the two lists disagree about \
         whether its authority was decided: {both:?}"
    );

    let covered: BTreeSet<String> = classified.union(&deferred).cloned().collect();

    let unknown: Vec<&String> = covered.difference(&documented).collect();
    assert!(
        unknown.is_empty(),
        "a list names an operation the API does not document, so the classification has \
         rotted against the spec: {unknown:?}"
    );

    let undecided: Vec<&String> = documented.difference(&covered).collect();
    assert!(
        undecided.is_empty(),
        "{} documented operation(s) declare no required permission and are on no deferral \
         list. An operation with no declared authority DEFAULTS TO ALLOWED, which is the \
         failure this pin exists to prevent. Classify it in CLASSIFIED, or add it to \
         UNCLASSIFIED with the rest of the debt: {undecided:?}",
        undecided.len()
    );
}

#[test]
fn the_credential_surface_is_classified_and_separated_from_configuration() {
    // The escalation path, asserted directly rather than left implied by the table above: a
    // credential granted ordinary configuration authority must not be able to mint or revoke
    // credentials, because a key that can mint keys can reach everything.
    for id in ["createManagementKey", "deleteManagementKey"] {
        let Some((_, permission)) = CLASSIFIED.iter().find(|(candidate, _)| *candidate == id)
        else {
            panic!("{id} is not classified");
        };
        let permission = *permission;
        assert_eq!(
            permission,
            ManagementPermission::WriteCredentials,
            "{id} is reachable by a permission other than WriteCredentials, so a credential \
             granted that permission can escalate to every authority by minting a new key"
        );
    }
}

#[test]
fn the_unclassified_debt_is_counted_so_it_cannot_grow_unnoticed() {
    // A deferral list with no number attached is a place to hide work. This is the count, and
    // it is expected to fall to zero as the enforcement rolls out. It must never RISE: a new
    // route is a new decision, not a new deferral.
    assert_eq!(
        UNCLASSIFIED.len(),
        194,
        "the unclassified list changed size. It may only SHRINK: an operation added to it is \
         an operation somebody chose not to decide about"
    );
}
