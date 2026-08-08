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
/// The SESSION surface is in the same position and for the same reason: `revoke_session`,
/// `bulk_revoke_sessions`, `list_sessions` and their neighbours all call `require_operator`,
/// so a management key cannot reach them either. Checked, not assumed, before deferring them.
///
/// The credential surface is classified but NOT enforced, and that is not an oversight:
/// `create_key`, `list_keys`, `get_key` and `delete_key` all call `require_operator`, so a
/// management key can never reach them and a permission check there could never refuse
/// anything. Adding one would be inert code that reads like a control. The classification
/// stands as the declaration of what authority those operations represent.
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
    // The user surface: the first operations where the declaration is actually ENFORCED,
    // because unlike the credential surface these are reachable by a management key.
    ("createUser", ManagementPermission::WriteUsers),
    ("deleteUser", ManagementPermission::WriteUsers),
    ("listUsers", ManagementPermission::Read),
    ("getUser", ManagementPermission::Read),
    // The organization surface. `disableOrganization` and `enableOrganization` are enforced in
    // their SHARED body, so both carry the same requirement by construction rather than by two
    // edits staying in agreement.
    (
        "createOrganization",
        ManagementPermission::WriteOrganizations,
    ),
    (
        "deleteOrganization",
        ManagementPermission::WriteOrganizations,
    ),
    (
        "disableOrganization",
        ManagementPermission::WriteOrganizations,
    ),
    (
        "enableOrganization",
        ManagementPermission::WriteOrganizations,
    ),
    ("listOrganizations", ManagementPermission::Read),
    ("getOrganization", ManagementPermission::Read),
    // The environment CONFIG surface. A secret write is configuration authority: a credential
    // that can seal a value can change what every connector authenticates with, so it sits
    // here rather than being treated as lesser because the value is unreadable afterwards.
    ("setVariable", ManagementPermission::WriteConfig),
    ("deleteVariable", ManagementPermission::WriteConfig),
    ("listVariables", ManagementPermission::Read),
    ("getVariable", ManagementPermission::Read),
    ("setSecret", ManagementPermission::WriteConfig),
    ("deleteSecret", ManagementPermission::WriteConfig),
    ("listSecrets", ManagementPermission::Read),
    ("getSecret", ManagementPermission::Read),
    // The organization SUB-surfaces: roles, memberships and the permission vocabulary. All
    // `WriteOrganizations` for the writes, because each is a way to change who holds what
    // inside an organization, which is the same authority as changing the organization.
    (
        "assignOrgRolePermission",
        ManagementPermission::WriteOrganizations,
    ),
    (
        "unassignOrgRolePermission",
        ManagementPermission::WriteOrganizations,
    ),
    ("listOrgRolePermissions", ManagementPermission::Read),
    ("createMembership", ManagementPermission::WriteOrganizations),
    ("deleteMembership", ManagementPermission::WriteOrganizations),
    ("listMemberships", ManagementPermission::Read),
    ("createPermission", ManagementPermission::WriteOrganizations),
    ("updatePermission", ManagementPermission::WriteOrganizations),
    ("deletePermission", ManagementPermission::WriteOrganizations),
    ("listPermissions", ManagementPermission::Read),
    ("getPermission", ManagementPermission::Read),
    // Bans and invitations, both USER authority. An invitation provisions a
    // `pending_verification` identity and a single-use token, so whoever may invite may
    // populate the environment; it is not a lesser "send an email" operation.
    ("createBan", ManagementPermission::WriteUsers),
    ("liftBan", ManagementPermission::WriteUsers),
    ("listBans", ManagementPermission::Read),
    ("createInvitation", ManagementPermission::WriteUsers),
    ("revokeInvitation", ManagementPermission::WriteUsers),
    ("resendInvitation", ManagementPermission::WriteUsers),
    ("listInvitations", ManagementPermission::Read),
    ("getInvitation", ManagementPermission::Read),
    // Environment presentation and resource-server configuration: brands, locales, signup
    // forms and permission claims. All configuration authority.
    (
        "updateResourceServerPermissionClaims",
        ManagementPermission::WriteConfig,
    ),
    ("listResourceServers", ManagementPermission::Read),
    ("getResourceServer", ManagementPermission::Read),
    ("setBrand", ManagementPermission::WriteConfig),
    ("deleteBrand", ManagementPermission::WriteConfig),
    ("listBrands", ManagementPermission::Read),
    ("getBrand", ManagementPermission::Read),
    ("setLocale", ManagementPermission::WriteConfig),
    ("deleteLocale", ManagementPermission::WriteConfig),
    ("getLocale", ManagementPermission::Read),
    ("setSignupForm", ManagementPermission::WriteConfig),
    ("deleteSignupForm", ManagementPermission::WriteConfig),
    ("getSignupForm", ManagementPermission::Read),
    // User sub-surfaces: identifiers, trait schemas, signup quarantine and recovery
    // approvals. Identifier UNIQUENESS and trait schemas are config rather than user
    // authority, because each changes a rule the whole environment obeys.
    ("addUserIdentifier", ManagementPermission::WriteUsers),
    ("removeUserIdentifier", ManagementPermission::WriteUsers),
    ("listUserIdentifiers", ManagementPermission::Read),
    (
        "applyIdentifierUniqueness",
        ManagementPermission::WriteConfig,
    ),
    ("getIdentifierUniqueness", ManagementPermission::Read),
    (
        "createTraitSchemaVersion",
        ManagementPermission::WriteConfig,
    ),
    (
        "activateTraitSchemaVersion",
        ManagementPermission::WriteConfig,
    ),
    ("createTraitMigrationJob", ManagementPermission::WriteConfig),
    ("listTraitSchemaVersions", ManagementPermission::Read),
    ("getActiveTraitSchema", ManagementPermission::Read),
    ("getTraitSchemaVersion", ManagementPermission::Read),
    ("getTraitMigrationJob", ManagementPermission::Read),
    ("approveSignupQuarantine", ManagementPermission::WriteUsers),
    ("rejectSignupQuarantine", ManagementPermission::WriteUsers),
    ("extendSignupQuarantine", ManagementPermission::WriteUsers),
    ("listSignupQuarantines", ManagementPermission::Read),
    ("approveRecoveryApproval", ManagementPermission::WriteUsers),
    ("rejectRecoveryApproval", ManagementPermission::WriteUsers),
    ("listRecoveryApprovals", ManagementPermission::Read),
    // Flow versions, webhook delivery, queue depth, step-up policy and SMS OTP: all
    // environment configuration. Webhook pause/resume and the SMS toggles are enforced in
    // shared bodies, so each pair carries one requirement rather than two that can drift.
    ("createFlowVersion", ManagementPermission::WriteConfig),
    ("pinFlowVersion", ManagementPermission::WriteConfig),
    ("listFlowVersions", ManagementPermission::Read),
    ("getFlowVersion", ManagementPermission::Read),
    ("createWebhookEndpoint", ManagementPermission::WriteConfig),
    (
        "rotateWebhookEndpointSecret",
        ManagementPermission::WriteConfig,
    ),
    ("deleteWebhookEndpoint", ManagementPermission::WriteConfig),
    (
        "replayWebhookDeadLetters",
        ManagementPermission::WriteConfig,
    ),
    ("setWebhookEventTypes", ManagementPermission::WriteConfig),
    ("pauseWebhookEndpoint", ManagementPermission::WriteConfig),
    ("resumeWebhookEndpoint", ManagementPermission::WriteConfig),
    ("listWebhookEndpoints", ManagementPermission::Read),
    ("listWebhookDeliveryAttempts", ManagementPermission::Read),
    ("listWebhookDeadLetters", ManagementPermission::Read),
    ("listQueueDepths", ManagementPermission::Read),
    ("setStepUpPolicy", ManagementPermission::WriteConfig),
    ("removeStepUpPolicy", ManagementPermission::WriteConfig),
    ("listStepUpPolicies", ManagementPermission::Read),
    ("setSmsOtpConfig", ManagementPermission::WriteConfig),
    ("allowSmsCountry", ManagementPermission::WriteConfig),
    ("denySmsCountry", ManagementPermission::WriteConfig),
    ("getSmsOtpConfig", ManagementPermission::Read),
    ("listSmsAllowlist", ManagementPermission::Read),
    // Organization groups and roles, client scopes and admin consent, identity export and
    // import, outbound verification and client postures. `exportIdentities` is `read` and is
    // the heaviest read on the surface: a persona that must not drain the environment should
    // not hold read at all.
    ("createOrgGroup", ManagementPermission::WriteOrganizations),
    ("updateOrgGroup", ManagementPermission::WriteOrganizations),
    (
        "setOrgGroupParent",
        ManagementPermission::WriteOrganizations,
    ),
    ("deleteOrgGroup", ManagementPermission::WriteOrganizations),
    ("listOrgGroups", ManagementPermission::Read),
    ("getOrgGroup", ManagementPermission::Read),
    ("createOrgRole", ManagementPermission::WriteOrganizations),
    ("updateOrgRole", ManagementPermission::WriteOrganizations),
    ("deleteOrgRole", ManagementPermission::WriteOrganizations),
    (
        "setOrgDefaultRole",
        ManagementPermission::WriteOrganizations,
    ),
    (
        "clearOrgDefaultRole",
        ManagementPermission::WriteOrganizations,
    ),
    ("listOrgRoles", ManagementPermission::Read),
    ("getOrgRole", ManagementPermission::Read),
    (
        "assignOrgGroupRole",
        ManagementPermission::WriteOrganizations,
    ),
    // Project grants (issue #102). The permission is the same one that governs the rest
    // of organization administration; what keeps a confined credential away from the
    // grant that BOUNDS it is a separate confinement fence in the handlers, not this
    // classification. A permission alone could not express it: the confined credential
    // legitimately holds `write_organizations` for its own organization.
    (
        "createProjectGrant",
        ManagementPermission::WriteOrganizations,
    ),
    // Enterprise inbound routing (issue #96): routing decides WHERE a login is sent,
    // which is environment configuration rather than organization membership.
    ("createRoutingRule", ManagementPermission::WriteConfig),
    ("verifyRoutingRuleDomain", ManagementPermission::WriteConfig),
    ("listRoutingRules", ManagementPermission::Read),
    (
        "createOrganizationApiKey",
        ManagementPermission::WriteCredentials,
    ),
    ("listOrganizationApiKeys", ManagementPermission::Read),
    (
        "revokeOrganizationApiKey",
        ManagementPermission::WriteCredentials,
    ),
    (
        "rotateOrganizationApiKey",
        ManagementPermission::WriteCredentials,
    ),
    ("listProjectGrants", ManagementPermission::Read),
    (
        "withdrawProjectGrant",
        ManagementPermission::WriteOrganizations,
    ),
    (
        "unassignOrgGroupRole",
        ManagementPermission::WriteOrganizations,
    ),
    (
        "assignOrgMembershipRole",
        ManagementPermission::WriteOrganizations,
    ),
    (
        "unassignOrgMembershipRole",
        ManagementPermission::WriteOrganizations,
    ),
    ("listOrgGroupRoles", ManagementPermission::Read),
    ("listOrgMembershipRoles", ManagementPermission::Read),
    (
        "addOrgGroupMember",
        ManagementPermission::WriteOrganizations,
    ),
    (
        "removeOrgGroupMember",
        ManagementPermission::WriteOrganizations,
    ),
    ("listOrgGroupMembers", ManagementPermission::Read),
    ("getOrgMembershipEffectiveRoles", ManagementPermission::Read),
    ("setClientAllowedScopes", ManagementPermission::WriteConfig),
    ("getClientAllowedScopes", ManagementPermission::Read),
    ("setClientAdminConsent", ManagementPermission::WriteConfig),
    (
        "deleteClientAdminConsent",
        ManagementPermission::WriteConfig,
    ),
    ("getClientAdminConsent", ManagementPermission::Read),
    ("exportIdentities", ManagementPermission::Read),
    ("createIdentityImport", ManagementPermission::WriteUsers),
    ("resumeIdentityImport", ManagementPermission::WriteUsers),
    ("setOutboundVerification", ManagementPermission::WriteConfig),
    (
        "deleteOutboundVerification",
        ManagementPermission::WriteConfig,
    ),
    ("getOutboundVerification", ManagementPermission::Read),
    ("setClientParRequirement", ManagementPermission::WriteConfig),
    ("setAutoLinkPosture", ManagementPermission::WriteConfig),
    // The last reachable user operations.
    ("updateUser", ManagementPermission::WriteUsers),
    ("setUserState", ManagementPermission::WriteUsers),
    ("linkUserExternalId", ManagementPermission::WriteUsers),
    ("unlinkUserExternalId", ManagementPermission::WriteUsers),
    ("getUserTraits", ManagementPermission::Read),
];

/// Operations not yet classified. This list is DEBT and is meant to shrink to nothing.
///
/// Every entry is currently unrestricted, which is exactly its behaviour before issue #102, so
/// nothing here is a regression. Removing an entry means deciding its authority, not changing
/// what it does today.
const UNCLASSIFIED: &[&str] = &[
    "abandonMigrationRun",
    "applyConfigPromotion",
    "bulkRevokeSessions",
    "createConnector",
    "createDcrInitialAccessToken",
    "createDcrPolicy",
    "createEnvironment",
    "createTenant",
    "deleteBrandFavicon",
    "deleteBrandLogo",
    "deleteConnector",
    "deleteEnvironment",
    "deleteTenant",
    "elevateAdminSudo",
    "exportConfigSnapshot",
    "getClientAuthDiagnostics",
    "getConnector",
    "getConnectorCapabilities",
    "getConnectorHealth",
    "getDcrClient",
    "getDiagnosticsWarnings",
    "getEnvironment",
    "getFlowObservation",
    "getMds3Health",
    "getMigrationProgress",
    "getMigrationRun",
    "getOperator",
    "getPolicyDecisionTraces",
    "getRefreshFamily",
    "getRiskDecision",
    "getSession",
    "getSigningRecommendations",
    "getTenant",
    "getUserRiskPosture",
    "listConnectors",
    "listDcrPolicies",
    "listEnvironments",
    "listMigrationRunViolations",
    "listMigrationRuns",
    "listOperators",
    "listRefreshFamilies",
    "listResourceTypes",
    "listSessions",
    "listTenants",
    "listUserConsents",
    "planConfigPromotion",
    "postFlowDryRun",
    "probePasswordHashing",
    "purgeTenant",
    "restoreTenant",
    "resumeTenant",
    "revokeSession",
    "revokeUserConsent",
    "revokeUserSessions",
    "setBrandFavicon",
    "setBrandLogo",
    "setClientSigningAlgorithm",
    "suspendTenant",
    "updateConnector",
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
        61,
        "the unclassified list changed size. It may only SHRINK: an operation added to it is \
         an operation somebody chose not to decide about"
    );
}

/// The admin source, read at COMPILE time so this cannot be fooled by a working tree that
/// differs from what was built.
const ADMIN_SOURCES: &[(&str, &str)] = &[
    ("api_keys.rs", include_str!("../src/api_keys.rs")),
    ("users.rs", include_str!("../src/users.rs")),
    ("organizations.rs", include_str!("../src/organizations.rs")),
    ("memberships.rs", include_str!("../src/memberships.rs")),
    ("secrets.rs", include_str!("../src/secrets.rs")),
    ("variables.rs", include_str!("../src/variables.rs")),
    ("brands.rs", include_str!("../src/brands.rs")),
    (
        "webhook_endpoints.rs",
        include_str!("../src/webhook_endpoints.rs"),
    ),
    ("invitations.rs", include_str!("../src/invitations.rs")),
    ("bans.rs", include_str!("../src/bans.rs")),
    ("export.rs", include_str!("../src/export.rs")),
    ("org_roles.rs", include_str!("../src/org_roles.rs")),
    ("org_groups.rs", include_str!("../src/org_groups.rs")),
];

#[test]
fn every_classified_operation_in_these_files_actually_calls_the_gate() {
    // The pin above proves every operation has a DECLARED permission. It does not prove the
    // declaration is enforced, and those are different claims: #591 shipped a state where the
    // handlers enforced and the table still said "deferred", and the reverse (classified in
    // the table, no call in the handler) is the dangerous direction because the table then
    // reads as a control that does not exist.
    //
    // This closes that gap for the files listed, by counting `require_permission` calls
    // against the classified operations each file owns. It is a TEXT scan and its ceiling is
    // worth stating: it cannot tell WHICH permission a handler demands, only that it demands
    // one, and it only covers the files enumerated above. The end-to-end tests in
    // `delegated_admin.rs` are what prove the specific permission on the paths they drive.
    for (name, source) in ADMIN_SOURCES {
        let declared = source
            .matches("Delegated administration (issue #102)")
            .count();
        let calls = source.matches("principal.require_permission(").count();
        assert_eq!(
            declared, calls,
            "{name} has {declared} classification comment(s) and {calls} require_permission \
             call(s). A comment without a call is a control that exists only in prose"
        );
        assert!(
            calls > 0,
            "{name} is listed here as an enforced file and calls the gate nowhere"
        );
    }
}
