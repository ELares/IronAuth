// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every documented management operation declares the permission it requires (issue #102).
//!
//! # Why this pin exists before the enforcement it guards
//!
//! Delegated administration restricts what a management credential may do. The dangerous
//! failure is not a wrong permission on a route, it is a route with NO permission: it defaults
//! to allowed, nothing goes red, and the gap is invisible until somebody audits the WHOLE
//! documented surface by hand. That is the same shape as every dormant-layer defect in this tree, and adding
//! routes is continuous.
//!
//! So the classification lands FIRST, as a total function over the operation set, and the
//! enforcement rolls out behind it. A route added tomorrow fails this test until somebody
//! decides what authority it needs.
//!
//! # The UNCLASSIFIED list is deliberate, explicit, and meant to shrink
//!
//! Classifying every documented operation correctly is not a mechanical exercise: several are
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
    (
        "createServiceAccountMembership",
        ManagementPermission::WriteOrganizations,
    ),
    ("registerAgent", ManagementPermission::WriteOrganizations),
    ("setAgentState", ManagementPermission::WriteOrganizations),
    (
        "storeAgentVaultConnection",
        ManagementPermission::WriteOrganizations,
    ),
    ("listAgents", ManagementPermission::Read),
    // The agent VAULT approvals. Deciding whether an agent may spend a stored credential is a
    // change to what that agent can reach outside IronAuth, so it sits with the rest of the
    // organization-scoped writes; the approver's queue is a read.
    ("listAgentVaultApprovals", ManagementPermission::Read),
    (
        "decideAgentVaultApproval",
        ManagementPermission::WriteOrganizations,
    ),
    ("deleteMembership", ManagementPermission::WriteOrganizations),
    ("listMemberships", ManagementPermission::Read),
    // The ordered event feed and the usage export (issue #107). Both are environment-scoped
    // READS: the feed replays what already happened and the export folds it, so neither
    // grants sight of anything a `management.read` caller could not already list.
    ("readEventFeed", ManagementPermission::Read),
    ("exportUsage", ManagementPermission::Read),
    ("publishUsage", ManagementPermission::WriteConfig),
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
    // Declarative claim mappings (issue #113). `write_config` rather than anything softer,
    // because a mapping decides the shape of EVERY token a client is issued -- which claims it
    // carries, under what names, and in which of the two tokens -- so a credential that could
    // set one could change what every resource server downstream sees. The DELETE is classified
    // the same way for the reason that is easy to miss: removing a mapping CHANGES THE SHAPE OF
    // EVERY TOKEN in both directions -- claims it filtered out come back to the ID token, and a
    // claim it had placed in the access token stops reaching one.
    ("setClaimsMapping", ManagementPermission::WriteConfig),
    ("deleteClaimsMapping", ManagementPermission::WriteConfig),
    ("getClaimsMapping", ManagementPermission::Read),
    // CUSTOM FACTOR components (issue #114 criterion 6). The three writes are `write_config`
    // with the token-hook deploy and for a stronger reason: a hook shapes claims on a token the
    // login has already earned, and a factor decides whether it is earned at all. The two reads
    // are `read`, and neither returns a component or a secret VALUE -- the listing returns
    // metadata and the secrets route returns NAMES.
    //
    // The DELETE is pinned separately from the deploy because its reason inverts the token
    // hook's: removing a hook restores the unshaped token, while removing a component a journey
    // still names makes every login that reaches that step REFUSE.
    // SESSION TOKENIZER templates (issue #119). A template decides which AUDIENCE receives
    // tokens for which subjects, with a claim set an operator chooses, verifiable for the whole
    // TTL with nothing able to withdraw it early -- so both writes are `write_config` and the
    // listing is `read`. The listing returns configuration and never key material, so demanding
    // `write_config` for it would make asking which templates exist cost the authority to change
    // them.
    ("setSessionTokenTemplate", ManagementPermission::WriteConfig),
    (
        "deleteSessionTokenTemplate",
        ManagementPermission::WriteConfig,
    ),
    ("listSessionTokenTemplates", ManagementPermission::Read),
    // CALLER INTROSPECTION (issue #123 criterion 4). `read` rather than open, because "any
    // authenticated caller may ask about itself" would be a second authorization rule on a
    // surface that has one -- and a credential that cannot read is one no agent tool server can
    // usefully drive anyway, since it would advertise nothing.
    ("getCaller", ManagementPermission::Read),
    // The OPT-IN JWT SESSION MODE switch (issue #119 criterion 4). `write_config` on BOTH
    // directions, and the disable is not a de-escalation: turning it on moves every session
    // check in the environment off the database, and turning it off moves them all back, which
    // is a load characteristic somebody sized for. The read is `read` for the reason the
    // template listing is.
    ("setSessionJwtMode", ManagementPermission::WriteConfig),
    ("deleteSessionJwtMode", ManagementPermission::WriteConfig),
    ("getSessionJwtMode", ManagementPermission::Read),
    (
        "deployChallengeComponent",
        ManagementPermission::WriteConfig,
    ),
    (
        "deleteChallengeComponent",
        ManagementPermission::WriteConfig,
    ),
    ("listChallengeComponents", ManagementPermission::Read),
    (
        "grantChallengeComponentSecret",
        ManagementPermission::WriteConfig,
    ),
    (
        "revokeChallengeComponentSecret",
        ManagementPermission::WriteConfig,
    ),
    ("listChallengeComponentSecrets", ManagementPermission::Read),
    ("deployTokenHook", ManagementPermission::WriteConfig),
    ("deleteTokenHook", ManagementPermission::WriteConfig),
    ("getTokenHook", ManagementPermission::Read),
    ("listTokenHookVersions", ManagementPermission::Read),
    ("rollbackTokenHook", ManagementPermission::WriteConfig),
    // READ, unlike its three write-shaped neighbours, and the reason is that it writes
    // nothing. It is a read of a hook resource this credential may already read, plus a
    // computation over an event it supplied. Classifying it with the deploy would demand
    // `write_config` and sudo freshness to ask a question.
    //
    // It DOES disclose more than the metadata read does, and an earlier version of this note
    // said otherwise ("a hook the caller can already fetch"): no endpoint returns the
    // component. What bounds the disclosure is the guest world importing nothing -- a run is a
    // pure function of the component and the supplied event -- and `getClaimsMapping` is the
    // precedent, handing this same reader the whole declarative rule list shaping the same
    // tokens.
    ("testTokenHook", ManagementPermission::Read),
    // READ, with the other reads: it reports byte LENGTHS and never components, so it discloses
    // exactly what `getTokenHook` already does, once per hook.
    ("listTokenHookChain", ManagementPermission::Read),
    // WRITE_CONFIG, with the DEPLOY rather than the reads, and the reason is worth stating: a
    // reorder changes what every later hook is HANDED, since each is given what the one before
    // it produced. So it can change every claim in a token while every component stays
    // byte-identical, which is a bigger act than its name suggests.
    ("reorderTokenHooks", ManagementPermission::WriteConfig),
    // READ, with the other reads: it reports secret NAMES and never values, so it discloses
    // which secrets an operator wired to a hook and nothing they hold.
    ("listTokenHookSecrets", ManagementPermission::Read),
    // WRITE_CONFIG, both of them. A grant widens what the operator's own code inside the token
    // mint may read, which is a configuration change with the same reach as deploying that
    // code. The REVOKE is the same permission and not a lesser one even though it is the safe
    // direction: a permission that let someone revoke but not grant would be a
    // denial-of-service primitive handed out as a read.
    ("grantTokenHookSecret", ManagementPermission::WriteConfig),
    ("revokeTokenHookSecret", ManagementPermission::WriteConfig),
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
    // SIEM log streams (issue #110). A READ: the status surface exposes delivery health
    // and the NAME of the sink credential, never its value.
    ("listLogStreams", ManagementPermission::Read),
    // Registering an HTTP flow target (issue #112) is `write_config` for the same reason the
    // two below are: it names an outbound destination the server will call. It is if anything
    // the stronger case, because a fail-closed target refuses every signup in the environment
    // until it answers, so registering one is closer to a kill switch than to configuration.
    ("listFlowTargets", ManagementPermission::Read),
    ("createFlowTarget", ManagementPermission::WriteConfig),
    ("deleteFlowTarget", ManagementPermission::WriteConfig),
    // The dead-letter tail is a READ of queue rows; asking for a replay is a WRITE, and
    // write_config rather than a softer class because a replay re-POSTs real signup
    // announcements to a third party -- the same reason registering the target is.
    ("listFlowTargetDeadLetters", ManagementPermission::Read),
    (
        "replayFlowTargetDeadLetters",
        ManagementPermission::WriteConfig,
    ),
    // The configuration writes are `write_config`, the same class the webhook endpoint
    // registration uses: both name an outbound destination the server will send to.
    ("createLogStream", ManagementPermission::WriteConfig),
    ("deleteLogStream", ManagementPermission::WriteConfig),
    // The dead-letter surface (issue #938). Reading what went undelivered is a status
    // question; requesting a replay ships those audit events to a third-party sink, which
    // is why it sits with the configuration writes rather than with the read.
    ("listLogStreamDeadLetters", ManagementPermission::Read),
    (
        "replayLogStreamDeadLetters",
        ManagementPermission::WriteConfig,
    ),
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
    // The SCIM provisioning credential surface (issue #135). A connection token provisions and
    // deprovisions an organization's entire user population, so minting or revoking one is
    // `WriteCredentials` on the same argument as the organization API key it sits beside; the
    // listing never carries a token and is `Read`.
    (
        "createScimConnection",
        ManagementPermission::WriteCredentials,
    ),
    ("listScimConnections", ManagementPermission::Read),
    (
        "revokeScimConnection",
        ManagementPermission::WriteCredentials,
    ),
    // The OUTBOUND provisioning surface (issue #137), and it is `WriteConfig` rather than the
    // `WriteCredentials` its inbound neighbour above carries. The difference is what the row
    // holds: an inbound connection IS a credential, minted and revoked here, while an outbound
    // one only NAMES an `environment_secrets` row that somebody with the credential permission
    // already created. Pointing a connection at an existing secret is configuration; it mints
    // nothing and reveals nothing, which is the same line `setSecret` and `deleteSecret` sit on.
    ("listScimPushConnections", ManagementPermission::Read),
    ("listScimPushResources", ManagementPermission::Read),
    (
        "createScimPushConnection",
        ManagementPermission::WriteConfig,
    ),
    (
        "setScimPushConnectionActive",
        ManagementPermission::WriteConfig,
    ),
    (
        "deleteScimPushConnection",
        ManagementPermission::WriteConfig,
    ),
    (
        "revokeOrganizationApiKey",
        ManagementPermission::WriteCredentials,
    ),
    (
        "rotateOrganizationApiKey",
        ManagementPermission::WriteCredentials,
    ),
    (
        "createServiceAccountApiKey",
        ManagementPermission::WriteCredentials,
    ),
    ("listServiceAccountApiKeys", ManagementPermission::Read),
    ("getClientServiceAccount", ManagementPermission::Read),
    ("getAuthzenConfiguration", ManagementPermission::Read),
    ("authzenEvaluation", ManagementPermission::Read),
    ("authzenEvaluations", ManagementPermission::Read),
    (
        "authorizeUserImpersonation",
        ManagementPermission::Impersonate,
    ),
    (
        "revokeServiceAccountApiKey",
        ManagementPermission::WriteCredentials,
    ),
    (
        "rotateServiceAccountApiKey",
        ManagementPermission::WriteCredentials,
    ),
    (
        "createUserPersonalAccessToken",
        ManagementPermission::WriteCredentials,
    ),
    ("listUserPersonalAccessTokens", ManagementPermission::Read),
    (
        "revokeUserPersonalAccessToken",
        ManagementPermission::WriteCredentials,
    ),
    (
        "rotateUserPersonalAccessToken",
        ManagementPermission::WriteCredentials,
    ),
    ("listProjectGrants", ManagementPermission::Read),
    ("getMessageStatus", ManagementPermission::Read),
    ("resendMessage", ManagementPermission::WriteUsers),
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
    ("setClientBearerTokens", ManagementPermission::WriteConfig),
    ("setAutoLinkPosture", ManagementPermission::WriteConfig),
    // The last reachable user operations.
    ("updateUser", ManagementPermission::WriteUsers),
    ("setUserState", ManagementPermission::WriteUsers),
    ("linkUserExternalId", ManagementPermission::WriteUsers),
    ("unlinkUserExternalId", ManagementPermission::WriteUsers),
    ("getUserTraits", ManagementPermission::Read),
    // Workload identity federation (issue #126). The two listings are reads; the four writes
    // are `write_config` rather than a federation-specific permission, because they configure
    // the environment's trust the same way the client and connector writes beside them do.
    //
    // Both halves carry the SAME fence deliberately. An anchor decides whose signature is
    // honoured and a mapping decides which principal a foreign subject becomes, so a caller
    // who can author a mapping against an issuer it already controls needs nothing else.
    ("listExternalIssuers", ManagementPermission::Read),
    ("registerExternalIssuer", ManagementPermission::WriteConfig),
    (
        "setExternalIssuerEnabled",
        ManagementPermission::WriteConfig,
    ),
    ("listSubjectMappings", ManagementPermission::Read),
    ("createSubjectMapping", ManagementPermission::WriteConfig),
    (
        "setSubjectMappingEnabled",
        ManagementPermission::WriteConfig,
    ),
    // The deletes carry the same authority as the creates, and deliberately not a higher one:
    // deleting a trust anchor REMOVES an authentication path rather than opening one, so it is
    // strictly less dangerous than registering it, and gating it above write_config would mean
    // a caller who can add an anchor cannot remove the one they mis-added.
    ("deleteExternalIssuer", ManagementPermission::WriteConfig),
    ("deleteSubjectMapping", ManagementPermission::WriteConfig),
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

/// The operations whose SPECIFIC required permission is proven end to end.
///
/// Classification is not proof, and this list is the difference. `CLASSIFIED` records what
/// each operation is INTENDED to require, and
/// `every_classified_operation_in_these_files_actually_calls_the_gate` asserts the handler
/// demands SOMETHING. Neither compares the two, as that test's own comment says. A handler
/// classified `WriteCredentials` that actually demands `Read` passes both.
///
/// An entry here means a test drives a credential holding a DIFFERENT permission and asserts
/// the refusal names the required one. Only `delegated_admin.rs` and
/// `delegated_scope_levels.rs` do that.
///
/// Deliberately NOT derived by scanning those files. A scan would have to guess which test
/// covers which operation from paths and slugs, and a wrong guess here manufactures exactly
/// the false coverage claim this list exists to prevent. Hand-maintained, and only for
/// operations somebody actually checked.
const PERMISSION_PROVEN: &[&str] = &[
    // The agent principal surface (issue #130), proven by
    // `the_agent_surface_splits_registering_and_revoking_from_listing`: registering and
    // revoking are write_organizations, listing is read, and each is driven in BOTH
    // directions -- an agent acts with a person's authority, so who may create one and who
    // may only look is the distinction that matters most here.
    "registerAgent",
    "setAgentState",
    "listAgents",
    // Binding a MACHINE IDENTITY into an organization (issue #126), proven by
    // `write_organizations_is_required_to_add_a_machine_identity_to_an_org`: both directions,
    // because adding an identity to an organization grants it whatever roles that
    // organization attaches.
    "createServiceAccountMembership",
    // The per-client DPoP exemption (issue #124), proven by
    // `write_config_is_required_to_exempt_a_client_from_the_dpop_posture`: both directions,
    // because this route TURNS OFF sender-constrained tokens and a blanket refusal would look
    // identical to a correct gate.
    "setClientBearerTokens",
    // Proven by `the_caller_endpoint_reports_only_the_presenting_credential`, which drives it
    // with a credential that lacks `management.read` and asserts the refusal names it.
    "getCaller",
    // The OPT-IN JWT session mode switch (issue #119 criterion 4), proven by
    // `the_jwt_session_mode_switch_splits_flipping_it_from_reading_it`: both directions on all
    // three routes, including the DISABLE, which is the safe direction and still not a
    // de-escalation.
    "setSessionJwtMode",
    "deleteSessionJwtMode",
    "getSessionJwtMode",
    // The session tokenizer template surface (issue #119), proven by
    // `the_session_tokenizer_surface_splits_writing_a_template_from_reading_the_list`: both
    // directions on all three routes, each refusal asserted to NAME the permission it wanted.
    "setSessionTokenTemplate",
    "deleteSessionTokenTemplate",
    "listSessionTokenTemplates",
    // Proven in `delegated_admin.rs`, each in BOTH directions: a credential holding a DIFFERENT
    // permission gets 403 and the classified one reaches the handler (404 on an absent client),
    // so neither a blanket refusal nor a missing gate would pass them. The DELETE is pinned
    // separately from the write because its reason is the one that is easy to get wrong --
    // removing a mapping restores the UNSHAPED token, so it is a widening.
    "setClaimsMapping",
    "deleteClaimsMapping",
    "getClaimsMapping",
    // CUSTOM FACTOR components (issue #114 criterion 6), proven in
    // `write_config_is_required_and_sufficient_to_deploy_a_custom_factor`, its removal sibling,
    // `read_is_required_and_sufficient_to_list_custom_factors`, and
    // `a_factors_secret_grants_split_read_from_write_config`, each in BOTH directions.
    //
    // The three secret routes are proven by ONE test deliberately: they share a path and differ
    // only in method, which is exactly the shape where a router-level gate would hand all three
    // the same authority. Proving them apart is the point, so they are proven together.
    "deployChallengeComponent",
    "deleteChallengeComponent",
    "listChallengeComponents",
    "listChallengeComponentSecrets",
    "grantChallengeComponentSecret",
    "revokeChallengeComponentSecret",
    // Proven in `write_config_is_required_and_sufficient_for_a_token_hook_deploy`, its removal
    // sibling, and `read_is_required_and_sufficient_for_a_token_hook_read`, each in BOTH
    // directions. The removal is pinned separately from the deploy because its reason is the
    // one that is easy to get wrong: removing a hook restores the UNSHAPED token, so it is a
    // change to every token's shape rather than a tidy-up.
    "deployTokenHook",
    "deleteTokenHook",
    "getTokenHook",
    // Proven in `read_is_required_and_sufficient_for_listing_token_hook_versions` and
    // `write_config_is_required_and_sufficient_for_a_token_hook_rollback`, both directions
    // each. The rollback is classified with the DEPLOY rather than the read because it is one:
    // it changes what every token this client is issued carries.
    "listTokenHookVersions",
    "rollbackTokenHook",
    // Proven in `delegated_admin.rs::read_is_required_and_sufficient_for_a_token_hook_draft_run`,
    // in BOTH directions: a `write_users` credential gets 403 and a `read` one reaches the
    // handler, so neither a blanket refusal nor a missing gate would pass it. An earlier
    // version of this entry cited `a_draft_run_reports_what_the_deployed_hook_would_do_and_
    // writes_nothing`, which drives the unrestricted bootstrap operator and would pass with the
    // gate deleted -- the false coverage claim this list's own header warns about.
    "testTokenHook",
    // Proven in `delegated_admin.rs::read_is_required_and_sufficient_for_listing_the_token_hook_chain`
    // and `..::write_config_is_required_and_sufficient_for_a_token_hook_reorder`, both in BOTH
    // directions. The pair matters more than either alone: they are the two halves of one
    // feature and they are classified DIFFERENTLY, so a gate that treated the chain listing as
    // a write, or the reorder as a read, passes one of these and fails the other.
    "listTokenHookChain",
    "reorderTokenHooks",
    // Proven in `delegated_admin.rs::read_is_required_and_sufficient_for_listing_hook_secrets`
    // and `..::write_config_is_required_and_sufficient_for_a_hook_secret_grant`, both in BOTH
    // directions. The grant and the revoke share one test because they share one permission and
    // one path; what the test separates is the READ from the two WRITES, which is the
    // classification a mistake here would get wrong.
    "listTokenHookSecrets",
    "grantTokenHookSecret",
    "revokeTokenHookSecret",
    // Proven in `read_is_required_and_sufficient_for_the_event_feed_and_usage_export`, in
    // BOTH directions: a `write_config` credential is refused and a `read` one is allowed,
    // so neither a blanket refusal nor a missing gate would pass it.
    "readEventFeed",
    "exportUsage",
    // Proven in `delegated_admin.rs::read_is_required_and_sufficient_for_message_status`, in
    // BOTH directions: a `write_config` credential gets 403 and a `read` one reaches the
    // handler (404 on an absent message), so neither a blanket refusal nor a missing gate
    // would pass it.
    "getMessageStatus",
    // Proven in `delegated_admin.rs::write_users_is_required_and_sufficient_for_message_resend`,
    // in BOTH directions: a `read` credential gets 403 and a `write_users` one reaches the
    // handler. `write_users` rather than `write_credentials` because every operation in the
    // credentials set MINTS a credential and this one mints nothing; the sibling
    // `resendInvitation` is classified the same way.
    "resendMessage",
    // Proven in `usage_export.rs::write_config_is_required_and_sufficient_for_publishing`,
    // in BOTH directions: a credential restricted to `management.read` is refused 403 and
    // one restricted to `management.write_config` is allowed. Publishing appends to the feed
    // every webhook subscriber receives, so a read-only credential reaching it would make
    // every subscriber receive a billing record.
    "publishUsage",
    // Proven in `a_read_only_credential_can_list_api_keys_and_cannot_mint_or_kill_one`,
    // verified by mutation: downgrading all three to `Read` fails that test and passes every
    // other pin.
    "createOrganizationApiKey",
    "revokeOrganizationApiKey",
    "rotateOrganizationApiKey",
    // Proven in `a_read_only_credential_can_list_scim_connections_and_cannot_mint_or_kill_one`,
    // which drives the mint and the revoke with a read-only credential and asserts each refusal
    // NAMES write_credentials, then drives the LISTING with a `write_config` credential so the
    // read is checked in both directions too. Verified by mutation: downgrading either write to
    // `Read`, or deleting the listing's check, fails that test and passes every other pin.
    "createScimConnection",
    "listScimConnections",
    "revokeScimConnection",
    // Proven in `a_read_only_credential_can_list_scim_push_connections_and_cannot_change_one`,
    // which drives create, pause and delete with a read-only credential and asserts each
    // refusal NAMES write_config, then drives the LISTING with a `write_config` credential so
    // the read is checked in both directions too. It also asserts the seeded connection is
    // still there AND still active, so a refusal that half-applied would fail it.
    "listScimPushConnections",
    "listScimPushResources",
    "createScimPushConnection",
    "setScimPushConnectionActive",
    "deleteScimPushConnection",
    // Proven in `a_read_only_credential_cannot_mint_or_kill_a_service_accounts_key`. The
    // listing is here too, and only here: that test checks it in BOTH directions, so a
    // downgrade of the read to "any permission" is refused as well as an upgrade of it.
    "createServiceAccountApiKey",
    "listServiceAccountApiKeys",
    "revokeServiceAccountApiKey",
    "rotateServiceAccountApiKey",
    // Proven in `a_read_only_credential_cannot_mint_or_kill_a_personal_access_token`, on the
    // same shape and in both directions for the listing.
    "createUserPersonalAccessToken",
    "listUserPersonalAccessTokens",
    "revokeUserPersonalAccessToken",
    "rotateUserPersonalAccessToken",
    // Proven in `a_read_only_credential_cannot_mint_or_kill_a_service_accounts_key`, which
    // drives this read in both directions alongside the key routes it sits with.
    "getClientServiceAccount",
    // Proven in `only_a_credential_holding_impersonate_can_authorize_one`, which drives a
    // credential holding every OTHER permission and asserts the refusal names this one.
    "authorizeUserImpersonation",
    // Proven across `the_flow_target_surface_splits_reading_from_registering` and
    // `registering_a_flow_target_demands_write_config`, which drive all three in both
    // directions: the listing served under read and refused (naming `management.read`) under
    // a different permission and unauthenticated; the register and the deregister refused
    // under read alone, with the register's refusal asserted to name
    // `management.write_config`, then both served under it.
    "listFlowTargets",
    "createFlowTarget",
    "deleteFlowTarget",
    // Proven across `the_external_issuer_surface_splits_reading_from_registering`,
    // `registering_and_disabling_a_trust_anchor_demand_write_config` and
    // `the_subject_mapping_surface_splits_reading_from_authoring`, which drive all eight in
    // both directions: each listing served under read and refused (naming `management.read`)
    // under a different permission, and each write refused under read alone with the refusal
    // asserted to name `management.write_config`, then served under it.
    "listExternalIssuers",
    "registerExternalIssuer",
    "setExternalIssuerEnabled",
    "listSubjectMappings",
    "createSubjectMapping",
    "setSubjectMappingEnabled",
    "deleteExternalIssuer",
    "deleteSubjectMapping",
    // Proven in `the_flow_target_dead_letter_surface_splits_reading_from_replaying`, which
    // drives both in both directions: the listing served under read and refused under
    // write_config alone, the replay refused under read alone naming
    // `management.write_config`, then served under it.
    "listFlowTargetDeadLetters",
    "replayFlowTargetDeadLetters",
    // Proven in `the_log_stream_status_read_demands_read_and_never_answers_unauthenticated`,
    // which drives it in BOTH directions: served under read, refused with the required
    // permission named under a different one.
    "listLogStreams",
    // Proven in the same test, which drives all three in both directions.
    "createLogStream",
    "deleteLogStream",
    // Proven in `the_listing_is_fenced_and_its_bound_is_real` and
    // `replaying_needs_more_than_reading` in `delegated_admin`. The listing is served under
    // read and refused without it; the replay is refused for a credential holding read
    // alone, AND the refusal is asserted to name `management.write_config`. That last
    // assertion is what earns the entry: without it, substituting one write permission for
    // another survived the whole crate, so the specific permission was unpinned and this
    // list said otherwise.
    "listLogStreamDeadLetters",
    "replayLogStreamDeadLetters",
    // Proven in `the_authzen_endpoints_demand_read_and_never_answer_unauthenticated`, which
    // drives a credential holding a WRITE but not read and asserts each refusal names read.
    "getAuthzenConfiguration",
    "authzenEvaluation",
    "authzenEvaluations",
    // The agent vault (issue #132). `delegated_admin.rs` drives a read-only credential at all
    // three and asserts the two writes are refused BY NAME; the queue is reached.
    "storeAgentVaultConnection",
    "listAgentVaultApprovals",
    "decideAgentVaultApproval",
];

/// Not every unproven operation CAN be proven the same way.
///
/// The management-key operations (`createManagementKey`, `deleteManagementKey`) are the most
/// dangerous on this surface: minting one is self-escalation for a restricted credential. I
/// tried to prove their permission with the read-only pattern and could not, because
/// `/v1/tenants/{t}/environments/{e}/keys` requires the OPERATOR plane. A restricted
/// environment-scoped key is refused with `wrong_scope` before any permission check runs, so
/// the plane fence MASKS the permission and the pattern cannot distinguish
/// `WriteCredentials` from `Read` there.
///
/// That is a safe masking, not a hole: the plane check is strictly stronger. But it means the
/// unproven count cannot be driven to zero with one technique, and an operator-plane
/// equivalent of `restrict` would be needed to prove those operations at all.
///
/// Classification is NOT proof, and the size of that gap is counted so it cannot hide.
///
/// 218 operations declare a required permission and 74 have that permission proven. The other
/// 144 are not known to be wrong; they are UNCHECKED, which is a different thing and worth a
/// number rather than a shrug.
///
/// ALL THREE NUMBERS ARE PINNED BELOW, and that is a repair rather than a flourish. This
/// paragraph read "148 ... and 4" while the assertion underneath pinned 166, because only the
/// first number had a test and the sentence beside it was maintained by hand. It was wrong at
/// merge-base of the PR that introduced it (147 and 3 against an actual 165 and 21), so it
/// had drifted twice without anything going red. A sentence that carries a count needs the count asserted, or
/// the next reader budgets against a figure nobody has checked since it was typed.
///
/// This pin may only improve: `PERMISSION_PROVEN` may grow, and the ratio may not get worse
/// without somebody editing this assertion and noticing what they are doing.
///
/// WITH BOTH SIZES PINNED EXACTLY, the `unproven <= 144` ratchet below can no longer fail on
/// its own: 225 minus 81 is always 144. (It read "166 minus 22", then "171 minus 27", then
/// "210 minus 66", then "218 minus 74" -- each of them stale, and the last of them stale in a doc paragraph that
/// says in the same breath that this is the hazard, while
/// the pins above it moved twice without it, which is the hazard of writing an arithmetic
/// identity beside the numbers it derives from rather than deriving it. Both operands are
/// pinned by the two `assert_eq!`s in the test below; if you change either, change this
/// sentence too.) That is deliberate rather than an oversight. The
/// ratchet's job was to catch a drift nothing else measured, and two exact pins catch it
/// earlier and name which set moved. What the ratchet still carries is its message, which is
/// the instruction for the person who just made one of those pins fail.
#[test]
fn classification_is_not_proof_and_the_unproven_gap_is_counted() {
    for operation in PERMISSION_PROVEN {
        assert!(
            CLASSIFIED.iter().any(|(name, _)| name == operation),
            "{operation} is listed as permission-proven but is not classified at all"
        );
    }
    assert_eq!(
        CLASSIFIED.len(),
        226,
        "the classified set changed size; update the unproven count below with it"
    );
    assert_eq!(
        PERMISSION_PROVEN.len(),
        82,
        "the permission-proven set changed size; update the doc comment above with it"
    );
    let unproven = CLASSIFIED.len() - PERMISSION_PROVEN.len();
    assert!(
        unproven <= 144,
        "the number of operations whose specific permission is UNPROVEN rose to {unproven}.          It may only fall. Add a `delegated_admin.rs` test that drives a credential holding a          different permission and asserts the refusal names the required one, then list the          operation in PERMISSION_PROVEN"
    );
}

/// The admin source, read at COMPILE time so this cannot be fooled by a working tree that
/// differs from what was built.
const ADMIN_SOURCES: &[(&str, &str)] = &[
    // Listed the moment the module existed: a file NOT enumerated here is one this gate never
    // reads, so its classification comments and its gate calls could disagree silently.
    ("agents.rs", include_str!("../src/agents.rs")),
    // The outbound provisioning module (issue #137). Listed the moment it existed: a file NOT
    // enumerated here is one this gate never reads, so a mutation deleting a
    // `require_permission` call inside it SURVIVES, and the classification above would look
    // like enforcement while enforcing nothing.
    (
        "scim_push_connections.rs",
        include_str!("../src/scim_push_connections.rs"),
    ),
    ("api_keys.rs", include_str!("../src/api_keys.rs")),
    (
        "claims_mappings.rs",
        include_str!("../src/claims_mappings.rs"),
    ),
    ("token_hooks.rs", include_str!("../src/token_hooks.rs")),
    // The custom factor surface (issue #114 criterion 6). Listed the moment the module existed:
    // a file NOT enumerated here is one this gate never reads, so its classification comments
    // and its gate calls could disagree silently -- which they did, two comments against six
    // calls, until it was added.
    (
        "challenge_components.rs",
        include_str!("../src/challenge_components.rs"),
    ),
    // The session tokenizer template surface (issue #119). Listed the moment the module
    // existed, for the reason recorded above.
    (
        "session_token_templates.rs",
        include_str!("../src/session_token_templates.rs"),
    ),
    ("messages.rs", include_str!("../src/messages.rs")),
    (
        "service_account_keys.rs",
        include_str!("../src/service_account_keys.rs"),
    ),
    (
        "personal_access_tokens.rs",
        include_str!("../src/personal_access_tokens.rs"),
    ),
    ("impersonation.rs", include_str!("../src/impersonation.rs")),
    ("authzen.rs", include_str!("../src/authzen.rs")),
    ("flow_targets.rs", include_str!("../src/flow_targets.rs")),
    ("log_streams.rs", include_str!("../src/log_streams.rs")),
    ("event_feed.rs", include_str!("../src/event_feed.rs")),
    ("usage.rs", include_str!("../src/usage.rs")),
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
