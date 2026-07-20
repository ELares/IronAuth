// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OpenAPI 3.1 document, generated from the annotated handlers.
//!
//! The spec is the source of truth. Every handler carries a `#[utoipa::path]`
//! annotation and is listed ONCE in [`ApiDoc`]'s `paths(...)`; the same handlers
//! are wired to the same paths by [`crate::management_router`]. The generated
//! document is committed to `docs/openapi/management.json` and CI regenerates it
//! and `git diff`s (`scripts/openapi-check.sh`), so a change to a handler that is
//! not reflected in the committed spec fails the build. The
//! `documented_paths_are_the_expected_set` contract test pins the exact
//! (method, path) set the spec documents, so the hand-wired router and the spec
//! cannot silently diverge.
//!
//! The utoipa-axum route-binder (which would fuse the router and the spec into a
//! single builder) is intentionally not used: it depends on the unmaintained
//! `paste` crate (RUSTSEC-2024-0436), which `cargo deny` rejects.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::error::ErrorBody;
use crate::views::{
    BulkRevocationView, BulkRevokeSessionsRequest, ClientVerificationView,
    ConnectorCapabilitiesView, ConnectorHealthView, ConnectorList, ConnectorView,
    CreateConnectorRequest, CreateDcrPolicyRequest, CreateEnvironmentRequest,
    CreateInitialAccessTokenRequest, CreateInvitationRequest, CreateManagementKeyRequest,
    CreateOrganizationRequest, CreateTenantRequest, CreateUserRequest, DcrPolicyList,
    DcrPolicyView, EnvironmentList, EnvironmentView, ExtendSignupQuarantineRequest, GuardrailView,
    InitialAccessTokenCreated, InvitationCreatedView, InvitationCredentialTypeView, InvitationList,
    InvitationStateChangeView, InvitationStateView, InvitationView, LinkExternalIdRequest,
    LocaleBundleView, ManagementKeyCreated, ManagementKeyList, ManagementKeyView, OperatorList,
    OperatorView, OrganizationList, OrganizationView, RecoveryApprovalCaseView,
    RecoveryApprovalDecisionView, RecoveryApprovalList, RecoveryApprovalStateView,
    RefreshFamilyList, RefreshFamilyView, ResourceTypeView, ResourceTypesList,
    RevokeSessionsRequest, SessionList, SessionRevocationView, SessionView, SetLocaleRequest,
    SetUserStateRequest, SignupQuarantineCaseView, SignupQuarantineDecisionView,
    SignupQuarantineList, SignupQuarantineReasonView, SignupQuarantineStateView, TenantCreated,
    TenantList, TenantStatusView, TenantView, UpdateUserRequest, UserExternalIdView, UserList,
    UserRevocationView, UserStateChangeView, UserStateView, UserView,
};

/// The management API's OpenAPI document. The handlers listed in `paths(...)`
/// contribute their `#[utoipa::path]` operations, `schemas(...)` fixes the shared
/// component schemas, and the info block, tags, and bearer security scheme are
/// fixed here.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "IronAuth Management API",
        version = "0.1.0",
        description = "The OpenAPI-first management API (issue #11). Every list endpoint uses \
                       cursor pagination; every POST honors Idempotency-Key; every response \
                       carries RateLimit headers; every mutation writes a same-transaction audit \
                       row. Credentials are environment-scoped management keys plus a config \
                       bootstrap operator token."
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "operators", description = "Operator plane: the root of the four-level \
                                           resource model, a read surface above tenants"),
        (name = "tenants", description = "Tenant CRUD (operator plane)"),
        (name = "environments", description = "Environment CRUD under a tenant"),
        (name = "organizations", description = "Organization CRUD under an environment: the \
                                               minimal per-environment shell (M10 adds membership)"),
        (name = "resource-model", description = "The resource-type classification catalog \
                                                (promotable, runtime, environment-identity)"),
        (name = "config-promotion", description = "Canonical secret-free config snapshot export: \
                                                  the diffable, committable substrate the \
                                                  config-promotion flagship consumes"),
        (name = "keys", description = "Environment-scoped management API keys"),
        (name = "dcr", description = "Dynamic Client Registration abuse controls: \
                                     policies, initial access tokens, client verification"),
        (name = "connectors", description = "Declarative inbound-federation connectors: \
                                            strict-validated OIDC-shaped upstream definitions \
                                            (CRUD) and the machine-readable capability matrix"),
        (name = "locales", description = "Per-environment localization bundles: set, get, and \
                                         delete a bundle of numeric message id to plain-text \
                                         render, strict-validated against the message registry"),
        (name = "sessions", description = "Session and refresh-family fleet operations: \
                                          search, inspect, revoke (single, bulk, and \
                                          everything-for-a-user with a token-family cascade)"),
        (name = "users", description = "Admin user CRUD, lifecycle state transitions, and \
                                       external-id correlation, with a session cascade on the \
                                       session-ending transitions"),
        (name = "invitations", description = "Admin user-invitation CRUD: create (provisioning a \
                                             pending-verification user and a single-use, expiring, \
                                             hashed-at-rest token), list, get, revoke, and resend"),
        (name = "signup-quarantine", description = "Signup fraud review queue (issue #82): \
                                             list the open quarantine cases and release, \
                                             reject, or extend one (experimental, feature-gated)"),
        (name = "recovery-approvals", description = "Admin-approved recovery review queue \
                                             (issue #82): list the open recovery approvals and \
                                             approve or reject one; approving completes the \
                                             recovery through the delay and downgrade gate \
                                             (experimental, feature-gated)"),
        (name = "exit", description = "The exit-friendliness covenant (issue #58): the full \
                                     identity export (users, traits, states, external ids, and \
                                     password hashes with their algorithm tags) in the \
                                     line-delimited import format, plus the outbound \
                                     lazy-migration credential-verification endpoint a successor \
                                     system calls to migrate away"),
        (name = "migration", description = "Inbound lazy-migration progress (issue #56): how \
                                          far an environment's lazy migration has come and the \
                                          node's circuit-breaker state"),
        (name = "sudo", description = "Admin session privilege separation (issue #73): the \
                                     re-authentication endpoint that records a fresh elevation \
                                     so admin mutations pass the sudo freshness gate")
    ),
    paths(
        crate::operators::list_operators,
        crate::operators::get_operator,
        crate::resource_types::list_resource_types,
        crate::tenants::list_tenants,
        crate::tenants::create_tenant,
        crate::tenants::get_tenant,
        crate::tenants::delete_tenant,
        crate::tenants::suspend_tenant,
        crate::tenants::resume_tenant,
        crate::tenants::restore_tenant,
        crate::environments::list_environments,
        crate::environments::create_environment,
        crate::environments::get_environment,
        crate::environments::delete_environment,
        crate::organizations::list_organizations,
        crate::organizations::create_organization,
        crate::organizations::get_organization,
        crate::organizations::delete_organization,
        crate::keys::list_keys,
        crate::keys::create_key,
        crate::keys::get_key,
        crate::keys::delete_key,
        crate::config::export_config_snapshot,
        crate::promotion::plan_config_promotion,
        crate::promotion::apply_config_promotion,
        crate::dcr::create_dcr_policy,
        crate::dcr::list_dcr_policies,
        crate::dcr::create_initial_access_token,
        crate::dcr::get_dcr_client,
        crate::dcr::verify_dcr_client,
        crate::connectors::create_connector,
        crate::connectors::list_connectors,
        crate::connectors::get_connector,
        crate::connectors::get_connector_capabilities,
        crate::connectors::get_connector_health,
        crate::connectors::update_connector,
        crate::connectors::delete_connector,
        crate::locales::set_locale,
        crate::locales::get_locale,
        crate::locales::delete_locale,
        crate::sessions::list_sessions,
        crate::sessions::get_session,
        crate::sessions::revoke_session,
        crate::sessions::bulk_revoke_sessions,
        crate::sessions::revoke_user_sessions,
        crate::sessions::list_refresh_families,
        crate::sessions::get_refresh_family,
        crate::users::create_user,
        crate::users::list_users,
        crate::users::get_user,
        crate::users::update_user,
        crate::users::delete_user,
        crate::users::set_user_state,
        crate::users::link_user_external_id,
        crate::users::unlink_user_external_id,
        crate::invitations::create_invitation,
        crate::invitations::list_invitations,
        crate::invitations::get_invitation,
        crate::invitations::revoke_invitation,
        crate::invitations::resend_invitation,
        crate::signup_quarantine::list_signup_quarantines,
        crate::signup_quarantine::approve_signup_quarantine,
        crate::signup_quarantine::reject_signup_quarantine,
        crate::signup_quarantine::extend_signup_quarantine,
        crate::recovery_approvals::list_recovery_approvals,
        crate::recovery_approvals::approve_recovery_approval,
        crate::recovery_approvals::reject_recovery_approval,
        crate::export::export_identities,
        crate::migration::verify_credential,
        crate::migration_status::get_migration_progress,
        crate::mds3_health::get_mds3_health,
        crate::password_hashing::probe_password_hashing,
        crate::migration_runs::list_migration_runs,
        crate::migration_runs::get_migration_run,
        crate::migration_runs::list_migration_run_violations,
        crate::bans::create_ban,
        crate::bans::lift_ban,
        crate::bans::list_bans,
        crate::sudo::elevate_sudo,
    ),
    components(schemas(
        ErrorBody,
        TenantView,
        TenantCreated,
        TenantList,
        TenantStatusView,
        CreateTenantRequest,
        EnvironmentView,
        GuardrailView,
        EnvironmentList,
        CreateEnvironmentRequest,
        OperatorView,
        OperatorList,
        OrganizationView,
        OrganizationList,
        CreateOrganizationRequest,
        ResourceTypeView,
        ResourceTypesList,
        ManagementKeyView,
        ManagementKeyCreated,
        ManagementKeyList,
        CreateManagementKeyRequest,
        crate::promotion::ApplyConfigPromotionRequest,
        CreateDcrPolicyRequest,
        DcrPolicyView,
        DcrPolicyList,
        CreateInitialAccessTokenRequest,
        InitialAccessTokenCreated,
        ClientVerificationView,
        CreateConnectorRequest,
        ConnectorView,
        ConnectorList,
        ConnectorCapabilitiesView,
        ConnectorHealthView,
        SetLocaleRequest,
        LocaleBundleView,
        SessionView,
        SessionList,
        RefreshFamilyView,
        RefreshFamilyList,
        RevokeSessionsRequest,
        BulkRevokeSessionsRequest,
        SessionRevocationView,
        BulkRevocationView,
        UserRevocationView,
        UserView,
        UserList,
        UserStateView,
        CreateUserRequest,
        UpdateUserRequest,
        SetUserStateRequest,
        UserStateChangeView,
        LinkExternalIdRequest,
        UserExternalIdView,
        InvitationCredentialTypeView,
        InvitationStateView,
        InvitationView,
        InvitationList,
        CreateInvitationRequest,
        InvitationCreatedView,
        InvitationStateChangeView,
        SignupQuarantineReasonView,
        SignupQuarantineStateView,
        SignupQuarantineCaseView,
        SignupQuarantineList,
        SignupQuarantineDecisionView,
        ExtendSignupQuarantineRequest,
        RecoveryApprovalStateView,
        RecoveryApprovalCaseView,
        RecoveryApprovalList,
        RecoveryApprovalDecisionView,
        crate::migration::VerifyCredentialRequest,
        crate::migration::VerifyCredentialResponse,
        crate::migration::VerifyProfile,
        crate::migration_status::MigrationProgressView,
        crate::mds3_health::Mds3HealthView,
        crate::password_hashing::PasswordHashingProbeRequest,
        crate::password_hashing::PasswordHashingProbeReport,
        crate::migration_runs::MigrationRunSummaryView,
        crate::migration_runs::MigrationRunList,
        crate::migration_runs::MigrationRunCountsView,
        crate::migration_runs::InvariantView,
        crate::migration_runs::MigrationRunDetailView,
        crate::migration_runs::OffendingRecordView,
        crate::migration_runs::MigrationRunViolationList,
        crate::bans::CreateBanRequest,
        crate::bans::LiftBanRequest,
        crate::bans::BanView,
        crate::bans::BanList,
        crate::bans::LiftBanView,
        crate::sudo::SudoElevationView,
    ))
)]
struct ApiDoc;

/// Adds the `bearer` HTTP security scheme (both the operator token and a
/// management key are presented as `Authorization: Bearer`).
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some(
                            "A management key token (mak_...) or the bootstrap operator token.",
                        ))
                        .build(),
                ),
            );
        }
    }
}

/// The generated OpenAPI 3.1 document for the management API. Pure: no state, no
/// database. This is what the served `/openapi.json` and the committed artifact
/// are both derived from.
#[must_use]
pub fn management_openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

/// The management API's OpenAPI document as pretty JSON, with a trailing newline.
///
/// This is the exact byte content committed to `docs/openapi/management.json` and
/// served at `/openapi.json`. `scripts/openapi-check.sh` regenerates it and fails
/// the build on any difference from the committed file.
///
/// Serialization of the generated document never fails in practice (a failure
/// would be a bug in the annotations, not a runtime condition), so rather than
/// panic on the served path this falls back to a minimal valid document and logs
/// the error, mirroring the error/response builders elsewhere in the crate.
#[must_use]
pub fn openapi_json() -> String {
    let mut json = serde_json::to_string_pretty(&management_openapi()).unwrap_or_else(|error| {
        tracing::error!(%error, "failed to serialize the management OpenAPI document");
        "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"IronAuth Management API\",\
         \"version\":\"0.1.0\"},\"paths\":{}}"
            .to_owned()
    });
    json.push('\n');
    json
}
