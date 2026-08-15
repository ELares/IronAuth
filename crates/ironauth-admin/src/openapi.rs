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
use crate::signing_algorithm::{
    ClientSigningAlgorithmView, SetClientSigningAlgorithmRequest, SigningRecommendationView,
};
use crate::views::{
    BrandAssetView, BrandPage, BrandView, BulkRevocationView, BulkRevokeSessionsRequest,
    ClientAdminConsentView, ClientVerificationView, ConnectorCapabilitiesView, ConnectorHealthView,
    ConnectorList, ConnectorView, ConsentRevocationView, CreateConnectorRequest,
    CreateDcrPolicyRequest, CreateEnvironmentRequest, CreateFlowVersionRequest,
    CreateInitialAccessTokenRequest, CreateInvitationRequest, CreateManagementKeyRequest,
    CreateMembershipRequest, CreateOrganizationRequest, CreateTenantRequest, CreateUserRequest,
    DcrPolicyList, DcrPolicyView, EnvironmentList, EnvironmentView, ExtendSignupQuarantineRequest,
    FlowVersionView, GuardrailView, InitialAccessTokenCreated, InvitationCreatedView,
    InvitationCredentialTypeView, InvitationList, InvitationStateChangeView, InvitationStateView,
    InvitationView, LinkExternalIdRequest, LocaleBundleView, ManagementKeyCreated,
    ManagementKeyList, ManagementKeyView, MembershipList, MembershipView, OperatorList,
    OperatorView, OrganizationList, OrganizationView, RecoveryApprovalCaseView,
    RecoveryApprovalDecisionView, RecoveryApprovalList, RecoveryApprovalStateView,
    RefreshFamilyList, RefreshFamilyView, ResourceTypeView, ResourceTypesList,
    RevokeSessionsRequest, SessionList, SessionRevocationView, SessionView, SetBrandRequest,
    SetClientAdminConsentRequest, SetLocaleRequest, SetSignupFormRequest, SetUserStateRequest,
    SignupFormFieldView, SignupFormView, SignupQuarantineCaseView, SignupQuarantineDecisionView,
    SignupQuarantineList, SignupQuarantineReasonView, SignupQuarantineStateView, TenantCreated,
    TenantList, TenantStatusView, TenantView, TraitAnnotationsView, TraitSchemaVersionView,
    UpdateUserRequest, UserConsentList, UserConsentView, UserExternalIdView, UserList,
    UserRevocationView, UserStateChangeView, UserStateView, UserTraitsView, UserView,
    VerificationAddressView,
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
        (name = "org-roles", description = "Organization roles (issue #97): first-class, \
                                           per-organization named roles. A role is a NAME only \
                                           in M10 (an immutable slug an authorization decision \
                                           keys on, plus a mutable label); what it grants is \
                                           issue #98. Uncapped in number by covenant"),
        (name = "authzen", description = "The AuthZEN Authorization API 1.0 policy \
                                         decision point (issue #100): runtime authorization \
                                         checks answered from IronAuth's OWN organizations, \
                                         groups, roles and permissions, over the same \
                                         resolution the token claims are built from. NOT a \
                                         Zanzibar engine: relationship-based authorization \
                                         is an explicit non-goal and integrates through \
                                         seams instead. The Search APIs are deferred and the \
                                         discovery document says so rather than omitting \
                                         them"),
        (name = "permissions", description = "The permission vocabulary (issue #98): the named \
                                             API capabilities an ENVIRONMENT defines. Scoped to \
                                             the environment and NOT to an organization, because \
                                             a permission names a capability and one string \
                                             cannot mean different things to two organizations \
                                             calling the same API; which permissions a ROLE \
                                             grants is per organization. The slug and the kind \
                                             are immutable. Uncapped in number by covenant"),
        (name = "resource-servers", description = "The resource-server registry (issue #29), \
                                                  given a management surface by issue #98. \
                                                  ENVIRONMENT level and not per organization: a \
                                                  registered protected API belongs to the \
                                                  environment. Addressed by `rsv_` id and never \
                                                  by audience, because an audience is an \
                                                  absolute URI and cannot be a path segment; the \
                                                  list exists so a console can find the id. The \
                                                  PATCH writes exactly one column, the \
                                                  permission-claim opt-in, and refuses to enable \
                                                  it on an `opaque` resource server"),
        (name = "client-scopes", description = "The per-client OAuth SCOPE allowlist \
                                                (issue #98): which scope tokens a \
                                                machine grant (`client_credentials`, \
                                                `jwt-bearer`) may request for one \
                                                client. `null` means no allowlist is \
                                                configured and every scope passes the \
                                                machine-grant denylist floor; an array \
                                                restricts to exactly its members; `[]` \
                                                admits nothing. A DELEGATION \
                                                restriction on what a machine may ASK \
                                                FOR, never the RBAC permission set \
                                                (machine principal permissions are \
                                                issue #99), and it can never re-admit \
                                                `openid` or `offline_access`"),
        (name = "org-role-permissions", description = "The role-to-permission mapping \
                                                       (issue #98): which permissions of the \
                                                       ENVIRONMENT'S vocabulary one \
                                                       ORGANIZATION'S role grants. Nested under \
                                                       the organization because the ROLE half \
                                                       is, while the permission half carries no \
                                                       organization at all. PAIR addressed, so \
                                                       the mapping id never appears in a path. \
                                                       Uncapped in both directions by covenant"),
        (name = "org-groups", description = "Organization groups (issue #97): first-class, \
                                            per-organization named groups holding a position in \
                                            that organization's group forest, with a dedicated \
                                            reparent endpoint carrying the cycle and depth \
                                            refusals. Uncapped in number by covenant; only \
                                            nesting DEPTH is bounded"),
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
        (name = "signup-forms", description = "Per-environment, per-client signup forms as data: \
                                             set (fail-fast validated against the active trait \
                                             schema, narrowing-only rules), get, and delete a \
                                             form keyed on the authorize client id"),
        (name = "brands", description = "Per-environment branding definitions: list, set \
                                        (create or overwrite), get, and delete a brand keyed on \
                                        its slug. Design tokens are a closed typed grammar and \
                                        rich-text slots are sanitized at ingest, so a brand can \
                                        never carry raw CSS or markup"),
        (name = "brand-assets", description = "Per-environment brand assets: upload (magic-byte \
                                              sniffed, size-capped, sudo-gated raster) or delete a \
                                              brand's logo and favicon; svg is refused"),
        (name = "sessions", description = "Session and refresh-family fleet operations: \
                                          search, inspect, revoke (single, bulk, and \
                                          everything-for-a-user with a token-family cascade)"),
        (name = "users", description = "Admin user CRUD, lifecycle state transitions, and \
                                       external-id correlation, with a session cascade on the \
                                       session-ending transitions"),
        (name = "trait-schemas", description = "Per-environment identity trait-schema versions: \
                                               an append-only registry of immutable JSON Schema \
                                               (draft 2020-12) versions with inline behavior \
                                               annotations, the active-version introspection \
                                               read, and the cutover-gated activation"),
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
        (name = "imports", description = "The streaming bulk identity IMPORT job (issue #55): \
                                         the write half of the migration on-ramp. Create a run \
                                         declaring the source record count and stream \
                                         newline-delimited identity records into it, in exactly \
                                         the format `exportIdentities` emits; resume the same \
                                         run with more records after an interruption. The body \
                                         is read one frame at a time and never buffered whole. \
                                         Resuming is idempotent on each record's stable key, so \
                                         a caller who does not know where a kill landed may \
                                         safely re-present the whole source without duplicating \
                                         or losing a record. These endpoints answer a job HANDLE \
                                         and no counters: progress is the `migration-runs` view, \
                                         which is the one projection of them"),
        (name = "diagnostics", description = "Admin flow inspector diagnostics (issue #91): the \
                                            rich, structured record of WHY a client authentication \
                                            failed (the specific reason, the assertion key id and \
                                            algorithm, the derived clock skew, the expectation \
                                            hint), kept off the wire while the token endpoint's \
                                            response stays the opaque invalid_client"),
        (name = "sudo", description = "Admin session privilege separation (issue #73): the \
                                     re-authentication endpoint that records a fresh elevation \
                                     so admin mutations pass the sudo freshness gate")
    ),
    paths(
        crate::event_feed::read_event_feed,
        crate::operators::list_operators,
        crate::operators::get_operator,
        crate::resource_types::list_resource_types,
        crate::tenants::list_tenants,
        crate::tenants::create_tenant,
        crate::tenants::get_tenant,
        crate::tenants::delete_tenant,
        crate::tenants::suspend_tenant,
        crate::tenants::resume_tenant,
        crate::tenants::purge_tenant,
        crate::tenants::restore_tenant,
        crate::environments::list_environments,
        crate::environments::create_environment,
        crate::environments::get_environment,
        crate::environments::delete_environment,
        crate::organizations::list_organizations,
        crate::organizations::create_organization,
        crate::organizations::get_organization,
        crate::organizations::delete_organization,
        crate::organizations::disable_organization,
        crate::organizations::enable_organization,
        crate::memberships::create_membership,
        crate::memberships::list_memberships,
        crate::memberships::delete_membership,
        crate::permissions::create_permission,
        crate::permissions::list_permissions,
        crate::permissions::get_permission,
        crate::permissions::update_permission,
        crate::permissions::delete_permission,
        // Environment VARIABLE management (issue #235). The variable half only; the secret
        // half needs a plane and master-key decision and is tracked on that issue.
        crate::secrets::list_secrets,
        crate::secrets::get_secret,
        crate::secrets::set_secret,
        crate::secrets::delete_secret,
        crate::variables::list_variables,
        crate::variables::get_variable,
        crate::variables::set_variable,
        crate::variables::delete_variable,
        crate::client_scopes::get_client_allowed_scopes,
        crate::client_scopes::set_client_allowed_scopes,
        crate::resource_servers::list_resource_servers,
        crate::resource_servers::get_resource_server,
        crate::resource_servers::update_resource_server_permission_claims,
        crate::org_roles::create_org_role,
        crate::org_roles::list_org_roles,
        crate::org_roles::get_org_role,
        crate::org_roles::update_org_role,
        crate::org_roles::delete_org_role,
        crate::org_roles::set_org_default_role,
        crate::org_roles::clear_org_default_role,
        crate::org_role_permissions::assign_org_role_permission,
        crate::org_role_permissions::list_org_role_permissions,
        crate::org_role_permissions::unassign_org_role_permission,
        crate::org_groups::create_org_group,
        crate::org_groups::list_org_groups,
        crate::org_groups::get_org_group,
        crate::org_groups::update_org_group,
        crate::org_groups::set_org_group_parent,
        crate::org_groups::delete_org_group,
        crate::org_group_members::add_org_group_member,
        crate::org_group_members::list_org_group_members,
        crate::org_group_members::remove_org_group_member,
        crate::routing_rules::create_routing_rule,
        crate::routing_rules::verify_routing_rule_domain,
        crate::routing_rules::list_routing_rules,
        crate::project_grants::create_project_grant,
        crate::project_grants::list_project_grants,
        crate::api_keys::list_organization_api_keys,
        crate::api_keys::create_organization_api_key,
        crate::api_keys::revoke_organization_api_key,
        crate::api_keys::rotate_organization_api_key,
        crate::service_account_keys::get_client_service_account,
        crate::service_account_keys::list_service_account_api_keys,
        crate::service_account_keys::create_service_account_api_key,
        crate::service_account_keys::revoke_service_account_api_key,
        crate::service_account_keys::rotate_service_account_api_key,
        crate::authzen::get_authzen_configuration,
        crate::authzen::authzen_evaluation,
        crate::authzen::authzen_evaluations,
        crate::impersonation::authorize_user_impersonation,
        crate::personal_access_tokens::list_user_personal_access_tokens,
        crate::personal_access_tokens::create_user_personal_access_token,
        crate::personal_access_tokens::revoke_user_personal_access_token,
        crate::personal_access_tokens::rotate_user_personal_access_token,
        crate::project_grants::withdraw_project_grant,
        crate::org_role_assignments::assign_org_group_role,
        crate::org_role_assignments::list_org_group_roles,
        crate::org_role_assignments::unassign_org_group_role,
        crate::org_role_assignments::assign_org_membership_role,
        crate::org_role_assignments::list_org_membership_roles,
        crate::org_role_assignments::unassign_org_membership_role,
        crate::org_effective_roles::get_org_membership_effective_roles,
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
        crate::signing_algorithm::get_signing_recommendations,
        crate::signing_algorithm::set_client_signing_algorithm,
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
        crate::signup_forms::set_signup_form,
        crate::signup_forms::get_signup_form,
        crate::signup_forms::delete_signup_form,
        crate::flow_versions::create_flow_version,
        crate::flow_versions::list_flow_versions,
        crate::flow_versions::get_flow_version,
        crate::flow_versions::pin_flow_version,
        crate::client_admin_grants::set_client_admin_consent,
        crate::client_admin_grants::get_client_admin_consent,
        crate::client_admin_grants::delete_client_admin_consent,
        crate::brands::list_brands,
        crate::brands::set_brand,
        crate::brands::get_brand,
        crate::brands::delete_brand,
        crate::brand_assets::set_brand_logo,
        crate::brand_assets::delete_brand_logo,
        crate::brand_assets::set_brand_favicon,
        crate::brand_assets::delete_brand_favicon,
        crate::sessions::list_sessions,
        crate::sessions::get_session,
        crate::sessions::revoke_session,
        crate::sessions::bulk_revoke_sessions,
        crate::sessions::revoke_user_sessions,
        crate::sessions::list_refresh_families,
        crate::sessions::get_refresh_family,
        crate::consents::list_user_consents,
        crate::consents::revoke_user_consent,
        crate::users::create_user,
        crate::users::list_users,
        crate::users::get_user,
        crate::users::update_user,
        crate::users::delete_user,
        crate::users::set_user_state,
        crate::users::link_user_external_id,
        crate::users::unlink_user_external_id,
        crate::users::get_user_traits,
        crate::identifiers::list_user_identifiers,
        crate::identifiers::add_user_identifier,
        crate::identifiers::remove_user_identifier,
        crate::identifiers::get_identifier_uniqueness,
        crate::sms_otp::get_sms_otp_config,
        crate::sms_otp::set_sms_otp_config,
        crate::sms_otp::list_sms_allowlist,
        crate::sms_otp::allow_sms_country,
        crate::sms_otp::deny_sms_country,
        crate::identifiers::apply_identifier_uniqueness,
        crate::trait_schemas::create_trait_schema_version,
        crate::trait_schemas::list_trait_schema_versions,
        crate::trait_schemas::get_active_trait_schema,
        crate::trait_schemas::get_trait_schema_version,
        crate::trait_schemas::activate_trait_schema_version,
        crate::trait_schemas::create_trait_migration_job,
        crate::trait_schemas::get_trait_migration_job,
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
        crate::migration::get_outbound_verification,
        crate::migration::set_outbound_verification,
        crate::migration::delete_outbound_verification,
        crate::migration_status::get_migration_progress,
        crate::diagnostics::get_client_auth_diagnostics,
        crate::diagnostics::get_policy_traces,
        crate::diagnostics::get_diagnostics_warnings,
        crate::diagnostics::get_user_risk_posture,
        crate::diagnostics::get_risk_decision,
        crate::diagnostics::get_flow_observation,
        crate::diagnostics::post_flow_dry_run,
        crate::mds3_health::get_mds3_health,
        crate::password_hashing::probe_password_hashing,
        crate::imports::create_identity_import,
        crate::imports::resume_identity_import,
        crate::migration_runs::list_migration_runs,
        crate::migration_runs::get_migration_run,
        crate::migration_runs::list_migration_run_violations,
        crate::migration_runs::abandon_migration_run,
        crate::bans::create_ban,
        crate::bans::lift_ban,
        crate::bans::list_bans,
        crate::step_up_policies::list_step_up_policies,
        crate::step_up_policies::set_step_up_policy,
        crate::step_up_policies::remove_step_up_policy,
        crate::log_streams::list_log_streams,
        crate::log_streams::create_log_stream,
        crate::log_streams::delete_log_stream,
        crate::webhook_endpoints::list_webhook_endpoints,
        crate::webhook_endpoints::create_webhook_endpoint,
        crate::webhook_endpoints::rotate_webhook_endpoint_secret,
        crate::postures::set_client_par_requirement,
        crate::postures::set_auto_link_posture,
        crate::queues::list_queue_depths,
        crate::webhook_endpoints::list_webhook_delivery_attempts,
        crate::webhook_endpoints::list_webhook_dead_letters,
        crate::webhook_endpoints::replay_webhook_dead_letters,
        crate::webhook_endpoints::set_webhook_event_types,
        crate::webhook_endpoints::pause_webhook_endpoint,
        crate::webhook_endpoints::resume_webhook_endpoint,
        crate::webhook_endpoints::delete_webhook_endpoint,
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
        MembershipView,
        MembershipList,
        CreateMembershipRequest,
        crate::permissions::PermissionView,
        crate::permissions::PermissionList,
        crate::permissions::CreatePermissionRequest,
        crate::secrets::SecretView,
        crate::secrets::SecretList,
        crate::secrets::SetSecretRequest,
        crate::variables::VariableView,
        crate::variables::VariableList,
        crate::variables::SetVariableRequest,
        crate::permissions::UpdatePermissionRequest,
        crate::client_scopes::ClientAllowedScopesView,
        crate::client_scopes::SetClientAllowedScopesRequest,
        crate::resource_servers::ResourceServerView,
        crate::resource_servers::ResourceServerList,
        crate::resource_servers::UpdateResourceServerRequest,
        crate::org_roles::OrgRoleView,
        crate::event_feed::EventFeedPage,
        crate::event_feed::FeedEvent,
        crate::event_feed::FeedGone,
        crate::org_roles::OrgRoleList,
        crate::org_roles::CreateOrgRoleRequest,
        crate::org_roles::SetOrgDefaultRoleRequest,
        crate::org_role_permissions::OrgRolePermissionView,
        crate::org_role_permissions::OrgRolePermissionList,
        crate::org_role_permissions::AssignOrgRolePermissionRequest,
        crate::org_roles::UpdateOrgRoleRequest,
        crate::org_groups::OrgGroupView,
        crate::org_groups::OrgGroupList,
        crate::org_groups::CreateOrgGroupRequest,
        crate::org_groups::UpdateOrgGroupRequest,
        crate::org_groups::SetOrgGroupParentRequest,
        crate::org_group_members::OrgGroupMemberView,
        crate::org_group_members::OrgGroupMemberList,
        crate::org_group_members::AddOrgGroupMemberRequest,
        crate::org_role_assignments::OrgGroupRoleView,
        crate::org_role_assignments::OrgGroupRoleList,
        crate::org_role_assignments::AssignOrgGroupRoleRequest,
        crate::org_role_assignments::OrgMembershipRoleView,
        crate::org_role_assignments::OrgMembershipRoleList,
        crate::org_role_assignments::AssignOrgMembershipRoleRequest,
        crate::org_effective_roles::EffectiveRolesView,
        crate::org_effective_roles::EffectiveRoleView,
        crate::org_effective_roles::EffectiveRoleSourceView,
        crate::org_effective_roles::PermissionBudgetView,
        crate::org_effective_roles::PermissionBudgetScope,
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
        SigningRecommendationView,
        SetClientSigningAlgorithmRequest,
        ClientSigningAlgorithmView,
        CreateConnectorRequest,
        ConnectorView,
        ConnectorList,
        ConnectorCapabilitiesView,
        ConnectorHealthView,
        SetLocaleRequest,
        LocaleBundleView,
        SetSignupFormRequest,
        SignupFormFieldView,
        SignupFormView,
        CreateFlowVersionRequest,
        FlowVersionView,
        crate::views::CreateTraitSchemaRequest,
        TraitSchemaVersionView,
        TraitAnnotationsView,
        VerificationAddressView,
        UserTraitsView,
        crate::identifiers::IdentifierView,
        crate::identifiers::IdentifierList,
        crate::identifiers::AddIdentifierRequest,
        crate::identifiers::UniquenessView,
        crate::sms_otp::SmsConfigView,
        crate::sms_otp::SetSmsConfigRequest,
        crate::sms_otp::SmsAllowlistView,
        crate::identifiers::CollisionView,
        crate::error::TraitErrorView,
        SetClientAdminConsentRequest,
        ClientAdminConsentView,
        BrandAssetView,
        BrandPage,
        BrandView,
        SetBrandRequest,
        SessionView,
        SessionList,
        RefreshFamilyView,
        RefreshFamilyList,
        RevokeSessionsRequest,
        BulkRevokeSessionsRequest,
        SessionRevocationView,
        BulkRevocationView,
        UserRevocationView,
        UserConsentView,
        UserConsentList,
        ConsentRevocationView,
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
        crate::migration::OutboundVerificationView,
        crate::migration::SetOutboundVerificationRequest,
        crate::migration::VerifyCredentialRequest,
        crate::migration::VerifyCredentialResponse,
        crate::migration::VerifyProfile,
        crate::migration_status::MigrationProgressView,
        crate::diagnostics::ClientAuthDiagnosticView,
        crate::diagnostics::ClientAuthDiagnosticsList,
        crate::diagnostics::PolicyTraceView,
        crate::diagnostics::PolicyTracesList,
        crate::diagnostics::RiskPostureView,
        crate::diagnostics::RiskDecisionSummary,
        crate::diagnostics::WarningItemView,
        crate::diagnostics::DiagnosticsWarningsList,
        crate::diagnostics::FlowContextResponse,
        crate::diagnostics::FlowNodeView,
        crate::diagnostics::FlowObserveResponse,
        crate::diagnostics::RiskSignalRequest,
        crate::diagnostics::RiskScenarioRequest,
        crate::diagnostics::FlowDryRunRequest,
        crate::diagnostics::StepUpDecisionResponse,
        crate::diagnostics::RiskSignalResponse,
        crate::diagnostics::RiskDecisionResponse,
        crate::diagnostics::FlowDryRunStep,
        crate::diagnostics::FlowDryRunResponse,
        crate::mds3_health::Mds3HealthView,
        crate::password_hashing::PasswordHashingProbeRequest,
        crate::password_hashing::PasswordHashingProbeReport,
        crate::imports::ImportJobView,
        crate::migration_runs::MigrationRunSummaryView,
        crate::migration_runs::MigrationRunList,
        crate::migration_runs::MigrationRunCountsView,
        crate::migration_runs::InvariantView,
        crate::migration_runs::MigrationRunDetailView,
        crate::migration_runs::OffendingRecordView,
        crate::migration_runs::MigrationRunViolationList,
        crate::migration_runs::AbandonMigrationRunRequest,
        crate::bans::CreateBanRequest,
        crate::bans::LiftBanRequest,
        crate::step_up_policies::StepUpPolicyView,
        crate::step_up_policies::StepUpPolicyList,
        crate::step_up_policies::SetStepUpPolicyRequest,
        crate::webhook_endpoints::WebhookEndpointView,
        crate::webhook_endpoints::WebhookEndpointList,
        crate::webhook_endpoints::WebhookEndpointCreated,
        crate::webhook_endpoints::CreateWebhookEndpointRequest,
        crate::webhook_endpoints::WebhookSecretRotated,
        crate::trait_schemas::CreateTraitMigrationRequest,
        crate::trait_schemas::TraitMigrationJobView,
        crate::trait_schemas::RecordFailureView,
        crate::postures::SetClientParRequirementRequest,
        crate::postures::ClientParRequirementView,
        crate::postures::SetAutoLinkPostureRequest,
        crate::postures::AutoLinkPostureView,
        crate::queues::QueueDepthView,
        crate::queues::QueueDepthList,
        crate::webhook_endpoints::DeliveryAttemptView,
        crate::webhook_endpoints::DeliveryAttemptList,
        crate::webhook_endpoints::SetEventTypesRequest,
        crate::webhook_endpoints::DeadLetteredDelivery,
        crate::webhook_endpoints::DeadLetterList,
        crate::webhook_endpoints::ReplayDeadLettersRequest,
        crate::webhook_endpoints::ReplayAccepted,
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
