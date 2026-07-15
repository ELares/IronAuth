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
    BulkRevocationView, BulkRevokeSessionsRequest, ClientVerificationView, CreateDcrPolicyRequest,
    CreateEnvironmentRequest, CreateInitialAccessTokenRequest, CreateManagementKeyRequest,
    CreateOrganizationRequest, CreateTenantRequest, DcrPolicyList, DcrPolicyView, EnvironmentList,
    EnvironmentView, GuardrailView, InitialAccessTokenCreated, ManagementKeyCreated,
    ManagementKeyList, ManagementKeyView, OperatorList, OperatorView, OrganizationList,
    OrganizationView, RefreshFamilyList, RefreshFamilyView, ResourceTypeView, ResourceTypesList,
    RevokeSessionsRequest, SessionList, SessionRevocationView, SessionView, TenantCreated,
    TenantList, TenantStatusView, TenantView, UserRevocationView,
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
        (name = "keys", description = "Environment-scoped management API keys"),
        (name = "dcr", description = "Dynamic Client Registration abuse controls: \
                                     policies, initial access tokens, client verification"),
        (name = "sessions", description = "Session and refresh-family fleet operations: \
                                          search, inspect, revoke (single, bulk, and \
                                          everything-for-a-user with a token-family cascade)")
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
        crate::dcr::create_dcr_policy,
        crate::dcr::list_dcr_policies,
        crate::dcr::create_initial_access_token,
        crate::dcr::get_dcr_client,
        crate::dcr::verify_dcr_client,
        crate::sessions::list_sessions,
        crate::sessions::get_session,
        crate::sessions::revoke_session,
        crate::sessions::bulk_revoke_sessions,
        crate::sessions::revoke_user_sessions,
        crate::sessions::list_refresh_families,
        crate::sessions::get_refresh_family,
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
        CreateDcrPolicyRequest,
        DcrPolicyView,
        DcrPolicyList,
        CreateInitialAccessTokenRequest,
        InitialAccessTokenCreated,
        ClientVerificationView,
        SessionView,
        SessionList,
        RefreshFamilyView,
        RefreshFamilyList,
        RevokeSessionsRequest,
        BulkRevokeSessionsRequest,
        SessionRevocationView,
        BulkRevocationView,
        UserRevocationView,
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
