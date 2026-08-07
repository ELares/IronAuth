// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management surface for project grants (issue #102, migration 0120).
//!
//! A grant binds one application to one customer organization and names the subset of
//! that organization's roles its DELEGATED administrators may assign. Migration 0120
//! ships the tables and the enforcement; this is how an operator creates one without
//! reaching for SQL.
//!
//! # Only the vendor may manage a grant, and this is a privilege-escalation fence
//!
//! Every handler here refuses a CONFINED credential outright, before it reaches the
//! organization. That is not a tidiness rule and it does not follow from the permission
//! check, so it is worth stating exactly why.
//!
//! A grant bounds a credential confined to one organization (migration 0119). A confined
//! credential holding `management.write_organizations` can already reach its OWN
//! organization: [`resolve_live_org`] is built to allow precisely that. If managing
//! grants were governed by the permission alone, such a credential could WITHDRAW the
//! grant that bounds it, and because absence of a grant means unrestricted, it would
//! silently become able to assign every role in its organization. It could equally
//! create a wider grant for itself. Either way the bound would be editable by the party
//! it exists to bind, which makes it decoration.
//!
//! So the fence is on CONFINEMENT rather than on permission, because confinement is what
//! the grant restricts. The vendor, who is unconfined, manages grants; the customer, who
//! is confined, is managed by them.
//!
//! # Changing a subset is a withdrawal and a fresh grant
//!
//! There is deliberately no endpoint that edits a live grant's role subset. Migration
//! 0120 never revives a withdrawn grant and mints a fresh id instead, so the audit
//! history of what was once assignable is never overwritten in place. Editing a subset
//! under a stable id would defeat that: an auditor reading `project_grant.create` would
//! see a set that no longer describes what the grant permitted for most of its life.
//! Withdraw and re-create leaves both records, and both are attributable.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    ClientId, CorrelationId, IdempotencyWrite, NewProjectGrant, OrgRoleId, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// A project grant to create.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateProjectGrantRequest {
    /// The application the grant is about (a `cli_` id).
    pub client_id: String,
    /// The roles a delegated administrator of this organization may assign. MAY be
    /// empty, which means they may assign nothing; that is a real contract and is not
    /// the same as having no grant at all.
    #[serde(default)]
    pub role_ids: Vec<String>,
}

/// A project grant as returned to a caller.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectGrantView {
    /// The grant identifier (`pgt_...`).
    pub id: String,
    /// The application the grant is about.
    pub client_id: String,
    /// The organization it bounds.
    pub organization_id: String,
    /// The roles assignable under it.
    pub role_ids: Vec<String>,
    /// Creation time in milliseconds since the epoch.
    pub created_at_unix_ms: i64,
}

/// A page of project grants.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProjectGrantListView {
    /// The live grants of this organization, oldest first.
    pub items: Vec<ProjectGrantView>,
}

/// Refuse a confined credential. See the module header: the party a grant binds must not
/// be able to edit it.
fn require_vendor(principal: &Principal) -> Result<(), ApiError> {
    if principal.confined_organization().is_none() {
        return Ok(());
    }
    Err(ApiError::WrongScope {
        expected: "an unconfined management credential".to_owned(),
        actual: "credential confined to one organization".to_owned(),
        message: "a project grant bounds a confined credential, so a confined credential \
                  may not create or withdraw one"
            .to_owned(),
    })
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/project-grants",
    operation_id = "createProjectGrant",
    tag = "org-roles",
    request_body = CreateProjectGrantRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created. The organization's delegated administrators may now assign only the roles named here", body = ProjectGrantView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or a confined credential attempted to manage the grant that bounds it", body = ErrorBody),
        (status = 404, description = "Not found: the organization, the client, or a named role is not a live row of this organization (uniform across absent, deleted, another scope's, and another organization's)", body = ErrorBody),
        (status = 409, description = "A live grant already binds this application and organization", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_project_grant(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    require_vendor(&principal)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;

    let request: CreateProjectGrantRequest = parse_json(&body)?;
    let client_id =
        ClientId::parse_in_scope(&request.client_id, &scope).map_err(|_| ApiError::NotFound)?;
    let mut role_ids = Vec::with_capacity(request.role_ids.len());
    for raw in &request.role_ids {
        role_ids.push(OrgRoleId::parse_in_scope(raw, &scope).map_err(|_| ApiError::NotFound)?);
    }

    let created_at_micros = state.now_unix_micros();
    let grant_id = ironauth_store::ProjectGrantId::generate(state.env(), &scope);
    let view = ProjectGrantView {
        id: grant_id.to_string(),
        client_id: client_id.to_string(),
        organization_id: org_id.to_string(),
        role_ids: role_ids.iter().map(ToString::to_string).collect(),
        created_at_unix_ms: created_at_micros / 1000,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &body_string,
    };
    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .project_grants(scope)
        .create(
            state.env(),
            NewProjectGrant {
                id: &grant_id,
                client_id: &client_id,
                organization_id: &org_id,
                role_ids: &role_ids,
            },
            created_at_micros,
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "a live grant already binds this application and organization".to_owned(),
        )),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/project-grants",
    operation_id = "listProjectGrants",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The live grants of this organization, oldest first", body = ProjectGrantListView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or a confined credential attempted to read the grant that bounds it", body = ErrorBody),
        (status = 404, description = "The organization is not a live row of this scope", body = ErrorBody)
    )
)]
pub async fn list_project_grants(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;
    require_vendor(&principal)?;

    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;

    let records = state
        .store()
        .management()
        .project_grants(scope)
        .list_in_org(&org_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    let view = ProjectGrantListView {
        items: records
            .into_iter()
            .map(|record| ProjectGrantView {
                id: record.id,
                client_id: record.client_id,
                organization_id: record.organization_id,
                role_ids: record.role_ids,
                created_at_unix_ms: record.created_at_unix_micros / 1000,
            })
            .collect(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/project-grants/{grant_id}",
    operation_id = "withdrawProjectGrant",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("grant_id" = String, Path, description = "The grant identifier (pgt_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Withdrawn. This WIDENS what the organization's delegated administrators may assign, because absence of a grant means unrestricted"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or a confined credential attempted to withdraw the grant that bounds it", body = ErrorBody),
        (status = 404, description = "The organization or the grant is not a live row of this scope", body = ErrorBody)
    )
)]
pub async fn withdraw_project_grant(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, grant_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    require_vendor(&principal)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let _org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let id = state
        .store()
        .management()
        .project_grants(scope)
        .parse_id(&grant_id)
        .map_err(|_| ApiError::NotFound)?;

    let now_micros = state.now_unix_micros();
    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .project_grants(scope)
        .withdraw(state.env(), &id, now_micros, None)
        .await;

    match result {
        Ok(()) => Ok(no_content()),
        Err(StoreError::NotFound) => Err(ApiError::NotFound),
        Err(_) => Err(ApiError::Internal),
    }
}
