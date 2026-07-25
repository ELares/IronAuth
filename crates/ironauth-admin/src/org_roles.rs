// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization role CRUD under an organization (issue #97).
//!
//! A role in M10 is a NAME only: an immutable `slug` an authorization decision
//! keys on, plus a mutable `display_name` and free-form metadata. What a role
//! GRANTS is issue #98. Every endpoint here is nested under an organization, so it
//! is scoped to a `(tenant, environment)` pair and reachable by the operator OR by
//! a management key scoped to exactly that environment, the same authorization as
//! the organization and membership endpoints.
//!
//! # Containment, and the two layers that enforce it
//!
//! Row-level security fences `(tenant, environment)` and NOTHING finer, so inside
//! one environment the `organization_id` is the only thing keeping one
//! organization's roles out of another's. Two layers carry it:
//!
//!   * The typed [`ironauth_store::OrgRoleId`] embeds the scope, so a role minted
//!     in another `(tenant, environment)` fails to parse in scope and never
//!     reaches a statement.
//!   * The nested address is the PAIR `(organization_id, role_id)`, resolved
//!     through [`ironauth_store::OrgRoleRepo::get_in_org`] on every id-addressed
//!     endpoint. A role of a SIBLING organization in the SAME environment is the
//!     uniform not-found, exactly like an absent, soft-deleted, or foreign-scope
//!     one.
//!
//! The mutating repository's `update` and `delete` are addressed by role id alone,
//! unlike the group mutations. That is SOUND here and is not an oversight to copy
//! elsewhere: `org_roles.organization_id` is immutable by GRANT (migration 0086
//! grants the control role UPDATE on `display_name`, `metadata`, `updated_at`, and
//! `deleted_at`, and on nothing else), so a role cannot change organizations
//! between the `get_in_org` that authorizes the request and the write that
//! executes it. The read-then-write is therefore not a check-to-use window: there
//! is no reachable state in which the pair was valid at the read and is invalid at
//! the write. Groups get their containment predicate in the statement itself
//! because a group's `parent_id` IS writable and its mutations reshape a tree.
//!
//! # No caps
//!
//! Nothing here limits how many roles an organization may define. The page size on
//! the list is clamped like every management list, which bounds ONE RESPONSE and
//! never the number of stored rows.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewOrgRole, OrgRoleId, OrgRoleRecord, OrganizationId, Scope,
    StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty, require_slug};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// An organization role, as returned by the management API (issue #97).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgRoleView {
    /// The role identifier (`rol_...`, embeds its scope).
    pub id: String,
    /// The organization the role belongs to (`org_...`).
    pub organization_id: String,
    /// The IMMUTABLE stable name. A rename changes `display_name`, never this, so
    /// a name an authorization decision keys on cannot move under it.
    pub slug: String,
    /// The mutable human-facing label.
    pub display_name: String,
    /// Free-form role metadata (the empty object when none was set).
    pub metadata: serde_json::Value,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Last-modification time, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: i64,
}

impl OrgRoleView {
    /// Build a view from a stored record. The repository only returns LIVE (not
    /// soft-deleted) roles.
    fn from_record(record: OrgRoleRecord) -> Self {
        Self {
            id: record.id.to_string(),
            organization_id: record.organization_id.to_string(),
            slug: record.slug,
            display_name: record.display_name,
            metadata: record.metadata,
            created_at_unix_ms: record.created_at_unix_micros / 1000,
            updated_at_unix_ms: record.updated_at_unix_micros / 1000,
        }
    }
}

/// The body to define a role in an organization.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateOrgRoleRequest {
    /// The IMMUTABLE stable name, unique among the organization's LIVE roles.
    /// Must match `^[a-z0-9][a-z0-9._-]{0,62}$`; it is never trimmed or case
    /// folded, so a non-canonical value is refused rather than silently rewritten.
    #[schema(example = "billing.admin")]
    pub slug: String,
    /// The mutable human-facing label.
    #[schema(example = "Billing Administrator")]
    pub display_name: String,
    /// Optional free-form role metadata; the empty object when omitted.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// The body to rename a role (RFC 7396 style partial edit: an omitted field is
/// left unchanged). The `slug` is deliberately absent and is not editable.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateOrgRoleRequest {
    /// A new human-facing label. Omitted leaves it unchanged.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Replacement free-form metadata (a whole-document replace, not a merge).
    /// Omitted leaves it unchanged.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// A page of organization roles.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgRoleList {
    /// The roles on this page, oldest first. There is no cap on how many roles an
    /// organization may hold; this page is size-clamped like every list.
    pub items: Vec<OrgRoleView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Resolve and authorize the `(tenant, environment)` scope from the path. The
/// operator passes; a management key must be scoped to exactly this environment
/// (otherwise the LOUD wrong-scope error). A malformed tenant or environment id is
/// the uniform not-found.
fn resolve_scope(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ironauth_store::ActorRef), ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(tenant)
        .parse_id(environment_id)?;
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// Resolve the parent organization id in scope, verifying it exists and is LIVE. A
/// foreign or soft-deleted organization reads as a uniform not-found.
async fn resolve_live_org(
    state: &AdminState,
    scope: Scope,
    organization_id: &str,
) -> Result<OrganizationId, ApiError> {
    let organizations = state.store().management().organizations(scope);
    let id = organizations.parse_id(organization_id)?;
    organizations.get(&id).await?;
    Ok(id)
}

/// Resolve the nested `(organization, role)` pair, which is the ROLE'S ADDRESS.
///
/// The cross-parent guard: a role of a DIFFERENT organization, even in the same
/// environment, is the uniform not-found here, exactly like an absent, a
/// soft-deleted, and a foreign-scope one. That uniformity is what stops the nested
/// path from being an existence oracle over a sibling organization's roles.
async fn resolve_role_in_org(
    state: &AdminState,
    scope: Scope,
    org_id: &OrganizationId,
    role_id: &str,
) -> Result<OrgRoleRecord, ApiError> {
    let roles = state.store().management().org_roles(scope);
    // A malformed id and one minted in another `(tenant, environment)` both fail to
    // parse in scope, which is the same not-found the read below returns.
    let id = roles.parse_id(role_id)?;
    Ok(roles.get_in_org(org_id, &id).await?)
}

/// Define a role in an organization.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles",
    operation_id = "createOrgRole",
    tag = "org-roles",
    request_body = CreateOrgRoleRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = OrgRoleView),
        (status = 400, description = "Malformed request (including a slug the stable-name rule refuses)", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Organization not found", body = ErrorBody),
        (status = 409, description = "A live role of this organization already holds that slug", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_org_role(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();

    // Replay BEFORE the parent-existence precondition, so a genuine replay returns
    // the original response even if the organization was disabled meanwhile.
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let org_id = resolve_live_org(&state, scope, &organization_id).await?;

    let request: CreateOrgRoleRequest = parse_json(&body)?;
    let slug = require_slug(&request.slug, "slug")?;
    let display_name = require_non_empty(&request.display_name, "display_name")?;

    let created_at_micros = state.now_unix_micros();
    let role_id = OrgRoleId::generate(state.env(), &scope);
    let view = OrgRoleView {
        id: role_id.to_string(),
        organization_id: org_id.to_string(),
        slug: slug.clone(),
        display_name: display_name.clone(),
        metadata: request
            .metadata
            .clone()
            .unwrap_or_else(|| serde_json::json!({})),
        created_at_unix_ms: created_at_micros / 1000,
        updated_at_unix_ms: created_at_micros / 1000,
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
        .org_roles(scope)
        .create(
            state.env(),
            NewOrgRole {
                id: &role_id,
                organization_id: &org_id,
                slug: &slug,
                display_name: &display_name,
                metadata: request.metadata.as_ref(),
            },
            created_at_micros,
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "a role of this organization already holds that slug".to_owned(),
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List an organization's roles (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles",
    operation_id = "listOrgRoles",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of roles", body = OrgRoleList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Organization not found", body = ErrorBody)
    )
)]
pub async fn list_org_roles(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let org_id = resolve_live_org(&state, scope, &organization_id).await?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    // `list_for_org` filters on organization_id, so a sibling organization's roles
    // can never appear on this page.
    let rows = state
        .store()
        .management()
        .org_roles(scope)
        .list_for_org(&org_id, page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = OrgRoleList {
        items: rows.into_iter().map(OrgRoleView::from_record).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one role of an organization.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}",
    operation_id = "getOrgRole",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("role_id" = String, Path, description = "The role identifier (rol_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The role", body = OrgRoleView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, deleted, another scope's, or another organization's)", body = ErrorBody)
    )
)]
pub async fn get_org_role(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, role_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let org_id = resolve_live_org(&state, scope, &organization_id).await?;
    let record = resolve_role_in_org(&state, scope, &org_id, &role_id).await?;
    let body =
        serde_json::to_string(&OrgRoleView::from_record(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Rename a role (or replace its metadata). The `slug` is immutable.
#[utoipa::path(
    patch,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}",
    operation_id = "updateOrgRole",
    tag = "org-roles",
    request_body = UpdateOrgRoleRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("role_id" = String, Path, description = "The role identifier (rol_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The updated role", body = OrgRoleView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, deleted, another scope's, or another organization's)", body = ErrorBody)
    )
)]
pub async fn update_org_role(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, role_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id = resolve_live_org(&state, scope, &organization_id).await?;
    // The cross-parent guard, BEFORE the write: a role of a sibling organization
    // presented under this organization's path is the uniform not-found, so the
    // nested path can never rename another organization's role. `organization_id`
    // is immutable by GRANT, so this pair cannot come apart before the write.
    let record = resolve_role_in_org(&state, scope, &org_id, &role_id).await?;

    let request: UpdateOrgRoleRequest = parse_json(&body)?;
    let display_name = request
        .display_name
        .as_deref()
        .map(|value| require_non_empty(value, "display_name"))
        .transpose()?;
    if display_name.is_some() || request.metadata.is_some() {
        state
            .store()
            .management()
            .acting(actor, CorrelationId::generate(state.env()))
            .org_roles(scope)
            .update(
                state.env(),
                &record.id,
                display_name.as_deref(),
                request.metadata.as_ref(),
            )
            .await?;
    }
    // Re-read through the SAME nested address, so the response can only ever
    // describe a role of this organization.
    let updated = resolve_role_in_org(&state, scope, &org_id, &role_id).await?;
    let body = serde_json::to_string(&OrgRoleView::from_record(updated))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Delete a role (soft delete; idempotent in effect).
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}",
    operation_id = "deleteOrgRole",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("role_id" = String, Path, description = "The role identifier (rol_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted (the slug is immediately free for a new role)"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, already deleted, another scope's, or another organization's)", body = ErrorBody)
    )
)]
pub async fn delete_org_role(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, role_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id = resolve_live_org(&state, scope, &organization_id).await?;
    // The cross-parent guard: deleting a sibling organization's role through this
    // path is the uniform not-found and removes nothing.
    let record = resolve_role_in_org(&state, scope, &org_id, &role_id).await?;
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_roles(scope)
        .delete(state.env(), &record.id)
        .await?;
    Ok(no_content())
}
