// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization role CRUD under an organization (issue #97), plus the
//! organization's DEFAULT ROLE designation (issue #98).
//!
//! A role in M10 is a NAME only: an immutable `slug` an authorization decision
//! keys on, plus a mutable `display_name` and free-form metadata. What a role
//! GRANTS is issue #98. Every endpoint here is nested under an organization, so it
//! is scoped to a `(tenant, environment)` pair and reachable by the operator OR by
//! a management key scoped to exactly that environment, the same authorization as
//! the organization and membership endpoints.
//!
//! # The default role: why `PUT .../default-role` and not `.../roles/{id}/default`
//!
//! The designation is a per-ORGANIZATION SINGLETON. It is STORED as a flag on a role
//! (migration 0093 records why it is not a pointer on `organizations`), but what it
//! names is one property of the organization, and its ADDRESS follows what it names
//! rather than where it is stored. Three consequences decided the shape:
//!
//!   * `PUT .../organizations/{organization_id}/default-role` addresses that one
//!     property at ONE path. `PUT .../roles/{role_id}/default` would give a
//!     single-valued property as many addresses as the organization has roles, and
//!     `PUT` would then no longer mean idempotent replacement of a value: two
//!     successive puts on two different role paths would both claim to have
//!     succeeded while only the second survives.
//!   * CLEARING has no role to name. `DELETE .../default-role` says exactly what it
//!     does; `DELETE .../roles/{role_id}/default` would force the caller to already
//!     know which role holds the designation, and would have to invent an answer for
//!     a role that does not, which is either a 404 that looks like the role is gone
//!     or a 204 that claims a removal it did not perform.
//!   * READING it needs no endpoint at all, because the flag is projected onto
//!     [`OrgRoleView`]: `GET .../roles` and `GET .../roles/{role_id}` report
//!     `is_default`, which is the honest place for it given where the value lives,
//!     and it keeps this PR at the five endpoints it owns.
//!
//! ## The second designation MOVES it; it is not a 409
//!
//! `org_roles_org_default_live_uniq` is a partial unique index, so a second LIVE
//! default in one organization is refused by Postgres. This endpoint does not let
//! that refusal reach a caller who sent one request: the store clears the incumbent
//! and sets the new role in ONE transaction, which is what `PUT` on a singleton
//! means. A caller who wants to move the designation must not have to perform a read,
//! a delete and a create with a window in the middle where the organization has no
//! default at all.
//!
//! The index stays the backstop for the case a single caller cannot produce: two
//! CONCURRENT designations in one organization. The loser's insert collides, the
//! store reports it as a conflict rather than as a raw database error, and this
//! module answers a typed 409. An untyped 500 there would be a defect, and it is the
//! one thing the atomic-move choice does not remove.
//!
//! ## A DISABLED organization can still be given a default role, deliberately
//!
//! [`crate::org_context::resolve_live_org`] treats a disabled (not deleted)
//! organization as reachable, because
//! [`ironauth_store::OrganizationRepo::get`] filters `deleted_at` and does NOT filter
//! `state`. So an operator may designate a default role on an organization whose
//! members cannot currently sign in, and the designation resolves to nothing until
//! the organization is enabled again. That is the right answer and it is the same one
//! every other management write under a disabled organization already gives: enabling
//! an organization must not require the operator to then remember to re-do the
//! configuration they set up while it was down, and refusing here would make winding
//! an organization up a two-step dance the API gives no signal about. Nothing on the
//! ISSUANCE path relies on this endpoint refusing: the closure seed is the only
//! organization-liveness fence there, and it is what makes a disabled organization
//! resolve no roles at all.
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
    CorrelationId, IdempotencyWrite, NewOrgRole, OrgRoleId, OrgRoleRecord, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty, require_slug};
use crate::org_context::{parse_role_id, require_role_in_org, resolve_live_org, resolve_scope};
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
    /// Whether this role is the organization's DEFAULT role (issue #98): the role
    /// every LIVE ACTIVE member of the organization holds without an assignment
    /// existing for it. At most one live role of an organization carries `true`.
    ///
    /// It is READ ONLY on this resource. `PUT .../organizations/{organization_id}/default-role`
    /// designates and `DELETE` on the same path clears, because the designation is a
    /// property of the organization rather than of the role. A role create or a role
    /// PATCH can never set it, which is why neither request body has the field.
    ///
    /// A role holding `true` is NOT listed in any membership's direct-assignment
    /// list, because the default role is resolved at read and no row is ever written
    /// for it. It appears in the effective-role views.
    pub is_default: bool,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Last-modification time, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: i64,
}

impl OrgRoleView {
    /// Build a view from a stored record. The repository only returns LIVE (not
    /// soft-deleted) roles, so an `is_default` of `true` here always means the
    /// designation is in force.
    fn from_record(record: OrgRoleRecord) -> Self {
        Self {
            id: record.id.to_string(),
            organization_id: record.organization_id.to_string(),
            slug: record.slug,
            display_name: record.display_name,
            metadata: record.metadata,
            is_default: record.is_default,
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

/// The body to designate an organization's DEFAULT role.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SetOrgDefaultRoleRequest {
    /// The role to designate (`rol_...`). It must be a LIVE role of THIS
    /// organization; anything else (absent, deleted, another scope's, another
    /// organization's) is the uniform not-found.
    #[schema(example = "rol_...")]
    pub role_id: String,
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
        // A create can never designate: the designation is a property of the
        // ORGANIZATION and moves through its own endpoint, so a fresh role is never
        // the default and `CreateOrgRoleRequest` has no field that could say
        // otherwise.
        is_default: false,
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
    let record = require_role_in_org(&state, scope, &org_id, &role_id).await?;
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
    let record = require_role_in_org(&state, scope, &org_id, &role_id).await?;

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
    let updated = require_role_in_org(&state, scope, &org_id, &role_id).await?;
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
    let record = require_role_in_org(&state, scope, &org_id, &role_id).await?;
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_roles(scope)
        .delete(state.env(), &record.id)
        .await?;
    Ok(no_content())
}

/// DESIGNATE one of the organization's roles as its DEFAULT role.
///
/// Idempotent replacement of a single-valued property: the store clears whatever
/// role held the designation and sets it on this one in ONE transaction, so a
/// second designation MOVES it rather than being refused. Designating the role
/// that already holds it is a no-op in effect and still answers 200.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/default-role",
    operation_id = "setOrgDefaultRole",
    tag = "org-roles",
    request_body = SetOrgDefaultRoleRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The role that is now the organization's default. Every LIVE ACTIVE member resolves it at the NEXT token issuance, with NO assignment row written for any of them, so it appears in the effective-role views and in no membership's direct-assignment list", body = OrgRoleView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found: the organization, or a role that is not a live role of it (uniform across absent, deleted, another scope's, and another organization's)", body = ErrorBody),
        (status = 409, description = "A CONCURRENT designation in this organization won the race; retry. A caller sending one request cannot reach this, because a second designation moves the existing one rather than colliding with it", body = ErrorBody)
    )
)]
pub async fn set_org_default_role(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // The ADDRESS of this resource is the ORGANIZATION, and it resolves BEFORE the
    // body is parsed: a caller who cannot reach the organization must not be able to
    // tell a body this endpoint would refuse from one it would accept.
    let org_id = resolve_live_org(&state, scope, &organization_id).await?;

    let request: SetOrgDefaultRoleRequest = parse_json(&body)?;
    // Parse ONLY. Whether the id names a live role OF THIS ORGANIZATION is the
    // store's own predicate, carried inside the write transaction, so a pre-read here
    // would be a second copy of the fence and would answer a question the write then
    // asks again.
    let role = parse_role_id(&state, scope, &request.role_id)?;

    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_roles(scope)
        .set_default(state.env(), &org_id, &role)
        .await;
    match result {
        Ok(()) => {}
        Err(StoreError::Conflict) => {
            return Err(ApiError::Conflict(
                "a concurrent request is designating this organization's default \
                 role; retry"
                    .to_owned(),
            ));
        }
        Err(error) => return Err(error.into()),
    }

    // Read back through the NESTED pair address, so the response can only ever
    // describe a live role of this organization and reports the flag as STORED
    // rather than as this handler assumed it.
    let updated = require_role_in_org(&state, scope, &org_id, &request.role_id).await?;
    let body = serde_json::to_string(&OrgRoleView::from_record(updated))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// CLEAR the organization's DEFAULT role designation.
///
/// Nothing is deleted: the role stays a live role of the organization and every
/// direct and group grant of it stands. What stops is the resolution that gave it to
/// every member without a row.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/default-role",
    operation_id = "clearOrgDefaultRole",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Cleared. Members stop resolving the role through the designation at the NEXT token issuance, and keep it if some row grants it; access tokens already issued are NOT revoked (revoke the session or refresh family for that). The role itself is untouched"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (the organization, or an organization with no live default role: a repeat clear and an organization whose default role has since been deleted are the same answer)", body = ErrorBody)
    )
)]
pub async fn clear_org_default_role(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id = resolve_live_org(&state, scope, &organization_id).await?;
    // The store resolves the outgoing role IN THE SAME STATEMENT that clears it, so
    // there is nothing to name here and no second read to race against. An
    // organization with no live default matches no row and is the uniform not-found.
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_roles(scope)
        .clear_default(state.env(), &org_id)
        .await?;
    Ok(no_content())
}
