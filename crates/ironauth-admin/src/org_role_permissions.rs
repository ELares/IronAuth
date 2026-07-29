// SPDX-License-Identifier: MIT OR Apache-2.0

//! The role-to-permission MAPPING under an organization (issue #98).
//!
//! Three endpoints over `org_role_permissions`: which permissions of the
//! ENVIRONMENT'S vocabulary one ORGANIZATION'S role grants. A permission row on its
//! own is a name and a label; a mapping row is what gives that name its
//! authorization meaning, so the blast radius of one attach is the whole effective
//! member set of that role, direct and inherited alike.
//!
//! # These endpoints join two resources with DIFFERENT scopes, and that is the shape
//!
//! The two halves of a mapping do not live at the same level, and getting that
//! backwards is the structural risk on this surface:
//!
//!   * `permissions` (migration 0091) hangs off the ENVIRONMENT and carries no
//!     organization at all, because a permission names an API CAPABILITY and one
//!     string cannot sensibly mean different things to two organizations calling the
//!     same API. [`crate::permissions`] serves it and takes no organization anywhere.
//!   * `org_roles` (migration 0086) hangs off the ORGANIZATION, because a role is one
//!     organization's own vocabulary for its own members.
//!   * What varies per organization is therefore exactly WHICH permissions a role
//!     grants. That is this row, it carries the organization because the role half
//!     does, and these endpoints are nested under the organization for the same
//!     reason.
//!
//! So a request here names an organization-scoped role and an environment-scoped
//! permission, and BOTH halves have to be resolved against the caller's address
//! before anything is written. A CROSS PAIRING (a role that exists and a permission
//! that exists, presented under an organization that does not own the role, or a
//! permission of a sibling environment) is refused UNIFORMLY, so a caller cannot tell
//! which half was wrong and cannot use the difference to enumerate either vocabulary.
//!
//! # The mapping is PAIR addressed, and its own id is never on the wire
//!
//! The wire address of a mapping is `(role_id, permission_id)`, which is the pair a
//! caller already holds. The `rpm_` id exists because the table needs a primary key
//! and because it is the audit target; no route here accepts one and no response
//! shape requires a caller to keep one.
//!
//! That is what settles which store read each handler uses, and it is a constraint
//! the review of the store PR wrote down rather than a preference:
//!
//!   * [`ironauth_store::OrgRolePermissionRepo::get`] is DELIBERATELY
//!     organization-blind. Given a well-formed id of this scope it returns that
//!     mapping whatever organization the row carries, because it is the by-id read
//!     the audit target and the detach handle resolve through. A management route
//!     NESTED UNDER AN ORGANIZATION must never resolve through it: doing so would
//!     hand back, and then detach, a sibling organization's capability grant with no
//!     fence in front of it, and row-level security cannot refuse that because it
//!     fences `(tenant, environment)` and cannot see the organization.
//!   * The detach here resolves through
//!     [`ironauth_store::OrgRolePermissionRepo::get_assignment`], which carries
//!     `organization_id`, `role_id` and `permission_id` in ONE predicate, so the
//!     three are resolved TOGETHER and a pair whose halves belong to different
//!     organizations matches no row.
//!   * The list resolves the role through
//!     [`crate::org_context::require_role_in_org`] first and then reads through
//!     [`ironauth_store::OrgRolePermissionRepo::list_for_role`], which takes the
//!     organization too.
//!   * The attach resolves the ROLE through the same fenced read before it parses
//!     the body, so an unreachable role is ONE answer whatever the body says. It
//!     does NOT resolve the permission: the store resolves that as a live permission
//!     of THIS scope inside the write transaction and BEFORE any conflict reasoning,
//!     which is what keeps the duplicate-attach 409 reachable only by a caller who
//!     has already proven they can see it.
//!
//! Since no route accepts an `rpm_` id, `get` has no caller in this module at all,
//! which is the strongest form the rule can take here.
//!
//! # The ADDRESS resolves before the BODY, on every endpoint that has both
//!
//! The attach is the only endpoint here carrying a request body, and everything that
//! is part of the mapping's ADDRESS (the organization and the role) resolves before
//! that body is parsed. Otherwise a body the edge alone would refuse becomes a
//! distinguishing signal: a malformed body against a role of a sibling organization
//! would answer a 400 where a well-formed one answers the uniform 404, and a caller
//! could separate "not yours" from "does not exist" by the status. The PERMISSION is
//! not part of the address, it is what the caller is asking for, and it is refused
//! under the same uniform not-found by the store.
//!
//! # Withdrawal takes effect at the NEXT token issuance
//!
//! Detaching a permission does not revoke tokens already issued. The exposure is
//! bounded at one access-token lifetime, because the refresh grant re-resolves rather
//! than replaying a frozen set. An operator who needs immediate withdrawal must
//! revoke the session or the refresh family.
//!
//! Deleting the ROLE or the PERMISSION is NOT a detach and writes no detach audit
//! row: neither cascades to this table, and the resolution stops selecting the
//! mapping on the endpoint's own liveness filter instead. So a live mapping row does
//! not by itself mean a live grant, and the absence of a detach never means one is
//! still in force.
//!
//! # No caps
//!
//! Nothing here limits how many permissions a role may carry or how many roles may
//! carry one permission; a project covenant forbids such a cap and migration 0092
//! carries none for this module to enforce. The page size on the list is clamped like
//! every management list, which bounds ONE RESPONSE and never the number of stored
//! rows. The byte budget a later PR of this issue adds bounds ONE TOKEN, never this
//! table.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewOrgRolePermission, OrgRolePermissionId,
    OrgRolePermissionRecord, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{
    parse_permission_id, parse_role_id, require_role_in_org, resolve_live_org, resolve_scope,
};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// A permission attached to an organization's role, as returned by the management
/// API (issue #98).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgRolePermissionView {
    /// The mapping identifier (`rpm_...`). Carried for correlation with the audit
    /// log, which targets it; the mapping's ADDRESS on the wire is the
    /// `(role_id, permission_id)` pair, and no endpoint here accepts this value.
    pub id: String,
    /// The organization the ROLE belongs to (`org_...`). The permission half has no
    /// organization, because the vocabulary is per environment.
    pub organization_id: String,
    /// The role that grants the permission (`rol_...`).
    pub role_id: String,
    /// The permission granted (`prm_...`), an entry in this ENVIRONMENT's vocabulary.
    pub permission_id: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Last-modification time, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: i64,
}

impl OrgRolePermissionView {
    /// Build a view from a stored record. The repository only returns LIVE (not
    /// detached) mappings.
    fn from_record(record: &OrgRolePermissionRecord) -> Self {
        Self {
            id: record.id.to_string(),
            organization_id: record.organization_id.to_string(),
            role_id: record.role_id.to_string(),
            permission_id: record.permission_id.to_string(),
            created_at_unix_ms: record.created_at_unix_micros / 1000,
            updated_at_unix_ms: record.updated_at_unix_micros / 1000,
        }
    }
}

/// The body to attach a permission to a role.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AssignOrgRolePermissionRequest {
    /// The permission to attach (`prm_...`). It must be a LIVE permission of THIS
    /// ENVIRONMENT; anything else (absent, deleted, another environment's,
    /// malformed) is the uniform not-found. It takes no organization, because the
    /// vocabulary has none.
    #[schema(example = "prm_...")]
    pub permission_id: String,
}

/// A page of the permissions a role grants.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgRolePermissionList {
    /// The mappings on this page, oldest first. There is no cap on how many
    /// permissions a role may carry; this page is size-clamped like every list.
    ///
    /// A mapping listed here is not by itself a live grant: deleting the permission
    /// leaves the row alone and the resolution stops selecting it on the
    /// permission's own liveness filter.
    pub items: Vec<OrgRolePermissionView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Attach a permission to an organization's role.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions",
    operation_id = "assignOrgRolePermission",
    tag = "org-role-permissions",
    request_body = AssignOrgRolePermissionRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("role_id" = String, Path, description = "The role identifier (rol_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Attached. Every member who effectively holds the role, directly or through the group forest, resolves the permission at the NEXT token issuance", body = OrgRolePermissionView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found: the organization, a role that is not a live role of it, or a permission that is not a live permission of this environment (uniform across absent, deleted, another scope's, and another organization's, so a cross pairing never says which half was wrong)", body = ErrorBody),
        (status = 409, description = "The role already carries that permission", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn assign_org_role_permission(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, role_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
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

    // `resolve_live_org` is also the ENVIRONMENT-existence precondition on this path,
    // and it is why no separate `require_live_environment` call belongs here. This
    // table carries a composite foreign key to `environments`, which is the constraint
    // that turns a well-formed but absent environment into an opaque 500 on the
    // ENVIRONMENT-scoped vocabulary create. It is UNREACHABLE from here:
    // `organizations` carries the same foreign key, so an organization can only
    // resolve in an environment whose row exists, and the insert below cannot then
    // violate it. Measured rather than reasoned about, and the measurement is what
    // `an_attach_into_an_unreachable_environment_is_never_a_server_error`
    // records, including the one case that is NOT a refusal and is shared with every
    // organization-nested write in the tree.
    let org_id = resolve_live_org(&state, scope, &organization_id).await?;
    // The ROLE is resolved as a live role of THIS organization BEFORE the body is
    // parsed, and that ordering is the point rather than the read. Parsing the id
    // alone would leave the role's EXISTENCE to the store, which runs after the body,
    // so a caller naming a role of a sibling organization would get a body-shaped 400
    // for a malformed body and the uniform 404 for a well-formed one, and could
    // separate the two. Resolving here makes every unreachable role one answer
    // whatever the body says.
    //
    // The store resolves the role AGAIN inside the write transaction, and that layer
    // is kept rather than being made redundant by this one: a store caller may attach
    // with no management route in front of it at all, and `organization_id` is
    // immutable by GRANT so the two can never disagree about the pair.
    let role = require_role_in_org(&state, scope, &org_id, &role_id).await?;

    let request: AssignOrgRolePermissionRequest = parse_json(&body)?;
    // The PERMISSION is deliberately NOT resolved here, unlike the role. It is the
    // half a caller supplies in the BODY rather than in the address, and the store
    // resolves it as a live permission of this scope inside the write transaction and
    // BEFORE any conflict reasoning, which is what keeps the duplicate-attach 409
    // reachable only by a caller who has already proven they can see it.
    let permission = parse_permission_id(&state, scope, &request.permission_id)?;

    let created_at_micros = state.now_unix_micros();
    let mapping_id = OrgRolePermissionId::generate(state.env(), &scope);
    let view = OrgRolePermissionView {
        id: mapping_id.to_string(),
        organization_id: org_id.to_string(),
        role_id: role.id.to_string(),
        permission_id: permission.to_string(),
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
    // Neither endpoint is resolved here. The store resolves the role as a live role
    // of THIS organization and the permission as a live permission of THIS scope,
    // inside the audited write transaction and BEFORE any conflict reasoning, so a
    // cross pairing is the uniform not-found and the 409 is reachable only by a
    // caller who can already see both halves.
    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_role_permissions(scope)
        .assign(
            state.env(),
            NewOrgRolePermission {
                id: &mapping_id,
                organization_id: &org_id,
                role_id: &role.id,
                permission_id: &permission,
            },
            created_at_micros,
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "that permission is already attached to this role".to_owned(),
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List the permissions an organization's role grants (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions",
    operation_id = "listOrgRolePermissions",
    tag = "org-role-permissions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("role_id" = String, Path, description = "The role identifier (rol_...)"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of the permissions this role grants. A row here is not by itself a live grant: deleting the permission leaves the row and stops the resolution selecting it", body = OrgRolePermissionList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (the organization, or a role that is not a live role of it)", body = ErrorBody)
    )
)]
pub async fn list_org_role_permissions(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, role_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let org_id = resolve_live_org(&state, scope, &organization_id).await?;
    // The role is resolved as a live role of THIS organization first, so a role of a
    // sibling organization is the same 404 that reading the role itself gives, rather
    // than an empty page asserting it exists here and grants nothing. The read below
    // ALSO carries the organization, and that layering is deliberate: this one makes
    // the answer uniform, and that one makes it correct.
    let role = require_role_in_org(&state, scope, &org_id, &role_id).await?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .management()
        .org_role_permissions(scope)
        .list_for_role(&org_id, &role.id, page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = OrgRolePermissionList {
        items: rows
            .iter()
            .map(OrgRolePermissionView::from_record)
            .collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Detach a permission from an organization's role.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions/{permission_id}",
    operation_id = "unassignOrgRolePermission",
    tag = "org-role-permissions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("role_id" = String, Path, description = "The role identifier (rol_...)"),
        ("permission_id" = String, Path, description = "The permission identifier (prm_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Detached. Members holding the role stop resolving the permission at the NEXT token issuance; access tokens already issued are NOT revoked (revoke the session or refresh family for that). The pair is immediately available again, and re-attaching mints a FRESH mapping rather than reviving this one"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (no such live mapping: absent, already detached, either half in another scope, a role of another organization, or a pair whose two halves are individually visible but do not belong together)", body = ErrorBody)
    )
)]
pub async fn unassign_org_role_permission(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, role_id, permission_id)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id = resolve_live_org(&state, scope, &organization_id).await?;
    let role = parse_role_id(&state, scope, &role_id)?;
    let permission = parse_permission_id(&state, scope, &permission_id)?;

    // The PAIR is the address, and `get_assignment` resolves all three ids in ONE
    // predicate that carries `organization_id`, so a role of one organization
    // presented under another's path matches no row. This is the read the store's own
    // doc names as the one a nested route must use: the organization-blind `get`
    // would resolve the mapping by id whatever organization it belongs to, and no
    // route here even accepts that id.
    //
    // Handing the id it returns to the detach is not a check-to-use window: migration
    // 0092 grants the control role UPDATE on `updated_at` and `deleted_at` and on
    // nothing else, so a mapping's role, permission, organization, and scope are
    // immutable by GRANT and the pair cannot come apart in between. A concurrent
    // detach makes the write match no live row, which is the same not-found this read
    // would have given.
    let mapping = state
        .store()
        .management()
        .org_role_permissions(scope)
        .get_assignment(&org_id, &role, &permission)
        .await?;
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_role_permissions(scope)
        .unassign(state.env(), &org_id, &mapping.id)
        .await?;
    Ok(no_content())
}
