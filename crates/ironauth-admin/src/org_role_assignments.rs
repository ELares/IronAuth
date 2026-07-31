// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two role-assignment surfaces of an organization (issue #97).
//!
//! Six endpoints, three per surface, and the two surfaces are deliberately NOT
//! collapsed into one polymorphic route even though their rows are structurally
//! identical:
//!
//!   * `.../groups/{group_id}/roles` grants a role to a GROUP. It is the
//!     INHERITING surface: the grant reaches every live member of that group AND of
//!     every descendant of it, so its blast radius is not the row it writes and can
//!     change later when the tree is reshaped.
//!   * `.../memberships/{membership_id}/roles` grants a role DIRECTLY to one
//!     membership. It reaches exactly that membership and stops, and it survives
//!     every change to the group forest.
//!
//! An operator has to be able to see which of the two they are doing in the URL,
//! in the audit action, and in the effective-role provenance, because "why does
//! this person have this role" has a different answer and a different remedy in
//! each case. Two surfaces, two audit actions, one provenance vocabulary
//! ([`crate::org_effective_roles`]).
//!
//! # Pair addressing and the cross-organization pairing refusal
//!
//! Both surfaces are PAIR addressed (`.../roles/{role_id}`), never assignment-id
//! addressed: an assignment is a relationship, and the pair is the key the caller
//! already holds. The `grl_` and `mrl_` ids exist because every table needs a
//! primary key and because that id is the audit target; they are never on the wire.
//!
//! Each request therefore names THREE ids, and all three are resolved TOGETHER
//! against ONE organization: the store's `get_assignment` carries
//! `organization_id`, `group_id`/`membership_id`, and `role_id` in a single
//! predicate on the read and unassign paths, and the acting `assign` resolves both
//! endpoints as live rows of the organization inside the write transaction. Two ids
//! that are individually visible to the caller but belong to DIFFERENT
//! organizations therefore resolve to no row and are the uniform not-found; nothing
//! else would refuse that pairing, because row-level security fences
//! `(tenant, environment)` and nothing finer.
//!
//! # Withdrawal takes effect at the NEXT token issuance
//!
//! Unassigning a role does not revoke tokens already issued. The exposure is
//! bounded at one access token lifetime, because the refresh grant re-resolves the
//! effective set rather than replaying a frozen one. An operator who needs
//! immediate withdrawal must revoke the session or the refresh family. This is
//! stated on every unassign response description and in `docs/THREAT-MODEL.md`.
//!
//! # No caps
//!
//! Nothing here limits how many roles a group or a membership may hold, or how many
//! groups and memberships may hold one role. The lists are page-size clamped like
//! every management list, which bounds ONE RESPONSE and never the number of stored
//! rows.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewOrgGroupRole, NewOrgMembershipRole, OrgGroupRoleRecord,
    OrgMembershipRoleRecord, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{
    EnvironmentAccess, parse_group_id, parse_membership_id, parse_role_id, require_group_in_org,
    require_membership_in_org, resolve_live_org, resolve_scope,
};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// A role granted to a GROUP, as returned by the management API.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgGroupRoleView {
    /// The assignment identifier (`grl_...`). Carried for correlation with the
    /// audit log, which targets it; the assignment's ADDRESS on the wire is the
    /// `(group_id, role_id)` pair.
    pub id: String,
    /// The organization both endpoints belong to (`org_...`).
    pub organization_id: String,
    /// The group the role is granted to (`grp_...`). Every live member of this
    /// group and of every DESCENDANT of it resolves the role.
    pub group_id: String,
    /// The role granted (`rol_...`).
    pub role_id: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Last-modification time, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: i64,
}

impl OrgGroupRoleView {
    /// Build a view from a stored record. The repository only returns LIVE (not
    /// withdrawn) assignments.
    fn from_record(record: &OrgGroupRoleRecord) -> Self {
        Self {
            id: record.id.to_string(),
            organization_id: record.organization_id.to_string(),
            group_id: record.group_id.to_string(),
            role_id: record.role_id.to_string(),
            created_at_unix_ms: record.created_at_unix_micros / 1000,
            updated_at_unix_ms: record.updated_at_unix_micros / 1000,
        }
    }
}

/// A role granted DIRECTLY to one membership, as returned by the management API.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgMembershipRoleView {
    /// The assignment identifier (`mrl_...`). Carried for correlation with the
    /// audit log; the assignment's ADDRESS on the wire is the
    /// `(membership_id, role_id)` pair.
    pub id: String,
    /// The organization both endpoints belong to (`org_...`).
    pub organization_id: String,
    /// The membership the role is granted to (`omb_...`). Exactly this membership
    /// resolves the role; no group is involved and no descendant inherits it.
    pub membership_id: String,
    /// The role granted (`rol_...`).
    pub role_id: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Last-modification time, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: i64,
}

impl OrgMembershipRoleView {
    /// Build a view from a stored record. The repository only returns LIVE (not
    /// withdrawn) assignments.
    fn from_record(record: &OrgMembershipRoleRecord) -> Self {
        Self {
            id: record.id.to_string(),
            organization_id: record.organization_id.to_string(),
            membership_id: record.membership_id.to_string(),
            role_id: record.role_id.to_string(),
            created_at_unix_ms: record.created_at_unix_micros / 1000,
            updated_at_unix_ms: record.updated_at_unix_micros / 1000,
        }
    }
}

/// The body to grant a role to a group.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AssignOrgGroupRoleRequest {
    /// The role to grant (`rol_...`). It must be a LIVE role of THIS organization;
    /// anything else (absent, deleted, another scope's, another organization's) is
    /// the uniform not-found.
    #[schema(example = "rol_...")]
    pub role_id: String,
}

/// The body to grant a role directly to a membership.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AssignOrgMembershipRoleRequest {
    /// The role to grant (`rol_...`), under the same live-role-of-this-organization
    /// rule as the group surface.
    #[schema(example = "rol_...")]
    pub role_id: String,
}

/// A page of the roles a group grants.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgGroupRoleList {
    /// The assignments on this page, oldest first. There is no cap on how many
    /// roles a group may grant; this page is size-clamped like every list.
    pub items: Vec<OrgGroupRoleView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// A page of the roles a membership holds DIRECTLY.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgMembershipRoleList {
    /// The assignments on this page, oldest first. DIRECT grants ONLY: a role the
    /// membership resolves through a group is NOT here, by design, because this
    /// list is the set of rows an unassign on this surface can remove. The whole
    /// resolved picture, with provenance, is
    /// `GET .../memberships/{membership_id}/effective-roles`.
    pub items: Vec<OrgMembershipRoleView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Grant a role to a group (inherited by the group's members and descendants).
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/roles",
    operation_id = "assignOrgGroupRole",
    tag = "org-roles",
    request_body = AssignOrgGroupRoleRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("group_id" = String, Path, description = "The group identifier (grp_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Granted. Every live member of the group and of every descendant of it resolves the role at the NEXT token issuance", body = OrgGroupRoleView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found: the organization, the group, or the role is not a live row of this organization (uniform across absent, deleted, another scope's, and another organization's). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 409, description = "The group already holds that role", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn assign_org_group_role(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, group_id)): Path<(
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

    let org_id =
        resolve_live_org(&state, scope, &organization_id, EnvironmentAccess::Write).await?;
    let group = parse_group_id(&state, scope, &group_id)?;

    let request: AssignOrgGroupRoleRequest = parse_json(&body)?;
    let role = parse_role_id(&state, scope, &request.role_id)?;

    let created_at_micros = state.now_unix_micros();
    let assignment_id = ironauth_store::OrgGroupRoleId::generate(state.env(), &scope);
    let view = OrgGroupRoleView {
        id: assignment_id.to_string(),
        organization_id: org_id.to_string(),
        group_id: group.to_string(),
        role_id: role.to_string(),
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
    // Neither endpoint is resolved here: the store resolves both as live rows of
    // THIS organization inside the audited write transaction and BEFORE any conflict
    // reasoning, which is what keeps the 409 reachable only by a caller who can
    // already see both endpoints.
    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_group_roles(scope)
        .assign(
            state.env(),
            NewOrgGroupRole {
                id: &assignment_id,
                organization_id: &org_id,
                group_id: &group,
                role_id: &role,
            },
            created_at_micros,
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "that role is already assigned to this group".to_owned(),
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List the roles a group grants (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/roles",
    operation_id = "listOrgGroupRoles",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("group_id" = String, Path, description = "The group identifier (grp_...)"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of the roles granted to this group. Roles granted to an ANCESTOR are inherited by this group's members but are NOT listed here; they are listed on the ancestor", body = OrgGroupRoleList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (the organization, or a group that is not a live group of it)", body = ErrorBody)
    )
)]
pub async fn list_org_group_roles(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, group_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let org_id = resolve_live_org(&state, scope, &organization_id, EnvironmentAccess::Read).await?;
    // The group is resolved as a live group of THIS organization first, so a group
    // of a sibling organization is the same 404 that reading the group itself gives,
    // rather than an empty page asserting it exists here and grants nothing.
    let group = require_group_in_org(&state, scope, &org_id, &group_id).await?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .management()
        .org_group_roles(scope)
        .list_for_group(&org_id, &group, page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = OrgGroupRoleList {
        items: rows.iter().map(OrgGroupRoleView::from_record).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Withdraw a role from a group.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/roles/{role_id}",
    operation_id = "unassignOrgGroupRole",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("group_id" = String, Path, description = "The group identifier (grp_...)"),
        ("role_id" = String, Path, description = "The role identifier (rol_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Withdrawn. Members of this group and its descendants stop resolving the role at the NEXT token issuance; access tokens already issued are NOT revoked (revoke the session or refresh family for that). The pair is immediately available again"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (no such live assignment: absent, already withdrawn, another scope's, another organization's, or a pair whose two halves belong to different organizations). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn unassign_org_group_role(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, group_id, role_id)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id =
        resolve_live_org(&state, scope, &organization_id, EnvironmentAccess::Write).await?;
    let group = parse_group_id(&state, scope, &group_id)?;
    let role = parse_role_id(&state, scope, &role_id)?;

    // The PAIR is the address, and this one statement resolves all three ids
    // together, so a group of one organization paired with a role of another matches
    // no row. Handing the id it returns to the unassign below is not a
    // check-to-use window: migration 0089 grants the control role UPDATE on
    // `updated_at` and `deleted_at` and nothing else, so no reachable state moves an
    // assignment between groups, roles, organizations, or scopes after this read.
    let assignment = state
        .store()
        .management()
        .org_group_roles(scope)
        .get_assignment(&org_id, &group, &role)
        .await?;
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_group_roles(scope)
        .unassign(state.env(), &org_id, &assignment.id)
        .await?;
    Ok(no_content())
}

/// Grant a role directly to one organization membership.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/roles",
    operation_id = "assignOrgMembershipRole",
    tag = "org-roles",
    request_body = AssignOrgMembershipRoleRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("membership_id" = String, Path, description = "The organization membership identifier (omb_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Granted. Exactly this membership resolves the role at the NEXT token issuance; no group is involved and no other member inherits it", body = OrgMembershipRoleView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found: the organization, the membership, or the role is not a live row of this organization (uniform across absent, deleted, another scope's, and another organization's). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 409, description = "The membership already holds that role directly", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn assign_org_membership_role(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, membership_id)): Path<(
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

    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let org_id =
        resolve_live_org(&state, scope, &organization_id, EnvironmentAccess::Write).await?;
    let membership = parse_membership_id(&state, scope, &membership_id)?;

    let request: AssignOrgMembershipRoleRequest = parse_json(&body)?;
    let role = parse_role_id(&state, scope, &request.role_id)?;

    let created_at_micros = state.now_unix_micros();
    let assignment_id = ironauth_store::OrgMembershipRoleId::generate(state.env(), &scope);
    let view = OrgMembershipRoleView {
        id: assignment_id.to_string(),
        organization_id: org_id.to_string(),
        membership_id: membership.to_string(),
        role_id: role.to_string(),
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
        .org_membership_roles(scope)
        .assign(
            state.env(),
            NewOrgMembershipRole {
                id: &assignment_id,
                organization_id: &org_id,
                membership_id: &membership,
                role_id: &role,
            },
            created_at_micros,
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "that role is already assigned to this membership".to_owned(),
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List the roles a membership holds DIRECTLY (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/roles",
    operation_id = "listOrgMembershipRoles",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("membership_id" = String, Path, description = "The organization membership identifier (omb_...)"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of the roles granted DIRECTLY to this membership. Roles resolved through a group are NOT listed here; use the effective-roles view for the whole picture with provenance", body = OrgMembershipRoleList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (the organization, or a membership that is not a live membership of it)", body = ErrorBody)
    )
)]
pub async fn list_org_membership_roles(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, membership_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let org_id = resolve_live_org(&state, scope, &organization_id, EnvironmentAccess::Read).await?;
    // The membership is resolved as a live membership of THIS organization first,
    // for the same reason the group lists resolve their group: a membership of a
    // sibling organization is the same 404 that removing it through this path gives.
    let membership = require_membership_in_org(&state, scope, &org_id, &membership_id).await?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .management()
        .org_membership_roles(scope)
        .list_for_membership(&org_id, &membership.id, page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = OrgMembershipRoleList {
        items: rows
            .iter()
            .map(OrgMembershipRoleView::from_record)
            .collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Withdraw a role granted directly to a membership.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/roles/{role_id}",
    operation_id = "unassignOrgMembershipRole",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("membership_id" = String, Path, description = "The organization membership identifier (omb_...)"),
        ("role_id" = String, Path, description = "The role identifier (rol_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Withdrawn. The membership stops resolving the role DIRECTLY at the NEXT token issuance, and may still resolve it through a group (check the effective-roles view); access tokens already issued are NOT revoked. The pair is immediately available again"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (no such live assignment: absent, already withdrawn, another scope's, another organization's, or a pair whose two halves belong to different organizations). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn unassign_org_membership_role(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, membership_id, role_id)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id =
        resolve_live_org(&state, scope, &organization_id, EnvironmentAccess::Write).await?;
    let membership = parse_membership_id(&state, scope, &membership_id)?;
    let role = parse_role_id(&state, scope, &role_id)?;

    let assignment = state
        .store()
        .management()
        .org_membership_roles(scope)
        .get_assignment(&org_id, &membership, &role)
        .await?;
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_membership_roles(scope)
        .unassign(state.env(), &org_id, &assignment.id)
        .await?;
    Ok(no_content())
}
