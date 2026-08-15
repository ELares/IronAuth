// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization group CRUD and reparenting under an organization (issue #97).
//!
//! A group is a named, nestable container inside ONE organization. Every endpoint
//! is nested under an organization, so it is scoped to a `(tenant, environment)`
//! pair and reachable by the operator OR by a management key scoped to exactly
//! that environment, the same authorization as the organization and membership
//! endpoints.
//!
//! # Containment, and why it is in the statement here
//!
//! Row-level security fences `(tenant, environment)` and NOTHING finer, so inside
//! one environment the `organization_id` is the only thing keeping one
//! organization's groups out of another's. All three mutating repository calls
//! ([`ironauth_store::ActingOrgGroupRepo::update`], `delete`, and `reparent`)
//! take the organization and carry it as a PREDICATE, so they share ONE addressing
//! key: this layer passes the path's organization through to every one of them and
//! relies on that, rather than resolving an id-only address of its own. A rename
//! addressed from organization A can therefore never land on a group in B, which
//! is exactly the hole that shipped and was closed in the store layer.
//!
//! The reads use the same pair address through
//! [`ironauth_store::OrgGroupRepo::get_in_org`].
//!
//! # The two typed refusals, and the oracle they are not
//!
//! Reparenting is the one mutation with structural refusals: `422` for a move that
//! would close a CYCLE, and `422` for one that would nest the moved subtree past
//! `max_group_depth`. Both are informative, so both would be an existence AND
//! STRUCTURE oracle over another organization's group graph if they could be seen
//! for an id the caller cannot address. They cannot: the store resolves both
//! endpoints as LIVE groups of THIS organization under a per-organization advisory
//! lock BEFORE any structural reasoning runs, and every failure of that resolution
//! (absent, soft-deleted, foreign scope, foreign organization) is the uniform
//! not-found. This layer preserves that by passing the organization down and by
//! mapping [`ironauth_store::StoreError::NotFound`] to the same 404 every other
//! endpoint returns. Nothing here inspects a group before the store does.
//!
//! The depth message reports a FLOOR ("at least N levels"), never an exact depth:
//! both recursive walks stop one level past the bound, so against an already
//! over-deep hierarchy the number saturates. See the `From<StoreError>` arm in
//! [`crate::error`].
//!
//! # No caps
//!
//! `max_group_depth` bounds tree DEPTH, which is what makes the ancestor walk on
//! the token-issuance path terminate. It is not a cap on the NUMBER of groups: an
//! organization may define as many as it likes, at any depth level. The list's
//! page size is clamped like every management list, which bounds ONE RESPONSE and
//! never the number of stored rows.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewOrgGroup, OrgGroupId, OrgGroupRecord, OrganizationId,
    Scope, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty, require_slug};
use crate::org_context::{EnvironmentAccess, parse_group_id, resolve_live_org, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// An organization group, as returned by the management API (issue #97).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgGroupView {
    /// The group identifier (`grp_...`, embeds its scope).
    pub id: String,
    /// The organization the group belongs to (`org_...`).
    pub organization_id: String,
    /// The parent group (`grp_...`), or null for a root.
    ///
    /// It may name a group that has since been DELETED: a delete DETACHES a
    /// subtree rather than cascading, and every hierarchy walk filters deleted
    /// rows, so a child of a deleted group is treated as a root. A consumer must
    /// not assume a non-null value here resolves to a readable group.
    pub parent_id: Option<String>,
    /// The IMMUTABLE stable name. A rename changes `display_name`, never this.
    pub slug: String,
    /// The mutable human-facing label.
    pub display_name: String,
    /// Free-form group metadata (the empty object when none was set).
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Last-modification time, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: i64,
}

impl OrgGroupView {
    /// Build a view from a stored record. The repository only returns LIVE (not
    /// soft-deleted) groups.
    fn from_record(record: OrgGroupRecord) -> Self {
        Self {
            id: record.id.to_string(),
            organization_id: record.organization_id.to_string(),
            parent_id: record.parent_id.map(|parent| parent.to_string()),
            slug: record.slug,
            display_name: record.display_name,
            metadata: record.metadata,
            created_at_unix_ms: record.created_at_unix_micros / 1000,
            updated_at_unix_ms: record.updated_at_unix_micros / 1000,
        }
    }
}

/// The body to define a group in an organization.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateOrgGroupRequest {
    /// The IMMUTABLE stable name, unique among the organization's LIVE groups.
    /// Must match `^[a-z0-9][a-z0-9._-]{0,62}$`; it is never trimmed or case
    /// folded, so a non-canonical value is refused rather than silently rewritten.
    #[schema(example = "engineering")]
    pub slug: String,
    /// The mutable human-facing label.
    #[schema(example = "Engineering")]
    pub display_name: String,
    /// The parent group to nest under. Omitted or null creates a ROOT, which is
    /// always admissible. A parent that is not a LIVE group of THIS organization
    /// (absent, deleted, another scope's, another organization's) is the uniform
    /// not-found.
    #[serde(default)]
    pub parent_id: Option<String>,
    /// Optional free-form group metadata; the empty object when omitted.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<serde_json::Value>,
}

/// The body to rename a group (RFC 7396 style partial edit: an omitted field is
/// left unchanged).
///
/// `parent_id` is deliberately absent: moving a group is `PUT .../parent`, which
/// carries the cycle and depth refusals and its own audit action. Folding the two
/// together would let a plain rename silently reshape the tree.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateOrgGroupRequest {
    /// A new human-facing label. Omitted leaves it unchanged.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Replacement free-form metadata (a whole-document replace, not a merge).
    /// Omitted leaves it unchanged.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub metadata: Option<serde_json::Value>,
}

/// The body to MOVE a group within its organization's group forest.
///
/// A `PUT` replaces the whole parent relationship, so an omitted `parent_id` and
/// an explicit `null` mean the same thing: promote the group to a ROOT, which is
/// always admissible and never refused.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SetOrgGroupParentRequest {
    /// The new parent group, or null to promote this group to a root.
    #[serde(default)]
    #[schema(example = "grp_...")]
    pub parent_id: Option<String>,
}

/// A page of organization groups.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgGroupList {
    /// The groups on this page, oldest first. FLAT: every group of the
    /// organization with its `parent_id`, not a subtree, so a console renders the
    /// tree from one page sequence rather than one request per level. There is no
    /// cap on how many groups an organization may hold, at any depth level; this
    /// page is size-clamped like every list.
    pub items: Vec<OrgGroupView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Read a group through the nested `(organization, group)` pair address.
///
/// The cross-parent guard on the read side: a group of a DIFFERENT organization,
/// even in the same environment, is the uniform not-found here, exactly like an
/// absent, a soft-deleted, and a foreign-scope one.
async fn read_group_in_org(
    state: &AdminState,
    scope: Scope,
    org_id: &OrganizationId,
    group_id: &OrgGroupId,
) -> Result<OrgGroupRecord, ApiError> {
    Ok(state
        .store()
        .management()
        .org_groups(scope)
        .get_in_org(org_id, group_id)
        .await?)
}

/// Parse an optional wire `parent_id` into a typed id in scope.
///
/// A malformed value and one minted in ANOTHER `(tenant, environment)` both
/// collapse to the uniform not-found, never a 400 that would distinguish "you sent
/// nonsense" from "that group belongs to someone else". Whether the id names a
/// live group of THIS organization is decided by the store, under its
/// per-organization advisory lock, so no answer here can go stale before the write.
fn parse_optional_parent(
    state: &AdminState,
    scope: Scope,
    parent_id: Option<&str>,
) -> Result<Option<OrgGroupId>, ApiError> {
    match parent_id {
        None => Ok(None),
        Some(raw) => Ok(Some(parse_group_id(state, scope, raw)?)),
    }
}

/// Define a group in an organization, optionally nested under a parent.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups",
    operation_id = "createOrgGroup",
    tag = "org-groups",
    request_body = CreateOrgGroupRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = OrgGroupView),
        (status = 400, description = "Malformed request (including a slug the stable-name rule refuses)", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Organization not found, or the parent is not a live group of it. The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 409, description = "A live group of this organization already holds that slug", body = ErrorBody),
        (status = 422, description = "The parent would nest the group past the configured maximum depth, or the Idempotency-Key was reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_org_group(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_organizations`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
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

    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;

    let request: CreateOrgGroupRequest = parse_json(&body)?;
    let slug = require_slug(&request.slug, "slug")?;
    let display_name = require_non_empty(&request.display_name, "display_name")?;
    let parent = parse_optional_parent(&state, scope, request.parent_id.as_deref())?;

    let created_at_micros = state.now_unix_micros();
    let group_id = OrgGroupId::generate(state.env(), &scope);
    let view = OrgGroupView {
        id: group_id.to_string(),
        organization_id: org_id.to_string(),
        parent_id: parent.map(|id| id.to_string()),
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
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .org_groups(scope)
        .create(
            state.env(),
            NewOrgGroup {
                id: &group_id,
                organization_id: &org_id,
                parent_id: parent.as_ref(),
                slug: &slug,
                display_name: &display_name,
                metadata: request.metadata.as_ref(),
            },
            created_at_micros,
            state.max_group_depth(),
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "a group of this organization already holds that slug".to_owned(),
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        // Every other variant, including the typed depth refusal, goes through the
        // one central conversion. See `impl From<StoreError> for ApiError`: the
        // depth arm renders the 422 with the "at least" floor wording, and the
        // not-found arm keeps a foreign or absent parent uniform with an absent
        // organization.
        Err(error) => Err(error.into()),
    }
}

/// List an organization's groups (cursor paginated, flat with `parent_id`).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups",
    operation_id = "listOrgGroups",
    tag = "org-groups",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of groups", body = OrgGroupList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Organization not found", body = ErrorBody)
    )
)]
pub async fn list_org_groups(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    // `list_for_org` filters on organization_id, so a sibling organization's groups
    // can never appear on this page.
    let rows = state
        .store()
        .management()
        .org_groups(scope)
        .list_for_org(&org_id, page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = OrgGroupList {
        items: rows.into_iter().map(OrgGroupView::from_record).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one group of an organization.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}",
    operation_id = "getOrgGroup",
    tag = "org-groups",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("group_id" = String, Path, description = "The group identifier (grp_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The group", body = OrgGroupView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, deleted, another scope's, or another organization's)", body = ErrorBody)
    )
)]
pub async fn get_org_group(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, group_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;
    let id = parse_group_id(&state, scope, &group_id)?;
    let record = read_group_in_org(&state, scope, &org_id, &id).await?;
    let body = serde_json::to_string(&OrgGroupView::from_record(record))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Rename a group (or replace its metadata). The `slug` and the `parent_id` are
/// not editable here.
#[utoipa::path(
    patch,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}",
    operation_id = "updateOrgGroup",
    tag = "org-groups",
    request_body = UpdateOrgGroupRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("group_id" = String, Path, description = "The group identifier (grp_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The updated group", body = OrgGroupView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, deleted, another scope's, or another organization's). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn update_org_group(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, group_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_organizations`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let id = parse_group_id(&state, scope, &group_id)?;

    let request: UpdateOrgGroupRequest = parse_json(&body)?;
    let display_name = request
        .display_name
        .as_deref()
        .map(|value| require_non_empty(value, "display_name"))
        .transpose()?;
    if display_name.is_some() || request.metadata.is_some() {
        // The ORGANIZATION is passed through, so the UPDATE statement carries it as
        // a predicate: a group of a sibling organization matches no row and is the
        // uniform not-found. This is the store's own containment, not a check this
        // layer performs and then races; do not replace it with an id-only address.
        state
            .store()
            .management()
            .acting(actor, CorrelationId::generate(state.env()))
            // Attribute the audit row to this organization (issue #110).
            .in_organization(org_id)
            .org_groups(scope)
            .update(
                state.env(),
                &org_id,
                &id,
                display_name.as_deref(),
                request.metadata.as_ref(),
            )
            .await?;
    }
    // Read through the SAME pair address. On the no-op patch (no mutable field
    // supplied) this is also what makes an absent or foreign group a 404 rather
    // than a silent 200.
    let updated = read_group_in_org(&state, scope, &org_id, &id).await?;
    let body = serde_json::to_string(&OrgGroupView::from_record(updated))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// MOVE a group within its organization's group forest.
///
/// `{"parent_id": null}` (or an omitted field) promotes the group to a root, which
/// is always admissible. Any other move is subject to the cycle check and the
/// depth bound, both evaluated in the write transaction under a per-organization
/// advisory lock, so a refusal leaves the store byte-identical.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/parent",
    operation_id = "setOrgGroupParent",
    tag = "org-groups",
    request_body = SetOrgGroupParentRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("group_id" = String, Path, description = "The group identifier (grp_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The moved group", body = OrgGroupView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found: the group or the proposed parent is not a live group of this organization (uniform across absent, deleted, another scope's, and another organization's). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 422, description = "The move would close a cycle, or would nest the moved subtree past the configured maximum depth", body = ErrorBody)
    )
)]
pub async fn set_org_group_parent(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, group_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_organizations`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let id = parse_group_id(&state, scope, &group_id)?;

    let request: SetOrgGroupParentRequest = parse_json(&body)?;
    let parent = parse_optional_parent(&state, scope, request.parent_id.as_deref())?;

    // NOTHING is resolved here before the store: the store takes the advisory lock
    // FIRST and only then resolves both endpoints as live groups of this
    // organization, so a pre-read in this layer would be both redundant and stale,
    // and an early "does the parent exist" answer here is precisely the oracle the
    // ordering exists to prevent.
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .org_groups(scope)
        .reparent(
            state.env(),
            &org_id,
            &id,
            parent.as_ref(),
            state.max_group_depth(),
        )
        .await?;

    let updated = read_group_in_org(&state, scope, &org_id, &id).await?;
    let body = serde_json::to_string(&OrgGroupView::from_record(updated))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Delete a group (soft delete; idempotent in effect). Its children are DETACHED,
/// not deleted: each becomes a root.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}",
    operation_id = "deleteOrgGroup",
    tag = "org-groups",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("group_id" = String, Path, description = "The group identifier (grp_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted (children detached to roots; the slug is immediately free for a new group)"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, already deleted, another scope's, or another organization's). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn delete_org_group(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, group_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_organizations`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let id = parse_group_id(&state, scope, &group_id)?;
    // The organization rides into the DELETE statement as a predicate: a group of a
    // sibling organization matches no row, is the uniform not-found, and is not
    // deleted.
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .org_groups(scope)
        .delete(state.env(), &org_id, &id)
        .await?;
    Ok(no_content())
}
