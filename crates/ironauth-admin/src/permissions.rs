// SPDX-License-Identifier: MIT OR Apache-2.0

//! The permission vocabulary CRUD under an ENVIRONMENT (issue #98).
//!
//! A permission is a NAME: an immutable namespaced `slug` a later authorization
//! decision keys on and a token claim carries, plus a mutable `display_name` and
//! free-form metadata. WHICH permissions a role grants is the role-to-permission
//! mapping (the next PR of this issue), not this surface.
//!
//! # These endpoints are ENVIRONMENT level, and that is the whole design
//!
//! Every other #97 surface hangs off
//! `.../organizations/{organization_id}/...`. This one does NOT, and no handler
//! here takes an organization. `permissions` carries no `organization_id` column
//! at all (migration 0091, section (1)): a permission NAMES AN API CAPABILITY, and
//! one string cannot sensibly mean different things to two organizations calling
//! the same API. What varies per organization is which permissions a role grants,
//! and the mapping table carries the organization because ROLES are per
//! organization.
//!
//! One consequence is load bearing for this module and is the reason it is shorter
//! than [`crate::org_roles`]: the table is scoped to exactly `(tenant,
//! environment)` and to nothing finer, so the row-level-security policy IS the
//! complete fence. There is no third dimension for a statement predicate to carry,
//! so there is no cross-parent guard here to forget. The two layers that remain are
//! the ones [`crate::org_context::resolve_scope`] and the typed
//! [`ironauth_store::PermissionId`] provide: the credential must be authorized for
//! the environment the path names, and an id minted in another `(tenant,
//! environment)` fails to parse in scope and never reaches a statement.
//!
//! There is one thing the absence of a parent does NOT buy, and it is worth stating
//! because it looks at first as though it should. [`crate::org_context::resolve_scope`]
//! proves the two path segments PARSE; it does not prove the environment row exists.
//! `permissions` carries a composite foreign key to `environments`, so the CREATE
//! resolves the environment as a live row through
//! [`crate::org_context::require_live_environment`] before it writes. Without that a
//! well-formed identifier naming an environment nobody created would reach the
//! insert, violate the constraint, and come back as an opaque 500 for an input the
//! caller controls. The reads have no such check and need none: neither can reach a
//! constraint.
//!
//! # `slug` and `kind` are immutable BY GRANT, so no PATCH may name them
//!
//! Migration 0091 grants the control role `UPDATE (display_name, metadata,
//! updated_at, deleted_at)` on `permissions` and nothing else. A statement naming
//! `slug` or `kind` is therefore refused by Postgres as SQLSTATE 42501, which
//! reaches a caller as an opaque 500. Two things follow, and both are enforced
//! here rather than assumed:
//!
//!   * [`UpdatePermissionRequest`] never reaches the store with either value:
//!     [`ironauth_store::ActingPermissionRepo::update`] takes a display name and
//!     metadata and has no parameter for either immutable column.
//!   * A request that NAMES either one is refused at the edge as a typed 400 that
//!     says which field and why, instead of being silently ignored. A permission
//!     slug is a direct authorization input, so a caller who believes they renamed
//!     one and did not is worse off than a caller who is told no. This is a
//!     deliberate departure from [`crate::org_roles`], whose `UpdateOrgRoleRequest`
//!     simply has no `slug` field and lets serde drop the value.
//!
//! # The `kind` discriminator
//!
//! [`CreatePermissionRequest`] has no `kind` field, matching
//! [`ironauth_store::NewPermission`]: issue #98's code only ever writes
//! `kind = 'permission'`, which migration 0091's header states as a property of
//! this issue, and a kind-taking writer would make that prose false. Issue #103
//! widens both structs together.
//!
//! The LIST endpoint therefore serves the `permission` half of the vocabulary and
//! says so in its schema. The item GET is addressed by id, which is unique across
//! kinds, and reports the stored `kind` rather than assuming one: today no write
//! path in the tree can produce any other value, so the two agree, and when issue
//! #103 starts writing entitlements this view reports what is stored instead of
//! mislabeling it.
//!
//! # No caps
//!
//! Nothing here limits how many permissions an environment may define; a project
//! covenant forbids such a cap and migration 0091 carries none for this module to
//! enforce. The page size on the list is clamped like every management list, which
//! bounds ONE RESPONSE and never the number of stored rows. The byte budget a later
//! PR of this issue adds bounds one TOKEN, never this table.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewPermission, PermissionEntryKind, PermissionId,
    PermissionRecord, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty, require_permission_slug};
use crate::org_context::{
    parse_permission_id, require_live_environment, require_live_permission, resolve_scope,
};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// A permission-vocabulary entry, as returned by the management API (issue #98).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PermissionView {
    /// The permission identifier (`prm_...`, embeds its scope).
    pub id: String,
    /// What this row defines: `permission` (a named API capability) or, from issue
    /// #103, `entitlement`. Projected from the stored row rather than hard coded.
    /// Every row this API can create carries `permission`, because the create path
    /// binds that discriminator and issue #98 defines no entitlements.
    #[schema(example = "permission")]
    pub kind: String,
    /// The IMMUTABLE namespaced stable name. This is the string a token claim
    /// carries, so a relabel changes `display_name` and never this.
    #[schema(example = "billing.invoice.read")]
    pub slug: String,
    /// The mutable human-facing label.
    #[schema(example = "Read invoices")]
    pub display_name: String,
    /// Free-form vocabulary metadata (the empty object when none was set). Never
    /// interpreted by the auth core and never emitted in a token claim.
    pub metadata: serde_json::Value,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Last-modification time, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: i64,
}

impl PermissionView {
    /// Build a view from a stored record. The repository only returns LIVE (not
    /// soft-deleted) permissions.
    fn from_record(record: PermissionRecord) -> Self {
        Self {
            id: record.id.to_string(),
            kind: record.kind.as_str().to_owned(),
            slug: record.slug,
            display_name: record.display_name,
            metadata: record.metadata,
            created_at_unix_ms: record.created_at_unix_micros / 1000,
            updated_at_unix_ms: record.updated_at_unix_micros / 1000,
        }
    }
}

/// The body to define a permission in an environment.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreatePermissionRequest {
    /// The IMMUTABLE namespaced stable name, unique among the environment's LIVE
    /// permissions. Must match `^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$` and
    /// be at most 63 characters, so it carries two or more dot-separated segments;
    /// it is never trimmed or case folded, so a non-canonical value is refused
    /// rather than silently rewritten.
    #[schema(example = "billing.invoice.read")]
    pub slug: String,
    /// The mutable human-facing label.
    #[schema(example = "Read invoices")]
    pub display_name: String,
    /// Optional free-form vocabulary metadata; the empty object when omitted.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// The body to relabel a permission (RFC 7396 style partial edit: an omitted field
/// is left unchanged).
///
/// `slug` and `kind` appear here ONLY so that naming either is a typed 400 that
/// says which field and why. Neither is editable, and neither is forwarded to the
/// store: both are absent from the control role's `UPDATE` grant in migration 0091,
/// so a statement naming one would be refused as SQLSTATE 42501 and reach the
/// caller as an opaque 500.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdatePermissionRequest {
    /// A new human-facing label. Omitted leaves it unchanged.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Replacement free-form metadata (a whole-document replace, not a merge).
    /// Omitted leaves it unchanged.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    /// REFUSED if present: the stable name is immutable. A permission slug is a
    /// direct authorization input, so a rename under live mappings would silently
    /// repoint every grant that names it.
    #[serde(default)]
    pub slug: Option<String>,
    /// REFUSED if present: the discriminator is immutable. Reclassifying a live row
    /// would change which resolution projections select it.
    #[serde(default)]
    pub kind: Option<String>,
}

/// A page of permissions.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PermissionList {
    /// The permissions on this page, oldest first. There is no cap on how many
    /// permissions an environment may define; this page is size-clamped like every
    /// list.
    pub items: Vec<PermissionView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Refuse a partial edit that names an immutable column, naming the field and the
/// rule.
///
/// This runs AFTER the target has resolved, so a caller who cannot address the
/// permission at all still gets the uniform not-found and learns nothing from the
/// shape of their body.
///
/// # Errors
///
/// [`ApiError::BadRequest`] if the body carries `slug` or `kind`.
fn refuse_immutable_fields(request: &UpdatePermissionRequest) -> Result<(), ApiError> {
    if request.slug.is_some() {
        return Err(ApiError::BadRequest(
            "slug is immutable: a permission's stable name is an authorization input \
             and cannot be changed after it is defined"
                .to_owned(),
        ));
    }
    if request.kind.is_some() {
        return Err(ApiError::BadRequest(
            "kind is immutable: reclassifying a live permission would change which \
             resolutions select it"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Define a permission in an environment.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions",
    operation_id = "createPermission",
    tag = "permissions",
    request_body = CreatePermissionRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = PermissionView),
        (status = 400, description = "Malformed request (including a slug the namespaced stable-name rule refuses)", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Tenant or environment not found", body = ErrorBody),
        (status = 409, description = "A live permission of this environment already holds that slug", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_permission(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();

    // Replay BEFORE any body validation, so a genuine replay returns the original
    // response rather than re-deciding anything about the request.
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // The PARENT-EXISTENCE precondition, and it earns its query. `permissions` has a
    // composite foreign key to `environments`, so a well-formed identifier naming an
    // environment that does not exist (or that has been deleted) would otherwise
    // reach the INSERT, fail that constraint, and surface as an opaque 500 for an
    // input the caller controls. Resolving it here turns that into the uniform
    // not-found, which is the same answer a MALFORMED environment segment already
    // gets from `resolve_scope`, so the two are indistinguishable.
    //
    // It sits AFTER the replay for the reason `org_roles.rs` records: a genuine
    // replay must return the original response even if the parent went away
    // meanwhile. The reads need no counterpart, because neither can reach a
    // constraint: a list in an absent environment is an empty page and an
    // id-addressed read is the uniform not-found.
    require_live_environment(&state, &scope).await?;

    let request: CreatePermissionRequest = parse_json(&body)?;
    // The management edge half of the grammar. Without it a bad slug reaches
    // migration 0091's `permissions_slug_valid` CHECK and surfaces as an opaque 500.
    let slug = require_permission_slug(&request.slug, "slug")?;
    let display_name = require_non_empty(&request.display_name, "display_name")?;

    let created_at_micros = state.now_unix_micros();
    let permission_id = PermissionId::generate(state.env(), &scope);
    let view = PermissionView {
        id: permission_id.to_string(),
        // The create path writes exactly this discriminator, from the same closed
        // set the store binds into the statement.
        kind: PermissionEntryKind::Permission.as_str().to_owned(),
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
        .permissions(scope)
        .create(
            state.env(),
            NewPermission {
                id: &permission_id,
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
            "a permission of this environment already holds that slug".to_owned(),
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List an environment's permission vocabulary (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions",
    operation_id = "listPermissions",
    tag = "permissions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of permissions", body = PermissionList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Tenant or environment not found", body = ErrorBody)
    )
)]
pub async fn list_permissions(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    // The `permission` half of the vocabulary. Nothing in issue #98 writes any other
    // kind, so today this filter selects every row; it is passed explicitly because
    // `kind` is part of the live uniqueness key and issue #103 adds the other half.
    let rows = state
        .store()
        .management()
        .permissions(scope)
        .list(
            PermissionEntryKind::Permission,
            page.fetch_limit(),
            page.after(),
        )
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = PermissionList {
        items: rows.into_iter().map(PermissionView::from_record).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one permission of an environment.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions/{permission_id}",
    operation_id = "getPermission",
    tag = "permissions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("permission_id" = String, Path, description = "The permission identifier (prm_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The permission", body = PermissionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, deleted, malformed, or another scope's)", body = ErrorBody)
    )
)]
pub async fn get_permission(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, permission_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let record = require_live_permission(&state, scope, &permission_id).await?;
    let body = serde_json::to_string(&PermissionView::from_record(record))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Relabel a permission (or replace its metadata). The `slug` and `kind` are
/// immutable.
#[utoipa::path(
    patch,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions/{permission_id}",
    operation_id = "updatePermission",
    tag = "permissions",
    request_body = UpdatePermissionRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("permission_id" = String, Path, description = "The permission identifier (prm_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The updated permission", body = PermissionView),
        (status = 400, description = "Malformed request, or a body naming the immutable slug or kind", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, deleted, malformed, or another scope's)", body = ErrorBody)
    )
)]
pub async fn update_permission(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, permission_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // Address the target FIRST. An empty body supplies no mutable field, so the
    // store write is skipped entirely and this read is the only guard left; and a
    // body naming an immutable column must not be told apart from a body that does
    // not when the caller cannot address the row at all.
    let record = require_live_permission(&state, scope, &permission_id).await?;

    let request: UpdatePermissionRequest = parse_json(&body)?;
    refuse_immutable_fields(&request)?;
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
            .permissions(scope)
            .update(
                state.env(),
                &record.id,
                display_name.as_deref(),
                request.metadata.as_ref(),
            )
            .await?;
    }
    // Re-read through the SAME address, so the response can only ever describe a
    // live permission of this environment.
    let updated = require_live_permission(&state, scope, &permission_id).await?;
    let body = serde_json::to_string(&PermissionView::from_record(updated))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Delete a permission (soft delete; idempotent in effect).
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions/{permission_id}",
    operation_id = "deletePermission",
    tag = "permissions",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("permission_id" = String, Path, description = "The permission identifier (prm_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted (the slug is immediately free for a NEW permission, which gets a fresh id)"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, already deleted, malformed, or another scope's)", body = ErrorBody)
    )
)]
pub async fn delete_permission(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, permission_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // Parse only. The store's own delete resolves the row as LIVE and IN SCOPE
    // inside the write transaction and answers the same uniform not-found, so a
    // pre-read here would be a second copy of a guard the write already carries.
    let id = parse_permission_id(&state, scope, &permission_id)?;
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .permissions(scope)
        .delete(state.env(), &id)
        .await?;
    Ok(no_content())
}
