// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization membership CRUD under an organization (issue #94).
//!
//! Memberships are the M10 join between a user and an organization: every endpoint
//! here is nested under an organization, so it is scoped to a `(tenant,
//! environment)` pair and reachable by the operator OR by a management key scoped to
//! exactly that environment (the same authorization as the organization endpoints).
//! Containment is enforced structurally: the parent organization must exist and be
//! live, the typed [`ironauth_store::OrgMembershipId`] embeds the scope, and the
//! membership's foreign keys reject a nonexistent organization or user.
//!
//! The scope and organization resolution comes from [`crate::org_context`] rather than
//! from private copies here. This file carried its own byte-identical pair until issue
//! #411, which is exactly what the note on those copies predicted would eventually
//! matter: the write fence for a soft-deleted environment went into the ONE
//! [`crate::org_context::resolve_live_org`], and a second copy would have been three
//! endpoints silently keeping the old answer.
//!
//! Add is idempotent through the required Idempotency-Key (a replayed POST returns
//! the original response); a distinct SECOND add of a user already a member is a 409.
//! Remove is a soft deactivation: the first remove of a live membership is a 204, and
//! a repeat remove (like a remove of an absent one) is the uniform 404.
//!
//! Because remove is a soft deactivation, adding a REMOVED member back REVIVES the
//! same row, which keeps its original id, its original creation time and, when the
//! re-add supplies none, its existing metadata. The 201 therefore describes the ROW
//! the store RESOLVED and never the request this module built it from (issues #395
//! and #435): a minted id would be persisted nowhere, so every endpoint keyed on an
//! `omb_` id would answer the uniform 404 for the very identifier the create just
//! handed back, and a request-derived creation time would anchor a cursor at a value
//! no row has.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, NewMembership, OrgMembershipId, OrgMembershipRecord, ResolvedIdempotencyWrite,
    StoreError, UserId,
};

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{CreateMembershipRequest, MembershipList, MembershipView};

/// Add a user to an organization.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships",
    operation_id = "createMembership",
    tag = "organizations",
    request_body = CreateMembershipRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = MembershipView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Organization or user not found. The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 409, description = "The user is already a member", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_membership(
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

    let request: CreateMembershipRequest = parse_json(&body)?;
    // The member must be a user in THIS scope; a malformed or cross-scope id is the
    // uniform not-found (never a cross-scope existence probe). Verify it names a LIVE
    // user up front so a nonexistent user is a clean 404 rather than a foreign-key
    // 500; the membership user foreign key is the ultimate backstop.
    let user_id =
        UserId::parse_in_scope(&request.user_id, &scope).map_err(|_| ApiError::NotFound)?;
    state.store().scoped(scope).users().get(&user_id).await?;

    let created_at_micros = state.now_unix_micros();
    let membership_id = OrgMembershipId::generate(state.env(), &scope);
    // The response describes the ROW the STORE resolves, never the request that asked
    // for it (issues #395 and #435). A re-add REVIVES the removed row, and a revived
    // row keeps its ORIGINAL id, its ORIGINAL creation time, and the metadata it
    // already carried when the re-add supplies none: a response built from request
    // state names an id that was never persisted (every endpoint keyed on an `omb_`
    // id answers the uniform 404 for it, so an integrator who follows the create
    // response is stuck) and reports two fields that disagree with every read. So the
    // view is built by the SAME `from_record` every read uses, over the row the write
    // returned. This renderer is used twice, for the same reason and with the same
    // argument: once by the store, to fill the Idempotency-Key record inside the
    // write's own transaction, and once here for the 201 itself. A replay therefore
    // serves the same real resource the original create returned.
    let render = |record: &OrgMembershipRecord| {
        serde_json::to_string(&MembershipView::from_record(record.clone()))
    };

    let write = ResolvedIdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &render,
    };
    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_memberships(scope)
        .create(
            state.env(),
            NewMembership {
                id: &membership_id,
                organization_id: &org_id,
                user_id: &user_id,
                metadata: request.metadata.as_ref(),
            },
            created_at_micros,
            Some(write),
        )
        .await;

    match result {
        // The RESOLVED row: the revived one on a re-add, the freshly inserted one
        // otherwise. Rendered here exactly as it was rendered into the stored
        // idempotency record, so the 201 and its replays are the same bytes.
        Ok(resolved) => {
            let body_string = render(&resolved).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::CREATED, body_string))
        }
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "the user is already a member of this organization".to_owned(),
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List the members of an organization (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships",
    operation_id = "listMemberships",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of memberships", body = MembershipList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Organization not found", body = ErrorBody)
    )
)]
pub async fn list_memberships(
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
    let rows = state
        .store()
        .management()
        .org_memberships(scope)
        .list_for_org(&org_id, page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = MembershipList {
        items: rows.into_iter().map(MembershipView::from_record).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Remove a user from an organization (soft delete; idempotent in effect).
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}",
    operation_id = "deleteMembership",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("membership_id" = String, Path, description = "The membership identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, or already removed: a repeat delete). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn delete_membership(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, membership_id)): Path<(
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
    // The parent organization must resolve in scope (a cross-scope org path segment is
    // the uniform not-found), keeping the nested resource consistent.
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    let memberships = state.store().management().org_memberships(scope);
    let id = memberships.parse_id(&membership_id)?;
    // Enforce the NESTED resource: the membership must belong to THIS organization. A
    // membership of a DIFFERENT organization (even in the same scope) presented under
    // this org's path is the uniform not-found, so a wrong-org path can never remove
    // another organization's membership.
    let record = memberships.get(&id).await?;
    if record.organization_id != org_id {
        return Err(ApiError::NotFound);
    }
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_memberships(scope)
        .remove(state.env(), &id)
        .await?;
    Ok(no_content())
}
