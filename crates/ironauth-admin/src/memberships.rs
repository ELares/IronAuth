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
//! Add is idempotent through the required Idempotency-Key (a replayed POST returns
//! the original response); a distinct SECOND add of a user already a member is a 409.
//! Remove is a soft deactivation: the first remove of a live membership is a 204, and
//! a repeat remove (like a remove of an absent one) is the uniform 404.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewMembership, OrgMembershipId, OrganizationId, Scope,
    StoreError, UserId,
};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{CreateMembershipRequest, MembershipList, MembershipView};

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
    // A soft-deleted or absent organization is the uniform not-found.
    organizations.get(&id).await?;
    Ok(id)
}

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
        (status = 404, description = "Organization or user not found", body = ErrorBody),
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
    let metadata = request
        .metadata
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));
    let view = MembershipView {
        id: membership_id.to_string(),
        organization_id: org_id.to_string(),
        user_id: user_id.to_string(),
        state: "active".to_owned(),
        metadata: metadata.clone(),
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
        Ok(_) => Ok(json(StatusCode::CREATED, body_string)),
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
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let org_id = resolve_live_org(&state, scope, &organization_id).await?;
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
        (status = 404, description = "Not found (absent, or already removed: a repeat delete)", body = ErrorBody)
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
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // The parent organization must resolve in scope (a cross-scope org path segment is
    // the uniform not-found), keeping the nested resource consistent.
    let _org_id = resolve_live_org(&state, scope, &organization_id).await?;
    let id = state
        .store()
        .management()
        .org_memberships(scope)
        .parse_id(&membership_id)?;
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        .org_memberships(scope)
        .remove(state.env(), &id)
        .await?;
    Ok(no_content())
}
