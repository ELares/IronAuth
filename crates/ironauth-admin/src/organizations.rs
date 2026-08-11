// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization CRUD under an environment (issue #41).
//!
//! Organizations are the fourth level of the resource model: they live inside an
//! environment, so every endpoint here is scoped to a `(tenant, environment)`
//! pair and is reachable by the operator OR by a management key scoped to exactly
//! that environment (the same authorization as environment reads). Containment is
//! enforced on create: the parent environment must exist and be live, and the
//! typed [`ironauth_store::OrganizationId`] embeds the scope so a foreign id
//! collapses to the uniform not-found rather than leaking existence.
//!
//! Delete is a soft deactivation, idempotent IN EFFECT per RFC 9110: the row is
//! retained so the `organization.delete` audit row's target stays resolvable (an
//! application rule: `audit_log` carries no foreign key to `organizations`), and a live
//! organization is deactivated and reads as absent thereafter, exactly as tenants and
//! environments behave. A soft-deleted organization reads as absent (get is a 404), so
//! the delete's STATUS CODE is not itself idempotent: the first delete of a live
//! organization is a 204, and a repeat delete of an already-deactivated organization,
//! like a delete of an absent one, is the uniform
//! 404. That anti-oracle 404 is the same not-found the get returns, so delete never
//! discloses whether a not-found id was once live.
//!
//! Scope and organization resolution come from [`crate::org_context`] rather than from
//! private copies here. The three WRITES (`delete`, `disable`, `enable`) address their
//! organization through [`crate::org_context::resolve_live_org`] with
//! [`crate::org_context::EnvironmentAccess::Write`], which is what puts them behind the same
//! soft-deleted-environment fence as every write nested under an organization (issue
//! #411), and `get` addresses its organization through the same function with
//! [`crate::org_context::EnvironmentAccess::Read`], which deliberately does NOT carry the fence:
//! a decommissioned environment stays auditable. `list` addresses no organization at
//! all, so it resolves only the scope.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, OrganizationId, OrganizationRecord, OrganizationState,
    ResolvedIdempotencyWrite, StoreError,
};

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::org_context::{EnvironmentAccess, resolve_live_org, resolve_scope};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{CreateOrganizationRequest, OrganizationList, OrganizationView};

/// Create an organization under an environment.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations",
    operation_id = "createOrganization",
    tag = "organizations",
    request_body = CreateOrganizationRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = OrganizationView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_organization(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_organizations`.
    // An UNRESTRICTED credential (every key minted before migration 0118) passes
    // unchanged; this only binds a credential someone deliberately restricted.
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();

    // Replay BEFORE the parent-existence precondition, so a genuine replay returns
    // the original response even if the environment was soft-deleted meanwhile.
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // Containment: the parent environment must exist and be live. A foreign or
    // soft-deleted environment reads as a uniform not-found (the tenant filter is
    // the anti-oracle), never a foreign-key error.
    //
    // This used to be an inline copy of the two-line read. It is the shared
    // [`crate::org_context::require_live_environment`] now, which is the same function
    // the writes nested UNDER an organization reach through `resolve_live_org` (issue
    // #411): a create that refused a deleted environment while every nested write
    // accepted one was half of the split this issue closed, and one copy of the check
    // is what keeps the halves from drifting apart again.
    crate::org_context::require_live_environment(&state, &scope).await?;

    let request: CreateOrganizationRequest = parse_json(&body)?;
    let display_name = require_non_empty(&request.display_name, "display_name")?;

    let created_at_micros = state.now_unix_micros();
    let organization_id = OrganizationId::generate(state.env(), &scope);
    let view = OrganizationView {
        id: organization_id.to_string(),
        tenant_id: scope.tenant().to_string(),
        environment_id: scope.environment().to_string(),
        display_name: display_name.clone(),
        active: true,
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
        .organizations(scope)
        .create(
            state.env(),
            &organization_id,
            created_at_micros,
            &display_name,
            Some(write),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List organizations under an environment (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations",
    operation_id = "listOrganizations",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of organizations", body = OrganizationList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_organizations(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential (every key minted before migration 0118) passes
    // unchanged; this only binds a credential someone deliberately restricted.
    principal.require_permission(ManagementPermission::Read)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;

    // Confinement narrows the LIST, not just the per-resource read (issue #102).
    //
    // A sibling organization answers the uniform not-found on `getOrganization` so that a
    // confined caller cannot learn whether it exists. An unfiltered list hands over every
    // organization's id and display name in ONE call, which makes that fence decorative:
    // the enumeration it prevents is available one endpoint over. Criterion 2 says
    // "cannot list, read, or mutate", and the list is the half a per-resource guard
    // cannot cover.
    //
    // A confined credential's list is therefore exactly its own organization, or EMPTY
    // when that organization is no longer live. Empty rather than not-found, because the
    // collection itself is reachable: the caller is asking what it may administer, and
    // the answer is legitimately "nothing right now".
    if let Some(confined) = principal.confined_organization() {
        let own = state
            .store()
            .management()
            .organizations(scope)
            .get(confined)
            .await;
        let items = match own {
            Ok(record) => vec![OrganizationView::from_record(record)],
            Err(StoreError::NotFound) => Vec::new(),
            Err(_) => return Err(ApiError::Internal),
        };
        let list = OrganizationList {
            items,
            // No cursor: the page is complete by construction, and emitting one would
            // invite a follow-up call that could only ever return the same single row.
            next_cursor: None,
        };
        let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
        return Ok(json(StatusCode::OK, body));
    }

    let rows = state
        .store()
        .management()
        .organizations(scope)
        .list(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = OrganizationList {
        items: rows
            .into_iter()
            .map(OrganizationView::from_record)
            .collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one organization.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}",
    operation_id = "getOrganization",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The organization", body = OrganizationView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody)
    )
)]
pub async fn get_organization(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential (every key minted before migration 0118) passes
    // unchanged; this only binds a credential someone deliberately restricted.
    principal.require_permission(ManagementPermission::Read)?;
    // Addressed through the shared resolution like every other route under this prefix
    // (issue #411), with [`EnvironmentAccess::Read`]: a decommissioned environment stays
    // auditable, so this read is deliberately NOT behind the environment fence. It
    // replaces an inline `parse_id` then `get` that was byte-identical to the helper's
    // body, which is the copy the module note above says does not exist here.
    //
    // The cost is one extra read of the same row: the helper proves the organization is
    // live and hands back only its id, and the projection below needs the record. That
    // is paid deliberately, because the alternative is the private copy this change
    // exists to remove.
    let id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Read,
    )
    .await?;
    let record = state
        .store()
        .management()
        .organizations(scope)
        .get(&id)
        .await?;
    let body = serde_json::to_string(&OrganizationView::from_record(record))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Deactivate an organization (soft delete; idempotent in effect).
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}",
    operation_id = "deleteOrganization",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deactivated"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, or already deactivated: a repeat delete). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn delete_organization(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_organizations`.
    // An UNRESTRICTED credential (every key minted before migration 0118) passes
    // unchanged; this only binds a credential someone deliberately restricted.
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // Addressed through the SAME resolution every other organization-nested write uses
    // (issue #411), which is what puts this route behind the one environment fence
    // instead of beside it. It replaces a bare `parse_id`, so it adds a read of the
    // organization that the delete below would have performed as its own predicate
    // anyway: a soft-deleted organization was already the uniform not-found from the
    // delete's zero-row result and is now the same not-found from this read.
    let id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(id)
        .organizations(scope)
        .delete(state.env(), &id)
        .await?;
    Ok(no_content())
}

/// Set an organization's lifecycle state (issue #94): the shared body of the enable
/// and disable actions. Resolves and authorizes the scope, gates on fresh privilege,
/// parses the organization id in scope, and audits the state change.
/// The request shape both organization state toggles share, grouped so the helper
/// stays inside the argument budget as it gained the idempotency extractors.
struct StateToggle<'a> {
    tenant_id: &'a str,
    environment_id: &'a str,
    organization_id: &'a str,
    target: OrganizationState,
    uri: &'a Uri,
    headers: &'a HeaderMap,
}

async fn set_organization_state(
    state: &AdminState,
    principal: &Principal,
    toggle: StateToggle<'_>,
) -> Result<Response, ApiError> {
    let StateToggle {
        tenant_id,
        environment_id,
        organization_id,
        target,
        uri,
        headers,
    } = toggle;
    let (scope, actor) = resolve_scope(state, principal, tenant_id, environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_organizations`.
    // Enforced in the SHARED body rather than in `disable_organization` and
    // `enable_organization` separately: two copies of one rule is one place to forget it,
    // and a third state added later would inherit the check for free.
    principal.require_permission(ManagementPermission::WriteOrganizations)?;
    crate::sudo::require_fresh_privilege(state, scope, actor).await?;
    // The same shared resolution the delete above uses (issue #411). It replaces a bare
    // `parse_id`, and the read it adds is one this handler already performed at the end
    // to render the response, so a soft-deleted organization answered the uniform
    // not-found before this line existed and answers it here now.
    let id = resolve_live_org(
        state,
        principal,
        scope,
        organization_id,
        EnvironmentAccess::Write,
    )
    .await?;

    // The Idempotency-Key gate (issue #345's sweep). Both toggles are naturally
    // idempotent, so this is not a data-safety fix: it is what makes a retry after a
    // network timeout return the ORIGINAL response rather than re-deriving one, which is
    // the convention every other admin state mutation follows.
    //
    // These routes take no request body, so the fingerprint is over an empty one. That
    // still binds the key to the method and PATH, so the same key reused against a
    // different organization, or against the opposite toggle, is the 422 rather than a
    // replay of the wrong answer.
    let key = idempotency::required_key(headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // The body is rendered from what the write RESOLVED, inside its own transaction,
    // rather than from a second read taken afterwards. That read used to be how this
    // handler learned the new state; taking the row from the UPDATE's RETURNING instead
    // means the response describes the state this request committed, and the stored
    // idempotent body is byte-identical to it by construction.
    let render = |resolved: &OrganizationRecord| {
        serde_json::to_string(&OrganizationView::from_record(resolved.clone()))
    };
    let record = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110). In the SHARED body,
        // for the reason the permission check is here: two copies of one rule is one
        // place to forget it, and enable and disable must not disagree about whose event
        // this is.
        .in_organization(id)
        .organizations(scope)
        .set_state(
            state.env(),
            &id,
            target,
            Some(ResolvedIdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &render,
            }),
        )
        .await?;
    let body = serde_json::to_string(&OrganizationView::from_record(record))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Disable an organization (issue #94). The organization stays readable (this is not
/// a soft delete) but is marked disabled; the login-time enforcement is a later PR.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/disable",
    operation_id = "disableOrganization",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The disabled organization", body = OrganizationView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found. The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn disable_organization(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    set_organization_state(
        &state,
        &principal,
        StateToggle {
            tenant_id: &tenant_id,
            environment_id: &environment_id,
            organization_id: &organization_id,
            target: OrganizationState::Disabled,
            uri: &uri,
            headers: &headers,
        },
    )
    .await
}

/// Re-enable a disabled organization (issue #94).
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/enable",
    operation_id = "enableOrganization",
    tag = "organizations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The enabled organization", body = OrganizationView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found. The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn enable_organization(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    set_organization_state(
        &state,
        &principal,
        StateToggle {
            tenant_id: &tenant_id,
            environment_id: &environment_id,
            organization_id: &organization_id,
            target: OrganizationState::Active,
            uri: &uri,
            headers: &headers,
        },
    )
    .await
}
