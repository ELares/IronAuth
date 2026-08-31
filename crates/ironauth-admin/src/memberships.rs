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
use crate::views::{
    CreateMembershipRequest, CreateServiceAccountMembershipRequest, MembershipList, MembershipView,
    ServiceAccountMembershipView,
};

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
    let delta = membership_delta_event(
        &state,
        scope,
        &org_id,
        vec![user_id.to_string()],
        Vec::new(),
    );
    let pending = membership_event(
        &state,
        scope,
        &membership_id,
        &org_id,
        &user_id,
        "organization.member_added",
    );
    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .org_memberships(scope)
        .create_with_event(
            state.env(),
            NewMembership {
                id: &membership_id,
                organization_id: &org_id,
                user_id: &user_id,
                metadata: request.metadata.as_ref(),
            },
            created_at_micros,
            Some(write),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
            delta
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
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

/// Add a MACHINE IDENTITY to an organization (issue #126).
///
/// Its own route rather than a variant of `createMembership`, because both the request and the
/// response would otherwise have to make `user_id` optional -- and relaxing a required
/// property is breaking for every consumer already decoding it.
///
/// This is the granting path for a capability the store has modelled since issue #99:
/// `MembershipPrincipal::ServiceAccount`, `create_for_service_account` and
/// `effective_permissions_for_service_account` all existed, AuthZEN read them, and the only
/// callers of the creator anywhere were two test files. So a machine identity could hold roles
/// in principle and could be given none in practice.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/service-account-memberships",
    operation_id = "createServiceAccountMembership",
    tag = "organizations",
    request_body = CreateServiceAccountMembershipRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = ServiceAccountMembershipView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Organization or machine identity not found. The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 409, description = "The machine identity is already a member", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_service_account_membership(
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
    // Granting an identity a place in an organization is granting it whatever roles that
    // organization attaches, so it is the class of change sudo mode exists for.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();

    // Replay BEFORE the parent-existence precondition, so a genuine replay returns the
    // original response even if the organization was disabled meanwhile.
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

    let request: CreateServiceAccountMembershipRequest = parse_json(&body)?;
    // The identity must exist in THIS scope; a malformed or cross-scope id is the uniform
    // not-found, never a cross-scope existence probe. Checked up front so an absent identity
    // is a clean 404 rather than a foreign-key 500.
    let service_account_id =
        ironauth_store::ServiceAccountId::parse_in_scope(&request.service_account_id, &scope)
            .map_err(|_| ApiError::NotFound)?;
    if !state
        .store()
        .scoped(scope)
        .service_accounts()
        .exists(&service_account_id)
        .await?
    {
        return Err(ApiError::NotFound);
    }

    let created_at_micros = state.now_unix_micros();
    let membership_id = ironauth_store::OrgMembershipId::generate(state.env(), &scope);
    // The response describes the ROW THE STORE RESOLVES, never the request: a re-add revives
    // the removed row, which keeps its original id, creation time and metadata. Same renderer
    // for the 201 and for the stored idempotency record, so a replay serves the same bytes.
    let render = |record: &ironauth_store::ServiceAccountMembershipRecord| {
        serde_json::to_string(&ServiceAccountMembershipView::from_record(record.clone()))
    };
    let write = ResolvedIdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &render,
    };
    let pending = service_account_membership_event(
        &state,
        scope,
        &membership_id,
        &org_id,
        &service_account_id,
    );

    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .org_memberships(scope)
        .create_for_service_account_with_event(
            state.env(),
            ironauth_store::NewServiceAccountMembership {
                id: &membership_id,
                organization_id: &org_id,
                service_account_id: &service_account_id,
                metadata: request.metadata.as_ref(),
            },
            created_at_micros,
            Some(write),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;

    match result {
        Ok(resolved) => {
            let body_string = render(&resolved).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::CREATED, body_string))
        }
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "the machine identity is already a member of this organization".to_owned(),
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// The event a machine identity LEAVING an organization emits (issue #126).
fn service_account_membership_removed_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    membership_id: &ironauth_store::OrgMembershipId,
    organization_id: &ironauth_store::OrganizationId,
    service_account_id: &ironauth_store::ServiceAccountId,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = membership_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "organization.service_account_removed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "membership_id": subject,
            "organization_id": organization_id.to_string(),
            "service_account_id": service_account_id.to_string(),
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The event a machine identity joining an organization emits (issue #126).
fn service_account_membership_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    membership_id: &ironauth_store::OrgMembershipId,
    organization_id: &ironauth_store::OrganizationId,
    service_account_id: &ironauth_store::ServiceAccountId,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = membership_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "organization.service_account_added",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "membership_id": subject,
            "organization_id": organization_id.to_string(),
            "service_account_id": service_account_id.to_string(),
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
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
    // EITHER PRINCIPAL KIND. `get` reads user memberships only, and `get_service_account`
    // reads the other, so resolving with just the first made a machine identity's membership
    // a ONE-WAY DOOR: creatable through `createServiceAccountMembership` and removable by
    // nothing. Measured, before this branch: the DELETE answered the uniform not-found.
    //
    // The store's `remove` never needed changing -- it matches on the membership id alone and
    // its own comment records that decoding `user_id` as a String once broke exactly this. It
    // was the ADDRESSING read in front of it that only knew about people.
    let (delta, pending) = match memberships.get(&id).await {
        Ok(record) => {
            if record.organization_id != org_id {
                return Err(ApiError::NotFound);
            }
            (
                membership_delta_event(
                    &state,
                    scope,
                    &org_id,
                    Vec::new(),
                    vec![record.user_id.to_string()],
                ),
                membership_event(
                    &state,
                    scope,
                    &id,
                    &org_id,
                    &record.user_id,
                    "organization.member_removed",
                ),
            )
        }
        Err(StoreError::NotFound) => {
            let record = memberships.get_service_account(&id).await?;
            if record.organization_id != org_id {
                return Err(ApiError::NotFound);
            }
            // NO DELTA EVENT. `organization.membership_delta` carries user ids, and a
            // machine identity is not one; inventing a shape for it here would put a value
            // in that field no consumer's schema expects.
            (
                None,
                service_account_membership_removed_event(
                    &state,
                    scope,
                    &id,
                    &org_id,
                    &record.service_account_id,
                ),
            )
        }
        Err(other) => return Err(other.into()),
    };
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .org_memberships(scope)
        .remove_with_event(
            state.env(),
            &id,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
            delta
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// The event an organization membership change emits (issue #108).
///
/// ONE builder for the add and the remove, because a membership is a JOIN and both facts need
/// the same two ends. The TYPES stay separate: an integrator PROVISIONS on one and
/// DEPROVISIONS on the other, and collapsing them would make the most consequential
/// distinction in the pair a field to branch on.
///
/// No role and no traits. A membership's role is changed through its own surface and
/// announced there, so folding it in here would make this event go stale the moment a role
/// moves without the membership changing.
fn membership_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    membership_id: &ironauth_store::OrgMembershipId,
    organization_id: &ironauth_store::OrganizationId,
    user_id: &ironauth_store::UserId,
    event_type: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = membership_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "membership_id": subject,
            "organization_id": organization_id.to_string(),
            "user_id": user_id.to_string(),
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The membership DELTA event (issue #107's criterion, issue #108's registry): the same
/// change as `organization.member_added`/`member_removed`, expressed as the added/removed
/// arrays a data-sync consumer applies, with the cap and truncation contract.
///
/// Both forms are emitted, in one transaction, because they answer different questions. The
/// per-member type says WHO changed, once, and is what an integrator deprovisioning a single
/// person subscribes to. This one says what the SET did, and is what a mirror applies -- and
/// it is the only one that can ever say "I could not fit it all, go and reconcile".
///
/// A single-member route produces a Complete delta of one id, which is not a degenerate case
/// but the contract holding at n=1: the cap and the truncation flag mean the same thing at
/// every size, so a consumer writes one code path rather than two. The truncation branch
/// engages when a bulk path exceeds the cap, and needs no new type when it lands.
///
/// The cap decision is NOT re-derived here. It comes from
/// `ironauth_store::membership_change`, which is where issue #107 put it, so there is one
/// expression of the rule rather than a copy per producer.
fn membership_delta_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    organization_id: &ironauth_store::OrganizationId,
    added: Vec<String>,
    removed: Vec<String>,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let change = ironauth_store::membership_change(added, removed);
    let mut payload = crate::events::membership_delta_payload(&change);
    let subject = organization_id.to_string();
    payload["organization_id"] = serde_json::json!(subject);
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "organization.membership_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        // The ORGANIZATION is the subject: every membership change to one organization stays
        // ordered, which is what lets a consumer apply them as a sequence of deltas at all.
        subject,
        envelope,
    })
}
