// SPDX-License-Identifier: MIT OR Apache-2.0

//! Binding organization memberships into organization groups (issue #97).
//!
//! Three endpoints under `.../organizations/{organization_id}/groups/{group_id}/members`:
//! add a member, list a group's members, and remove one. They inherit the
//! authorization of every other endpoint nested under an organization (the
//! operator, or a management key scoped to exactly that environment), resolved
//! once in [`crate::org_context`].
//!
//! A binding names an org MEMBERSHIP (`omb_`), never a bare user. Being in a group
//! therefore presupposes being in the organization, structurally rather than by
//! convention, and there is no way to express "in a group of an organization I am
//! not a member of".
//!
//! # Pair addressing, and the three ids that must agree
//!
//! A binding is a RELATIONSHIP, so its wire address is the pair the caller already
//! holds (`.../groups/{group_id}/members/{membership_id}`), not the `gmb_` id the
//! row carries for the audit log. Every request therefore names THREE ids: the
//! organization, the group, and the membership. All three are resolved TOGETHER,
//! never one at a time:
//!
//!   * the organization by [`crate::org_context::resolve_live_org`];
//!   * the group and the membership by the store, inside ONE statement that carries
//!     `organization_id` as a predicate
//!     ([`ironauth_store::OrgGroupMemberRepo::get_binding`] on the read and remove
//!     paths, and the two `require_live_*_in_org` resolutions inside the audited
//!     write transaction on the add path).
//!
//! That is what refuses a cross-organization PAIRING: two ids that are each
//! individually visible to the caller, but that belong to DIFFERENT organizations,
//! resolve to no row and are the uniform not-found. Row-level security fences
//! `(tenant, environment)` and nothing finer, so nothing else would.
//!
//! # No caps
//!
//! Nothing here limits how many members a group may hold or how many groups a
//! membership may join. The list's page size is clamped like every management list,
//! which bounds ONE RESPONSE and never the number of stored rows.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewOrgGroupMember, OrgGroupMemberRecord, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{
    EnvironmentAccess, parse_group_id, parse_membership_id, require_group_in_org, resolve_live_org,
    resolve_scope,
};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One membership's binding into one group, as returned by the management API.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgGroupMemberView {
    /// The binding identifier (`gmb_...`). Carried for correlation with the audit
    /// log, which targets it; the binding's ADDRESS on the wire is the
    /// `(group_id, membership_id)` pair, not this.
    pub id: String,
    /// The organization both endpoints belong to (`org_...`).
    pub organization_id: String,
    /// The group the membership is bound into (`grp_...`).
    pub group_id: String,
    /// The organization membership bound into the group (`omb_...`), never a bare
    /// user id.
    pub membership_id: String,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
    /// Last-modification time, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: i64,
}

impl OrgGroupMemberView {
    /// Build a view from a stored record. The repository only returns LIVE (not
    /// removed) bindings.
    fn from_record(record: &OrgGroupMemberRecord) -> Self {
        Self {
            id: record.id.to_string(),
            organization_id: record.organization_id.to_string(),
            group_id: record.group_id.to_string(),
            membership_id: record.membership_id.to_string(),
            created_at_unix_ms: record.created_at_unix_micros / 1000,
            updated_at_unix_ms: record.updated_at_unix_micros / 1000,
        }
    }
}

/// The body to bind a membership into a group.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AddOrgGroupMemberRequest {
    /// The organization membership to bind (`omb_...`), NOT a user id. It must be a
    /// LIVE membership of THIS organization; anything else (absent, removed,
    /// another scope's, another organization's) is the uniform not-found.
    #[schema(example = "omb_...")]
    pub membership_id: String,
}

/// A page of a group's members.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OrgGroupMemberList {
    /// The bindings on this page, oldest first. There is no cap on how many members
    /// a group may hold; this page is size-clamped like every list.
    pub items: Vec<OrgGroupMemberView>,
    /// The opaque cursor for the next page, or null if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Bind an organization membership into a group.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/members",
    operation_id = "addOrgGroupMember",
    tag = "org-groups",
    request_body = AddOrgGroupMemberRequest,
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
        (status = 201, description = "Bound", body = OrgGroupMemberView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found: the organization, the group, or the membership is not a live row of this organization (uniform across absent, deleted, another scope's, and another organization's). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 409, description = "The membership is already a live member of this group", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn add_org_group_member(
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
    let group = parse_group_id(&state, scope, &group_id)?;

    let request: AddOrgGroupMemberRequest = parse_json(&body)?;
    let membership = parse_membership_id(&state, scope, &request.membership_id)?;

    let created_at_micros = state.now_unix_micros();
    let binding_id = ironauth_store::OrgGroupMemberId::generate(state.env(), &scope);
    let view = OrgGroupMemberView {
        id: binding_id.to_string(),
        organization_id: org_id.to_string(),
        group_id: group.to_string(),
        membership_id: membership.to_string(),
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
    // NEITHER endpoint is resolved here as a PRECONDITION of the write. The store resolves both as
    // live rows of THIS organization INSIDE the audited write transaction and BEFORE
    // any conflict reasoning, so a pre-read here would be redundant, would be stale
    // by the time the write ran, and would answer "does that group exist" a request
    // early: the ordering is what keeps the 409 reachable only by a caller who has
    // already proved they can see both endpoints.
    // THE ARRAYS CARRY USER IDS, so the membership is resolved to the person it binds. A
    // membership id in a field the schema names `added_user_ids` is what every producer of this
    // type used to send, and a consumer resolving it as a user found nothing.
    //
    // A MISS BUILDS NO EVENT AND CHANGES NO RESPONSE. The store resolves both endpoints inside
    // its own write transaction and answers the authoritative not-found; this read only decides
    // whether an event can be built, so the ordering the comment above preserves is intact and
    // an absent membership announces nothing rather than announcing a guess.
    let delta =
        group_membership_delta_for(&state, scope, &group, &org_id, &membership, true).await?;
    let pending = org_group_member_event(
        &state,
        scope,
        &group,
        &org_id,
        &membership,
        "org_group.member_added",
    );
    let result = state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .org_group_members(scope)
        .add_with_event(
            state.env(),
            NewOrgGroupMember {
                id: &binding_id,
                organization_id: &org_id,
                group_id: &group,
                membership_id: &membership,
                source_scim_connection_id: None,
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
        Ok(()) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "that membership is already a member of this group".to_owned(),
        )),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// List a group's members (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/members",
    operation_id = "listOrgGroupMembers",
    tag = "org-groups",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("group_id" = String, Path, description = "The group identifier (grp_...)"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of group members", body = OrgGroupMemberList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (the organization, or a group that is not a live group of it)", body = ErrorBody)
    )
)]
pub async fn list_org_group_members(
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
    // The group is resolved as a LIVE group of THIS organization before the page is
    // read, so listing the members of a group of a SIBLING organization is the same
    // 404 that reading the group itself gives, rather than a 200 with an empty page
    // that would assert the group exists here and is empty.
    let group = require_group_in_org(&state, scope, &org_id, &group_id).await?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .management()
        .org_group_members(scope)
        .list_for_group(&org_id, &group, page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = OrgGroupMemberList {
        items: rows.iter().map(OrgGroupMemberView::from_record).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Unbind a membership from a group (soft delete; a repeat remove is the uniform
/// 404).
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/members/{membership_id}",
    operation_id = "removeOrgGroupMember",
    tag = "org-groups",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("group_id" = String, Path, description = "The group identifier (grp_...)"),
        ("membership_id" = String, Path, description = "The organization membership identifier (omb_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Removed (the pair is immediately available again)"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (no such live binding: absent, already removed, another scope's, another organization's, or a pair whose two halves belong to different organizations). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn remove_org_group_member(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, group_id, membership_id)): Path<(
        String,
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
    let group = parse_group_id(&state, scope, &group_id)?;
    let membership = parse_membership_id(&state, scope, &membership_id)?;

    // The PAIR is the address, and this one statement resolves all three ids
    // together: a group of one organization paired with a membership of another
    // matches no row and is the uniform not-found. Feeding the id it returns to the
    // remove below is not a check-to-use window, because migration 0088 grants the
    // control role UPDATE on `updated_at` and `deleted_at` and nothing else, so no
    // reachable state moves a binding between groups, memberships, organizations, or
    // scopes after this read.
    let binding = state
        .store()
        .management()
        .org_group_members(scope)
        .get_binding(&org_id, &group, &membership)
        .await?;
    // The organization rides into the UPDATE as a predicate as well, so the write is
    // fenced independently of the read that addressed it.
    let delta = group_membership_delta_for(
        &state,
        scope,
        &binding.group_id,
        &org_id,
        &binding.membership_id,
        false,
    )
    .await?;
    let pending = org_group_member_event(
        &state,
        scope,
        &binding.group_id,
        &org_id,
        &binding.membership_id,
        "org_group.member_removed",
    );
    state
        .store()
        .management()
        .acting(actor, CorrelationId::generate(state.env()))
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .org_group_members(scope)
        .remove_with_event(
            state.env(),
            &org_id,
            &binding.id,
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

/// The event an organization-group membership change emits (issue #108).
///
/// Both ends of the join and the organization, exactly as the organization membership types
/// carry them: an integrator PROVISIONS on the add and DEPROVISIONS on the remove, and each
/// needs to know which membership joined or left which group.
fn org_group_member_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    group_id: &ironauth_store::OrgGroupId,
    organization_id: &ironauth_store::OrganizationId,
    membership_id: &ironauth_store::OrgMembershipId,
    event_type: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = group_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "org_group_id": subject,
            "organization_id": organization_id.to_string(),
            "membership_id": membership_id.to_string(),
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The delta for one membership joining or leaving one group, resolved to the PERSON.
///
/// THE ARRAYS CARRY USER IDS, so the membership is resolved to whom it binds. A membership id in
/// a field the schema names `added_user_ids` is what every producer of this type used to send,
/// and a consumer resolving it as a user found nothing.
///
/// A MISS BUILDS NO EVENT AND CHANGES NO RESPONSE. The store resolves both endpoints inside its
/// own write transaction and answers the authoritative not-found; this read only decides whether
/// an event can be built, so the handler's deliberate ordering (no pre-read, so a 409 is reachable
/// only by a caller who can already see both endpoints) is intact, and an absent membership
/// announces nothing rather than announcing a guess.
async fn group_membership_delta_for(
    state: &AdminState,
    scope: ironauth_store::Scope,
    group_id: &ironauth_store::OrgGroupId,
    organization_id: &ironauth_store::OrganizationId,
    membership_id: &ironauth_store::OrgMembershipId,
    joining: bool,
) -> Result<Option<crate::events::PendingEvent>, ApiError> {
    let record = match state
        .store()
        .management()
        .org_memberships(scope)
        .get(membership_id)
        .await
    {
        Ok(record) => record,
        // NOT-FOUND IS THE ONLY MISS THIS MAY SWALLOW. The store answers the authoritative
        // not-found for the write itself a moment later, so building no event is correct: there
        // is nothing to announce.
        Err(ironauth_store::StoreError::NotFound) => return Ok(None),
        // ANYTHING ELSE FAILS THE REQUEST. `remove_with_event` promises a consumer sees "never
        // one form without the other", and the first version of this ended the read with
        // `.ok()?`: a transient database fault dropped the delta while the binding committed and
        // the per-member event was enqueued, silently and with no way to notice.
        Err(_) => return Err(ApiError::Internal),
    };
    let user = record.user_id.to_string();
    let (added, removed) = if joining {
        (vec![user], Vec::new())
    } else {
        (Vec::new(), vec![user])
    };
    Ok(group_membership_delta_event(
        state,
        scope,
        group_id,
        organization_id,
        added,
        removed,
    ))
}

/// The GROUP membership delta (issue #107's criterion, issue #108's registry), the twin of
/// the organization form.
///
/// Groups are where the cap actually bites. An enterprise group is the thing with tens of
/// thousands of members, and issue #107 named full group dumps as the failure mode this
/// contract exists to avoid: past the cap the arrays become a PREFIX, `truncated` says so,
/// and the consumer re-reads the membership through the management API rather than applying
/// a delta that would leave it confidently wrong about everyone it was not sent.
///
/// Emitted beside `org_group.member_added`/`member_removed`, in the same transaction, for the
/// reason the organization twin documents: the per-member type says WHO, this says what the
/// SET did, and only this one can say "there was more than I could carry".
fn group_membership_delta_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    group_id: &ironauth_store::OrgGroupId,
    organization_id: &ironauth_store::OrganizationId,
    added: Vec<String>,
    removed: Vec<String>,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let change = ironauth_store::membership_change(added, removed);
    let mut payload =
        ironauth_store::membership_delta_payload(&change, "added_user_ids", "removed_user_ids");
    let subject = group_id.to_string();
    payload["org_group_id"] = serde_json::json!(subject);
    payload["organization_id"] = serde_json::json!(organization_id.to_string());
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "org_group.membership_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        // The GROUP is the subject: changes to one group stay ordered, which is what lets a
        // consumer apply them as a sequence at all.
        subject,
        envelope,
    })
}
