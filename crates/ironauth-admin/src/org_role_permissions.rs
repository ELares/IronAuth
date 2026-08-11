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
//! rows. The byte and count budget issue #98 ships bounds ONE TOKEN, never this
//! table: an attach past it still answers 201, and
//! `the_management_plane_never_truncates_a_permission_set_past_the_budget` measures
//! exactly that.
//!
//! # The attach REPORTS the budget, and reports which set it measured
//!
//! Since issue #425 the attach 201 carries `role_permission_budget`, so the operator
//! who crosses a threshold learns it from the write that caused it rather than from a
//! separate read of some membership that happens to hold the role. Reporting is all it
//! does: no count and no size turns this into a 4xx or a 5xx and nothing is truncated.
//!
//! It is computed over THIS ROLE'S OWN live mappings, which is what the write already
//! addresses, and NOT over the resolved set of every affected membership. The blast
//! radius of one attach is the whole effective member set of the role, direct and
//! group-inherited through the recursive closure, and resolving that on a write is the
//! unbounded fan-out issue #98 refused everywhere else. The cost of the cheap answer is
//! that it answers a DIFFERENT question from the effective-roles read, one that bounds
//! it in NEITHER direction, so the mitigation is stated twice over: the field is named
//! `role_permission_budget` rather than `permission_budget`, AND the verdict object
//! itself carries `scope: "role"`, so the distinction survives being lifted out of the
//! response and passed around. `an_attach_within_the_role_budget_can_still_be_a_membership_over_it`
//! constructs the divergence and pins both answers.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, NewOrgRolePermission, OrgRolePermissionId, OrgRolePermissionRecord,
    ResolvedIdempotencyWrite, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{
    EnvironmentAccess, parse_permission_id, parse_role_id, require_role_in_org, resolve_live_org,
    resolve_scope,
};
use crate::org_effective_roles::{PermissionBudgetScope, PermissionBudgetView};
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
    /// The budget verdict over THIS ROLE'S OWN live permission mappings, counting the
    /// one this response reports (issue #425). ADVISORY: it refuses nothing, and the
    /// attach that produced it answered 201 however far past any threshold it went.
    ///
    /// # It is named for the set it measures, and the verdict repeats the name
    ///
    /// This is NOT `permission_budget`, and the difference is not cosmetic. The
    /// `permission_budget` on `GET .../memberships/{id}/effective-roles` is over one
    /// MEMBERSHIP'S RESOLVED set: every role that member holds directly, everything
    /// inherited through the group ancestor closure, and the organization's default
    /// role, unioned. THIS verdict is over one role's own live mappings. The object
    /// here always carries `scope: "role"` and the one there always carries
    /// `scope: "membership"`, so a reader that keeps only the verdict still knows which
    /// question it answers.
    ///
    /// # It is a DIFFERENT set, and NEITHER an upper nor a lower bound on that one
    ///
    /// A membership can be OVER budget while this field reads perfectly fine, AND this
    /// field can name an `overflow` that no membership will ever see. Both are
    /// legitimate answers rather than bugs, and three separate mechanisms produce them:
    ///
    ///   * A DEAD PERMISSION ENDPOINT. This count filters the MAPPING'S liveness and
    ///     nothing else, while the membership resolution also requires the PERMISSION
    ///     row to be live; deleting a permission cascades to no mapping. Measured: an
    ///     attach reported 3 with `budget_exceeded` while the membership read 1 with no
    ///     overflow at all.
    ///   * The ORGANIZATION LIFECYCLE. A DISABLED organization stays writable here on
    ///     purpose, while the resolution closure seeds only on an ACTIVE one. Measured:
    ///     an attach reported 2 and overflowing while the membership read 0.
    ///   * STALENESS, in EITHER direction, described below.
    ///
    /// So when this field says `approaching` or carries an `overflow` it says nothing
    /// about any membership, and when it says neither it says nothing about any
    /// membership either. The effective-roles view is the membership-scoped answer and
    /// the only one that predicts what a token will carry.
    ///
    /// # A SNAPSHOT taken at the write, reproduced exactly on a replay
    ///
    /// The count is taken INSIDE the write transaction and AFTER the insert (issue #430),
    /// so it includes the row being attached and everything committed before that
    /// transaction's snapshot. The 201 and the stored Idempotency-Key body are rendered
    /// from that one figure by the same closure, so a response can never disagree with
    /// its own replay.
    ///
    /// It is exact with respect to that SNAPSHOT rather than globally serialized. Under
    /// READ COMMITTED two attaches racing on one role can each see their own insert and
    /// not the other's, so both may report the same figure; ruling that out would mean
    /// serializing every attach on a per-role lock for an ADVISORY number, which the
    /// covenant above argues against.
    ///
    /// An Idempotency-Key REPLAY reproduces the original snapshot byte for byte by
    /// design, so a 201 can still report a count the role no longer has (measured: a
    /// replay reported 2 and `approaching` against a live count of 1). That is correct
    /// behaviour for an idempotent replay and is not staleness this field can fix.
    ///
    /// # Present on the attach 201 ONLY
    ///
    /// Serialized only when the verdict exists, so it is ABSENT rather than null on
    /// every item of `GET .../roles/{role_id}/permissions`. The published schema still
    /// renders the member as nullable, exactly as `overflow` on `PermissionBudgetView`
    /// does, so a generated client sees `null | PermissionBudgetView` and must treat
    /// absent and null alike. A verdict per listed row would be one count query per
    /// item, an N+1 on a read whose whole job is to page cheaply, and every row of one
    /// page would carry the same number anyway. The count that list wants is the attach
    /// response's, or the effective-roles view's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_permission_budget: Option<PermissionBudgetView>,
}

impl OrgRolePermissionView {
    /// Build a view from a stored record. The repository only returns LIVE (not
    /// detached) mappings.
    ///
    /// No budget verdict: this is the LIST projection, and the field is documented as
    /// present on the attach 201 alone. Computing one here would be a count query per
    /// listed row.
    fn from_record(record: &OrgRolePermissionRecord) -> Self {
        Self {
            id: record.id.to_string(),
            organization_id: record.organization_id.to_string(),
            role_id: record.role_id.to_string(),
            permission_id: record.permission_id.to_string(),
            created_at_unix_ms: record.created_at_unix_micros / 1000,
            updated_at_unix_ms: record.updated_at_unix_micros / 1000,
            role_permission_budget: None,
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
        (status = 201, description = "Attached. Every member who effectively holds the role, directly or through the group forest, resolves the permission at the NEXT token issuance. The body carries `role_permission_budget`, the advisory budget verdict over THIS ROLE'S OWN live mappings including this one, stamped `scope: \"role\"` (issue #425). It refuses nothing: an attach past every threshold is still this 201, and nothing is truncated anywhere. Read the field for what it does NOT cover: a role's mappings are a DIFFERENT set from any membership's resolved set and bound it in NEITHER direction, because a soft-deleted permission is still counted here, a disabled organization stays writable here while resolving nothing, and the figure is a snapshot taken at the write that a replay reproduces unchanged. The effective-roles view, whose verdict is stamped `scope: \"membership\"`, is the only answer that predicts what a token will carry", body = OrgRolePermissionView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found: the organization, a role that is not a live role of it, or a permission that is not a live permission of this environment (uniform across absent, deleted, another scope's, and another organization's, so a cross pairing never says which half was wrong). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
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
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization_id,
        EnvironmentAccess::Write,
    )
    .await?;
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

    // The ROLE-SCOPED budget verdict this response carries (issue #425), counted INSIDE
    // the write transaction and AFTER the insert (issue #430). The store returns the exact
    // figure and BOTH the response and the stored replay body are rendered from it by the
    // same closure, so the two cannot disagree.
    //
    // What this closes: the count used to run in its own earlier transaction and be
    // incremented by hand, so it could not see its own insert and missed anything committed
    // in the window between the two transactions. What it does NOT close, deliberately, is
    // the REPLAY snapshot: a replay reproduces the original 201 byte for byte by design, so
    // its figure is a snapshot of the original write however exact that write was.
    //
    // It is exact with respect to the inserting transaction's SNAPSHOT rather than globally
    // serialized. Under READ COMMITTED two concurrent attaches on one role can each see
    // their own insert and not the other's, so both may report the same figure; making that
    // impossible would mean serializing every attach on a per-role lock for an ADVISORY
    // number, which the covenant on this field argues against (no count may turn the attach
    // into a 4xx or a 5xx).
    //
    // One indexed count over ONE role, never a fan-out. The honest verdict for an operator
    // is the MEMBERSHIP-scoped one, but computing that here would mean resolving the whole
    // effective member set of this role (direct plus the recursive group closure) and then a
    // resolved permission set per member, on a WRITE. Issue #98 avoided exactly that shape
    // everywhere else. So this reports what the write cheaply knows and the field NAMES the
    // set it measured.
    let created_at_micros = state.now_unix_micros();
    let mapping_id = OrgRolePermissionId::generate(state.env(), &scope);
    let render_view = |attached: &i64| {
        // Widening rather than narrowing, for the reason `PermissionBudgetView::evaluate`
        // gives: saturating at `usize::MAX` on a target too narrow to hold the count reports
        // an overflow, which is the safe direction, while a truncating cast could report a
        // huge set as a small one.
        let attached_count = usize::try_from(*attached).unwrap_or(usize::MAX);
        OrgRolePermissionView {
            id: mapping_id.to_string(),
            organization_id: org_id.to_string(),
            role_id: role.id.to_string(),
            permission_id: permission.to_string(),
            created_at_unix_ms: created_at_micros / 1000,
            updated_at_unix_ms: created_at_micros / 1000,
            // ROLE scoped, and the verdict carries that on the wire so the answer stays
            // attributable to its set after it leaves this response.
            role_permission_budget: Some(PermissionBudgetView::evaluate(
                PermissionBudgetScope::Role,
                state.token_claims(),
                attached_count,
            )),
        }
    };
    let render = |attached: &i64| serde_json::to_string(&render_view(attached));

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
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
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
        Ok(attached) => {
            // Rendered from the SAME closure and the SAME count the store stored, so the
            // 201 and every replay of it are the same bytes.
            let body_string = render(&attached).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::CREATED, body_string))
        }
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
        (status = 404, description = "Not found (no such live mapping: absent, already detached, either half in another scope, a role of another organization, or a pair whose two halves are individually visible but do not belong together). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
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
        // Attribute the audit row to this organization (issue #110).
        .in_organization(org_id)
        .org_role_permissions(scope)
        .unassign(state.env(), &org_id, &mapping.id)
        .await?;
    Ok(no_content())
}
