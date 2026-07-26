// SPDX-License-Identifier: MIT OR Apache-2.0

//! The EFFECTIVE ROLE view for one organization membership (issue #97).
//!
//! One endpoint, `GET .../organizations/{organization_id}/memberships/{membership_id}/effective-roles`,
//! answering the question the two assignment lists cannot: not "which rows did
//! someone write" but "which roles does this person actually have here, and WHY".
//!
//! # Why provenance is the point
//!
//! A flat list of slugs answers "what". It leaves an operator who wants to take a
//! role away with no idea what to change, and it is actively dangerous for the
//! common case where a role arrives by more than one route: an operator who
//! withdraws the one grant they know about, sees the role survive, and concludes
//! the system is broken. Each entry here therefore names its GRANT PATH: `direct`
//! for a grant straight to the membership, or `group` plus the `via_group_id` of
//! the group that carries it (which may be a group the member is in, or an ANCESTOR
//! of one).
//!
//! # One entry per PATH, not per role
//!
//! A role reachable several ways appears several times, once per path, and the
//! effective role SET is the distinct `slug` values. That is deliberate: see
//! [`ironauth_store::OrgGroupRepo::effective_role_grants`], where the same choice
//! is made and defended at the layer that produces it. Entries are evidence, and
//! dropping evidence is what would make the endpoint misleading.
//!
//! # An OBJECT, not a bare array
//!
//! The response is `{"roles": [...]}` rather than `[...]` so that issue #98 can add
//! `permissions` (per role, and a top-level summary if it wants one) as a pure
//! addition, with no consumer having to change how it parses today's shape. A bare
//! array would have made every later field a breaking change.
//!
//! # Un-paginated, and why that is safe
//!
//! This is a BOUNDED read, not an unbounded one. Its cost is bounded by the number
//! of roles the organization DEFINES, and each role contributes at most one direct
//! entry plus one entry per group in the member's ancestor closure that grants it;
//! that closure is itself bounded by `max_group_depth` (default 8, ceiling 32)
//! times the groups the member belongs to. The bound is structural, not a cap:
//! nothing here refuses to return a row, no count is checked, and an organization
//! may define as many roles and groups as it likes. Cursoring a set whose whole
//! value is that it is complete would also make the common consumer (render this
//! member's roles) into a paging loop for no benefit.
//!
//! # This is a READ of the CURRENT state, not of any issued token
//!
//! The set it returns is what the NEXT token issuance would carry. Tokens already
//! issued are unaffected by a change made a moment ago: role changes take effect at
//! the next issuance, and the exposure is bounded at one access token lifetime
//! because the refresh grant re-resolves rather than replaying a frozen set. So a
//! caller must not read this endpoint as "what the bearer of that user's current
//! access token can do". `docs/THREAT-MODEL.md` states the same gap.
//!
//! # Fails closed, and loudly
//!
//! A store fault is a 500, never an empty `roles` array. On this surface an empty
//! set is indistinguishable from a member who legitimately holds nothing, so
//! swallowing an error would render a silent, plausible-looking authorization
//! downgrade in the console.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{EffectiveRoleGrant, EffectiveRoleSource};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::org_context::{require_membership_in_org, resolve_live_org, resolve_scope};
use crate::response::json;
use crate::state::AdminState;

/// How one role reaches a membership.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveRoleSourceView {
    /// Granted straight to this membership. It survives every change to the group
    /// forest, and withdrawing it is a `DELETE .../memberships/{id}/roles/{role}`.
    Direct,
    /// Inherited through a group: either one the membership is a live member of, or
    /// an ANCESTOR of one. `via_group_id` names which. Withdrawing it means either
    /// removing the membership from the group or withdrawing the grant from the
    /// group named there.
    Group,
}

/// One role a membership effectively holds, and the ONE path by which it holds it.
///
/// A role reachable by several paths yields several of these, one per path, all
/// carrying the same `slug`. The effective role SET is the distinct `slug` values.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EffectiveRoleView {
    /// The role's IMMUTABLE stable name. Slugs rather than ids because a slug is
    /// what an authorization decision keys on and what a token claim will carry: it
    /// is stable across a rename and across a promotion between environments.
    #[schema(example = "billing.admin")]
    pub slug: String,
    /// Whether this path is a direct grant or an inherited one.
    pub source: EffectiveRoleSourceView,
    /// The group that carries the grant (`grp_...`). Present exactly when `source`
    /// is `group`, and absent (rather than null) otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "grp_...")]
    pub via_group_id: Option<String>,
}

impl EffectiveRoleView {
    /// Build one entry from a store grant. The two representations are one enum
    /// apart, so the wire vocabulary cannot drift from the resolution vocabulary.
    fn from_grant(grant: EffectiveRoleGrant) -> Self {
        match grant.source {
            EffectiveRoleSource::Direct => Self {
                slug: grant.slug,
                source: EffectiveRoleSourceView::Direct,
                via_group_id: None,
            },
            EffectiveRoleSource::Group(group) => Self {
                slug: grant.slug,
                source: EffectiveRoleSourceView::Group,
                via_group_id: Some(group.to_string()),
            },
        }
    }
}

/// The resolved roles of one organization membership.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EffectiveRolesView {
    /// Every grant path, ordered by `(slug, via_group_id)` with direct grants
    /// first, so two reads of unchanged state are byte-identical. NOT deduplicated
    /// by slug: a role held both directly and through a group appears twice, which
    /// is what tells an operator that withdrawing one grant will not take it away.
    ///
    /// An OBJECT wraps this array rather than the array being the whole body, so a
    /// later `permissions` field (issue #98) is a pure addition.
    ///
    /// The whole set, never a page: this is a bounded read (see the module docs),
    /// and there is no cap on how many roles a member may hold.
    pub roles: Vec<EffectiveRoleView>,
}

/// Resolve every role one organization membership effectively holds, with the
/// provenance of each.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/effective-roles",
    operation_id = "getOrgMembershipEffectiveRoles",
    tag = "org-roles",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("organization_id" = String, Path, description = "The organization identifier"),
        ("membership_id" = String, Path, description = "The organization membership identifier (omb_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The resolved roles, one entry per grant path. This is what the NEXT token issuance would carry; tokens already issued are NOT affected by a recent change. Not paginated: a bounded read of one membership's whole set", body = EffectiveRolesView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (the organization, or a membership that is not a live membership of it: uniform across absent, removed, another scope's, and another organization's)", body = ErrorBody)
    )
)]
pub async fn get_org_membership_effective_roles(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, organization_id, membership_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let org_id = resolve_live_org(&state, scope, &organization_id).await?;
    // The membership is resolved in THIS organization first: a membership of a
    // sibling organization is the uniform not-found, so this view can never report a
    // member of another organization's authorization picture.
    let membership = require_membership_in_org(&state, scope, &org_id, &membership_id).await?;

    // Resolution is keyed on the (organization, USER) pair rather than on the
    // membership id, because that is the seam the token-issuance path resolves and
    // reusing it verbatim is what keeps this view and the eventual claim in
    // agreement. The two keys name the same rows: a partial unique index admits at
    // most ONE live membership per (organization, user), so the membership resolved
    // above is the one the seed selects. The seed additionally requires state
    // `active`, so a membership in any other state resolves to the empty set, which
    // is exactly what a token would carry for it.
    let grants = state
        .store()
        .management()
        .org_groups(scope)
        .effective_role_grants(&org_id, &membership.user_id, state.max_group_depth())
        .await?;

    let view = EffectiveRolesView {
        roles: grants
            .into_iter()
            .map(EffectiveRoleView::from_grant)
            .collect(),
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
