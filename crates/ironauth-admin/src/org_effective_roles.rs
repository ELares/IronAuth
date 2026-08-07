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
//! for a grant straight to the membership, `group` plus the `via_group_id` of the
//! group that carries it (which may be a group the member is in, or an ANCESTOR of
//! one), or `default` for the organization's default role (issue #98).
//!
//! `default` is the case this endpoint exists for. That role is held by every live
//! active member with no assignment row anywhere, so it is the ONE path that appears
//! in neither assignment list and that no amount of reading the configuration would
//! explain. Without this variant an operator would see a role in the effective set,
//! find no grant for it on any surface, and have nothing to conclude but that the
//! system is wrong.
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
//! The response is `{"roles": [...], "permissions": [...], "permission_budget": {...}}`.
//! Issue #97 shipped the object wrapper with only `roles` in it precisely so issue #98
//! could add the other two as a pure addition, with no consumer having to change how
//! it parses. A bare array would have made both a breaking change.
//!
//! # The permission set, and the budget verdict beside it
//!
//! `permissions` is the WHOLE resolved set, un-paginated and un-capped, and it is the
//! same store read the mint runs. It is a flat set rather than a per-role breakdown
//! because that is the shape the token claim takes and this endpoint's contract is
//! "what would the next token carry".
//!
//! `permission_budget` reports what the budget would say about that set. It is
//! ADVISORY and it refuses nothing: this endpoint is a read, and no endpoint anywhere
//! in issue #98 answers 4xx or 5xx for a count or a size reason. Read
//! [`PermissionBudgetView`] for the one thing it deliberately does NOT answer.
//!
//! # Un-paginated, and why that is safe
//!
//! This is a BOUNDED read, not an unbounded one. Its cost is bounded by the number
//! of roles the organization DEFINES, and each role contributes at most one direct
//! entry, at most one default entry (and at most ONE role per organization can carry
//! that, by partial unique index), plus one entry per group in the member's ancestor
//! closure that grants it;
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
//! # A DISABLED organization resolves to an empty set here, deliberately
//!
//! An organization that has been disabled mints no roles, so this view reports none
//! for every one of its members. That is the SAME sentence as the paragraph above
//! rather than an exception to it: the endpoint answers "what would the next token
//! carry", the next token carries nothing, and reporting provenance for roles no
//! token will assert is the answer that would mislead. The CONFIGURATION is not
//! hidden and nothing is lost: the direct-assignment list
//! (`GET .../memberships/{id}/roles`) and the group-grant list
//! (`GET .../groups/{id}/roles`) both ignore the organization's lifecycle state, and
//! they are the surfaces that answer "which rows did someone write". Re-enabling the
//! organization restores this view and the token claim together, in one step,
//! because both read the one shared closure.
//!
//! A SOFT-DELETED organization never reaches this handler at all: `resolve_live_org`
//! answers the uniform 404 first.
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
use ironauth_config::TokenClaimsConfig;
use ironauth_store::{EffectiveRoleGrant, EffectiveRoleSource};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::org_context::{
    EnvironmentAccess, require_membership_in_org, resolve_live_org, resolve_scope,
};
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
    /// The ORGANIZATION'S DEFAULT ROLE: held by every live active member because the
    /// organization designated it, and NOT because anybody granted it.
    ///
    /// There is no assignment row behind this entry, so it appears in NO assignment
    /// list and no `DELETE .../memberships/{id}/roles/{role}` can take it away. It is
    /// withdrawn for the WHOLE organization at once, by designating a different
    /// default role, clearing the designation, or deleting the role.
    Default,
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
    /// Whether this path is a direct grant, an inherited one, or the organization's
    /// default role.
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
            // No `via_group_id`, and not because one is unknown: the organization's
            // default role reaches the member through no group and through no
            // assignment row at all.
            EffectiveRoleSource::Default => Self {
                slug: grant.slug,
                source: EffectiveRoleSourceView::Default,
                via_group_id: None,
            },
        }
    }
}

/// WHICH SET a [`PermissionBudgetView`] was computed over (issue #425).
///
/// A REQUIRED discriminator INSIDE the verdict, not a property of the field carrying
/// it, and that placement is the whole point. The two verdicts this plane reports are
/// byte-shape identical apart from this member, so a bare `PermissionBudgetView`
/// handed to an SDK, a console component or a log pipeline WITHOUT the name of the
/// field it arrived in would otherwise have lost, irrecoverably, which set it
/// describes. A discriminator travels with the object and makes the two carriers
/// non-interchangeable by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PermissionBudgetScope {
    /// ONE ROLE'S OWN live permission mappings, counted inside one organization.
    ///
    /// What the role-to-permission ATTACH reports, because that is the set the write
    /// already addresses. It is a DIFFERENT question from [`Self::Membership`] and
    /// bounds it in NEITHER direction; the type docs name the three mechanisms.
    Role,
    /// ONE MEMBERSHIP'S RESOLVED permission set: every role the member holds
    /// directly, everything inherited through the group ancestor closure, and the
    /// organization's default role, unioned and deduplicated.
    ///
    /// What the effective-roles READ reports, and the only verdict that predicts what
    /// a token claim will carry.
    Membership,
}

/// What the permission budget would say about ONE set of permissions (issue #98).
/// ADVISORY ONLY.
///
/// Nothing here refuses a write and no number here is a cap on what may be STORED. It
/// reports what a token issuance would carry, in the same units the `[token_claims]`
/// configuration is written in.
///
/// # WHICH set, said by the object itself
///
/// This type is the budget ARITHMETIC plus the NAME OF THE SET it ran over. It is
/// carried by two fields on two different endpoints, over two DIFFERENT sets, and
/// [`Self::scope`] states which one on every instance (issue #425):
///
///   * [`EffectiveRolesView::permission_budget`] carries
///     [`PermissionBudgetScope::Membership`]: every role the member holds directly,
///     through the group ancestor closure, and by the organization's default role,
///     unioned and deduplicated. That is the set a token claim would carry, so it is
///     the authoritative verdict.
///   * `OrgRolePermissionView::role_permission_budget`, on the attach 201, carries
///     [`PermissionBudgetScope::Role`]: one role's OWN live mappings. It is there
///     because the write is where an operator's attention is at the moment they cross
///     a threshold.
///
/// # The two verdicts bound each other in NEITHER direction
///
/// The role figure is not an upper bound on the membership figure and not a lower
/// bound on it either. It is a different set, and an earlier draft of this document
/// claimed a lower bound, which is why the refuting mechanisms are named rather than
/// summarized:
///
///   * A DEAD PERMISSION ENDPOINT. The role count filters the MAPPING'S `deleted_at`
///     and nothing else, while the membership resolution additionally requires the
///     permission ROW to be live. Neither a role nor a permission cascades to the
///     mapping table, so a soft-deleted permission leaves its mapping counted here and
///     resolved nowhere. Measured: an attach reported 3 with `budget_exceeded` while
///     the same membership read 1 with no overflow at all.
///   * The ORGANIZATION LIFECYCLE. This plane deliberately keeps a DISABLED
///     organization writable, while the resolution closure seeds only on an ACTIVE
///     one. Measured: an attach reported 2 and overflowing while the same membership
///     read 0, with no roles and no permissions.
///   * STALENESS, in EITHER direction. The role figure is a SNAPSHOT taken at the
///     write that reported it: a concurrent attach on the same role leaves it SHORT
///     and a concurrent detach leaves it LONG, and an Idempotency-Key REPLAY
///     faithfully reproduces the original snapshot by design, so a byte-identical 201
///     can report a count the role no longer has. Measured: a replay reported 2 and
///     `approaching` against a live count of 1.
///
/// So a membership can be over budget while the role verdict reads fine, AND the role
/// verdict can name an overflow no membership will ever see.
/// `an_attach_within_the_role_budget_can_still_be_a_membership_over_it` drives the
/// first direction and pins both answers at once. What CANNOT disagree is the
/// vocabulary: both carriers evaluate through [`PermissionBudgetView::evaluate`] and
/// take every wire string from
/// [`ironauth_config::PermissionOverflow::permissions_status`], which is also where
/// the mint takes it from.
///
/// # The one thing this does NOT answer, said plainly
///
/// The budget has TWO bounds, an element count and a compact-token BYTE size, and
/// this view evaluates only the first. `approaching` and `overflow` are the ELEMENT
/// verdict. The byte verdict is not withheld out of caution, it is genuinely not
/// computable here: an exact compact-token size needs the environment's signing key
/// (for the protected header and the signature width) and the whole rest of the
/// exchange (the audience set, the granted scope, any `cnf` binding), none of which
/// exists on a management read of a membership. The alternative would be an ESTIMATE,
/// and an estimated byte verdict is a lie in exactly the direction that matters: it
/// would tell an operator a set fits when the mint will withhold it. So the byte
/// BOUNDS are reported as the configured numbers, for context, and the byte VERDICT
/// belongs to the mint, which measures rather than estimates and puts
/// `permissions_status` on the token when it withholds.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PermissionBudgetView {
    /// WHICH SET the numbers below were computed over. ALWAYS present, on both
    /// carriers, and the one member that makes them distinguishable once the object
    /// has been separated from the field it arrived in (issue #425).
    ///
    /// `role` on the attach 201, `membership` on the effective-roles read. A reader
    /// that treats the two alike is reading a different question from the one it
    /// asked; see the type docs for the three mechanisms that make them disagree.
    pub scope: PermissionBudgetScope,
    /// How many permissions are in the set this verdict was computed over. A count,
    /// never a cap: nothing refuses a permission because of it.
    ///
    /// WHICH set that is, `scope` above says.
    pub permission_count: usize,
    /// The configured largest element count ONE permission claim may carry.
    pub max_permission_count: u32,
    /// The configured element count above which an emitted claim is reported as
    /// approaching the budget.
    pub warn_permission_count: u32,
    /// The configured largest compact access token, in bytes, that may carry a
    /// permission claim. Reported for context; see the type docs for why no byte
    /// verdict is computed here.
    pub max_token_bytes: u32,
    /// The configured compact-token size above which an emitted claim is reported as
    /// approaching the budget. Context only, as above.
    pub warn_token_bytes: u32,
    /// `true` when the set is PAST `warn_permission_count` but still within
    /// `max_permission_count`. The ELEMENT verdict only.
    pub approaching: bool,
    /// The `permissions_status` value the next token would carry, present ONLY when
    /// the set is past `max_permission_count`. Absent (rather than null) otherwise.
    ///
    /// Its presence means the next token will carry NO `permissions` claim. It does
    /// NOT mean anything was refused here: this membership still holds every one of
    /// those permissions, the management plane still reports them all, and every
    /// attach that produced them answered 201.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "budget_exceeded")]
    pub overflow: Option<String>,
}

impl PermissionBudgetView {
    /// Evaluate the ELEMENT half of `budget` against a set of `count` permissions.
    ///
    /// The comparisons mirror `ironauth_oidc`'s pure budget core exactly, including
    /// that both are STRICTLY greater-than, so a count sitting exactly on a threshold
    /// is neither approaching nor overflowing. An off-by-one here would make the
    /// console disagree with the token about a boundary set, which is the worst
    /// possible place to disagree.
    ///
    /// The ONE evaluation on this plane, shared by both carriers of the type (issue
    /// #425): the effective-roles read passes a membership's resolved count and the
    /// attach passes one role's own mapping count, and neither re-implements the
    /// comparisons or re-spells an overflow marker. Two copies would be two chances for
    /// the console and the write response to disagree about the same numbers.
    ///
    /// `scope` is a parameter rather than a second constructor for the same reason
    /// there is one `evaluate` at all: a caller cannot produce a verdict without
    /// stating which set it counted, and the two carriers cannot drift apart by taking
    /// different code paths to say so.
    pub(crate) fn evaluate(
        scope: PermissionBudgetScope,
        budget: &TokenClaimsConfig,
        count: usize,
    ) -> Self {
        // Widened to `usize` rather than narrowing `count` to `u32`, for the reason
        // `ironauth_oidc`'s budget gives: the widening is lossless on every supported
        // target, while a narrowing cast is the one arithmetic step that could turn a
        // large configured bound into a small effective one.
        let max = usize::try_from(budget.permission_claim_max_count).unwrap_or(usize::MAX);
        let warn = usize::try_from(budget.permission_claim_warn_count).unwrap_or(usize::MAX);
        let over = count > max;
        let approaching = !over && count > warn;
        Self {
            scope,
            permission_count: count,
            max_permission_count: budget.permission_claim_max_count,
            warn_permission_count: budget.permission_claim_warn_count,
            max_token_bytes: budget.access_token_max_bytes,
            warn_token_bytes: budget.access_token_warn_bytes,
            approaching,
            overflow: over.then(|| {
                budget
                    .permission_claim_overflow
                    .permissions_status()
                    .to_owned()
            }),
        }
    }
}

/// The resolved roles of one organization membership.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EffectiveRolesView {
    /// Every grant path, ordered by `(slug, source, via_group_id)`, so two reads of
    /// unchanged state are byte-identical. NOT deduplicated by slug: a role held both
    /// directly and through a group appears twice, which is what tells an operator
    /// that withdrawing one grant will not take it away, and a role that is also the
    /// organization's default appears with a `default` entry that no withdrawal
    /// touches at all.
    ///
    /// An OBJECT wraps this array rather than the array being the whole body, which
    /// is what let issue #98 add `permissions` and `permission_budget` beside it as a
    /// pure addition.
    ///
    /// The whole set, never a page: this is a bounded read (see the module docs),
    /// and there is no cap on how many roles a member may hold.
    pub roles: Vec<EffectiveRoleView>,
    /// Every permission slug the membership effectively holds (issue #98), in the
    /// store's total order, DEDUPLICATED: unlike `roles` above this is a SET and not a
    /// list of grant paths, because that is what the token claim is and because a
    /// permission's provenance is the role that carries it, which the list above
    /// already names.
    ///
    /// The WHOLE set, never truncated and never paged, however large and whatever
    /// `permission_budget` says about it. That is a structural property and not a
    /// courtesy: an operator must always be able to see what a token will not carry,
    /// so the one surface that could show them is the one surface that must never
    /// shorten the answer.
    pub permissions: Vec<String>,
    /// What the budget would say about `permissions` at the next issuance. Advisory;
    /// see [`PermissionBudgetView`], in particular for which half of the budget it
    /// evaluates.
    ///
    /// This is the MEMBERSHIP-scoped verdict and the authoritative one, because this
    /// set is what a token claim would carry. It always carries `scope: "membership"`.
    /// The attach 201's `role_permission_budget` carries `scope: "role"` and counts a
    /// DIFFERENT set, which bounds this one in NEITHER direction; the type docs name
    /// the three mechanisms.
    pub permission_budget: PermissionBudgetView,
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
        (status = 200, description = "The resolved roles, one entry per grant path, plus the resolved permission SET and the advisory budget verdict over it (issue #98). This is what the NEXT token issuance would carry; tokens already issued are NOT affected by a recent change. A DISABLED organization mints nothing, so both are empty for every one of its members until it is re-enabled (the assignment lists still show the configuration). Not paginated and never truncated, whatever the budget says: an operator must always be able to see what a token will not carry", body = EffectiveRolesView),
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
    // is exactly what a token would carry for it. The same seed requires the
    // ORGANIZATION to be live and active, so a disabled organization resolves to the
    // empty set here for the same reason and by the same code path the mint uses.
    let grants = state
        .store()
        .management()
        .org_groups(scope)
        .effective_role_grants(&org_id, &membership.user_id, state.max_group_depth())
        .await?;

    // The permission set, through the SAME repository, the SAME (organization, user)
    // key, and the SAME depth bound as the roles above and as the mint (issue #98), so
    // this view and the token claim cannot answer differently for one membership. A
    // store fault is a 500 here for the reason the module docs give for roles, and one
    // step more sharply: an empty permission set is indistinguishable from a member who
    // legitimately holds nothing.
    let permissions = state
        .store()
        .management()
        .org_groups(scope)
        .effective_permissions(&org_id, &membership.user_id, state.max_group_depth())
        .await?;

    // MEMBERSHIP scoped, and the verdict says so on the wire: `permissions` above is
    // the whole resolved set, so this is the answer that predicts the next token.
    let permission_budget = PermissionBudgetView::evaluate(
        PermissionBudgetScope::Membership,
        state.token_claims(),
        permissions.len(),
    );
    let view = EffectiveRolesView {
        roles: grants
            .into_iter()
            .map(EffectiveRoleView::from_grant)
            .collect(),
        permissions: permissions.into_iter().collect(),
        permission_budget,
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
