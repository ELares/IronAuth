// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shared ADDRESS resolution every endpoint nested under an organization
//! performs first (issue #97).
//!
//! Six modules' worth of endpoints hang off
//! `/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}`,
//! and every one of them opens with the same two steps: authorize the
//! `(tenant, environment)` scope the path names, then resolve the organization
//! segment as a live organization in it. Those two steps used to be copy-pasted
//! per module.
//!
//! They live here instead, in ONE copy, for a reason the reviews on this surface
//! have already demonstrated twice. [`resolve_scope`] contains the single
//! [`Principal::require_environment`] call that confines a management key to the
//! environment it was minted for; a copy of it per module means a copy of that
//! call per module, each of which can be deleted independently and each of which
//! therefore needs its own test to notice. One call site is one thing to test and
//! one thing to review. The same argument applies to the `organizations.get`
//! liveness check in [`resolve_live_org`], whose omission would let a nested route
//! keep serving an organization that had been deleted.
//!
//! `memberships.rs` (issue #94) still carries its own copies. That is deliberate
//! rather than an oversight: folding it in would put an issue #94 file in an issue
//! #97 diff for no behavior change. The two copies there are byte-identical to
//! these and should be folded in whenever that file is next touched.
//!
//! # Two callers here are NOT nested under an organization
//!
//! The permission vocabulary (issue #98) is scoped to the ENVIRONMENT: migration
//! 0091 gives `permissions` no `organization_id`, so its row-level-security policy
//! is the complete fence and there is no parent organization to resolve.
//! `permissions.rs` therefore calls [`resolve_scope`] and stops, and it addresses a
//! row through [`parse_permission_id`] and [`require_live_permission`] below.
//!
//! The resource-server registry (issue #98) is the second, for the same reason:
//! `resource_servers` carries no organization either, so `resource_servers.rs` calls
//! [`resolve_scope`] and addresses a row through [`parse_resource_server_id`] and
//! [`require_live_resource_server`].
//!
//! It lives here anyway, and the reason is the paragraph above rather than the
//! module's name: [`resolve_scope`] is the ONE copy of the
//! [`Principal::require_environment`] call that confines a management key, and the
//! whole point of folding the copies together was that a second copy is a second
//! thing to delete and a second thing to test. An environment-scoped module writing
//! its own would be exactly that. Several older environment-scoped modules do carry
//! private copies of the same two lines; those predate this module and are noted
//! rather than claimed to be folded in.
//!
//! # A disabled organization is LIVE here
//!
//! [`resolve_live_org`] treats a DISABLED (not deleted) organization as reachable,
//! because [`ironauth_store::OrganizationRepo::get`] filters only `deleted_at`.
//! Membership management under a disabled organization therefore still works, which
//! is what `memberships.rs` has always done and what an operator winding an
//! organization down needs: disabling stops its users signing IN, and an operator
//! must still be able to strip roles and groups afterwards. It is stated here so
//! that it reads as a decision rather than an accident.

use ironauth_store::{
    ActorRef, OrgGroupId, OrgMembershipId, OrgMembershipRecord, OrgRoleId, OrgRoleRecord,
    OrganizationId, PermissionId, PermissionRecord, ResourceServerId, ResourceServerRecord, Scope,
};

use crate::auth::Principal;
use crate::error::ApiError;
use crate::state::AdminState;

/// Resolve and authorize the `(tenant, environment)` scope from the path. The
/// operator passes; a management key must be scoped to exactly this environment
/// (otherwise the LOUD wrong-scope error). A malformed tenant or environment id is
/// the uniform not-found.
///
/// # Errors
///
/// [`ApiError::NotFound`] for a malformed or absent tenant or environment;
/// [`ApiError::WrongScope`] for a credential that is not authorized for this
/// environment or is on the wrong plane.
pub fn resolve_scope(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ActorRef), ApiError> {
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
/// foreign, malformed, or soft-deleted organization reads as a uniform not-found.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the segment is malformed, out of scope, absent, or
/// soft-deleted.
pub async fn resolve_live_org(
    state: &AdminState,
    scope: Scope,
    organization_id: &str,
) -> Result<OrganizationId, ApiError> {
    let organizations = state.store().management().organizations(scope);
    let id = organizations.parse_id(organization_id)?;
    organizations.get(&id).await?;
    Ok(id)
}

/// Parse an untrusted group id in scope. A malformed value and one minted in
/// another `(tenant, environment)` both collapse to the uniform not-found, never a
/// 400 that would distinguish "you sent nonsense" from "that belongs to someone
/// else".
///
/// Whether the id names a LIVE group of a PARTICULAR organization is a separate
/// question, answered either by [`require_group_in_org`] or, on a write, by the
/// store inside the write transaction. Parsing alone proves only the scope.
///
/// # Errors
///
/// [`ApiError::NotFound`] if malformed or out of scope.
pub fn parse_group_id(
    state: &AdminState,
    scope: Scope,
    group_id: &str,
) -> Result<OrgGroupId, ApiError> {
    Ok(state
        .store()
        .management()
        .org_groups(scope)
        .parse_id(group_id)?)
}

/// Parse an untrusted role id in scope, under the same uniform not-found as
/// [`parse_group_id`].
///
/// # Errors
///
/// [`ApiError::NotFound`] if malformed or out of scope.
pub fn parse_role_id(
    state: &AdminState,
    scope: Scope,
    role_id: &str,
) -> Result<OrgRoleId, ApiError> {
    Ok(state
        .store()
        .management()
        .org_roles(scope)
        .parse_id(role_id)?)
}

/// Parse an untrusted organization-membership id in scope, under the same uniform
/// not-found as [`parse_group_id`].
///
/// # Errors
///
/// [`ApiError::NotFound`] if malformed or out of scope.
pub fn parse_membership_id(
    state: &AdminState,
    scope: Scope,
    membership_id: &str,
) -> Result<OrgMembershipId, ApiError> {
    Ok(state
        .store()
        .management()
        .org_memberships(scope)
        .parse_id(membership_id)?)
}

/// Verify the scope's ENVIRONMENT exists and is LIVE, for a write whose table has a
/// foreign key to `environments`.
///
/// [`resolve_scope`] parses the two segments and authorizes the credential; it does
/// NOT prove the environment row exists, because most endpoints never need it. A
/// write does: a well-formed identifier naming an environment that was never created
/// (or that has been deleted) reaches the insert, violates the foreign key, and
/// surfaces as an opaque 500 for an input the caller controls. This turns that into
/// the uniform not-found, which is the same answer a MALFORMED environment segment
/// already gets, so a caller cannot tell the two apart.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the environment is absent or soft-deleted.
pub async fn require_live_environment(state: &AdminState, scope: &Scope) -> Result<(), ApiError> {
    state
        .store()
        .management()
        .environments(scope.tenant())
        .get(&scope.environment())
        .await?;
    Ok(())
}

/// Parse an untrusted permission id in scope, under the same uniform not-found as
/// [`parse_group_id`].
///
/// Unlike the three parsers above, this one addresses a row that hangs off the
/// ENVIRONMENT rather than off an organization, so parsing in scope is the whole of
/// what an address needs to prove here. Whether the id names a LIVE permission is
/// answered either by [`require_live_permission`] or, on a write, by the store
/// inside the write transaction.
///
/// # Errors
///
/// [`ApiError::NotFound`] if malformed or out of scope.
pub fn parse_permission_id(
    state: &AdminState,
    scope: Scope,
    permission_id: &str,
) -> Result<PermissionId, ApiError> {
    Ok(state
        .store()
        .management()
        .permissions(scope)
        .parse_id(permission_id)?)
}

/// Resolve a permission as a LIVE permission of THIS environment, returning the
/// stored record.
///
/// The four addressing failures collapse to one answer: a malformed id and one
/// minted in another `(tenant, environment)` fail to parse in scope, and an absent
/// or soft-deleted one is the repository's own not-found. A caller therefore cannot
/// tell "never existed" from "deleted" from "belongs to another environment" from
/// "nonsense", which is what stops the vocabulary from being an existence oracle
/// over a sibling environment's capability names.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the id is malformed, out of scope, absent, or deleted.
pub async fn require_live_permission(
    state: &AdminState,
    scope: Scope,
    permission_id: &str,
) -> Result<PermissionRecord, ApiError> {
    let id = parse_permission_id(state, scope, permission_id)?;
    Ok(state
        .store()
        .management()
        .permissions(scope)
        .get(&id)
        .await?)
}

/// Parse an untrusted resource-server id in scope, under the same uniform not-found
/// as [`parse_group_id`].
///
/// Like [`parse_permission_id`] this addresses a row hanging off the ENVIRONMENT
/// rather than off an organization, so parsing in scope is the whole of what an
/// address needs to prove here.
///
/// # Errors
///
/// [`ApiError::NotFound`] if malformed or out of scope.
pub fn parse_resource_server_id(
    state: &AdminState,
    scope: Scope,
    resource_server_id: &str,
) -> Result<ResourceServerId, ApiError> {
    Ok(state
        .store()
        .management()
        .resource_servers(scope)
        .parse_id(resource_server_id)?)
}

/// Resolve a resource server as a live resource server of THIS environment,
/// returning the stored record.
///
/// The addressing failures collapse to one answer: a malformed id and one minted in
/// another `(tenant, environment)` fail to parse in scope, and an absent one is the
/// repository's own not-found. A caller therefore cannot tell "never registered" from
/// "belongs to another environment" from "nonsense", which is what stops the registry
/// from being an existence oracle over a sibling environment's protected APIs.
///
/// There are THREE such failures here and not the usual four: `resource_servers`
/// carries no `deleted_at`, so there is no soft-deleted state to make uniform. A row
/// a promotion hard-deleted is simply absent, and reads exactly like one that never
/// existed.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the id is malformed, out of scope, or absent.
pub async fn require_live_resource_server(
    state: &AdminState,
    scope: Scope,
    resource_server_id: &str,
) -> Result<ResourceServerRecord, ApiError> {
    let id = parse_resource_server_id(state, scope, resource_server_id)?;
    Ok(state
        .store()
        .management()
        .resource_servers(scope)
        .get(&id)
        .await?)
}

/// Resolve a group as a LIVE group of THIS organization: the cross-parent guard a
/// nested READ performs before it lists anything hanging off that group.
///
/// A group of a DIFFERENT organization, even in the same environment, is the
/// uniform not-found here, exactly like an absent, a soft-deleted, and a
/// foreign-scope one, so the nested path is never an existence oracle over a
/// sibling organization's groups.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the id is malformed, out of scope, absent, deleted, or
/// belongs to another organization.
pub async fn require_group_in_org(
    state: &AdminState,
    scope: Scope,
    org_id: &OrganizationId,
    group_id: &str,
) -> Result<OrgGroupId, ApiError> {
    let id = parse_group_id(state, scope, group_id)?;
    state
        .store()
        .management()
        .org_groups(scope)
        .get_in_org(org_id, &id)
        .await?;
    Ok(id)
}

/// Resolve a role as a LIVE role of THIS organization, returning the stored record:
/// the cross-parent guard every endpoint addressed by the `(organization, role)` pair
/// performs, and the ONE copy of it.
///
/// A role of a DIFFERENT organization, even in the same environment, is the uniform
/// not-found here, exactly like an absent, a soft-deleted, and a foreign-scope one,
/// so a nested path is never an existence oracle over a sibling organization's roles.
///
/// It resolves through [`ironauth_store::OrgRoleRepo::get_in_org`] and NEVER through
/// `get`, which takes no organization: the same split
/// [`ironauth_store::OrgRolePermissionRepo`] records for the mapping table applies
/// here, and an id-only read behind an organization-nested route would hand back a
/// sibling organization's row with no fence in front of it.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the id is malformed, out of scope, absent, deleted, or
/// belongs to another organization.
pub async fn require_role_in_org(
    state: &AdminState,
    scope: Scope,
    org_id: &OrganizationId,
    role_id: &str,
) -> Result<OrgRoleRecord, ApiError> {
    let roles = state.store().management().org_roles(scope);
    // A malformed id and one minted in another `(tenant, environment)` both fail to
    // parse in scope, which is the same not-found the read below returns.
    let id = roles.parse_id(role_id)?;
    Ok(roles.get_in_org(org_id, &id).await?)
}

/// Resolve a membership as a LIVE membership of THIS organization, returning the
/// stored record (whose `user_id` the effective-role resolution needs).
///
/// The containment guard `memberships.rs` performs inline for its own delete, in
/// one place: a membership of a DIFFERENT organization presented under this
/// organization's path is the uniform not-found.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the id is malformed, out of scope, absent, removed, or
/// belongs to another organization.
pub async fn require_membership_in_org(
    state: &AdminState,
    scope: Scope,
    org_id: &OrganizationId,
    membership_id: &str,
) -> Result<OrgMembershipRecord, ApiError> {
    let id = parse_membership_id(state, scope, membership_id)?;
    let record = state
        .store()
        .management()
        .org_memberships(scope)
        .get(&id)
        .await?;
    if &record.organization_id == org_id {
        Ok(record)
    } else {
        Err(ApiError::NotFound)
    }
}
