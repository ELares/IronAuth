// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shared ADDRESS resolution the environment-scoped endpoints perform first
//! (issues #97, #411, #443, #451).
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
//! `memberships.rs` (issue #94) and `organizations.rs` (issue #41) used to carry their
//! own byte-identical copies, left there because folding them in would have put those
//! files in an issue #97 diff for no behavior change, with a note to fold them in
//! whenever either file was next touched. Issue #411 is that touch, and it is the
//! reason the note existed: the fence below had to be added to the ONE copy of
//! [`resolve_live_org`], and a second copy in `memberships.rs` would have been three
//! endpoints that kept the old answer. Both files now import from here.
//!
//! # A WRITE into a SOFT-DELETED environment is refused; a READ is not
//!
//! Deleting an environment does not cascade to its organizations, so an
//! `organizations` row under a deleted environment is still live and
//! [`resolve_live_org`] still resolves it. Every write nested under an organization
//! therefore LANDED in an environment an operator believed they had decommissioned,
//! while `POST .../permissions` refused the identical request because issue #98 PR 7
//! had given the environment-scoped vocabulary create a [`require_live_environment`]
//! precondition for an unrelated reason. The tree had two answers to one question,
//! decided by which route the caller picked (issue #411).
//!
//! The answer is now one answer, and it is placed HERE rather than per endpoint,
//! because per endpoint is exactly how it drifted. [`resolve_live_org`] takes an
//! [`EnvironmentAccess`] and performs the environment fence for a write, so all nineteen
//! organization-nested writes inherit it from the single call each of them already
//! made, and the three organization-lifecycle writes in `organizations.rs` inherit it
//! by resolving through the same function. There is ONE call to
//! [`require_live_environment`] behind the whole organization surface, and the
//! vocabulary create calls the same function, so the two cannot be given different
//! answers without editing one place.
//!
//! # The organization surface was a THIRD of the defect (issue #451)
//!
//! Issue #411 fixed the surface it looked at and left the rest of the environment
//! prefix untouched, and nothing measured the rest. Driven at a soft-deleted
//! environment with one of every row seeded, TWENTY SIX of the seventy five documented
//! environment-scoped writes still succeeded, of which issue #451 named three. The full
//! measured list, and the before-and-after, is in
//! `crates/ironauth-admin/tests/live_surface.rs`; the mechanism was the same one in
//! every case, which is that soft-deleting an environment cascades to almost nothing, so
//! each handler's own addressing read still found the row it was given and never asked
//! about the parent.
//!
//! FIVE resolutions here now carry the fence behind a required [`EnvironmentAccess`]:
//! [`resolve_live_org`] for the organization surface, [`resolve_user`] for the user
//! surface (which is `users.rs`, `consents.rs`, the user session revoke, and the signup
//! review queue), [`require_live_permission`] for the vocabulary, and
//! [`require_live_resource_server`] and [`require_client_scope_policy`] for the two
//! registries. The rest of the fixed writes had no shared resolution to put it behind
//! and call [`require_live_environment`] directly, which is a weaker guarantee, stated
//! plainly here rather than glossed: those call sites are constrained by the sweep and
//! not by the type system.
//!
//! A READ keeps working, which is the same line issue #409 drew when it made an ABSENT
//! environment the uniform not-found for every NON-GET operation under the environment
//! prefix and left every GET alone. An operator who decommissions an environment still
//! has to be able to see what is inside it, and the resurrection question issue #411
//! raises (a restored environment returns carrying whatever was written while it was
//! deleted) is only auditable if the listings still answer. That line is now pinned over
//! the WHOLE environment prefix rather than the organization subtree: the sweep drives
//! every documented environment-scoped GET at a soft-deleted environment and requires
//! the answer to match the live one. It has exactly one exception, `getManagementKey`,
//! because deleting an environment CASCADES `deleted_at` onto its management
//! credentials, which is a deliberate security property older than any of this.
//!
//! # What holds that in place, and what does NOT
//!
//! The required [`EnvironmentAccess`] argument constrains CALLERS of the five resolutions
//! that take it: an endpoint that resolves its row through one of them has to name an
//! intent, and a call site that names the wrong one is caught by
//! `tests/deleted_environment.rs` for the organization subtree and by the whole-prefix
//! sweep in `tests/live_surface.rs` for the rest, both of which require the answer to
//! match the method. That is a real constraint, and it is the only one the type system
//! gives.
//!
//! It is NOT true that divergence cannot compile, and that claim used to stand here.
//! The refutation is measured rather than argued: a new organization-nested write wired
//! into `management_router`, resolving its organization with a bare `parse_id` and
//! carrying no `#[utoipa::path]`, answers 204 and destroys a role row inside a
//! soft-deleted environment with `tests/deleted_environment.rs` and
//! `tests/openapi_contract.rs` both green. The argument constrains callers of these
//! functions; the sweep constrains DOCUMENTED routes; a route that is neither is
//! constrained by nothing.
//!
//! Issue #451 widened what escapes, and it is worth being exact. A handler that
//! addresses a USER with a bare `UserId::parse_in_scope` instead of [`resolve_user`], or
//! one that reads any other child row directly, is outside the argument in the same way.
//! Nothing about the five resolutions prevents that; what catches it is the sweep, and
//! only when the route is documented. It is the honest conditional and not a guarantee.
//!
//! What IS unbroken is the chain conditioned on documentation, and it is worth stating
//! because it is what the sweep actually buys. IF the new route carries a
//! `#[utoipa::path]`, then `openapi_contract`'s
//! `committed_artifact_matches_generated_spec` fails until `docs/openapi/management.json`
//! is regenerated, the regenerated artifact publishes the operation,
//! `every_documented_organization_operation_is_driven_by_a_case` then fails until a case
//! drives it, and the sweep drives that case into a soft-deleted environment and sees
//! the bypass. An UNDOCUMENTED served route escapes all of it. That is the same hole
//! `tests/openapi_contract.rs` already records against
//! `served_routes_match_documented_routes` ("NOT caught here: a brand-new served path
//! outside the documented set"), for the reason stated there: axum does not expose its
//! route table, so there is no served set to compare the documented one against.
//!
//! # The uniform answer is the DEFAULT configuration's answer
//!
//! Every claim on this surface that a write into a soft-deleted environment answers the
//! uniform not-found is a claim about the default configuration, in which sudo mode is
//! off. With sudo mode armed, [`crate::sudo::require_fresh_privilege`] runs BEFORE this
//! function in every environment-scoped write, so a caller whose elevation has lapsed is
//! answered 401 `insufficient_user_authentication` and the environment liveness read
//! never happens.
//!
//! That is not an existence oracle, which is the property this fence is for: an ABSENT
//! environment answers a lapsed elevation identically, so the two stay indistinguishable
//! and only WHICH uniform answer the caller sees changes. It IS one write that lands in a
//! soft-deleted environment: the challenge path records an
//! `admin.privilege.challenged` row in the `audit_log` of the environment an operator
//! believes is decommissioned (MEASURED: three audit rows to four).
//!
//! Issue #452 asked whether the ordering should change. The owner decided it should not
//! and the row should stay, because an audit record of a REJECTED attempt against a
//! decommissioned environment is worth having. So the sentence to carry away is the
//! qualified one: the organization-nested write path, and every other environment-scoped
//! write, refuses a soft-deleted environment in the DEFAULT configuration, and an armed
//! sudo challenge is a deliberate exception. The reasoning and the measurement live on
//! [`crate::sudo::require_fresh_privilege`].
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
//! The per-client scope allowlist (issue #98) is the third: a `clients` row carries no
//! organization, so `client_scopes.rs` calls [`resolve_scope`] and addresses a row
//! through [`require_client_scope_policy`].
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
    ActorRef, ClientId, ClientScopePolicy, OrgGroupId, OrgMembershipId, OrgMembershipRecord,
    OrgRoleId, OrgRoleRecord, OrganizationId, PermissionId, PermissionRecord, ResourceServerId,
    ResourceServerRecord, Scope, UserId,
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

/// What the caller resolving a row is about to do with the environment that row hangs
/// off: the ONE thing the environment-scoped endpoints do not all agree about, and
/// therefore the one thing each of them has to say (issues #411, #451).
///
/// It is a named intent rather than a `bool` so that a call site reads as the decision
/// it is, and it is a required argument rather than a defaulted one so that a new
/// endpoint RESOLVING THROUGH ONE OF THESE FUNCTIONS cannot inherit the wrong answer by
/// saying nothing. One that addresses its row some other way is outside the argument
/// altogether; the module note on what holds this in place says so and says what does
/// catch it. The backstop for a call site that names the wrong variant is the
/// whole-surface sweep in `tests/live_surface.rs`, which drives every operation the
/// committed contract publishes under the environment prefix at a soft-deleted
/// environment and requires the answer to match the method.
///
/// It is ONE enum across every resolution rather than one per surface. Issue #411
/// introduced it for organizations alone, under the name `OrgAccess`; issue #451 found
/// the same question being answered differently on the user surface, and a second enum
/// spelling the same two intents would have been the very thing issue #443 is about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentAccess {
    /// The request only READS. A soft-deleted environment is not fenced: its
    /// organizations, roles, groups, memberships and users stay listable, which is what
    /// an operator auditing a decommissioned environment needs and what makes the
    /// resurrection question answerable.
    Read,
    /// The request WRITES. The environment must exist and be live, or the write would
    /// land rows inside something an operator believes is gone.
    Write,
}

/// Resolve the parent organization id in scope, verifying it exists and is LIVE, and,
/// for a WRITE, that the environment it hangs off is live too. A foreign, malformed, or
/// soft-deleted organization reads as a uniform not-found, and so does a soft-deleted
/// or absent environment on a write.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the segment is malformed, out of scope, absent, or
/// soft-deleted, or, on an [`EnvironmentAccess::Write`], if the environment is absent or
/// soft-deleted.
pub async fn resolve_live_org(
    state: &AdminState,
    scope: Scope,
    organization_id: &str,
    access: EnvironmentAccess,
) -> Result<OrganizationId, ApiError> {
    // The GRANDPARENT-existence precondition (issue #411), and the ONE copy of it
    // behind the organization surface. It runs BEFORE the organization segment is even
    // parsed, so a caller cannot tell a malformed organization id in a deleted
    // environment from a well-formed one; both answers are the uniform not-found
    // anyway, which is what makes the ordering free to be the one that reads as
    // "prove the parent, then address the child".
    //
    // The precondition also inherits its ORDERING from the one call site each handler
    // already had. SEVEN of the twenty two organization-addressed writes carry an
    // Idempotency-Key (the three creates and the four assigns), and every one of them
    // performs the replay BEFORE it calls this function, which is the ordering the
    // sibling environment-scoped creates observe: a genuine replay still returns the
    // original response even if the environment went away in between, so a retry of a
    // request that ALREADY SUCCEEDED never becomes a 404 the client cannot tell from
    // "my write never landed". The other fifteen carry no key, so there is nothing to
    // order against and the precondition is simply the first thing after the scope is
    // authorized.
    //
    // That ordering is a client-visible property, so it is PINNED rather than merely
    // observed: `a_keyed_writes_replay_survives_the_environments_deletion` in
    // `tests/deleted_environment.rs` drives all seven, storing each response while the
    // environment is live, deleting the environment, and then requiring the same key to
    // return the original 201 while a FRESH key at the same route is the uniform
    // not-found. Hoisting this precondition above the replay in `create_org_role` was
    // measured to fail that test and nothing else in the file; the other six are driven
    // by the same loop, which reports the route by name.
    if access == EnvironmentAccess::Write {
        require_live_environment(state, &scope).await?;
    }
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

/// Resolve an untrusted user id in scope and, for a WRITE, verify that the environment
/// the user hangs off is live: the user surface's equivalent of [`resolve_live_org`]
/// (issue #451).
///
/// Soft-deleting an environment does not cascade to its users, so the `users` row
/// survives and a handler's own addressing read still finds it. Every write on this
/// surface therefore LANDED in an environment an operator believed they had
/// decommissioned, while `POST .../users` refused the identical request because it
/// carried the parent-existence precondition for an unrelated reason. That is the same
/// split issue #411 closed on the organization surface, on a surface that issue did not
/// name, and it is closed the same way: the fence lives in the resolution behind a
/// required [`EnvironmentAccess`], so a handler that addresses a user through this
/// function cannot inherit an answer by saying nothing.
///
/// The ordering is "prove the parent, then address the child", which is free here: a
/// malformed user id and a live one in a deleted environment are both the uniform
/// not-found, so no caller can tell which check refused.
///
/// A READ is not fenced, deliberately, and that is the same line issue #409 drew for an
/// ABSENT environment and issue #411 for a soft-deleted one. An operator who
/// decommissions an environment still has to be able to see the users inside it, and the
/// resurrection question (a restored environment comes back carrying whatever was
/// written while it was deleted) is only auditable if the reads still answer.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the id is malformed or out of scope, or, on an
/// [`EnvironmentAccess::Write`], if the environment is absent or soft-deleted.
pub async fn resolve_user(
    state: &AdminState,
    scope: Scope,
    user_id: &str,
    access: EnvironmentAccess,
) -> Result<UserId, ApiError> {
    if access == EnvironmentAccess::Write {
        require_live_environment(state, &scope).await?;
    }
    UserId::parse_in_scope(user_id, &scope).map_err(|_| ApiError::NotFound)
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
/// For a WRITE it also verifies the ENVIRONMENT is live, for the reason
/// [`resolve_user`] records: `permissions` rows survive their environment's soft delete,
/// so `updatePermission` and `deletePermission` both LANDED inside a decommissioned
/// environment (MEASURED: 200 and 204) while `createPermission` next door refused.
///
/// # Errors
///
/// [`ApiError::NotFound`] if the id is malformed, out of scope, absent, or deleted, or,
/// on an [`EnvironmentAccess::Write`], if the environment is absent or soft-deleted.
pub async fn require_live_permission(
    state: &AdminState,
    scope: Scope,
    permission_id: &str,
    access: EnvironmentAccess,
) -> Result<PermissionRecord, ApiError> {
    if access == EnvironmentAccess::Write {
        require_live_environment(state, &scope).await?;
    }
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
/// For a WRITE it also verifies the ENVIRONMENT is live, for the reason
/// [`resolve_user`] records: a `resource_servers` row survives its environment's soft
/// delete, so `updateResourceServerPermissionClaims` LANDED inside a decommissioned
/// environment (MEASURED: 200).
///
/// # Errors
///
/// [`ApiError::NotFound`] if the id is malformed, out of scope, or absent, or, on an
/// [`EnvironmentAccess::Write`], if the environment is absent or soft-deleted.
pub async fn require_live_resource_server(
    state: &AdminState,
    scope: Scope,
    resource_server_id: &str,
    access: EnvironmentAccess,
) -> Result<ResourceServerRecord, ApiError> {
    if access == EnvironmentAccess::Write {
        require_live_environment(state, &scope).await?;
    }
    let id = parse_resource_server_id(state, scope, resource_server_id)?;
    Ok(state
        .store()
        .management()
        .resource_servers(scope)
        .get(&id)
        .await?)
}

/// Resolve an OAuth client of THIS environment and read its scope allowlist (issue
/// #98), returning both its typed id and the policy.
///
/// The read IS the address resolution, so there is nothing to forget: a caller cannot
/// hold a `ClientId` this function produced without the client having resolved.
///
/// The addressing failures collapse to one answer: a malformed id and one minted in
/// another `(tenant, environment)` fail to parse in scope, and an absent one is the
/// repository's own not-found. There are THREE such failures and not the usual four,
/// for the same reason `resource_servers` has three: `clients` carries no
/// `deleted_at`, so `ActingClientRepo::delete` removes the row outright and a deleted
/// client reads exactly like one that never existed.
///
/// It goes through the NARROW control-plane door
/// ([`ironauth_store::ManagementStore::client_scope_policies`]) rather than a whole
/// [`ironauth_store::ClientRepo`], so this surface can read one column of a client
/// and nothing else.
///
/// For a WRITE it also verifies the ENVIRONMENT is live, for the reason
/// [`resolve_user`] records: a `clients` row survives its environment's soft delete, so
/// `setClientAllowedScopes` LANDED inside a decommissioned environment (MEASURED: 200).
///
/// # Errors
///
/// [`ApiError::NotFound`] if the id is malformed, out of scope, or absent, or, on an
/// [`EnvironmentAccess::Write`], if the environment is absent or soft-deleted.
pub async fn require_client_scope_policy(
    state: &AdminState,
    scope: Scope,
    client_id: &str,
    access: EnvironmentAccess,
) -> Result<(ClientId, ClientScopePolicy), ApiError> {
    if access == EnvironmentAccess::Write {
        require_live_environment(state, &scope).await?;
    }
    let policies = state.store().management().client_scope_policies(scope);
    let id = policies.parse_id(client_id)?;
    let policy = policies.get(&id).await?;
    Ok((id, policy))
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
