// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization group members, role assignments, the membership cascade, and the
//! deterministic resolution engine (issue #97, store PR 3), over a real database
//! (`DATABASE_URL`).
//!
//! This is the PR that closes the store half of the M10 role model, so it pins the
//! properties every later PR of the issue depends on:
//!
//!   * a membership is bound into a group, listed both ways, and unbound; a role is
//!     granted to a group and directly to a membership and withdrawn again, each
//!     audited with the exact delta wire strings;
//!   * every list and every mutation is fenced to ONE organization, proved against a
//!     second organization in the SAME scope holding its own rows;
//!   * every resolve-by-id surface is a uniform not-found for an absent, a removed, a
//!     foreign-organization, and a foreign-scope row alike, and a cross-organization
//!     PAIRING of two individually visible endpoints is refused the same way;
//!   * effective-role resolution is the exact union of direct, group, and
//!     ancestor-inherited roles, deduplicated across paths, byte-stable across
//!     evaluations, and matches an independent in-memory model over randomized
//!     forests;
//!   * resolution TERMINATES and stays correct on a STORED CYCLE through a
//!     soft-deleted node, which the live graph's acyclicity does not rule out;
//!   * removing an org membership REVOKES its group bindings and direct role grants,
//!     and a membership revived by an admin re-add OR by an invitation accept comes
//!     back with none of either;
//!   * the grants are least-privilege: the data plane may never CREATE or REPOINT a
//!     row on any of the three, may only REVOKE on the two the accept-path cascade
//!     has to reach, and stays strictly read only on the third; and no endpoint
//!     column is writable by anybody, on either plane;
//!   * and there is NO cap on members per group, groups per member, or roles per
//!     subject.
//!
//! Cross-tenant and cross-environment isolation is additionally exercised through the
//! registered IDOR probes (`crates/ironauth-admin/tests/idor.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, InvitationCredentialType, MintedInvitationToken, NewAdminUser,
    NewInvitation, NewMembership, NewOrgGroup, NewOrgGroupMember, NewOrgGroupRole,
    NewOrgMembershipRole, NewOrgRole, ORG_GROUP_MAX_DEPTH_CEILING, OrgGroupId, OrgGroupMemberId,
    OrgGroupRoleId, OrgMembershipId, OrgMembershipRoleId, OrgRoleId, OrganizationId, Scope,
    ServiceId, StoreError, UserId, UserState, mint_invitation_token,
};
use sqlx::Row;

/// The Postgres "insufficient privilege" SQLSTATE.
const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// The fan-out the covenant test builds: enough rows to prove nothing counts before
/// writing, small enough to stay inside the test job's time budget.
const WIDE: usize = 40;

/// A valid Argon2id PHC verifier (a fixed one; hashing is exercised in the higher
/// layers, the store only persists the string).
const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";

/// The depth bound most tests pass: the shipped `[organizations] max_group_depth`
/// default. Tests that are ABOUT the bound state their own.
const DEFAULT_DEPTH: u32 = 8;

/// A page size comfortably above anything these tests create. Page size is clamped on
/// every management list; the number of stored rows is not.
const PAGE: i64 = 500;

fn actor(env: &Env) -> ActorRef {
    ActorRef::service(ServiceId::generate(env))
}

/// The current clock-seam time in microseconds since the Unix epoch.
fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Create an organization in `scope` via the control store, returning its id.
async fn create_org(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    display_name: &str,
) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now_micros(env), display_name, None)
        .await
        .expect("create organization");
    id
}

/// Define a group in `org`, optionally under `parent`, returning the new group id.
async fn create_group(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    slug: &str,
    parent: Option<&OrgGroupId>,
) -> OrgGroupId {
    let id = OrgGroupId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_groups(scope)
        .create(
            env,
            NewOrgGroup {
                id: &id,
                organization_id: org,
                parent_id: parent,
                slug,
                display_name: "Group",
                metadata: None,
            },
            now_micros(env),
            ORG_GROUP_MAX_DEPTH_CEILING,
            None,
        )
        .await
        .expect("create group");
    id
}

/// Define a role in `org`, returning the new role id.
async fn create_role(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    slug: &str,
) -> OrgRoleId {
    let id = OrgRoleId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_roles(scope)
        .create(
            env,
            NewOrgRole {
                id: &id,
                organization_id: org,
                slug,
                display_name: "Role",
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create role");
    id
}

/// Create an ACTIVE user in `scope`, returning its id.
async fn create_user(db: &TestDatabase, env: &Env, scope: Scope, identifier: &str) -> UserId {
    db.control_store()
        .scoped(scope)
        .acting(actor(env), CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            NewAdminUser {
                id: None,
                identifier,
                password_hash: Some(PASSWORD_HASH),
                claims_json: None,
                external_id: None,
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create active user")
}

/// Bind `user` into `org`, returning the live membership id.
async fn add_membership(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
) -> Result<OrgMembershipId, StoreError> {
    let id = OrgMembershipId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_memberships(scope)
        .create(
            env,
            NewMembership {
                id: &id,
                organization_id: org,
                user_id: user,
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
}

/// Create a fresh active user and bind it into `org`, returning `(user, membership)`.
async fn create_member(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    identifier: &str,
) -> (UserId, OrgMembershipId) {
    let user = create_user(db, env, scope, identifier).await;
    let membership = add_membership(db, env, scope, org, &user)
        .await
        .expect("bind user into organization");
    (user, membership)
}

/// Bind `membership` into `group`, returning the new binding id (or the store error,
/// so refusal cases can assert on it).
async fn bind_member(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    group: &OrgGroupId,
    membership: &OrgMembershipId,
) -> Result<OrgGroupMemberId, StoreError> {
    let id = OrgGroupMemberId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_group_members(scope)
        .add(
            env,
            NewOrgGroupMember {
                id: &id,
                organization_id: org,
                group_id: group,
                membership_id: membership,
            },
            now_micros(env),
            None,
        )
        .await
        .map(|()| id)
}

/// Grant `role` to `group`, returning the new assignment id.
async fn grant_group_role(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    group: &OrgGroupId,
    role: &OrgRoleId,
) -> Result<OrgGroupRoleId, StoreError> {
    let id = OrgGroupRoleId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_group_roles(scope)
        .assign(
            env,
            NewOrgGroupRole {
                id: &id,
                organization_id: org,
                group_id: group,
                role_id: role,
            },
            now_micros(env),
            None,
        )
        .await
        .map(|()| id)
}

/// Grant `role` directly to `membership`, returning the new assignment id.
async fn grant_direct_role(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    membership: &OrgMembershipId,
    role: &OrgRoleId,
) -> Result<OrgMembershipRoleId, StoreError> {
    let id = OrgMembershipRoleId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_membership_roles(scope)
        .assign(
            env,
            NewOrgMembershipRole {
                id: &id,
                organization_id: org,
                membership_id: membership,
                role_id: role,
            },
            now_micros(env),
            None,
        )
        .await
        .map(|()| id)
}

/// The effective role slugs for `user` in `org`, resolved through the CONTROL plane.
async fn roles_of(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
    depth: u32,
) -> BTreeSet<String> {
    let _ = env;
    db.control_store()
        .management()
        .org_groups(scope)
        .effective_roles(org, user, depth)
        .await
        .expect("resolve effective roles")
}

/// The effective group slugs for `user` in `org`, resolved through the CONTROL plane.
async fn groups_of(
    db: &TestDatabase,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
    depth: u32,
) -> BTreeSet<String> {
    db.control_store()
        .management()
        .org_groups(scope)
        .effective_group_slugs(org, user, depth)
        .await
        .expect("resolve effective groups")
}

/// A `BTreeSet<String>` from string literals, for the expected-set assertions.
fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// The audit actions recorded against `target_id` in `scope`, SORTED.
///
/// Sorted rather than in `(occurred_at, id)` order, and that is deliberate rather
/// than a weakening. Several of the writes under test append TWO audit rows to ONE
/// transaction (the membership cascade row and the membership row it rides with),
/// both stamped from the same clock seam read, so they can legitimately share a
/// microsecond and the tie is then broken by a random id. Asserting the multiset is
/// the strongest claim that is actually true of the data; the per-row facts that DO
/// have a defined order (which target, which detail) are asserted separately.
async fn audit_actions(db: &TestDatabase, scope: Scope, target_id: &str) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT action FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND target_id = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(target_id)
    .fetch_all(db.owner_pool())
    .await
    .expect("read audit rows");
    let mut actions: Vec<String> = rows.iter().map(|r| r.get::<String, _>("action")).collect();
    actions.sort();
    actions
}

/// The `detail` dimensions recorded against `target_id` for one action.
async fn audit_details_for(
    db: &TestDatabase,
    scope: Scope,
    target_id: &str,
    action: &str,
) -> Vec<Option<String>> {
    let rows = sqlx::query(
        "SELECT detail FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND target_id = $3 AND action = $4 \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(target_id)
    .bind(action)
    .fetch_all(db.owner_pool())
    .await
    .expect("read audit details");
    rows.iter()
        .map(|r| r.get::<Option<String>, _>("detail"))
        .collect()
}

/// How many LIVE rows of `table` reference `membership_id`, read through the OWNER
/// pool so nothing hides behind row-level security or behind a repository filter.
async fn live_attachment_count(
    db: &TestDatabase,
    scope: Scope,
    table: &str,
    membership: &OrgMembershipId,
) -> i64 {
    let sql = format!(
        "SELECT COUNT(*) AS n FROM {table} \
         WHERE tenant_id = $1 AND environment_id = $2 AND membership_id = $3 \
         AND deleted_at IS NULL"
    );
    sqlx::query(&sql)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(membership.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("count live attachments")
        .get("n")
}

/// Soft-delete a membership row DIRECTLY, bypassing the repository (and therefore the
/// cascade), through the owner pool.
///
/// This is how the two REVIVE tests construct the state a revive must clean up:
/// "membership dead, attachments still live". Going through the ordinary remove would
/// leave nothing for the revive-site cascade to do, so a revive site that was silently
/// missing would still pass. That state is not hypothetical: it is what rows written
/// by a binary older than this cascade look like, and what any future path that
/// soft-deletes a membership without cascading would produce.
async fn kill_membership_row(db: &TestDatabase, scope: Scope, membership: &OrgMembershipId) {
    sqlx::query(
        "UPDATE org_memberships SET deleted_at = now() \
         WHERE tenant_id = $1 AND environment_id = $2 AND id = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(membership.to_string())
    .execute(db.owner_pool())
    .await
    .expect("soft-delete the membership row out of band");
}

#[tokio::test]
async fn a_membership_is_bound_into_a_group_listed_both_ways_and_unbound() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    let (_, membership) = create_member(&db, &env, scope, &org, "eng@example.test").await;

    let binding = bind_member(&db, &env, scope, &org, &group, &membership)
        .await
        .expect("bind the membership into the group");

    // Readable by id, and by id WITHIN the organization (the nested-route read).
    let record = db
        .control_store()
        .management()
        .org_group_members(scope)
        .get_in_org(&org, &binding)
        .await
        .expect("the binding is readable in its own organization");
    assert_eq!(record.group_id, group);
    assert_eq!(record.membership_id, membership);
    assert_eq!(record.organization_id, org);

    // Listed BOTH ways: who is in this group, and which groups is this member in.
    let members = db
        .control_store()
        .management()
        .org_group_members(scope)
        .list_for_group(&org, &group, PAGE, None)
        .await
        .expect("list the group's members");
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].id, binding);
    let groups = db
        .control_store()
        .management()
        .org_group_members(scope)
        .list_for_membership(&org, &membership, PAGE, None)
        .await
        .expect("list the membership's groups");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].id, binding);

    // A duplicate bind of a pair that is already LIVE is the typed conflict, never a
    // second row.
    assert!(matches!(
        bind_member(&db, &env, scope, &org, &group, &membership).await,
        Err(StoreError::Conflict)
    ));

    // Unbind, and everything about it reads as absent again.
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_group_members(scope)
        .remove(&env, &org, &binding)
        .await
        .expect("unbind");
    assert!(matches!(
        db.control_store()
            .management()
            .org_group_members(scope)
            .get_in_org(&org, &binding)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(
        db.control_store()
            .management()
            .org_group_members(scope)
            .list_for_group(&org, &group, PAGE, None)
            .await
            .expect("list after unbind")
            .is_empty()
    );
    // A repeat unbind matches no live row and is the uniform not-found.
    assert!(matches!(
        db.control_store()
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_group_members(scope)
            .remove(&env, &org, &binding)
            .await,
        Err(StoreError::NotFound)
    ));
    // The freed pair is immediately re-bindable, as a FRESH row with a fresh id: a
    // removed binding is never revived, so the removal's audit history stands.
    let rebound = bind_member(&db, &env, scope, &org, &group, &membership)
        .await
        .expect("the freed pair is available again");
    assert_ne!(rebound, binding, "a re-bind is a fresh row, not a revival");

    // The exact delta vocabulary, per target.
    assert_eq!(
        audit_actions(&db, scope, &binding.to_string()).await,
        vec![
            "organization.group.member.add".to_owned(),
            "organization.group.member.remove".to_owned(),
        ]
    );
    assert_eq!(
        audit_actions(&db, scope, &rebound.to_string()).await,
        vec!["organization.group.member.add".to_owned()]
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one assignment surface's whole lifecycle stated twice (group-inherited and \
              direct), against ONE fixture, so the two cannot drift apart"
)]
async fn a_role_is_granted_to_a_group_and_to_a_membership_and_withdrawn() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    let role = create_role(&db, &env, scope, &org, "deployer").await;
    let (_, membership) = create_member(&db, &env, scope, &org, "eng@example.test").await;

    let group_grant = grant_group_role(&db, &env, scope, &org, &group, &role)
        .await
        .expect("grant the role to the group");
    let direct_grant = grant_direct_role(&db, &env, scope, &org, &membership, &role)
        .await
        .expect("grant the role directly");

    // Both are readable in their organization and listed from BOTH ends.
    assert_eq!(
        db.control_store()
            .management()
            .org_group_roles(scope)
            .get_in_org(&org, &group_grant)
            .await
            .expect("read the group grant")
            .role_id,
        role
    );
    assert_eq!(
        db.control_store()
            .management()
            .org_group_roles(scope)
            .list_for_group(&org, &group, PAGE, None)
            .await
            .expect("list the group's roles")
            .len(),
        1
    );
    assert_eq!(
        db.control_store()
            .management()
            .org_group_roles(scope)
            .list_for_role(&org, &role, PAGE, None)
            .await
            .expect("list the role's groups")
            .len(),
        1,
        "the blast-radius list an operator wants before deleting a role"
    );
    assert_eq!(
        db.control_store()
            .management()
            .org_membership_roles(scope)
            .list_for_membership(&org, &membership, PAGE, None)
            .await
            .expect("list the membership's direct roles")
            .len(),
        1
    );
    assert_eq!(
        db.control_store()
            .management()
            .org_membership_roles(scope)
            .list_for_role(&org, &role, PAGE, None)
            .await
            .expect("list the role's direct holders")
            .len(),
        1
    );

    // Duplicates on either surface are the typed conflict.
    assert!(matches!(
        grant_group_role(&db, &env, scope, &org, &group, &role).await,
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        grant_direct_role(&db, &env, scope, &org, &membership, &role).await,
        Err(StoreError::Conflict)
    ));

    // Withdraw both.
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_group_roles(scope)
        .unassign(&env, &org, &group_grant)
        .await
        .expect("withdraw the group grant");
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_membership_roles(scope)
        .unassign(&env, &org, &direct_grant)
        .await
        .expect("withdraw the direct grant");
    for repeat in [
        db.control_store()
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_group_roles(scope)
            .unassign(&env, &org, &group_grant)
            .await,
        db.control_store()
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_membership_roles(scope)
            .unassign(&env, &org, &direct_grant)
            .await,
    ] {
        assert!(
            matches!(repeat, Err(StoreError::NotFound)),
            "a repeat unassign matches no live row and is the uniform not-found"
        );
    }
    // Both pairs are free again, and re-granting inserts FRESH rows.
    assert_ne!(
        grant_group_role(&db, &env, scope, &org, &group, &role)
            .await
            .expect("re-grant to the group"),
        group_grant
    );
    assert_ne!(
        grant_direct_role(&db, &env, scope, &org, &membership, &role)
            .await
            .expect("re-grant directly"),
        direct_grant
    );

    assert_eq!(
        audit_actions(&db, scope, &group_grant.to_string()).await,
        vec![
            "organization.group.role.assign".to_owned(),
            "organization.group.role.unassign".to_owned(),
        ]
    );
    assert_eq!(
        audit_actions(&db, scope, &direct_grant.to_string()).await,
        vec![
            "organization.membership.role.assign".to_owned(),
            "organization.membership.role.unassign".to_owned(),
        ]
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the organization-containment contract of all three tables, stated once \
              against one second organization in the SAME scope so a single missing \
              organization predicate anywhere cannot hide"
)]
async fn every_list_and_mutation_is_fenced_to_its_own_organization() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // TWO organizations in ONE scope. Row-level security fences (tenant,
    // environment) and nothing finer, so this is the pair that catches a missing
    // organization predicate; a cross-SCOPE test cannot, because the policy would
    // refuse it no matter how wide the app-layer filter was.
    let alpha = create_org(&db, &env, scope, "Alpha").await;
    let beta = create_org(&db, &env, scope, "Beta").await;

    let alpha_group = create_group(&db, &env, scope, &alpha, "team", None).await;
    let beta_group = create_group(&db, &env, scope, &beta, "team", None).await;
    let alpha_role = create_role(&db, &env, scope, &alpha, "admin").await;
    let beta_role = create_role(&db, &env, scope, &beta, "admin").await;
    let (_, alpha_member) = create_member(&db, &env, scope, &alpha, "a@example.test").await;
    let (_, beta_member) = create_member(&db, &env, scope, &beta, "b@example.test").await;

    let alpha_binding = bind_member(&db, &env, scope, &alpha, &alpha_group, &alpha_member)
        .await
        .expect("bind in alpha");
    let beta_binding = bind_member(&db, &env, scope, &beta, &beta_group, &beta_member)
        .await
        .expect("bind in beta");
    let alpha_grant = grant_group_role(&db, &env, scope, &alpha, &alpha_group, &alpha_role)
        .await
        .expect("grant in alpha");
    let beta_grant = grant_group_role(&db, &env, scope, &beta, &beta_group, &beta_role)
        .await
        .expect("grant in beta");
    let alpha_direct = grant_direct_role(&db, &env, scope, &alpha, &alpha_member, &alpha_role)
        .await
        .expect("direct grant in alpha");
    let beta_direct = grant_direct_role(&db, &env, scope, &beta, &beta_member, &beta_role)
        .await
        .expect("direct grant in beta");

    let management = db.control_store();
    // Every LIST returns EXACTLY its own organization's set, addressed by its own
    // organization. Addressed by the OTHER organization it returns nothing, which is
    // what proves the organization is part of the address and not a decoration.
    for (org, group, membership, role, binding, grant, direct) in [
        (
            &alpha,
            &alpha_group,
            &alpha_member,
            &alpha_role,
            &alpha_binding,
            &alpha_grant,
            &alpha_direct,
        ),
        (
            &beta,
            &beta_group,
            &beta_member,
            &beta_role,
            &beta_binding,
            &beta_grant,
            &beta_direct,
        ),
    ] {
        let other = if org == &alpha { &beta } else { &alpha };
        let members = management.management().org_group_members(scope);
        assert_eq!(
            members
                .list_for_group(org, group, PAGE, None)
                .await
                .expect("list")
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![*binding]
        );
        assert!(
            members
                .list_for_group(other, group, PAGE, None)
                .await
                .expect("list under the wrong organization")
                .is_empty(),
            "a group listed under a SIBLING organization must return nothing"
        );
        assert_eq!(
            members
                .list_for_membership(org, membership, PAGE, None)
                .await
                .expect("list")
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![*binding]
        );
        assert!(
            members
                .list_for_membership(other, membership, PAGE, None)
                .await
                .expect("list under the wrong organization")
                .is_empty()
        );
        let group_roles = management.management().org_group_roles(scope);
        assert_eq!(
            group_roles
                .list_for_group(org, group, PAGE, None)
                .await
                .expect("list")
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![*grant]
        );
        assert!(
            group_roles
                .list_for_group(other, group, PAGE, None)
                .await
                .expect("list under the wrong organization")
                .is_empty()
        );
        assert_eq!(
            group_roles
                .list_for_role(org, role, PAGE, None)
                .await
                .expect("list")
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![*grant]
        );
        assert!(
            group_roles
                .list_for_role(other, role, PAGE, None)
                .await
                .expect("list under the wrong organization")
                .is_empty()
        );
        let direct_roles = management.management().org_membership_roles(scope);
        assert_eq!(
            direct_roles
                .list_for_membership(org, membership, PAGE, None)
                .await
                .expect("list")
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![*direct]
        );
        assert!(
            direct_roles
                .list_for_membership(other, membership, PAGE, None)
                .await
                .expect("list under the wrong organization")
                .is_empty()
        );
        assert_eq!(
            direct_roles
                .list_for_role(org, role, PAGE, None)
                .await
                .expect("list")
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec![*direct]
        );
        assert!(
            direct_roles
                .list_for_role(other, role, PAGE, None)
                .await
                .expect("list under the wrong organization")
                .is_empty()
        );
        // Every resolve-by-id in the wrong organization is the uniform not-found.
        assert!(matches!(
            members.get_in_org(other, binding).await,
            Err(StoreError::NotFound)
        ));
        assert!(matches!(
            group_roles.get_in_org(other, grant).await,
            Err(StoreError::NotFound)
        ));
        assert!(matches!(
            direct_roles.get_in_org(other, direct).await,
            Err(StoreError::NotFound)
        ));
    }

    // Every MUTATION addressed through the wrong organization is refused, and the
    // victim row survives. This is the assertion PR 2's review found genuinely
    // missing on a sibling method: a removal whose organization predicate is absent
    // succeeds, and nothing about the caller's own organization looks wrong.
    let acting = management
        .management()
        .acting(actor(&env), CorrelationId::generate(&env));
    assert!(matches!(
        acting
            .org_group_members(scope)
            .remove(&env, &alpha, &beta_binding)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        acting
            .org_group_roles(scope)
            .unassign(&env, &alpha, &beta_grant)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        acting
            .org_membership_roles(scope)
            .unassign(&env, &alpha, &beta_direct)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(
        management
            .management()
            .org_group_members(scope)
            .get_in_org(&beta, &beta_binding)
            .await
            .is_ok(),
        "beta's binding must survive alpha's attempt to remove it"
    );
    assert!(
        management
            .management()
            .org_group_roles(scope)
            .get_in_org(&beta, &beta_grant)
            .await
            .is_ok(),
        "beta's group grant must survive alpha's attempt to withdraw it"
    );
    assert!(
        management
            .management()
            .org_membership_roles(scope)
            .get_in_org(&beta, &beta_direct)
            .await
            .is_ok(),
        "beta's direct grant must survive alpha's attempt to withdraw it"
    );

    // A cross-organization PAIRING of two endpoints the caller CAN see is refused
    // the same way, on every write. This is the case the foreign keys cannot catch:
    // both rows really exist, and the id-only keys are satisfied.
    assert!(matches!(
        bind_member(&db, &env, scope, &alpha, &beta_group, &alpha_member).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        bind_member(&db, &env, scope, &alpha, &alpha_group, &beta_member).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        grant_group_role(&db, &env, scope, &alpha, &alpha_group, &beta_role).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        grant_group_role(&db, &env, scope, &alpha, &beta_group, &alpha_role).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        grant_direct_role(&db, &env, scope, &alpha, &alpha_member, &beta_role).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        grant_direct_role(&db, &env, scope, &alpha, &beta_member, &alpha_role).await,
        Err(StoreError::NotFound)
    ));

    // Resolution itself is organization-fenced: alpha's member holds alpha's role and
    // NOTHING of beta's, even though both organizations named their role "admin".
    let alpha_user = management
        .management()
        .org_memberships(scope)
        .get(&alpha_member)
        .await
        .expect("read alpha's membership")
        .user_id;
    assert_eq!(
        roles_of(&db, &env, scope, &alpha, &alpha_user, DEFAULT_DEPTH).await,
        set(&["admin"])
    );
    assert!(
        roles_of(&db, &env, scope, &beta, &alpha_user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "alpha's user is not a member of beta and resolves to nothing there"
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the anti-oracle uniformity contract of every resolve-by-id and every write \
              in the PR, against one fixture that really holds an absent, a removed, \
              a foreign-organization, and a foreign-scope row of each kind"
)]
async fn absent_removed_foreign_org_and_foreign_scope_rows_are_indistinguishable() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other_scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let sibling = create_org(&db, &env, scope, "Sibling").await;
    let group = create_group(&db, &env, scope, &org, "team", None).await;
    let role = create_role(&db, &env, scope, &org, "admin").await;
    let (_, membership) = create_member(&db, &env, scope, &org, "m@example.test").await;
    let binding = bind_member(&db, &env, scope, &org, &group, &membership)
        .await
        .expect("bind");
    let grant = grant_group_role(&db, &env, scope, &org, &group, &role)
        .await
        .expect("grant");
    let direct = grant_direct_role(&db, &env, scope, &org, &membership, &role)
        .await
        .expect("direct grant");

    // A row in ANOTHER organization of the same scope: plant real victims there.
    let sibling_group = create_group(&db, &env, scope, &sibling, "team", None).await;
    let sibling_role = create_role(&db, &env, scope, &sibling, "admin").await;
    let (_, sibling_member) = create_member(&db, &env, scope, &sibling, "s@example.test").await;
    let sibling_binding = bind_member(&db, &env, scope, &sibling, &sibling_group, &sibling_member)
        .await
        .expect("bind in the sibling");

    // Remove one of each so "soft-deleted" is a real case rather than a hypothesis.
    let acting = db
        .control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env));
    acting
        .org_group_members(scope)
        .remove(&env, &org, &binding)
        .await
        .expect("unbind");
    acting
        .org_group_roles(scope)
        .unassign(&env, &org, &grant)
        .await
        .expect("withdraw");
    acting
        .org_membership_roles(scope)
        .unassign(&env, &org, &direct)
        .await
        .expect("withdraw direct");

    let members = db.control_store().management().org_group_members(scope);
    let group_roles = db.control_store().management().org_group_roles(scope);
    let direct_roles = db.control_store().management().org_membership_roles(scope);

    // Four cases, one answer, on every surface: ABSENT, SOFT-DELETED, FOREIGN
    // ORGANIZATION, FOREIGN SCOPE.
    let absent_binding = OrgGroupMemberId::generate(&env, &scope);
    let foreign_binding = OrgGroupMemberId::generate(&env, &other_scope);
    for candidate in [
        &absent_binding,
        &binding,
        &sibling_binding,
        &foreign_binding,
    ] {
        assert!(
            matches!(
                members.get_in_org(&org, candidate).await,
                Err(StoreError::NotFound)
            ),
            "absent, removed, foreign-organization, and foreign-scope bindings must be \
             indistinguishable"
        );
        assert!(matches!(
            acting
                .org_group_members(scope)
                .remove(&env, &org, candidate)
                .await,
            Err(StoreError::NotFound)
        ));
    }
    // A foreign-scope id does not even PARSE in this scope, which is the earliest and
    // most uniform refusal of the four.
    assert!(matches!(
        members.parse_id(&foreign_binding.to_string()),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        group_roles.parse_id(&OrgGroupRoleId::generate(&env, &other_scope).to_string()),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        direct_roles.parse_id(&OrgMembershipRoleId::generate(&env, &other_scope).to_string()),
        Err(StoreError::NotFound)
    ));

    let absent_grant = OrgGroupRoleId::generate(&env, &scope);
    for candidate in [&absent_grant, &grant] {
        assert!(matches!(
            group_roles.get_in_org(&org, candidate).await,
            Err(StoreError::NotFound)
        ));
        assert!(matches!(
            acting
                .org_group_roles(scope)
                .unassign(&env, &org, candidate)
                .await,
            Err(StoreError::NotFound)
        ));
    }
    let absent_direct = OrgMembershipRoleId::generate(&env, &scope);
    for candidate in [&absent_direct, &direct] {
        assert!(matches!(
            direct_roles.get_in_org(&org, candidate).await,
            Err(StoreError::NotFound)
        ));
        assert!(matches!(
            acting
                .org_membership_roles(scope)
                .unassign(&env, &org, candidate)
                .await,
            Err(StoreError::NotFound)
        ));
    }

    // Binding into a group that is absent, soft-deleted, or another organization's is
    // ALSO the uniform not-found, so a bind probe is not an existence oracle either.
    let deleted_group = create_group(&db, &env, scope, &org, "gone", None).await;
    acting
        .org_groups(scope)
        .delete(&env, &org, &deleted_group)
        .await
        .expect("delete the group");
    for candidate in [
        OrgGroupId::generate(&env, &scope),
        deleted_group,
        sibling_group,
    ] {
        assert!(matches!(
            bind_member(&db, &env, scope, &org, &candidate, &membership).await,
            Err(StoreError::NotFound)
        ));
        assert!(matches!(
            grant_group_role(&db, &env, scope, &org, &candidate, &role).await,
            Err(StoreError::NotFound)
        ));
    }
    for candidate in [OrgRoleId::generate(&env, &scope), sibling_role] {
        assert!(matches!(
            grant_direct_role(&db, &env, scope, &org, &membership, &candidate).await,
            Err(StoreError::NotFound)
        ));
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the resolution contract read as one story: direct only, then group, then \
              ancestor, then the union, then deduplication, then determinism, each \
              step building on the last fixture"
)]
async fn resolution_is_the_union_of_direct_group_and_ancestor_roles() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    // all-staff -> engineering -> platform, a three-level chain.
    let all_staff = create_group(&db, &env, scope, &org, "all-staff", None).await;
    let engineering = create_group(&db, &env, scope, &org, "engineering", Some(&all_staff)).await;
    let platform = create_group(&db, &env, scope, &org, "platform", Some(&engineering)).await;
    let unrelated = create_group(&db, &env, scope, &org, "sales", None).await;

    let staff_role = create_role(&db, &env, scope, &org, "staff").await;
    let eng_role = create_role(&db, &env, scope, &org, "engineer").await;
    let platform_role = create_role(&db, &env, scope, &org, "platform-oncall").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;
    let sales_role = create_role(&db, &env, scope, &org, "seller").await;
    let unassigned_role = create_role(&db, &env, scope, &org, "nobody").await;

    for (group, role) in [
        (&all_staff, &staff_role),
        (&engineering, &eng_role),
        (&platform, &platform_role),
        (&unrelated, &sales_role),
    ] {
        grant_group_role(&db, &env, scope, &org, group, role)
            .await
            .expect("grant");
    }

    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    // 1. Direct only.
    grant_direct_role(&db, &env, scope, &org, &membership, &direct_role)
        .await
        .expect("direct grant");
    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["founder"]),
        "a member in no group holds exactly their direct roles"
    );
    assert!(
        groups_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a member in no group has an empty group closure"
    );

    // 2. Group and ANCESTOR inherited: binding into the LEAF grants the whole chain.
    bind_member(&db, &env, scope, &org, &platform, &membership)
        .await
        .expect("bind into the leaf");
    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["engineer", "founder", "platform-oncall", "staff"]),
        "the union of direct, own-group, and ANCESTOR-inherited roles, and nothing else"
    );
    assert_eq!(
        groups_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["all-staff", "engineering", "platform"]),
        "the group closure is the flattened ancestor chain"
    );
    // The unrelated branch is not reachable, so its role never appears; neither does
    // a role nobody was granted.
    let resolved = roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await;
    assert!(!resolved.contains("seller"));
    assert!(!resolved.contains("nobody"));
    let _ = unassigned_role;

    // 3. The SAME role reachable by SEVERAL paths collapses to exactly one entry.
    grant_group_role(&db, &env, scope, &org, &unrelated, &staff_role)
        .await
        .expect("grant the staff role to a second group too");
    bind_member(&db, &env, scope, &org, &unrelated, &membership)
        .await
        .expect("bind into the second group as well");
    grant_direct_role(&db, &env, scope, &org, &membership, &staff_role)
        .await
        .expect("and grant it directly as well");
    let three_ways = roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await;
    assert_eq!(
        three_ways,
        set(&["engineer", "founder", "platform-oncall", "seller", "staff"]),
        "a role held directly AND through two groups is still one entry"
    );

    // 4. Determinism: repeated evaluation against unchanged state is byte-identical.
    for _ in 0..5 {
        assert_eq!(
            roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
            three_ways,
            "two evaluations against identical stored state must be identical"
        );
    }
    assert_eq!(
        three_ways.iter().cloned().collect::<Vec<_>>(),
        vec![
            "engineer".to_owned(),
            "founder".to_owned(),
            "platform-oncall".to_owned(),
            "seller".to_owned(),
            "staff".to_owned(),
        ],
        "the set's iteration order is the total slug order a token claim will serialize"
    );

    // 5. The DATA plane resolves identically. This is the plane the mint path runs on,
    // and it holds SELECT and nothing else on all five tables.
    assert_eq!(
        db.store()
            .scoped(scope)
            .org_groups()
            .effective_roles(&org, &user, DEFAULT_DEPTH)
            .await
            .expect("the data plane can resolve"),
        three_ways
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one exclusion rule per soft-deletable row on the resolution path, \
              asserted against ONE fixture so the five rules cannot be tested \
              against five different graphs"
)]
async fn resolution_excludes_every_soft_deleted_row_on_the_path() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let parent = create_group(&db, &env, scope, &org, "all-staff", None).await;
    let child = create_group(&db, &env, scope, &org, "engineering", Some(&parent)).await;

    let parent_role = create_role(&db, &env, scope, &org, "staff").await;
    let child_role = create_role(&db, &env, scope, &org, "engineer").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;

    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    let binding = bind_member(&db, &env, scope, &org, &child, &membership)
        .await
        .expect("bind");
    let parent_grant = grant_group_role(&db, &env, scope, &org, &parent, &parent_role)
        .await
        .expect("grant to the parent");
    let child_grant = grant_group_role(&db, &env, scope, &org, &child, &child_role)
        .await
        .expect("grant to the child");
    let direct_grant = grant_direct_role(&db, &env, scope, &org, &membership, &direct_role)
        .await
        .expect("direct grant");

    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["engineer", "founder", "staff"]),
        "the baseline every exclusion below is measured against"
    );

    let acting = db
        .control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env));

    // 1. A soft-deleted ASSIGNMENT drops its role.
    acting
        .org_membership_roles(scope)
        .unassign(&env, &org, &direct_grant)
        .await
        .expect("withdraw the direct grant");
    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["engineer", "staff"])
    );

    // 2. A soft-deleted ROLE drops out even while its assignment row is still live.
    acting
        .org_roles(scope)
        .delete(&env, &child_role)
        .await
        .expect("delete the child's role");
    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["staff"]),
        "a deleted role is excluded even though org_group_roles still names it"
    );

    // 3. A soft-deleted ANCESTOR GROUP detaches, so its role stops being inherited.
    acting
        .org_groups(scope)
        .delete(&env, &org, &parent)
        .await
        .expect("delete the ancestor");
    assert!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a deleted ancestor is invisible to the walk, so nothing is inherited through it"
    );
    assert_eq!(
        groups_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["engineering"]),
        "the child survives as a ROOT: a delete DETACHES, it does not cascade"
    );

    // 4. A soft-deleted BINDING empties the closure entirely.
    let _ = (parent_grant, child_grant);
    acting
        .org_group_members(scope)
        .remove(&env, &org, &binding)
        .await
        .expect("unbind");
    assert!(
        groups_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty()
    );

    // 5. A soft-deleted MEMBERSHIP resolves to the empty set, not an error. Rebuild a
    // live grant first so the assertion is about the membership and not about there
    // being nothing left to find.
    let fresh_role = create_role(&db, &env, scope, &org, "auditor").await;
    grant_direct_role(&db, &env, scope, &org, &membership, &fresh_role)
        .await
        .expect("grant a fresh direct role");
    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["auditor"])
    );
    acting
        .org_memberships(scope)
        .remove(&env, &membership)
        .await
        .expect("remove the membership");
    assert!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a user with no live membership resolves to the EMPTY set, never an error"
    );
    // And a user who never had a membership at all is the same answer, so the two are
    // indistinguishable.
    let stranger = create_user(&db, &env, scope, "stranger@example.test").await;
    assert!(
        roles_of(&db, &env, scope, &org, &stranger, DEFAULT_DEPTH)
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn resolution_ignores_a_binding_into_a_dead_group_and_a_dead_membership() {
    // The two liveness filters the ordinary lifecycle cannot exercise, because the
    // repository's own cascades tidy up behind themselves: a binding whose GROUP was
    // deleted (the binding row itself stays live, since a group delete DETACHES) and
    // a MEMBERSHIP soft-deleted while its attachments are still live (which is what
    // rows written by a binary older than the attachment cascade look like). Both are
    // reachable states, and each is guarded by exactly one predicate in the seed arm
    // of the resolution walk.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    let group_role = create_role(&db, &env, scope, &org, "engineer").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;
    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    grant_group_role(&db, &env, scope, &org, &group, &group_role)
        .await
        .expect("grant to the group");
    bind_member(&db, &env, scope, &org, &group, &membership)
        .await
        .expect("bind");
    grant_direct_role(&db, &env, scope, &org, &membership, &direct_role)
        .await
        .expect("direct grant");
    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["engineer", "founder"]),
        "the baseline both exclusions below are measured against"
    );

    // 1. The group is DELETED while the binding stays LIVE. A group delete detaches
    // rather than cascading, so this is the ordinary post-delete state, and only the
    // seed arm's liveness filter keeps the dead group (and its still-live role grant)
    // out of the answer.
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_groups(scope)
        .delete(&env, &org, &group)
        .await
        .expect("delete the group the member is bound into");
    assert_eq!(
        live_attachment_count(&db, scope, "org_group_members", &membership).await,
        1,
        "the binding row is untouched by the group delete: a delete DETACHES"
    );
    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["founder"]),
        "a binding into a DELETED group contributes nothing"
    );
    assert!(
        groups_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "and the dead group is not in the closure either"
    );

    // 2. The MEMBERSHIP is soft-deleted with its attachments left live. The membership
    // predicate is the only thing standing between a removed user and their old roles.
    kill_membership_row(&db, scope, &membership).await;
    assert_eq!(
        live_attachment_count(&db, scope, "org_membership_roles", &membership).await,
        1,
        "the fixture keeps the direct grant LIVE, so only the membership filter can \
         exclude it"
    );
    assert!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a user with no live membership resolves to nothing, whatever rows still name them"
    );
}

#[tokio::test]
async fn resolution_terminates_and_stays_correct_on_a_stored_cycle_through_a_dead_node() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    // The worked example from the group delete's documentation: a live root `r`, its
    // child `a`, and `a`'s child `b`. Delete `a`, then reparent `r` under `b`. Reading
    // each STORED parent_id as an arrow, the pointers are now r -> b, b -> a, a -> r:
    // a cycle. The LIVE graph is just `r` hanging under the root `b`, which is a
    // forest, and that is the graph every walk must traverse.
    let r = create_group(&db, &env, scope, &org, "r", None).await;
    let a = create_group(&db, &env, scope, &org, "a", Some(&r)).await;
    let b = create_group(&db, &env, scope, &org, "b", Some(&a)).await;

    let r_role = create_role(&db, &env, scope, &org, "role-r").await;
    let a_role = create_role(&db, &env, scope, &org, "role-a").await;
    let b_role = create_role(&db, &env, scope, &org, "role-b").await;
    for (group, role) in [(&r, &r_role), (&a, &a_role), (&b, &b_role)] {
        grant_group_role(&db, &env, scope, &org, group, role)
            .await
            .expect("grant");
    }

    let acting = db
        .control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env));
    acting
        .org_groups(scope)
        .delete(&env, &org, &a)
        .await
        .expect("delete the middle group");
    acting
        .org_groups(scope)
        .reparent(&env, &org, &r, Some(&b), ORG_GROUP_MAX_DEPTH_CEILING)
        .await
        .expect("the reparent is admissible: `b` is a root in the LIVE graph");

    // The stored pointers really do form a cycle. Read them raw, through the owner
    // pool, so this is a fact about the rows and not about what a repository projects.
    let stored: BTreeMap<String, Option<String>> = sqlx::query(
        "SELECT id, parent_id FROM org_groups \
         WHERE tenant_id = $1 AND environment_id = $2 AND organization_id = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(org.to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read stored edges")
    .iter()
    .map(|row| {
        (
            row.get::<String, _>("id"),
            row.get::<Option<String>, _>("parent_id"),
        )
    })
    .collect();
    assert_eq!(stored.get(&r.to_string()), Some(&Some(b.to_string())));
    assert_eq!(stored.get(&b.to_string()), Some(&Some(a.to_string())));
    assert_eq!(stored.get(&a.to_string()), Some(&Some(r.to_string())));

    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    bind_member(&db, &env, scope, &org, &r, &membership)
        .await
        .expect("bind into r");

    // Resolution TERMINATES (this test completing at all is that assertion) and
    // returns the LIVE-graph answer: r and its live ancestor b, never the dead a. A
    // walk that dropped the liveness filter would ride the stored cycle and either
    // hang or hand `role-a` to a member of a group whose grant was detached.
    for depth in [DEFAULT_DEPTH, ORG_GROUP_MAX_DEPTH_CEILING] {
        assert_eq!(
            roles_of(&db, &env, scope, &org, &user, depth).await,
            set(&["role-b", "role-r"]),
            "the stored cycle must not leak the dead group's role at depth {depth}"
        );
        assert_eq!(
            groups_of(&db, scope, &org, &user, depth).await,
            set(&["b", "r"])
        );
    }
}

#[tokio::test]
async fn the_read_walk_truncates_at_the_bound_where_the_write_walk_refuses() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    // A chain of six groups built at the CEILING, then read back under a much lower
    // bound: exactly what an operator LOWERING max_group_depth on a populated
    // environment leaves behind. The write path would refuse to extend this; the read
    // path must truncate rather than refuse, because refusing would turn a data defect
    // into an authentication outage.
    let mut chain: Vec<OrgGroupId> = Vec::new();
    for level in 0..6 {
        let parent = chain.last().copied();
        let group = create_group(
            &db,
            &env,
            scope,
            &org,
            &format!("level-{level}"),
            parent.as_ref(),
        )
        .await;
        let role = create_role(&db, &env, scope, &org, &format!("role-{level}")).await;
        grant_group_role(&db, &env, scope, &org, &group, &role)
            .await
            .expect("grant");
        chain.push(group);
    }
    let leaf = *chain.last().expect("the chain is nonempty");

    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    bind_member(&db, &env, scope, &org, &leaf, &membership)
        .await
        .expect("bind into the deepest group");

    // At the full bound, every level is reachable.
    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["role-0", "role-1", "role-2", "role-3", "role-4", "role-5"])
    );
    // At a bound of 2, the walk sees the seed and two ancestors and then stops: the
    // deepest three levels are the only ones that survive.
    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, 2).await,
        set(&["role-3", "role-4", "role-5"]),
        "the read walk truncates at the bound instead of refusing or looping"
    );
    // At a bound of 0, only the group the member is actually IN contributes.
    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, 0).await,
        set(&["role-5"]),
        "a bound of zero means flat groups only, never unlimited"
    );
    // Truncation can only ever OMIT roles, never invent one: every truncated answer is
    // a subset of the full one.
    let full = roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await;
    for bound in 0..DEFAULT_DEPTH {
        assert!(
            roles_of(&db, &env, scope, &org, &user, bound)
                .await
                .is_subset(&full),
            "the answer at bound {bound} must be a subset of the unbounded answer"
        );
    }
}

/// How many randomized forests the resolution property sweeps.
const FORESTS: usize = 6;
/// How many groups each randomized forest holds.
const GROUPS: usize = 10;
/// How many roles each randomized forest's organization defines.
const ROLES: usize = 6;
/// The depth bound the randomized property resolves under. Deliberately BELOW the
/// depth some generated chains reach, so the sweep covers truncation as well.
const DEPTH: u32 = 4;

/// A deterministic `SplitMix64` stream, seeded from a hard-coded constant so a failure
/// in CI is reproducible from the log alone.
///
/// A file-local generator rather than a crate: the workspace has no property-testing
/// dependency, and `scripts/invariant-lints.sh` bans the `rand` family outright so
/// randomness in tests is always seeded and replayable. This mirrors the convention
/// the parse-fuzz corpora and the group hierarchy properties already follow.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`. `bound` must be nonzero.
    fn below(&mut self, bound: usize) -> usize {
        let bound_u64 = u64::try_from(bound).expect("bound fits u64");
        usize::try_from(self.next_u64() % bound_u64).expect("modulus fits usize")
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one randomized-forest property: the generator, the independent \
              in-memory model, and the comparison belong together or the model \
              stops being independent"
)]
async fn resolution_matches_an_independent_model_over_randomized_forests() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // A modest iteration count on purpose: this property needs a real database (the
    // whole point is the SQL), and every database test in this suite spins its own
    // cluster against a CI job already near its time ceiling. The pure hierarchy
    // properties that need no database sweep thousands of cases in the unit lane.
    let mut rng = Rng(0x5eed_0097_0003_0001);

    for forest in 0..FORESTS {
        let org = create_org(&db, &env, scope, &format!("Org {forest}")).await;

        // A random forest. Node `i` may only parent to a node with a SMALLER index,
        // so it is acyclic by construction and the model below cannot loop; a
        // generator that could emit a cycle would make a failure ambiguous between
        // the generator and the code under test. A quarter of the nodes are roots so
        // this is a forest and not one deep chain.
        let mut parent_of: Vec<Option<usize>> = Vec::with_capacity(GROUPS);
        let mut group_ids: Vec<OrgGroupId> = Vec::with_capacity(GROUPS);
        for index in 0..GROUPS {
            let parent = if index == 0 || rng.below(4) == 0 {
                None
            } else {
                Some(rng.below(index))
            };
            let parent_id = parent.map(|p| group_ids[p]);
            let id = create_group(
                &db,
                &env,
                scope,
                &org,
                &format!("g{index}"),
                parent_id.as_ref(),
            )
            .await;
            parent_of.push(parent);
            group_ids.push(id);
        }

        let mut role_ids: Vec<OrgRoleId> = Vec::with_capacity(ROLES);
        for index in 0..ROLES {
            role_ids.push(create_role(&db, &env, scope, &org, &format!("r{index}")).await);
        }

        // Random grants to groups, and a random direct grant set.
        let mut group_grants: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for group in 0..GROUPS {
            for role in 0..ROLES {
                if rng.below(5) == 0 {
                    group_grants.entry(group).or_default().insert(role);
                }
            }
        }
        for (group, roles) in &group_grants {
            for role in roles {
                grant_group_role(&db, &env, scope, &org, &group_ids[*group], &role_ids[*role])
                    .await
                    .expect("grant to group");
            }
        }

        let (user, membership) =
            create_member(&db, &env, scope, &org, &format!("u{forest}@example.test")).await;

        let mut direct: BTreeSet<usize> = BTreeSet::new();
        for role in 0..ROLES {
            if rng.below(4) == 0 {
                direct.insert(role);
            }
        }
        for role in &direct {
            grant_direct_role(&db, &env, scope, &org, &membership, &role_ids[*role])
                .await
                .expect("direct grant");
        }

        let mut bound_groups: BTreeSet<usize> = BTreeSet::new();
        for group in 0..GROUPS {
            if rng.below(3) == 0 {
                bound_groups.insert(group);
            }
        }
        for group in &bound_groups {
            bind_member(&db, &env, scope, &org, &group_ids[*group], &membership)
                .await
                .expect("bind");
        }

        // The independent model: walk each bound group's parent chain in memory,
        // bounded exactly as the SQL is, and union the roles. It shares no code with
        // the query under test.
        let mut expected_groups: BTreeSet<usize> = BTreeSet::new();
        for seed in &bound_groups {
            let mut node = Some(*seed);
            let mut depth = 0_u32;
            while let Some(current) = node {
                expected_groups.insert(current);
                if depth >= DEPTH {
                    break;
                }
                depth += 1;
                node = parent_of[current];
            }
        }
        let mut expected_roles: BTreeSet<String> = direct.iter().map(|r| format!("r{r}")).collect();
        for group in &expected_groups {
            if let Some(roles) = group_grants.get(group) {
                for role in roles {
                    expected_roles.insert(format!("r{role}"));
                }
            }
        }
        let expected_group_slugs: BTreeSet<String> =
            expected_groups.iter().map(|g| format!("g{g}")).collect();

        let resolved = roles_of(&db, &env, scope, &org, &user, DEPTH).await;
        assert_eq!(
            resolved, expected_roles,
            "forest {forest} (seeded run, parents={parent_of:?}, bound={bound_groups:?}, \
             group_grants={group_grants:?}, direct={direct:?})"
        );
        assert_eq!(
            groups_of(&db, scope, &org, &user, DEPTH).await,
            expected_group_slugs,
            "forest {forest} group closure (parents={parent_of:?}, bound={bound_groups:?})"
        );
        // Idempotent and order independent: the same stored state resolves to the same
        // set every time, and the set never depends on the order the grants were
        // written in (which the randomized generator already varies between forests).
        assert_eq!(
            roles_of(&db, &env, scope, &org, &user, DEPTH).await,
            resolved
        );
    }
}

#[tokio::test]
async fn removing_a_membership_revokes_its_groups_and_direct_roles() {
    // CASCADE SITE 1 of 3: the admin removal.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    let second = create_group(&db, &env, scope, &org, "oncall", None).await;
    let group_role = create_role(&db, &env, scope, &org, "engineer").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;
    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    grant_group_role(&db, &env, scope, &org, &group, &group_role)
        .await
        .expect("grant to the group");
    bind_member(&db, &env, scope, &org, &group, &membership)
        .await
        .expect("bind");
    bind_member(&db, &env, scope, &org, &second, &membership)
        .await
        .expect("bind into a second group");
    grant_direct_role(&db, &env, scope, &org, &membership, &direct_role)
        .await
        .expect("direct grant");

    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["engineer", "founder"])
    );
    assert_eq!(
        live_attachment_count(&db, scope, "org_group_members", &membership).await,
        2
    );
    assert_eq!(
        live_attachment_count(&db, scope, "org_membership_roles", &membership).await,
        1
    );

    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_memberships(scope)
        .remove(&env, &membership)
        .await
        .expect("remove the membership");

    // The attachments are GONE at the moment of removal, not merely ignored: an
    // administrator removing a compromised account is entitled to see the grants stop
    // existing, and a later revive must have nothing to bring back.
    assert_eq!(
        live_attachment_count(&db, scope, "org_group_members", &membership).await,
        0,
        "removing a membership must revoke its group bindings"
    );
    assert_eq!(
        live_attachment_count(&db, scope, "org_membership_roles", &membership).await,
        0,
        "removing a membership must revoke its direct role grants"
    );

    // The cascade audits itself against the MEMBERSHIP, with the counts it stripped.
    let actions = audit_actions(&db, scope, &membership.to_string()).await;
    assert_eq!(
        actions,
        vec![
            "organization.membership.add".to_owned(),
            "organization.membership.attachments.revoke".to_owned(),
            "organization.membership.remove".to_owned(),
        ]
    );
    assert_eq!(
        audit_details_for(
            &db,
            scope,
            &membership.to_string(),
            "organization.membership.attachments.revoke"
        )
        .await,
        vec![Some("groups=2,roles=1".to_owned())],
        "the cascade records how much authorization it stripped"
    );

    // Re-adding the user produces a live membership with NOTHING attached.
    let revived = add_membership(&db, &env, scope, &org, &user)
        .await
        .expect("re-add");
    assert_eq!(
        revived, membership,
        "the membership row is revived, not recreated"
    );
    assert!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a removed and re-added user starts with no groups and no roles"
    );
}

#[tokio::test]
async fn an_admin_re_add_revives_a_membership_with_nothing_attached() {
    // CASCADE SITE 2 of 3: the admin re-add, exercised against a membership that was
    // soft-deleted WITHOUT its attachments being cleaned up, so the site-1 cascade has
    // nothing to do with whether this passes.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    let group_role = create_role(&db, &env, scope, &org, "engineer").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;
    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    grant_group_role(&db, &env, scope, &org, &group, &group_role)
        .await
        .expect("grant to the group");
    bind_member(&db, &env, scope, &org, &group, &membership)
        .await
        .expect("bind");
    grant_direct_role(&db, &env, scope, &org, &membership, &direct_role)
        .await
        .expect("direct grant");

    kill_membership_row(&db, scope, &membership).await;
    assert_eq!(
        live_attachment_count(&db, scope, "org_group_members", &membership).await,
        1,
        "the fixture is the state a revive must clean up: dead membership, LIVE attachments"
    );
    assert_eq!(
        live_attachment_count(&db, scope, "org_membership_roles", &membership).await,
        1
    );

    let revived = add_membership(&db, &env, scope, &org, &user)
        .await
        .expect("re-add through the admin surface");
    assert_eq!(
        revived, membership,
        "the membership row is revived, not recreated"
    );

    assert_eq!(
        live_attachment_count(&db, scope, "org_group_members", &membership).await,
        0,
        "an admin re-add must not restore the member's groups"
    );
    assert_eq!(
        live_attachment_count(&db, scope, "org_membership_roles", &membership).await,
        0,
        "an admin re-add must not restore the member's direct roles"
    );
    assert!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty()
    );
    assert!(
        audit_actions(&db, scope, &membership.to_string())
            .await
            .contains(&"organization.membership.attachments.revoke".to_owned()),
        "the revive cascade audits itself"
    );
    assert_eq!(
        audit_details_for(
            &db,
            scope,
            &membership.to_string(),
            "organization.membership.attachments.revoke"
        )
        .await,
        vec![Some("groups=1,roles=1".to_owned())]
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the invitation-accept fixture (a pending user, an org-context \
              invitation, and the token) is irreducible, and splitting it from the \
              assertion would separate the exploit from its proof"
)]
async fn an_invitation_accept_revives_a_membership_with_nothing_attached() {
    // CASCADE SITE 3 of 3, and the one a change wired only into the admin path would
    // miss. The exploit this closes, concretely: an administrator removes a
    // compromised user, and the user restores every group and every role simply by
    // redeeming an invitation they were sent earlier.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    let group_role = create_role(&db, &env, scope, &org, "engineer").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;

    // A pending_verification user, because that is the state an invitation accept
    // activates. Bind them into the organization and give them attachments.
    let created = now_micros(&env);
    let MintedInvitationToken { token, digest, id } = mint_invitation_token(&env, &scope);
    let user = db
        .control_store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .users()
        .admin_create(
            &env,
            NewAdminUser {
                id: None,
                identifier: "invitee@example.test",
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::PendingVerification,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            created,
            None,
        )
        .await
        .expect("create the pending user");
    let membership = add_membership(&db, &env, scope, &org, &user)
        .await
        .expect("bind the invitee into the organization");
    grant_group_role(&db, &env, scope, &org, &group, &group_role)
        .await
        .expect("grant to the group");
    bind_member(&db, &env, scope, &org, &group, &membership)
        .await
        .expect("bind into the group");
    grant_direct_role(&db, &env, scope, &org, &membership, &direct_role)
        .await
        .expect("direct grant");

    let org_context = org.to_string();
    db.control_store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .invitations()
        .create(
            &env,
            NewInvitation {
                id: &id,
                user_id: &user,
                target_identifier: "invitee@example.test",
                token_digest: &digest,
                credential_type: InvitationCredentialType::Password,
                org_context: Some(&org_context),
                expires_at_unix_micros: created.saturating_add(3_600_000_000),
            },
            created,
            None,
        )
        .await
        .expect("create the org invitation");

    // The membership is soft-deleted WITHOUT its attachments being cleaned up, so
    // this test cannot be satisfied by the removal-side cascade. Only the cascade
    // wired into the accept path can make it pass.
    kill_membership_row(&db, scope, &membership).await;
    assert_eq!(
        live_attachment_count(&db, scope, "org_group_members", &membership).await,
        1
    );
    assert_eq!(
        live_attachment_count(&db, scope, "org_membership_roles", &membership).await,
        1
    );

    // Accept on the DATA plane, exactly as the invitee side does.
    let accepted = db
        .store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .invitations()
        .accept(&env, &token, Some(PASSWORD_HASH), now_micros(&env))
        .await
        .expect("accept the invitation");
    assert_eq!(accepted.organization_id, Some(org));

    assert_eq!(
        live_attachment_count(&db, scope, "org_group_members", &membership).await,
        0,
        "redeeming an old invitation must NOT restore the member's groups"
    );
    assert_eq!(
        live_attachment_count(&db, scope, "org_membership_roles", &membership).await,
        0,
        "redeeming an old invitation must NOT restore the member's direct roles"
    );
    assert!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "the re-accepted member holds nothing until somebody grants it again"
    );
    assert!(
        audit_actions(&db, scope, &membership.to_string())
            .await
            .contains(&"organization.membership.attachments.revoke".to_owned()),
        "the accept-path cascade audits itself against the membership"
    );
    assert_eq!(
        audit_details_for(
            &db,
            scope,
            &membership.to_string(),
            "organization.membership.attachments.revoke"
        )
        .await,
        vec![Some("groups=1,roles=1".to_owned())]
    );
}

#[tokio::test]
async fn a_fresh_membership_add_writes_no_empty_cascade_row() {
    // The counterpart to the three cascade tests: a membership that never existed
    // before has a brand-new id nothing can reference, so the cascade must not fire
    // and must not pollute the audit log with an empty revoke on every add.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let (_, membership) = create_member(&db, &env, scope, &org, "fresh@example.test").await;

    assert_eq!(
        audit_actions(&db, scope, &membership.to_string()).await,
        vec!["organization.membership.add".to_owned()],
        "a first-time add writes exactly one audit row"
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the least-privilege matrix of three tables on two roles, kept in one \
              place so a grant that widened on one table could not hide behind the \
              other two"
)]
async fn the_data_plane_can_read_the_join_tables_but_never_write_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    let role = create_role(&db, &env, scope, &org, "engineer").await;
    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    let binding = bind_member(&db, &env, scope, &org, &group, &membership)
        .await
        .expect("bind");
    grant_group_role(&db, &env, scope, &org, &group, &role)
        .await
        .expect("grant");
    grant_direct_role(&db, &env, scope, &org, &membership, &role)
        .await
        .expect("direct grant");

    // The DATA plane READS all three through the scoped store: the grants effective
    // role resolution depends on. Without them the mint path would fail with SQLSTATE
    // 42501, which is why 0088 and 0089 grant them in the creating migrations.
    let scoped = db.store().scoped(scope);
    assert_eq!(
        scoped
            .org_group_members()
            .get(&binding)
            .await
            .expect("the data plane can READ a binding")
            .group_id,
        group
    );
    assert_eq!(
        scoped
            .org_group_roles()
            .list_for_group(&org, &group, PAGE, None)
            .await
            .expect("the data plane can READ group grants")
            .len(),
        1
    );
    assert_eq!(
        scoped
            .org_membership_roles()
            .list_for_membership(&org, &membership, PAGE, None)
            .await
            .expect("the data plane can READ direct grants")
            .len(),
        1
    );
    assert_eq!(
        scoped
            .org_groups()
            .effective_roles(&org, &user, DEFAULT_DEPTH)
            .await
            .expect("and can resolve"),
        set(&["engineer"])
    );

    let pool = db.app_pool();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    // Precondition: the low-privilege data-plane role, not a superuser.
    let who = sqlx::query(
        "SELECT current_user AS u, \
         (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_super",
    )
    .fetch_one(pool)
    .await
    .expect("identify session role");
    assert_eq!(who.get::<String, _>("u"), "ironauth_app");
    assert!(!who.get::<bool, _>("is_super"));

    // Deleting outright, and moving a row between organizations, are refused as
    // insufficient privilege on every table and on BOTH planes: removal is always the
    // soft delete, and a row's organization is fixed for its whole life.
    for table in [
        "org_group_members",
        "org_group_roles",
        "org_membership_roles",
    ] {
        for statement in [
            format!("DELETE FROM {table}"),
            format!("UPDATE {table} SET organization_id = $3"),
        ] {
            assert_denied(pool, &tenant, &environment, &statement, &[&org.to_string()]).await;
        }
    }
    // The data plane may REVOKE on the two MEMBERSHIP-keyed tables and only there.
    // That grant exists for exactly one caller, the invitation-accept side effect,
    // which runs on this plane and revives memberships; `org_group_roles` is keyed on
    // a group, no membership lifecycle reaches it, and the data plane must stay read
    // only there. Asserted in BOTH directions, so a grant that widened to the third
    // table would fail here rather than silently pass.
    assert_denied(
        pool,
        &tenant,
        &environment,
        "UPDATE org_group_roles SET deleted_at = now(), updated_at = now()",
        &[],
    )
    .await;
    for table in ["org_group_members", "org_membership_roles"] {
        let mut tx = pool.begin().await.expect("begin app revoke tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        sqlx::query(&format!(
            "UPDATE {table} SET deleted_at = now(), updated_at = now()"
        ))
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "the data plane must hold the column-scoped soft-delete pair on {table}, \
                 or the invitation-accept cascade fails with 42501: {error:?}"
            )
        });
        let _ = tx.rollback().await;
    }
    // The forge INSERTs write rows that are valid in EVERY respect but the grant: the
    // session's OWN scope, a real organization, and real endpoints, so the row
    // satisfies the row-level-security WITH CHECK and every foreign key. If the data
    // plane ever gained INSERT, whether table-wide or column-scoped, these would
    // SUCCEED. Postgres reports a policy refusal and a privilege refusal under the
    // SAME SQLSTATE, which is exactly the trap this avoids: a probe writing literal
    // foreign-scope values would be refused by the policy no matter how far the grant
    // was widened, and could never observe the grant at all.
    assert_denied(
        pool,
        &tenant,
        &environment,
        "INSERT INTO org_group_members \
         (id, tenant_id, environment_id, organization_id, group_id, membership_id) \
         VALUES ('gmb_probe', $1, $2, $3, $4, $5)",
        &[
            &org.to_string(),
            &group.to_string(),
            &membership.to_string(),
        ],
    )
    .await;
    assert_denied(
        pool,
        &tenant,
        &environment,
        "INSERT INTO org_group_roles \
         (id, tenant_id, environment_id, organization_id, group_id, role_id) \
         VALUES ('grl_probe', $1, $2, $3, $4, $5)",
        &[&org.to_string(), &group.to_string(), &role.to_string()],
    )
    .await;
    assert_denied(
        pool,
        &tenant,
        &environment,
        "INSERT INTO org_membership_roles \
         (id, tenant_id, environment_id, organization_id, membership_id, role_id) \
         VALUES ('mrl_probe', $1, $2, $3, $4, $5)",
        &[&org.to_string(), &membership.to_string(), &role.to_string()],
    )
    .await;

    // Neither role may REPOINT a live row at a different endpoint. That is what keeps
    // the same-organization containment resolved at write time from being undone
    // afterwards by a plain UPDATE, and it applies to the CONTROL plane too.
    for (table, column) in [
        ("org_group_members", "group_id"),
        ("org_group_members", "membership_id"),
        ("org_group_roles", "group_id"),
        ("org_group_roles", "role_id"),
        ("org_membership_roles", "membership_id"),
        ("org_membership_roles", "role_id"),
    ] {
        for probe_pool in [pool, db.control_pool()] {
            assert_denied(
                probe_pool,
                &tenant,
                &environment,
                &format!("UPDATE {table} SET {column} = $3"),
                &[&group.to_string()],
            )
            .await;
        }
    }

    // Positive control: the CONTROL role's column-scoped soft delete DOES succeed, so
    // the denials above are about those columns and not about that role's access
    // generally.
    for table in [
        "org_group_members",
        "org_group_roles",
        "org_membership_roles",
    ] {
        let mut tx = db.control_pool().begin().await.expect("begin control tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        sqlx::query(&format!(
            "UPDATE {table} SET deleted_at = now(), updated_at = now()"
        ))
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|error| {
            panic!("the control role holds column-scoped UPDATE on {table}: {error:?}")
        });
        let _ = tx.rollback().await;
    }
}

#[tokio::test]
async fn there_is_no_cap_on_members_groups_or_assignments() {
    // The covenant, asserted rather than assumed. Nothing here counts rows before
    // writing one: no quota check, no advisory-lock-plus-COUNT gate, no paywall.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let group = create_group(&db, &env, scope, &org, "everyone", None).await;
    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    // Many groups for ONE member, and many roles on ONE membership.
    let mut expected = BTreeSet::new();
    for index in 0..WIDE {
        let other = create_group(&db, &env, scope, &org, &format!("g{index}"), None).await;
        bind_member(&db, &env, scope, &org, &other, &membership)
            .await
            .expect("a member may belong to unlimited groups");
        let role = create_role(&db, &env, scope, &org, &format!("r{index}")).await;
        grant_direct_role(&db, &env, scope, &org, &membership, &role)
            .await
            .expect("a membership may hold unlimited direct roles");
        expected.insert(format!("r{index}"));
    }
    // And many members in ONE group.
    for index in 0..WIDE {
        let (_, other) =
            create_member(&db, &env, scope, &org, &format!("m{index}@example.test")).await;
        bind_member(&db, &env, scope, &org, &group, &other)
            .await
            .expect("a group may hold unlimited members");
    }

    assert_eq!(
        roles_of(&db, &env, scope, &org, &user, DEFAULT_DEPTH).await,
        expected
    );
    assert_eq!(
        db.control_store()
            .management()
            .org_group_members(scope)
            .list_for_group(&org, &group, PAGE, None)
            .await
            .expect("list")
            .len(),
        WIDE
    );
}

/// Run `statement` in a scoped transaction on `pool` and assert it is refused as
/// insufficient privilege.
///
/// `$1` and `$2` are always the session's OWN (tenant, environment), and `extra`
/// supplies `$3` onwards, so a probe INSERT writes a row that SATISFIES the
/// row-level-security WITH CHECK and every foreign key, leaving the missing GRANT as
/// the only thing that can refuse it. That distinction is the whole point: Postgres
/// reports a policy refusal and a privilege refusal under the SAME SQLSTATE (42501),
/// so a probe writing literal foreign-scope values would be rejected by the policy no
/// matter how far the grant was widened, and could never observe the grant at all.
async fn assert_denied(
    pool: &sqlx::PgPool,
    tenant: &str,
    environment: &str,
    statement: &str,
    extra: &[&str],
) {
    let mut tx = pool.begin().await.expect("begin denied-statement tx");
    bind_scope(&mut tx, tenant, environment).await;
    let mut query = sqlx::query(statement).bind(tenant).bind(environment);
    for value in extra {
        query = query.bind((*value).to_owned());
    }
    let result = query.execute(&mut *tx).await;
    assert!(
        result.as_ref().err().is_some_and(|error| error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .is_some_and(|code| code == INSUFFICIENT_PRIVILEGE)),
        "statement must be refused as insufficient privilege: {statement:?} -> {result:?}"
    );
    let _ = tx.rollback().await;
}

/// Bind the transaction-local row-level-security scope variables, exactly as the
/// repository does.
async fn bind_scope(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    environment: &str,
) {
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(tenant)
        .execute(&mut **tx)
        .await
        .expect("bind tenant scope");
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(environment)
        .execute(&mut **tx)
        .await
        .expect("bind environment scope");
}
