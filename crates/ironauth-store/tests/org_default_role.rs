// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ORGANIZATION'S DEFAULT ROLE (issue #98, store PR 6): the role every live
//! active member of an organization holds because the organization designated it,
//! over a real database (`DATABASE_URL`).
//!
//! Migration 0093 added `org_roles.is_default` and one `OR` branch to the
//! `effective_roles` arm of the shared closure. That branch is the FIRST new branch
//! that arm has ever had, and it rests on exactly two predicates: `EXISTS (SELECT 1
//! FROM membership)`, which is the whole of its subject fence and of its
//! organization-LIFECYCLE fence, and `r.organization_id = $3`, which is the whole of
//! its organization-IDENTITY fence. This file is about those two.
//!
//! What it pins, in the order the tests appear:
//!
//! * RESOLUTION for a member who holds NOTHING else: no direct grant, no group, no
//!   assignment row anywhere. The designation alone puts the role in the effective
//!   set, its permissions in the permission set, and one `Default` entry in the
//!   provenance, while the effective GROUP set stays empty, because the group
//!   projection reads `closure` and the default role touches no group.
//! * `a_non_member_never_receives_the_default_role`, against a real non-member of
//!   the organization standing beside a real member of it, so the assertion cannot
//!   pass by resolving nothing at all.
//! * The ORGANIZATION-LIFECYCLE fence, in both halves, THROUGH THIS BRANCH: the
//!   subject holds no grant of any other kind, so nothing but the membership seed
//!   can be what empties the answer. Two separate tests, because `o.state =
//!   'active'` and `o.deleted_at IS NULL` are two predicates and a mutation that
//!   drops either must turn a test red on that column alone.
//! * A soft-deleted MEMBERSHIP, which is the same seed read from the other side.
//! * The ORGANIZATION-IDENTITY fence, `r.organization_id`. Until this branch landed
//!   that predicate was one of the census's mutually redundant survivors, because
//!   every branch of the arm carried an `mr.organization_id` or a
//!   `gr.organization_id` beside it. The default branch carries neither, so it is
//!   now the only thing keeping a SIBLING organization's default role out, and this
//!   is where that is measured.
//! * SCOPE fencing, with the sharpest victim: a scope differing from the caller's in
//!   the ENVIRONMENT ALONE, holding the same slugs. `seed_scope` mints a NEW TENANT
//!   on every call, so a probe between two seeded scopes is decided by the tenant
//!   half and can say nothing about the environment half.
//! * The same fence one layer DOWN. Every cross-scope probe of the test above is
//!   refused by `run_effective`'s typed-id guard before a statement is ever built, so
//!   what happens BELOW that guard is a separate question with a separate test:
//!   `a_default_role_whose_scope_columns_disagree_with_its_organization_never_resolves`
//!   plants a designated-default role row that names the caller's organization while
//!   its scope columns name somewhere else, which is the one shape that satisfies
//!   `r.organization_id = $3` rather than being refused by it. It is the shipped proof
//!   that the shape cannot leak. It is NOT a kill of the two survivors below; see
//!   there.
//! * UNION behaviour: a role held as the default AND directly AND through a group is
//!   ONE slug and THREE provenance entries, because the store reports one entry per
//!   grant PATH and never collapses them.
//! * The two ways a default role stops resolving: deleting the role, and designating
//!   a different one. Both take effect on the very next read, and the deleted row
//!   keeps its flag, which is what makes `r.deleted_at IS NULL` the predicate that
//!   decides rather than a clearing pass nobody wrote.
//!
//! # What this file does NOT kill, measured rather than assumed
//!
//! Three mutations survive every test here, and none of them is a hole worth papering
//! over with a weaker assertion:
//!
//! * `r.tenant_id = $1` and `r.environment_id = $2` in the `effective_roles` arm.
//!   Dropping either ALONE is green, and dropping BOTH together is green too, so they
//!   are not each other's backstop: an organization id is globally unique and embeds
//!   its own scope, so `r.organization_id = $3` already excludes every row of another
//!   tenant or environment, with forced row-level security underneath. Dropping all
//!   THREE is KILLED, by `a_default_role_never_crosses_into_a_sibling_organization`.
//!
//!   `a_default_role_whose_scope_columns_disagree_with_its_organization_never_resolves`
//!   was written to attack exactly the case that argument leaves open, a row whose
//!   `organization_id` agrees with the caller while its scope columns do not, and it
//!   does NOT kill them either: all four mutations were re-run against it, including
//!   the all-three one that four other tests kill, and it stayed green through every
//!   one. They are EQUIVALENT rather than untested, and the mechanism is measured in
//!   that test rather than argued: three role rows name the organization and the
//!   resolution's own session can see one, because forced row-level security refuses
//!   the other two before the statement's predicates are reached. What the test buys is
//!   the shipped proof that the shape is closed, and a regression assertion on the
//!   policy that closes it.
//! * The `source` conjunct of the provenance tail's `ORDER BY`. With it gone the tied
//!   rows come back in the order the `UNION ALL` produced them, which happens to be the
//!   asserted one. What it buys is a plan-independent TOTAL order, which no single
//!   evaluation can observe. `EFFECTIVE_ROLE_GRANTS_TAIL` records the same measurement.
//! * `m.state = 'active'` on the shared membership seed. That one is UNREACHABLE rather
//!   than untested: `org_memberships_state_valid` (migration 0084) is
//!   `CHECK (state IN ('active'))`, so no path, supported or otherwise, can write a row
//!   the predicate would exclude. It is headroom for a wider lifecycle set.
//!
//! # Why the designation is written with direct SQL here
//!
//! Issue #98's PR 8 adds the management route and the audited store writer for the
//! designation. Until it lands there is no supported path, so these tests write the
//! column themselves. They do it through the CONTROL pool, under the same role, the
//! same bound scope and the same grants the repository runs with, which makes
//! migration 0093's `GRANT UPDATE (is_default) ON org_roles TO ironauth_control`
//! load-bearing for every test in this file: without it every one of them fails on
//! SQLSTATE 42501 rather than passing quietly. This is the same convention
//! `effective_permissions.rs` follows for the two rows no supported path can write.

use std::collections::BTreeSet;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, EffectiveRoleGrant, EffectiveRoleSource, NewAdminUser, NewMembership,
    NewOrgGroup, NewOrgGroupMember, NewOrgGroupRole, NewOrgMembershipRole, NewOrgRole,
    NewOrgRolePermission, NewPermission, ORG_GROUP_MAX_DEPTH_CEILING, OrgGroupId, OrgGroupMemberId,
    OrgGroupRoleId, OrgMembershipId, OrgMembershipRoleId, OrgRoleId, OrgRolePermissionId,
    OrganizationId, OrganizationState, PermissionId, Scope, ServiceId, StoreError, UserId,
    UserState,
};
use sqlx::Row;

/// A valid Argon2id PHC verifier (a fixed one; hashing is exercised in the higher
/// layers, the store only persists the string).
const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";

/// The depth bound every test here passes: the shipped `[organizations]
/// max_group_depth` default. Nothing in this file is about the bound.
const DEFAULT_DEPTH: u32 = 8;

/// The instant every row in this file is stamped with. Nothing here paginates or
/// orders by time, so one fixed instant keeps the fixtures free of any clock read.
const AT: i64 = 1_000;

fn actor(env: &Env) -> ActorRef {
    ActorRef::service(ServiceId::generate(env))
}

/// A `BTreeSet<String>` from string literals, for the expected-set assertions.
fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// The expected provenance entry for a role held as the organization's DEFAULT.
fn as_default(slug: &str) -> EffectiveRoleGrant {
    EffectiveRoleGrant {
        slug: slug.to_owned(),
        source: EffectiveRoleSource::Default,
    }
}

/// The expected provenance entry for a role granted straight to the membership.
fn as_direct(slug: &str) -> EffectiveRoleGrant {
    EffectiveRoleGrant {
        slug: slug.to_owned(),
        source: EffectiveRoleSource::Direct,
    }
}

/// The expected provenance entry for a role inherited through `group`.
fn as_group(slug: &str, group: &OrgGroupId) -> EffectiveRoleGrant {
    EffectiveRoleGrant {
        slug: slug.to_owned(),
        source: EffectiveRoleSource::Group(*group),
    }
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

/// Create an organization in `scope` through the control store.
async fn create_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, AT, name, None)
        .await
        .expect("create organization");
    id
}

/// Define a group in `org`, optionally under `parent`.
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
            AT,
            ORG_GROUP_MAX_DEPTH_CEILING,
            None,
        )
        .await
        .expect("create group");
    id
}

/// Define a role in `org`. A fresh role is never the default: `is_default` defaults
/// to false in migration 0093 and no write path here sets it.
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
            AT,
            None,
        )
        .await
        .expect("create role");
    id
}

/// Soft-delete a role through the audited write repository. Nothing cascades: the
/// assignment rows and the `is_default` flag both survive.
async fn delete_role(db: &TestDatabase, env: &Env, scope: Scope, role: &OrgRoleId) {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_roles(scope)
        .delete(env, role)
        .await
        .expect("delete the role");
}

/// Define a permission in `scope`'s vocabulary through the audited write repository.
async fn create_permission(db: &TestDatabase, env: &Env, scope: Scope, slug: &str) -> PermissionId {
    let id = PermissionId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .permissions(scope)
        .create(
            env,
            NewPermission {
                id: &id,
                slug,
                display_name: "Capability",
                metadata: None,
            },
            AT,
            None,
        )
        .await
        .expect("create permission");
    id
}

/// Create an ACTIVE user in `scope`.
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
                traits: None,
            },
            AT,
            None,
        )
        .await
        .expect("create active user")
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
                user_id: &user,
                metadata: None,
            },
            AT,
            None,
        )
        .await
        .expect("bind user into organization");
    (user, id)
}

/// Remove a membership through the audited write repository, which soft-deletes it
/// and revokes every live attachment in the same transaction.
async fn remove_member(db: &TestDatabase, env: &Env, scope: Scope, membership: &OrgMembershipId) {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_memberships(scope)
        .remove(env, membership)
        .await
        .expect("remove the membership");
}

/// Bind `membership` into `group`.
async fn bind_member(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    group: &OrgGroupId,
    membership: &OrgMembershipId,
) -> OrgGroupMemberId {
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
                source_scim_connection_id: None,
            },
            AT,
            None,
        )
        .await
        .expect("bind membership into group");
    id
}

/// Grant `role` to `group`.
async fn grant_group_role(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    group: &OrgGroupId,
    role: &OrgRoleId,
) -> OrgGroupRoleId {
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
            AT,
            None,
        )
        .await
        .expect("grant role to group");
    id
}

/// Grant `role` directly to `membership`.
async fn grant_direct_role(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    membership: &OrgMembershipId,
    role: &OrgRoleId,
) -> OrgMembershipRoleId {
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
            AT,
            None,
        )
        .await
        .expect("grant role directly");
    id
}

/// Attach `permission` to `role` through the audited write repository.
async fn attach(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    role: &OrgRoleId,
    permission: &PermissionId,
) -> OrgRolePermissionId {
    let id = OrgRolePermissionId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_role_permissions(scope)
        .assign(
            env,
            NewOrgRolePermission {
                id: &id,
                organization_id: org,
                role_id: role,
                permission_id: permission,
            },
            AT,
            None,
        )
        .await
        .expect("attach permission to role");
    id
}

/// Write `org_roles.is_default` with direct SQL through the CONTROL pool, under the
/// same role, the same bound scope, and the same grants the repository runs with.
///
/// Fallible on purpose: the partial unique index refuses a SECOND live default in one
/// organization, and one test is about that refusal. Every other caller goes through
/// [`designate_default`] and [`clear_default`], which assert the write landed.
async fn try_set_default(
    db: &TestDatabase,
    scope: Scope,
    role: &OrgRoleId,
    value: bool,
) -> Result<u64, sqlx::Error> {
    let mut tx = db.control_pool().begin().await.expect("begin designate");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    let outcome = sqlx::query(
        "UPDATE org_roles \
            SET is_default = $4, \
                updated_at = TIMESTAMPTZ 'epoch' + ($5::text || ' microseconds')::interval \
          WHERE tenant_id = $1 AND environment_id = $2 AND id = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(role.to_string())
    .bind(value)
    .bind(AT)
    .execute(&mut *tx)
    .await;
    match outcome {
        Ok(done) => {
            tx.commit().await.expect("commit designate");
            Ok(done.rows_affected())
        }
        Err(error) => {
            tx.rollback().await.expect("roll the refused write back");
            Err(error)
        }
    }
}

/// Designate `role` as its organization's default role.
async fn designate_default(db: &TestDatabase, scope: Scope, role: &OrgRoleId) {
    let affected = try_set_default(db, scope, role, true)
        .await
        .expect("designate the default role");
    assert_eq!(affected, 1, "the designation landed on exactly one role");
}

/// Clear the designation from `role`.
async fn clear_default(db: &TestDatabase, scope: Scope, role: &OrgRoleId) {
    let affected = try_set_default(db, scope, role, false)
        .await
        .expect("clear the default role");
    assert_eq!(affected, 1, "the clear landed on exactly one role");
}

/// Plant a designated-default `org_roles` row whose `organization_id` is `org` but
/// whose SCOPE COLUMNS are `columns`, which is a scope the organization does not
/// belong to.
///
/// A CORRUPT row, and deliberately so. No supported path can produce it: 0086 grants
/// the control plane a column-scoped UPDATE that omits `id`, `tenant_id`,
/// `environment_id`, and `organization_id`, so no row can be moved between scopes or
/// between organizations after it is written, and every INSERT the repository issues
/// takes its scope columns from the same bound scope the row-level-security WITH CHECK
/// tests. What makes the row REPRESENTABLE at all is that
/// `org_roles_organization_id_fkey` references `organizations (id)` alone rather than
/// the composite key, which 0086 documents as sufficient because an organization id
/// embeds its own scope. This helper is the probe that says so out loud: it writes the
/// row the foreign key cannot refuse.
///
/// It goes through the OWNER pool because nothing else can. The control role's
/// row-level-security WITH CHECK rejects a scope other than the bound one, which is
/// what `org_roles.rs` measures directly, and the harness's `DATABASE_URL` connection
/// is a superuser, so it is the only writer that can build this state at all.
///
/// The plant asserts it landed, so a fixture defeated by a constraint (a foreign key,
/// the live-slug index, or `org_roles_org_default_live_uniq`) fails HERE rather than
/// leaving a test that passes because there was never a row to leak.
async fn plant_cross_scope_default_role(
    db: &TestDatabase,
    env: &Env,
    columns: Scope,
    org: &OrganizationId,
    slug: &str,
) -> OrgRoleId {
    // The id is minted in the scope the COLUMNS name, so the row is internally
    // consistent and disagrees with the organization on exactly one thing: which scope
    // owns it. Nothing in the resolution parses this id, so its form is documentation
    // rather than mechanism.
    let id = OrgRoleId::generate(env, &columns);
    // Stamped at `AT` like every other row in this file rather than left to the
    // column's `now()` default, so the fixture stays free of a clock read.
    let affected = sqlx::query(
        "INSERT INTO org_roles \
         (id, tenant_id, environment_id, organization_id, slug, display_name, is_default, \
          created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, 'Planted', true, \
                 TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval, \
                 TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval)",
    )
    .bind(id.to_string())
    .bind(columns.tenant().to_string())
    .bind(columns.environment().to_string())
    .bind(org.to_string())
    .bind(slug)
    .bind(AT)
    .execute(db.owner_pool())
    .await
    .expect("plant the cross-scope default role")
    .rows_affected();
    assert_eq!(affected, 1, "the plant landed exactly one row");
    id
}

/// How many `org_roles` rows name `org` in the table AS STORED, read through the OWNER
/// pool, which the harness connects as a superuser and which therefore sees the table
/// with row-level security out of the way entirely.
async fn stored_role_count(db: &TestDatabase, org: &OrganizationId) -> i64 {
    sqlx::query("SELECT count(*) AS n FROM org_roles WHERE organization_id = $1")
        .bind(org.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("count the stored roles of the organization")
        .get("n")
}

/// How many `org_roles` rows naming `org` a CONTROL-plane session bound to `scope` can
/// SEE, with no repository filter and no statement predicate in the way.
///
/// The pair with [`stored_role_count`] is what ATTRIBUTES a negative result to
/// row-level security rather than to the statement: the owner counts what exists, this
/// counts what the resolution's own session is even able to reach.
async fn visible_role_count(db: &TestDatabase, scope: Scope, org: &OrganizationId) -> i64 {
    let mut tx = db
        .control_pool()
        .begin()
        .await
        .expect("begin a scoped read");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    let count: i64 = sqlx::query("SELECT count(*) AS n FROM org_roles WHERE organization_id = $1")
        .bind(org.to_string())
        .fetch_one(&mut *tx)
        .await
        .expect("count the roles this session can see")
        .get("n");
    tx.commit().await.expect("commit the scoped read");
    count
}

/// The stored `is_default` of one role, read through the OWNER pool so nothing hides
/// behind row-level security or behind a repository filter.
async fn stored_is_default(db: &TestDatabase, role: &OrgRoleId) -> bool {
    sqlx::query("SELECT is_default FROM org_roles WHERE id = $1")
        .bind(role.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("read the stored designation")
        .get("is_default")
}

/// The effective ROLE slugs for `user` in `org`.
async fn roles_of(
    db: &TestDatabase,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
) -> BTreeSet<String> {
    db.control_store()
        .management()
        .org_groups(scope)
        .effective_roles(org, user, DEFAULT_DEPTH)
        .await
        .expect("resolve effective roles")
}

/// The effective PERMISSION slugs for `user` in `org`.
async fn permissions_of(
    db: &TestDatabase,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
) -> BTreeSet<String> {
    db.control_store()
        .management()
        .org_groups(scope)
        .effective_permissions(org, user, DEFAULT_DEPTH)
        .await
        .expect("resolve effective permissions")
}

/// The effective GROUP slugs for `user` in `org`.
async fn group_slugs_of(
    db: &TestDatabase,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
) -> BTreeSet<String> {
    db.control_store()
        .management()
        .org_groups(scope)
        .effective_group_slugs(org, user, DEFAULT_DEPTH)
        .await
        .expect("resolve effective group slugs")
}

/// The effective role GRANTS (one entry per path) for `user` in `org`.
async fn grants_of(
    db: &TestDatabase,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
) -> Vec<EffectiveRoleGrant> {
    db.control_store()
        .management()
        .org_groups(scope)
        .effective_role_grants(org, user, DEFAULT_DEPTH)
        .await
        .expect("resolve effective role grants")
}

/// Flip an organization's lifecycle state through the control plane.
async fn set_org_state(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    state: OrganizationState,
) {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .set_state(env, org, state, None)
        .await
        .expect("set organization state");
}

/// Soft-delete an organization through the control plane. Nothing cascades.
async fn delete_org(db: &TestDatabase, env: &Env, scope: Scope, org: &OrganizationId) {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .delete(env, org)
        .await
        .expect("soft delete organization");
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the default role's whole read contract as one story: nothing, then the \
              designation, then all four projections, then a second member, then the \
              clear, each step measured against the one fixture the step before built"
)]
async fn the_default_role_reaches_all_four_projections_and_leaves_the_group_set_alone() {
    // The subject here holds NO assignment of any kind: no direct grant, no group
    // binding, no group. That is deliberate and it is what makes every assertion
    // below about the default-role branch rather than about one of the two grant
    // branches standing beside it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let baseline = create_role(&db, &env, scope, &org, "everyone").await;
    let read = create_permission(&db, &env, scope, "directory.read").await;
    let write = create_permission(&db, &env, scope, "directory.write").await;
    attach(&db, &env, scope, &org, &baseline, &read).await;
    attach(&db, &env, scope, &org, &baseline, &write).await;

    let (user, _membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    // A role exists, it carries permissions, and the subject is a live active member.
    // Every one of the four projections is still empty, because a role nobody granted
    // and nobody designated is held by nobody.
    assert!(
        roles_of(&db, scope, &org, &user).await.is_empty(),
        "a role that is neither granted nor designated is held by nobody"
    );
    assert!(permissions_of(&db, scope, &org, &user).await.is_empty());
    assert!(grants_of(&db, scope, &org, &user).await.is_empty());
    assert!(group_slugs_of(&db, scope, &org, &user).await.is_empty());

    // The designation, and nothing else. No row is written against the membership:
    // that is the whole point of resolving rather than materializing.
    designate_default(&db, scope, &baseline).await;

    // Projection 1, the role slugs: this is what a later PR of this issue emits into
    // the access token.
    assert_eq!(
        roles_of(&db, scope, &org, &user).await,
        set(&["everyone"]),
        "the designation alone puts the role in the effective set"
    );
    // Projection 2, the permissions: a default role maps like any other role, through
    // the same `org_role_permissions` rows and the same fourth projection.
    assert_eq!(
        permissions_of(&db, scope, &org, &user).await,
        set(&["directory.read", "directory.write"]),
        "the default role carries its permissions exactly as a granted role does"
    );
    // Projection 3, the provenance: ONE entry, and it says Default rather than
    // Direct. Reporting it as Direct would send an operator looking for an
    // `org_membership_roles` row that does not exist and cannot be made to exist.
    assert_eq!(
        grants_of(&db, scope, &org, &user).await,
        vec![as_default("everyone")],
        "the provenance names the designation, because there is no grant to name"
    );
    // Projection 4, the group slugs: UNAFFECTED, and that is not an oversight. It
    // projects `closure`, and the default role reaches the member through no group at
    // all, so there is nothing for it to add. Asserted rather than assumed, because a
    // default-role branch written into the closure instead of the role arm would show
    // up exactly here.
    assert!(
        group_slugs_of(&db, scope, &org, &user).await.is_empty(),
        "the group projection is untouched: a default role belongs to no group"
    );

    // It is the ORGANIZATION'S default, not this member's. A second member who was
    // created after the designation and who holds nothing either resolves the same
    // answer, with no backfill and no write of any kind between the two reads.
    let (second, _second_membership) =
        create_member(&db, &env, scope, &org, "ops@example.test").await;
    assert_eq!(
        roles_of(&db, scope, &org, &second).await,
        set(&["everyone"]),
        "every live active member holds it, including one created afterwards"
    );
    assert_eq!(
        grants_of(&db, scope, &org, &second).await,
        vec![as_default("everyone")]
    );

    // And clearing it takes both members back to nothing on the very next read.
    clear_default(&db, scope, &baseline).await;
    assert!(roles_of(&db, scope, &org, &user).await.is_empty());
    assert!(roles_of(&db, scope, &org, &second).await.is_empty());
    assert!(permissions_of(&db, scope, &org, &user).await.is_empty());
    assert!(grants_of(&db, scope, &org, &user).await.is_empty());
}

#[tokio::test]
async fn a_non_member_never_receives_the_default_role() {
    // The single most important predicate issue #98 adds. The default-role branch is
    // `r.is_default AND EXISTS (SELECT 1 FROM membership)`, and without that EXISTS
    // the organization's default role would resolve for EVERY user in the scope.
    //
    // Two non-members, because they are different shapes and only one of them is
    // obvious: a user with no membership anywhere, and a user who is a live active
    // member of a SIBLING organization in the same scope. The second is the one that
    // matters, because it is the shape a real deployment produces constantly and
    // because it agrees with the caller on tenant and environment, so no scope
    // predicate is involved in refusing it.
    //
    // A real member stands beside both, so none of the assertions below can pass by
    // the fixture resolving nothing at all.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let sibling = create_org(&db, &env, scope, "Initech").await;

    let baseline = create_role(&db, &env, scope, &org, "everyone").await;
    let read = create_permission(&db, &env, scope, "directory.read").await;
    attach(&db, &env, scope, &org, &baseline, &read).await;
    designate_default(&db, scope, &baseline).await;

    let (member, _membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    let (neighbour, _neighbour_membership) =
        create_member(&db, &env, scope, &sibling, "ops@example.test").await;
    let outsider = create_user(&db, &env, scope, "nobody@example.test").await;

    // The positive control: the member of THIS organization does hold it.
    assert_eq!(
        roles_of(&db, scope, &org, &member).await,
        set(&["everyone"]),
        "the member holds the default role, so the fixture is real"
    );
    assert_eq!(
        grants_of(&db, scope, &org, &member).await,
        vec![as_default("everyone")]
    );

    for (subject, label) in [
        (&neighbour, "a live active member of a SIBLING organization"),
        (&outsider, "a user with no membership anywhere"),
    ] {
        assert!(
            roles_of(&db, scope, &org, subject).await.is_empty(),
            "{label} must not receive this organization's default role"
        );
        assert!(
            permissions_of(&db, scope, &org, subject).await.is_empty(),
            "{label} must not receive the permissions that role carries either"
        );
        assert!(
            grants_of(&db, scope, &org, subject).await.is_empty(),
            "{label} must have no provenance entry at all"
        );
    }
}

#[tokio::test]
async fn a_disabled_organization_never_resolves_its_default_role() {
    // The organization's own lifecycle is the COARSEST revocation the product has, and
    // the membership seed of the shared closure is the ONLY place on the issuance path
    // where it is checked. Nothing upstream re-checks it: `OrganizationRepo::get`
    // filters `deleted_at` and NOT `state`, so a disabled organization is still live
    // for management writes, and an operator can go on designating a default role on
    // one.
    //
    // The subject holds NOTHING but the default role, which is what makes this a test
    // of the NEW branch. A subject who also held a direct grant would resolve to the
    // empty set even if the default branch had reached around the seed, because the
    // assertion would be satisfied by the direct branch being fenced.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let bystander = create_org(&db, &env, scope, "Initech").await;

    let baseline = create_role(&db, &env, scope, &org, "everyone").await;
    let read = create_permission(&db, &env, scope, "directory.read").await;
    attach(&db, &env, scope, &org, &baseline, &read).await;
    designate_default(&db, scope, &baseline).await;
    let (user, _membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    // A second organization in the SAME scope with its OWN default role, so this is
    // proved to be a fence per organization rather than a scope-wide outage.
    let other_baseline = create_role(&db, &env, scope, &bystander, "staff").await;
    let rotate = create_permission(&db, &env, scope, "keys.rotate").await;
    attach(&db, &env, scope, &bystander, &other_baseline, &rotate).await;
    designate_default(&db, scope, &other_baseline).await;
    let (other_user, _other_membership) =
        create_member(&db, &env, scope, &bystander, "ops@example.test").await;

    assert_eq!(
        roles_of(&db, scope, &org, &user).await,
        set(&["everyone"]),
        "the fixture resolves before any lifecycle change"
    );

    // DISABLED: the empty set, and NOT an error. A disabled organization is an
    // operator STATE, not a store fault, and refusing here would turn a deliberate
    // administrative action into a token-endpoint outage for every member.
    set_org_state(&db, &env, scope, &org, OrganizationState::Disabled).await;
    assert!(
        roles_of(&db, scope, &org, &user).await.is_empty(),
        "a disabled organization asserts no default role"
    );
    assert!(
        permissions_of(&db, scope, &org, &user).await.is_empty(),
        "nor the permissions that role carries"
    );
    assert!(
        grants_of(&db, scope, &org, &user).await.is_empty(),
        "nor any provenance entry explaining it"
    );
    // The designation itself is untouched. A disable revokes nothing and cascades
    // nothing; it only stops the resolution seeing the member.
    assert!(
        stored_is_default(&db, &baseline).await,
        "the disable changed no row: the role is still designated"
    );
    assert_eq!(
        roles_of(&db, scope, &bystander, &other_user).await,
        set(&["staff"]),
        "a sibling organization in the same scope is untouched"
    );

    // Re-enabling restores it from rows that were never touched: a fence on live
    // state, not a destructive revocation.
    set_org_state(&db, &env, scope, &org, OrganizationState::Active).await;
    assert_eq!(
        roles_of(&db, scope, &org, &user).await,
        set(&["everyone"]),
        "re-enabling restores the default role in one step"
    );
    assert_eq!(
        grants_of(&db, scope, &org, &user).await,
        vec![as_default("everyone")]
    );
}

#[tokio::test]
async fn a_soft_deleted_organization_never_resolves_its_default_role_either() {
    // The other half of the organization fence, through the other lifecycle column.
    // Its own test rather than a second phase of the disable one, because
    // `o.state = 'active'` and `o.deleted_at IS NULL` are two separate predicates on
    // the seed's join and a mutation that drops either must turn a test red on that
    // column alone.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let bystander = create_org(&db, &env, scope, "Initech").await;

    let baseline = create_role(&db, &env, scope, &org, "everyone").await;
    let read = create_permission(&db, &env, scope, "directory.read").await;
    attach(&db, &env, scope, &org, &baseline, &read).await;
    designate_default(&db, scope, &baseline).await;
    let (user, _membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    let other_baseline = create_role(&db, &env, scope, &bystander, "staff").await;
    designate_default(&db, scope, &other_baseline).await;
    let (other_user, _other_membership) =
        create_member(&db, &env, scope, &bystander, "ops@example.test").await;

    assert_eq!(
        roles_of(&db, scope, &org, &user).await,
        set(&["everyone"]),
        "the fixture resolves while the organization is live"
    );

    delete_org(&db, &env, scope, &org).await;
    assert!(
        roles_of(&db, scope, &org, &user).await.is_empty(),
        "a soft-deleted organization asserts no default role either"
    );
    assert!(permissions_of(&db, scope, &org, &user).await.is_empty());
    assert!(grants_of(&db, scope, &org, &user).await.is_empty());
    // Again nothing cascaded: the role row and its designation are exactly as they
    // were, and the resolution is empty because the seed refuses the organization.
    assert!(
        stored_is_default(&db, &baseline).await,
        "the soft delete cascaded nothing: the role is still designated"
    );
    assert_eq!(
        roles_of(&db, scope, &bystander, &other_user).await,
        set(&["staff"]),
        "and the sibling organization is still untouched"
    );
}

#[tokio::test]
async fn a_soft_deleted_membership_never_resolves_the_default_role() {
    // The membership seed read from the other side. `remove` soft-deletes the
    // membership and revokes every live attachment in the same transaction; this
    // subject HAS no attachment, so the strip is a no-op and `m.deleted_at IS NULL`
    // on the seed is the only thing that can decide the answer.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let baseline = create_role(&db, &env, scope, &org, "everyone").await;
    let read = create_permission(&db, &env, scope, "directory.read").await;
    attach(&db, &env, scope, &org, &baseline, &read).await;
    designate_default(&db, scope, &baseline).await;

    let (leaver, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    let (stayer, _stayer_membership) =
        create_member(&db, &env, scope, &org, "ops@example.test").await;

    assert_eq!(
        roles_of(&db, scope, &org, &leaver).await,
        set(&["everyone"])
    );
    assert_eq!(
        roles_of(&db, scope, &org, &stayer).await,
        set(&["everyone"])
    );

    remove_member(&db, &env, scope, &membership).await;
    assert!(
        roles_of(&db, scope, &org, &leaver).await.is_empty(),
        "a removed member stops holding the default role on the very next read"
    );
    assert!(permissions_of(&db, scope, &org, &leaver).await.is_empty());
    assert!(grants_of(&db, scope, &org, &leaver).await.is_empty());
    assert_eq!(
        roles_of(&db, scope, &org, &stayer).await,
        set(&["everyone"]),
        "and the member who stayed is unaffected, so the removal was not scope-wide"
    );
}

#[tokio::test]
async fn a_default_role_never_crosses_into_a_sibling_organization() {
    // `r.organization_id = $3` in the `effective_roles` arm, and its twin in the
    // provenance tail. Until this branch landed both were MUTUALLY REDUNDANT
    // survivors: every branch of the arm was an `IN` subquery carrying its own
    // `mr.organization_id` or `gr.organization_id`, so no sibling organization's role
    // could reach the arm for this predicate to refuse.
    //
    // The default branch carries no such subquery. `r.is_default AND EXISTS (SELECT 1
    // FROM membership)` says nothing about WHICH organization the role belongs to, so
    // this predicate is now the only thing standing between a caller and the default
    // role of every other organization in the environment. It is observable with no
    // corrupt row and no detached pointer: two organizations that have each designated
    // a default role is the ORDINARY configuration this feature produces.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let alpha = create_org(&db, &env, scope, "Alpha").await;
    let beta = create_org(&db, &env, scope, "Beta").await;
    // A third organization with a designated default and NO member at all, so the
    // sweep is not merely between two symmetric fixtures.
    let gamma = create_org(&db, &env, scope, "Gamma").await;

    let alpha_default = create_role(&db, &env, scope, &alpha, "alpha.everyone").await;
    let beta_default = create_role(&db, &env, scope, &beta, "beta.everyone").await;
    let gamma_default = create_role(&db, &env, scope, &gamma, "gamma.everyone").await;
    let alpha_permission = create_permission(&db, &env, scope, "alpha.read").await;
    let beta_permission = create_permission(&db, &env, scope, "beta.read").await;
    let gamma_permission = create_permission(&db, &env, scope, "gamma.read").await;
    attach(&db, &env, scope, &alpha, &alpha_default, &alpha_permission).await;
    attach(&db, &env, scope, &beta, &beta_default, &beta_permission).await;
    attach(&db, &env, scope, &gamma, &gamma_default, &gamma_permission).await;
    designate_default(&db, scope, &alpha_default).await;
    designate_default(&db, scope, &beta_default).await;
    designate_default(&db, scope, &gamma_default).await;

    let (alpha_user, _alpha_membership) =
        create_member(&db, &env, scope, &alpha, "a@example.test").await;
    let (beta_user, _beta_membership) =
        create_member(&db, &env, scope, &beta, "b@example.test").await;

    // Each member holds EXACTLY their own organization's default role. Equality of the
    // whole set rather than membership, so a leak is a failure rather than an extra
    // nobody looked at.
    assert_eq!(
        roles_of(&db, scope, &alpha, &alpha_user).await,
        set(&["alpha.everyone"]),
        "alpha's member holds alpha's default role and nothing else"
    );
    assert_eq!(
        roles_of(&db, scope, &beta, &beta_user).await,
        set(&["beta.everyone"]),
        "beta's member holds beta's default role and nothing else"
    );
    assert_eq!(
        permissions_of(&db, scope, &alpha, &alpha_user).await,
        set(&["alpha.read"])
    );
    assert_eq!(
        permissions_of(&db, scope, &beta, &beta_user).await,
        set(&["beta.read"])
    );
    // The provenance tail carries its own copy of the same predicate, so it is asserted
    // separately rather than assumed to agree.
    assert_eq!(
        grants_of(&db, scope, &alpha, &alpha_user).await,
        vec![as_default("alpha.everyone")]
    );
    assert_eq!(
        grants_of(&db, scope, &beta, &beta_user).await,
        vec![as_default("beta.everyone")]
    );
    // And an organization the caller is not a member of resolves nothing when asked
    // about directly, which is the same fence read from the caller's side.
    assert!(
        roles_of(&db, scope, &gamma, &alpha_user).await.is_empty(),
        "gamma's default role reaches nobody: it has no members"
    );
}

#[tokio::test]
async fn the_default_role_is_fenced_to_its_own_scope_including_a_sibling_environment() {
    // Scope fencing with the victim that actually makes the ENVIRONMENT half of the
    // fence decide: `seed_scope` mints a NEW TENANT on every call, so a probe between
    // two seeded scopes is refused by the tenant conjunct no matter how far the
    // environment conjunct is widened, and can say nothing about it.
    //
    // The sibling environment holds the SAME slugs throughout and designates its own
    // default role, so a resolution that leaked across would return a slug that looks
    // entirely plausible rather than an obviously foreign one.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let sibling_env = Scope::new(
        scope.tenant(),
        db.seed_environment(&env, scope.tenant()).await,
    );
    let other_tenant = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let baseline = create_role(&db, &env, scope, &org, "everyone").await;
    let read = create_permission(&db, &env, scope, "directory.read").await;
    attach(&db, &env, scope, &org, &baseline, &read).await;
    designate_default(&db, scope, &baseline).await;
    let (user, _membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    let sibling_org = create_org(&db, &env, sibling_env, "Globex").await;
    let sibling_baseline = create_role(&db, &env, sibling_env, &sibling_org, "everyone").await;
    let sibling_only = create_role(&db, &env, sibling_env, &sibling_org, "sibling.only").await;
    let sibling_permission = create_permission(&db, &env, sibling_env, "directory.read").await;
    let sibling_secret = create_permission(&db, &env, sibling_env, "sibling.secret").await;
    attach(
        &db,
        &env,
        sibling_env,
        &sibling_org,
        &sibling_baseline,
        &sibling_permission,
    )
    .await;
    attach(
        &db,
        &env,
        sibling_env,
        &sibling_org,
        &sibling_only,
        &sibling_secret,
    )
    .await;
    // The sibling environment designates the role that exists ONLY there, so a leak
    // across the environment half would show up as a slug this scope has never seen.
    designate_default(&db, sibling_env, &sibling_only).await;
    let (sibling_user, _sibling_membership) =
        create_member(&db, &env, sibling_env, &sibling_org, "dev@example.test").await;

    assert_eq!(
        roles_of(&db, scope, &org, &user).await,
        set(&["everyone"]),
        "this scope resolves its own designation"
    );
    assert_eq!(
        roles_of(&db, sibling_env, &sibling_org, &sibling_user).await,
        set(&["sibling.only"]),
        "and the sibling environment resolves its own, so the fixture is real"
    );
    assert_eq!(
        permissions_of(&db, sibling_env, &sibling_org, &sibling_user).await,
        set(&["sibling.secret"])
    );

    // Ids of one scope addressed through the OTHER scope's repository are the uniform
    // not-found, in both directions and across both dimensions of the scope.
    for (probe_scope, probe_org, probe_user, label) in [
        (
            sibling_env,
            &org,
            &user,
            "this scope's ids through the sibling ENVIRONMENT",
        ),
        (
            scope,
            &sibling_org,
            &sibling_user,
            "the sibling environment's ids through this scope",
        ),
        (
            other_tenant,
            &org,
            &user,
            "this scope's ids through another TENANT",
        ),
    ] {
        let outcome = db
            .control_store()
            .management()
            .org_groups(probe_scope)
            .effective_roles(probe_org, probe_user, DEFAULT_DEPTH)
            .await;
        assert!(
            matches!(outcome, Err(StoreError::NotFound)),
            "{label} must be the uniform not-found, got {outcome:?}"
        );
    }
}

#[tokio::test]
async fn a_default_role_whose_scope_columns_disagree_with_its_organization_never_resolves() {
    // The default branch's scope fence read at the SQL layer rather than at the Rust
    // one, which is a different question from the test above and is why both exist.
    //
    // Every cross-scope probe in
    // `the_default_role_is_fenced_to_its_own_scope_including_a_sibling_environment`
    // passes a TYPED id of one scope to a repository bound to another, and
    // `OrgGroupRepo::run_effective` refuses that with `NotFound` BEFORE it opens a
    // transaction or builds a statement. Those probes measure the RUST guard, and a
    // green result from them says nothing about what the statement would have done with
    // the row.
    //
    // This test reaches PAST that guard. Every id it hands the repository is its own,
    // so the guard passes and the statement runs; what is wrong is inside the DATA. The
    // shape is a role row whose `organization_id` is the caller's organization while
    // its `tenant_id` and `environment_id` name somewhere else. Nothing supported can
    // write it: 0086's column-scoped UPDATE grant names neither of those two nor
    // `organization_id` nor `id`, so no row moves between scopes after it is written,
    // and every INSERT the repository issues takes its scope columns from the same
    // bound scope the row-level-security WITH CHECK tests. It is representable at all
    // only because `org_roles_organization_id_fkey` references
    // `organizations (id)` alone rather than the composite key. It is the one shape
    // that defeats `r.organization_id = $3`, the predicate this feature promoted from
    // redundant to load-bearing, by SATISFYING it.
    //
    // # What this test pins, and what it does not: measured, not assumed
    //
    // It pins the OUTCOME and attributes the mechanism. It does NOT kill the arm's
    // `r.tenant_id = $1` or `r.environment_id = $2`, and it is worth being exact about
    // that rather than implying otherwise: all FOUR mutations of the arm's scope
    // predicates were run against it, dropping the tenant conjunct, the environment
    // conjunct, both, and all three INCLUDING `r.organization_id`, and this test stayed
    // GREEN through every one of them. So those predicates are EQUIVALENT with respect
    // to this shape, and the file header's census stands unchanged.
    //
    // The reason is not that the fixture is inert, and the two counts below are what
    // say so rather than leave it to be believed: three rows name the organization, and
    // the caller's own session can see ONE. Row-level security hides the other two from
    // the resolution's session before any predicate of the statement is reached, which
    // is why no arrangement of the WHERE clause changes the answer. Precisely: 0086 both
    // ENABLEs and FORCEs row-level security on `org_roles`, and the resolution runs as
    // the low-privilege control role rather than as the table owner, so the clause doing
    // the refusing is `org_roles_tenant_isolation`'s USING, which every non-owner role is
    // subject to under the ENABLE alone. The FORCE is what extends the same refusal to
    // the owner, and it is the reason the plants below had to be written through the
    // harness's SUPERUSER connection, which is the one writer no policy binds.
    //
    // That makes this the SHIPPED proof of a claim the tree otherwise carried only in
    // prose: the corrupt-row shape cannot leak, and row-level security rather than the
    // statement is what closes it. Its standing assertion is a REGRESSION one. If a
    // later migration ever relaxes that policy, or a later resolution reads `org_roles`
    // through a path that is not the scoped session, this is the test that turns red on
    // the leak itself rather than on a proxy for it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    // A sibling environment of the SAME tenant, so the first planted row differs from
    // the caller in the ENVIRONMENT column ALONE. `seed_scope` mints a fresh tenant on
    // every call, so a second seeded scope could never isolate that column.
    let sibling_env = Scope::new(
        scope.tenant(),
        db.seed_environment(&env, scope.tenant()).await,
    );
    let other_tenant = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    // The POSITIVE CONTROL, in the same organization and the same fixture: a correctly
    // scoped designated default role that DOES resolve. Without it every assertion
    // below could be satisfied by a fixture that resolves nothing at all, which is the
    // way a negative test quietly stops testing anything.
    let honest = create_role(&db, &env, scope, &org, "everyone").await;
    let read = create_permission(&db, &env, scope, "directory.read").await;
    attach(&db, &env, scope, &org, &honest, &read).await;
    designate_default(&db, scope, &honest).await;

    // Two corrupt rows, both designated the default and both naming the caller's
    // organization, differing from the caller in ONE scope column each. Their slugs are
    // distinct from the honest one and from each other, so a leak names which column
    // failed rather than merely showing an extra entry.
    let from_sibling_environment = plant_cross_scope_default_role(
        &db,
        &env,
        sibling_env,
        &org,
        "planted.from.sibling.environment",
    )
    .await;
    let from_other_tenant =
        plant_cross_scope_default_role(&db, &env, other_tenant, &org, "planted.from.other.tenant")
            .await;
    // Both plants are LIVE and DESIGNATED, read through the owner pool so the check
    // sees the rows as stored rather than as any scoped reader would. This is what
    // makes the negatives below about the fence: a plant that had been refused, or
    // whose flag had not landed, fails here.
    assert!(
        stored_is_default(&db, &from_sibling_environment).await,
        "the sibling-environment plant is stored as a designated default role"
    );
    assert!(
        stored_is_default(&db, &from_other_tenant).await,
        "the other-tenant plant is stored as a designated default role"
    );
    // The partial unique index tolerates all three at once precisely because it is keyed
    // on (tenant_id, environment_id, organization_id): the corrupt rows sit in different
    // key groups from the honest one despite naming the same organization. That is the
    // same id-only reach this whole test is about, seen from the index side.

    // THE ATTRIBUTION, and the reason the negatives below are not vacuous. Three rows
    // name this organization in the table as stored; the session the resolution itself
    // runs in can reach exactly ONE of them. The gap is forced row-level security on
    // `org_roles`, which refuses the planted rows before any predicate of the statement
    // is evaluated, and it is what makes the arm's scope conjuncts equivalent against
    // this shape rather than load-bearing against it.
    assert_eq!(
        stored_role_count(&db, &org).await,
        3,
        "the organization is named by the honest role and by both plants"
    );
    assert_eq!(
        visible_role_count(&db, scope, &org).await,
        1,
        "the caller's own session reaches only the correctly scoped role"
    );

    let (user, _membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    // A LIVE ACTIVE member of the organization, so `EXISTS (SELECT 1 FROM membership)`
    // holds and the default branch is genuinely evaluated. Equality of the whole set
    // rather than membership, so a planted slug that leaked is a failure rather than an
    // extra nobody looked at.
    assert_eq!(
        roles_of(&db, scope, &org, &user).await,
        set(&["everyone"]),
        "only the correctly scoped designation resolves; neither planted row reaches the arm"
    );
    // The permission projection reads the same arm, so a leaked role would drag no
    // permission along here (the plants carry none), but the set is asserted anyway to
    // show the positive control resolving all the way through.
    assert_eq!(
        permissions_of(&db, scope, &org, &user).await,
        set(&["directory.read"])
    );
    // The provenance tail carries its OWN copy of the scope pair on its own default
    // branch rather than reading the arm, so it is asserted separately rather than
    // assumed to agree with the roles projection.
    assert_eq!(
        grants_of(&db, scope, &org, &user).await,
        vec![as_default("everyone")],
        "the provenance projection reports one default entry, the honest one"
    );
}

#[tokio::test]
async fn a_role_that_is_also_granted_yields_one_slug_and_one_entry_per_path() {
    // The union rule and the multiset rule at once. The effective SET is a set, so a
    // role reachable three ways is ONE slug; the provenance is one entry per PATH, so
    // the same role is THREE entries. Collapsing those would hide the fact that
    // matters here: withdrawing the direct grant and the group grant leaves the role
    // in place, because the designation is not a grant and there is nothing to
    // withdraw.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let shared = create_role(&db, &env, scope, &org, "shared").await;
    let group_only = create_role(&db, &env, scope, &org, "grouponly").await;
    let read = create_permission(&db, &env, scope, "directory.read").await;
    attach(&db, &env, scope, &org, &shared, &read).await;

    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    grant_group_role(&db, &env, scope, &org, &group, &shared).await;
    grant_group_role(&db, &env, scope, &org, &group, &group_only).await;

    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    bind_member(&db, &env, scope, &org, &group, &membership).await;
    grant_direct_role(&db, &env, scope, &org, &membership, &shared).await;
    designate_default(&db, scope, &shared).await;

    // ONE slug per role, however many ways it is reachable.
    assert_eq!(
        roles_of(&db, scope, &org, &user).await,
        set(&["grouponly", "shared"]),
        "a role reachable three ways is still one slug"
    );
    assert_eq!(
        permissions_of(&db, scope, &org, &user).await,
        set(&["directory.read"]),
        "and its permissions are resolved once, not once per path"
    );
    // THREE entries for `shared`, in the total order the tail's ORDER BY defines:
    // slug, then the source token (`default` before `direct` before `group`), then the
    // group id. Equality of the whole vector, so an entry that went missing and an
    // entry that was reordered both fail.
    assert_eq!(
        grants_of(&db, scope, &org, &user).await,
        vec![
            as_group("grouponly", &group),
            as_default("shared"),
            as_direct("shared"),
            as_group("shared", &group),
        ],
        "one entry per grant PATH, never collapsed, with the default entry first"
    );

    // Withdrawing the designation leaves the two real grants standing, which is the
    // half of the union rule that says the branches are independent.
    clear_default(&db, scope, &shared).await;
    assert_eq!(
        grants_of(&db, scope, &org, &user).await,
        vec![
            as_group("grouponly", &group),
            as_direct("shared"),
            as_group("shared", &group),
        ],
        "clearing the designation removes exactly the default entry"
    );
    assert_eq!(
        roles_of(&db, scope, &org, &user).await,
        set(&["grouponly", "shared"]),
        "and the role is still held, because two grants still reach it"
    );
}

#[tokio::test]
async fn deleting_the_default_role_stops_it_resolving() {
    // `r.deleted_at IS NULL` on the arm's single `org_roles` scan. For the two grant
    // branches it has a second layer of sorts, in that the assignment row can be
    // withdrawn instead; for the DEFAULT branch there is no row to withdraw, so this
    // predicate is the whole of how a delete takes effect.
    //
    // Nothing clears `is_default` on delete, deliberately (migration 0093's section
    // (3)), so the flag is read back here to prove the emptiness is the predicate's
    // doing rather than a clearing pass.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let baseline = create_role(&db, &env, scope, &org, "everyone").await;
    let read = create_permission(&db, &env, scope, "directory.read").await;
    attach(&db, &env, scope, &org, &baseline, &read).await;
    designate_default(&db, scope, &baseline).await;
    let (user, _membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    assert_eq!(roles_of(&db, scope, &org, &user).await, set(&["everyone"]));

    delete_role(&db, &env, scope, &baseline).await;
    assert!(
        roles_of(&db, scope, &org, &user).await.is_empty(),
        "a soft-deleted role stops being the default on the very next read"
    );
    assert!(permissions_of(&db, scope, &org, &user).await.is_empty());
    assert!(grants_of(&db, scope, &org, &user).await.is_empty());
    assert!(
        stored_is_default(&db, &baseline).await,
        "the dead row KEEPS its designation: the liveness filter is what decides, not \
         a clearing pass"
    );

    // And because the uniqueness index is PARTIAL over live rows, the dead row does
    // not occupy the designation: a fresh role can take it immediately.
    let replacement = create_role(&db, &env, scope, &org, "everyone.v2").await;
    designate_default(&db, scope, &replacement).await;
    assert_eq!(
        roles_of(&db, scope, &org, &user).await,
        set(&["everyone.v2"]),
        "a dead default role does not block the next designation"
    );
}

#[tokio::test]
async fn changing_which_role_is_default_takes_effect_on_the_next_read() {
    // Retroactive by construction, in both directions and with no write against any
    // membership. This is the behaviour that made resolving preferable to
    // materializing: a materialized default would need an unbounded backfill here, and
    // it would attribute a grant to an operator who performed no grant.
    //
    // The second half is the structural half: `org_roles_org_default_live_uniq` refuses
    // a SECOND live default in one organization, so the swap must clear before it sets.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let bystander = create_org(&db, &env, scope, "Initech").await;
    let first = create_role(&db, &env, scope, &org, "everyone").await;
    let second = create_role(&db, &env, scope, &org, "contractor").await;
    let read = create_permission(&db, &env, scope, "directory.read").await;
    let limited = create_permission(&db, &env, scope, "directory.limited").await;
    attach(&db, &env, scope, &org, &first, &read).await;
    attach(&db, &env, scope, &org, &second, &limited).await;
    let (user, _membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    designate_default(&db, scope, &first).await;
    assert_eq!(roles_of(&db, scope, &org, &user).await, set(&["everyone"]));
    assert_eq!(
        permissions_of(&db, scope, &org, &user).await,
        set(&["directory.read"])
    );

    // A SECOND live default in one organization is refused by the index, which is what
    // makes "at most one" structural rather than a convention the write path keeps.
    let refusal = try_set_default(&db, scope, &second, true)
        .await
        .expect_err("a second live default in one organization must be refused");
    assert!(
        matches!(&refusal, sqlx::Error::Database(inner) if inner.code().as_deref() == Some("23505")),
        "the refusal is the unique-violation from org_roles_org_default_live_uniq, got \
         {refusal:?}"
    );
    assert_eq!(
        roles_of(&db, scope, &org, &user).await,
        set(&["everyone"]),
        "the refused write changed nothing"
    );

    // A sibling organization designating its own default at the same time is NOT a
    // conflict: the index is keyed per organization.
    let bystander_default = create_role(&db, &env, scope, &bystander, "everyone").await;
    designate_default(&db, scope, &bystander_default).await;

    // The swap, clear then set, and the very next read is the new answer.
    clear_default(&db, scope, &first).await;
    designate_default(&db, scope, &second).await;
    assert_eq!(
        roles_of(&db, scope, &org, &user).await,
        set(&["contractor"]),
        "the next read carries the new designation and not the old one"
    );
    assert_eq!(
        permissions_of(&db, scope, &org, &user).await,
        set(&["directory.limited"]),
        "and the permission set follows the role, with no write against the membership"
    );
    assert_eq!(
        grants_of(&db, scope, &org, &user).await,
        vec![as_default("contractor")]
    );
}
