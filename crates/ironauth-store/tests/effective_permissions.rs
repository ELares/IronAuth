// SPDX-License-Identifier: MIT OR Apache-2.0

//! The FOURTH projection over the shared effective-resolution closure (issue #98,
//! store PR 5): the effective PERMISSION set, over a real database (`DATABASE_URL`).
//!
//! Migration 0091 shipped a vocabulary of names and 0092 shipped the mapping that
//! gives a name authorization meaning. This is the read that turns those rows into an
//! answer, and `ironauth_oidc`'s mint emits that answer into an access token, so
//! everything here is about what the answer must be and about what must stop it.
//!
//! What this file pins, in the order the tests appear:
//!
//! * RESOLUTION over every shape that has mattered: a member with no roles, a role
//!   with no permissions, a direct grant only, a group grant, an ancestor-inherited
//!   grant, one permission reachable by SEVERAL paths yielding exactly one entry, and
//!   a permission attached to a role nobody holds staying absent. Plus determinism,
//!   plus the DATA plane (the plane the mint path runs on) resolving identically.
//! * AGREEMENT with the ROLE projection over randomized fixtures: the permission set
//!   is exactly the union of the mappings of the roles [`OrgGroupRepo::effective_roles`]
//!   reports. Both read one `effective_roles` arm, and this is what would catch them
//!   drifting apart.
//! * LIVENESS at EVERY level, one numbered rule per soft-deletable row on the path,
//!   against ONE fixture so the rules cannot be tested against several graphs. Two of
//!   them are this projection's own and have no second layer behind them: a DETACHED
//!   mapping and a soft-DELETED permission. Two more live in a test of their own, and
//!   they are there for two DIFFERENT reasons. A membership soft-deleted with its
//!   attachments left live is UNREACHABLE through the ordinary lifecycle, because
//!   `remove` revokes those attachments in the same transaction, so that test kills
//!   the row out of band. A binding into a DELETED group is perfectly reachable, since
//!   a group delete DETACHES; it was simply UNCOVERED, because no rule in the liveness
//!   test deletes the member's OWN group.
//! * The `kind` filter, twice over. An ENTITLEMENT planted by SQL and attached to a
//!   role the subject holds never resolves, while a PERMISSION of the same slug does;
//!   and a row whose `kind` is drifted underneath a live mapping stops resolving on
//!   the very next read. Together they pin that the projection discriminates on the
//!   kind COLUMN and that the literal in the SQL is the string the type writes.
//! * The ORGANIZATION fence, in both of its halves (disabled and soft-deleted), which
//!   this projection INHERITS from the closure's membership seed. That seed is the
//!   only organization-liveness fence anywhere on the issuance path, so these two are
//!   worth more than the rest of the file.
//! * The organization fence one layer lower: a mapping row whose stamped
//!   `organization_id` disagrees with its role's. The write path cannot produce one,
//!   the id-only foreign keys accept it, and `rp.organization_id` is the only thing in
//!   the statement that catches the FIRST of the two shapes. The second is refused for
//!   an entirely different reason, which is that the subject HOLDS NO SUCH ROLE, so
//!   the `effective_roles` arm's two grant subqueries never put it in the arm to map
//!   from. That arm's `r.organization_id` fence would refuse the same row, but it is a
//!   SECOND refusal here and nothing in this file kills it. That is a statement about
//!   this file and not about the predicate: `org_default_role.rs` DOES kill it, because
//!   the default-role branch reaches `org_roles` with no grant subquery beside it, and
//!   the census in `EFFECTIVE_CLOSURE_CTE` files it among the load-bearing predicates
//!   for that reason.
//! * SCOPE fencing, with the sharpest victim: a scope differing from the caller's in
//!   the ENVIRONMENT ALONE, holding the same slugs. `seed_scope` mints a NEW TENANT on
//!   every call, so a probe between two seeded scopes is decided by the tenant half
//!   and can say nothing about the environment half.
//! * TERMINATION on a STORED CYCLE through a soft-deleted node, which the live graph's
//!   acyclicity does not rule out and which this projection inherits from the walk.
//!
//! Two ways of planting a row coexist here, exactly as in `permissions.rs` and
//! `org_role_permissions.rs`. The audited write repositories are the production path
//! and are used for everything they can express. Direct SQL through the CONTROL pool,
//! under the same role, the same bound scope, and the same grants, is kept for the two
//! rows no supported path can write: an ENTITLEMENT (`NewPermission` deliberately
//! carries no `kind`, because issue #98's code only ever writes `kind = 'permission'`,
//! which migration 0091's header states as a property of this issue) and a mapping row
//! whose stamped organization disagrees with its role's.

use std::collections::{BTreeMap, BTreeSet};

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, NewAdminUser, NewMembership, NewOrgGroup, NewOrgGroupMember,
    NewOrgGroupRole, NewOrgMembershipRole, NewOrgRole, NewOrgRolePermission, NewPermission,
    ORG_GROUP_MAX_DEPTH_CEILING, OrgGroupId, OrgGroupMemberId, OrgGroupRoleId, OrgMembershipId,
    OrgMembershipRoleId, OrgRoleId, OrgRolePermissionId, OrganizationId, OrganizationState,
    PermissionEntryKind, PermissionId, Scope, ServiceId, StoreError, UserId, UserState,
};
use sqlx::Row;

/// A valid Argon2id PHC verifier (a fixed one; hashing is exercised in the higher
/// layers, the store only persists the string).
const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";

/// The depth bound most tests pass: the shipped `[organizations] max_group_depth`
/// default. Tests that are ABOUT the bound state their own.
const DEFAULT_DEPTH: u32 = 8;

/// The creation instant every row in this file is stamped with. Nothing here paginates
/// or orders by time, so one fixed instant keeps the fixtures free of any clock read.
const AT: i64 = 1_000;

fn actor(env: &Env) -> ActorRef {
    ActorRef::service(ServiceId::generate(env))
}

/// A `BTreeSet<String>` from string literals, for the expected-set assertions.
fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
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

/// Define a role in `org`.
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

/// Define a permission in `scope`'s vocabulary through the AUDITED WRITE repository:
/// the production path, which can only ever write `kind = 'permission'`.
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

/// Plant a vocabulary row of an explicit `kind` with DIRECT SQL through the control
/// pool, under the same role, the same bound scope, and the same grants the repository
/// runs with.
///
/// The ONLY way to create an ENTITLEMENT. [`NewPermission`] carries no `kind` field on
/// purpose: migration 0091's header states that issue #98's own code never writes
/// `kind = 'entitlement'`, and a kind-taking store writer would make that shipped
/// sentence false. Issue #103 is what widens the struct. Until then the projection's
/// `kind` filter is reachable only from here, which is exactly why the filter belongs
/// at the projection and not at write time.
async fn plant_permission(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    kind: PermissionEntryKind,
    slug: &str,
) -> PermissionId {
    let id = PermissionId::generate(env, &scope);
    let mut tx = db.control_pool().begin().await.expect("begin plant");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    sqlx::query(
        "INSERT INTO permissions \
         (id, tenant_id, environment_id, kind, slug, display_name, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, \
                 TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval, \
                 TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval)",
    )
    .bind(id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(kind.as_str())
    .bind(slug)
    .bind("Planted")
    .bind(AT)
    .execute(&mut *tx)
    .await
    .expect("plant the vocabulary row");
    tx.commit().await.expect("commit plant");
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

/// Attach `permission` to `role` through the AUDITED WRITE repository.
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

/// Detach a mapping through the audited write repository.
async fn detach(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    id: &OrgRolePermissionId,
) {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_role_permissions(scope)
        .unassign(env, org, id)
        .await
        .expect("detach the mapping");
}

/// Plant a mapping row with DIRECT SQL, stamping `stamped_org` regardless of which
/// organization `role` actually belongs to.
///
/// The repository refuses to write this row: `assign` resolves the role as LIVE IN the
/// organization it then stamps, so a mapping's organization and its role's always
/// agree on any data the write path can produce. The table's foreign keys are id only
/// and accept it perfectly, which is the gap `rp.organization_id` covers.
async fn plant_mapping(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    stamped_org: &OrganizationId,
    role: &OrgRoleId,
    permission: &PermissionId,
) -> OrgRolePermissionId {
    let id = OrgRolePermissionId::generate(env, &scope);
    let mut tx = db.control_pool().begin().await.expect("begin plant");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    sqlx::query(
        "INSERT INTO org_role_permissions \
         (id, tenant_id, environment_id, organization_id, role_id, permission_id, \
          created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, \
                 TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval, \
                 TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval)",
    )
    .bind(id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(stamped_org.to_string())
    .bind(role.to_string())
    .bind(permission.to_string())
    .bind(AT)
    .execute(&mut *tx)
    .await
    .expect("plant the mapping row");
    tx.commit().await.expect("commit plant");
    id
}

/// The effective PERMISSION slugs for `user` in `org`, resolved through the CONTROL
/// plane. The projection under test.
async fn permissions_of(
    db: &TestDatabase,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
    depth: u32,
) -> BTreeSet<String> {
    db.control_store()
        .management()
        .org_groups(scope)
        .effective_permissions(org, user, depth)
        .await
        .expect("resolve effective permissions")
}

/// The effective ROLE slugs for `user` in `org`: the sibling projection over the same
/// closure arm, used wherever a permission assertion has to be tied to the role set it
/// is supposed to be derived from.
async fn roles_of(
    db: &TestDatabase,
    scope: Scope,
    org: &OrganizationId,
    user: &UserId,
    depth: u32,
) -> BTreeSet<String> {
    db.control_store()
        .management()
        .org_groups(scope)
        .effective_roles(org, user, depth)
        .await
        .expect("resolve effective roles")
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
        .set_state(env, org, state)
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

/// How many LIVE mapping rows name `permission`, read through the OWNER pool so
/// nothing hides behind row-level security or behind a repository filter.
///
/// Used to prove the NEGATIVE assertions are about the predicate they name: when a
/// deleted permission stops resolving, this is what says its mapping row is still
/// live and that nothing cascaded.
async fn live_mappings_naming(db: &TestDatabase, permission: &PermissionId) -> i64 {
    sqlx::query(
        "SELECT count(*) AS n FROM org_role_permissions \
         WHERE permission_id = $1 AND deleted_at IS NULL",
    )
    .bind(permission.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count live mappings")
    .get("n")
}

/// How many LIVE rows of `table` reference `membership`, read through the OWNER pool
/// so nothing hides behind row-level security or behind a repository filter.
async fn live_attachment_count(
    db: &TestDatabase,
    scope: Scope,
    table: &str,
    membership: &OrgMembershipId,
) -> i64 {
    // `table` is a fixed test-local literal, never caller input.
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

/// Soft-delete a membership row DIRECTLY, bypassing the repository and therefore its
/// attachment cascade, through the owner pool.
///
/// The only way to build the state "membership dead, attachments still live", which is
/// what rows written by a binary older than that cascade look like and what any future
/// path that soft-deletes a membership without cascading would produce. Going through
/// the ordinary remove leaves nothing for the seed's own filter to do, so a missing
/// filter would still pass.
async fn kill_membership_row(db: &TestDatabase, scope: Scope, membership: &OrgMembershipId) {
    let affected = sqlx::query(
        "UPDATE org_memberships SET deleted_at = now() \
         WHERE tenant_id = $1 AND environment_id = $2 AND id = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(membership.to_string())
    .execute(db.owner_pool())
    .await
    .expect("soft-delete the membership row out of band")
    .rows_affected();
    assert_eq!(affected, 1, "the kill landed on exactly one row");
}

/// The stored `kind` of one vocabulary row, read through the OWNER pool.
async fn stored_kind(db: &TestDatabase, permission: &PermissionId) -> String {
    sqlx::query("SELECT kind FROM permissions WHERE id = $1")
        .bind(permission.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("read the stored kind")
        .get("kind")
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the resolution contract read as one story: nothing, then a direct \
              grant, then a group grant, then an inherited one, then several paths \
              to one permission, then determinism, each step building on the last \
              fixture so no step is measured against a graph of its own"
)]
async fn resolution_is_the_union_of_the_permissions_of_every_role_held() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    // all-staff -> engineering -> platform, a three-level chain, plus a branch the
    // member never joins.
    let all_staff = create_group(&db, &env, scope, &org, "all-staff", None).await;
    let engineering = create_group(&db, &env, scope, &org, "engineering", Some(&all_staff)).await;
    let platform = create_group(&db, &env, scope, &org, "platform", Some(&engineering)).await;
    let unrelated = create_group(&db, &env, scope, &org, "sales", None).await;

    let staff_role = create_role(&db, &env, scope, &org, "staff").await;
    let eng_role = create_role(&db, &env, scope, &org, "engineer").await;
    let platform_role = create_role(&db, &env, scope, &org, "platform-oncall").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;
    let sales_role = create_role(&db, &env, scope, &org, "seller").await;
    let bare_role = create_role(&db, &env, scope, &org, "auditor").await;

    let directory = create_permission(&db, &env, scope, "directory.read").await;
    let deploy = create_permission(&db, &env, scope, "deploy.write").await;
    let pager = create_permission(&db, &env, scope, "pager.ack").await;
    let billing = create_permission(&db, &env, scope, "billing.admin").await;
    let leads = create_permission(&db, &env, scope, "leads.export").await;
    let unattached = create_permission(&db, &env, scope, "nobody.holds-this").await;

    for (role, permission) in [
        (&staff_role, &directory),
        (&eng_role, &deploy),
        (&platform_role, &pager),
        (&direct_role, &billing),
        (&sales_role, &leads),
    ] {
        attach(&db, &env, scope, &org, role, permission).await;
    }
    for (group, role) in [
        (&all_staff, &staff_role),
        (&engineering, &eng_role),
        (&platform, &platform_role),
        (&unrelated, &sales_role),
    ] {
        grant_group_role(&db, &env, scope, &org, group, role).await;
    }

    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;

    // 1. A member of no groups holding no roles resolves to the EMPTY set, not an
    // error, even though the organization's vocabulary and its mappings are populated.
    assert!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a member who holds no role holds no permission"
    );

    // 2. A role with NO permissions attached grants none. Held, and still empty: this
    // is the case a projection that resolved roles rather than permissions would fail.
    grant_direct_role(&db, &env, scope, &org, &membership, &bare_role).await;
    assert_eq!(
        roles_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["auditor"]),
        "the role really is held"
    );
    assert!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a held role that carries no permission contributes none"
    );

    // 3. DIRECT only.
    grant_direct_role(&db, &env, scope, &org, &membership, &direct_role).await;
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin"]),
        "a member in no group holds exactly the permissions of their direct roles"
    );

    // 4. GROUP and ANCESTOR inherited: binding into the LEAF carries the whole chain,
    // so the permissions of the leaf's role AND of every ancestor's role resolve.
    bind_member(&db, &env, scope, &org, &platform, &membership).await;
    let inherited = permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await;
    assert_eq!(
        inherited,
        set(&[
            "billing.admin",
            "deploy.write",
            "directory.read",
            "pager.ack"
        ]),
        "the union over the direct, own-group, and ANCESTOR-inherited roles"
    );
    assert!(
        !inherited.contains("leads.export"),
        "the unrelated branch is not reachable, so its role's permission never appears"
    );
    assert!(
        !inherited.contains("nobody.holds-this"),
        "a permission attached to no role at all never appears"
    );
    let _ = unattached;

    // 5. ONE permission reachable by SEVERAL paths is exactly ONE entry. `directory.read`
    // arrives through the ancestor `all-staff` already; attach it to a SECOND held role
    // and grant it directly as well, so three independent paths carry the same slug.
    attach(&db, &env, scope, &org, &platform_role, &directory).await;
    let second_direct = create_role(&db, &env, scope, &org, "reader").await;
    attach(&db, &env, scope, &org, &second_direct, &directory).await;
    grant_direct_role(&db, &env, scope, &org, &membership, &second_direct).await;
    let many_paths = permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await;
    assert_eq!(
        many_paths, inherited,
        "a permission reachable three ways is still exactly one entry, and adds nothing"
    );

    // 6. DETERMINISM. Repeated evaluation against unchanged state is byte-identical,
    // and the iteration order is the total slug order a token claim will serialize.
    for _ in 0..5 {
        assert_eq!(
            permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
            many_paths,
            "two evaluations against identical stored state must be identical"
        );
    }
    assert_eq!(
        many_paths.iter().cloned().collect::<Vec<_>>(),
        vec![
            "billing.admin".to_owned(),
            "deploy.write".to_owned(),
            "directory.read".to_owned(),
            "pager.ack".to_owned(),
        ],
        "the set's iteration order is the total slug order"
    );

    // 7. The DATA plane resolves identically. That is the plane the mint path runs on,
    // and it holds SELECT and nothing else on every table this statement reads.
    assert_eq!(
        db.store()
            .scoped(scope)
            .org_groups()
            .effective_permissions(&org, &user, DEFAULT_DEPTH)
            .await
            .expect("the data plane can resolve"),
        many_paths
    );

    // 8. A user with no membership at all in this organization is the empty set, and is
    // indistinguishable from a member who holds nothing.
    let stranger = create_user(&db, &env, scope, "stranger@example.test").await;
    assert!(
        permissions_of(&db, scope, &org, &stranger, DEFAULT_DEPTH)
            .await
            .is_empty()
    );
}

/// How many randomized fixtures the agreement property sweeps.
const FIXTURES: usize = 4;
/// How many groups each randomized fixture builds.
const GROUPS: usize = 6;
/// How many roles each randomized fixture's organization defines.
const ROLES: usize = 5;
/// How many permissions each randomized fixture's environment defines.
const VOCABULARY: usize = 6;
/// The depth bound the randomized property resolves under, deliberately BELOW the
/// depth some generated chains reach so the sweep covers truncation too.
const DEPTH: u32 = 3;

/// A deterministic `SplitMix64` stream, seeded from a hard-coded constant so a failure
/// in CI is reproducible from the log alone.
///
/// A file-local generator rather than a crate: the workspace has no property-testing
/// dependency and `scripts/invariant-lints.sh` bans the `rand` family outright, so
/// randomness in tests is always seeded and replayable. This mirrors the convention
/// `org_assignments.rs` and the parse-fuzz corpora already follow.
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
    reason = "one randomized property: the generator, the fixture, and the two \
              projections being compared belong together or the comparison stops \
              being about the same stored state"
)]
async fn the_permission_set_is_exactly_the_mapping_of_the_role_set() {
    // What holds the shared `effective_roles` arm honest. Both projections read that
    // one arm, so the permissions resolved must be exactly the union of the mappings
    // of the roles the ROLE projection reports, over any graph. A permission tail
    // that re-derived "which roles are held" could pass every named fixture in this
    // file and still disagree here on a randomized one.
    //
    // The comparison is deliberately against the SHIPPED role projection rather than
    // against an in-memory ancestry model: `org_assignments.rs` already pins that
    // projection against an independent model, so re-deriving ancestry here would
    // test the model twice and the agreement not at all.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mut rng = Rng(0x5eed_0098_0005_0001);

    let permissions: Vec<PermissionId> = {
        let mut ids = Vec::with_capacity(VOCABULARY);
        for index in 0..VOCABULARY {
            ids.push(create_permission(&db, &env, scope, &format!("cap.p{index}")).await);
        }
        ids
    };

    for fixture in 0..FIXTURES {
        let org = create_org(&db, &env, scope, &format!("Org {fixture}")).await;

        // An acyclic forest by construction: node `i` may only parent to a smaller
        // index, so a failure can never be blamed on the generator.
        let mut group_ids: Vec<OrgGroupId> = Vec::with_capacity(GROUPS);
        for index in 0..GROUPS {
            let parent = if index == 0 || rng.below(4) == 0 {
                None
            } else {
                Some(group_ids[rng.below(index)])
            };
            group_ids.push(
                create_group(
                    &db,
                    &env,
                    scope,
                    &org,
                    &format!("g{index}"),
                    parent.as_ref(),
                )
                .await,
            );
        }

        let mut role_ids: Vec<OrgRoleId> = Vec::with_capacity(ROLES);
        for index in 0..ROLES {
            role_ids.push(create_role(&db, &env, scope, &org, &format!("r{index}")).await);
        }

        // A random role-to-permission mapping, kept in memory so the expectation can
        // be computed from the ROLE set alone.
        let mut mapping: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (role, role_id) in role_ids.iter().enumerate() {
            for (permission, permission_id) in permissions.iter().enumerate() {
                if rng.below(3) == 0 {
                    attach(&db, &env, scope, &org, role_id, permission_id).await;
                    mapping
                        .entry(format!("r{role}"))
                        .or_default()
                        .insert(format!("cap.p{permission}"));
                }
            }
        }

        for group_id in &group_ids {
            for role_id in &role_ids {
                if rng.below(5) == 0 {
                    grant_group_role(&db, &env, scope, &org, group_id, role_id).await;
                }
            }
        }

        let (user, membership) =
            create_member(&db, &env, scope, &org, &format!("u{fixture}@example.test")).await;
        for role_id in &role_ids {
            if rng.below(4) == 0 {
                grant_direct_role(&db, &env, scope, &org, &membership, role_id).await;
            }
        }
        for group_id in &group_ids {
            if rng.below(3) == 0 {
                bind_member(&db, &env, scope, &org, group_id, &membership).await;
            }
        }

        let held_roles = roles_of(&db, scope, &org, &user, DEPTH).await;
        let expected: BTreeSet<String> = held_roles
            .iter()
            .filter_map(|role| mapping.get(role))
            .flat_map(|slugs| slugs.iter().cloned())
            .collect();
        assert_eq!(
            permissions_of(&db, scope, &org, &user, DEPTH).await,
            expected,
            "fixture {fixture}: the permission set must be the mapping of the role set \
             (roles={held_roles:?}, mapping={mapping:?})"
        );
        // Non-vacuity, stated as an assertion rather than hoped for: at least one
        // fixture in the sweep must resolve a NONEMPTY set, or the property above is
        // comparing two empty sets and proves nothing.
        if fixture + 1 == FIXTURES {
            assert!(
                !expected.is_empty(),
                "the last fixture resolved nothing, so the sweep was vacuous"
            );
        }
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one exclusion rule per soft-deletable row on the permission path, \
              asserted against ONE fixture so the rules cannot be tested against \
              several different graphs"
)]
async fn resolution_excludes_every_soft_deleted_row_on_the_permission_path() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let parent = create_group(&db, &env, scope, &org, "all-staff", None).await;
    let child = create_group(&db, &env, scope, &org, "engineering", Some(&parent)).await;

    let parent_role = create_role(&db, &env, scope, &org, "staff").await;
    let child_role = create_role(&db, &env, scope, &org, "engineer").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;

    let directory = create_permission(&db, &env, scope, "directory.read").await;
    let deploy = create_permission(&db, &env, scope, "deploy.write").await;
    let billing = create_permission(&db, &env, scope, "billing.admin").await;

    let parent_map = attach(&db, &env, scope, &org, &parent_role, &directory).await;
    attach(&db, &env, scope, &org, &child_role, &deploy).await;
    attach(&db, &env, scope, &org, &direct_role, &billing).await;

    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    let binding = bind_member(&db, &env, scope, &org, &child, &membership).await;
    let parent_grant = grant_group_role(&db, &env, scope, &org, &parent, &parent_role).await;
    let child_grant = grant_group_role(&db, &env, scope, &org, &child, &child_role).await;
    let direct_grant = grant_direct_role(&db, &env, scope, &org, &membership, &direct_role).await;

    let baseline = set(&["billing.admin", "deploy.write", "directory.read"]);
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        baseline,
        "the baseline every exclusion below is measured against"
    );

    let acting = db
        .control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env));

    // 1. A DETACHED MAPPING stops granting, immediately, while BOTH endpoints stay
    // live. This is the projection's own filter and it has no second layer: the role
    // is still held and the permission is still defined, so `rp.deleted_at IS NULL` is
    // the only thing that can exclude it. Without it, an operator who detaches a
    // permission sees the audit row and sees the mapping leave every list while every
    // member holding that role keeps receiving the permission forever.
    detach(&db, &env, scope, &org, &parent_map).await;
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin", "deploy.write"]),
        "a detached mapping stops granting even though the role and the permission are \
         both still live"
    );
    assert!(
        roles_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .contains("staff"),
        "and the role itself is untouched, so this rule is about the mapping row"
    );
    // Restore the baseline with a FRESH mapping, so every rule below is measured
    // against the same three-permission fixture and none becomes vacuous.
    let parent_remap = attach(&db, &env, scope, &org, &parent_role, &directory).await;
    assert_ne!(
        parent_remap, parent_map,
        "a re-attach inserts a FRESH row; it does not revive the detached one"
    );
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        baseline
    );

    // 2. A soft-DELETED PERMISSION stops granting while its mapping row stays LIVE.
    // The mirror of rule 1 and the projection's other own filter: deleting a
    // permission does NOT cascade to the mapping (migration 0092 records why), so
    // `p.deleted_at IS NULL` is the only thing that observes the deletion.
    acting
        .permissions(scope)
        .delete(&env, &directory)
        .await
        .expect("delete the permission");
    assert_eq!(
        live_mappings_naming(&db, &directory).await,
        1,
        "the delete really did not cascade: the mapping row is still live"
    );
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin", "deploy.write"]),
        "a deleted permission stops resolving on the very next read"
    );
    // A permission RE-CREATED under the same slug is a fresh id and does NOT inherit
    // the dead one's mappings, so restoring the baseline needs a fresh attach too.
    let directory_again = create_permission(&db, &env, scope, "directory.read").await;
    assert_ne!(directory_again, directory);
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin", "deploy.write"]),
        "re-creating the slug does not revive the grant"
    );
    attach(&db, &env, scope, &org, &parent_role, &directory_again).await;
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        baseline
    );

    // 3. A soft-DELETED ROLE drops its permissions even while the mapping and the
    // permission are both live. This filter lives in the shared closure arm; the rule
    // is stated here because the answer being read is permissions, and a projection
    // that reached mappings without going through that arm would leak this one.
    acting
        .org_roles(scope)
        .delete(&env, &child_role)
        .await
        .expect("delete the role");
    assert_eq!(
        live_mappings_naming(&db, &deploy).await,
        1,
        "the role delete did not cascade to the mapping either"
    );
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin", "directory.read"]),
        "a deleted role carries none of its permissions"
    );

    // 4. A withdrawn GROUP GRANT stops applying to the group's own members, so the
    // permissions of that role stop resolving. Re-grant a live role to the child first,
    // because rule 3 deleted the one it held.
    let replacement = create_role(&db, &env, scope, &org, "engineer-2").await;
    attach(&db, &env, scope, &org, &replacement, &deploy).await;
    let replacement_grant = grant_group_role(&db, &env, scope, &org, &child, &replacement).await;
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        baseline
    );
    acting
        .org_group_roles(scope)
        .unassign(&env, &org, &replacement_grant)
        .await
        .expect("withdraw the group grant");
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin", "directory.read"]),
        "a withdrawn group grant takes its role's permissions with it"
    );
    let _ = child_grant;

    // 5. A soft-DELETED ANCESTOR GROUP detaches, so the permissions inherited through
    // it stop resolving.
    acting
        .org_groups(scope)
        .delete(&env, &org, &parent)
        .await
        .expect("delete the ancestor");
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin"]),
        "nothing is inherited through a deleted ancestor"
    );

    // 6. A soft-DELETED BINDING removes the whole group half. A live group
    // contribution is rebuilt FIRST, because rules 4 and 5 between them left the group
    // half contributing nothing: measured against that state this rule would pass with
    // the binding's liveness filter missing entirely.
    let rebound_role = create_role(&db, &env, scope, &org, "engineer-3").await;
    attach(&db, &env, scope, &org, &rebound_role, &deploy).await;
    grant_group_role(&db, &env, scope, &org, &child, &rebound_role).await;
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin", "deploy.write"]),
        "the group half is carrying a permission again, so the unbind below has \
         something to take away"
    );
    acting
        .org_group_members(scope)
        .remove(&env, &org, &binding)
        .await
        .expect("unbind");
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin"]),
        "an unbound member inherits nothing, and the direct grant survives"
    );

    // 7. A withdrawn DIRECT ASSIGNMENT drops its role's permissions.
    acting
        .org_membership_roles(scope)
        .unassign(&env, &org, &direct_grant)
        .await
        .expect("withdraw the direct grant");
    assert!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty()
    );

    // 8. A soft-DELETED MEMBERSHIP resolves to the empty set, not an error. Rebuild a
    // live grant first, so the assertion is about the membership and not about there
    // being nothing left to find.
    let fresh_role = create_role(&db, &env, scope, &org, "auditor").await;
    let audit_read = create_permission(&db, &env, scope, "audit.read").await;
    attach(&db, &env, scope, &org, &fresh_role, &audit_read).await;
    grant_direct_role(&db, &env, scope, &org, &membership, &fresh_role).await;
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["audit.read"])
    );
    acting
        .org_memberships(scope)
        .remove(&env, &membership)
        .await
        .expect("remove the membership");
    assert!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a user with no live membership resolves to the EMPTY set, never an error"
    );
    let _ = parent_grant;
}

#[tokio::test]
async fn an_entitlement_row_never_reaches_the_permission_projection() {
    // The `kind` filter, made real. `permissions.kind` admits `'entitlement'` from
    // migration 0091 as headroom for issue #103, and the write path deliberately does
    // NOT refuse one: `require_live_permission` resolves an entitlement exactly as it
    // resolves a permission, so an entitlement CAN be attached to a role through the
    // ordinary audited path. The projection's `p.kind = 'permission'` is the only
    // thing between such a row and an access token.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let role = create_role(&db, &env, scope, &org, "staff").await;
    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    grant_direct_role(&db, &env, scope, &org, &membership, &role).await;

    // The entitlement, planted by SQL because no supported writer can create one.
    let entitlement = plant_permission(
        &db,
        &env,
        scope,
        PermissionEntryKind::Entitlement,
        "plan.enterprise",
    )
    .await;
    assert_eq!(stored_kind(&db, &entitlement).await, "entitlement");

    // It attaches through the PRODUCTION path, and that is the point: the refusal
    // under test cannot be the write path's, because the write path accepts it.
    attach(&db, &env, scope, &org, &role, &entitlement).await;
    assert_eq!(
        live_mappings_naming(&db, &entitlement).await,
        1,
        "the entitlement really is attached to a role the subject holds"
    );
    assert!(
        roles_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .contains("staff"),
        "and the role really is held, so nothing else in the statement excludes this"
    );

    assert!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "an entitlement never reaches the permission projection"
    );

    // A PERMISSION of the SAME SLUG resolves. This is what makes the assertion above
    // about the `kind` column rather than about the slug, the mapping, or anything
    // else: the live-uniqueness key is `(tenant, environment, kind, slug)`, so the two
    // rows coexist, and only one of them is selected.
    let permission = create_permission(&db, &env, scope, "plan.enterprise").await;
    assert_ne!(permission, entitlement);
    attach(&db, &env, scope, &org, &role, &permission).await;
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["plan.enterprise"]),
        "the permission of the same slug resolves, and exactly once"
    );
}

#[tokio::test]
async fn the_projection_filters_the_same_kind_string_the_type_writes() {
    // The literal `'permission'` inside the tail is a COPY of a wire string that also
    // lives in `PermissionEntryKind` and in migration 0091's CHECK, and a copy in a SQL
    // string is exactly the kind that can drift without anything noticing. This pins
    // the three together from the outside: the type's string, the string the audited
    // create actually stores, and the value the projection selects on.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    assert_eq!(PermissionEntryKind::Permission.as_str(), "permission");
    assert_eq!(PermissionEntryKind::Entitlement.as_str(), "entitlement");

    let org = create_org(&db, &env, scope, "Globex").await;
    let role = create_role(&db, &env, scope, &org, "staff").await;
    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    grant_direct_role(&db, &env, scope, &org, &membership, &role).await;
    let permission = create_permission(&db, &env, scope, "billing.read").await;
    attach(&db, &env, scope, &org, &role, &permission).await;

    assert_eq!(
        stored_kind(&db, &permission).await,
        PermissionEntryKind::Permission.as_str(),
        "the audited create stores the string the type reports"
    );
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.read"]),
        "and the projection selects rows carrying that string"
    );

    // Drift the discriminator underneath a live mapping, changing NOTHING else. The
    // grant, the role, the membership and the mapping are all untouched, so the only
    // thing that can change the answer is the `kind` predicate.
    db.execute_owner_sql(&format!(
        "UPDATE permissions SET kind = 'entitlement' WHERE id = '{permission}'"
    ))
    .await;
    assert_eq!(
        live_mappings_naming(&db, &permission).await,
        1,
        "the mapping is still live, so this is about the kind column alone"
    );
    assert!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a row that stops being a permission stops resolving on the very next read"
    );
}

#[tokio::test]
async fn a_disabled_organization_resolves_to_no_permissions() {
    // The organization's OWN lifecycle is the COARSEST revocation the product has, and
    // the membership seed of the shared closure is the ONLY place on the issuance path
    // where it is checked. Nothing upstream re-checks it: `OrganizationRepo::get`
    // filters `deleted_at` and NOT `state`, so a disabled organization is still live
    // for management writes. This projection is fenced only because it reaches the
    // subject through that seed and through nothing else.
    //
    // A disable cascades NOTHING: every membership, group binding, role assignment and
    // mapping row underneath stays live and readable, which is precisely why the
    // resolution has to observe the organization row itself.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    // A second organization in the SAME scope, so this is proved to be a fence per
    // organization rather than a scope-wide outage.
    let bystander = create_org(&db, &env, scope, "Initech").await;

    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    let group_role = create_role(&db, &env, scope, &org, "engineer").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;
    let deploy = create_permission(&db, &env, scope, "deploy.write").await;
    let billing = create_permission(&db, &env, scope, "billing.admin").await;
    attach(&db, &env, scope, &org, &group_role, &deploy).await;
    attach(&db, &env, scope, &org, &direct_role, &billing).await;
    grant_group_role(&db, &env, scope, &org, &group, &group_role).await;

    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    bind_member(&db, &env, scope, &org, &group, &membership).await;
    grant_direct_role(&db, &env, scope, &org, &membership, &direct_role).await;

    let (other_user, other_membership) =
        create_member(&db, &env, scope, &bystander, "ops@example.test").await;
    let other_role = create_role(&db, &env, scope, &bystander, "keeper").await;
    let other_permission = create_permission(&db, &env, scope, "keys.rotate").await;
    attach(&db, &env, scope, &bystander, &other_role, &other_permission).await;
    grant_direct_role(&db, &env, scope, &bystander, &other_membership, &other_role).await;

    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin", "deploy.write"]),
        "the fixture resolves before any lifecycle change"
    );

    // DISABLED: the empty set, and NOT an error. A disabled organization is an operator
    // STATE, not a store fault, and refusing here would turn a deliberate
    // administrative action into a token-endpoint outage for every member.
    set_org_state(&db, &env, scope, &org, OrganizationState::Disabled).await;
    assert!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a disabled organization grants no permission"
    );
    assert_eq!(
        permissions_of(&db, scope, &bystander, &other_user, DEFAULT_DEPTH).await,
        set(&["keys.rotate"]),
        "a sibling organization in the same scope is untouched"
    );

    // Re-enabling restores it from rows that were never touched: a fence on live state,
    // not a destructive revocation.
    set_org_state(&db, &env, scope, &org, OrganizationState::Active).await;
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin", "deploy.write"]),
        "re-enabling restores the whole resolution"
    );
}

#[tokio::test]
async fn a_soft_deleted_organization_resolves_to_no_permissions_too() {
    // The other half of the organization fence, through the other lifecycle column.
    // Stated as its own test rather than as a second phase of the disable one, because
    // the two are separate predicates on the seed's join (`o.state = 'active'` and
    // `o.deleted_at IS NULL`) and a mutation that drops either must have a test that
    // fails on that column alone.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let bystander = create_org(&db, &env, scope, "Initech").await;

    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    let group_role = create_role(&db, &env, scope, &org, "engineer").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;
    let deploy = create_permission(&db, &env, scope, "deploy.write").await;
    let billing = create_permission(&db, &env, scope, "billing.admin").await;
    attach(&db, &env, scope, &org, &group_role, &deploy).await;
    attach(&db, &env, scope, &org, &direct_role, &billing).await;
    grant_group_role(&db, &env, scope, &org, &group, &group_role).await;

    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    bind_member(&db, &env, scope, &org, &group, &membership).await;
    grant_direct_role(&db, &env, scope, &org, &membership, &direct_role).await;

    let (other_user, other_membership) =
        create_member(&db, &env, scope, &bystander, "ops@example.test").await;
    let other_role = create_role(&db, &env, scope, &bystander, "keeper").await;
    let other_permission = create_permission(&db, &env, scope, "keys.rotate").await;
    attach(&db, &env, scope, &bystander, &other_role, &other_permission).await;
    grant_direct_role(&db, &env, scope, &bystander, &other_membership, &other_role).await;

    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin", "deploy.write"]),
        "the fixture resolves while the organization is live"
    );

    delete_org(&db, &env, scope, &org).await;
    assert!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a soft-deleted organization grants no permission either"
    );
    assert_eq!(
        permissions_of(&db, scope, &bystander, &other_user, DEFAULT_DEPTH).await,
        set(&["keys.rotate"]),
        "and the sibling organization is still untouched"
    );
}

#[tokio::test]
async fn a_soft_deleted_user_resolves_to_no_permissions() {
    // The USER'S tombstone (issue #406) on the FOURTH projection. The fence lives in
    // the membership seed of the shared closure, so this projection inherits it by
    // construction rather than by its own predicate; that inheritance is the whole
    // design claim, and it is only a claim until each projection is driven.
    //
    // A permission is the sharpest of the four to leave unfenced, because it names an
    // API capability rather than a label: a console reporting `billing.admin` for a
    // deleted account is reporting authority that account can never again exercise.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    let group_role = create_role(&db, &env, scope, &org, "engineer").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;
    let deploy = create_permission(&db, &env, scope, "deploy.write").await;
    let billing = create_permission(&db, &env, scope, "billing.admin").await;
    attach(&db, &env, scope, &org, &group_role, &deploy).await;
    attach(&db, &env, scope, &org, &direct_role, &billing).await;
    grant_group_role(&db, &env, scope, &org, &group, &group_role).await;

    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    bind_member(&db, &env, scope, &org, &group, &membership).await;
    grant_direct_role(&db, &env, scope, &org, &membership, &direct_role).await;

    // A second member of the SAME organization, holding the same permissions through
    // the same rows: the fence must be per user, not a collapse of the organization.
    let (bystander, bystander_membership) =
        create_member(&db, &env, scope, &org, "ops@example.test").await;
    grant_direct_role(&db, &env, scope, &org, &bystander_membership, &direct_role).await;

    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin", "deploy.write"]),
        "the fixture resolves while the user is live"
    );

    db.control_store()
        .scoped(scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .users()
        .delete(&env, &user, false, None)
        .await
        .expect("soft delete user");

    assert!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a soft-deleted user holds no permission"
    );
    assert!(
        roles_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "and the role set it derives from is empty too, so the two agree"
    );
    assert_eq!(
        permissions_of(&db, scope, &org, &bystander, DEFAULT_DEPTH).await,
        set(&["billing.admin"]),
        "another member of the same organization is untouched"
    );
}

#[tokio::test]
async fn the_projection_never_crosses_organization_via_a_corrupt_mapping_row() {
    // The organization fence the fourth projection adds, `rp.organization_id`, over the
    // two shapes of corruption it has to survive. It is the ONLY thing in the statement
    // that decides the FIRST, which is what earns it a place in the census. The SECOND
    // is read from BOTH organizations here, and the two readings are refused by
    // different things: from the organization that does not hold the role, by the
    // `effective_roles` arm declining to yield a role the subject was never granted;
    // from the one that DOES hold it, by `rp.organization_id` again. Which thing
    // decides which reading is measured rather than reasoned about, and the comments
    // below say so per shape.
    //
    // Neither row below is writable through any supported path: `assign` resolves the
    // role as live IN the organization it then stamps. Both satisfy every foreign key
    // (all three endpoints exist), so nothing under the application layer refuses them,
    // and an import, a restore, or a future write-path bug produces exactly this.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let alpha = create_org(&db, &env, scope, "Alpha").await;
    let beta = create_org(&db, &env, scope, "Beta").await;

    let alpha_role = create_role(&db, &env, scope, &alpha, "alpha.member").await;
    let beta_role = create_role(&db, &env, scope, &beta, "beta.admin").await;
    let held = create_permission(&db, &env, scope, "alpha.granted").await;
    let smuggled = create_permission(&db, &env, scope, "beta.secret").await;
    attach(&db, &env, scope, &alpha, &alpha_role, &held).await;
    attach(&db, &env, scope, &beta, &beta_role, &smuggled).await;

    let (alpha_user, alpha_membership) =
        create_member(&db, &env, scope, &alpha, "a@example.test").await;
    grant_direct_role(&db, &env, scope, &alpha, &alpha_membership, &alpha_role).await;
    let (beta_user, beta_membership) =
        create_member(&db, &env, scope, &beta, "b@example.test").await;
    grant_direct_role(&db, &env, scope, &beta, &beta_membership, &beta_role).await;

    assert_eq!(
        permissions_of(&db, scope, &alpha, &alpha_user, DEFAULT_DEPTH).await,
        set(&["alpha.granted"]),
        "the baseline both corruptions are measured against"
    );
    assert_eq!(
        permissions_of(&db, scope, &beta, &beta_user, DEFAULT_DEPTH).await,
        set(&["beta.secret"])
    );

    // Shape 1: a mapping row stamped with the SIBLING organization that names a role of
    // THIS one, which the subject holds. `rp.organization_id` is the only predicate in
    // the whole statement that catches this: the role is genuinely in
    // `effective_roles`, so the arm's own fence is satisfied and does nothing here.
    plant_mapping(&db, &env, scope, &beta, &alpha_role, &smuggled).await;
    assert_eq!(
        permissions_of(&db, scope, &alpha, &alpha_user, DEFAULT_DEPTH).await,
        set(&["alpha.granted"]),
        "a mapping stamped with another organization grants nothing here"
    );

    // Shape 2: the mirror, a mapping row stamped with THIS organization that names a
    // role of the SIBLING.
    //
    // Read from alpha, what keeps it out is that the subject HOLDS NO SUCH ROLE, which
    // is decided by the `effective_roles` arm's two GRANT SUBQUERIES rather than by any
    // organization predicate: alpha's membership has no `org_membership_roles` row
    // naming beta's role, and this fixture stands up no groups at all, so both
    // subqueries come back empty and beta's role is never in the arm to map from. The
    // arm's `r.organization_id` fence would refuse the row as well, but here it is the
    // SECOND refusal, and dropping it leaves every test in this file green. That is a
    // fact about this file, not about the predicate: since issue #98's default-role
    // branch reaches `org_roles` with no grant subquery beside it, that copy is load
    // bearing, and `a_default_role_never_crosses_into_a_sibling_organization` in
    // `org_default_role.rs` is the test that kills it.
    //
    // Read from beta, whose member DOES hold that role, `rp.organization_id` refuses it
    // instead, and THAT one is load bearing. The same corrupt row, two readers, two
    // different reasons.
    let alpha_only = create_permission(&db, &env, scope, "alpha.private").await;
    plant_mapping(&db, &env, scope, &alpha, &beta_role, &alpha_only).await;
    assert_eq!(
        permissions_of(&db, scope, &alpha, &alpha_user, DEFAULT_DEPTH).await,
        set(&["alpha.granted"]),
        "alpha's member holds no such role, so neither grant subquery of the arm ever \
         yields beta's role to map a permission from"
    );
    assert_eq!(
        permissions_of(&db, scope, &beta, &beta_user, DEFAULT_DEPTH).await,
        set(&["beta.secret"]),
        "and beta's member, who DOES hold that role, is kept out by the stamp instead"
    );
}

#[tokio::test]
async fn resolution_is_fenced_to_its_own_scope_including_a_sibling_environment() {
    // Scope fencing, with the victim that actually makes the environment half of the
    // fence deciding: `seed_scope` mints a NEW TENANT on every call, so a probe between
    // two seeded scopes is refused by the tenant conjunct no matter how far the
    // environment conjunct is widened, and can say nothing about it.
    //
    // This table pair makes the case sharp rather than hypothetical. The vocabulary is
    // per ENVIRONMENT (migration 0091's section (1)), so the SAME SLUG legitimately exists
    // as a different row in the sibling environment, and a resolution that leaked
    // across would return a slug that looks entirely plausible.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let sibling_env = Scope::new(
        scope.tenant(),
        db.seed_environment(&env, scope.tenant()).await,
    );
    let other_tenant = db.seed_scope(&env).await;

    // The caller's own fixture.
    let org = create_org(&db, &env, scope, "Globex").await;
    let role = create_role(&db, &env, scope, &org, "staff").await;
    let mine = create_permission(&db, &env, scope, "directory.read").await;
    attach(&db, &env, scope, &org, &role, &mine).await;
    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    grant_direct_role(&db, &env, scope, &org, &membership, &role).await;

    // The same shape again in the SIBLING ENVIRONMENT of the SAME TENANT, with the same
    // slugs throughout, plus a slug that exists ONLY there.
    let sibling_org = create_org(&db, &env, sibling_env, "Globex").await;
    let sibling_role = create_role(&db, &env, sibling_env, &sibling_org, "staff").await;
    let sibling_permission = create_permission(&db, &env, sibling_env, "directory.read").await;
    let sibling_only = create_permission(&db, &env, sibling_env, "sibling.only").await;
    attach(
        &db,
        &env,
        sibling_env,
        &sibling_org,
        &sibling_role,
        &sibling_permission,
    )
    .await;
    attach(
        &db,
        &env,
        sibling_env,
        &sibling_org,
        &sibling_role,
        &sibling_only,
    )
    .await;
    let (sibling_user, sibling_membership) =
        create_member(&db, &env, sibling_env, &sibling_org, "dev@example.test").await;
    grant_direct_role(
        &db,
        &env,
        sibling_env,
        &sibling_org,
        &sibling_membership,
        &sibling_role,
    )
    .await;

    // Each scope resolves its OWN answer, and the sibling-only slug never crosses.
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["directory.read"])
    );
    assert_eq!(
        permissions_of(&db, sibling_env, &sibling_org, &sibling_user, DEFAULT_DEPTH).await,
        set(&["directory.read", "sibling.only"]),
        "the sibling environment resolves its own vocabulary, so the fixture is real"
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
            .effective_permissions(probe_org, probe_user, DEFAULT_DEPTH)
            .await;
        assert!(
            matches!(outcome, Err(StoreError::NotFound)),
            "{label} must be the uniform not-found, got {outcome:?}"
        );
    }
}

#[tokio::test]
async fn resolution_terminates_on_a_stored_cycle_through_a_dead_node() {
    // The STORED graph can hold a cycle while the LIVE graph stays acyclic, because a
    // group delete DETACHES rather than cascades. This projection inherits the walk, so
    // it inherits both of the properties that make that safe: `deleted_at IS NULL` in
    // every arm, and the explicit depth guard. This test COMPLETING is the termination
    // assertion; the equality is the correctness one.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    // r -> a -> b built live, then `a` is deleted and `r` is reparented under `b`.
    // Reading each STORED parent_id as an arrow: r -> b, b -> a, a -> r, a cycle.
    let r = create_group(&db, &env, scope, &org, "r", None).await;
    let a = create_group(&db, &env, scope, &org, "a", Some(&r)).await;
    let b = create_group(&db, &env, scope, &org, "b", Some(&a)).await;

    let r_role = create_role(&db, &env, scope, &org, "role-r").await;
    let a_role = create_role(&db, &env, scope, &org, "role-a").await;
    let b_role = create_role(&db, &env, scope, &org, "role-b").await;
    let r_permission = create_permission(&db, &env, scope, "cap.r").await;
    let a_permission = create_permission(&db, &env, scope, "cap.a").await;
    let b_permission = create_permission(&db, &env, scope, "cap.b").await;
    for (role, permission) in [
        (&r_role, &r_permission),
        (&a_role, &a_permission),
        (&b_role, &b_permission),
    ] {
        attach(&db, &env, scope, &org, role, permission).await;
    }
    for (group, role) in [(&r, &r_role), (&a, &a_role), (&b, &b_role)] {
        grant_group_role(&db, &env, scope, &org, group, role).await;
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

    // The stored pointers really do form a cycle, read raw through the owner pool so
    // this is a fact about the rows rather than about what a repository projects.
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
    bind_member(&db, &env, scope, &org, &r, &membership).await;

    for depth in [DEFAULT_DEPTH, ORG_GROUP_MAX_DEPTH_CEILING] {
        assert_eq!(
            permissions_of(&db, scope, &org, &user, depth).await,
            set(&["cap.b", "cap.r"]),
            "the stored cycle must not carry the dead group's permission at depth {depth}"
        );
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the weakened-policy fixture, the proof that the fence really is down, \
              and both probes under it read as one unit: splitting them would rebuild \
              the fixture per probe and let two copies of the policy surgery drift"
)]
async fn the_projection_still_fences_the_environment_with_the_policy_half_down() {
    // What the statement's OWN scope conjuncts are worth, measured rather than
    // asserted. `p.tenant_id`, `p.environment_id`, `rp.tenant_id` and
    // `rp.environment_id` sit above two forced row-level-security policies that fence
    // the same rows, so with those policies intact each conjunct is an EQUIVALENT
    // mutant: dropping one alone leaves every other test in this file green, because
    // the policy refuses the row anyway. That is the expected consequence of the
    // backstop and not evidence the conjunct is dead.
    //
    // This is the one fixture where the two layers come apart, and it comes apart for
    // the ENVIRONMENT halves specifically. With the environment half of each policy
    // replaced away, `p.environment_id` and `rp.environment_id` are the only thing left,
    // and both rows below are ones the write path cannot produce and the id-only foreign
    // keys accept: a mapping of THIS environment naming a permission of the sibling
    // one, and a mapping stamped with the sibling environment naming a permission and
    // a role of this one. Each isolates one side of the pair, so dropping
    // `p.environment_id` reddens the first probe and dropping `rp.environment_id`
    // reddens the second.
    //
    // The two TENANT conjuncts stay equivalent survivors even under this fixture, and no
    // fixture on this statement can change that, because the reason is structural rather
    // than a gap here: `environments_pkey` is on `id` ALONE, so an environment id
    // DETERMINES its tenant, and the environment conjunct standing beside each tenant
    // one already excludes every cross-tenant row.
    //
    // The policies are REPLACED rather than dropped: both tables FORCE row-level
    // security, so a table carrying no policy at all denies everything and every probe
    // below would pass for exactly the wrong reason.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let sibling_env = Scope::new(
        scope.tenant(),
        db.seed_environment(&env, scope.tenant()).await,
    );

    let org = create_org(&db, &env, scope, "Globex").await;
    let role = create_role(&db, &env, scope, &org, "staff").await;
    let mine = create_permission(&db, &env, scope, "directory.read").await;
    attach(&db, &env, scope, &org, &role, &mine).await;
    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    grant_direct_role(&db, &env, scope, &org, &membership, &role).await;

    // The sibling environment's own vocabulary row, live in its own scope.
    let theirs = create_permission(&db, &env, sibling_env, "sibling.only").await;

    for statement in [
        "DROP POLICY permissions_tenant_isolation ON permissions",
        "CREATE POLICY permissions_tenant_isolation ON permissions \
         USING (tenant_id = current_setting('ironauth.tenant_id', true)) \
         WITH CHECK (tenant_id = current_setting('ironauth.tenant_id', true))",
        "DROP POLICY org_role_permissions_tenant_isolation ON org_role_permissions",
        "CREATE POLICY org_role_permissions_tenant_isolation ON org_role_permissions \
         USING (tenant_id = current_setting('ironauth.tenant_id', true)) \
         WITH CHECK (tenant_id = current_setting('ironauth.tenant_id', true))",
    ] {
        db.execute_owner_sql(statement).await;
    }

    // The fence really is down: a raw session bound to this scope now sees the sibling
    // environment's vocabulary row too. Without this the probes below would prove
    // nothing about the statement.
    {
        let mut tx = db
            .control_pool()
            .begin()
            .await
            .expect("begin weakened-policy read");
        bind_scope(
            &mut tx,
            &scope.tenant().to_string(),
            &scope.environment().to_string(),
        )
        .await;
        let visible: i64 = sqlx::query("SELECT count(*) AS c FROM permissions")
            .fetch_one(&mut *tx)
            .await
            .expect("count under the weakened policy")
            .get("c");
        assert_eq!(
            visible, 2,
            "the weakened policy must no longer fence the environment, or this test \
             proves nothing about the statement"
        );
        tx.commit().await.expect("commit the weakened-policy read");
    }

    // Row 1: a mapping of THIS environment, attached to a role the subject holds, that
    // names the SIBLING environment's permission. `require_live_permission` refuses
    // this pairing, so no supported path can write it. What excludes the slug now is
    // `p.tenant_id` and `p.environment_id` alone.
    plant_mapping(&db, &env, scope, &org, &role, &theirs).await;
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["directory.read"]),
        "a permission of the sibling environment does not resolve, even with the \
         permissions policy's environment half down"
    );

    // Row 2: a mapping stamped with the SIBLING environment naming this environment's
    // role and permission. Written through the owner pool because even the weakened
    // policy's WITH CHECK would refuse it from a scoped session. What excludes it now
    // is `rp.tenant_id` and `rp.environment_id` alone.
    let smuggled = create_permission(&db, &env, scope, "smuggled.read").await;
    let planted_id = OrgRolePermissionId::generate(&env, &scope);
    db.execute_owner_sql(&format!(
        "INSERT INTO org_role_permissions \
         (id, tenant_id, environment_id, organization_id, role_id, permission_id, \
          created_at, updated_at) \
         VALUES ('{planted_id}', '{}', '{}', '{org}', '{role}', '{smuggled}', now(), now())",
        scope.tenant(),
        sibling_env.environment(),
    ))
    .await;
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["directory.read"]),
        "a mapping row stamped with the sibling environment grants nothing here, even \
         with the mapping policy's environment half down"
    );
}

#[tokio::test]
async fn resolution_ignores_a_binding_into_a_dead_group_and_a_dead_membership() {
    // The two seed-arm liveness filters that survived every other test in this file,
    // which is exactly why they get one of their own. Each is guarded by exactly one
    // predicate in the seed, but they survived for two DIFFERENT reasons, and the
    // difference is what tells the next author whether an ordinary test could have
    // caught them.
    //
    // Step 1's binding whose GROUP was deleted is an entirely ORDINARY state that any
    // operator can produce, because a group delete DETACHES and the binding row stays
    // live. That filter was merely UNCOVERED: no other test here deletes the member's
    // OWN group, and rule 5 of the liveness test deletes an ANCESTOR, which the
    // recursive arm's copy of the filter decides instead of the seed's.
    //
    // Step 2's MEMBERSHIP soft-deleted with its attachments left live is the
    // REACHABILITY case, and the ordinary lifecycle cannot produce it at all: `remove`
    // revokes every binding and every direct grant in the same transaction, so it never
    // leaves anything standing for the seed filter to decide. That is why the step below
    // kills the row out of band rather than calling `remove`, and the state it builds is
    // one an import or a restore reaches rather than one an operator can.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let group = create_group(&db, &env, scope, &org, "engineering", None).await;
    let group_role = create_role(&db, &env, scope, &org, "engineer").await;
    let direct_role = create_role(&db, &env, scope, &org, "founder").await;
    let deploy = create_permission(&db, &env, scope, "deploy.write").await;
    let billing = create_permission(&db, &env, scope, "billing.admin").await;
    attach(&db, &env, scope, &org, &group_role, &deploy).await;
    attach(&db, &env, scope, &org, &direct_role, &billing).await;

    let (user, membership) = create_member(&db, &env, scope, &org, "dev@example.test").await;
    grant_group_role(&db, &env, scope, &org, &group, &group_role).await;
    bind_member(&db, &env, scope, &org, &group, &membership).await;
    grant_direct_role(&db, &env, scope, &org, &membership, &direct_role).await;
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin", "deploy.write"]),
        "the baseline both exclusions below are measured against"
    );

    // 1. The member's OWN group is DELETED while the binding stays LIVE. Only the seed
    // arm's group-liveness filter keeps the dead group, its still-live role grant, and
    // that role's still-live permission mapping out of the answer.
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
        live_mappings_naming(&db, &deploy).await,
        1,
        "and the permission mapping is untouched too"
    );
    assert_eq!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH).await,
        set(&["billing.admin"]),
        "a binding into a DELETED group contributes no permission"
    );

    // 2. The MEMBERSHIP is soft-deleted with its attachments left live. That predicate
    // is the only thing standing between a removed member and their old permissions.
    kill_membership_row(&db, scope, &membership).await;
    assert_eq!(
        live_attachment_count(&db, scope, "org_membership_roles", &membership).await,
        1,
        "the fixture keeps the direct grant LIVE, so only the membership filter can \
         exclude it"
    );
    assert!(
        permissions_of(&db, scope, &org, &user, DEFAULT_DEPTH)
            .await
            .is_empty(),
        "a user with no live membership resolves to nothing, whatever rows still name \
         them"
    );
}
