// SPDX-License-Identifier: MIT OR Apache-2.0

//! The role-to-permission mapping (issue #98, store PR 3), over a real database
//! (`DATABASE_URL`).
//!
//! This is the table that gives a permission its authorization meaning. Migration
//! 0091 shipped a vocabulary of NAMES; 0092 is what puts one of those names into an
//! organization's role, and therefore into an access token for every member who
//! effectively holds that role.
//!
//! What this file pins, in the order the tests appear:
//!
//! * The round trip: attach, read by id, by `(organization, id)`, by the
//!   PAIR ADDRESS, and both ways round through the two lists; detach; and the audit
//!   multiset after every step, checked scope-wide as well as per target so a
//!   PHANTOM row written against another id or into another scope cannot hide.
//! * CROSS PAIRING. Four caller-supplied identifiers meet here and only some
//!   combinations are legal. A role of organization A named from organization B's
//!   path, a permission that does not exist, a permission of ANOTHER ENVIRONMENT
//!   (the interesting one, because the vocabulary is per environment and the foreign
//!   key cannot see the difference), and a role of another scope are each the
//!   uniform not-found with nothing mutated and nothing audited.
//! * ORGANIZATION containment inside ONE scope, which is the only pair a cross-scope
//!   test cannot stand in for: row-level security fences `(tenant, environment)` and
//!   nothing finer, so the organization predicate an organization-addressed read or
//!   write carries is the whole fence between two organizations of one environment.
//!   The one DELIBERATE exception is pinned in the same test: `get` is addressed by
//!   the mapping id alone, carries no organization predicate, and resolves a sibling
//!   organization's row.
//! * PAGINATION, in two separable halves. The CURSOR comparison must be strict and
//!   keyed on `(created_at, id)`, and the list's own ORDER BY must be TOTAL, which
//!   only becomes observable once the index that supplies the order incidentally is
//!   taken away. Every walk in this file is BOUNDED, so a cursor that stops
//!   advancing fails fast instead of hanging the job.
//! * LIVENESS on all three rows: a soft-deleted role and a soft-deleted permission
//!   are unattachable, a detached mapping is invisible and re-detaching it is the
//!   uniform not-found, and re-attaching after a detach mints a FRESH id rather than
//!   reviving the dead row.
//! * The live PAIR uniqueness index, both halves, plus the property that would be
//!   lost if `organization_id` were in its key.
//! * Forced row-level security, with ALL THREE halves of the policy individually
//!   pinned: the environment conjunct (a victim differing from the caller ONLY in
//!   the environment), the `WITH CHECK` half (a forge INSERT binding the victim's
//!   own live endpoint ids, so nothing but the policy can refuse it), and the tenant
//!   conjunct, which needs a MISMATCHED-SCOPE session to reach at all because an
//!   environment id is globally unique and names exactly one tenant. Plus the
//!   write-side environment fence, pinned by weakening the deployed policy.
//! * Least-privilege grants, swept from `pg_attribute` as an exact set, with a
//!   data-plane FORGE probe whose refusal is attributable to the MISSING GRANT
//!   rather than to the policy.
//! * Audit atomicity in BOTH directions, and the covenant: a role may carry
//!   unlimited permissions and a permission may be carried by unlimited roles.
//! * The role-scoped COUNT (issue #425), which is what the management attach response
//!   reports its budget verdict over. Its organization fence is pinned on its own by
//!   the CROSS ORGANIZATION ADDRESS assertion, which a mutant that neutered the
//!   predicate answers with the addressed role's own non-zero count instead of zero,
//!   plus liveness and the cross-scope zero with a positive control behind it. Two
//!   further properties get their own fixtures because nothing smaller reaches them:
//!   the count is driven PAST the list's page clamp, so substituting a page length is
//!   red rather than silent, and a mapping whose PERMISSION has been soft-deleted is
//!   asserted to keep counting, which is the mechanism that makes this figure larger
//!   than the set a token would carry.
//!
//! Two ways of planting a row coexist here on purpose, exactly as in
//! `permissions.rs`. `attach` goes through the audited write repository and is the
//! production path. `plant_mapping` uses direct SQL through the CONTROL pool, under
//! the same role, the same bound scope, and the same grants, and is kept for the two
//! things the repository deliberately cannot do: write a pairing the repository
//! refuses (which is how the uniqueness key is probed in a shape no supported path
//! can reach), and surface the CONSTRAINT NAME, so a refusal is pinned to the rule
//! that was meant to refuse rather than to something else that happened to fail.
//!
//! Cross-tenant and cross-environment isolation is additionally exercised through
//! the registered IDOR probes (`crates/ironauth-admin/tests/idor.rs`), which now
//! include the mutating `org_role_permissions.unassign`.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, CursorPosition, MANAGEMENT_LIST_HARD_CAP, NewOrgRole,
    NewOrgRolePermission, NewPermission, OrgRoleId, OrgRolePermissionId, OrganizationId,
    PermissionId, Scope, ServiceId, StoreError,
};
use sqlx::{PgPool, Row};

/// The Postgres "insufficient privilege" SQLSTATE.
const INSUFFICIENT_PRIVILEGE: &str = "42501";
/// The Postgres "unique violation" SQLSTATE.
const UNIQUE_VIOLATION: &str = "23505";

/// A page size comfortably above anything most tests create. Page size is clamped on
/// every management list; the number of stored rows is not.
const PAGE: i64 = 500;

/// How many permissions the covenant walk attaches to ONE role, and how many roles
/// it attaches ONE permission to. Enough that a count gate would have to fire,
/// small enough to stay inside the test job's time budget.
const WIDE: usize = 40;

/// How many mappings the cursor-tiebreak walk pins to ONE instant. Comfortably more
/// than the page size it is walked at, so a page boundary lands INSIDE the tie.
const TIED: usize = 10;

/// The page size both covenant walks page at: small enough that several page
/// boundaries are crossed.
const WALK_PAGE: usize = 7;

/// The page size the tied-set walk pages at, chosen so a boundary lands INSIDE the
/// tie, which is exactly where a cursor keyed on `created_at` alone loses rows.
const TIED_PAGE: usize = 4;

/// The iteration cap every pagination walk in this file runs under.
///
/// A cursor comparison that is not STRICT (`>=` where `>` is meant) makes a walk
/// serve the SAME page forever. In an unbounded loop that defect does not fail, it
/// HANGS: the test job burns its whole budget and reports nothing, which is strictly
/// worse than a red. The cap turns it into a fast, named failure.
///
/// Generous by construction, so no correct walk can reach it: one iteration per row,
/// plus one per page, plus slack for the terminating empty page.
fn walk_cap(rows: usize, page: usize) -> usize {
    rows + rows.div_ceil(page) + 8
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

fn actor(env: &Env) -> ActorRef {
    ActorRef::service(ServiceId::generate(env))
}

/// Create an organization in `scope` through the control store.
async fn create_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, 1_000, name, None)
        .await
        .expect("create organization");
    id
}

/// Define a role in `org` through the control store.
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
            1_000,
            None,
        )
        .await
        .expect("create role");
    id
}

/// Define a permission in `scope`'s vocabulary through the control store.
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
            1_000,
            None,
        )
        .await
        .expect("create permission");
    id
}

/// Attach `permission` to `role` through the AUDITED WRITE repository: the
/// production path, which writes the row and its
/// `organization.role.permission.assign` audit row in one transaction.
///
/// The creation instant is supplied by the caller so a test can pin rows to chosen
/// times; nothing here reads a wall clock of its own.
async fn attach_at(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    role: &OrgRoleId,
    permission: &PermissionId,
    created_at_micros: i64,
) -> Result<OrgRolePermissionId, StoreError> {
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
            created_at_micros,
            None,
        )
        .await
        .map(|_attached| id)
}

/// Attach at a fixed instant, for the majority of tests that do not care.
async fn attach(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    role: &OrgRoleId,
    permission: &PermissionId,
) -> Result<OrgRolePermissionId, StoreError> {
    attach_at(db, env, scope, org, role, permission, 2_000).await
}

/// Detach a mapping through the audited write repository.
async fn detach(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    id: &OrgRolePermissionId,
) -> Result<(), StoreError> {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_role_permissions(scope)
        .unassign(env, org, id)
        .await
}

/// Write a mapping row with DIRECT SQL through the control pool, under the same
/// role, the same bound scope, and the same grants the repository runs with.
///
/// Kept for exactly what the repository refuses to do: pair endpoints that do not
/// belong together, so the live-uniqueness index can be probed in a shape no
/// supported path can reach, and surface the driver error so a refusal can be
/// attributed to a CONSTRAINT BY NAME.
async fn plant_mapping(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    role: &OrgRoleId,
    permission: &PermissionId,
    created_at_micros: i64,
) -> Result<OrgRolePermissionId, sqlx::Error> {
    let id = OrgRolePermissionId::generate(env, &scope);
    let mut tx = db.control_pool().begin().await.expect("begin plant");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    let result = sqlx::query(
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
    .bind(org.to_string())
    .bind(role.to_string())
    .bind(permission.to_string())
    .bind(created_at_micros)
    .execute(&mut *tx)
    .await;
    match result {
        Ok(_) => {
            tx.commit().await.expect("commit plant");
            Ok(id)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// Plant `rows` live mappings on ONE role in ONE statement pair, with a fresh
/// permission behind each, through the control pool under the same role, the same
/// bound scope and the same grants the repository runs with.
///
/// The ONLY caller is `count_live_for_role_is_not_a_page_length`, which needs more
/// mappings than a page can return and would otherwise pay for a couple of thousand
/// audited write transactions to get there. Nothing about the count under test depends
/// on how the rows arrived, and every property that DOES depend on the audited write
/// path is proved row by row elsewhere in this file.
///
/// Ids are generated the same way the repository generates them, so the planted rows
/// are indistinguishable from written ones; `created_at` is spread so the list's
/// `(created_at, id)` order is total over them without relying on the id tiebreak.
async fn plant_many(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    role: &OrgRoleId,
    rows: i64,
) {
    let count = usize::try_from(rows).expect("a row count fits usize");
    let permission_ids: Vec<String> = (0..count)
        .map(|_| PermissionId::generate(env, &scope).to_string())
        .collect();
    let mapping_ids: Vec<String> = (0..count)
        .map(|_| OrgRolePermissionId::generate(env, &scope).to_string())
        .collect();

    let mut tx = db.control_pool().begin().await.expect("begin plant many");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    sqlx::query(
        "INSERT INTO permissions (id, tenant_id, environment_id, slug, display_name) \
         SELECT p.id, $1, $2, 'bulk.capability_' || p.ord, 'Capability' \
         FROM unnest($3::text[]) WITH ORDINALITY AS p(id, ord)",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(&permission_ids)
    .execute(&mut *tx)
    .await
    .expect("plant the permissions");
    sqlx::query(
        "INSERT INTO org_role_permissions \
         (id, tenant_id, environment_id, organization_id, role_id, permission_id, \
          created_at, updated_at) \
         SELECT t.mapping_id, $1, $2, $3, $4, t.permission_id, \
                TIMESTAMPTZ 'epoch' + (t.ord::text || ' microseconds')::interval, \
                TIMESTAMPTZ 'epoch' + (t.ord::text || ' microseconds')::interval \
         FROM unnest($5::text[], $6::text[]) \
              WITH ORDINALITY AS t(mapping_id, permission_id, ord)",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(org.to_string())
    .bind(role.to_string())
    .bind(&mapping_ids)
    .bind(&permission_ids)
    .execute(&mut *tx)
    .await
    .expect("plant the mappings");
    tx.commit().await.expect("commit plant many");
}

/// The audit actions recorded against `target_id` in `scope`, in order. Read through
/// the OWNER pool so nothing hides behind row-level security: an audit row written
/// into the WRONG scope would be invisible to a scoped read and would look exactly
/// like an absent one.
async fn audit_actions(db: &TestDatabase, scope: Scope, target_id: &str) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT action FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND target_id = $3 \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(target_id)
    .fetch_all(db.owner_pool())
    .await
    .expect("read audit rows");
    rows.iter()
        .map(|row| row.get::<String, _>("action"))
        .collect()
}

/// Every `organization.role.permission.*` audit action anywhere in the database,
/// regardless of scope and regardless of target, read through the OWNER pool.
///
/// The scope-blind counterpart of [`audit_actions`]. A per-target read cannot see a
/// PHANTOM audit row written against some other id, nor one written into another
/// scope, and both are exactly what a broken failure path would leave behind.
async fn all_mapping_audit_actions(db: &TestDatabase) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT action FROM audit_log WHERE action LIKE 'organization.role.permission.%' \
         ORDER BY occurred_at, id",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("read mapping audit rows");
    rows.iter()
        .map(|row| row.get::<String, _>("action"))
        .collect()
}

/// Count rows of `org_role_permissions` matching `predicate`, through the OWNER pool
/// so row-level security hides nothing: a row written into another scope still
/// counts.
async fn count_mappings(db: &TestDatabase, predicate: &str) -> i64 {
    // `predicate` is a fixed test-local literal, never caller input.
    sqlx::query(&format!(
        "SELECT count(*) AS c FROM org_role_permissions WHERE {predicate}"
    ))
    .fetch_one(db.owner_pool())
    .await
    .expect("count mappings")
    .get("c")
}

/// The ids of every live mapping of `role`, ordered by `id` ALONE, read through the
/// OWNER pool.
///
/// The reference the list's own `ORDER BY created_at, id` must reproduce once every
/// row shares one `created_at`: under a full tie the two orders are the same order by
/// definition. Sorted by the DATABASE rather than in Rust, so the comparison is in
/// the column's own collation and not in whatever order Rust would put the strings.
async fn ids_ordered_by_id(db: &TestDatabase, role: &OrgRoleId) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT id FROM org_role_permissions \
         WHERE role_id = $1 AND deleted_at IS NULL ORDER BY id",
    )
    .bind(role.to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read mapping ids ordered by id");
    rows.iter().map(|row| row.get::<String, _>("id")).collect()
}

/// How many indexes of `name` exist on `org_role_permissions`. Read from the
/// catalog, so a test that removes an index to expose the layer above it can prove
/// the removal actually happened.
async fn count_indexes_named(db: &TestDatabase, name: &str) -> i64 {
    sqlx::query(
        "SELECT count(*) AS c FROM pg_index \
         JOIN pg_class idx ON idx.oid = pg_index.indexrelid \
         WHERE pg_index.indrelid = 'org_role_permissions'::regclass AND idx.relname = $1",
    )
    .bind(name)
    .fetch_one(db.owner_pool())
    .await
    .expect("count indexes")
    .get("c")
}

/// Assert `statement` is refused as SQLSTATE 42501 with the session bound to its OWN
/// scope.
///
/// A statement carrying placeholders binds `$1` and `$2` to the session's OWN
/// (tenant, environment), so a probe INSERT writes a row that SATISFIES the
/// row-level-security WITH CHECK, leaving the missing GRANT as the only thing that
/// can refuse it. That distinction is the whole point of the probe: Postgres reports
/// a policy refusal and a privilege refusal under the SAME SQLSTATE (42501), so a
/// probe writing literal foreign scope values would be rejected by the policy no
/// matter how far the grant was widened, and could never observe the grant at all.
async fn assert_denied_in_scope(pool: &PgPool, tenant: &str, environment: &str, statement: &str) {
    let mut tx = pool.begin().await.expect("begin denied-statement tx");
    bind_scope(&mut tx, tenant, environment).await;
    let mut query = sqlx::query(statement);
    if statement.contains("$1") {
        query = query.bind(tenant).bind(environment);
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

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one mapping's whole lifecycle (attach, four read shapes, both lists on \
              both planes, detach, and the audit multiset after every step) read as \
              one unit, because the point is that the steps agree with each other"
)]
async fn a_permission_is_attached_to_a_role_listed_both_ways_and_detached() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;
    let role = create_role(&db, &env, scope, &org, "billing.admin").await;
    let permission = create_permission(&db, &env, scope, "billing.invoice.read").await;

    let mapping = attach(&db, &env, scope, &org, &role, &permission)
        .await
        .expect("attach the permission to the role");

    let control = db.control_store().management().org_role_permissions(scope);

    // 1. By id.
    let record = control.get(&mapping).await.expect("get by id");
    assert_eq!(record.id, mapping);
    assert_eq!(record.organization_id, org);
    assert_eq!(record.role_id, role);
    assert_eq!(record.permission_id, permission);
    assert_eq!(record.created_at_unix_micros, 2_000);
    assert_eq!(record.updated_at_unix_micros, 2_000);

    // 2. By (organization, id).
    assert_eq!(
        control
            .get_in_org(&org, &mapping)
            .await
            .expect("get_in_org"),
        record
    );

    // 3. By the PAIR ADDRESS, which is the wire address of a mapping: the two
    //    endpoints a caller already holds. The `rpm_` id exists as the audit target
    //    and as the detach handle, and a management route never has to make a caller
    //    carry it.
    assert_eq!(
        control
            .get_assignment(&org, &role, &permission)
            .await
            .expect("get_assignment"),
        record
    );

    // 4. Both lists, in both directions. "Which permissions does this role grant" and
    //    "which of this organization's roles grant this permission" are the two
    //    questions the two lookup indexes exist for.
    assert_eq!(
        control
            .list_for_role(&org, &role, PAGE, None)
            .await
            .expect("list for role"),
        vec![record.clone()]
    );
    assert_eq!(
        control
            .list_for_permission(&org, &permission, PAGE, None)
            .await
            .expect("list for permission"),
        vec![record.clone()]
    );

    // The DATA plane reads it too: the grant migration 0092 makes in the creating
    // migration, which the effective-permission resolution depends on.
    // Without it that path would fail with SQLSTATE 42501 on the token-issuance path.
    let data = db.store().scoped(scope).org_role_permissions();
    assert_eq!(
        data.get(&mapping).await.expect("the data plane READS"),
        record
    );
    assert_eq!(
        data.get_assignment(&org, &role, &permission)
            .await
            .expect("the data plane reads the pair address too"),
        record
    );

    assert_eq!(
        audit_actions(&db, scope, &mapping.to_string()).await,
        vec!["organization.role.permission.assign"]
    );

    // The detach is SOFT: the row is retained so the id the unassign audit row names
    // stays resolvable, and every read filters it out.
    detach(&db, &env, scope, &org, &mapping)
        .await
        .expect("detach");
    assert!(matches!(
        control.get(&mapping).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        control.get_in_org(&org, &mapping).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        control.get_assignment(&org, &role, &permission).await,
        Err(StoreError::NotFound)
    ));
    assert!(
        control
            .list_for_role(&org, &role, PAGE, None)
            .await
            .expect("list after detach")
            .is_empty()
    );
    assert!(
        control
            .list_for_permission(&org, &permission, PAGE, None)
            .await
            .expect("list after detach")
            .is_empty()
    );
    assert_eq!(
        count_mappings(&db, "deleted_at IS NOT NULL").await,
        1,
        "the row is retained, not removed"
    );

    let after_detach = vec![
        "organization.role.permission.assign",
        "organization.role.permission.unassign",
    ];
    assert_eq!(
        audit_actions(&db, scope, &mapping.to_string()).await,
        after_detach,
        "both mutations are audited, in order, under the exact wire strings migration \
         0092 declares as the delta contract"
    );

    // A repeat detach is the uniform not-found and writes NO audit row: the refusal
    // happens inside the same transaction the audit row would have been written in,
    // so it rolls back with it.
    assert!(matches!(
        detach(&db, &env, scope, &org, &mapping).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(
        audit_actions(&db, scope, &mapping.to_string()).await,
        after_detach,
        "a refused detach writes no audit row against its target"
    );
    assert_eq!(
        all_mapping_audit_actions(&db).await,
        after_detach,
        "and none against any other target or scope either"
    );

    // Neither endpoint was touched. A detach withdraws the GRANT and never the role
    // or the capability name, both of which many other roles may still be using.
    assert!(
        db.control_store()
            .management()
            .org_roles(scope)
            .get(&role)
            .await
            .is_ok(),
        "detaching a permission must not delete the role"
    );
    assert!(
        db.control_store()
            .management()
            .permissions(scope)
            .get(&permission)
            .await
            .is_ok(),
        "detaching a permission must not delete the permission itself"
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "every illegal pairing of the four caller-supplied identifiers, stated \
              once against one fixture so a single missing resolution anywhere \
              cannot hide behind another"
)]
async fn every_cross_pairing_is_refused_and_mutates_nothing() {
    // The case class the foreign keys CANNOT catch, and the one #97's review found on
    // its own assignment tables. Every endpoint below really exists and every id-only
    // foreign key is satisfied; what refuses these is the repository resolving each
    // endpoint in the place it is supposed to be.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    // A THIRD scope differing from A in the ENVIRONMENT ALONE. `seed_scope` mints a
    // NEW TENANT on every call, so scope_a and scope_b differ in BOTH dimensions and
    // the tenant half of every fence decides every probe between them. The
    // environment-only victim is the one that makes the environment half deciding,
    // and on THIS table it is also the sharpest case in the issue: the vocabulary is
    // per ENVIRONMENT, so "a permission of the other environment" is a real,
    // reachable, wrong pairing rather than a hypothetical.
    let scope_a2 = Scope::new(
        scope_a.tenant(),
        db.seed_environment(&env, scope_a.tenant()).await,
    );

    let alpha = create_org(&db, &env, scope_a, "Alpha").await;
    let beta = create_org(&db, &env, scope_a, "Beta").await;
    let alpha_role = create_role(&db, &env, scope_a, &alpha, "admin").await;
    let beta_role = create_role(&db, &env, scope_a, &beta, "admin").await;
    let permission = create_permission(&db, &env, scope_a, "billing.read").await;

    // The two foreign-scope endpoints, each a REAL live row in its own scope.
    let other_env_permission = create_permission(&db, &env, scope_a2, "billing.read").await;
    let other_tenant_org = create_org(&db, &env, scope_b, "Gamma").await;
    let other_tenant_role = create_role(&db, &env, scope_b, &other_tenant_org, "admin").await;
    let other_tenant_permission = create_permission(&db, &env, scope_b, "billing.read").await;

    // A well-formed permission id in the caller's OWN scope that was never stored.
    let absent_permission = PermissionId::generate(&env, &scope_a);
    let absent_role = OrgRoleId::generate(&env, &scope_a);
    let absent_org = OrganizationId::generate(&env, &scope_a);

    // Positive control FIRST: the legal pairing really does attach, so a repository
    // that refused everything could not pass this test.
    let legal = attach(&db, &env, scope_a, &alpha, &alpha_role, &permission)
        .await
        .expect("the legal pairing attaches");
    let audits_before = all_mapping_audit_actions(&db).await;
    let rows_before = count_mappings(&db, "true").await;

    for (org, role, permission_id, label) in [
        // The role exists and is live, but in a DIFFERENT organization of the same
        // environment. Nothing in the database refuses this: both rows exist and the
        // id-only foreign keys are satisfied.
        (
            &alpha,
            &beta_role,
            &permission,
            "a role of a SIBLING organization",
        ),
        (
            &beta,
            &alpha_role,
            &permission,
            "a role of another organization, addressed from that other path",
        ),
        // The permission does not exist at all.
        (
            &alpha,
            &alpha_role,
            &absent_permission,
            "a permission that was never defined",
        ),
        // The permission is live, but belongs to the SAME TENANT'S OTHER
        // ENVIRONMENT. The vocabulary is per environment, so this is the pairing the
        // whole namespace decision makes reachable, and the `permission_id` foreign
        // key is satisfied by it perfectly.
        (
            &alpha,
            &alpha_role,
            &other_env_permission,
            "a permission of the same tenant's OTHER ENVIRONMENT",
        ),
        // And of another tenant.
        (
            &alpha,
            &alpha_role,
            &other_tenant_permission,
            "a permission of another TENANT",
        ),
        // The role is of another tenant.
        (
            &alpha,
            &other_tenant_role,
            &permission,
            "a role of another TENANT",
        ),
        // The organization is of another tenant.
        (
            &other_tenant_org,
            &alpha_role,
            &permission,
            "an organization of another TENANT",
        ),
        // Each endpoint absent in the caller's own scope.
        (
            &alpha,
            &absent_role,
            &permission,
            "a role that never existed",
        ),
        (
            &absent_org,
            &alpha_role,
            &permission,
            "an organization that never existed",
        ),
    ] {
        let refused = attach(&db, &env, scope_a, org, role, permission_id).await;
        assert!(
            matches!(refused, Err(StoreError::NotFound)),
            "attaching with {label} must be the UNIFORM not-found, never a typed or \
             database error a caller could tell apart: {refused:?}"
        );
    }

    // Nothing was written and nothing was audited by ANY of those refusals: not a row
    // in the caller's scope, not one in a victim's, and no phantom audit row against
    // an id this test never got back.
    assert_eq!(
        count_mappings(&db, "true").await,
        rows_before,
        "a refused pairing must write no row anywhere"
    );
    assert_eq!(
        all_mapping_audit_actions(&db).await,
        audits_before,
        "a refused pairing must leave the audit log untouched"
    );

    // The legal mapping is still there and still says what it said, so the refusals
    // above did not damage the row that WAS legitimate.
    let survivor = db
        .control_store()
        .management()
        .org_role_permissions(scope_a)
        .get(&legal)
        .await
        .expect("the legal mapping survives");
    assert_eq!(survivor.role_id, alpha_role);
    assert_eq!(survivor.permission_id, permission);

    // And the near-miss endpoints are each individually VISIBLE to this caller where
    // they are visible at all, which is what makes the refusals above about the
    // PAIRING rather than about the caller being unable to see one half. Without
    // this the whole test could pass with a repository that refused every write.
    assert!(
        db.control_store()
            .management()
            .org_roles(scope_a)
            .get(&beta_role)
            .await
            .is_ok(),
        "beta's role is visible in scope A: the refusal above was about the PAIRING"
    );
    assert!(
        db.control_store()
            .management()
            .permissions(scope_a)
            .get(&permission)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn get_assignment_is_the_pair_address_and_refuses_every_near_miss() {
    // The pair-address read gets its own test because it is the read a management
    // route performs and because each of its three predicates answers a different
    // question. The fixture stands TWO roles and TWO permissions in ONE organization
    // and attaches only ONE of the four pairs, so a statement that ignored either
    // endpoint segment returns a row that exists rather than nothing, which is the
    // shape a "both endpoints have exactly one mapping" fixture cannot catch.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let alpha = create_org(&db, &env, scope, "Alpha").await;
    let beta = create_org(&db, &env, scope, "Beta").await;

    let role_one = create_role(&db, &env, scope, &alpha, "one").await;
    let role_two = create_role(&db, &env, scope, &alpha, "two").await;
    let permission_one = create_permission(&db, &env, scope, "billing.one").await;
    let permission_two = create_permission(&db, &env, scope, "billing.two").await;

    // Two mappings that share NEITHER endpoint with the pair under test, so a lookup
    // that dropped the role segment or the permission segment finds one of these.
    let target = attach_at(&db, &env, scope, &alpha, &role_one, &permission_one, 2_000)
        .await
        .expect("attach the pair under test");
    attach_at(&db, &env, scope, &alpha, &role_two, &permission_two, 3_000)
        .await
        .expect("attach the decoy");

    let repo = db.control_store().management().org_role_permissions(scope);

    assert_eq!(
        repo.get_assignment(&alpha, &role_one, &permission_one)
            .await
            .expect("the pair resolves")
            .id,
        target
    );

    // The two UNATTACHED pairs of the same four endpoints are the uniform not-found,
    // which is what makes both segments load-bearing: `(role_one, permission_two)`
    // proves the permission segment decides, and `(role_two, permission_one)` proves
    // the role segment does.
    for (role, permission, label) in [
        (&role_one, &permission_two, "the permission segment"),
        (&role_two, &permission_one, "the role segment"),
    ] {
        assert!(
            matches!(
                repo.get_assignment(&alpha, role, permission).await,
                Err(StoreError::NotFound)
            ),
            "an unattached pair must be the uniform not-found, so {label} really decides"
        );
    }

    // Addressed through a SIBLING organization, with both endpoints unchanged and
    // both individually visible: the uniform not-found again. This is the
    // cross-organization PAIRING case, and `organization_id` in the statement is the
    // only thing that refuses it.
    assert!(matches!(
        repo.get_assignment(&beta, &role_one, &permission_one).await,
        Err(StoreError::NotFound)
    ));

    // The id it hands back is the detach handle, and feeding it straight to the
    // detach works because 0092 grants UPDATE on the soft-delete pair alone, so the
    // mapping cannot come apart between the read and the write.
    detach(&db, &env, scope, &alpha, &target)
        .await
        .expect("the pair address yields a usable detach handle");
    assert!(matches!(
        repo.get_assignment(&alpha, &role_one, &permission_one)
            .await,
        Err(StoreError::NotFound)
    ));
    // The decoy is untouched, so the detach was addressed and not a sweep.
    assert!(
        repo.get_assignment(&alpha, &role_two, &permission_two)
            .await
            .is_ok()
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the organization-containment contract of every read and every write on \
              this table, stated once against one second organization in the SAME \
              scope so a single missing organization predicate cannot hide"
)]
async fn every_list_and_mutation_is_fenced_to_its_own_organization() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // TWO organizations in ONE scope. Row-level security fences (tenant, environment)
    // and nothing finer, so this is the pair that catches a missing organization
    // predicate; a cross-SCOPE test cannot, because the policy would refuse it no
    // matter how wide the app-layer filter was.
    let alpha = create_org(&db, &env, scope, "Alpha").await;
    let beta = create_org(&db, &env, scope, "Beta").await;
    let alpha_role = create_role(&db, &env, scope, &alpha, "admin").await;
    let beta_role = create_role(&db, &env, scope, &beta, "admin").await;

    // ONE permission, shared by both organizations. That sharing is the point of the
    // per-environment vocabulary and it is what makes the permission-side list the
    // interesting one: `list_for_permission` addressed by alpha must NOT return
    // beta's mapping of the very same permission.
    let permission = create_permission(&db, &env, scope, "billing.read").await;

    let alpha_mapping = attach(&db, &env, scope, &alpha, &alpha_role, &permission)
        .await
        .expect("attach in alpha");
    let beta_mapping = attach(&db, &env, scope, &beta, &beta_role, &permission)
        .await
        .expect("attach in beta");

    let repo = db.control_store().management().org_role_permissions(scope);

    for (org, role, mapping) in [
        (&alpha, &alpha_role, &alpha_mapping),
        (&beta, &beta_role, &beta_mapping),
    ] {
        let other = if org == &alpha { &beta } else { &alpha };

        assert_eq!(
            repo.list_for_role(org, role, PAGE, None)
                .await
                .expect("list for role")
                .iter()
                .map(|record| record.id)
                .collect::<Vec<_>>(),
            vec![*mapping]
        );
        assert!(
            repo.list_for_role(other, role, PAGE, None)
                .await
                .expect("list for role under the wrong organization")
                .is_empty(),
            "a role listed under a SIBLING organization must return nothing"
        );
        // The permission list is the sharper one: BOTH organizations map the SAME
        // permission, so a missing organization predicate here returns the other
        // organization's mapping rather than an empty page.
        assert_eq!(
            repo.list_for_permission(org, &permission, PAGE, None)
                .await
                .expect("list for permission")
                .iter()
                .map(|record| record.id)
                .collect::<Vec<_>>(),
            vec![*mapping],
            "one shared permission, two organizations: each must see only its own row"
        );
        // Resolve-by-id and the pair address are fenced the same way.
        assert!(matches!(
            repo.get_in_org(other, mapping).await,
            Err(StoreError::NotFound)
        ));
        assert!(matches!(
            repo.get_assignment(other, role, &permission).await,
            Err(StoreError::NotFound)
        ));
    }

    // Every MUTATION addressed through the wrong organization is refused, and the
    // victim row survives.
    assert!(matches!(
        detach(&db, &env, scope, &alpha, &beta_mapping).await,
        Err(StoreError::NotFound)
    ));
    assert!(
        repo.get_in_org(&beta, &beta_mapping).await.is_ok(),
        "beta's mapping must survive alpha's attempt to detach it"
    );
    assert_eq!(
        count_mappings(&db, "deleted_at IS NULL").await,
        2,
        "both mappings are still live"
    );

    // The ONE deliberate exception, asserted here so the code and the doc on
    // `OrgRolePermissionRepo` cannot drift apart. `get` is addressed by the mapping id
    // ALONE and its statement carries no `organization_id` conjunct, so it resolves a
    // SIBLING organization's mapping: alpha's caller, holding beta's id, gets beta's
    // row back. That is what the audit target and the detach handle need from a by-id
    // read, and it is exactly why a management route nested under an organization must
    // resolve through `get_in_org` (refused just above) and never through this. If
    // this ever stops holding, the struct doc and the redundancy census both have to
    // change with it.
    assert_eq!(
        repo.get(&beta_mapping)
            .await
            .expect("get resolves by id alone, whatever organization the row carries")
            .organization_id,
        beta,
        "`get` is organization-BLIND by design, and the fenced read is `get_in_org`"
    );

    // A cross-organization PAIRING is refused on the write too, in both directions.
    for (org, role) in [(&alpha, &beta_role), (&beta, &alpha_role)] {
        assert!(matches!(
            attach(&db, &env, scope, org, role, &permission).await,
            Err(StoreError::NotFound)
        ));
    }
}

#[tokio::test]
async fn an_attach_refuses_a_deleted_role_and_a_deleted_permission() {
    // The liveness half. A soft delete RETAINS the row, so both endpoint foreign keys
    // are still satisfied by a DEAD endpoint and nothing in the database refuses
    // either of these: the two resolutions are the whole fence, and dropping either
    // one lets a dead endpoint be attached.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;

    let dead_role = create_role(&db, &env, scope, &org, "dead").await;
    let live_role = create_role(&db, &env, scope, &org, "live").await;
    let dead_permission = create_permission(&db, &env, scope, "billing.dead").await;
    let live_permission = create_permission(&db, &env, scope, "billing.live").await;

    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_roles(scope)
        .delete(&env, &dead_role)
        .await
        .expect("soft delete the role");
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .permissions(scope)
        .delete(&env, &dead_permission)
        .await
        .expect("soft delete the permission");

    for (role, permission, label) in [
        (&dead_role, &live_permission, "a soft-deleted ROLE"),
        (&live_role, &dead_permission, "a soft-deleted PERMISSION"),
        (&dead_role, &dead_permission, "both endpoints soft-deleted"),
    ] {
        let refused = attach(&db, &env, scope, &org, role, permission).await;
        assert!(
            matches!(refused, Err(StoreError::NotFound)),
            "attaching to {label} must be the uniform not-found: {refused:?}"
        );
    }
    assert_eq!(
        count_mappings(&db, "true").await,
        0,
        "no refused attach wrote a row"
    );
    assert!(all_mapping_audit_actions(&db).await.is_empty());

    // Positive control: the two LIVE endpoints attach, so the refusals above are
    // about liveness and not about a repository that stopped writing.
    attach(&db, &env, scope, &org, &live_role, &live_permission)
        .await
        .expect("two live endpoints attach");

    // And the ASYMMETRY that makes this table's liveness story worth stating: deleting
    // an endpoint AFTER the attach does NOT cascade here. The mapping row stays LIVE,
    // and what stops the grant taking effect is the endpoint's own liveness filter in
    // the resolution projection. So a live mapping row is not by
    // itself a live grant, and this test pins the schema behaviour that fact rests on.
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .permissions(scope)
        .delete(&env, &live_permission)
        .await
        .expect("delete the permission out from under a live mapping");
    assert_eq!(
        count_mappings(&db, "deleted_at IS NULL").await,
        1,
        "deleting a permission does NOT cascade a detach; the resolution projection's \
         own liveness filter is what makes the grant stop"
    );
    assert_eq!(
        all_mapping_audit_actions(&db).await,
        vec!["organization.role.permission.assign"],
        "and it writes no unassign action, so the audit log never claims an operator \
         detached anything"
    );
}

#[tokio::test]
async fn the_live_pair_index_refuses_a_duplicate_and_frees_the_pair_on_detach() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let alpha = create_org(&db, &env, scope, "Alpha").await;
    let role = create_role(&db, &env, scope, &alpha, "admin").await;
    let permission = create_permission(&db, &env, scope, "billing.read").await;

    let first = attach(&db, &env, scope, &alpha, &role, &permission)
        .await
        .expect("the first attach");

    // HALF ONE: while it is LIVE the pair is taken, by the partial unique index.
    assert!(matches!(
        attach(&db, &env, scope, &alpha, &role, &permission).await,
        Err(StoreError::Conflict)
    ));
    // Refused BY NAME rather than by something else that happened to fail, which the
    // repository's wrapped error cannot say. Direct SQL is the only way to see the
    // constraint, and it is the same statement under the same role and scope.
    let duplicate = plant_mapping(&db, &env, scope, &alpha, &role, &permission, 3_000)
        .await
        .expect_err("a live pair is taken");
    let database_error = duplicate.as_database_error().expect("a database error");
    assert_eq!(database_error.code().as_deref(), Some(UNIQUE_VIOLATION));
    assert_eq!(
        database_error.constraint(),
        Some("org_role_permissions_pair_live_uniq"),
        "the duplicate must be refused by the live-uniqueness index BY NAME"
    );

    // The KEY really is (role, permission) and NOT (organization, role, permission).
    // A second organization's id on the same pair is still refused, which is the
    // assertion that would go green if `organization_id` were added to the key, and
    // it is the reason the narrower key is the stronger invariant: a role belongs to
    // exactly one organization, so the wider key could only ever admit a corruption.
    // Direct SQL, because the repository refuses this pairing one layer earlier.
    let beta = create_org(&db, &env, scope, "Beta").await;
    let wrong_org = plant_mapping(&db, &env, scope, &beta, &role, &permission, 4_000)
        .await
        .expect_err("the pair is taken regardless of the organization named");
    assert_eq!(
        wrong_org
            .as_database_error()
            .expect("a database error")
            .constraint(),
        Some("org_role_permissions_pair_live_uniq"),
        "organization_id must NOT be part of the live uniqueness key"
    );

    // HALF TWO: a pair freed by a DETACH is available again, and re-attaching mints a
    // FRESH id rather than reviving the dead row.
    detach(&db, &env, scope, &alpha, &first)
        .await
        .expect("detach");
    let second = attach_at(&db, &env, scope, &alpha, &role, &permission, 5_000)
        .await
        .expect("a detached pair is free again");
    assert_ne!(
        first, second,
        "a re-attach mints a FRESH id and is never a revival, so the audit history of \
         the detachment is not overwritten by the row that replaces it"
    );

    // Exactly ONE live row holds the pair, and the dead one is still there.
    assert_eq!(count_mappings(&db, "deleted_at IS NULL").await, 1);
    assert_eq!(count_mappings(&db, "true").await, 2);
    assert_eq!(
        db.control_store()
            .management()
            .org_role_permissions(scope)
            .get_assignment(&alpha, &role, &permission)
            .await
            .expect("the live row")
            .id,
        second,
        "the pair address resolves to the FRESH row, never the revived-looking dead one"
    );
    assert!(matches!(
        db.control_store()
            .management()
            .org_role_permissions(scope)
            .get(&first)
            .await,
        Err(StoreError::NotFound)
    ));

    // The dead row keeps its own audit history and the fresh row starts its own, so
    // the log says two mappings existed rather than one that came back.
    assert_eq!(
        audit_actions(&db, scope, &first.to_string()).await,
        vec![
            "organization.role.permission.assign",
            "organization.role.permission.unassign"
        ]
    );
    assert_eq!(
        audit_actions(&db, scope, &second.to_string()).await,
        vec!["organization.role.permission.assign"]
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the anti-oracle uniformity contract of every write on this table, over \
              every case that must be indistinguishable, read as one unit"
)]
async fn every_mutation_answers_absent_detached_and_both_foreign_scopes_alike() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    // A THIRD scope differing from A in the ENVIRONMENT ALONE. `seed_scope` mints a
    // NEW TENANT on every call, so scope_a and scope_b differ in BOTH dimensions and
    // the tenant conjunct of every fence decides every probe between them; a victim
    // that differs only in the environment is the one that makes the environment half
    // deciding. Without it the whole environment fence on this write path would be
    // asserted by nothing, which is exactly the hole PR 1's review found.
    let scope_a2 = Scope::new(
        scope_a.tenant(),
        db.seed_environment(&env, scope_a.tenant()).await,
    );

    let org_a = create_org(&db, &env, scope_a, "A").await;
    let role_a = create_role(&db, &env, scope_a, &org_a, "admin").await;
    let permission_a = create_permission(&db, &env, scope_a, "billing.read").await;

    let org_b = create_org(&db, &env, scope_b, "B").await;
    let role_b = create_role(&db, &env, scope_b, &org_b, "admin").await;
    let permission_b = create_permission(&db, &env, scope_b, "billing.read").await;
    let victim_b = attach(&db, &env, scope_b, &org_b, &role_b, &permission_b)
        .await
        .expect("attach in tenant B");

    let org_a2 = create_org(&db, &env, scope_a2, "A2").await;
    let role_a2 = create_role(&db, &env, scope_a2, &org_a2, "admin").await;
    let permission_a2 = create_permission(&db, &env, scope_a2, "staging.read").await;
    let victim_a2 = attach(&db, &env, scope_a2, &org_a2, &role_a2, &permission_a2)
        .await
        .expect("attach in the same tenant's other environment");

    // A's own detached mapping, and a well-formed id in A's scope never stored.
    let own_detached = attach_at(&db, &env, scope_a, &org_a, &role_a, &permission_a, 3_000)
        .await
        .expect("attach in A");
    detach(&db, &env, scope_a, &org_a, &own_detached)
        .await
        .expect("detach A's own");
    let absent = OrgRolePermissionId::generate(&env, &scope_a);

    // Positive control first: a live mapping of A really is detachable from A.
    let live_a = attach_at(&db, &env, scope_a, &org_a, &role_a, &permission_a, 4_000)
        .await
        .expect("attach A's live one");

    let audits_before = all_mapping_audit_actions(&db).await;

    for (target, label) in [
        (&absent, "absent in the caller's own scope"),
        (&own_detached, "detached in the caller's own scope"),
        (&victim_b, "live in another TENANT"),
        (&victim_a2, "live in the same tenant's other ENVIRONMENT"),
    ] {
        assert!(
            matches!(
                detach(&db, &env, scope_a, &org_a, target).await,
                Err(StoreError::NotFound)
            ),
            "a detach of a mapping {label} must be the uniform not-found"
        );
    }

    // An ATTACH naming an `rpm_` id minted in another scope is refused before any
    // statement runs. This is the guard with NO layer behind it, and the fixture is
    // built so the mutant's REAL behaviour is what fails: each forged attach names a
    // FRESH permission, so the live pair slot is empty and nothing else can refuse the
    // statement. Measured with the guard deleted, this exact call returns `Ok(())` and
    // persists a row whose `tenant_id` and `environment_id` are the CALLER'S OWN while
    // the id is the foreign scope's, together with a matching assign audit row. A
    // fixture that reused an already-attached pair would instead see the mutant answer
    // `Conflict`, which is still a failure but says nothing about what went wrong.
    for (index, foreign_scope) in [scope_b, scope_a2].into_iter().enumerate() {
        let smuggled = OrgRolePermissionId::generate(&env, &foreign_scope);
        let fresh = create_permission(&db, &env, scope_a, &format!("billing.fresh_{index}")).await;
        let refused = db
            .control_store()
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_role_permissions(scope_a)
            .assign(
                &env,
                NewOrgRolePermission {
                    id: &smuggled,
                    organization_id: &org_a,
                    role_id: &role_a,
                    permission_id: &fresh,
                },
                5_000,
                None,
            )
            .await;
        assert!(
            matches!(refused, Err(StoreError::NotFound)),
            "a forged mapping id from another scope must be refused: {refused:?}"
        );
        // And it left NOTHING behind, read through the OWNER pool so a row written
        // into any scope still counts.
        assert_eq!(
            count_mappings(&db, &format!("id = '{smuggled}'")).await,
            0,
            "a forged attach must persist no row"
        );
        // The role stays LISTABLE. This is the consequence that makes the guard's
        // removal catastrophic rather than merely wrong: one undecodable row makes
        // every mapping of that role unreadable through the management surface, so a
        // liveness-only assertion on the forged id would miss it.
        assert!(
            db.control_store()
                .management()
                .org_role_permissions(scope_a)
                .list_for_role(&org_a, &role_a, PAGE, None)
                .await
                .is_ok(),
            "one forged row must not make the whole role's mapping list undecodable"
        );
        // And the pair the forgery named is still FREE, so a legitimate attach of it
        // still works. Under the mutant this is a `Conflict` for good, because the
        // live uniqueness slot is held by a row no supported path can address.
        attach_at(&db, &env, scope_a, &org_a, &role_a, &fresh, 5_500)
            .await
            .expect("the pair a forged attach named must still be attachable");
    }

    // Both victims SURVIVED, live and still joining what they joined. Without this
    // the refusals above could be satisfied by a repository that destroyed the row
    // and then reported not-found.
    for (victim_scope, victim, org, role, permission) in [
        (scope_b, &victim_b, &org_b, &role_b, &permission_b),
        (scope_a2, &victim_a2, &org_a2, &role_a2, &permission_a2),
    ] {
        let record = db
            .control_store()
            .management()
            .org_role_permissions(victim_scope)
            .get(victim)
            .await
            .expect("the victim survives in its own scope");
        assert_eq!(&record.organization_id, org);
        assert_eq!(&record.role_id, role);
        assert_eq!(&record.permission_id, permission);
    }

    // Not one of those refusals wrote an audit row ANYWHERE. The only rows added since
    // the baseline are the TWO legitimate attaches the loop above performs to prove
    // the forged pairs stayed free, so the expected list is the baseline plus exactly
    // those two, and any phantom row from a refused path breaks the equality.
    let mut expected = audits_before.clone();
    expected.extend(vec!["organization.role.permission.assign".to_owned(); 2]);
    assert_eq!(
        all_mapping_audit_actions(&db).await,
        expected,
        "a refused cross-scope mutation must leave the audit log untouched"
    );
    assert!(
        db.control_store()
            .management()
            .org_role_permissions(scope_a)
            .get(&live_a)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn rls_hides_another_scopes_mappings_and_refuses_forging_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    // A THIRD scope differing from A in the ENVIRONMENT ALONE, and the reason it must
    // exist: `seed_scope` mints a NEW TENANT on every call, so scope_a and scope_b
    // differ in BOTH dimensions and the policy's TENANT conjunct decides every probe
    // between them regardless of what its environment conjunct says. Deleting
    // `AND environment_id = ...` from BOTH halves of the policy would otherwise leave
    // this whole file green while a session bound to (T, E1) could read, detach, and
    // forge grants in (T, E2).
    let scope_a2 = Scope::new(
        scope_a.tenant(),
        db.seed_environment(&env, scope_a.tenant()).await,
    );

    // Each victim's endpoint ids are kept, because the FORGE probe below has to bind
    // REAL ones. A forge INSERT that could not name a live organization, role, and
    // permission would be refused by NOT NULL or by a foreign key before the policy
    // ever ran, and would then survive a policy with `WITH CHECK (true)`. That is not
    // hypothetical: the first version of this test selected the endpoint ids through
    // a subquery, which returns NULL under the ATTACKER's row-level security because
    // the attacker has no mappings, and it duly failed to kill that mutant.
    let mut victims = Vec::new();
    for scope in [scope_b, scope_a2] {
        let org = create_org(&db, &env, scope, "Victim").await;
        let role = create_role(&db, &env, scope, &org, "admin").await;
        let permission = create_permission(&db, &env, scope, "billing.read").await;
        attach(&db, &env, scope, &org, &role, &permission)
            .await
            .expect("plant a victim mapping");
        victims.push((scope, org, role, permission));
    }

    let pool = db.control_pool();

    // Precondition: we really are the low-privilege CONTROL role, not a superuser.
    let who = sqlx::query(
        "SELECT current_user AS u, \
         (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_super",
    )
    .fetch_one(pool)
    .await
    .expect("identify session role");
    assert_eq!(who.get::<String, _>("u"), "ironauth_control");
    assert!(!who.get::<bool, _>("is_super"));

    // Deny by default: no scope bound on the session, zero rows.
    let unset: i64 = sqlx::query("SELECT count(*) AS c FROM org_role_permissions")
        .fetch_one(pool)
        .await
        .expect("count with unset scope")
        .get("c");
    assert_eq!(unset, 0, "an unset scope must see no mappings");

    // Every probe, run TWICE: once against a victim differing in the TENANT and once
    // against one differing ONLY in the ENVIRONMENT. Each conjunct of the policy is
    // therefore the deciding one in at least one probe.
    for ((victim, org, role, permission), differing) in
        victims.iter().zip(["TENANT", "ENVIRONMENT"])
    {
        assert_fenced_from(
            pool,
            &env,
            scope_a,
            Victim {
                scope: *victim,
                organization: *org,
                role: *role,
                permission: *permission,
            },
            differing,
        )
        .await;
    }

    // The MISMATCHED-SCOPE probe, and the reason it has to exist. The two probes
    // above cannot reach the policy's TENANT conjunct, and that is structural rather
    // than an oversight in how they were written: an `environment_id` is globally
    // unique and its row names exactly one tenant (the composite foreign key
    // `(environment_id, tenant_id) REFERENCES environments (id, tenant_id)` pins it),
    // so no two tenants can ever share an environment and the environment conjunct
    // alone refuses every ordinary cross-tenant probe. Deleting
    // `tenant_id = current_setting(...)` from BOTH halves of the policy left this
    // whole file, the migration structure test, and the IDOR probes green.
    //
    // The one session the tenant conjunct really does refuse is one that binds a
    // MISMATCHED pair: tenant B with environment A1. `Scope::new` performs no
    // ownership check, so such a scope is constructible in Rust, and this is the
    // session that would read tenant A's grants with the tenant conjunct gone. It is
    // probed here through raw SQL because that is the layer the policy lives at.
    {
        let mut tx = pool.begin().await.expect("begin mismatched-scope probe");
        bind_scope(
            &mut tx,
            &scope_b.tenant().to_string(),
            &scope_a2.environment().to_string(),
        )
        .await;
        let visible: i64 = sqlx::query("SELECT count(*) AS c FROM org_role_permissions")
            .fetch_one(&mut *tx)
            .await
            .expect("count under a mismatched scope")
            .get("c");
        assert_eq!(
            visible, 0,
            "a session binding a tenant that does not OWN the bound environment must \
             see nothing: the policy's tenant conjunct is the only thing that refuses \
             this, and it is unreachable by any probe whose two scopes differ in the \
             environment as well"
        );
        // The write half of the same mismatch, so the tenant conjunct is pinned in the
        // USING clause and not only in the read path.
        let updated = sqlx::query("UPDATE org_role_permissions SET deleted_at = now()")
            .execute(&mut *tx)
            .await
            .expect("update runs")
            .rows_affected();
        assert_eq!(
            updated, 0,
            "a mismatched-scope session must not be able to detach anything either"
        );
        let _ = tx.rollback().await;
    }

    // Positive controls: bound to each victim the same role sees exactly that
    // victim's row. Without the SECOND of these the environment probes above would be
    // satisfied by an empty environment, which is precisely how a zero becomes
    // vacuous, and without them the mismatched-scope zero above would be vacuous too.
    for (victim, label) in [(scope_b, "scope B"), (scope_a2, "scope A2")] {
        let mut tx = pool.begin().await.expect("begin as the victim scope");
        bind_scope(
            &mut tx,
            &victim.tenant().to_string(),
            &victim.environment().to_string(),
        )
        .await;
        let visible: i64 = sqlx::query("SELECT count(*) AS c FROM org_role_permissions")
            .fetch_one(&mut *tx)
            .await
            .expect("count in the victim scope")
            .get("c");
        assert_eq!(visible, 1, "{label} sees its own mapping");
        tx.commit().await.expect("commit the victim read");
    }
}

/// One victim scope and the LIVE endpoint ids planted in it, bundled so the forge
/// probe can bind real values.
#[derive(Clone, Copy)]
struct Victim {
    scope: Scope,
    organization: OrganizationId,
    role: OrgRoleId,
    permission: PermissionId,
}

/// Every probe a session bound to `attacker` can aim at `victim`'s mappings: the read
/// with the app-layer filter subverted, the cross-scope detach, and the forge INSERT.
/// `differing` names the dimension the two scopes differ in, so a failure says which
/// half of the policy fell.
///
/// Every statement names BOTH scope columns. A probe naming the tenant alone is
/// decided by the tenant conjunct no matter what the environment conjunct says, which
/// is exactly the position blindness that left the environment half of the sibling
/// table's policy asserted by nothing.
///
/// Each victim gets its OWN transaction because the forge INSERT is expected to fail,
/// and a failed statement aborts the surrounding transaction: a second victim probed
/// in the same transaction would see every statement refused as 25P02 and pass for
/// the wrong reason.
async fn assert_fenced_from(
    pool: &PgPool,
    env: &Env,
    attacker: Scope,
    victim: Victim,
    differing: &str,
) {
    let tenant = victim.scope.tenant().to_string();
    let environment = victim.scope.environment().to_string();
    let mut tx = pool.begin().await.expect("begin as the attacker scope");
    bind_scope(
        &mut tx,
        &attacker.tenant().to_string(),
        &attacker.environment().to_string(),
    )
    .await;

    // Read side, app-layer filter SUBVERTED: the query explicitly targets the
    // victim's rows. Forced row-level security still returns zero.
    let leaked: i64 = sqlx::query(
        "SELECT count(*) AS c FROM org_role_permissions \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_one(&mut *tx)
    .await
    .expect("cross-scope count")
    .get("c");
    assert_eq!(
        leaked, 0,
        "RLS must hide a mapping whose {differing} differs, even with the filter bypassed"
    );

    // Write side, the half a read-only probe would miss: the USING clause hides the
    // victim's row from the detach.
    let updated = sqlx::query(
        "UPDATE org_role_permissions SET deleted_at = now() \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(&tenant)
    .bind(&environment)
    .execute(&mut *tx)
    .await
    .expect("update runs")
    .rows_affected();
    assert_eq!(
        updated, 0,
        "RLS must hide a row whose {differing} differs from a cross-scope detach"
    );

    // FORGE probe: an INSERT claiming the victim's scope, with the victim's OWN live
    // endpoint ids bound in. The WITH CHECK half of the policy is what refuses it, and
    // it is a distinct property from the USING half: a policy with USING only would
    // pass every assertion so far and still let one scope grant a capability inside
    // another.
    //
    // Binding REAL endpoint ids is what makes this probe observe the policy at all.
    // Every other rule that could refuse this row is satisfied: the three NOT NULLs,
    // the three foreign keys (all id-only, and all three rows really exist), the
    // nonempty-scope CHECK, and the live uniqueness index (this exact pair is already
    // live in the victim's scope, so a policy that let the row through would then hit
    // 23505 rather than succeeding, which is still an error and still a kill, but the
    // row would have been evaluated as writable). A probe that could not name real
    // endpoints would be refused by NOT NULL first and would survive a
    // `WITH CHECK (true)` mutant, which is exactly what the first version of this
    // helper did.
    let forged = OrgRolePermissionId::generate(env, &victim.scope).to_string();
    let insert = sqlx::query(
        "INSERT INTO org_role_permissions \
         (id, tenant_id, environment_id, organization_id, role_id, permission_id) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(forged)
    .bind(&tenant)
    .bind(&environment)
    .bind(victim.organization.to_string())
    .bind(victim.role.to_string())
    .bind(victim.permission.to_string())
    .execute(&mut *tx)
    .await;
    assert!(
        insert.is_err(),
        "the RLS WITH CHECK must reject writing into a scope whose {differing} differs"
    );
    // And it is refused as INSUFFICIENT PRIVILEGE (the SQLSTATE a policy refusal
    // reports), not as a null violation or a foreign-key violation, which is what
    // makes the refusal attributable to the policy rather than to a fixture that
    // could not build a valid row.
    let code = insert.as_ref().err().and_then(|error| {
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(std::borrow::Cow::into_owned)
    });
    assert_eq!(
        code.as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "the forge must be refused BY THE POLICY, not by a null or foreign-key \
         violation that would refuse it however wide the policy was: {insert:?}"
    );
    let _ = tx.rollback().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the weakened-policy fixture and every surface probed under it read as \
              one unit: splitting them would rebuild the fixture per probe and let \
              two copies of the policy surgery drift"
)]
async fn the_repository_still_fences_by_environment_with_the_policy_half_down() {
    // The OTHER direction of the same masking, and the reason the test above is not
    // enough on its own: it pins the POLICY half, and this pins what is left when the
    // policy half is gone.
    //
    // What that IS, stated precisely, because the obvious claim is wrong and was
    // measured rather than assumed. On this table the environment is fenced FOUR
    // times over: the typed-id guard that refuses an out-of-scope argument before any
    // statement, the statement's own `environment_id = $N` conjunct, the policy, and
    // the in-scope decode in `org_role_permission_from_row`. Every read here is
    // addressed by SCOPED IDS ONLY, which means the statement conjunct is the layer
    // that can never be reached on its own: a caller cannot get an id of another
    // environment past the guard, and a row of another environment cannot carry ids
    // this caller could name. Neutering the two scope conjuncts in `get_assignment`
    // leaves the whole suite green, and that is EQUIVALENCE, not a hole. (This is the
    // one place this table differs from `permissions`, whose `get_by_slug` addresses
    // by a caller-typed SLUG and so does make its own conjunct observable.)
    //
    // So what this test pins is the WRITE side, where the layers really are
    // separable: with the policy's environment half replaced away and the detach's
    // in-process guard removed, `soft_delete_assignment_row`'s own `environment_id`
    // conjunct is the ONLY thing standing between a scope A caller and a live grant in
    // the same tenant's other environment. That triple is killed here and nowhere
    // else.
    //
    // The policy is REPLACED rather than dropped: this table FORCEs row-level
    // security, so a table carrying no policy at all denies everything and the probe
    // would pass for exactly the wrong reason.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_a2 = Scope::new(
        scope_a.tenant(),
        db.seed_environment(&env, scope_a.tenant()).await,
    );

    let org_a = create_org(&db, &env, scope_a, "A").await;
    let role_a = create_role(&db, &env, scope_a, &org_a, "admin").await;
    let permission_a = create_permission(&db, &env, scope_a, "billing.read").await;
    attach(&db, &env, scope_a, &org_a, &role_a, &permission_a)
        .await
        .expect("attach in A");

    let org_a2 = create_org(&db, &env, scope_a2, "A2").await;
    let role_a2 = create_role(&db, &env, scope_a2, &org_a2, "admin").await;
    let permission_a2 = create_permission(&db, &env, scope_a2, "staging.read").await;
    attach(&db, &env, scope_a2, &org_a2, &role_a2, &permission_a2)
        .await
        .expect("attach in A2");

    db.execute_owner_sql(
        "DROP POLICY org_role_permissions_tenant_isolation ON org_role_permissions",
    )
    .await;
    db.execute_owner_sql(
        "CREATE POLICY org_role_permissions_tenant_isolation ON org_role_permissions \
         USING (tenant_id = current_setting('ironauth.tenant_id', true)) \
         WITH CHECK (tenant_id = current_setting('ironauth.tenant_id', true))",
    )
    .await;

    // The fence really is down: raw SQL bound to scope A now sees BOTH rows. So
    // whatever the repository refuses below, it refuses on its own predicate and not
    // because the storage engine got there first.
    {
        let mut tx = db
            .control_pool()
            .begin()
            .await
            .expect("begin weakened-policy read");
        bind_scope(
            &mut tx,
            &scope_a.tenant().to_string(),
            &scope_a.environment().to_string(),
        )
        .await;
        let visible: i64 = sqlx::query("SELECT count(*) AS c FROM org_role_permissions")
            .fetch_one(&mut *tx)
            .await
            .expect("count under the weakened policy")
            .get("c");
        assert_eq!(
            visible, 2,
            "the weakened policy must no longer fence the environment, or this test \
             proves nothing about the repository"
        );
        tx.commit().await.expect("commit the weakened-policy read");
    }

    // Every READ surface still refuses A2's row, addressed by A2's own ids. With the
    // policy half down the refusing layer here is the typed-id guard (and, behind it,
    // the in-scope decode), so this half of the test is a REGRESSION FENCE on the
    // guards rather than on the SQL, and saying which is which is the point of the
    // census above.
    let repo = db
        .control_store()
        .management()
        .org_role_permissions(scope_a);
    assert!(
        repo.list_for_role(&org_a2, &role_a2, PAGE, None)
            .await
            .expect("a cross-environment list is empty rather than an error")
            .is_empty()
    );
    let a2_mapping = db
        .control_store()
        .management()
        .org_role_permissions(scope_a2)
        .get_assignment(&org_a2, &role_a2, &permission_a2)
        .await
        .expect("A2's mapping in its own scope")
        .id;
    assert!(matches!(
        repo.get(&a2_mapping).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        repo.get_assignment(&org_a2, &role_a2, &permission_a2).await,
        Err(StoreError::NotFound)
    ));

    // Scope A's own mapping still reads, so the refusals above are about the
    // environment and not about a repository that stopped working.
    assert_eq!(
        repo.list_for_role(&org_a, &role_a, PAGE, None)
            .await
            .expect("scope A still lists its own mapping")
            .len(),
        1
    );

    // The DETACH: the write side, where the layers really are separable. A2's mapping
    // is now visible to a raw scope A session, and the repository must still refuse to
    // withdraw it. Removing the in-process guard from `unassign` AND the
    // `environment_id` conjunct from `soft_delete_assignment_row` makes this
    // succeed (measured), which is what makes this assertion the one that pins that
    // conjunct rather than merely restating the guard.
    assert!(matches!(
        detach(&db, &env, scope_a, &org_a2, &a2_mapping).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(
        count_mappings(&db, "deleted_at IS NULL").await,
        2,
        "A2's mapping survives a scope A detach with the policy's environment half down"
    );
    // And it is still LIVE and still granting in its own scope, which a liveness count
    // alone would not say: a detach that landed would leave the count at two only if
    // it had also failed, so the pair address is the sharper read.
    assert!(
        db.control_store()
            .management()
            .org_role_permissions(scope_a2)
            .get_assignment(&org_a2, &role_a2, &permission_a2)
            .await
            .is_ok()
    );
}

/// Every column of `org_role_permissions` the given role may UPDATE, swept from the
/// catalog.
///
/// `has_table_privilege(role, 'org_role_permissions', 'UPDATE')` cannot answer this:
/// a COLUMN-scoped grant is invisible to it, so a table-level check reports "no
/// UPDATE" for a role that can in fact rewrite two columns, and would keep reporting
/// it however far the column list was widened. Sweeping `pg_attribute` and asking
/// `has_column_privilege` per column is the only form that sees the real grant, and
/// asking it of EVERY column (rather than of an expected list) is what makes the
/// answer an exact set rather than a subset.
async fn updatable_columns(db: &TestDatabase, role: &str) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT a.attname AS name \
           FROM pg_attribute a \
          WHERE a.attrelid = 'org_role_permissions'::regclass \
            AND a.attnum > 0 AND NOT a.attisdropped \
            AND has_column_privilege($1::name, a.attrelid, a.attnum, 'UPDATE') \
          ORDER BY a.attname",
    )
    .bind(role)
    .fetch_all(db.owner_pool())
    .await
    .expect("sweep column privileges");
    rows.iter()
        .map(|row| row.get::<String, _>("name"))
        .collect()
}

/// Every live column of `org_role_permissions`, so the sweep above can be shown to
/// have looked at all of them rather than at an empty relation.
async fn all_columns(db: &TestDatabase) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT a.attname AS name FROM pg_attribute a \
          WHERE a.attrelid = 'org_role_permissions'::regclass \
            AND a.attnum > 0 AND NOT a.attisdropped \
          ORDER BY a.attname",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("read columns");
    rows.iter()
        .map(|row| row.get::<String, _>("name"))
        .collect()
}

/// Whether `role` holds `privilege` on `org_role_permissions` at TABLE level.
async fn has_table_privilege(db: &TestDatabase, role: &str, privilege: &str) -> bool {
    sqlx::query("SELECT has_table_privilege($1::name, 'org_role_permissions', $2) AS held")
        .bind(role)
        .bind(privilege)
        .fetch_one(db.owner_pool())
        .await
        .expect("read table privilege")
        .get("held")
}

#[tokio::test]
async fn the_grants_are_exactly_what_the_write_path_needs_and_nothing_more() {
    let db = TestDatabase::start().await;

    // The sweep really looked at the table: nine columns, the shape migration 0092
    // creates. Without this the set comparisons below could both be satisfied by a
    // relation the catalog query failed to find.
    assert_eq!(
        all_columns(&db).await,
        vec![
            "created_at",
            "deleted_at",
            "environment_id",
            "id",
            "organization_id",
            "permission_id",
            "role_id",
            "tenant_id",
            "updated_at",
        ]
    );

    // EXACTLY the soft-delete pair, as an exact set. Every ADDRESSING column is
    // absent, which is what makes it impossible to repoint a mapping at a different
    // role, permission, organization, or scope after the containment was checked.
    assert_eq!(
        updatable_columns(&db, "ironauth_control").await,
        vec!["deleted_at", "updated_at"],
        "widening this grant is a security change and must not pass silently"
    );

    // The DATA plane holds no UPDATE on any column at all, and the asymmetry with
    // org_membership_roles (which DOES hold the pair, for the invitation-accept
    // cascade) is deliberate: no membership lifecycle reaches this table.
    assert_eq!(
        updatable_columns(&db, "ironauth_app").await,
        Vec::<String>::new()
    );

    // DELETE is granted to NOBODY on either plane: removal is the soft delete, which
    // is what keeps a detached mapping's id resolvable from its audit row.
    for role in ["ironauth_control", "ironauth_app"] {
        assert!(
            !has_table_privilege(&db, role, "DELETE").await,
            "{role} must not hold DELETE on org_role_permissions"
        );
        assert!(
            !has_table_privilege(&db, role, "UPDATE").await,
            "{role} must hold UPDATE per COLUMN and never over the whole table"
        );
        assert!(
            has_table_privilege(&db, role, "SELECT").await,
            "{role} reads the mapping"
        );
    }
    assert!(
        has_table_privilege(&db, "ironauth_control", "INSERT").await,
        "the control plane attaches"
    );
    assert!(
        !has_table_privilege(&db, "ironauth_app", "INSERT").await,
        "the data plane never attaches one"
    );
}

#[tokio::test]
async fn the_data_plane_can_read_a_mapping_but_never_write_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;
    let role = create_role(&db, &env, scope, &org, "admin").await;
    let permission = create_permission(&db, &env, scope, "billing.read").await;
    let mapping = attach(&db, &env, scope, &org, &role, &permission)
        .await
        .expect("attach");

    let read = db
        .store()
        .scoped(scope)
        .org_role_permissions()
        .get(&mapping)
        .await
        .expect("the data plane can READ a mapping");
    assert_eq!(read.permission_id, permission);

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

    // Every MUTATING statement is refused as insufficient privilege. A data plane
    // able to decide which capabilities a role grants is a data plane able to write
    // its own token claim.
    for statement in [
        "DELETE FROM org_role_permissions",
        "UPDATE org_role_permissions SET deleted_at = now()",
        "UPDATE org_role_permissions SET updated_at = now()",
        // The FORGE probe: a row valid in EVERY respect but the grant. The session's
        // OWN scope, and endpoint ids copied from the live row, so the row satisfies
        // the row-level-security WITH CHECK and every foreign key, leaving the
        // MISSING GRANT as the only thing that can refuse it. Postgres reports a
        // policy refusal and a privilege refusal under the SAME SQLSTATE (42501), so
        // a probe writing literal foreign scope values would be rejected by the
        // policy no matter how far the grant was widened, and could never observe the
        // grant at all.
        "INSERT INTO org_role_permissions \
         (id, tenant_id, environment_id, organization_id, role_id, permission_id) \
         SELECT 'rpm_probe', $1, $2, organization_id, role_id, permission_id \
           FROM org_role_permissions LIMIT 1",
    ] {
        assert_denied_in_scope(pool, &tenant, &environment, statement).await;
    }

    // The addressing columns are immutable by GRANT on BOTH roles: not even the
    // control plane, which owns the whole mapping lifecycle, may repoint a live
    // mapping. Repointing would move an authorization decision with no audit trail
    // saying which grant changed, because the row's id would not have moved.
    for statement in [
        "UPDATE org_role_permissions SET role_id = 'rol_other' \
         WHERE tenant_id = $1 AND environment_id = $2",
        "UPDATE org_role_permissions SET permission_id = 'prm_other' \
         WHERE tenant_id = $1 AND environment_id = $2",
        "UPDATE org_role_permissions SET organization_id = 'org_other' \
         WHERE tenant_id = $1 AND environment_id = $2",
    ] {
        assert_denied_in_scope(db.control_pool(), &tenant, &environment, statement).await;
    }

    // Positive control: the control role's column-scoped soft delete DOES succeed, so
    // the denials above are about the columns and not about the role's access
    // generally.
    {
        let mut tx = db.control_pool().begin().await.expect("begin control tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        sqlx::query("UPDATE org_role_permissions SET deleted_at = now(), updated_at = now()")
            .execute(&mut *tx)
            .await
            .expect("the control role holds the column-scoped soft-delete UPDATE");
        let _ = tx.rollback().await;
    }

    // And nothing above actually moved the row.
    assert_eq!(
        db.control_store()
            .management()
            .org_role_permissions(scope)
            .get(&mapping)
            .await
            .expect("the mapping survives every refused statement"),
        read
    );
}

#[tokio::test]
async fn a_failing_audit_insert_rolls_the_mapping_write_back() {
    // The direction the refusal tests cannot reach. They prove that a failed MUTATION
    // writes no audit row; this proves the converse, that a failed AUDIT INSERT writes
    // no mutation, and together the two say the pair really is one transaction rather
    // than two statements that usually both succeed.
    //
    // The audit insert is made to fail by constraining `audit_log` on the exact action
    // under test, which is the only lever a test has on a write path with no injected
    // failure seam of its own.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;
    let role = create_role(&db, &env, scope, &org, "admin").await;
    let first = create_permission(&db, &env, scope, "billing.read").await;
    let second = create_permission(&db, &env, scope, "billing.write").await;

    let mapping = attach(&db, &env, scope, &org, &role, &first)
        .await
        .expect("attach");

    // The DETACH half: the row must still be LIVE afterwards.
    db.execute_owner_sql(
        "ALTER TABLE audit_log ADD CONSTRAINT audit_probe \
         CHECK (action <> 'organization.role.permission.unassign') NOT VALID",
    )
    .await;
    let result = detach(&db, &env, scope, &org, &mapping).await;
    assert!(
        matches!(result, Err(StoreError::Database(_))),
        "the poisoned detach must fail: {result:?}"
    );
    db.execute_owner_sql("ALTER TABLE audit_log DROP CONSTRAINT audit_probe")
        .await;
    assert!(
        db.control_store()
            .management()
            .org_role_permissions(scope)
            .get_assignment(&org, &role, &first)
            .await
            .is_ok(),
        "the mapping survives an audit failure, live and still granting"
    );

    // The ATTACH half: no row, and no partial write.
    db.execute_owner_sql(
        "ALTER TABLE audit_log ADD CONSTRAINT audit_probe \
         CHECK (action <> 'organization.role.permission.assign') NOT VALID",
    )
    .await;
    let result = attach(&db, &env, scope, &org, &role, &second).await;
    assert!(
        matches!(result, Err(StoreError::Database(_))),
        "the poisoned attach must fail: {result:?}"
    );
    db.execute_owner_sql("ALTER TABLE audit_log DROP CONSTRAINT audit_probe")
        .await;

    assert_eq!(
        count_mappings(&db, "true").await,
        1,
        "an attach whose audit row could not be written leaves no mapping row"
    );
    assert_eq!(
        all_mapping_audit_actions(&db).await,
        vec!["organization.role.permission.assign"],
        "and the only audit row is the successful attach at the top"
    );
    // The pair the poisoned attach named is still FREE, so the failed write did not
    // leave the live uniqueness slot occupied by a row nothing can see.
    attach_at(&db, &env, scope, &org, &role, &second, 6_000)
        .await
        .expect("the pair a poisoned attach named is still free");
}

#[tokio::test]
async fn a_role_may_carry_unlimited_permissions_and_a_permission_unlimited_roles() {
    // The covenant, made mechanical, in BOTH directions: there is no count
    // constraint, no quota, and no gate on how many permissions a role carries or on
    // how many roles carry one permission. The page size is clamped like every
    // management list, which is a PAGINATION bound and not a cap on the set. The byte
    // budget issue #98 ships bounds ONE TOKEN and has nothing to do with
    // this table.
    //
    // Every row here is written through the AUDITED WRITE REPOSITORY rather than with
    // direct SQL, because that is where a cap would have to live. A covenant test that
    // planted rows behind the repository would leave an advisory-lock-plus-COUNT gate
    // in `ActingOrgRolePermissionRepo::assign` completely unguarded, and that gate is
    // the exact shape this module uses elsewhere and the exact shape the covenant
    // forbids here.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;

    // Direction one: ONE role, many permissions.
    let wide_role = create_role(&db, &env, scope, &org, "everything").await;
    let mut permissions = Vec::with_capacity(WIDE);
    for index in 0..WIDE {
        let permission =
            create_permission(&db, &env, scope, &format!("billing.capability_{index}")).await;
        attach_at(
            &db,
            &env,
            scope,
            &org,
            &wide_role,
            &permission,
            2_000 + i64::try_from(index).expect("fits i64"),
        )
        .await
        .unwrap_or_else(|error| panic!("no cap may refuse permission {index}: {error:?}"));
        permissions.push(permission);
    }

    // Direction two: ONE permission, many roles. The reverse direction has its own
    // index and its own list, and a cap could plausibly have been put on either side.
    let shared = create_permission(&db, &env, scope, "billing.shared").await;
    for index in 0..WIDE {
        let role = create_role(&db, &env, scope, &org, &format!("role_{index}")).await;
        attach_at(
            &db,
            &env,
            scope,
            &org,
            &role,
            &shared,
            10_000 + i64::try_from(index).expect("fits i64"),
        )
        .await
        .unwrap_or_else(|error| panic!("no cap may refuse role {index}: {error:?}"));
    }

    // Every one of those writes was audited, and nothing else was. This is the "no
    // unaudited mutation" property at a scale where a path that skipped the audited
    // seam under some condition (a batch, a retry, a fast path) shows up as a count
    // mismatch rather than as a passing single-row test.
    assert_eq!(
        all_mapping_audit_actions(&db).await,
        vec!["organization.role.permission.assign"; WIDE * 2],
        "each of the {} attaches writes exactly one assign audit row",
        WIDE * 2
    );

    let repo = db.control_store().management().org_role_permissions(scope);

    // Both lists page the whole set with no row lost and none served twice.
    for (label, listed) in [
        (
            "permissions of one role",
            walk_role(&repo, &org, &wide_role).await,
        ),
        (
            "roles carrying one permission",
            walk_permission(&repo, &org, &shared).await,
        ),
    ] {
        assert_eq!(listed.len(), WIDE, "the {label} walk sees every row once");
        let unique: std::collections::BTreeSet<String> =
            listed.iter().map(ToString::to_string).collect();
        assert_eq!(unique.len(), WIDE, "no duplication across pages: {label}");
    }
}

/// The role-scoped live-mapping count, unwrapped. A count that FAILED is a distinct
/// bug from a count that came back wrong, so the `expect` is here once rather than at
/// each of the many call sites below.
async fn count_for(
    repo: &ironauth_store::OrgRolePermissionRepo<'_>,
    org: &OrganizationId,
    role: &OrgRoleId,
) -> i64 {
    repo.count_live_for_role(org, role)
        .await
        .expect("counting a role's live mappings must not fail")
}

#[tokio::test]
async fn count_live_for_role_counts_only_this_organizations_live_mappings() {
    // The read behind the attach response's role-scoped budget verdict (issue #425).
    // It is a COUNT rather than a page length, and the three things that could make it
    // report a number over the wrong set are pinned here, each on its own.
    //
    // The organization fence first, because it is the one row-level security CANNOT
    // supply: the policy fences (tenant, environment) and cannot see `organization_id`,
    // so this statement's own conjunct is the whole fence between two organizations of
    // one environment. The fixture is built so a mutant that dropped it returns the
    // OTHER organization's number rather than an empty answer, which is why both
    // organizations here carry a DIFFERENT count.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let foreign = db.seed_scope(&env).await;

    let alpha = create_org(&db, &env, scope, "Alpha").await;
    let beta = create_org(&db, &env, scope, "Beta").await;
    let alpha_role = create_role(&db, &env, scope, &alpha, "admin").await;
    let beta_role = create_role(&db, &env, scope, &beta, "admin").await;

    let repo = db.control_store().management().org_role_permissions(scope);
    assert_eq!(
        count_for(&repo, &alpha, &alpha_role).await,
        0,
        "a role carrying nothing counts ZERO, never an error and never an absence"
    );

    // Three in alpha, one in beta, so the two counts can never be confused for each
    // other and neither can be confused for the scope-wide total of four.
    let mut alpha_mappings = Vec::new();
    for index in 0_i64..3 {
        let permission =
            create_permission(&db, &env, scope, &format!("alpha.capability_{index}")).await;
        alpha_mappings.push(
            attach_at(
                &db,
                &env,
                scope,
                &alpha,
                &alpha_role,
                &permission,
                2_000 + index,
            )
            .await
            .expect("attach in alpha"),
        );
    }
    let beta_permission = create_permission(&db, &env, scope, "beta.capability").await;
    attach(&db, &env, scope, &beta, &beta_role, &beta_permission)
        .await
        .expect("attach in beta");

    assert_eq!(
        count_for(&repo, &alpha, &alpha_role).await,
        3,
        "alpha's role counts its own three"
    );
    assert_eq!(
        count_for(&repo, &beta, &beta_role).await,
        1,
        "beta's role counts its own one, not the scope-wide four"
    );

    // The ORGANIZATION conjunct, driven from the wrong organization in both directions.
    // Without it each of these returns the OTHER organization's count, and an operator
    // attaching in beta would be shown alpha's picture.
    assert_eq!(
        count_for(&repo, &beta, &alpha_role).await,
        0,
        "a role counted under a SIBLING organization counts nothing"
    );
    assert_eq!(
        count_for(&repo, &alpha, &beta_role).await,
        0,
        "and the same the other way round"
    );

    // LIVENESS. A detach must stop counting at once, or the verdict an attach reports
    // would keep including capabilities that were withdrawn.
    detach(&db, &env, scope, &alpha, &alpha_mappings[0])
        .await
        .expect("detach one of alpha's");
    assert_eq!(
        count_for(&repo, &alpha, &alpha_role).await,
        2,
        "a detached mapping stops counting immediately"
    );

    // A role of ANOTHER scope counts zero rather than erroring: the same uniform
    // "nothing is visible here" the role list answers with an empty page.
    let foreign_org = create_org(&db, &env, foreign, "Foreign").await;
    let foreign_role = create_role(&db, &env, foreign, &foreign_org, "admin").await;
    let foreign_permission = create_permission(&db, &env, foreign, "foreign.capability").await;
    attach(
        &db,
        &env,
        foreign,
        &foreign_org,
        &foreign_role,
        &foreign_permission,
    )
    .await
    .expect("attach in the foreign scope");
    assert_eq!(
        count_for(&repo, &alpha, &foreign_role).await,
        0,
        "a role id of another scope is not visible here, so it counts zero"
    );
    assert_eq!(
        count_for(&repo, &foreign_org, &foreign_role).await,
        0,
        "and neither is a wholly foreign pair"
    );
    // The positive control on that last pair: the foreign scope's OWN repository does
    // count it, so the zeros above are the fence and not a broken fixture.
    assert_eq!(
        count_for(
            &db.control_store()
                .management()
                .org_role_permissions(foreign),
            &foreign_org,
            &foreign_role,
        )
        .await,
        1,
        "the foreign row really exists; this scope simply cannot see it"
    );
}

#[tokio::test]
async fn count_live_for_role_is_not_a_page_length() {
    // THE REASON `count_live_for_role` IS A COUNT AND NOT A LIST LENGTH, driven past
    // the point where the difference shows.
    //
    // Its docs say a length read off `list_for_role` would silently stop growing at the
    // page clamp. Every other test in this file works well below that clamp, so before
    // this one the rationale was untestable and the regression it warns about was free:
    // replacing the statement with `list_for_role(..).len()` at ANY limit passed the
    // whole suite, because the clamp is `MANAGEMENT_LIST_HARD_CAP + 1` and no fixture
    // came near it.
    //
    // So this fixture is deliberately the expensive one: MORE live mappings on ONE role
    // than any single page can return. The covenant permits it (a role's mappings are
    // uncapped) and the budget verdict the management attach reports is exactly the
    // consumer that would be silently wrong.
    //
    // Seeded through the CONTROL POOL with direct SQL rather than through the audited
    // write repository, for the reason `plant_mapping` gives one level up: what is under
    // test here is the arithmetic of the read at scale, and paying for a thousand audit
    // transactions to get there would buy nothing this file does not already prove
    // row by row.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;
    let role = create_role(&db, &env, scope, &org, "admin").await;

    let clamp = MANAGEMENT_LIST_HARD_CAP + 1;
    let seeded = clamp + 1;
    plant_many(&db, &env, scope, &org, &role, seeded).await;

    let repo = db.control_store().management().org_role_permissions(scope);
    assert_eq!(
        count_for(&repo, &org, &role).await,
        seeded,
        "the count reports EVERY live mapping of the role, however many there are"
    );

    // The clamp really is where the docs say it is, and it really does bite. Asking for
    // more than the hard cap returns the clamped page, so the length of ANY single page
    // is strictly less than the count above: that inequality is the whole claim, and it
    // is asserted rather than assumed so a future clamp change cannot quietly make this
    // test vacuous.
    let page = repo
        .list_for_role(&org, &role, i64::MAX, None)
        .await
        .expect("one page of a very large role");
    let page_len = i64::try_from(page.len()).expect("a page length fits i64");
    assert_eq!(
        page_len, clamp,
        "one page is clamped at MANAGEMENT_LIST_HARD_CAP + 1 however large the request"
    );
    assert!(
        page_len < count_for(&repo, &org, &role).await,
        "so a length read off one page UNDERSTATES the role: {page_len} against \
         {seeded}. A budget verdict computed that way would stop growing here and \
         report a role at the clamp forever"
    );
}

#[tokio::test]
async fn count_live_for_role_counts_a_mapping_whose_endpoints_are_dead() {
    // The "NOT a grant count" caveat, asserted rather than only written down.
    //
    // Deleting a ROLE or a PERMISSION cascades to no mapping row
    // (`an_attach_refuses_a_deleted_role_and_a_deleted_permission` pins that schema
    // behaviour), so a mapping whose endpoint is soft-deleted stays LIVE in this table
    // and stays counted here, while it resolves for nobody: the effective-permission
    // projection filters the permission's own `deleted_at` as well.
    //
    // That is the mechanism that makes this count LARGER than a membership's resolved
    // set, which is half of why the two figures bound each other in NEITHER direction.
    // It is pinned here so a future liveness join added to this statement is a
    // deliberate, visible change of meaning rather than a silent one.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;
    let role = create_role(&db, &env, scope, &org, "admin").await;
    let repo = db.control_store().management().org_role_permissions(scope);

    let doomed = create_permission(&db, &env, scope, "billing.doomed").await;
    let survivor = create_permission(&db, &env, scope, "billing.survivor").await;
    attach(&db, &env, scope, &org, &role, &doomed)
        .await
        .expect("attach the doomed permission");
    attach(&db, &env, scope, &org, &role, &survivor)
        .await
        .expect("attach the surviving permission");
    assert_eq!(count_for(&repo, &org, &role).await, 2, "both are counted");

    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .permissions(scope)
        .delete(&env, &doomed)
        .await
        .expect("soft delete the permission out from under its live mapping");
    assert_eq!(
        count_for(&repo, &org, &role).await,
        2,
        "a mapping whose PERMISSION is dead is STILL counted: this is a mapping count \
         and not a grant count, and it is exactly how this figure comes out LARGER \
         than the set a token would carry"
    );

    // A DETACH is the one thing that does stop the count, which is what separates
    // "withdrawn" from "endpoint deleted" here.
    let mapping = repo
        .get_assignment(&org, &role, &survivor)
        .await
        .expect("the surviving mapping is addressable");
    detach(&db, &env, scope, &org, &mapping.id)
        .await
        .expect("detach the survivor");
    assert_eq!(
        count_for(&repo, &org, &role).await,
        1,
        "only a DETACH stops a mapping counting; the dead-endpoint row is still there"
    );
}

/// Page the whole "permissions of this role" list through the `(created_at, id)`
/// cursor, at a page size small enough that several boundaries are crossed.
///
/// BOUNDED, for the reason [`walk_cap`] gives: a cursor that stops advancing must
/// fail here rather than spin.
async fn walk_role(
    repo: &ironauth_store::OrgRolePermissionRepo<'_>,
    org: &OrganizationId,
    role: &OrgRoleId,
) -> Vec<OrgRolePermissionId> {
    let mut seen = Vec::new();
    let mut cursor: Option<CursorPosition> = None;
    let cap = walk_cap(WIDE, WALK_PAGE);
    let mut steps = 0_usize;
    loop {
        steps += 1;
        assert!(
            steps <= cap,
            "the \"permissions of this role\" walk ran past {cap} pages without ending: \
             the cursor is not advancing, which is what a non-strict cursor comparison \
             produces"
        );
        let page = repo
            .list_for_role(
                org,
                role,
                i64::try_from(WALK_PAGE).expect("page size fits i64"),
                cursor.as_ref(),
            )
            .await
            .expect("page");
        let Some(last) = page.last() else {
            break;
        };
        cursor = Some(CursorPosition {
            created_at_unix_micros: last.created_at_unix_micros,
            id: last.id.to_string(),
        });
        seen.extend(page.iter().map(|record| record.id));
    }
    seen
}

/// The reverse-direction walk, over "roles carrying this permission". Bounded for
/// the same reason as [`walk_role`].
async fn walk_permission(
    repo: &ironauth_store::OrgRolePermissionRepo<'_>,
    org: &OrganizationId,
    permission: &PermissionId,
) -> Vec<OrgRolePermissionId> {
    let mut seen = Vec::new();
    let mut cursor: Option<CursorPosition> = None;
    let cap = walk_cap(WIDE, WALK_PAGE);
    let mut steps = 0_usize;
    loop {
        steps += 1;
        assert!(
            steps <= cap,
            "the \"roles carrying this permission\" walk ran past {cap} pages without \
             ending: the cursor is not advancing, which is what a non-strict cursor \
             comparison produces"
        );
        let page = repo
            .list_for_permission(
                org,
                permission,
                i64::try_from(WALK_PAGE).expect("page size fits i64"),
                cursor.as_ref(),
            )
            .await
            .expect("page");
        let Some(last) = page.last() else {
            break;
        };
        cursor = Some(CursorPosition {
            created_at_unix_micros: last.created_at_unix_micros,
            id: last.id.to_string(),
        });
        seen.extend(page.iter().map(|record| record.id));
    }
    seen
}

#[tokio::test]
async fn the_list_cursor_stays_total_and_stable_across_a_tied_created_at() {
    // Every row shares ONE creation instant, so `created_at` alone cannot order them
    // and the id half of the `(created_at, id)` pagination key is the only thing
    // making the order total. Ties are not hypothetical: `created_at` defaults to
    // `now()`, which is the TRANSACTION clock, so any multi-row attach in one
    // transaction produces byte-identical timestamps, and this table's covenant
    // invites exactly that shape.
    //
    // Replacing the row comparison `(created_at, id) > (ts, $6)` with a created_at
    // only comparison leaves every other test in this file green while a walk of ten
    // tied rows returns four and silently loses six.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;
    let role = create_role(&db, &env, scope, &org, "admin").await;

    let tied = 7_000_i64;
    for index in 0..TIED {
        let permission =
            create_permission(&db, &env, scope, &format!("billing.tied_{index}")).await;
        attach_at(&db, &env, scope, &org, &role, &permission, tied)
            .await
            .unwrap_or_else(|error| panic!("mapping {index} must be attachable: {error:?}"));
    }

    let repo = db.control_store().management().org_role_permissions(scope);

    // The whole set in one unpaged read: the reference order, in the database's own
    // terms rather than any assumption about how Rust would sort the ids.
    let whole = repo
        .list_for_role(&org, &role, 50, None)
        .await
        .expect("unpaged list of the tied set");
    let reference: Vec<OrgRolePermissionId> = whole.iter().map(|record| record.id).collect();
    assert_eq!(reference.len(), TIED, "the whole tied set is listed");
    assert!(
        whole
            .iter()
            .all(|record| record.created_at_unix_micros == tied),
        "the tie is real: every row shares one creation time"
    );

    // This test pins the CURSOR comparison. The ORDER BY's own `, id` tiebreak is a
    // separate property that nothing here can see, because both sides of every
    // assertion below come from the same ORDER BY and would drift together;
    // `the_list_order_by_is_total_with_the_ordering_index_taken_away` pins that one
    // and records why it needs its own fixture.
    //
    // Walk the same set in pages of four, TWICE. A page boundary lands inside the
    // tie, which is where a cursor keyed on created_at alone repeats or drops a row.
    let cap = walk_cap(TIED, TIED_PAGE);
    for attempt in 0..2 {
        let mut walked: Vec<OrgRolePermissionId> = Vec::new();
        let mut cursor: Option<CursorPosition> = None;
        let mut steps = 0_usize;
        loop {
            steps += 1;
            assert!(
                steps <= cap,
                "walk {attempt}: the tied-set walk ran past {cap} pages without ending: \
                 the cursor is not advancing, which is what a non-strict cursor \
                 comparison produces"
            );
            let page = repo
                .list_for_role(
                    &org,
                    &role,
                    i64::try_from(TIED_PAGE).expect("page size fits i64"),
                    cursor.as_ref(),
                )
                .await
                .expect("page of the tied set");
            let Some(last) = page.last() else {
                break;
            };
            cursor = Some(CursorPosition {
                created_at_unix_micros: last.created_at_unix_micros,
                id: last.id.to_string(),
            });
            walked.extend(page.iter().map(|record| record.id));
        }
        assert_eq!(
            walked, reference,
            "walk {attempt}: paging a tied set must reproduce the unpaged order exactly, \
             with no row skipped and none served twice at a page boundary"
        );
        let unique: std::collections::BTreeSet<String> =
            walked.iter().map(ToString::to_string).collect();
        assert_eq!(
            unique.len(),
            TIED,
            "walk {attempt}: every mapping in the tied set is seen exactly once"
        );
    }
}

#[tokio::test]
async fn the_list_order_by_is_total_with_the_ordering_index_taken_away() {
    // The list's own `ORDER BY created_at, id`, which the cursor test above cannot
    // reach and which is worth its own fixture for a reason that was MEASURED rather
    // than assumed.
    //
    // Dropping `, id` from the ORDER BY leaves this whole file green on the shipped
    // schema, and not because the property does not matter: the planner answers
    // `list_for_role` from `org_role_permissions_role_idx`, whose trailing
    // `(created_at, id)` columns hand the tie back in id order FOR FREE. So the
    // predicate looks pinned while what is actually holding the order up is an index
    // the query never named. Take that index away and the query has to stand on its
    // own: the plan becomes a scan plus a sort, and a sort keyed on `created_at`
    // ALONE returns a tie in whatever order the scan produced, which is insertion
    // order and not id order (the ids carry random unique components).
    //
    // Same move, and the same reason, as
    // `the_repository_still_fences_by_environment_with_the_policy_half_down`: remove
    // the layer underneath so the layer under test is the only thing left. A walk
    // over a set whose ORDER BY is not total can miss or repeat rows at a page
    // boundary even though the cursor comparison is exactly right, which is why the
    // two properties need two tests.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "Acme").await;
    let role = create_role(&db, &env, scope, &org, "admin").await;

    let tied = 7_000_i64;
    for index in 0..TIED {
        let permission =
            create_permission(&db, &env, scope, &format!("billing.tied_{index}")).await;
        attach_at(&db, &env, scope, &org, &role, &permission, tied)
            .await
            .unwrap_or_else(|error| panic!("mapping {index} must be attachable: {error:?}"));
    }

    // Under a FULL tie in `created_at`, `ORDER BY created_at, id` IS `ORDER BY id`.
    // That is the reference, sorted by the database in the column's own collation.
    let by_id = ids_ordered_by_id(&db, &role).await;
    assert_eq!(by_id.len(), TIED, "the whole tied set is there");

    // The layer really is down, and it cannot come back: after this no plan can use
    // it, whatever role or statistics the read runs under.
    db.execute_owner_sql("DROP INDEX org_role_permissions_role_idx")
        .await;
    assert_eq!(
        count_indexes_named(&db, "org_role_permissions_role_idx").await,
        0,
        "the ordering index must be gone, or this test proves nothing about the \
         ORDER BY"
    );

    let repo = db.control_store().management().org_role_permissions(scope);

    // Repeated, because a total order is also a STABLE one: the same query over the
    // same rows cannot reorder the tie between two calls.
    for repeat in 0..3 {
        let listed: Vec<String> = repo
            .list_for_role(&org, &role, 50, None)
            .await
            .expect("unpaged list of the tied set")
            .iter()
            .map(|record| record.id.to_string())
            .collect();
        assert_eq!(
            listed, by_id,
            "repeat {repeat}: with no index supplying the order, the list's own \
             ORDER BY must still be TOTAL, which under a full created_at tie means \
             exactly the id order"
        );
    }
}

/// Deleting a permission emits `permission.deleted`, carrying its slug (issue #108).
///
/// This is the WIDEST narrowing in the registry: deleting a permission removes it from every
/// role that referenced it at once -- one row, and everybody who held it through any role
/// loses it. A receiver mirroring access has more to undo here than for any other event,
/// which is why the slug travels: that is what a policy is written against, and after the
/// delete there is no live row to resolve the id from.
#[tokio::test]
async fn deleting_a_permission_emits_the_registered_event_with_its_slug() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let permission = create_permission(&db, &env, scope, "reports.read").await;

    assert_eq!(
        queued_events(&db, scope).await.len(),
        0,
        "creating a permission emits nothing today, so the delete's event is unambiguous"
    );

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_permission_deleted",
        "permission.deleted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({
            "permission_id": permission.to_string(),
            "slug": "reports.read",
        }),
    )
    .expect("permission.deleted is registered");

    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .permissions(scope)
        .delete_with_event(
            &env,
            &permission,
            Some(&ironauth_store::DomainEvent {
                id: "evt_permission_deleted",
                subject: &permission.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("delete with event");

    let events = queued_events(&db, scope).await;
    assert_eq!(events.len(), 1, "the delete enqueues exactly one event");
    assert_eq!(events[0]["type"], "permission.deleted");
    assert_eq!(
        events[0]["payload"]["slug"], "reports.read",
        "the slug survives the row it came from: a policy is written against it, not the id"
    );
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
}

/// A delete carrying no event enqueues nothing.
#[tokio::test]
async fn deleting_a_permission_without_an_event_enqueues_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let permission = create_permission(&db, &env, scope, "reports.write").await;

    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .permissions(scope)
        .delete(&env, &permission)
        .await
        .expect("delete");

    assert_eq!(
        queued_events(&db, scope).await.len(),
        0,
        "a delete with no event must not invent one"
    );
}

/// Every webhook-event envelope queued in `scope`.
async fn queued_events(db: &TestDatabase, scope: Scope) -> Vec<serde_json::Value> {
    use std::time::Duration;

    db.store()
        .scoped(scope)
        .outbox()
        .claim(
            &Env::system(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim webhook events")
        .into_iter()
        .map(|message| message.payload)
        .collect()
}
