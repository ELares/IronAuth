// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization roles (issue #97, store PR 1), over a real database (`DATABASE_URL`).
//!
//! Pins the role half of the M10 role model at the persistence layer: a role is
//! defined in an organization through an audited create; it renames and deletes
//! (audited, soft); a duplicate LIVE slug is a typed conflict while a DELETED
//! slug is freed for a fresh role; the resolve-by-id surfaces are a uniform
//! not-found for an absent, a deleted, a foreign-organization, and a foreign-scope
//! role alike (the anti-oracle discipline); forced row-level security hides another
//! scope's roles even with the app-layer filter subverted; the grants are
//! least-privilege (the data plane is read only, and `slug` is immutable by GRANT
//! on BOTH roles); and there is NO cap on how many roles an organization may hold.
//!
//! Cross-tenant and cross-environment isolation is additionally exercised through
//! the registered IDOR probes (`crates/ironauth-admin/tests/idor.rs`).

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, CursorPosition, NewOrgRole, OrgRoleId, OrganizationId, Scope,
    ServiceId, StoreError,
};
use sqlx::Row;

/// The Postgres "insufficient privilege" SQLSTATE.
const INSUFFICIENT_PRIVILEGE: &str = "42501";

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

/// Define a role in `org` via the control store, returning the new role id (or the
/// store error, so the conflict cases can assert on it).
async fn create_role(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    slug: &str,
    display_name: &str,
) -> Result<OrgRoleId, StoreError> {
    create_role_at(db, env, scope, org, slug, display_name, now_micros(env)).await
}

/// Define a role with an EXPLICIT creation time, so a test can pin several roles
/// to the SAME `created_at` and exercise the `(created_at, id)` cursor tiebreak.
/// The time still originates at the caller's env clock seam; nothing here reads a
/// wall clock of its own.
async fn create_role_at(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    slug: &str,
    display_name: &str,
    created_at_micros: i64,
) -> Result<OrgRoleId, StoreError> {
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
                display_name,
                metadata: None,
            },
            created_at_micros,
            None,
        )
        .await
        .map(|()| id)
}

/// The audit actions recorded against `target_id` in `scope`, in order. Read
/// through the OWNER pool so nothing hides behind row-level security.
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
    rows.iter().map(|r| r.get::<String, _>("action")).collect()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn role_create_get_list_rename_delete_round_trip_and_audits() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org = create_org(&db, &env, scope, "Globex").await;
    let role = create_role(&db, &env, scope, &org, "billing.admin", "Billing Admin")
        .await
        .expect("create role");

    // The role reads back within scope, bound to its organization.
    let record = control
        .management()
        .org_roles(scope)
        .get(&role)
        .await
        .expect("get role");
    assert_eq!(record.id, role);
    assert_eq!(record.organization_id, org);
    assert_eq!(record.slug, "billing.admin");
    assert_eq!(record.display_name, "Billing Admin");
    assert_eq!(record.metadata, serde_json::json!({}));

    // The organization's role list sees it.
    let listed = control
        .management()
        .org_roles(scope)
        .list_for_org(&org, 50, None)
        .await
        .expect("list roles");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, role);

    // A rename changes display_name and NOTHING else: the slug (what a later
    // authorization decision keys on) is untouched, so a rename can never move an
    // authorization decision.
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_roles(scope)
        .update(&env, &role, Some("Billing Administrator"), None)
        .await
        .expect("rename role");
    let renamed = control
        .management()
        .org_roles(scope)
        .get(&role)
        .await
        .expect("get after rename");
    assert_eq!(renamed.display_name, "Billing Administrator");
    assert_eq!(renamed.slug, "billing.admin", "the slug is immutable");
    assert_eq!(
        renamed.created_at_unix_micros, record.created_at_unix_micros,
        "a rename does not move the creation time (the pagination key)"
    );

    // Metadata replaces on its own, leaving the display name alone.
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_roles(scope)
        .update(
            &env,
            &role,
            None,
            Some(&serde_json::json!({"tier": "gold"})),
        )
        .await
        .expect("set metadata");
    let with_metadata = control
        .management()
        .org_roles(scope)
        .get(&role)
        .await
        .expect("get after metadata write");
    assert_eq!(with_metadata.metadata, serde_json::json!({"tier": "gold"}));
    assert_eq!(with_metadata.display_name, "Billing Administrator");

    // Delete is a soft delete: afterwards the role reads as absent everywhere.
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_roles(scope)
        .delete(&env, &role)
        .await
        .expect("delete role");
    assert!(matches!(
        control.management().org_roles(scope).get(&role).await,
        Err(StoreError::NotFound)
    ));
    assert!(
        control
            .management()
            .org_roles(scope)
            .list_for_org(&org, 50, None)
            .await
            .expect("list after delete")
            .is_empty()
    );

    // A repeat delete of an already deleted role is the uniform not-found, and so
    // is a rename of it: a deleted role is indistinguishable from an absent one on
    // every surface.
    assert!(matches!(
        control
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_roles(scope)
            .delete(&env, &role)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        control
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_roles(scope)
            .update(&env, &role, Some("resurrected"), None)
            .await,
        Err(StoreError::NotFound)
    ));

    // Every mutation audited against the role, in order, with the exact wire
    // strings the delta vocabulary declares.
    assert_eq!(
        audit_actions(&db, scope, &role.to_string()).await,
        vec![
            "organization.role.create",
            "organization.role.update",
            "organization.role.update",
            "organization.role.delete",
        ]
    );
}

#[tokio::test]
async fn a_live_slug_conflicts_while_a_deleted_slug_is_freed_for_a_fresh_role() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org = create_org(&db, &env, scope, "Globex").await;
    let other_org = create_org(&db, &env, scope, "Initech").await;

    let first = create_role(&db, &env, scope, &org, "admin", "Admin")
        .await
        .expect("first role");

    // A second LIVE role with the same slug in the same organization is refused on
    // the partial unique index.
    assert!(matches!(
        create_role(&db, &env, scope, &org, "admin", "Admin Again").await,
        Err(StoreError::Conflict)
    ));

    // The slug is scoped to the ORGANIZATION: another organization in the same
    // scope may hold the same slug.
    create_role(&db, &env, scope, &other_org, "admin", "Admin")
        .await
        .expect("the same slug in another organization is fine");

    // Delete the first role. Its slug is freed, and re-using it inserts a FRESH row
    // with a FRESH id rather than reviving the dead one, so deleting a role can
    // never be quietly undone in its authorization effects.
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_roles(scope)
        .delete(&env, &first)
        .await
        .expect("delete first role");
    let second = create_role(&db, &env, scope, &org, "admin", "Admin Reborn")
        .await
        .expect("a deleted slug is available again");
    assert_ne!(
        second, first,
        "the re-created role is a NEW role, not a revive"
    );
    assert!(
        matches!(
            control.management().org_roles(scope).get(&first).await,
            Err(StoreError::NotFound)
        ),
        "the deleted role stays deleted"
    );
    assert_eq!(
        control
            .management()
            .org_roles(scope)
            .get(&second)
            .await
            .expect("get the fresh role")
            .display_name,
        "Admin Reborn"
    );
}

#[tokio::test]
async fn an_organization_may_hold_unlimited_roles_and_the_list_pages_them() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org = create_org(&db, &env, scope, "Globex").await;

    // There is NO count cap, quota, or paywall gate on roles: a covenant. Define
    // enough of them that any hidden per-organization limit would have to fire.
    let total = 60;
    for index in 0..total {
        create_role(
            &db,
            &env,
            scope,
            &org,
            &format!("role-{index}"),
            &format!("Role {index}"),
        )
        .await
        .unwrap_or_else(|error| panic!("role {index} must be creatable: {error:?}"));
    }

    let first_page = control
        .management()
        .org_roles(scope)
        .list_for_org(&org, 25, None)
        .await
        .expect("first page");
    assert_eq!(first_page.len(), 25, "the PAGE is bounded, the SET is not");
    let cursor = CursorPosition {
        created_at_unix_micros: first_page[24].created_at_unix_micros,
        id: first_page[24].id.to_string(),
    };
    let second_page = control
        .management()
        .org_roles(scope)
        .list_for_org(&org, 100, Some(&cursor))
        .await
        .expect("second page");
    assert_eq!(
        second_page.len(),
        total - 25,
        "every remaining role is reachable through the cursor"
    );
    // The two pages are disjoint and together cover the whole set.
    let mut seen: Vec<String> = first_page
        .iter()
        .chain(second_page.iter())
        .map(|role| role.slug.clone())
        .collect();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), total, "no role is dropped or double counted");
}

#[tokio::test]
async fn the_role_list_is_confined_to_one_organization_within_a_shared_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    // TWO organizations in the SAME scope, both holding live roles. Row-level
    // security cannot fence these from each other (both sit in the caller's bound
    // scope), so the organization predicate in the list statement is the ONLY
    // thing separating them, and it needs a second organization present to be
    // observable at all. With just one organization in the fixture the predicate
    // could be dropped outright and every other assertion in this file would stay
    // green while the nested "roles in this organization" list served every role
    // in the environment: a cross-organization read leak.
    let globex = create_org(&db, &env, scope, "Globex").await;
    let initech = create_org(&db, &env, scope, "Initech").await;

    let globex_slugs = ["billing.admin", "billing.viewer"];
    let initech_slugs = ["auditor"];
    for slug in globex_slugs {
        create_role(&db, &env, scope, &globex, slug, "Role")
            .await
            .expect("role in Globex");
    }
    for slug in initech_slugs {
        create_role(&db, &env, scope, &initech, slug, "Role")
            .await
            .expect("role in Initech");
    }

    // Each organization's list is EXACTLY its own set: not a superset carrying the
    // sibling's roles, and not empty.
    for (org, expected) in [
        (&globex, globex_slugs.as_slice()),
        (&initech, initech_slugs.as_slice()),
    ] {
        let listed = control
            .management()
            .org_roles(scope)
            .list_for_org(org, 50, None)
            .await
            .expect("list roles for one organization");
        let mut slugs: Vec<&str> = listed.iter().map(|role| role.slug.as_str()).collect();
        slugs.sort_unstable();
        let mut want: Vec<&str> = expected.to_vec();
        want.sort_unstable();
        assert_eq!(
            slugs, want,
            "an organization's role list must hold exactly its own roles"
        );
        assert!(
            listed.iter().all(|role| &role.organization_id == org),
            "every listed role must belong to the organization that was asked for"
        );
    }
}

#[tokio::test]
async fn the_list_cursor_stays_total_and_stable_across_a_tied_created_at() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org = create_org(&db, &env, scope, "Globex").await;

    // Every role shares ONE creation instant, so `created_at` alone cannot order
    // them and the id half of the (created_at, id) pagination key is the only
    // thing making the order total. A tie is exactly where a cursor loses
    // determinism: the boundary row is served twice, or skipped. Determinism of
    // listing is an acceptance criterion of issue #97, so it is pinned here rather
    // than left to the accident of distinct clock readings. The instant is taken
    // once from the env clock seam and reused, never re-read per row.
    let tied = now_micros(&env);
    let total = 9_usize;
    for index in 0..total {
        create_role_at(
            &db,
            &env,
            scope,
            &org,
            &format!("tied-{index}"),
            &format!("Tied {index}"),
            tied,
        )
        .await
        .unwrap_or_else(|error| panic!("role {index} must be creatable: {error:?}"));
    }

    // The whole set in one unpaged read: the reference order, in the database's
    // own terms rather than any assumption about how Rust would sort the ids.
    let whole = control
        .management()
        .org_roles(scope)
        .list_for_org(&org, 50, None)
        .await
        .expect("unpaged list of the tied set");
    let reference: Vec<String> = whole.iter().map(|role| role.id.to_string()).collect();
    assert_eq!(reference.len(), total, "the whole tied set is listed");
    let mut distinct = reference.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), total, "the listed ids are distinct");
    assert!(
        whole.iter().all(|role| role.created_at_unix_micros == tied),
        "the tie is real: every row shares one creation time"
    );

    // Walk the same set in pages of four, TWICE. A page boundary lands inside the
    // tie, which is where a cursor keyed on created_at alone would repeat or drop
    // a row.
    for attempt in 0..2 {
        let mut walked: Vec<String> = Vec::new();
        let mut cursor: Option<CursorPosition> = None;
        loop {
            let page = control
                .management()
                .org_roles(scope)
                .list_for_org(&org, 4, cursor.as_ref())
                .await
                .expect("page of the tied set");
            let Some(last) = page.last() else {
                break;
            };
            cursor = Some(CursorPosition {
                created_at_unix_micros: last.created_at_unix_micros,
                id: last.id.to_string(),
            });
            walked.extend(page.iter().map(|role| role.id.to_string()));
        }
        assert_eq!(
            walked, reference,
            "walk {attempt}: paging a tied set must reproduce the unpaged order exactly, \
             with no row skipped and none served twice at a page boundary"
        );
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn absent_deleted_foreign_org_and_foreign_scope_roles_are_all_the_same_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);
    let control = db.control_store();

    let org_a = create_org(&db, &env, scope_a, "Alpha").await;
    let other_org_a = create_org(&db, &env, scope_a, "Alpha Sibling").await;
    let org_b = create_org(&db, &env, scope_b, "Beta").await;
    let org_a2 = create_org(&db, &env, scope_a2, "Alpha Staging").await;

    let live = create_role(&db, &env, scope_a, &org_a, "admin", "Admin")
        .await
        .expect("live role");
    let deleted = create_role(&db, &env, scope_a, &org_a, "auditor", "Auditor")
        .await
        .expect("role to delete");
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_roles(scope_a)
        .delete(&env, &deleted)
        .await
        .expect("delete");
    let in_tenant_b = create_role(&db, &env, scope_b, &org_b, "admin", "Admin")
        .await
        .expect("role in tenant B");
    let in_env_a2 = create_role(&db, &env, scope_a2, &org_a2, "admin", "Admin")
        .await
        .expect("role in environment A2");
    let absent = OrgRoleId::generate(&env, &scope_a);

    let roles_a = control.management().org_roles(scope_a);

    // 1. A well-formed id in the caller's own scope that was never stored.
    assert!(matches!(
        roles_a.get(&absent).await,
        Err(StoreError::NotFound)
    ));
    // 2. A soft-deleted role.
    assert!(matches!(
        roles_a.get(&deleted).await,
        Err(StoreError::NotFound)
    ));
    // 3. A role of another TENANT and 4. of another ENVIRONMENT: both fail at the
    //    parse boundary, before any statement runs, with the same not-found.
    for foreign in [&in_tenant_b, &in_env_a2] {
        assert!(
            matches!(
                roles_a.parse_id(&foreign.to_string()),
                Err(StoreError::NotFound)
            ),
            "a foreign-scope role id must parse to the uniform not-found"
        );
        assert!(
            matches!(roles_a.get(foreign).await, Err(StoreError::NotFound)),
            "a foreign-scope role must read as the uniform not-found"
        );
    }
    // 5. A LIVE role of another ORGANIZATION in the SAME scope, presented under the
    //    nested organization path. This is the one case row-level security does not
    //    fence (both organizations are in the caller's scope), so the repository
    //    must, and it must be indistinguishable from every case above.
    assert!(matches!(
        roles_a.get_in_org(&other_org_a, &live).await,
        Err(StoreError::NotFound)
    ));
    assert!(
        matches!(
            roles_a.get_in_org(&other_org_a, &absent).await,
            Err(StoreError::NotFound)
        ),
        "a foreign-org role and an absent one are indistinguishable"
    );
    // The positive control: under its OWN organization the same id resolves.
    assert_eq!(
        roles_a
            .get_in_org(&org_a, &live)
            .await
            .expect("the role resolves under its own organization")
            .id,
        live
    );

    // A cross-scope organization id yields an EMPTY list, never another scope's
    // roles and never an error that would distinguish it from an empty org.
    assert!(
        roles_a
            .list_for_org(&org_b, 50, None)
            .await
            .expect("list for a foreign-scope org")
            .is_empty()
    );

    // A mutation is fenced identically: deleting a foreign-scope role is not found,
    // and the victim survives.
    assert!(matches!(
        control
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_roles(scope_a)
            .delete(&env, &in_tenant_b)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(
        control
            .management()
            .org_roles(scope_b)
            .get(&in_tenant_b)
            .await
            .is_ok(),
        "tenant B's role survives a cross-scope delete attempt"
    );

    // A create that names a foreign-scope organization is refused before any
    // statement runs, so a role can never be planted into another scope's org.
    let smuggled = OrgRoleId::generate(&env, &scope_a);
    assert!(matches!(
        control
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_roles(scope_a)
            .create(
                &env,
                NewOrgRole {
                    id: &smuggled,
                    organization_id: &org_b,
                    slug: "smuggled",
                    display_name: "Smuggled",
                    metadata: None,
                },
                now_micros(&env),
                None,
            )
            .await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn rls_hides_another_scopes_roles_from_the_control_role_and_refuses_forging_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    let org_b = create_org(&db, &env, scope_b, "Beta").await;
    create_role(&db, &env, scope_b, &org_b, "admin", "Admin")
        .await
        .expect("role in scope B");

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

    // 1. Deny by default: no scope bound on the session, zero rows.
    let unset: i64 = sqlx::query("SELECT count(*) AS c FROM org_roles")
        .fetch_one(pool)
        .await
        .expect("count with unset scope")
        .get("c");
    assert_eq!(unset, 0, "an unset scope must see no roles");

    // 2. Mis-scoped session with the app-layer filter SUBVERTED: bound to A, the
    //    query explicitly targets B's rows. Forced row-level security still
    //    returns zero.
    {
        let mut tx = pool.begin().await.expect("begin as scope A");
        bind_scope(
            &mut tx,
            &scope_a.tenant().to_string(),
            &scope_a.environment().to_string(),
        )
        .await;
        let leaked: i64 = sqlx::query(
            "SELECT count(*) AS c FROM org_roles WHERE tenant_id = $1 AND environment_id = $2",
        )
        .bind(scope_b.tenant().to_string())
        .bind(scope_b.environment().to_string())
        .fetch_one(&mut *tx)
        .await
        .expect("cross-scope count")
        .get("c");
        assert_eq!(
            leaked, 0,
            "RLS must hide scope B roles from a scope A session even with the filter bypassed"
        );

        // 3. Write-side isolation: a scope A session cannot rename scope B's role
        //    (the USING clause hides it) nor INSERT one claiming scope B (the WITH
        //    CHECK rejects it).
        let updated =
            sqlx::query("UPDATE org_roles SET display_name = 'hijacked' WHERE tenant_id = $1")
                .bind(scope_b.tenant().to_string())
                .execute(&mut *tx)
                .await
                .expect("update runs")
                .rows_affected();
        assert_eq!(
            updated, 0,
            "RLS must hide scope B rows from a scope A UPDATE"
        );

        let forged = OrgRoleId::generate(&env, &scope_b).to_string();
        let insert = sqlx::query(
            "INSERT INTO org_roles \
             (id, tenant_id, environment_id, organization_id, slug, display_name) \
             VALUES ($1, $2, $3, $4, 'forged', 'Forged')",
        )
        .bind(forged)
        .bind(scope_b.tenant().to_string())
        .bind(scope_b.environment().to_string())
        .bind(org_b.to_string())
        .execute(&mut *tx)
        .await;
        assert!(
            insert.is_err(),
            "RLS WITH CHECK must reject writing another scope's role"
        );
        let _ = tx.rollback().await;
    }

    // 4. Positive control: bound to B, the same role sees exactly B's row.
    {
        let mut tx = pool.begin().await.expect("begin as scope B");
        bind_scope(
            &mut tx,
            &scope_b.tenant().to_string(),
            &scope_b.environment().to_string(),
        )
        .await;
        let visible: i64 = sqlx::query("SELECT count(*) AS c FROM org_roles")
            .fetch_one(&mut *tx)
            .await
            .expect("count in B")
            .get("c");
        assert_eq!(visible, 1, "scope B sees its own role");
        tx.commit().await.expect("commit B read");
    }
}

#[tokio::test]
async fn the_data_plane_can_read_a_role_but_never_write_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let role = create_role(&db, &env, scope, &org, "admin", "Admin")
        .await
        .expect("create role");

    // The DATA plane reads a role through the scoped store: the grant a later PR's
    // token-issuance role resolution depends on. Without it that path would fail
    // with SQLSTATE 42501, which is why 0086 grants it in the creating migration.
    let read = db
        .store()
        .scoped(scope)
        .org_roles()
        .get(&role)
        .await
        .expect("the data plane can READ a role");
    assert_eq!(read.slug, "admin");

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

    // Every MUTATING statement is refused as insufficient privilege: the data plane
    // can look a role up but never define, rename, delete, or hard-remove one.
    assert_denied_in_scope(pool, &tenant, &environment, &org, "DELETE FROM org_roles").await;
    assert_denied_in_scope(
        pool,
        &tenant,
        &environment,
        &org,
        "UPDATE org_roles SET display_name = 'tampered'",
    )
    .await;
    assert_denied_in_scope(
        pool,
        &tenant,
        &environment,
        &org,
        "UPDATE org_roles SET deleted_at = now()",
    )
    .await;
    // The forge probe writes a row that is valid in EVERY respect but the grant:
    // the session's own scope, a real organization of that scope, and a slug and
    // display name the CHECKs accept. If the data plane ever gained INSERT, whether
    // table-wide or column-scoped, this statement would SUCCEED rather than fail
    // with a different error, so the assertion cannot be satisfied by a refusal
    // that has nothing to do with privilege.
    assert_denied_in_scope(
        pool,
        &tenant,
        &environment,
        &org,
        "INSERT INTO org_roles (id, tenant_id, environment_id, organization_id, slug, \
         display_name) VALUES ('rol_probe', $1, $2, $3, 'probe', 'probe')",
    )
    .await;

    // The slug is immutable by GRANT on BOTH roles: not even the control plane, which
    // owns the whole role lifecycle, may rewrite the stable name.
    assert_denied_in_scope(
        db.control_pool(),
        &tenant,
        &environment,
        &org,
        "UPDATE org_roles SET slug = 'tampered'",
    )
    .await;
    // Positive control: the control role's column-scoped rename DOES succeed, so the
    // denial above is about the column and not about the role's access generally.
    {
        let mut tx = db.control_pool().begin().await.expect("begin control tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        sqlx::query("UPDATE org_roles SET display_name = 'renamed by the control plane'")
            .execute(&mut *tx)
            .await
            .expect("the control role holds column-scoped UPDATE on display_name");
        let _ = tx.rollback().await;
    }
}

#[tokio::test]
async fn the_slug_charset_check_refuses_a_malformed_slug() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;

    // The charset CHECK is the storage-engine backstop under the management edge's
    // own validation: an uppercase, empty, or space-carrying slug never lands, so
    // two roles cannot differ only by case (there is no case folding on this column
    // and comparison is byte exact).
    for bad in [
        "Admin",
        "",
        "has space",
        ".leading-dot",
        "way-too-long-slug-that-runs-past-the-sixty-three-character-ceiling-xxxxx",
    ] {
        let result = create_role(&db, &env, scope, &org, bad, "Bad").await;
        assert!(
            matches!(result, Err(StoreError::Database(_))),
            "the slug CHECK must refuse {bad:?}, got {result:?}"
        );
    }
    // A nonempty display name is likewise pinned by a CHECK.
    assert!(matches!(
        create_role(&db, &env, scope, &org, "fine", "").await,
        Err(StoreError::Database(_))
    ));

    // The valid charset really is accepted (the CHECK is not simply refusing
    // everything): lowercase alphanumerics plus dot, underscore, and ASCII hyphen.
    create_role(&db, &env, scope, &org, "a1.b_c-d", "Fine")
        .await
        .expect("the documented charset is accepted");
}

/// Run `statement` in a scoped transaction on `pool` and assert it is refused as
/// insufficient privilege.
///
/// A statement carrying placeholders binds `$1` and `$2` to the session's OWN
/// (tenant, environment) and `$3` to `organization`, so a probe INSERT writes a
/// row that SATISFIES the row-level-security WITH CHECK (and the organization
/// foreign key), leaving the missing GRANT as the only thing that can refuse it.
/// That distinction is the whole point of the probe: Postgres reports a policy
/// refusal and a privilege refusal under the SAME SQLSTATE (42501), so a probe
/// writing literal foreign scope values would be rejected by the policy no matter
/// how far the grant was widened, and could never observe the grant at all.
async fn assert_denied_in_scope(
    pool: &sqlx::PgPool,
    tenant: &str,
    environment: &str,
    organization: &OrganizationId,
    statement: &str,
) {
    let mut tx = pool.begin().await.expect("begin denied-statement tx");
    bind_scope(&mut tx, tenant, environment).await;
    let mut query = sqlx::query(statement);
    if statement.contains("$1") {
        query = query
            .bind(tenant)
            .bind(environment)
            .bind(organization.to_string());
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
