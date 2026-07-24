// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization groups and hierarchy safety (issue #97, store PR 2), over a real
//! database (`DATABASE_URL`).
//!
//! Pins the group half of the M10 role model at the persistence layer, and with it
//! the one piece of genuinely concurrent structural logic in the issue:
//!
//!   * a group is defined in an organization, optionally under a parent, renamed,
//!     MOVED, and deleted, each audited with the exact delta wire strings;
//!   * a reparent that would close a CYCLE is refused with a typed error and writes
//!     nothing, including the audit row;
//!   * the configurable DEPTH bound is exact at the boundary and is measured over
//!     the WHOLE moved subtree, not just the new edge;
//!   * CONCURRENT reparents that would jointly close a cycle no single transaction
//!     could observe cannot both commit (the advisory lock);
//!   * every resolve-by-id surface is a uniform not-found for an absent, a deleted,
//!     a foreign-organization, and a foreign-scope group alike, and the typed cycle
//!     and depth errors are never an existence oracle for a group the caller cannot
//!     see;
//!   * forced row-level security hides another scope's groups even with the
//!     app-layer filter subverted, the grants are least-privilege (the data plane is
//!     read only, and `slug` is immutable by GRANT on BOTH roles);
//!   * and there is NO cap on how many groups an organization may hold, at any depth.
//!
//! Cross-tenant and cross-environment isolation is additionally exercised through the
//! registered IDOR probes (`crates/ironauth-admin/tests/idor.rs`).

use std::collections::BTreeSet;
use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, CursorPosition, NewOrgGroup, ORG_GROUP_MAX_DEPTH_CEILING, OrgGroupId,
    OrgRoleId, OrganizationId, Scope, ServiceId, Store, StoreError,
};
use sqlx::Row;

/// The Postgres "insufficient privilege" SQLSTATE.
const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// The depth bound most tests pass: the shipped `[organizations] max_group_depth`
/// default. Tests that are ABOUT the bound state their own.
const DEFAULT_DEPTH: u32 = 8;

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

/// Define a group in `org`, optionally under `parent`, returning the new group id
/// (or the store error, so the refusal cases can assert on it).
async fn create_group(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    slug: &str,
    parent: Option<&OrgGroupId>,
) -> Result<OrgGroupId, StoreError> {
    create_group_with(db, env, scope, org, slug, parent, DEFAULT_DEPTH).await
}

/// Define a group with an explicit depth bound, for the tests that are about the
/// bound itself.
async fn create_group_with(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    slug: &str,
    parent: Option<&OrgGroupId>,
    max_group_depth: u32,
) -> Result<OrgGroupId, StoreError> {
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
            max_group_depth,
            None,
        )
        .await
        .map(|()| id)
}

/// Move `group` under `parent` (or to a root when `parent` is `None`).
async fn reparent(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    group: &OrgGroupId,
    parent: Option<&OrgGroupId>,
    max_group_depth: u32,
) -> Result<(), StoreError> {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_groups(scope)
        .reparent(env, org, group, parent, max_group_depth)
        .await
}

/// Build a CHAIN of `length` groups, each the child of the previous, returning every
/// id root-first. Built with a generous bound so the chain itself is never the thing
/// under test.
async fn build_chain(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    length: usize,
) -> Vec<OrgGroupId> {
    let mut chain: Vec<OrgGroupId> = Vec::with_capacity(length);
    for index in 0..length {
        let parent = chain.last().copied();
        let id = create_group_with(
            db,
            env,
            scope,
            org,
            &format!("chain-{index}"),
            parent.as_ref(),
            ORG_GROUP_MAX_DEPTH_CEILING,
        )
        .await
        .unwrap_or_else(|error| panic!("chain link {index} must be creatable: {error:?}"));
        chain.push(id);
    }
    chain
}

/// The audit actions recorded against `target_id` in `scope`, in order. Read through
/// the OWNER pool so nothing hides behind row-level security.
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

/// The `detail` dimensions recorded against `target_id`, in order.
async fn audit_details(db: &TestDatabase, scope: Scope, target_id: &str) -> Vec<Option<String>> {
    let rows = sqlx::query(
        "SELECT detail FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND target_id = $3 \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(target_id)
    .fetch_all(db.owner_pool())
    .await
    .expect("read audit details");
    rows.iter()
        .map(|r| r.get::<Option<String>, _>("detail"))
        .collect()
}

/// Every live group of `org` as `(id, parent_id)`, read through the OWNER pool so
/// the assertion sees the raw stored graph rather than anything the repository
/// chooses to project.
async fn stored_edges(
    db: &TestDatabase,
    scope: Scope,
    org: &OrganizationId,
) -> Vec<(String, Option<String>)> {
    let rows = sqlx::query(
        "SELECT id, parent_id FROM org_groups \
         WHERE tenant_id = $1 AND environment_id = $2 AND organization_id = $3 \
         AND deleted_at IS NULL ORDER BY id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(org.to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read stored edges");
    rows.iter()
        .map(|row| {
            (
                row.get::<String, _>("id"),
                row.get::<Option<String>, _>("parent_id"),
            )
        })
        .collect()
}

/// Assert the stored graph of `org` is a forest: every parent chain terminates.
///
/// Walks the RAW stored rows, bounded by the node count, so a cycle shows up as a
/// non-terminating chain rather than as a hang.
async fn assert_acyclic(db: &TestDatabase, scope: Scope, org: &OrganizationId) {
    let edges = stored_edges(db, scope, org).await;
    let parent_of = |id: &str| -> Option<Option<String>> {
        edges
            .iter()
            .find(|(node, _)| node == id)
            .map(|(_, parent)| parent.clone())
    };
    for (start, _) in &edges {
        let mut current = start.clone();
        let mut steps = 0_usize;
        loop {
            match parent_of(&current) {
                None | Some(None) => break,
                Some(Some(parent)) => {
                    current = parent;
                    steps += 1;
                    assert!(
                        steps <= edges.len(),
                        "the stored group graph contains a CYCLE reachable from {start}: {edges:?}"
                    );
                }
            }
        }
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn group_create_get_list_rename_reparent_delete_round_trip_and_audits() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org = create_org(&db, &env, scope, "Globex").await;
    let root = create_group(&db, &env, scope, &org, "all-staff", None)
        .await
        .expect("create root group");
    let child = create_group(&db, &env, scope, &org, "engineering", Some(&root))
        .await
        .expect("create child group");

    // The root reads back with no parent; the child with its parent.
    let root_record = control
        .management()
        .org_groups(scope)
        .get(&root)
        .await
        .expect("get root");
    assert_eq!(root_record.organization_id, org);
    assert_eq!(root_record.parent_id, None, "a root group has no parent");
    assert_eq!(root_record.slug, "all-staff");
    assert_eq!(root_record.metadata, serde_json::json!({}));
    let child_record = control
        .management()
        .org_groups(scope)
        .get(&child)
        .await
        .expect("get child");
    assert_eq!(child_record.parent_id, Some(root));

    // The organization's group list is FLAT and carries the parent pointers, so a
    // console can render the tree from one page sequence.
    let listed = control
        .management()
        .org_groups(scope)
        .list_for_org(&org, 50, None)
        .await
        .expect("list groups");
    assert_eq!(listed.len(), 2);
    assert_eq!(
        listed
            .iter()
            .map(|group| (group.slug.clone(), group.parent_id))
            .collect::<Vec<_>>(),
        vec![
            ("all-staff".to_owned(), None),
            ("engineering".to_owned(), Some(root)),
        ]
    );

    // A rename changes display_name and NOTHING else: not the slug (what a later
    // authorization or routing decision keys on) and not the parent.
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_groups(scope)
        .update(&env, &child, Some("Engineering"), None)
        .await
        .expect("rename group");
    let renamed = control
        .management()
        .org_groups(scope)
        .get(&child)
        .await
        .expect("get after rename");
    assert_eq!(renamed.display_name, "Engineering");
    assert_eq!(renamed.slug, "engineering", "the slug is immutable");
    assert_eq!(
        renamed.parent_id,
        Some(root),
        "a rename must never move a group in the hierarchy"
    );

    // A reparent to a root promotes the child.
    reparent(&db, &env, scope, &org, &child, None, DEFAULT_DEPTH)
        .await
        .expect("promote to root");
    assert_eq!(
        control
            .management()
            .org_groups(scope)
            .get(&child)
            .await
            .expect("get after promote")
            .parent_id,
        None
    );
    // And back under the root again.
    reparent(&db, &env, scope, &org, &child, Some(&root), DEFAULT_DEPTH)
        .await
        .expect("re-nest under the root");

    // Delete is a soft delete: afterwards the group reads as absent everywhere.
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_groups(scope)
        .delete(&env, &org, &child)
        .await
        .expect("delete group");
    assert!(matches!(
        control.management().org_groups(scope).get(&child).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(
        control
            .management()
            .org_groups(scope)
            .list_for_org(&org, 50, None)
            .await
            .expect("list after delete")
            .len(),
        1
    );

    // A repeat delete, a rename, and a reparent of an already deleted group are all
    // the uniform not-found: a deleted group is indistinguishable from an absent one
    // on every surface, including the hierarchy one.
    assert!(matches!(
        control
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_groups(scope)
            .delete(&env, &org, &child)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        control
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_groups(scope)
            .update(&env, &child, Some("resurrected"), None)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        reparent(&db, &env, scope, &org, &child, Some(&root), DEFAULT_DEPTH).await,
        Err(StoreError::NotFound)
    ));

    // Every mutation audited against the group, in order, with the exact wire strings
    // the delta vocabulary declares. The reparent is its own action, never folded
    // into the update.
    assert_eq!(
        audit_actions(&db, scope, &child.to_string()).await,
        vec![
            "organization.group.create",
            "organization.group.update",
            "organization.group.reparent",
            "organization.group.reparent",
            "organization.group.delete",
        ]
    );
    // The reparent rows carry the resulting parent in their operator-safe detail, so
    // the shape of the tree over time is reconstructable from the audit log alone.
    // Nothing else carries a detail.
    assert_eq!(
        audit_details(&db, scope, &child.to_string()).await,
        vec![
            None,
            None,
            Some("parent=none".to_owned()),
            Some(format!("parent={root}")),
            None,
        ]
    );
}

#[tokio::test]
async fn a_live_slug_conflicts_while_a_deleted_slug_is_freed_and_the_charset_is_enforced() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org = create_org(&db, &env, scope, "Globex").await;
    let other_org = create_org(&db, &env, scope, "Initech").await;

    let first = create_group(&db, &env, scope, &org, "engineering", None)
        .await
        .expect("first group");
    assert!(matches!(
        create_group(&db, &env, scope, &org, "engineering", None).await,
        Err(StoreError::Conflict)
    ));
    // The slug is scoped to the ORGANIZATION.
    create_group(&db, &env, scope, &other_org, "engineering", None)
        .await
        .expect("the same slug in another organization is fine");

    // Deleting frees the slug, and re-using it inserts a FRESH row with a fresh id
    // rather than reviving the dead one, so deleting a group can never be quietly
    // undone in its authorization effects (later PRs hang memberships and role
    // assignments off a group id).
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_groups(scope)
        .delete(&env, &org, &first)
        .await
        .expect("delete first group");
    let second = create_group(&db, &env, scope, &org, "engineering", None)
        .await
        .expect("a deleted slug is available again");
    assert_ne!(second, first, "the re-created group is a NEW group");

    // The charset CHECK is the storage-engine backstop under the management edge's
    // own validation: no case folding, so two groups cannot differ only by case.
    for bad in [
        "Engineering",
        "",
        "has space",
        ".leading-dot",
        "way-too-long-slug-that-runs-past-the-sixty-three-character-ceiling-xxxxx",
    ] {
        let result = create_group(&db, &env, scope, &org, bad, None).await;
        assert!(
            matches!(result, Err(StoreError::Database(_))),
            "the slug CHECK must refuse {bad:?}, got {result:?}"
        );
    }
    create_group(&db, &env, scope, &org, "a1.b_c-d", None)
        .await
        .expect("the documented charset is accepted");
}

#[tokio::test]
async fn an_organization_may_hold_unlimited_groups_at_one_depth_and_the_list_pages_them() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org = create_org(&db, &env, scope, "Globex").await;
    let root = create_group(&db, &env, scope, &org, "all-staff", None)
        .await
        .expect("root");

    // There is NO count cap, quota, or paywall gate on groups: a covenant. The depth
    // bound bounds DEPTH, never the NUMBER of groups, so a wide layer at ONE depth
    // must be unlimited even with the tightest useful bound in force. Every child
    // below sits at depth 1 against a bound of 1, which is exactly the configuration
    // where a limit confused with a cap would fire.
    let total = 60;
    for index in 0..total {
        create_group_with(
            &db,
            &env,
            scope,
            &org,
            &format!("team-{index}"),
            Some(&root),
            1,
        )
        .await
        .unwrap_or_else(|error| panic!("group {index} must be creatable: {error:?}"));
    }

    let first_page = control
        .management()
        .org_groups(scope)
        .list_for_org(&org, 25, None)
        .await
        .expect("first page");
    assert_eq!(first_page.len(), 25, "the PAGE is bounded, the SET is not");
    let cursor = CursorPosition {
        created_at_unix_micros: first_page[24].created_at_unix_micros,
        id: first_page[24].id.to_string(),
    };
    let rest = control
        .management()
        .org_groups(scope)
        .list_for_org(&org, 100, Some(&cursor))
        .await
        .expect("second page");
    // 60 children plus the root.
    assert_eq!(rest.len(), total + 1 - 25);
    let slugs: BTreeSet<String> = first_page
        .iter()
        .chain(rest.iter())
        .map(|group| group.slug.clone())
        .collect();
    assert_eq!(
        slugs.len(),
        total + 1,
        "no group is dropped or double counted"
    );
}

#[tokio::test]
async fn the_group_list_is_confined_to_one_organization_within_a_shared_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    // TWO organizations in the SAME scope, both holding live groups. Row-level
    // security cannot fence these from each other (both sit in the caller's bound
    // scope), so the organization predicate in the list statement is the ONLY thing
    // separating them, and it needs a second organization present to be observable
    // at all. With one organization in the fixture the predicate could be dropped
    // outright and every other assertion in this file would stay green while the
    // nested "groups in this organization" list served every group in the
    // environment.
    let globex = create_org(&db, &env, scope, "Globex").await;
    let initech = create_org(&db, &env, scope, "Initech").await;

    let globex_slugs = ["all-staff", "engineering"];
    let initech_slugs = ["auditors"];
    for slug in globex_slugs {
        create_group(&db, &env, scope, &globex, slug, None)
            .await
            .expect("group in Globex");
    }
    for slug in initech_slugs {
        create_group(&db, &env, scope, &initech, slug, None)
            .await
            .expect("group in Initech");
    }

    for (org, expected) in [
        (&globex, globex_slugs.as_slice()),
        (&initech, initech_slugs.as_slice()),
    ] {
        let listed = control
            .management()
            .org_groups(scope)
            .list_for_org(org, 50, None)
            .await
            .expect("list groups for one organization");
        let got: BTreeSet<&str> = listed.iter().map(|group| group.slug.as_str()).collect();
        let want: BTreeSet<&str> = expected.iter().copied().collect();
        assert_eq!(
            got, want,
            "an organization's group list must hold exactly its own groups"
        );
        assert!(
            listed.iter().all(|group| &group.organization_id == org),
            "every listed group must belong to the organization that was asked for"
        );
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_reparent_that_would_close_a_cycle_is_refused_and_writes_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    // A chain a -> b -> c -> d (a is the root).
    let chain = build_chain(&db, &env, scope, &org, 4).await;
    let (a, b, c, d) = (chain[0], chain[1], chain[2], chain[3]);

    // 1. A group under ITSELF. The storage engine's own CHECK would also refuse this,
    //    but the repository must get there first with the TYPED error, because a raw
    //    23514 mid-transaction would abort the transaction before the audit row could
    //    be written.
    assert!(matches!(
        reparent(
            &db,
            &env,
            scope,
            &org,
            &a,
            Some(&a),
            ORG_GROUP_MAX_DEPTH_CEILING
        )
        .await,
        Err(StoreError::OrgGroupCycle)
    ));

    // 2. A two-node back edge: the root under its own child.
    assert!(matches!(
        reparent(
            &db,
            &env,
            scope,
            &org,
            &a,
            Some(&b),
            ORG_GROUP_MAX_DEPTH_CEILING
        )
        .await,
        Err(StoreError::OrgGroupCycle)
    ));

    // 3. A DEEP back edge: the root under its own great-grandchild. This is the case
    //    a single-hop check misses, and the one the recursive ancestor walk exists
    //    for.
    assert!(matches!(
        reparent(
            &db,
            &env,
            scope,
            &org,
            &a,
            Some(&d),
            ORG_GROUP_MAX_DEPTH_CEILING
        )
        .await,
        Err(StoreError::OrgGroupCycle)
    ));

    // 4. A mid-tree back edge that does not involve the root at all.
    assert!(matches!(
        reparent(
            &db,
            &env,
            scope,
            &org,
            &b,
            Some(&d),
            ORG_GROUP_MAX_DEPTH_CEILING
        )
        .await,
        Err(StoreError::OrgGroupCycle)
    ));

    // Nothing was written by ANY of the four refusals: the stored graph is exactly
    // the chain it started as, and no audit row was appended for any of them. This
    // is the consistency claim made concrete rather than asserted: the checks run
    // inside the audited write transaction, so a refusal rolls the attempted data
    // change AND its audit row back together.
    let edges = stored_edges(&db, scope, &org).await;
    let mut expected: Vec<(String, Option<String>)> = vec![
        (a.to_string(), None),
        (b.to_string(), Some(a.to_string())),
        (c.to_string(), Some(b.to_string())),
        (d.to_string(), Some(c.to_string())),
    ];
    expected.sort();
    let mut got = edges;
    got.sort();
    assert_eq!(got, expected, "a refused reparent must write nothing");
    for group in [&a, &b] {
        assert_eq!(
            audit_actions(&db, scope, &group.to_string()).await,
            vec!["organization.group.create"],
            "a refused reparent must not append an audit row"
        );
    }
    assert_acyclic(&db, scope, &org).await;

    // The positive control: a legal move in the same fixture SUCCEEDS, so the four
    // refusals above are about the cycle and not about reparenting being broken.
    reparent(
        &db,
        &env,
        scope,
        &org,
        &d,
        Some(&a),
        ORG_GROUP_MAX_DEPTH_CEILING,
    )
    .await
    .expect("moving a descendant UP its own chain is legal and must be admitted");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn the_depth_bound_is_exact_at_the_boundary_and_covers_the_whole_moved_subtree() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;

    // A chain of four: depths 0, 1, 2, 3.
    let chain = build_chain(&db, &env, scope, &org, 4).await;
    let deepest = chain[3];

    // Creating a child of the depth-3 node lands at depth 4. With a bound of 4 that
    // is EXACTLY on the boundary and must be admitted; with a bound of 3 it is one
    // level too deep and must be refused. An off-by-one in the bound is the whole
    // difference between these two lines.
    let at_bound = create_group_with(&db, &env, scope, &org, "at-bound", Some(&deepest), 4)
        .await
        .expect("a group landing EXACTLY on the bound must be admitted");
    let over = create_group_with(&db, &env, scope, &org, "over-bound", Some(&deepest), 3).await;
    assert!(
        matches!(
            over,
            Err(StoreError::OrgGroupDepthExceeded {
                max: 3,
                attempted: 4
            })
        ),
        "one level past the bound must be refused with the attempted depth: {over:?}"
    );

    // The SUBTREE case, which is what makes the bound a property of the whole moved
    // subtree rather than of the new edge. Build a separate chain of three
    // (depths 0, 1, 2, so its root carries a subtree of HEIGHT 2), then move that
    // root under the depth-1 node of the first chain. The deepest descendant would
    // land at 1 + 1 + 2 = 4.
    let mover = create_group(&db, &env, scope, &org, "mover", None)
        .await
        .expect("mover root");
    let mid = create_group(&db, &env, scope, &org, "mover-mid", Some(&mover))
        .await
        .expect("mover mid");
    create_group(&db, &env, scope, &org, "mover-leaf", Some(&mid))
        .await
        .expect("mover leaf");

    // Against a bound of 3 the move is refused even though the PARENT sits at depth 1
    // and the MOVER is a root at depth 0: neither endpoint breaches the bound on its
    // own, and a check that looked only at the new edge would admit this.
    let refused = reparent(&db, &env, scope, &org, &mover, Some(&chain[1]), 3).await;
    assert!(
        matches!(
            refused,
            Err(StoreError::OrgGroupDepthExceeded {
                max: 3,
                attempted: 4
            })
        ),
        "moving a subtree of height 2 under a depth-1 parent must be refused against a \
         bound of 3: {refused:?}"
    );
    // Nothing moved.
    assert_eq!(
        db.control_store()
            .management()
            .org_groups(scope)
            .get(&mover)
            .await
            .expect("the mover survives")
            .parent_id,
        None,
        "a refused reparent must leave the group where it was"
    );

    // Against a bound of 4 the same move lands EXACTLY on the boundary and is
    // admitted, so the refusal above is about the arithmetic and not about subtree
    // moves being rejected wholesale.
    reparent(&db, &env, scope, &org, &mover, Some(&chain[1]), 4)
        .await
        .expect("the same move must be admitted when the bound accommodates it");
    assert_acyclic(&db, scope, &org).await;

    // A bound of ZERO means FLAT GROUPS ONLY, not unlimited: any parent at all is one
    // edge too many. Creating a ROOT under the same bound still works, so zero does
    // not disable groups.
    let flat_root = create_group_with(&db, &env, scope, &org, "flat-root", None, 0)
        .await
        .expect("a root group is always admissible, even at a bound of zero");
    // The parent here is a ROOT, so the ancestor walk does not saturate and the
    // reported depth is EXACT: one edge, against a bound of zero.
    let flat = create_group_with(&db, &env, scope, &org, "flat-child", Some(&flat_root), 0).await;
    assert!(
        matches!(
            flat,
            Err(StoreError::OrgGroupDepthExceeded {
                max: 0,
                attempted: 1
            })
        ),
        "one edge against a bound of zero must be refused with an attempted depth of \
         exactly 1: {flat:?}"
    );
    // Under a DEEP parent the same bound still refuses, but the reported depth is the
    // SATURATED figure rather than the true one: the walk stops one level past the
    // bound by design, so `attempted` is a floor on how deep the write would have
    // gone, never an exact reading. Documented, and pinned here so a later reader does
    // not take `attempted` for a precise measurement of an over-deep tree.
    let saturated = create_group_with(
        &db,
        &env,
        scope,
        &org,
        "flat-deep-child",
        Some(&at_bound),
        0,
    )
    .await;
    assert!(
        matches!(
            saturated,
            Err(StoreError::OrgGroupDepthExceeded {
                max: 0,
                attempted
            }) if attempted >= 1
        ),
        "a saturated walk must still refuse, reporting a floor on the depth: {saturated:?}"
    );

    // A caller asking for a bound ABOVE the ceiling is CLAMPED, not obeyed: the store
    // mirrors the config ceiling and clamps independently, so even a miswired caller
    // cannot put an unbounded ancestor walk on the token-issuance path. Build a chain
    // exactly as deep as the ceiling and prove one more level is refused however
    // large a bound is asked for.
    let ceiling = usize::try_from(ORG_GROUP_MAX_DEPTH_CEILING).expect("ceiling fits usize");
    let mut tip = create_group_with(&db, &env, scope, &org, "deep-0", None, u32::MAX)
        .await
        .expect("deep root");
    for index in 1..=ceiling {
        tip = create_group_with(
            &db,
            &env,
            scope,
            &org,
            &format!("deep-{index}"),
            Some(&tip),
            u32::MAX,
        )
        .await
        .unwrap_or_else(|error| panic!("deep link {index} must be creatable: {error:?}"));
    }
    let past_ceiling =
        create_group_with(&db, &env, scope, &org, "past-ceiling", Some(&tip), u32::MAX).await;
    assert!(
        matches!(
            past_ceiling,
            Err(StoreError::OrgGroupDepthExceeded { max, .. })
                if max == ORG_GROUP_MAX_DEPTH_CEILING
        ),
        "a request for u32::MAX must be clamped to the store's ceiling: {past_ceiling:?}"
    );
}

#[tokio::test]
async fn deleting_a_mid_tree_group_detaches_its_subtree_rather_than_cascading() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let org = create_org(&db, &env, scope, "Globex").await;
    let chain = build_chain(&db, &env, scope, &org, 3).await;
    let (root, mid, leaf) = (chain[0], chain[1], chain[2]);

    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_groups(scope)
        .delete(&env, &org, &mid)
        .await
        .expect("delete the middle group");

    // The leaf SURVIVES and keeps its stored pointer at the dead row: the delete
    // neither cascades nor rewrites. Every hierarchy walk filters deleted rows, so
    // the leaf now behaves as a root. Documented behavior, pinned here because it is
    // exactly the kind of thing a later reader would "fix" into a cascade.
    let survivor = control
        .management()
        .org_groups(scope)
        .get(&leaf)
        .await
        .expect("the leaf survives its parent's deletion");
    assert_eq!(survivor.parent_id, Some(mid));

    // Detaching can only ever DECREASE a descendant's depth, so a subtree left
    // hanging off a dead parent can still be extended under a tight bound: with the
    // middle group gone the leaf is at effective depth 0, and a child of it is
    // admissible against a bound of 1 that its ORIGINAL depth of 2 would have failed.
    create_group_with(&db, &env, scope, &org, "regrown", Some(&leaf), 1)
        .await
        .expect("a detached subtree is measured from its live root");
    assert!(
        control
            .management()
            .org_groups(scope)
            .get(&root)
            .await
            .is_ok(),
        "the root is untouched by a delete further down"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn absent_deleted_foreign_org_and_foreign_scope_groups_are_all_the_same_not_found() {
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

    let live = create_group(&db, &env, scope_a, &org_a, "engineering", None)
        .await
        .expect("live group");
    let sibling = create_group(&db, &env, scope_a, &org_a, "sales", None)
        .await
        .expect("sibling group");
    let deleted = create_group(&db, &env, scope_a, &org_a, "retired", None)
        .await
        .expect("group to delete");
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .org_groups(scope_a)
        .delete(&env, &org_a, &deleted)
        .await
        .expect("delete");
    // A LIVE group of ANOTHER organization in the SAME scope. This is the case
    // row-level security cannot fence, so the repository must.
    let in_other_org = create_group(&db, &env, scope_a, &other_org_a, "outsider", None)
        .await
        .expect("group in a sibling organization");
    let in_tenant_b = create_group(&db, &env, scope_b, &org_b, "engineering", None)
        .await
        .expect("group in tenant B");
    let in_env_a2 = create_group(&db, &env, scope_a2, &org_a2, "engineering", None)
        .await
        .expect("group in environment A2");
    let absent = OrgGroupId::generate(&env, &scope_a);

    let groups_a = control.management().org_groups(scope_a);

    // Reads: absent, deleted, and both foreign scopes are one error.
    assert!(matches!(
        groups_a.get(&absent).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        groups_a.get(&deleted).await,
        Err(StoreError::NotFound)
    ));
    for foreign in [&in_tenant_b, &in_env_a2] {
        assert!(matches!(
            groups_a.parse_id(&foreign.to_string()),
            Err(StoreError::NotFound)
        ));
        assert!(matches!(
            groups_a.get(foreign).await,
            Err(StoreError::NotFound)
        ));
    }
    assert!(matches!(
        groups_a.get_in_org(&other_org_a, &live).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(
        groups_a
            .get_in_org(&org_a, &live)
            .await
            .expect("the group resolves under its own organization")
            .id,
        live
    );
    assert!(
        groups_a
            .list_for_org(&org_b, 50, None)
            .await
            .expect("list for a foreign-scope org")
            .is_empty()
    );

    // THE LOAD-BEARING PART. Every hierarchy write must answer the SAME not-found for
    // an unusable id, and must NEVER answer a typed cycle or depth error, because
    // those are informative: distinguishing them would turn the structural errors
    // into an existence and STRUCTURE oracle over another organization's group graph
    // (a caller could probe foreign ids and learn which are ancestors of which).
    //
    // Each row is a REPARENT with one unusable endpoint, and each must be NotFound.
    let unusable_parents: Vec<(&str, OrgGroupId)> = vec![
        ("absent", absent),
        ("soft-deleted", deleted),
        ("another organization in the same scope", in_other_org),
        ("another tenant", in_tenant_b),
        ("another environment", in_env_a2),
    ];
    for (case, parent) in &unusable_parents {
        let result = reparent(
            &db,
            &env,
            scope_a,
            &org_a,
            &live,
            Some(parent),
            DEFAULT_DEPTH,
        )
        .await;
        assert!(
            matches!(result, Err(StoreError::NotFound)),
            "a {case} parent must be the uniform not-found, never a typed structural \
             error: {result:?}"
        );
    }
    // And with the unusable id as the SUBJECT rather than the parent.
    for (case, subject) in &unusable_parents {
        let result = reparent(
            &db,
            &env,
            scope_a,
            &org_a,
            subject,
            Some(&sibling),
            DEFAULT_DEPTH,
        )
        .await;
        assert!(
            matches!(result, Err(StoreError::NotFound)),
            "a {case} subject must be the uniform not-found: {result:?}"
        );
        let cleared = reparent(&db, &env, scope_a, &org_a, subject, None, DEFAULT_DEPTH).await;
        assert!(
            matches!(cleared, Err(StoreError::NotFound)),
            "clearing the parent of a {case} subject must be the uniform not-found: \
             {cleared:?}"
        );
    }
    // A create naming an unusable parent, likewise.
    for (case, parent) in &unusable_parents {
        let result = create_group(&db, &env, scope_a, &org_a, "probe", Some(parent)).await;
        assert!(
            matches!(result, Err(StoreError::NotFound)),
            "creating under a {case} parent must be the uniform not-found: {result:?}"
        );
    }
    // A delete under the WRONG organization is likewise not found, and the victim
    // survives: the nested path can never be used to delete across organizations.
    assert!(matches!(
        control
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .org_groups(scope_a)
            .delete(&env, &other_org_a, &live)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(
        groups_a.get(&live).await.is_ok(),
        "a cross-organization delete attempt must not touch the victim"
    );
    // Tenant B's group survives every probe above.
    assert!(
        control
            .management()
            .org_groups(scope_b)
            .get(&in_tenant_b)
            .await
            .is_ok()
    );

    // A create that names a foreign-scope organization is refused before any
    // statement runs.
    assert!(matches!(
        create_group(&db, &env, scope_a, &org_b, "smuggled", None).await,
        Err(StoreError::NotFound)
    ));

    // A ROLE id is not a group id, even in the right scope: roles and groups are
    // sibling resources of one issue, and a reparent that accepted a role id as a
    // parent would be a type confusion inside the hierarchy itself.
    let role_shaped = OrgRoleId::generate(&env, &scope_a).to_string();
    assert!(matches!(
        groups_a.parse_id(&role_shaped),
        Err(StoreError::NotFound)
    ));
}

/// Concurrent reparents that would JOINTLY close a cycle cannot both commit.
///
/// This is the test the advisory lock exists for, and the only one that can observe
/// its absence. `begin_scoped` pins READ COMMITTED, so without the lock two
/// transactions reparenting `A` under `B` and `B` under `A` each read an acyclic
/// graph, each pass the cycle check, and both commit: a cycle no single transaction
/// could observe, which nothing reports and which is discovered later only when a
/// resolution walk saturates its depth guard. Every sequential assertion in this file
/// stays green in that world.
///
/// The shape is the one the role suite uses for its slug race, widened: N tasks race
/// to close a cycle around one pair, exactly one may win, and the stored graph must
/// be a forest afterwards. Rounds are repeated because a lost race is timing
/// dependent and one round can miss the interleaving.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_reparents_that_would_close_a_cycle_never_both_commit() {
    const RACERS: usize = 8;
    const ROUNDS: usize = 12;

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    // One shared, wide CONTROL pool so the storm actually overlaps rather than
    // queueing on connections.
    let pool_size = u32::try_from(RACERS).expect("racer count fits u32") + 4;
    let store: Store = db.control_store_with_pool(pool_size).await;

    let org = create_org(&db, &env, scope, "Globex").await;

    let mut wins_total = 0_usize;
    for round in 0..ROUNDS {
        // Two independent roots per round. Every racer tries to make one the parent
        // of the other; the two directions together are a cycle.
        let left = create_group(&db, &env, scope, &org, &format!("left-{round}"), None)
            .await
            .expect("left root");
        let right = create_group(&db, &env, scope, &org, &format!("right-{round}"), None)
            .await
            .expect("right root");

        let mut tasks = tokio::task::JoinSet::new();
        for racer in 0..RACERS {
            let store = store.clone();
            // Half the racers push left under right, half the other way. Any two
            // opposing racers that both committed would form a two-node cycle.
            let (subject, parent) = if racer % 2 == 0 {
                (left, right)
            } else {
                (right, left)
            };
            tasks.spawn(async move {
                let env = Env::system();
                store
                    .management()
                    .acting(
                        ActorRef::service(ServiceId::generate(&env)),
                        CorrelationId::generate(&env),
                    )
                    .org_groups(scope)
                    .reparent(&env, &org, &subject, Some(&parent), DEFAULT_DEPTH)
                    .await
            });
        }

        // Collect every outcome BEFORE asserting anything, so the structural
        // invariants below are checked against the settled graph first and report the
        // graph itself. Classifying the outcomes first would surface a broken lock as
        // "a racer failed for an unexpected reason", which is a symptom, not the
        // defect.
        let mut outcomes: Vec<Result<(), StoreError>> = Vec::with_capacity(RACERS);
        while let Some(joined) = tasks.join_next().await {
            outcomes.push(joined.expect("a storm task panicked"));
        }

        // The invariant, asserted on the RAW stored rows rather than through the
        // repository: whatever the interleaving, the result is a forest.
        assert_acyclic(&db, scope, &org).await;

        // At most ONE direction can be in force. Both edges present is the exact
        // defect this test exists to catch.
        let edges = stored_edges(&db, scope, &org).await;
        let parent_of = |id: &OrgGroupId| -> Option<String> {
            edges
                .iter()
                .find(|(node, _)| node == &id.to_string())
                .and_then(|(_, parent)| parent.clone())
        };
        let left_under_right = parent_of(&left) == Some(right.to_string());
        let right_under_left = parent_of(&right) == Some(left.to_string());
        assert!(
            !(left_under_right && right_under_left),
            "round {round}: both directions committed, which is a two-node cycle no \
             single transaction could observe; edges={edges:?}"
        );
        // Every racer either won or was refused for the CYCLE, and for nothing else.
        // A depth refusal here would mean a cycle HAD formed and the ancestor walk
        // merely saturated against it, which is the same defect wearing a different
        // error.
        let mut wins = 0_usize;
        for outcome in &outcomes {
            match outcome {
                Ok(()) => wins += 1,
                Err(StoreError::OrgGroupCycle) => {}
                Err(other) => panic!(
                    "round {round}: a racer failed for a reason other than the cycle \
                     refusal, which means the graph was not what any single transaction \
                     could observe: {other:?}; edges={edges:?}"
                ),
            }
        }
        wins_total += wins;
        // Non-vacuity: the round has to have RACED. Zero wins would mean the fixture
        // never admitted anything, and RACERS wins would mean nothing was refused, so
        // either extreme means the test is not observing a contended reparent.
        assert!(
            (1..RACERS).contains(&wins),
            "round {round}: expected a contended outcome, got {wins} wins out of {RACERS}"
        );
    }
    assert!(
        wins_total >= ROUNDS,
        "the storm never admitted a reparent, so it is not exercising the winning path"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn rls_hides_another_scopes_groups_from_the_control_role_and_refuses_forging_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    let org_b = create_org(&db, &env, scope_b, "Beta").await;
    create_group(&db, &env, scope_b, &org_b, "engineering", None)
        .await
        .expect("group in scope B");

    let pool = db.control_pool();

    // Precondition: the low-privilege CONTROL role, not a superuser.
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
    let unset: i64 = sqlx::query("SELECT count(*) AS c FROM org_groups")
        .fetch_one(pool)
        .await
        .expect("count with unset scope")
        .get("c");
    assert_eq!(unset, 0, "an unset scope must see no groups");

    {
        let mut tx = pool.begin().await.expect("begin as scope A");
        bind_scope(
            &mut tx,
            &scope_a.tenant().to_string(),
            &scope_a.environment().to_string(),
        )
        .await;
        // 2. Mis-scoped session with the app-layer filter SUBVERTED.
        let leaked: i64 = sqlx::query(
            "SELECT count(*) AS c FROM org_groups WHERE tenant_id = $1 AND environment_id = $2",
        )
        .bind(scope_b.tenant().to_string())
        .bind(scope_b.environment().to_string())
        .fetch_one(&mut *tx)
        .await
        .expect("cross-scope count")
        .get("c");
        assert_eq!(
            leaked, 0,
            "RLS must hide scope B groups from a scope A session even with the filter bypassed"
        );

        // 3. And the same for a RECURSIVE walk, which is the shape the hierarchy
        //    check runs. A recursive traversal is exactly where a policy that applied
        //    only to the seed and not to the recursive term would leak: the walk would
        //    start empty in this scope but a corrupt parent pointer into another
        //    tenant would be followed. The policy applies to every arm, so it cannot.
        let reachable: i64 = sqlx::query(
            "WITH RECURSIVE walk AS ( \
                 SELECT id, parent_id FROM org_groups WHERE tenant_id = $1 \
                 UNION ALL \
                 SELECT g.id, g.parent_id FROM org_groups g JOIN walk w ON g.id = w.parent_id \
             ) SELECT count(*) AS c FROM walk",
        )
        .bind(scope_b.tenant().to_string())
        .fetch_one(&mut *tx)
        .await
        .expect("recursive cross-scope walk")
        .get("c");
        assert_eq!(
            reachable, 0,
            "a recursive walk must not reach another scope's groups"
        );

        // 4. Write-side isolation: a scope A session cannot rename or REPARENT scope
        //    B's group (the USING clause hides it) nor INSERT one claiming scope B
        //    (the WITH CHECK rejects it).
        let updated =
            sqlx::query("UPDATE org_groups SET display_name = 'hijacked' WHERE tenant_id = $1")
                .bind(scope_b.tenant().to_string())
                .execute(&mut *tx)
                .await
                .expect("update runs")
                .rows_affected();
        assert_eq!(
            updated, 0,
            "RLS must hide scope B rows from a scope A UPDATE"
        );
        let moved = sqlx::query("UPDATE org_groups SET parent_id = NULL WHERE tenant_id = $1")
            .bind(scope_b.tenant().to_string())
            .execute(&mut *tx)
            .await
            .expect("reparent runs")
            .rows_affected();
        assert_eq!(
            moved, 0,
            "RLS must hide scope B rows from a scope A REPARENT"
        );

        let forged = OrgGroupId::generate(&env, &scope_b).to_string();
        let insert = sqlx::query(
            "INSERT INTO org_groups \
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
            "RLS WITH CHECK must reject writing another scope's group"
        );
        let _ = tx.rollback().await;
    }

    // 5. Positive control: bound to B, the same role sees exactly B's row.
    {
        let mut tx = pool.begin().await.expect("begin as scope B");
        bind_scope(
            &mut tx,
            &scope_b.tenant().to_string(),
            &scope_b.environment().to_string(),
        )
        .await;
        let visible: i64 = sqlx::query("SELECT count(*) AS c FROM org_groups")
            .fetch_one(&mut *tx)
            .await
            .expect("count in B")
            .get("c");
        assert_eq!(visible, 1, "scope B sees its own group");
        tx.commit().await.expect("commit B read");
    }
}

#[tokio::test]
async fn the_data_plane_can_read_a_group_but_never_write_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let org = create_org(&db, &env, scope, "Globex").await;
    let root = create_group(&db, &env, scope, &org, "all-staff", None)
        .await
        .expect("root");
    let child = create_group(&db, &env, scope, &org, "engineering", Some(&root))
        .await
        .expect("child");

    // The DATA plane reads a group through the scoped store: the grant the ancestor
    // walk on the token-issuance path depends on. Without it that path would fail
    // with SQLSTATE 42501, which is why 0087 grants it in the creating migration.
    let read = db
        .store()
        .scoped(scope)
        .org_groups()
        .get(&child)
        .await
        .expect("the data plane can READ a group");
    assert_eq!(read.slug, "engineering");
    assert_eq!(
        read.parent_id,
        Some(root),
        "the data plane can see the parent pointer it will walk"
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

    // Every MUTATING statement is refused as insufficient privilege.
    assert_denied_in_scope(pool, &tenant, &environment, &org, "DELETE FROM org_groups").await;
    assert_denied_in_scope(
        pool,
        &tenant,
        &environment,
        &org,
        "UPDATE org_groups SET display_name = 'tampered'",
    )
    .await;
    // Reparenting is the one that matters most on this plane: a data plane that could
    // rewrite parent_id could reshape the hierarchy that decides which roles a token
    // carries.
    assert_denied_in_scope(
        pool,
        &tenant,
        &environment,
        &org,
        "UPDATE org_groups SET parent_id = NULL",
    )
    .await;
    assert_denied_in_scope(
        pool,
        &tenant,
        &environment,
        &org,
        "UPDATE org_groups SET deleted_at = now()",
    )
    .await;
    // The forge probe writes a row that is valid in EVERY respect but the grant: the
    // session's own scope, a real organization of that scope, and a slug and display
    // name the CHECKs accept. If the data plane ever gained INSERT, whether
    // table-wide or column-scoped, this statement would SUCCEED rather than fail with
    // a different error, so the assertion cannot be satisfied by a refusal that has
    // nothing to do with privilege. Postgres reports a policy refusal and a privilege
    // refusal under the SAME SQLSTATE, which is exactly the trap this avoids.
    assert_denied_in_scope(
        pool,
        &tenant,
        &environment,
        &org,
        "INSERT INTO org_groups (id, tenant_id, environment_id, organization_id, slug, \
         display_name) VALUES ('grp_probe', $1, $2, $3, 'probe', 'probe')",
    )
    .await;

    // The slug is immutable by GRANT on BOTH roles: not even the control plane, which
    // owns the whole group lifecycle, may rewrite the stable name.
    assert_denied_in_scope(
        db.control_pool(),
        &tenant,
        &environment,
        &org,
        "UPDATE org_groups SET slug = 'tampered'",
    )
    .await;
    // Nor may either role move a group between organizations in place, which is what
    // keeps the same-organization containment the hierarchy check enforces from being
    // undone after the fact.
    assert_denied_in_scope(
        db.control_pool(),
        &tenant,
        &environment,
        &org,
        "UPDATE org_groups SET organization_id = $3",
    )
    .await;
    // Positive control: the control role's column-scoped rename and reparent DO
    // succeed, so the denials above are about those columns and not about the role's
    // access generally.
    {
        let mut tx = db.control_pool().begin().await.expect("begin control tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        sqlx::query("UPDATE org_groups SET display_name = 'renamed', parent_id = NULL")
            .execute(&mut *tx)
            .await
            .expect("the control role holds column-scoped UPDATE on display_name and parent_id");
        let _ = tx.rollback().await;
    }
}

/// Run `statement` in a scoped transaction on `pool` and assert it is refused as
/// insufficient privilege.
///
/// A statement carrying placeholders binds `$1` and `$2` to the session's OWN
/// (tenant, environment) and `$3` to `organization`, so a probe INSERT writes a row
/// that SATISFIES the row-level-security WITH CHECK (and the organization foreign
/// key), leaving the missing GRANT as the only thing that can refuse it. That
/// distinction is the whole point of the probe: Postgres reports a policy refusal
/// and a privilege refusal under the SAME SQLSTATE (42501), so a probe writing
/// literal foreign scope values would be rejected by the policy no matter how far
/// the grant was widened, and could never observe the grant at all.
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
    if statement.contains("$1") || statement.contains("$3") {
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
