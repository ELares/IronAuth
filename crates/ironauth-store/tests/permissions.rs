// SPDX-License-Identifier: MIT OR Apache-2.0

//! The permission vocabulary (issue #98, store PRs 1 and 2), over a real database
//! (`DATABASE_URL`).
//!
//! Pins the vocabulary half of the M10 permission model at the persistence layer: a
//! permission is defined in an ENVIRONMENT and carries no organization; the read
//! surfaces are a uniform not-found for an absent, a deleted, and a foreign-scope
//! permission alike (the anti-oracle discipline); a permission and an entitlement may
//! share a slug because `kind` is part of the live uniqueness key (the issue #103
//! headroom, exercised rather than merely declared, in BOTH directions: the shared
//! slug is free across kinds and taken within one); forced row-level security hides
//! another scope's vocabulary even with the app-layer filter subverted AND refuses to
//! write into another scope, with the TENANT and the ENVIRONMENT each the deciding
//! dimension in probes of its own; the repository's own scope conjuncts fence
//! independently of that policy; the `(created_at, id)` page cursor stays total
//! across a tied `created_at`; the grants are least-privilege (the data plane is read
//! only, and `slug` and `kind` are immutable by GRANT on BOTH roles); an unrecognized
//! stored `kind` fails the read CLOSED rather than defaulting into the kind a token
//! claim selects; and there is NO cap on how many permissions an environment may
//! define.
//!
//! PR 2 adds the WRITE half and everything that hangs off it: the create, relabel,
//! and soft delete each write their audit row (`permission.create`,
//! `permission.update`, `permission.delete`) in the SAME transaction as the mutation,
//! in both directions (a failed mutation leaves no audit row, and a failed audit
//! insert leaves no mutation); the create BINDS the `kind` rather than inheriting the
//! column default, proved where the two disagree by moving the default to
//! `'entitlement'` first, since the shipped default and the bind otherwise agree on
//! every row this file writes; a relabel can move neither the `slug` nor the `kind`,
//! which is enforced by a COLUMN-scoped grant rather than by convention, swept here
//! against `pg_attribute` so a widened grant is caught by exact set equality; every
//! mutation answers absent, soft-deleted, another tenant's, and the SAME TENANT'S
//! OTHER ENVIRONMENT'S with one indistinguishable not-found; a deleted slug is freed
//! and re-using it mints a FRESH id rather than reviving the dead row; and the
//! covenant is proved on the write path, which is where a cap would have to live.
//!
//! Two ways of planting a row coexist here on purpose. `define` goes through the
//! audited write repository and is the production path. `plant` and `plant_at` use
//! direct SQL through the CONTROL pool, under the same role, the same bound scope,
//! and the same grants, and are kept for the two things the repository cannot do: it
//! never writes `kind = 'entitlement'` (issue #98 defines no entitlements, which
//! migration 0091's header states as a property of this issue), and it wraps the
//! driver error, while several assertions here need the CONSTRAINT NAME so that a
//! refusal is pinned to the rule that was meant to refuse rather than to something
//! else that happened to fail.
//!
//! Cross-tenant and cross-environment isolation is additionally exercised through the
//! registered IDOR probes (`crates/ironauth-admin/tests/idor.rs`), which now include
//! the mutating `permissions.delete`, and the CHECK versus Rust-validator agreement
//! through the parity oracle
//! (`crates/ironauth-admin/tests/permission_slug_parity.rs`).

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, CursorPosition, NewPermission, PermissionEntryKind, PermissionId,
    Scope, ServiceId, StoreError,
};
use sqlx::{PgPool, Row};

/// The Postgres "insufficient privilege" SQLSTATE.
const INSUFFICIENT_PRIVILEGE: &str = "42501";
/// The Postgres "unique violation" SQLSTATE.
const UNIQUE_VIOLATION: &str = "23505";
/// The Postgres "check violation" SQLSTATE.
const CHECK_VIOLATION: &str = "23514";

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

/// Define a permission through the CONTROL pool, at an explicit creation time so a
/// test can pin several rows to the same instant and exercise the `(created_at, id)`
/// cursor tiebreak, which
/// [`the_list_cursor_stays_total_and_stable_across_a_tied_created_at`] does. The
/// instant is supplied by the caller (a literal, or a reading of the env clock seam);
/// nothing here reads a wall clock of its own.
async fn plant_at(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    kind: PermissionEntryKind,
    slug: &str,
    display_name: &str,
    created_at_micros: i64,
) -> Result<PermissionId, sqlx::Error> {
    let id = PermissionId::generate(env, &scope);
    let mut tx = db.control_pool().begin().await.expect("begin plant");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    let result = sqlx::query(
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
    .bind(display_name)
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

/// Define a permission of the ordinary kind at a monotonically increasing instant.
async fn plant(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    slug: &str,
    display_name: &str,
    at: i64,
) -> Result<PermissionId, sqlx::Error> {
    plant_at(
        db,
        env,
        scope,
        PermissionEntryKind::Permission,
        slug,
        display_name,
        at,
    )
    .await
}

fn actor(env: &Env) -> ActorRef {
    ActorRef::service(ServiceId::generate(env))
}

/// Define a permission through the AUDITED WRITE repository: the production path,
/// which writes the row and its `permission.create` audit row in one transaction.
///
/// The creation instant is supplied by the caller so a test can pin rows to chosen
/// times; nothing here reads a wall clock of its own.
async fn define(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    slug: &str,
    display_name: &str,
    created_at_micros: i64,
) -> Result<PermissionId, StoreError> {
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
                display_name,
                metadata: None,
            },
            created_at_micros,
            None,
        )
        .await
        .map(|()| id)
}

/// Relabel a permission through the audited write repository.
async fn relabel(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    id: &PermissionId,
    display_name: Option<&str>,
    metadata: Option<&serde_json::Value>,
) -> Result<(), StoreError> {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .permissions(scope)
        .update(env, id, display_name, metadata)
        .await
}

/// Soft-delete a permission through the audited write repository.
async fn remove(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    id: &PermissionId,
) -> Result<(), StoreError> {
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .permissions(scope)
        .delete(env, id)
        .await
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

/// Every `permission.*` audit action anywhere in the database, regardless of scope
/// and regardless of target, read through the OWNER pool.
///
/// The scope-blind counterpart of [`audit_actions`]. A per-target read cannot see a
/// PHANTOM audit row written against some other id, nor one written into another
/// scope, and both are exactly what a broken failure path would leave behind.
async fn all_permission_audit_actions(db: &TestDatabase) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT action FROM audit_log WHERE action LIKE 'permission.%' \
         ORDER BY occurred_at, id",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("read permission audit rows");
    rows.iter()
        .map(|row| row.get::<String, _>("action"))
        .collect()
}

/// Count rows of `permissions` matching `predicate`, through the OWNER pool so
/// row-level security hides nothing: a row written into another scope still counts.
async fn count_permissions(db: &TestDatabase, predicate: &str) -> i64 {
    // `predicate` is a fixed test-local literal, never caller input.
    sqlx::query(&format!(
        "SELECT count(*) AS c FROM permissions WHERE {predicate}"
    ))
    .fetch_one(db.owner_pool())
    .await
    .expect("count permissions")
    .get("c")
}

/// Soft-delete a permission through the CONTROL pool's column-scoped UPDATE grant.
async fn soft_delete(db: &TestDatabase, scope: Scope, id: &PermissionId) {
    let mut tx = db.control_pool().begin().await.expect("begin delete");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    let affected = sqlx::query("UPDATE permissions SET deleted_at = now() WHERE id = $1")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await
        .expect("the control plane holds the soft-delete UPDATE grant")
        .rows_affected();
    assert_eq!(affected, 1, "the soft delete must reach exactly one row");
    tx.commit().await.expect("commit delete");
}

#[tokio::test]
async fn a_permission_round_trips_through_the_read_repository_on_both_planes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let id = plant(
        &db,
        &env,
        scope,
        "billing.invoice.read",
        "Read invoices",
        1_000,
    )
    .await
    .expect("plant a permission");

    // The CONTROL plane reads it by id.
    let control = db.control_store().management().permissions(scope);
    let record = control.get(&id).await.expect("control-plane get");
    assert_eq!(record.id, id);
    assert_eq!(record.kind, PermissionEntryKind::Permission);
    assert_eq!(record.slug, "billing.invoice.read");
    assert_eq!(record.display_name, "Read invoices");
    assert_eq!(record.metadata, serde_json::json!({}));
    assert_eq!(record.created_at_unix_micros, 1_000);
    assert_eq!(record.updated_at_unix_micros, 1_000);

    // The same row by its (kind, slug) address.
    let by_slug = control
        .get_by_slug(PermissionEntryKind::Permission, "billing.invoice.read")
        .await
        .expect("control-plane get_by_slug");
    assert_eq!(by_slug, record);

    // The DATA plane reads it too: the grant migration 0091 makes in the creating
    // migration, which the token-issuance resolution depends on. Without it
    // that path would fail with SQLSTATE 42501.
    let data = db.store().scoped(scope).permissions();
    assert_eq!(
        data.get(&id).await.expect("the data plane can READ"),
        record
    );

    // And it lists.
    let listed = control
        .list(PermissionEntryKind::Permission, 50, None)
        .await
        .expect("list");
    assert_eq!(listed, vec![record]);
}

#[tokio::test]
async fn absent_deleted_and_foreign_scope_permissions_are_all_the_same_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    // A THIRD scope differing from A in the ENVIRONMENT ALONE. `seed_scope` mints a
    // NEW tenant on every call, so scope_a and scope_b differ in BOTH dimensions and
    // the tenant half of every fence decides every probe between them; a foreign
    // scope that differs only in the environment is the case that makes the
    // environment half deciding. This follows org_roles.rs case 4.
    let scope_a2 = Scope::new(
        scope_a.tenant(),
        db.seed_environment(&env, scope_a.tenant()).await,
    );

    let live = plant(&db, &env, scope_a, "billing.read", "Read billing", 1_000)
        .await
        .expect("plant live");
    let deleted = plant(&db, &env, scope_a, "billing.write", "Write billing", 2_000)
        .await
        .expect("plant to delete");
    soft_delete(&db, scope_a, &deleted).await;
    let foreign = plant(&db, &env, scope_b, "billing.read", "Read billing", 3_000)
        .await
        .expect("plant in scope B");
    let other_environment = plant(&db, &env, scope_a2, "staging.read", "Read staging", 4_000)
        .await
        .expect("plant in the same tenant's OTHER environment");

    let repo = db.control_store().management().permissions(scope_a);

    // Positive control first, so a repository that answered NotFound to everything
    // could not pass this test.
    assert!(repo.get(&live).await.is_ok());

    // 1. Absent: a well-formed id in the caller's OWN scope that was never stored.
    let absent = PermissionId::generate(&env, &scope_a);
    assert!(matches!(repo.get(&absent).await, Err(StoreError::NotFound)));

    // 2. Soft-deleted: retained for the audit foreign key, invisible to every read.
    assert!(matches!(
        repo.get(&deleted).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        repo.get_by_slug(PermissionEntryKind::Permission, "billing.write")
            .await,
        Err(StoreError::NotFound)
    ));

    // 3. Foreign TENANT and 4. foreign ENVIRONMENT of the SAME tenant: the typed id
    //    fails to parse in scope before any query runs, and the raw string is refused
    //    by the same not-found rather than a distinct parse error a caller could tell
    //    apart. Both dimensions are probed, so neither is decided only by the other.
    for foreign in [&foreign, &other_environment] {
        assert!(matches!(
            repo.parse_id(&foreign.to_string()),
            Err(StoreError::NotFound)
        ));
        assert!(matches!(repo.get(foreign).await, Err(StoreError::NotFound)));
    }
    // The other environment's SLUG is the uniform not-found too, which is the
    // (kind, slug) address's version of the same fence. Two layers stand behind this
    // one: the repository's own `environment_id` conjunct and, behind it, the
    // in-scope id decode, so this assertion alone cannot tell which refused. The
    // repository conjunct is pinned on its own by
    // `the_repository_fences_by_environment_even_when_the_policy_no_longer_does`.
    assert!(matches!(
        repo.get_by_slug(PermissionEntryKind::Permission, "staging.read")
            .await,
        Err(StoreError::NotFound)
    ));

    // 5. A malformed id is the same answer again.
    assert!(matches!(
        repo.parse_id("prm_not-base64-!!"),
        Err(StoreError::NotFound)
    ));

    // 6. The (kind, slug) address is not an oracle either: the RIGHT slug under the
    //    WRONG kind is the uniform not-found, never the other row.
    assert!(matches!(
        repo.get_by_slug(PermissionEntryKind::Entitlement, "billing.read")
            .await,
        Err(StoreError::NotFound)
    ));

    // 7. Neither foreign row reaches a scope A LIST, which is what proves the list is
    //    fenced and not merely the point read. Scope B's row is fenced by the tenant
    //    and scope A2's by the environment, so one page proves both.
    let listed = repo
        .list(PermissionEntryKind::Permission, 50, None)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1, "scope A sees only its own live permission");
    assert_eq!(listed[0].id, live);
}

#[tokio::test]
async fn a_permission_and_an_entitlement_may_share_one_slug() {
    // The issue #103 headroom, exercised rather than declared: `kind` is part of the
    // live uniqueness key, so `plan.enterprise` may exist as an entitlement while a
    // permission of the same slug exists independently. If the unique index dropped
    // `kind`, the second plant below would be a 23505 and #103 would need a migration
    // on a table the token path reads.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let permission = plant_at(
        &db,
        &env,
        scope,
        PermissionEntryKind::Permission,
        "plan.enterprise",
        "Enterprise plan capability",
        1_000,
    )
    .await
    .expect("plant the permission");
    let entitlement = plant_at(
        &db,
        &env,
        scope,
        PermissionEntryKind::Entitlement,
        "plan.enterprise",
        "Enterprise plan entitlement",
        2_000,
    )
    .await
    .expect("the same slug is free under the other kind");
    assert_ne!(permission, entitlement);

    // The OTHER half of the same key, and the half nothing asserted before: two LIVE
    // ENTITLEMENTS may not share a slug either. Every live-uniqueness probe in this
    // file sat at `kind = 'permission'`, so narrowing the index predicate to
    // `WHERE deleted_at IS NULL AND kind = 'permission'` left this file and the
    // migration structure test green (`partial_unique_index_exists` reads only
    // `indpred IS NOT NULL` and `index_columns` only `indkey`; both are blind to a
    // narrowed predicate) while #103's entitlements would get no uniqueness at all:
    // `get_by_slug` would return an arbitrary duplicate and soft-deleting "the"
    // entitlement would leave a live twin still granting it.
    let duplicate = plant_at(
        &db,
        &env,
        scope,
        PermissionEntryKind::Entitlement,
        "plan.enterprise",
        "Duplicate entitlement",
        3_000,
    )
    .await
    .expect_err("a LIVE entitlement slug is taken too");
    let database_error = duplicate.as_database_error().expect("a database error");
    assert_eq!(database_error.code().as_deref(), Some(UNIQUE_VIOLATION));
    assert_eq!(
        database_error.constraint(),
        Some("permissions_kind_slug_live_uniq"),
        "the second live entitlement must be refused by the live-uniqueness index, \
         by name, and not by something else that happens to fail"
    );

    let repo = db.control_store().management().permissions(scope);
    assert_eq!(
        repo.get_by_slug(PermissionEntryKind::Permission, "plan.enterprise")
            .await
            .expect("the permission")
            .id,
        permission
    );
    assert_eq!(
        repo.get_by_slug(PermissionEntryKind::Entitlement, "plan.enterprise")
            .await
            .expect("the entitlement")
            .id,
        entitlement
    );

    // The LIST is kind-addressed too, so an entitlement can never arrive through a
    // caller that asked for permissions. That separation is what the
    // `kind = 'permission'` projection filter rests on.
    let permissions = repo
        .list(PermissionEntryKind::Permission, 50, None)
        .await
        .expect("list permissions");
    assert_eq!(permissions.len(), 1);
    assert_eq!(permissions[0].id, permission);
    let entitlements = repo
        .list(PermissionEntryKind::Entitlement, 50, None)
        .await
        .expect("list entitlements");
    assert_eq!(entitlements.len(), 1);
    assert_eq!(entitlements[0].id, entitlement);
}

#[tokio::test]
async fn a_live_slug_conflicts_while_a_deleted_slug_is_freed_for_a_fresh_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let first = plant(&db, &env, scope, "billing.read", "Read billing", 1_000)
        .await
        .expect("plant the first");

    // A second LIVE row with the same (kind, slug) is refused by the partial unique
    // index, which is what makes the name unambiguous while it is in use.
    let conflict = plant(&db, &env, scope, "billing.read", "Duplicate", 2_000)
        .await
        .expect_err("a live slug is taken");
    assert_eq!(
        conflict
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some(UNIQUE_VIOLATION)
    );

    // Deleting frees the name, and the replacement is a FRESH row with a FRESH id.
    // It is NOT a revival: the mapping table hangs role grants off the id, so
    // reviving would silently restore every grant that pointed at the dead row.
    soft_delete(&db, scope, &first).await;
    let second = plant(&db, &env, scope, "billing.read", "Read billing", 3_000)
        .await
        .expect("a deleted slug is free again");
    assert_ne!(first, second, "a re-create must mint a fresh id");

    let repo = db.control_store().management().permissions(scope);
    assert_eq!(
        repo.get_by_slug(PermissionEntryKind::Permission, "billing.read")
            .await
            .expect("the live row")
            .id,
        second
    );
    assert!(matches!(repo.get(&first).await, Err(StoreError::NotFound)));
}

/// How many permissions the covenant test defines. Comfortably past any page size,
/// so the walk really pages, and past any number a cap would plausibly have chosen.
const DEFINED: usize = 250;

#[tokio::test]
async fn an_environment_may_define_unlimited_permissions_and_the_list_pages_them() {
    // The covenant, made mechanical: there is no count constraint, no quota, and no
    // gate. The page size is clamped like every management list, which is a
    // PAGINATION bound and not a cap on the set. The byte budget issue #98 ships
    // bounds ONE TOKEN and has nothing to do with this table.
    //
    // Every row here is written through the AUDITED WRITE REPOSITORY rather than with
    // direct SQL, because that is where a cap would have to live. A covenant test that
    // planted rows behind the repository would leave an advisory-lock-plus-COUNT gate
    // in `ActingPermissionRepo::create` completely unguarded, and that gate is the
    // exact shape this module uses elsewhere and the exact shape the covenant forbids
    // here.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    for index in 0..DEFINED {
        define(
            &db,
            &env,
            scope,
            &format!("billing.capability_{index}"),
            "Capability",
            1_000 + i64::try_from(index).expect("fits i64"),
        )
        .await
        .unwrap_or_else(|error| panic!("no cap may refuse permission {index}: {error:?}"));
    }

    // Every one of those writes was audited, and nothing else was. This is the
    // "no unaudited mutation" property at a scale where a path that skipped the
    // audited seam under some condition (a batch, a retry, a fast path) would show up
    // as a count mismatch rather than as a passing single-row test.
    assert_eq!(
        all_permission_audit_actions(&db).await,
        vec!["permission.create"; DEFINED],
        "each of the {DEFINED} defines writes exactly one create audit row"
    );

    let repo = db.control_store().management().permissions(scope);
    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<CursorPosition> = None;
    loop {
        let page = repo
            .list(PermissionEntryKind::Permission, 40, cursor.as_ref())
            .await
            .expect("page");
        if page.is_empty() {
            break;
        }
        let last = page.last().expect("nonempty");
        cursor = Some(CursorPosition {
            created_at_unix_micros: last.created_at_unix_micros,
            id: last.id.to_string(),
        });
        seen.extend(page.into_iter().map(|record| record.slug));
    }
    assert_eq!(
        seen.len(),
        DEFINED,
        "the walk must see every permission exactly once"
    );
    let unique: std::collections::BTreeSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), DEFINED, "no duplication across pages");
}

/// How many permissions the cursor-tiebreak test pins to ONE instant. Comfortably
/// more than the page size it is walked at, so a page boundary lands INSIDE the tie.
const TIED: usize = 10;

#[tokio::test]
async fn the_list_cursor_stays_total_and_stable_across_a_tied_created_at() {
    // Every row shares ONE creation instant, so `created_at` alone cannot order them
    // and the id half of the `(created_at, id)` pagination key is the only thing
    // making the order total. Nothing asserted that before: every other caller of
    // `plant_at` in this file passes a DISTINCT instant (1_000 / 2_000 / 3_000, and
    // the covenant walk's `1_000 + index`), so no two rows ever shared a created_at
    // and the id half of the key was exercised nowhere. Replacing the row comparison
    // `(created_at, id) > (ts, $5)` in `PermissionRepo::list` with a created_at-only
    // comparison left this whole file green while a walk of ten tied rows returned
    // four and silently lost six.
    //
    // Ties are not hypothetical here: `created_at` defaults to `now()`, which is the
    // TRANSACTION clock, so any multi-row define in one transaction produces
    // byte-identical timestamps, and this table's covenant invites unbounded
    // vocabularies. org_roles.rs ships exactly this walk; the SQL was copied here
    // without it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let tied = 7_000_i64;
    for index in 0..TIED {
        plant(
            &db,
            &env,
            scope,
            &format!("billing.tied_{index}"),
            "Tied",
            tied,
        )
        .await
        .unwrap_or_else(|error| panic!("permission {index} must be definable: {error:?}"));
    }

    let repo = db.control_store().management().permissions(scope);

    // The whole set in one unpaged read: the reference order, in the database's own
    // terms rather than any assumption about how Rust would sort the ids.
    let whole = repo
        .list(PermissionEntryKind::Permission, 50, None)
        .await
        .expect("unpaged list of the tied set");
    let reference: Vec<String> = whole.iter().map(|record| record.slug.clone()).collect();
    assert_eq!(reference.len(), TIED, "the whole tied set is listed");
    assert!(
        whole
            .iter()
            .all(|record| record.created_at_unix_micros == tied),
        "the tie is real: every row shares one creation time"
    );

    // Walk the same set in pages of four, TWICE. A page boundary lands inside the
    // tie, which is where a cursor keyed on created_at alone repeats or drops a row.
    for attempt in 0..2 {
        let mut walked: Vec<String> = Vec::new();
        let mut cursor: Option<CursorPosition> = None;
        loop {
            let page = repo
                .list(PermissionEntryKind::Permission, 4, cursor.as_ref())
                .await
                .expect("page of the tied set");
            let Some(last) = page.last() else {
                break;
            };
            cursor = Some(CursorPosition {
                created_at_unix_micros: last.created_at_unix_micros,
                id: last.id.to_string(),
            });
            walked.extend(page.iter().map(|record| record.slug.clone()));
        }
        assert_eq!(
            walked, reference,
            "walk {attempt}: paging a tied set must reproduce the unpaged order exactly, \
             with no row skipped and none served twice at a page boundary"
        );
        let unique: std::collections::BTreeSet<&String> = walked.iter().collect();
        assert_eq!(
            unique.len(),
            TIED,
            "walk {attempt}: every slug in the tied set is seen exactly once"
        );
    }
}

#[tokio::test]
async fn rls_hides_another_scopes_vocabulary_and_refuses_forging_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    // A THIRD scope differing from A in the ENVIRONMENT ALONE, and the reason it must
    // exist: `seed_scope` mints a NEW TENANT on every call, so scope_a and scope_b
    // differ in BOTH dimensions and the policy's TENANT conjunct decides every probe
    // between them regardless of what its environment conjunct says. Deleting
    // `AND environment_id = ...` from BOTH halves of the policy left this entire
    // file, the migration structure test, the IDOR probes, the parity oracle, and the
    // fuzz target green, while a session bound to (T, E1) could read, relabel,
    // soft-delete, and forge rows in (T, E2). This table's policy is THE COMPLETE
    // FENCE (there is no organization predicate repeated behind it), so half a fence
    // guarded by nothing is the whole exposure.
    let scope_a2 = Scope::new(
        scope_a.tenant(),
        db.seed_environment(&env, scope_a.tenant()).await,
    );

    plant(&db, &env, scope_b, "billing.read", "Read billing", 1_000)
        .await
        .expect("plant in scope B");
    plant(&db, &env, scope_a2, "staging.read", "Read staging", 2_000)
        .await
        .expect("plant in the same tenant's OTHER environment");

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

    // 1. Deny by default: no scope bound on the session, zero rows. This table is
    //    scoped to exactly (tenant, environment), so the policy IS its complete
    //    fence; there is no third dimension behind it.
    let unset: i64 = sqlx::query("SELECT count(*) AS c FROM permissions")
        .fetch_one(pool)
        .await
        .expect("count with unset scope")
        .get("c");
    assert_eq!(unset, 0, "an unset scope must see no permissions");

    // 2, 3, and 4. Read-side isolation with the app-layer filter subverted, both
    //    write-side probes, and the forge INSERT, run TWICE: once against a victim
    //    that differs in the TENANT and once against one that differs ONLY in the
    //    ENVIRONMENT. Each conjunct of the policy is therefore the deciding one in at
    //    least one probe, and neither can be deleted without a red test.
    for (victim, differing) in [(scope_b, "TENANT"), (scope_a2, "ENVIRONMENT")] {
        assert_fenced_from(pool, &env, scope_a, victim, differing).await;
    }

    // 4b. The WIDER, tenant-only spelling of the two write probes as well: not merely
    //     scope B's rows in scope B's environment, but every row of tenant B in ANY
    //     environment, is unreachable from a scope A session. Kept alongside the
    //     two-column probes above because it is the strictly larger claim for the
    //     tenant half.
    {
        let mut tx = pool.begin().await.expect("begin tenant-wide write probe");
        bind_scope(
            &mut tx,
            &scope_a.tenant().to_string(),
            &scope_a.environment().to_string(),
        )
        .await;
        for statement in [
            "UPDATE permissions SET display_name = 'hijacked' WHERE tenant_id = $1",
            "UPDATE permissions SET deleted_at = now() WHERE tenant_id = $1",
        ] {
            let updated = sqlx::query(statement)
                .bind(scope_b.tenant().to_string())
                .execute(&mut *tx)
                .await
                .expect("update runs")
                .rows_affected();
            assert_eq!(
                updated, 0,
                "RLS must hide every row of tenant B from a scope A write: {statement}"
            );
        }
        let _ = tx.rollback().await;
    }

    // 5. Positive controls: bound to B the same role sees exactly B's row, and bound
    //    to A2 it sees exactly A2's row. Without the SECOND of these the environment
    //    probes above would be satisfied by an empty environment, which is precisely
    //    how a zero becomes vacuous.
    for (victim, label) in [(scope_b, "scope B"), (scope_a2, "scope A2")] {
        let mut tx = pool.begin().await.expect("begin as the victim scope");
        bind_scope(
            &mut tx,
            &victim.tenant().to_string(),
            &victim.environment().to_string(),
        )
        .await;
        let visible: i64 = sqlx::query("SELECT count(*) AS c FROM permissions")
            .fetch_one(&mut *tx)
            .await
            .expect("count in the victim scope")
            .get("c");
        assert_eq!(visible, 1, "{label} sees its own permission");
        tx.commit().await.expect("commit the victim read");
    }
}

/// Every probe a session bound to `attacker` can aim at `victim`'s rows: the read
/// with the app-layer filter subverted, the two cross-scope writes, and the forge
/// INSERT. `differing` names the dimension the two scopes differ in, so a failure
/// says which half of the policy fell.
///
/// Every statement names BOTH scope columns. A probe naming the tenant alone is
/// decided by the tenant conjunct no matter what the environment conjunct says,
/// which is exactly the position blindness that left the environment half of this
/// policy asserted by nothing.
///
/// Each victim gets its OWN transaction because the forge INSERT is expected to
/// fail, and a failed statement aborts the surrounding transaction: a second victim
/// probed in the same transaction would see every statement refused as 25P02 and
/// pass for the wrong reason.
async fn assert_fenced_from(
    pool: &PgPool,
    env: &Env,
    attacker: Scope,
    victim: Scope,
    differing: &str,
) {
    let tenant = victim.tenant().to_string();
    let environment = victim.environment().to_string();
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
        "SELECT count(*) AS c FROM permissions WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_one(&mut *tx)
    .await
    .expect("cross-scope count")
    .get("c");
    assert_eq!(
        leaked, 0,
        "RLS must hide a permission whose {differing} differs, even with the filter bypassed"
    );

    // Write side, the half a read-only probe would miss: the USING clause hides the
    // victim's row from a relabel and from a soft delete alike.
    for statement in [
        "UPDATE permissions SET display_name = 'hijacked' \
         WHERE tenant_id = $1 AND environment_id = $2",
        "UPDATE permissions SET deleted_at = now() \
         WHERE tenant_id = $1 AND environment_id = $2",
    ] {
        let updated = sqlx::query(statement)
            .bind(&tenant)
            .bind(&environment)
            .execute(&mut *tx)
            .await
            .expect("update runs")
            .rows_affected();
        assert_eq!(
            updated, 0,
            "RLS must hide a row whose {differing} differs from a write: {statement}"
        );
    }

    // FORGE probe: an INSERT claiming the victim's scope. The WITH CHECK half of the
    // policy is what refuses it, and it is a distinct property from the USING half
    // above: a policy with USING only would pass every assertion so far and still let
    // one scope write into another.
    let forged = PermissionId::generate(env, &victim).to_string();
    let insert = sqlx::query(
        "INSERT INTO permissions (id, tenant_id, environment_id, slug, display_name) \
         VALUES ($1, $2, $3, 'forged.permission', 'Forged')",
    )
    .bind(forged)
    .bind(&tenant)
    .bind(&environment)
    .execute(&mut *tx)
    .await;
    assert!(
        insert.is_err(),
        "the RLS WITH CHECK must reject writing into a scope whose {differing} differs"
    );
    let _ = tx.rollback().await;
}

#[tokio::test]
async fn the_repository_fences_by_environment_even_when_the_policy_no_longer_does() {
    // The OTHER direction of the same masking, and the reason the test above is not
    // enough on its own. Every `PermissionRepo` statement carries its own
    // `environment_id = $N` conjunct AND binds the row-level-security variables to
    // the same value, so in production the two always agree and each one masks the
    // other: deleting EITHER leaves every functional assertion green. The test above
    // pins the POLICY half (a same-tenant, other-environment victim through raw SQL).
    // This pins the REPOSITORY half, by weakening the deployed policy to its tenant
    // conjunct alone and asserting the repository still refuses.
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

    plant(&db, &env, scope_a, "billing.read", "Read billing", 1_000)
        .await
        .expect("plant in A");
    plant(&db, &env, scope_a2, "staging.read", "Read staging", 2_000)
        .await
        .expect("plant in A2");

    db.execute_owner_sql("DROP POLICY permissions_tenant_isolation ON permissions")
        .await;
    db.execute_owner_sql(
        "CREATE POLICY permissions_tenant_isolation ON permissions \
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
        let visible: i64 = sqlx::query("SELECT count(*) AS c FROM permissions")
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

    let repo = db.control_store().management().permissions(scope_a);

    // The LIST is the assertion that catches a repository conjunct going missing: a
    // list without it returns A2's row too, which cannot even decode under scope A.
    let listed = repo
        .list(PermissionEntryKind::Permission, 50, None)
        .await
        .expect("the list must succeed and carry only this environment's rows");
    assert_eq!(
        listed.len(),
        1,
        "the repository's own environment conjunct must fence the list with the \
         policy no longer doing it"
    );
    assert_eq!(listed[0].slug, "billing.read");

    // The (kind, slug) address too. Two layers stand behind this one: the conjunct
    // and, behind it, the in-scope id decode in `permission_from_row`, which turns a
    // leaked row into the same not-found. So this assertion is defence in depth and
    // NOT the one that would catch a missing conjunct; the list above is.
    assert!(matches!(
        repo.get_by_slug(PermissionEntryKind::Permission, "staging.read")
            .await,
        Err(StoreError::NotFound)
    ));

    // Positive control: scope A's own vocabulary still reads, so the refusals above
    // are about the environment and not about a repository that stopped working.
    assert_eq!(
        repo.get_by_slug(PermissionEntryKind::Permission, "billing.read")
            .await
            .expect("scope A still reads its own permission")
            .slug,
        "billing.read"
    );
}

#[tokio::test]
async fn the_data_plane_can_read_a_permission_but_never_write_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let id = plant(&db, &env, scope, "billing.read", "Read billing", 1_000)
        .await
        .expect("plant");

    let read = db
        .store()
        .scoped(scope)
        .permissions()
        .get(&id)
        .await
        .expect("the data plane can READ a permission");
    assert_eq!(read.slug, "billing.read");

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
    // able to DEFINE the capability names it is about to put into a token is the
    // whole threat these grants exist to prevent.
    for statement in [
        "DELETE FROM permissions",
        "UPDATE permissions SET display_name = 'tampered'",
        "UPDATE permissions SET deleted_at = now()",
        // The FORGE probe: a row valid in EVERY respect but the grant. The session's
        // own scope, a slug and display name the CHECKs accept, and a kind the closed
        // set admits, so the row satisfies the row-level-security WITH CHECK and the
        // MISSING GRANT is the only thing that can refuse it. Postgres reports a
        // policy refusal and a privilege refusal under the SAME SQLSTATE (42501), so
        // a probe writing literal foreign scope values would be rejected by the
        // policy no matter how far the grant was widened, and could never observe the
        // grant at all.
        "INSERT INTO permissions (id, tenant_id, environment_id, slug, display_name) \
         VALUES ('prm_probe', $1, $2, 'probe.forged', 'probe')",
    ] {
        assert_denied_in_scope(pool, &tenant, &environment, statement).await;
    }

    // `slug` and `kind` are immutable by GRANT on BOTH roles: not even the control
    // plane, which owns the whole vocabulary lifecycle, may rewrite the stable name
    // or reclassify a live row. A rename under live mappings would silently repoint
    // every grant that names it, and a reclassification would silently move a row
    // into or out of the set a token claim selects.
    for statement in [
        "UPDATE permissions SET slug = 'tampered.slug'",
        "UPDATE permissions SET kind = 'entitlement'",
    ] {
        assert_denied_in_scope(db.control_pool(), &tenant, &environment, statement).await;
    }

    // Positive control: the control role's column-scoped relabel DOES succeed, so the
    // denials above are about the columns and not about the role's access generally.
    {
        let mut tx = db.control_pool().begin().await.expect("begin control tx");
        bind_scope(&mut tx, &tenant, &environment).await;
        sqlx::query("UPDATE permissions SET display_name = 'relabelled by the control plane'")
            .execute(&mut *tx)
            .await
            .expect("the control role holds column-scoped UPDATE on display_name");
        let _ = tx.rollback().await;
    }
}

#[tokio::test]
async fn the_storage_checks_refuse_a_malformed_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // The slug CHECK is the storage-engine backstop under the management edge's own
    // validator. The two are pinned equal case by case by the parity oracle in
    // ironauth-admin; this asserts the backstop is genuinely there, including the
    // three structural refusals the permission grammar adds on top of the #97 role
    // charset.
    for bad in [
        "billing",     // a single segment: namespacing is structural
        ".leading",    // a leading dot
        "trailing.",   // a trailing dot
        "double..dot", // a doubled dot
        "Billing.Read",
        "read:orders",
        "has space.read",
        "",
        "a.way-too-long-slug-that-runs-past-the-sixty-three-character-ceiling-xxxxx",
    ] {
        let error = plant(&db, &env, scope, bad, "Bad", 1_000)
            .await
            .expect_err("the slug CHECK must refuse");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::constraint),
            Some("permissions_slug_valid"),
            "{bad:?} must be refused by the slug CHECK, got {error}"
        );
    }

    // A nonempty display name is likewise pinned by a CHECK of its own.
    let error = plant(&db, &env, scope, "billing.read", "", 1_000)
        .await
        .expect_err("the display-name CHECK must refuse");
    assert_eq!(
        error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::constraint),
        Some("permissions_display_name_nonempty")
    );

    // The valid grammar really is accepted, so the CHECK is not simply refusing
    // everything: lowercase alphanumerics plus underscore and ASCII hyphen inside a
    // segment, dot between segments.
    plant(&db, &env, scope, "a1.b_c-d.e2", "Fine", 2_000)
        .await
        .expect("the documented grammar is accepted");
}

#[tokio::test]
async fn the_kind_column_defaults_to_permission_and_admits_only_the_closed_set() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // The DEFAULT is the storage-engine half of the closed set, and it is what a
    // hand-written insert meets. This pins that half, which issue #103's first
    // entitlement write and every operator-run insert meet. The audited write
    // repository does NOT rely on it, and that separate claim is pinned separately by
    // `the_write_path_binds_the_kind_and_does_not_inherit_a_drifted_default`: while
    // the default and the bind agree, no assertion here can tell them apart.
    let id = PermissionId::generate(&env, &scope);
    let mut tx = db.control_pool().begin().await.expect("begin");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    sqlx::query(
        "INSERT INTO permissions (id, tenant_id, environment_id, slug, display_name) \
         VALUES ($1, $2, $3, 'billing.read', 'Read billing')",
    )
    .bind(id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(&mut *tx)
    .await
    .expect("insert with no kind stated");
    tx.commit().await.expect("commit");

    assert_eq!(
        db.control_store()
            .management()
            .permissions(scope)
            .get(&id)
            .await
            .expect("get")
            .kind,
        PermissionEntryKind::Permission,
        "an unstated kind must default to the ordinary permission"
    );

    // The closed set is pinned by a CHECK: an unknown kind is UNWRITABLE, which is
    // what stops a future writer from inventing a third classification that no
    // projection filter accounts for.
    let error = plant_at(
        &db,
        &env,
        scope,
        PermissionEntryKind::Permission,
        "billing.write",
        "Write billing",
        2_000,
    )
    .await;
    assert!(error.is_ok(), "the closed set admits the ordinary kind");
    let mut tx = db.control_pool().begin().await.expect("begin");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    let refused = sqlx::query(
        "INSERT INTO permissions (id, tenant_id, environment_id, kind, slug, display_name) \
         VALUES ($1, $2, $3, 'capability', 'billing.admin', 'Admin')",
    )
    .bind(PermissionId::generate(&env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(&mut *tx)
    .await
    .expect_err("an unknown kind must be unwritable");
    let _ = tx.rollback().await;
    let database_error = refused.as_database_error().expect("a database error");
    assert_eq!(database_error.code().as_deref(), Some(CHECK_VIOLATION));
    assert_eq!(
        database_error.constraint(),
        Some("permissions_kind_known"),
        "the kind must be refused by its OWN named constraint"
    );
}

#[tokio::test]
async fn a_stored_kind_outside_the_closed_set_fails_the_read_closed() {
    // The Rust half of the closed set. `permissions_kind_known` makes an unrecognized
    // kind unwritable, so the decode arm in `permission_from_row` is unreachable
    // through any supported path; dropping the constraint is what makes it reachable
    // here. The property is worth a test because the plausible mistake is decoding an
    // unknown kind as the ORDINARY permission, which would put an unclassified row
    // into the set a token claim selects. Fail closed, loudly, instead.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    db.execute_owner_sql("ALTER TABLE permissions DROP CONSTRAINT permissions_kind_known")
        .await;

    let id = PermissionId::generate(&env, &scope);
    let mut tx = db.control_pool().begin().await.expect("begin");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    sqlx::query(
        "INSERT INTO permissions (id, tenant_id, environment_id, kind, slug, display_name) \
         VALUES ($1, $2, $3, 'capability', 'billing.read', 'Read billing')",
    )
    .bind(id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(&mut *tx)
    .await
    .expect("the constraint is gone, so the row lands");
    tx.commit().await.expect("commit");

    let repo = db.control_store().management().permissions(scope);
    assert!(
        matches!(repo.get(&id).await, Err(StoreError::Database(_))),
        "an unrecognized stored kind must fail the read, never decode as a permission"
    );
    // The kind-ADDRESSED reads never select it in the first place, which is the
    // other half of the same guarantee and the one the
    // `kind = 'permission'` projection filter relies on: an unclassified row is
    // excluded in SQL, so it cannot reach a list or a slug lookup at all. Both kinds
    // are asserted, so "excluded" means excluded from EVERY addressed read and not
    // merely from the one it happens not to match.
    for kind in [
        PermissionEntryKind::Permission,
        PermissionEntryKind::Entitlement,
    ] {
        assert_eq!(
            repo.list(kind, 50, None).await.expect("the list succeeds"),
            Vec::new(),
            "a row outside the closed set must be excluded in SQL, never listed"
        );
        assert!(matches!(
            repo.get_by_slug(kind, "billing.read").await,
            Err(StoreError::NotFound)
        ));
    }
}

/// Run `statement` in a scoped transaction on `pool` and assert it is refused as
/// insufficient privilege.
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

// ===========================================================================
// The AUDITED WRITE path (issue #98, store PR 2).
// ===========================================================================

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_permission_round_trips_through_the_audited_write_repository() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let id = define(
        &db,
        &env,
        scope,
        "billing.invoice.read",
        "Read invoices",
        1_000,
    )
    .await
    .expect("define a permission");

    // It reads back on both planes. The `kind` assertion below is a round-trip check
    // and NOT the proof that the write path binds the discriminator: the column
    // default is `'permission'` too, so this row would read back the same either way.
    // `the_write_path_binds_the_kind_and_does_not_inherit_a_drifted_default` is where
    // the two are made to disagree.
    let created = control
        .management()
        .permissions(scope)
        .get(&id)
        .await
        .expect("get after create");
    assert_eq!(created.slug, "billing.invoice.read");
    assert_eq!(created.kind, PermissionEntryKind::Permission);
    assert_eq!(created.display_name, "Read invoices");
    assert_eq!(created.metadata, serde_json::json!({}));
    assert_eq!(created.created_at_unix_micros, 1_000);
    assert_eq!(created.updated_at_unix_micros, 1_000);
    assert_eq!(
        db.store()
            .scoped(scope)
            .permissions()
            .get(&id)
            .await
            .expect("the data plane reads what the control plane wrote"),
        created
    );
    assert_eq!(
        audit_actions(&db, scope, &id.to_string()).await,
        vec!["permission.create"]
    );

    // A relabel moves the display name and the modification time, and moves NOTHING
    // else. The slug is what a token claim carries and the kind decides whether a
    // resolution projection selects the row at all, so a relabel that could move
    // either would silently move an authorization decision.
    relabel(&db, &env, scope, &id, Some("Read invoices (billing)"), None)
        .await
        .expect("relabel");
    let relabelled = control
        .management()
        .permissions(scope)
        .get(&id)
        .await
        .expect("get after relabel");
    assert_eq!(relabelled.display_name, "Read invoices (billing)");
    assert_eq!(relabelled.slug, created.slug, "the slug is immutable");
    assert_eq!(relabelled.kind, created.kind, "the kind is immutable");
    assert_eq!(
        relabelled.created_at_unix_micros, created.created_at_unix_micros,
        "a relabel does not move the creation time (the pagination key)"
    );
    assert!(
        relabelled.updated_at_unix_micros > created.updated_at_unix_micros,
        "a relabel moves the modification time"
    );
    assert_eq!(
        relabelled.metadata, created.metadata,
        "a None metadata argument leaves the stored document alone"
    );
    assert_eq!(
        audit_actions(&db, scope, &id.to_string()).await,
        vec!["permission.create", "permission.update"]
    );

    // Metadata replaces on its own, leaving the label alone.
    relabel(
        &db,
        &env,
        scope,
        &id,
        None,
        Some(&serde_json::json!({"owner": "billing"})),
    )
    .await
    .expect("replace metadata");
    let with_metadata = control
        .management()
        .permissions(scope)
        .get(&id)
        .await
        .expect("get after metadata write");
    assert_eq!(
        with_metadata.metadata,
        serde_json::json!({"owner": "billing"})
    );
    assert_eq!(with_metadata.display_name, "Read invoices (billing)");
    assert_eq!(with_metadata.slug, created.slug);
    assert_eq!(with_metadata.kind, created.kind);
    assert_eq!(
        audit_actions(&db, scope, &id.to_string()).await,
        vec![
            "permission.create",
            "permission.update",
            "permission.update"
        ]
    );

    // The delete is SOFT: the row is retained so the audit foreign key to it stays
    // satisfiable, and every read filters it out.
    remove(&db, &env, scope, &id).await.expect("delete");
    assert!(matches!(
        control.management().permissions(scope).get(&id).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        control
            .management()
            .permissions(scope)
            .get_by_slug(PermissionEntryKind::Permission, "billing.invoice.read")
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(
        control
            .management()
            .permissions(scope)
            .list(PermissionEntryKind::Permission, 50, None)
            .await
            .expect("list after delete")
            .is_empty()
    );
    assert_eq!(
        count_permissions(&db, "deleted_at IS NOT NULL").await,
        1,
        "the row is retained, not removed"
    );

    let after_delete = vec![
        "permission.create",
        "permission.update",
        "permission.update",
        "permission.delete",
    ];
    assert_eq!(
        audit_actions(&db, scope, &id.to_string()).await,
        after_delete,
        "every mutation is audited, in order, under the exact wire strings migration \
         0091 declares as the delta contract"
    );

    // A repeat delete and a relabel of the dead row are the uniform not-found, and
    // NEITHER writes an audit row: the refusal happens inside the same transaction
    // the audit row would have been written in, so it rolls back with it.
    assert!(matches!(
        remove(&db, &env, scope, &id).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        relabel(&db, &env, scope, &id, Some("resurrected"), None).await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(
        audit_actions(&db, scope, &id.to_string()).await,
        after_delete,
        "a refused mutation writes no audit row against its target"
    );
    assert_eq!(
        all_permission_audit_actions(&db).await,
        after_delete,
        "and none against any other target or scope either"
    );
    assert_eq!(
        count_permissions(&db, "true").await,
        1,
        "and it created nothing"
    );
}

#[tokio::test]
async fn the_write_path_binds_the_kind_and_does_not_inherit_a_drifted_default() {
    // The one rule this PR adds that no other assertion can reach. Every other test
    // reads back `kind = permission` from a row the DEFAULT would have supplied
    // anyway, because the shipped default IS `'permission'`: the explicit bind and the
    // default agree on every row this file writes, so dropping the bind entirely
    // leaves all of them green. The bind is only observable where the two DISAGREE,
    // and the only way to make them disagree is to move the default.
    //
    // The scenario is issue #103's, not a hypothetical: that issue's whole job is
    // entitlement rows, so `ALTER COLUMN kind SET DEFAULT 'entitlement'` is a
    // plausible step in it. If the explicit bind has regressed by then, every #98
    // create silently stores `kind = 'entitlement'` and the resolution projection's
    // `kind = 'permission'` filter silently drops every permission from the access
    // token claim, with nothing anywhere turning red.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    db.execute_owner_sql("ALTER TABLE permissions ALTER COLUMN kind SET DEFAULT 'entitlement'")
        .await;

    let id = define(&db, &env, scope, "billing.read", "Read billing", 1_000)
        .await
        .expect("define under the drifted default");

    // Read through the OWNER pool, as the raw stored string. A read through the
    // repository would decode into `PermissionEntryKind` and could only report what
    // the row says anyway, but going around it makes the assertion about the STORED
    // byte and not about any decode the repository performs.
    let stored: String = sqlx::query("SELECT kind FROM permissions WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("read the stored kind")
        .get("kind");
    assert_eq!(
        stored, "permission",
        "the audited write path must BIND the discriminator, so a drifted column \
         default cannot reclassify what it writes"
    );

    // And the drift really was in place, or the assertion above would prove nothing:
    // an insert that states no kind takes the moved default.
    let mut tx = db.control_pool().begin().await.expect("begin");
    bind_scope(
        &mut tx,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    )
    .await;
    let unstated = PermissionId::generate(&env, &scope);
    sqlx::query(
        "INSERT INTO permissions (id, tenant_id, environment_id, slug, display_name) \
         VALUES ($1, $2, $3, 'billing.write', 'Write billing')",
    )
    .bind(unstated.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(&mut *tx)
    .await
    .expect("insert with no kind stated");
    tx.commit().await.expect("commit");
    let drifted: String = sqlx::query("SELECT kind FROM permissions WHERE id = $1")
        .bind(unstated.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("read the unstated kind")
        .get("kind");
    assert_eq!(
        drifted, "entitlement",
        "the default must really have moved, or this test cannot tell a bound \
         discriminator from an inherited one"
    );
}

#[tokio::test]
async fn a_relabel_can_move_neither_the_slug_nor_the_kind() {
    // Immutability here is a GRANT property, not a convention, so it is worth
    // probing at the layer that enforces it. Migration 0091 grants the control role
    // `UPDATE (display_name, metadata, updated_at, deleted_at)` and nothing more, so
    // a statement naming `slug` or `kind` in its SET list is refused WHOLESALE, even
    // when it also names a column the role may write. That is the property that makes
    // it impossible to smuggle a slug rewrite alongside a legitimate relabel, and it
    // is also what would turn `ActingPermissionRepo::update` red the moment somebody
    // added `slug = COALESCE(...)` to it: every relabel would begin failing 42501.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    let id = define(&db, &env, scope, "billing.read", "Read billing", 1_000)
        .await
        .expect("define");

    // The repository's own relabel leaves both stable fields alone.
    relabel(&db, &env, scope, &id, Some("Relabelled"), None)
        .await
        .expect("relabel");
    let after = db
        .control_store()
        .management()
        .permissions(scope)
        .get(&id)
        .await
        .expect("get");
    assert_eq!(after.slug, "billing.read");
    assert_eq!(after.kind, PermissionEntryKind::Permission);

    // A statement that TRIES, from the very role the repository runs as, with the
    // session bound to the row's OWN scope so the row satisfies the isolation
    // policy's USING clause and only the absent grant can refuse it. Postgres reports
    // a policy refusal and a privilege refusal under the same SQLSTATE, so a probe
    // aimed at a foreign row could never observe the grant at all.
    for statement in [
        "UPDATE permissions SET display_name = 'smuggled', slug = 'other.slug' \
         WHERE tenant_id = $1 AND environment_id = $2",
        "UPDATE permissions SET display_name = 'smuggled', kind = 'entitlement' \
         WHERE tenant_id = $1 AND environment_id = $2",
    ] {
        assert_denied_in_scope(db.control_pool(), &tenant, &environment, statement).await;
    }

    // Nothing moved, including the display name the refused statements also named:
    // the whole statement is refused, so a rewrite cannot ride along with a change
    // the role IS allowed to make.
    let untouched = db
        .control_store()
        .management()
        .permissions(scope)
        .get(&id)
        .await
        .expect("get after the refused statements");
    assert_eq!(untouched, after);
}

/// Every column of `permissions` the given role may UPDATE, swept from the catalog.
///
/// `has_table_privilege(role, 'permissions', 'UPDATE')` cannot answer this: a
/// COLUMN-scoped grant is invisible to it, so a table-level check would report "no
/// UPDATE" for a role that can in fact rewrite four columns, and would keep reporting
/// it however far the column list was widened. Sweeping `pg_attribute` and asking
/// `has_column_privilege` per column is the only form that sees the real grant, and
/// asking it of EVERY column (rather than of an expected list) is what makes the
/// answer an exact set rather than a subset.
async fn updatable_columns(db: &TestDatabase, role: &str) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT a.attname AS name \
           FROM pg_attribute a \
          WHERE a.attrelid = 'permissions'::regclass \
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

/// Every live column of `permissions`, so the sweep above can be shown to have looked
/// at all of them rather than at an empty relation.
async fn all_columns(db: &TestDatabase) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT a.attname AS name FROM pg_attribute a \
          WHERE a.attrelid = 'permissions'::regclass \
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

/// Whether `role` holds `privilege` on `permissions` at TABLE level.
async fn has_table_privilege(db: &TestDatabase, role: &str, privilege: &str) -> bool {
    sqlx::query("SELECT has_table_privilege($1::name, 'permissions', $2) AS held")
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

    // The sweep really looked at the table: ten columns, the shape migration 0091
    // creates. Without this the set comparisons below could both be satisfied by a
    // relation the catalog query failed to find.
    assert_eq!(
        all_columns(&db).await,
        vec![
            "created_at",
            "deleted_at",
            "display_name",
            "environment_id",
            "id",
            "kind",
            "metadata",
            "slug",
            "tenant_id",
            "updated_at",
        ]
    );

    // EXACTLY the four mutable columns, as an exact set. `slug` and `kind` are absent
    // (the immutability the token claim rests on), and so are `id`, `tenant_id`, and
    // `environment_id`, which is what makes it impossible to move a permission
    // between scopes (the #31 lesson).
    assert_eq!(
        updatable_columns(&db, "ironauth_control").await,
        vec!["deleted_at", "display_name", "metadata", "updated_at"],
        "widening this grant is a security change and must not pass silently"
    );

    // The DATA plane holds no UPDATE on any column at all. It resolves permissions
    // onto the token-issuance path and must never be able to define or
    // relabel the capability names it is about to emit.
    assert_eq!(
        updatable_columns(&db, "ironauth_app").await,
        Vec::<String>::new()
    );

    // DELETE is granted to NOBODY on either plane: removal is the soft delete, which
    // is what keeps the audit foreign key satisfiable.
    for role in ["ironauth_control", "ironauth_app"] {
        assert!(
            !has_table_privilege(&db, role, "DELETE").await,
            "{role} must not hold DELETE on permissions"
        );
        assert!(
            !has_table_privilege(&db, role, "UPDATE").await,
            "{role} must hold UPDATE per COLUMN and never over the whole table"
        );
        assert!(
            has_table_privilege(&db, role, "SELECT").await,
            "{role} reads the vocabulary"
        );
    }
    assert!(
        has_table_privilege(&db, "ironauth_control", "INSERT").await,
        "the control plane defines the vocabulary"
    );
    assert!(
        !has_table_privilege(&db, "ironauth_app", "INSERT").await,
        "the data plane never defines one"
    );
}

#[tokio::test]
async fn a_deleted_slug_is_free_again_and_a_re_create_mints_a_fresh_id() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let first = define(&db, &env, scope, "billing.read", "Read billing", 1_000)
        .await
        .expect("define the first");

    // While it is LIVE the slug is taken, by the partial unique index.
    assert!(matches!(
        define(&db, &env, scope, "billing.read", "Duplicate", 2_000).await,
        Err(StoreError::Conflict)
    ));

    remove(&db, &env, scope, &first).await.expect("delete");

    let second = define(
        &db,
        &env,
        scope,
        "billing.read",
        "Read billing again",
        3_000,
    )
    .await
    .expect("a deleted slug is free again");
    assert_ne!(
        first, second,
        "a re-create mints a FRESH id and is never a revival: the mapping table \
         hangs role grants off the id, so reviving would silently restore every \
         grant that pointed at the dead row"
    );

    // Exactly ONE live row holds the slug, and the dead one is still there.
    assert_eq!(
        count_permissions(&db, "slug = 'billing.read' AND deleted_at IS NULL").await,
        1,
        "the re-create must leave one live row, not two"
    );
    assert_eq!(count_permissions(&db, "slug = 'billing.read'").await, 2);
    assert_eq!(
        control
            .management()
            .permissions(scope)
            .get_by_slug(PermissionEntryKind::Permission, "billing.read")
            .await
            .expect("the live row")
            .id,
        second
    );
    assert!(matches!(
        control.management().permissions(scope).get(&first).await,
        Err(StoreError::NotFound)
    ));

    // The dead row keeps its own audit history and the fresh row starts its own, so
    // the log says two permissions existed rather than one that came back.
    assert_eq!(
        audit_actions(&db, scope, &first.to_string()).await,
        vec!["permission.create", "permission.delete"]
    );
    assert_eq!(
        audit_actions(&db, scope, &second.to_string()).await,
        vec!["permission.create"]
    );
}

#[tokio::test]
async fn the_kind_is_part_of_the_live_conflict_key_from_the_write_path_too() {
    // The issue #103 headroom as the WRITE path sees it. `permissions.rs` already
    // pins both halves through direct SQL; this pins the half the repository can
    // reach, because a unique index that lost `kind` would make the create below a
    // Conflict and #103 would need a migration on a table the token path reads.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // A live ENTITLEMENT first, planted with SQL because issue #98's write path
    // deliberately defines no entitlements.
    plant_at(
        &db,
        &env,
        scope,
        PermissionEntryKind::Entitlement,
        "plan.enterprise",
        "Enterprise plan entitlement",
        1_000,
    )
    .await
    .expect("plant the entitlement");

    // The repository may define a PERMISSION of the same slug.
    let permission = define(
        &db,
        &env,
        scope,
        "plan.enterprise",
        "Enterprise plan capability",
        2_000,
    )
    .await
    .expect("the same slug is free under the other kind");

    // A second live PERMISSION of that slug is not.
    assert!(matches!(
        define(&db, &env, scope, "plan.enterprise", "Duplicate", 3_000).await,
        Err(StoreError::Conflict)
    ));

    // And a second live ENTITLEMENT of that slug is not either. Keeping this half
    // guarded matters because every live-uniqueness probe reachable from the write
    // path sits at `kind = 'permission'`, so narrowing the index predicate to
    // `WHERE deleted_at IS NULL AND kind = 'permission'` would leave the whole write
    // surface green while #103's entitlements got no uniqueness at all.
    let duplicate = plant_at(
        &db,
        &env,
        scope,
        PermissionEntryKind::Entitlement,
        "plan.enterprise",
        "Duplicate entitlement",
        4_000,
    )
    .await
    .expect_err("a LIVE entitlement slug is taken too");
    let database_error = duplicate.as_database_error().expect("a database error");
    assert_eq!(database_error.code().as_deref(), Some(UNIQUE_VIOLATION));
    assert_eq!(
        database_error.constraint(),
        Some("permissions_kind_slug_live_uniq"),
        "refused by the live-uniqueness index BY NAME, not by something else that \
         happened to fail"
    );

    // The conflict wrote nothing and audited nothing beyond the one real define.
    assert_eq!(
        all_permission_audit_actions(&db).await,
        vec!["permission.create"]
    );
    assert_eq!(
        audit_actions(&db, scope, &permission.to_string()).await,
        vec!["permission.create"]
    );
}

#[tokio::test]
async fn a_refused_create_writes_neither_a_row_nor_an_audit_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let live = define(&db, &env, scope, "billing.read", "Read billing", 1_000)
        .await
        .expect("define the live one");

    // 1. The CONFLICT path: a second live row with the same (kind, slug).
    assert!(matches!(
        define(&db, &env, scope, "billing.read", "Duplicate", 2_000).await,
        Err(StoreError::Conflict)
    ));

    // 2. The CHECK path: a slug the storage engine refuses. The management edge
    //    validates this up front and reports a 400, so reaching the CHECK means a
    //    caller bypassed the edge; it must still leave nothing behind.
    for (slug, display_name) in [
        // A single segment: namespacing is structural in this grammar.
        ("billing", "Not namespaced"),
        (".leading", "Leading dot"),
        ("Billing.Read", "Uppercase"),
        ("read:orders", "An OAuth scope token, not a permission slug"),
        // A valid slug with an empty label: the OTHER CHECK.
        ("billing.write", ""),
    ] {
        let refused = define(&db, &env, scope, slug, display_name, 3_000).await;
        assert!(
            matches!(refused, Err(StoreError::Database(_))),
            "{slug:?} with label {display_name:?} must be refused by the storage \
             CHECKs: {refused:?}"
        );
    }

    // Nothing landed: one row, and exactly one audit row, both from the single
    // successful define. A phantom audit row is what a create that audited BEFORE (or
    // outside) its data change would leave, and it would be invisible to a per-target
    // read because the refused ids were never returned to this test.
    assert_eq!(count_permissions(&db, "true").await, 1);
    assert_eq!(
        all_permission_audit_actions(&db).await,
        vec!["permission.create"]
    );
    assert_eq!(
        audit_actions(&db, scope, &live.to_string()).await,
        vec!["permission.create"]
    );

    // Positive control: the write path still works, so the refusals above are about
    // the values and not about a repository that stopped writing.
    define(&db, &env, scope, "billing.write", "Write billing", 4_000)
        .await
        .expect("a well-formed define still lands");
    assert_eq!(count_permissions(&db, "deleted_at IS NULL").await, 2);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn every_mutation_answers_absent_deleted_and_both_foreign_scopes_alike() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    // A THIRD scope differing from A in the ENVIRONMENT ALONE. `seed_scope` mints a
    // NEW TENANT on every call, so scope_a and scope_b differ in BOTH dimensions and
    // the tenant conjunct of every fence decides every probe between them; a victim
    // that differs only in the environment is the one that makes the environment half
    // deciding. Without it the whole environment fence on the WRITE path would be
    // asserted by nothing, which is exactly the hole this file's review found on the
    // read path.
    let scope_a2 = Scope::new(
        scope_a.tenant(),
        db.seed_environment(&env, scope_a.tenant()).await,
    );

    let victim_b = define(&db, &env, scope_b, "billing.read", "Read billing", 1_000)
        .await
        .expect("define in tenant B");
    let victim_a2 = define(&db, &env, scope_a2, "staging.read", "Read staging", 2_000)
        .await
        .expect("define in the same tenant's other environment");
    let own_deleted = define(&db, &env, scope_a, "billing.write", "Write billing", 3_000)
        .await
        .expect("define in A");
    remove(&db, &env, scope_a, &own_deleted)
        .await
        .expect("delete A's own");
    let absent = PermissionId::generate(&env, &scope_a);

    // Positive control first: a live permission of A really is mutable from A, so a
    // repository that refused everything could not pass this test.
    let live_a = define(&db, &env, scope_a, "billing.admin", "Admin billing", 4_000)
        .await
        .expect("define A's live one");
    relabel(
        &db,
        &env,
        scope_a,
        &live_a,
        Some("Administer billing"),
        None,
    )
    .await
    .expect("A may relabel its own");

    let audits_before = all_permission_audit_actions(&db).await;

    // Every mutating surface, against every case that must be indistinguishable.
    for (target, label) in [
        (&absent, "absent in the caller's own scope"),
        (&own_deleted, "soft-deleted in the caller's own scope"),
        (&victim_b, "live in another TENANT"),
        (&victim_a2, "live in the same tenant's other ENVIRONMENT"),
    ] {
        assert!(
            matches!(
                relabel(&db, &env, scope_a, target, Some("hijacked"), None).await,
                Err(StoreError::NotFound)
            ),
            "a relabel of a permission {label} must be the uniform not-found"
        );
        assert!(
            matches!(
                remove(&db, &env, scope_a, target).await,
                Err(StoreError::NotFound)
            ),
            "a delete of a permission {label} must be the uniform not-found"
        );
    }

    // A CREATE naming an id minted in another scope is refused before any statement
    // runs, so a permission can never be planted into another environment's
    // vocabulary through the id.
    for foreign_scope in [scope_b, scope_a2] {
        let smuggled = PermissionId::generate(&env, &foreign_scope);
        let refused = db
            .control_store()
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .permissions(scope_a)
            .create(
                &env,
                NewPermission {
                    id: &smuggled,
                    slug: "smuggled.permission",
                    display_name: "Smuggled",
                    metadata: None,
                },
                5_000,
                None,
            )
            .await;
        assert!(matches!(refused, Err(StoreError::NotFound)));
    }

    // Both victims SURVIVED, live and with their labels untouched. Without this the
    // refusals above could be satisfied by a repository that destroyed the row and
    // then reported not-found.
    for (victim_scope, victim, slug, label) in [
        (scope_b, &victim_b, "billing.read", "Read billing"),
        (scope_a2, &victim_a2, "staging.read", "Read staging"),
    ] {
        let record = db
            .control_store()
            .management()
            .permissions(victim_scope)
            .get(victim)
            .await
            .expect("the victim survives in its own scope");
        assert_eq!(record.slug, slug);
        assert_eq!(record.display_name, label);
    }

    // And not one of those refusals wrote an audit row ANYWHERE: not against the
    // foreign target, not in the caller's scope, not in the victim's.
    assert_eq!(
        all_permission_audit_actions(&db).await,
        audits_before,
        "a refused cross-scope mutation must leave the audit log untouched"
    );
    assert_eq!(
        count_permissions(&db, "deleted_at IS NULL").await,
        3,
        "A's live one plus the two victims"
    );
}

#[tokio::test]
async fn a_failing_audit_insert_rolls_the_permission_write_back() {
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
    let control = db.control_store();

    let id = define(&db, &env, scope, "billing.read", "Read billing", 1_000)
        .await
        .expect("define");

    for (action, attempt) in [
        ("permission.update", "update"),
        ("permission.delete", "delete"),
    ] {
        // NOT VALID, so the constraint applies to rows written from here on and does
        // not re-validate the audit history the successful define above already
        // wrote. Without it the ALTER itself would fail on that row and the probe
        // would never run.
        db.execute_owner_sql(&format!(
            "ALTER TABLE audit_log ADD CONSTRAINT audit_probe \
             CHECK (action <> '{action}') NOT VALID"
        ))
        .await;

        let result = if attempt == "update" {
            relabel(&db, &env, scope, &id, Some("hijacked"), None).await
        } else {
            remove(&db, &env, scope, &id).await
        };
        assert!(
            matches!(result, Err(StoreError::Database(_))),
            "the poisoned {attempt} must fail: {result:?}"
        );

        // The mutation rolled back with the audit row it could not write: the label is
        // the original and the row is still LIVE.
        let survivor = control
            .management()
            .permissions(scope)
            .get(&id)
            .await
            .expect("the permission survives an audit failure, live and unchanged");
        assert_eq!(survivor.display_name, "Read billing");

        db.execute_owner_sql("ALTER TABLE audit_log DROP CONSTRAINT audit_probe")
            .await;
    }

    // The create half of the same property: no row, and no partial write.
    db.execute_owner_sql(
        "ALTER TABLE audit_log ADD CONSTRAINT audit_probe \
         CHECK (action <> 'permission.create') NOT VALID",
    )
    .await;
    let result = define(&db, &env, scope, "billing.write", "Write billing", 2_000).await;
    assert!(
        matches!(result, Err(StoreError::Database(_))),
        "the poisoned create must fail: {result:?}"
    );
    db.execute_owner_sql("ALTER TABLE audit_log DROP CONSTRAINT audit_probe")
        .await;

    assert_eq!(
        count_permissions(&db, "true").await,
        1,
        "a create whose audit row could not be written leaves no permission row"
    );
    assert_eq!(
        all_permission_audit_actions(&db).await,
        vec!["permission.create"],
        "and the only audit row is the successful define at the top"
    );
}
