// SPDX-License-Identifier: MIT OR Apache-2.0

//! The organization resource (issue #41), against a real database, through the
//! control-plane store. Covers create/get/list/delete, cursor pagination,
//! cross-tenant and cross-environment isolation (uniform not-found), containment
//! (a child cannot be created under a foreign or nonexistent parent), idempotent
//! creation, and the audited-mutation invariant.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, IdempotencyWrite, OrganizationId, Scope, ServiceId, StoreError,
};
use sqlx::Row;

fn actor(env: &Env) -> ActorRef {
    ActorRef::service(ServiceId::generate(env))
}

/// Create an organization in `scope` via the control store, returning its id.
async fn create_org(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    display_name: &str,
    created_at_micros: i64,
) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, created_at_micros, display_name, None)
        .await
        .expect("create organization");
    id
}

#[tokio::test]
async fn create_get_and_delete_round_trip() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let id = create_org(&db, &env, scope, "Globex", 1_000_000).await;

    // Get returns the created organization within its scope.
    let record = control
        .management()
        .organizations(scope)
        .get(&id)
        .await
        .expect("get organization");
    assert_eq!(record.id, id);
    assert_eq!(record.display_name, "Globex");
    assert_eq!(record.created_at_unix_micros, 1_000_000);
    assert_eq!(record.id.scope(), scope, "the id embeds its scope");

    // Delete is a soft deactivation; afterwards the organization reads as absent.
    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete(&env, &id)
        .await
        .expect("delete organization");
    assert!(matches!(
        control.management().organizations(scope).get(&id).await,
        Err(StoreError::NotFound)
    ));

    // Delete is idempotent-ish: a second delete of an already-deactivated row is
    // a uniform not-found (no live row matched).
    assert!(matches!(
        control
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .organizations(scope)
            .delete(&env, &id)
            .await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn list_is_cursor_paginated_and_ordered() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    // Plant five organizations with strictly increasing created_at so the
    // (created_at, id) keyset order is deterministic.
    let mut ids = Vec::new();
    for i in 0..5 {
        ids.push(create_org(&db, &env, scope, &format!("org-{i}"), 1_000 + i64::from(i)).await);
    }

    // Page 1: first two.
    let page1 = control
        .management()
        .organizations(scope)
        .list(2, None)
        .await
        .expect("page 1");
    assert_eq!(page1.len(), 2);
    assert_eq!(page1[0].id, ids[0]);
    assert_eq!(page1[1].id, ids[1]);

    // Page 2: next two, strictly after the page-1 cursor.
    let cursor = ironauth_store::CursorPosition {
        created_at_unix_micros: page1[1].created_at_unix_micros,
        id: page1[1].id.to_string(),
    };
    let page2 = control
        .management()
        .organizations(scope)
        .list(2, Some(&cursor))
        .await
        .expect("page 2");
    assert_eq!(page2.len(), 2);
    assert_eq!(page2[0].id, ids[2]);
    assert_eq!(page2[1].id, ids[3]);

    // No loss or duplication across the walk.
    let all: Vec<String> = control
        .management()
        .organizations(scope)
        .list(100, None)
        .await
        .expect("all")
        .into_iter()
        .map(|r| r.id.to_string())
        .collect();
    assert_eq!(all.len(), 5);
}

#[tokio::test]
async fn cross_tenant_and_cross_environment_are_uniform_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let control = db.control_store();

    // Two tenants, plus a second environment of the first tenant.
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    let org_b = create_org(&db, &env, scope_b, "in tenant B", 5_000).await;
    let org_a2 = create_org(&db, &env, scope_a2, "in environment A2", 5_000).await;

    // A well-formed id from tenant A that was never stored: the baseline denial.
    let absent = OrganizationId::generate(&env, &scope_a);
    assert!(matches!(
        control
            .management()
            .organizations(scope_a)
            .get(&absent)
            .await,
        Err(StoreError::NotFound)
    ));

    // parse_id under scope A rejects a foreign-tenant and a foreign-environment id
    // identically (the typed id embeds its scope, so it never parses in scope).
    let organizations_a = control.management().organizations(scope_a);
    assert!(matches!(
        organizations_a.parse_id(&org_b.to_string()),
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        organizations_a.parse_id(&org_a2.to_string()),
        Err(StoreError::NotFound)
    ));

    // Even if the typed id is smuggled straight to get(), the scope guard denies.
    assert!(matches!(
        organizations_a.get(&org_b).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        organizations_a.get(&org_a2).await,
        Err(StoreError::NotFound)
    ));

    // The victims survive: no cross-scope get mutated or leaked them.
    assert!(
        control
            .management()
            .organizations(scope_b)
            .get(&org_b)
            .await
            .is_ok()
    );
    assert!(
        control
            .management()
            .organizations(scope_a2)
            .get(&org_a2)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn create_under_a_nonexistent_environment_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    // A scope whose tenant and environment were NEVER seeded: the parent does not
    // exist, so the foreign-key check refuses the insert (containment).
    let phantom = Scope::new(
        ironauth_store::TenantId::generate(&env),
        ironauth_store::EnvironmentId::generate(&env),
    );
    let id = OrganizationId::generate(&env, &phantom);
    let result = db
        .control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(phantom)
        .create(&env, &id, 1_000, "orphan", None)
        .await;
    assert!(
        matches!(result, Err(StoreError::Database(_))),
        "an organization under a nonexistent environment must be refused, got {result:?}"
    );
}

#[tokio::test]
async fn create_with_a_foreign_scoped_id_is_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    // An id minted for scope B, handed to the scope-A repository: the scope guard
    // rejects it before any SQL runs (uniform not-found), so it can never be a
    // vector for writing into a foreign scope.
    let foreign_id = OrganizationId::generate(&env, &scope_b);
    let result = db
        .control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(scope_a)
        .create(&env, &foreign_id, 1_000, "smuggled", None)
        .await;
    assert!(matches!(result, Err(StoreError::NotFound)));
}

#[tokio::test]
async fn create_is_idempotent_under_a_replayed_key() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let id = OrganizationId::generate(&env, &scope);
    let write = |body: &'static str| IdempotencyWrite {
        credential_ref: "svc_probe",
        key: "key-1",
        request_fingerprint: "fp-1",
        response_status: 201,
        response_body: body,
    };

    control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &id, 1_000, "first", Some(write("first-body")))
        .await
        .expect("first create stores the idempotency row");

    // A second create reusing the same key races the stored row: the distinct
    // IdempotencyConflict tells the caller to replay rather than double-execute.
    let second = control
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(
            &env,
            &OrganizationId::generate(&env, &scope),
            2_000,
            "second",
            Some(write("second-body")),
        )
        .await;
    assert!(matches!(second, Err(StoreError::IdempotencyConflict)));

    // The stored response is the ORIGINAL, so a replay returns it verbatim.
    let stored = control
        .management()
        .idempotency()
        .lookup("svc_probe", "key-1")
        .await
        .expect("lookup")
        .expect("a stored response exists");
    assert_eq!(stored.response_body, "first-body");

    // Exactly one organization was created (the second create wrote nothing).
    let count = control
        .management()
        .organizations(scope)
        .list(100, None)
        .await
        .expect("list")
        .len();
    assert_eq!(count, 1, "the replayed create did not double-insert");
}

#[tokio::test]
async fn every_mutation_writes_its_audit_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let id = create_org(&db, &env, scope, "audited", 1_000).await;
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete(&env, &id)
        .await
        .expect("delete");

    // The owner pool bypasses row-level security, so it sees the audit rows for
    // both mutations, scoped to this (tenant, environment) and targeting the org.
    let rows = sqlx::query(
        "SELECT action FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND target_id = $3 \
         ORDER BY occurred_at, id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(id.to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read audit rows");
    let actions: Vec<String> = rows.iter().map(|r| r.get::<String, _>("action")).collect();
    assert_eq!(actions, vec!["organization.create", "organization.delete"]);
}
