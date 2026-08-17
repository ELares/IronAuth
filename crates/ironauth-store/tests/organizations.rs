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
    // The containment property this test exists for is unchanged: the insert is REFUSED
    // by the foreign key. What changed is the shape the store reports it with (issues
    // #409, #449): a write into a scope that was never created is now the uniform
    // not-found rather than a database FAULT, because the difference between the two was
    // an environment existence oracle on the unauthenticated data plane.
    //
    // The variant alone no longer identifies WHICH refusal this is. `Database` could
    // only have come from Postgres; `NotFound` is also what an early guard returns, so
    // this assertion on its own would be satisfied by a create that declined before it
    // reached the constraint. The control below is what keeps the foreign key as the
    // thing being measured.
    assert!(
        matches!(result, Err(StoreError::NotFound)),
        "an organization under a nonexistent environment must be refused as the uniform \
         not-found, got {result:?}"
    );

    // THE CONTROL: the SAME create, differing only in that its scope was seeded,
    // succeeds. Without it a store that refused every create would pass this test.
    let seeded = db.seed_scope(&env).await;
    let live_id = OrganizationId::generate(&env, &seeded);
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(seeded)
        .create(&env, &live_id, 1_000, "control", None)
        .await
        .expect(
            "the same create into a SEEDED scope must succeed, or the refusal above is \
             the store declining to write rather than containment holding",
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

/// Creating and deleting an organization each emit their registered event, in the SAME
/// transaction as the write (issue #108).
///
/// Both are asserted in one test because the pair is the point: a receiver that saw creates
/// and no deletes would hold organizations that no longer exist, which is worse than seeing
/// neither.
#[tokio::test]
async fn organization_writes_emit_their_registered_events() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = OrganizationId::generate(&env, &scope);

    assert_eq!(
        webhook_events(&db, scope).await.len(),
        0,
        "nothing is queued before the writes"
    );

    let created = envelope_for(
        scope,
        "evt_org_created",
        "organization.created",
        &serde_json::json!({ "organization_id": id.to_string(), "display_name": "Acme" }),
    );
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create_with_event(
            &env,
            &id,
            1_000,
            "Acme",
            None,
            Some(&ironauth_store::DomainEvent {
                id: "evt_org_created",
                subject: &id.to_string(),
                envelope: &created,
            }),
        )
        .await
        .expect("create with event");

    let deleted = envelope_for(
        scope,
        "evt_org_deleted",
        "organization.deleted",
        &serde_json::json!({ "organization_id": id.to_string() }),
    );
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete_with_event(
            &env,
            &id,
            Some(&ironauth_store::DomainEvent {
                id: "evt_org_deleted",
                subject: &id.to_string(),
                envelope: &deleted,
            }),
        )
        .await
        .expect("delete with event");

    // ONE at a time, and that is the ordering guarantee rather than a limitation. Both events
    // carry the organization as their ordering key, so the outbox will not hand out the
    // delete while the create is still outstanding -- a receiver must never learn an
    // organization was deleted before it learns it existed. Discovered here: the first
    // version of this test claimed once and asserted both, and got only the create.
    let first = claim_one(&db, scope).await.expect("the create is queued");
    assert_eq!(
        first.payload["type"], "organization.created",
        "{:?}",
        first.payload
    );
    assert_eq!(first.payload["payload"]["display_name"], "Acme");
    ironauth_store::event_catalog::validate_event(&first.payload)
        .expect("the create envelope validates against the registry the fan-out enforces");

    assert!(
        claim_one(&db, scope).await.is_none(),
        "the delete must not be handed out while the create is outstanding"
    );

    db.store()
        .scoped(scope)
        .outbox()
        .complete(&Env::system(), &first)
        .await
        .expect("complete the create");

    let second = claim_one(&db, scope).await.expect("the delete follows it");
    assert_eq!(
        second.payload["type"], "organization.deleted",
        "{:?}",
        second.payload
    );
    assert_eq!(second.payload["payload"]["organization_id"], id.to_string());
    ironauth_store::event_catalog::validate_event(&second.payload)
        .expect("the delete envelope validates against the registry the fan-out enforces");
}

/// One claimable webhook event, or `None` when nothing is available.
async fn claim_one(db: &TestDatabase, scope: Scope) -> Option<ironauth_store::OutboxMessage> {
    use std::time::Duration;

    db.store()
        .scoped(scope)
        .outbox()
        .claim(
            &Env::system(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim webhook events")
        .into_iter()
        .next()
}

/// The un-suffixed methods emit nothing.
///
/// The paired negative, and it guards a specific hazard of the delegating-wrapper shape: if
/// `create` ever stopped passing `None` and started inventing an event, every internal
/// provisioning path and every test would begin emitting one.
#[tokio::test]
async fn the_plain_organization_writes_emit_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let id = create_org(&db, &env, scope, "Quiet", 1_000).await;

    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .delete(&env, &id)
        .await
        .expect("delete");

    assert_eq!(
        webhook_events(&db, scope).await.len(),
        0,
        "create and delete without an event must not invent one"
    );
}

fn envelope_for(
    scope: Scope,
    id: &str,
    event_type: &str,
    payload: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "type": event_type,
        "payload_schema_version": 1,
        "occurred_at_unix_ms": 1_i64,
        "tenant_id": scope.tenant().to_string(),
        "environment_id": scope.environment().to_string(),
        "payload": payload,
    })
}

/// Every webhook-event envelope currently queued in `scope`, oldest first.
async fn webhook_events(db: &TestDatabase, scope: Scope) -> Vec<serde_json::Value> {
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

/// The envelope builder stamps the version the REGISTRY declares, and refuses an
/// unregistered type (issue #108).
///
/// This is the seam that makes a producer possible from any crate. Getting it wrong is quiet:
/// a hand-passed version that disagrees with the registry produces an event the fan-out
/// refuses PERMANENTLY at delivery, so the write succeeds and the notice never arrives.
#[tokio::test]
async fn the_envelope_builder_takes_its_version_from_the_registry() {
    let built = ironauth_store::event_catalog::envelope(
        "evt_1",
        "client.deleted",
        "ten_x",
        "env_y",
        1_700_000_000_000,
        &serde_json::json!({ "client_id": "cli_1" }),
    )
    .expect("a registered type builds");

    let registered = ironauth_store::event_catalog::registered("client.deleted")
        .expect("client.deleted is registered");
    assert_eq!(
        built["payload_schema_version"].as_u64(),
        Some(u64::from(registered.payload_version)),
        "the stamped version is the registry's, not a constant"
    );
    // The whole point: what it builds is what the fan-out accepts.
    ironauth_store::event_catalog::validate_event(&built)
        .expect("a built envelope validates against the registry that supplied its version");

    // An unregistered type yields nothing rather than an envelope the fan-out would refuse.
    assert!(
        ironauth_store::event_catalog::envelope(
            "evt_2",
            "client.invented",
            "ten_x",
            "env_y",
            0,
            &serde_json::json!({}),
        )
        .is_none(),
        "an unregistered type must not produce an envelope"
    );
}

/// A payload carrying a field its schema does not declare is REFUSED (issue #108,
/// criterion 1).
///
/// Criterion 1 says every emitted event "validates against its registered schema". That was
/// weaker than it read: JSON Schema permits undeclared properties unless a schema forbids
/// them, so a payload could carry anything at all and still validate. MEASURED before the
/// fix, on `environment_variable.deleted`: adding the removed variable's VALUE to the payload
/// left validation passing, and only a hand-written search caught the leak.
///
/// Every registered payload schema now sets `additionalProperties: false`, so "it validates"
/// means the fields are exactly the declared ones. This test is what keeps that true: it is
/// asserted per registered type rather than on one example, because a schema added later
/// without the line is exactly how the hole reopens.
#[tokio::test]
async fn no_registered_payload_accepts_an_undeclared_field() {
    let registry = ironauth_store::event_catalog::registry();
    assert!(
        registry.len() >= 19,
        "the registry shrank; this test's denominator must not silently fall: {}",
        registry.len()
    );

    for registered in registry {
        let schema: serde_json::Value = serde_json::from_str(&registered.payload_schema)
            .expect("a registered payload schema parses");
        assert_eq!(
            schema["additionalProperties"],
            serde_json::json!(false),
            "{} does not forbid undeclared fields, so anything could ride along in its payload",
            registered.wire
        );

        // And prove it through the ACTUAL validator, not just by reading the schema: a
        // property present in the text but ignored by the compiler would pass the assertion
        // above and fail nothing.
        let mut payload = serde_json::Map::new();
        if let Some(properties) = schema["properties"].as_object() {
            for (name, property) in properties {
                let filler = match property["type"].as_str() {
                    Some("boolean") => serde_json::json!(false),
                    Some("array") => serde_json::json!(["claims"]),
                    _ => serde_json::json!("x"),
                };
                payload.insert(name.clone(), filler);
            }
        }
        payload.insert(
            "smuggled".to_owned(),
            serde_json::json!("should be refused"),
        );

        let envelope = serde_json::json!({
            "id": "evt_probe",
            "type": registered.wire,
            "payload_schema_version": registered.payload_version,
            "occurred_at_unix_ms": 1_i64,
            "tenant_id": "ten_x",
            "environment_id": "env_y",
            "payload": serde_json::Value::Object(payload),
        });
        assert!(
            ironauth_store::event_catalog::validate_event(&envelope).is_err(),
            "{} accepted an undeclared `smuggled` field: {envelope}",
            registered.wire
        );
    }
}
