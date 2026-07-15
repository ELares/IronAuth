// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management-plane IDOR probes, registered with the #6 harness and run
//! against a real database. A management key resolved by id under one scope must
//! never reach a key minted in another tenant or environment.

use ironauth_env::Env;
use ironauth_store::idor_harness::IdorHarness;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, ManagementKeyId, OrganizationId, Scope, ServiceId, StoreError,
};

/// A stand-in key hash for a planted victim (the probes resolve by id, not hash).
const VICTIM_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[tokio::test]
async fn management_probes_deny_cross_tenant_and_cross_environment_uniformly() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let control = db.control_store();

    // Caller is tenant A, environment A1. Victims: tenant B, and a second
    // environment of tenant A (cross-environment is a distinct probe).
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    let victim_b = plant_key(control, &env, scope_b).await;
    let victim_a2 = plant_key(control, &env, scope_a2).await;

    // Organizations are the fourth level (issue #41): plant a victim in each
    // foreign scope so the organization probes have a real cross-scope target.
    let victim_org_b = plant_org(control, &env, scope_b).await;
    let victim_org_a2 = plant_org(control, &env, scope_a2).await;

    // A well-formed key id in the caller's OWN scope that was never stored.
    let absent_in_a = ManagementKeyId::generate(&env, &scope_a).to_string();

    // Baseline for uniformity: the absent id is NotFound in the caller's scope.
    let credentials_a = control.management().credentials(scope_a);
    let absent_id = credentials_a
        .parse_id(&absent_in_a)
        .expect("absent id is well formed and in scope");
    assert!(matches!(
        credentials_a.get(&absent_id).await,
        Err(StoreError::NotFound)
    ));

    let mut harness = IdorHarness::new();
    harness.register_management_probes();
    assert_eq!(
        harness.probe_names(),
        vec![
            "management_credentials.get",
            "management_credentials.delete",
            "organizations.get",
            "organizations.delete",
        ],
        "every management resolve-by-id operation is registered",
    );

    let foreign = [
        victim_b.to_string(),
        victim_a2.to_string(),
        victim_org_b.to_string(),
        victim_org_a2.to_string(),
        absent_in_a.clone(),
    ];
    let foreign_refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(control, scope_a, &foreign_refs).await;
    assert!(leaks.is_empty(), "cross-scope leak detected: {leaks:?}");

    // The delete probe must not have leak-deleted the victims: they survive.
    assert!(
        control
            .management()
            .credentials(scope_b)
            .get(&victim_b)
            .await
            .is_ok(),
        "tenant B's key must survive the delete probe"
    );
    assert!(
        control
            .management()
            .credentials(scope_a2)
            .get(&victim_a2)
            .await
            .is_ok(),
        "environment A2's key must survive the delete probe"
    );

    // The victim organizations must likewise survive: the organizations.delete
    // probe must not have leak-deactivated a foreign-scope row.
    assert!(
        control
            .management()
            .organizations(scope_b)
            .get(&victim_org_b)
            .await
            .is_ok(),
        "tenant B's organization must survive the delete probe"
    );
    assert!(
        control
            .management()
            .organizations(scope_a2)
            .get(&victim_org_a2)
            .await
            .is_ok(),
        "environment A2's organization must survive the delete probe"
    );
}

/// Plant a live organization in `scope` via the control store.
async fn plant_org(control: &ironauth_store::Store, env: &Env, scope: Scope) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, 1_000_000, "victim organization", None)
        .await
        .expect("plant victim organization");
    id
}

/// Plant a live management key in `scope` via the control store.
async fn plant_key(control: &ironauth_store::Store, env: &Env, scope: Scope) -> ManagementKeyId {
    let id = ManagementKeyId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    control
        .management()
        .acting(actor, CorrelationId::generate(env))
        .credentials(scope)
        .create(env, &id, 1_000_000, VICTIM_HASH, "victim key", None)
        .await
        .expect("plant victim key");
    id
}
