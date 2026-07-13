// SPDX-License-Identifier: MIT OR Apache-2.0

//! The cross-tenant and cross-environment IDOR harness, against a real
//! database, over every scoped-repository operation that exists today.

use ironauth_env::Env;
use ironauth_store::idor_harness::IdorHarness;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ClientId, CorrelationId, Scope, StoreError};

#[tokio::test]
async fn idor_harness_denies_cross_tenant_and_cross_environment_uniformly() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // Caller is tenant A, environment A1. Victims: tenant B, and a SECOND
    // environment of tenant A (cross-environment is a distinct probe).
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    // Plant a victim client in each foreign scope (writes need an acting context).
    let victim_b = db
        .store()
        .scoped(scope_b)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "victim in tenant B")
        .await
        .expect("create victim B");
    let victim_a2 = db
        .store()
        .scoped(scope_a2)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "victim in environment A2")
        .await
        .expect("create victim A2");

    // A well-formed identifier in the caller's OWN scope that was never stored.
    let absent_in_a = ClientId::generate(&env, &scope_a).to_string();

    // Baseline for uniformity: in its own scope the caller gets NotFound for the
    // absent identifier. This is the response every foreign probe must match.
    let clients_a = db.store().scoped(scope_a).clients();
    let absent_id = clients_a
        .parse_id(&absent_in_a)
        .expect("absent identifier is well formed and in scope");
    assert!(matches!(
        clients_a.get(&absent_id).await,
        Err(StoreError::NotFound)
    ));

    // Run every registered store probe against the foreign identifiers.
    let mut harness = IdorHarness::new();
    harness.register_store_probes();
    assert_eq!(
        harness.probe_names(),
        vec!["clients.get", "clients.delete"],
        "every scoped-repository resolve-by-id operation is registered"
    );

    let foreign = [
        victim_b.to_string(),
        victim_a2.to_string(),
        // The absent id is included so a leak would show up as a false Denied
        // nowhere and the run stays a strict superset of the real attack.
        absent_in_a.clone(),
    ];
    let foreign_refs: Vec<&str> = foreign.iter().map(String::as_str).collect();
    let leaks = harness.run(db.store(), scope_a, &foreign_refs).await;
    assert!(leaks.is_empty(), "cross-scope leak detected: {leaks:?}");

    // The delete probe must not have leak-deleted the victims: they survive.
    assert!(
        db.store()
            .scoped(scope_b)
            .clients()
            .get(&victim_b)
            .await
            .is_ok(),
        "tenant B's client must survive the delete probe"
    );
    assert!(
        db.store()
            .scoped(scope_a2)
            .clients()
            .get(&victim_a2)
            .await
            .is_ok(),
        "environment A2's client must survive the delete probe"
    );

    // Uniformity at the parse boundary: a cross-tenant identifier and a
    // cross-environment identifier both fail exactly like an absent one.
    assert!(
        matches!(
            clients_a.parse_id(&victim_b.to_string()),
            Err(StoreError::NotFound)
        ),
        "cross-tenant identifier must parse to the uniform NotFound"
    );
    assert!(
        matches!(
            clients_a.parse_id(&victim_a2.to_string()),
            Err(StoreError::NotFound)
        ),
        "cross-environment identifier must parse to the uniform NotFound"
    );
}
