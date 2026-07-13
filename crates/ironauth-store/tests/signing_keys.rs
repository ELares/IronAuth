// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment signing-key persistence and isolation (issue #19), over a
//! real database (`DATABASE_URL`).
//!
//! Proves acceptance criterion 1 at the persistence layer: two environments of
//! the SAME tenant, and two DIFFERENT tenants, have provably disjoint key sets
//! (no `kid` and no key-material overlap), a cross-scope key read is refused with
//! the uniform not-found, and every provision writes its audit row.

use std::collections::HashSet;

use ironauth_env::Env;
use ironauth_store::idor_harness::IdorHarness;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewSigningKey, Scope, SigningKeyId, SigningKeyMaterialKind, StoreError,
};

/// Provision one Ed25519 signing key in `scope`, drawing distinct 32-byte
/// material from the entropy seam. Returns the key's id (its `kid`) and material.
async fn provision_ed25519(db: &TestDatabase, env: &Env, scope: Scope) -> (SigningKeyId, Vec<u8>) {
    let id = SigningKeyId::generate(env, &scope);
    let mut material = [0_u8; 32];
    env.entropy().fill_bytes(&mut material);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .signing_keys()
        .provision(
            env,
            NewSigningKey {
                id: &id,
                algorithm: "EdDSA",
                material_kind: SigningKeyMaterialKind::Ed25519Seed,
                material: &material,
                publish_at_micros: 0,
                activate_at_micros: 0,
                retire_at_micros: None,
                expire_at_micros: None,
            },
        )
        .await
        .expect("provision signing key");
    (id, material.to_vec())
}

#[tokio::test]
async fn signing_key_sets_are_disjoint_across_environments_and_tenants() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // Tenant A, environment A1; a SECOND environment A2 of the same tenant; and a
    // wholly separate tenant B.
    let scope_a1 = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a1.tenant()).await;
    let scope_a2 = Scope::new(scope_a1.tenant(), env_a2);
    let scope_b = db.seed_scope(&env).await;

    // Provision two keys per scope.
    let mut kids: HashSet<String> = HashSet::new();
    let mut materials: HashSet<Vec<u8>> = HashSet::new();
    let mut total = 0;
    for scope in [scope_a1, scope_a2, scope_b] {
        for _ in 0..2 {
            let (id, material) = provision_ed25519(&db, &env, scope).await;
            assert!(kids.insert(id.to_string()), "kid collision across issuers");
            assert!(
                materials.insert(material),
                "key material overlap across issuers"
            );
            total += 1;
        }
    }
    assert_eq!(total, 6);
    assert_eq!(kids.len(), 6, "every kid is unique across all issuers");
    assert_eq!(materials.len(), 6, "every key material is disjoint");

    // Each scope's repository returns ONLY its own two keys, never another
    // scope's. This is the structural disjointness: the lookup is scope-bound.
    for scope in [scope_a1, scope_a2, scope_b] {
        let keys = db
            .store()
            .scoped(scope)
            .signing_keys()
            .list()
            .await
            .expect("list keys");
        assert_eq!(keys.len(), 2, "each issuer sees exactly its own keys");
        for key in &keys {
            assert_eq!(key.id.scope(), scope, "listed key is in the caller scope");
            assert_eq!(key.algorithm, "EdDSA");
        }
    }
}

#[tokio::test]
async fn a_cross_scope_signing_key_read_is_a_uniform_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    // Victims: a real key in tenant B, and one in a second environment of tenant A.
    let (victim_b, _) = provision_ed25519(&db, &env, scope_b).await;
    let (victim_a2, _) = provision_ed25519(&db, &env, scope_a2).await;

    // A well-formed key id in the caller's OWN scope that was never stored. In its
    // own scope the caller gets the uniform not-found; every cross-scope probe
    // must match exactly this.
    let absent = SigningKeyId::generate(&env, &scope_a);
    let keys_a = db.store().scoped(scope_a).signing_keys();
    assert!(matches!(
        keys_a.get(&absent).await,
        Err(StoreError::NotFound)
    ));

    // The IDOR harness signing-key probe: every foreign id is denied uniformly.
    let mut harness = IdorHarness::new();
    harness.register_signing_key_probes();
    assert_eq!(harness.probe_names(), vec!["signing_keys.get"]);
    let foreign_ids = [
        victim_b.to_string(),
        victim_a2.to_string(),
        absent.to_string(),
        "sik_not-base64-!!".to_owned(),
    ];
    let refs: Vec<&str> = foreign_ids.iter().map(String::as_str).collect();
    let leaks = harness.run(db.store(), scope_a, &refs).await;
    assert!(leaks.is_empty(), "cross-scope signing-key leaks: {leaks:?}");
}

#[tokio::test]
async fn provisioning_a_signing_key_writes_its_audit_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let (id, _) = provision_ed25519(&db, &env, scope).await;

    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("list audit");
    let provision_rows: Vec<_> = audit
        .iter()
        .filter(|row| row.action == "signing_key.provision")
        .collect();
    assert_eq!(provision_rows.len(), 1, "exactly one provision audit row");
    assert_eq!(provision_rows[0].target_kind, "sik");
    assert_eq!(provision_rows[0].target_id, id.to_string());
}
