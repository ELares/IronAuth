// SPDX-License-Identifier: MIT OR Apache-2.0

//! Repository round-trip and non-recycling, against a real database.

use std::collections::HashSet;

use ironauth_env::Env;
use ironauth_store::StoreError;
use ironauth_store::test_support::TestDatabase;

#[tokio::test]
async fn create_get_list_delete_round_trip() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let clients = db.store().scoped(scope).clients();

    // Create returns a typed identifier that round-trips through the scoped
    // parser (the request-layer boundary).
    let id = clients.create(&env, "acme web").await.expect("create");
    let parsed = clients.parse_id(&id.to_string()).expect("parse in scope");
    assert_eq!(parsed, id);
    assert_eq!(id.scope(), scope, "the identifier embeds its scope");

    // Get.
    let record = clients.get(&id).await.expect("get");
    assert_eq!(record.id, id);
    assert_eq!(record.display_name, "acme web");

    // List.
    let all = clients.list().await.expect("list");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, id);

    // Delete, then the row is gone and the outcome is the uniform not-found.
    clients.delete(&id).await.expect("delete");
    assert!(matches!(clients.get(&id).await, Err(StoreError::NotFound)));
    assert!(matches!(
        clients.delete(&id).await,
        Err(StoreError::NotFound)
    ));
    assert!(clients.list().await.expect("list").is_empty());
}

#[tokio::test]
async fn identifiers_are_never_recycled_after_deletion() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let clients = db.store().scoped(scope).clients();

    // Create then delete many; remember every identifier ever issued.
    let mut ever_issued = HashSet::new();
    for _ in 0..200 {
        let id = clients.create(&env, "ephemeral").await.expect("create");
        clients.delete(&id).await.expect("delete");
        assert!(
            ever_issued.insert(id.to_string()),
            "an identifier was issued twice"
        );
    }

    // A fresh batch never collides with any deleted identifier: no serial
    // reuse, no recycled-identifier leakage.
    for _ in 0..200 {
        let id = clients.create(&env, "fresh").await.expect("create");
        assert!(
            !ever_issued.contains(&id.to_string()),
            "a deleted identifier was recycled"
        );
    }
}
