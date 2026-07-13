// SPDX-License-Identifier: MIT OR Apache-2.0

//! Repository round-trip and non-recycling, against a real database.

use std::collections::HashSet;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, StoreError};

#[tokio::test]
async fn create_get_list_delete_round_trip() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Reads need no actor; writes go through an acting context.
    let reader = db.store().scoped(scope).clients();
    let actor = db.test_actor(&env);
    let writer = db
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(&env))
        .clients();

    // Create returns a typed identifier that round-trips through the scoped
    // parser (the request-layer boundary).
    let id = writer.create(&env, "acme web").await.expect("create");
    let parsed = reader.parse_id(&id.to_string()).expect("parse in scope");
    assert_eq!(parsed, id);
    assert_eq!(id.scope(), scope, "the identifier embeds its scope");

    // Get.
    let record = reader.get(&id).await.expect("get");
    assert_eq!(record.id, id);
    assert_eq!(record.display_name, "acme web");

    // List.
    let all = reader.list().await.expect("list");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, id);

    // Delete, then the row is gone and the outcome is the uniform not-found.
    writer.delete(&env, &id).await.expect("delete");
    assert!(matches!(reader.get(&id).await, Err(StoreError::NotFound)));
    assert!(matches!(
        writer.delete(&env, &id).await,
        Err(StoreError::NotFound)
    ));
    assert!(reader.list().await.expect("list").is_empty());
}

#[tokio::test]
async fn identifiers_are_never_recycled_after_deletion() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let writer = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients();

    // Create then delete many; remember every identifier ever issued.
    let mut ever_issued = HashSet::new();
    for _ in 0..200 {
        let id = writer.create(&env, "ephemeral").await.expect("create");
        writer.delete(&env, &id).await.expect("delete");
        assert!(
            ever_issued.insert(id.to_string()),
            "an identifier was issued twice"
        );
    }

    // A fresh batch never collides with any deleted identifier: no serial
    // reuse, no recycled-identifier leakage.
    for _ in 0..200 {
        let id = writer.create(&env, "fresh").await.expect("create");
        assert!(
            !ever_issued.contains(&id.to_string()),
            "a deleted identifier was recycled"
        );
    }
}

/// A management list at the hard cap keeps its has-next sentinel: with
/// `HARD_CAP + 1` rows present, a fetch of `HARD_CAP + 1` (the page size at the
/// cap, plus one for the sentinel) returns all `HARD_CAP + 1`. Before the store
/// clamped the fetch to `HARD_CAP + 1` (rather than `HARD_CAP`), the sentinel was
/// dropped and the final page hidden.
#[tokio::test]
async fn management_list_at_the_hard_cap_keeps_the_has_next_sentinel() {
    use ironauth_store::{MANAGEMENT_LIST_HARD_CAP, ManagementKeyId};

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Insert HARD_CAP + 1 credentials as the owner (a superuser, so it bypasses
    // row-level security), in one bulk statement via UNNEST.
    let n = usize::try_from(MANAGEMENT_LIST_HARD_CAP).expect("cap fits usize") + 1;
    let ids: Vec<String> = (0..n)
        .map(|_| ManagementKeyId::generate(&env, &scope).to_string())
        .collect();
    let tenants = vec![scope.tenant().to_string(); n];
    let environments = vec![scope.environment().to_string(); n];
    let hashes: Vec<String> = (0..n).map(|i| format!("hash-{i}")).collect();
    let names: Vec<String> = (0..n).map(|i| format!("key-{i}")).collect();
    sqlx::query(
        "INSERT INTO management_credentials \
         (id, tenant_id, environment_id, key_hash, display_name) \
         SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[])",
    )
    .bind(ids)
    .bind(tenants)
    .bind(environments)
    .bind(hashes)
    .bind(names)
    .execute(db.owner_pool())
    .await
    .expect("bulk insert credentials");

    // The admin layer fetches page_size + 1; at a page size of HARD_CAP that is
    // HARD_CAP + 1. The store must return all of them (the extra row is the
    // sentinel that tells the admin layer a further page exists).
    let rows = db
        .control_store()
        .management()
        .credentials(scope)
        .list(MANAGEMENT_LIST_HARD_CAP + 1, None)
        .await
        .expect("list at the hard cap");
    assert_eq!(
        rows.len(),
        n,
        "the has-next sentinel survives at a page size equal to the hard cap"
    );
}
