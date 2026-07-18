// SPDX-License-Identifier: MIT OR Apache-2.0

//! The FedCM assertion-nonce single-use replay store at the storage layer (issue #83),
//! against a real database.
//!
//! These pin the storage-side guarantees the IdP-side FedCM id-assertion endpoint depends
//! on, with that endpoint still UNWIRED (PR 1 ships the store inert; PR 2 consumes it):
//!
//! - reserve / consume round-trips a fresh `(client_id, nonce)` exactly once;
//! - a REPLAYED `(client_id, nonce)` collides on reserve and is refused;
//! - consume is single-use: a second consume of a consumed nonce loses;
//! - an EXPIRED reservation is not consumable;
//! - the nonce is scoped to its `(tenant, environment, client_id)` (a different client or
//!   a different scope never sees another's nonce), so isolation holds.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ClientId, FedcmNonceId, Scope};

/// A far-future expiry (year 2100) in epoch microseconds.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

#[tokio::test]
async fn reserve_then_consume_is_single_use_and_rejects_replay() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = ClientId::generate(&env, &scope);
    let nonce = "fedcm-nonce-abc";

    // First reserve wins (a fresh, never-before-seen nonce).
    let id = FedcmNonceId::generate(&env, &scope);
    let reserved = db
        .store()
        .scoped(scope)
        .fedcm_nonces()
        .reserve(&id, &client, nonce, FAR_FUTURE_MICROS)
        .await
        .expect("reserve fresh nonce");
    assert!(reserved, "the first reserve of a fresh nonce wins");

    // A second reserve of the SAME (client_id, nonce) is a replay: it must not insert a
    // second row and must report the collision.
    let id2 = FedcmNonceId::generate(&env, &scope);
    let replayed = db
        .store()
        .scoped(scope)
        .fedcm_nonces()
        .reserve(&id2, &client, nonce, FAR_FUTURE_MICROS)
        .await
        .expect("reserve replay");
    assert!(
        !replayed,
        "a replayed (client_id, nonce) must not reserve again"
    );

    // Consume wins exactly once.
    let won = db
        .store()
        .scoped(scope)
        .fedcm_nonces()
        .consume(&client, nonce, 0)
        .await
        .expect("consume reserved nonce");
    assert!(won, "the first consume of a reserved, unexpired nonce wins");

    // A second consume of the now-consumed nonce loses (single-use).
    let again = db
        .store()
        .scoped(scope)
        .fedcm_nonces()
        .consume(&client, nonce, 0)
        .await
        .expect("second consume");
    assert!(
        !again,
        "a consumed nonce can never be consumed twice (replay defense)"
    );
}

#[tokio::test]
async fn expired_reservation_is_not_consumable() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = ClientId::generate(&env, &scope);
    let nonce = "fedcm-nonce-expired";

    // Reserve with an expiry at 1000us.
    let id = FedcmNonceId::generate(&env, &scope);
    db.store()
        .scoped(scope)
        .fedcm_nonces()
        .reserve(&id, &client, nonce, 1_000)
        .await
        .expect("reserve short-lived nonce");

    // Consume at a time PAST the expiry loses (the TTL boundary is enforced).
    let won = db
        .store()
        .scoped(scope)
        .fedcm_nonces()
        .consume(&client, nonce, 2_000)
        .await
        .expect("consume expired nonce");
    assert!(!won, "an expired reservation is never consumable");
}

#[tokio::test]
async fn nonce_is_isolated_by_client_and_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client_a = ClientId::generate(&env, &scope);
    let client_b = ClientId::generate(&env, &scope);
    let nonce = "shared-string";

    // Reserve the nonce for client A.
    let id = FedcmNonceId::generate(&env, &scope);
    db.store()
        .scoped(scope)
        .fedcm_nonces()
        .reserve(&id, &client_a, nonce, FAR_FUTURE_MICROS)
        .await
        .expect("reserve for client A");

    // The SAME nonce string is fresh for a DIFFERENT client (the key is
    // (tenant, environment, client_id, nonce)), so client B reserves it independently.
    let id_b = FedcmNonceId::generate(&env, &scope);
    let reserved_b = db
        .store()
        .scoped(scope)
        .fedcm_nonces()
        .reserve(&id_b, &client_b, nonce, FAR_FUTURE_MICROS)
        .await
        .expect("reserve for client B");
    assert!(
        reserved_b,
        "the same nonce string is independent per client_id"
    );

    // Another scope never sees this scope's nonce: consuming client A's nonce under a
    // foreign scope loses (RLS + scope-bound key).
    let other: Scope = db.seed_scope(&env).await;
    let foreign_client = ClientId::generate(&env, &other);
    let won = db
        .store()
        .scoped(other)
        .fedcm_nonces()
        .consume(&foreign_client, nonce, 0)
        .await
        .expect("consume under foreign scope");
    assert!(!won, "a nonce is never consumable from another scope");
}
