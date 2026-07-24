// SPDX-License-Identifier: MIT OR Apache-2.0

//! The cross-node `DPoP` proof `jti` replay store (issue #368, resource-server
//! verify), over a real database (`DATABASE_URL`).
//!
//! Proves the single-use latch across two independent store handles (two nodes on
//! one database, the second use rejected), that the same `(jkt, jti)` under a
//! DIFFERENT key or in a DIFFERENT scope is fresh, the safe on-insert prune (a jti
//! is reclaimed only once its freshness window has passed), and the RLS scoping
//! (another scope's identical `(jkt, jti)` is independent and invisible).

use std::time::Duration;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{Scope, Store};

/// A far-future expiry (year 2100) in epoch microseconds, so a recorded `(jkt, jti)`
/// is never pruned before a test means it to be.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Check-and-record `(jkt, jti)` in `scope` with a far-future expiry. Returns `true`
/// when fresh (recorded), `false` when a replay.
async fn check(store: &Store, env: &Env, scope: Scope, jkt: &str, jti: &str) -> bool {
    store
        .scoped(scope)
        .dpop_replay()
        .check_and_record(env, jkt, jti, FAR_FUTURE_MICROS)
        .await
        .expect("check_and_record")
}

/// Check-and-record with an explicit expiry, for the prune test.
async fn check_expiring(
    store: &Store,
    env: &Env,
    scope: Scope,
    jkt: &str,
    jti: &str,
    expires_at_micros: i64,
) -> bool {
    store
        .scoped(scope)
        .dpop_replay()
        .check_and_record(env, jkt, jti, expires_at_micros)
        .await
        .expect("check_and_record")
}

#[tokio::test]
async fn a_jti_is_single_use_across_two_store_handles_on_one_database() {
    // Two store handles over the SAME database simulate two server nodes: the second
    // use of a (jkt, jti) must be rejected by the shared primary key, not by any
    // in-memory state. This is exactly the cross-instance replay the in-memory cache
    // cannot catch at a resource server.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x51);
    let scope = db.seed_scope(&env).await;

    let node_a: Store = db.store().clone();
    let node_b: Store = Store::from_pool(db.app_pool().clone());

    assert!(
        check(&node_a, &env, scope, "jkt-x", "jti-shared").await,
        "first sight on node A is fresh"
    );
    assert!(
        !check(&node_b, &env, scope, "jkt-x", "jti-shared").await,
        "a second node cannot reuse a (jkt, jti)"
    );

    // A different jti, and the same jti under a DIFFERENT key, are both fresh: a jti
    // is only ever a replay under the SAME key.
    assert!(
        check(&node_b, &env, scope, "jkt-x", "jti-other").await,
        "a distinct jti is fresh"
    );
    assert!(
        check(&node_a, &env, scope, "jkt-y", "jti-shared").await,
        "the same jti under a different key is fresh"
    );
}

#[tokio::test]
async fn a_replayed_jti_in_another_scope_is_not_a_conflict() {
    // The replay store is RLS-scoped: the same (jkt, jti) in a different (tenant,
    // environment) is a fresh, independent single use, never a cross-scope clash and
    // never visible across the scope boundary.
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x52);
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;

    assert!(check(db.store(), &env, scope_a, "jkt-x", "jti-1").await);
    assert!(
        !check(db.store(), &env, scope_a, "jkt-x", "jti-1").await,
        "the same scope replays"
    );
    assert!(
        check(db.store(), &env, scope_b, "jkt-x", "jti-1").await,
        "another scope is independent (RLS isolation)"
    );
    // And the second scope now replays its own, while the first is still latched.
    assert!(!check(db.store(), &env, scope_b, "jkt-x", "jti-1").await);
    assert!(!check(db.store(), &env, scope_a, "jkt-x", "jti-1").await);
}

#[tokio::test]
async fn the_prune_reclaims_a_jti_only_after_its_freshness_window_has_passed() {
    // A (jkt, jti) stays single-use while its proof could still pass the freshness
    // window, and is reclaimed only once its stored expiry has passed, so pruning
    // never opens a window for a still-fresh proof.
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x53);
    let scope = db.seed_scope(&env).await;

    // Record jti-A expiring one second from the epoch (the clock's start).
    let expires = 1_000_000_i64;
    assert!(check_expiring(db.store(), &env, scope, "jkt-x", "jti-A", expires).await);
    // While still within its window, a replay is rejected.
    assert!(
        !check_expiring(db.store(), &env, scope, "jkt-x", "jti-A", expires).await,
        "still within the freshness window"
    );

    // Advance the clock past the window. Recording ANY (jkt, jti) now prunes the
    // expired jti-A first, so jti-A becomes re-insertable (a proof still carrying it
    // would itself fail the freshness check).
    clock.advance(Duration::from_secs(5));
    assert!(check_expiring(db.store(), &env, scope, "jkt-x", "jti-B", FAR_FUTURE_MICROS).await);
    assert!(
        check_expiring(db.store(), &env, scope, "jkt-x", "jti-A", FAR_FUTURE_MICROS).await,
        "an expired (jkt, jti) is reclaimed by the prune"
    );
}
