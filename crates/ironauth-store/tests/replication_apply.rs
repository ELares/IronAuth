// SPDX-License-Identifier: MIT OR Apache-2.0

//! The follower's event-APPLY, against two real databases (issue #155).
//!
//! The shipper tests prove the ordered stream lands on the follower; this is the other
//! half of the acceptance criterion — "users, credentials, and environment config
//! created in the home region are queryable in the follower within the configured lag
//! bound, verified by an integration test." A user registered in the home region, its
//! `user.created` event shipped, and the apply run makes the user QUERYABLE on the
//! follower through the same read path the runtime uses.
//!
//! The copy rides `row_to_json` + `json_populate_record`, so the sealed columns, the
//! blind indexes, and the password hash all travel byte-for-byte — the drift gate: a
//! migration that changes a replicated table's shape is exercised by this test.

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::replication::ReplicationShipper;
use ironauth_store::replication_apply::{apply_envelopes, shipped_domain_events};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, NewOutboxMessage, WEBHOOK_EVENT_CONSUMER};

/// THE ACCEPTANCE CRITERION'S INTEGRATION TEST: a home-region user becomes queryable
/// on the follower within the replication pass.
#[tokio::test]
async fn a_home_user_is_queryable_on_the_follower_after_ship_and_apply() {
    let home = TestDatabase::start().await;
    let follower = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0F0A_01);
    let (follow_env, _follow_clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0F0A_01);
    let scope = home.seed_scope(&env).await;
    follower.seed_scope(&follow_env).await;

    // A real user in the home region, through the same registration path the login
    // surface uses.
    const PHC_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo";
    let (actor, corr) = (home.test_actor(&env), CorrelationId::generate(&env));
    let user_id = home
        .store()
        .scoped(scope)
        .acting(actor, corr)
        .users()
        .register(&env, "alice@example.test", PHC_HASH, None)
        .await
        .expect("register the home user");

    // The domain event the mutation would emit, on the home stream.
    let envelope = ironauth_store::event_catalog::envelope(
        "evt-apply-user",
        "user.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        0,
        &serde_json::json!({ "user_id": user_id.to_string(), "state": "active" }),
    )
    .expect("a registered event type");
    home.store()
        .scoped(scope)
        .outbox()
        .append_event(
            &env,
            &NewOutboxMessage {
                consumer: WEBHOOK_EVENT_CONSUMER,
                idempotency_key: "evt-apply-user",
                ordering_key: &user_id.to_string(),
                payload: envelope,
            },
        )
        .await
        .expect("enqueue the event");

    // SHIP the ordered stream, then APPLY it on the follower.
    let shipper = ReplicationShipper::new(home.owner_pool().clone(), follower.owner_pool().clone());
    let ship = shipper.ship(1_000).await.expect("the stream ships");
    assert_eq!(ship.partitions.len(), 1);
    assert_eq!(ship.partitions[0].lag_messages, 0, "caught up");

    let events = shipped_domain_events(follower.owner_pool())
        .await
        .expect("the follower's shipped domain events");
    assert_eq!(events.len(), 1, "one domain event on the follower");
    let apply = apply_envelopes(home.owner_pool(), follower.owner_pool(), &events)
        .await
        .expect("the apply runs");
    assert_eq!(apply.applied.len(), 1);
    assert_eq!(
        apply.applied[0].copied.as_deref(),
        Some("users"),
        "the user's row was copied"
    );

    // THE CRITERION: the user is QUERYABLE on the follower through the same read path
    // the runtime uses, with the same identity and the same credential hash.
    let replicated = follower
        .store()
        .scoped(scope)
        .users()
        .by_identifier("alice@example.test")
        .await
        .expect("the follower read runs")
        .expect("the user resolves on the follower");
    assert_eq!(
        replicated.id, user_id,
        "the follower serves the SAME user the home created"
    );
    assert_eq!(
        replicated.password_hash.as_str(),
        PHC_HASH,
        "the credential hash travelled intact"
    );

    // RE-APPLY converges (the upsert is idempotent), and the follower still has one user.
    let again = apply_envelopes(home.owner_pool(), follower.owner_pool(), &events)
        .await
        .expect("the re-apply runs");
    assert_eq!(again.applied.len(), 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(follower.owner_pool())
        .await
        .expect("count the follower users");
    assert_eq!(count, 1, "a re-apply must not duplicate");
}
