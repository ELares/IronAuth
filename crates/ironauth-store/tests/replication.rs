// SPDX-License-Identifier: MIT OR Apache-2.0

//! The outbox-stream replication shipper, against two real databases (issue #155).
//!
//! The first slice of the multi-region replication: shipping the ordered outbox stream
//! from a home region's database to a follower's, with the per-(tenant, environment)
//! position held on the follower and lag as the difference to the home high-water mark.
//!
//! What is pinned here is the transport contract:
//!
//! * The follower's outbox holds the SAME message rows (by id, payload, order) as the
//!   home stream — order-preserved, because the copy reads home's `sequence` order and
//!   the follower's own identity assigns its drain order in that same order.
//! * The cursor advances to the LAST COPIED HOME SEQUENCE in the same transaction as the
//!   copy, so a retry converges instead of double-copying (the `ON CONFLICT` id no-op).
//! * A fresh follower (no cursor rows) starts from zero and catches up; lag is reported
//!   per partition and drops to zero once the stream is shipped.
//! * A partition with nothing pending is reported with its current lag, not skipped.

use ironauth_env::Env;
use ironauth_store::replication::ReplicationShipper;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{NewOutboxMessage, WEBHOOK_EVENT_CONSUMER};
use sqlx::Row;
use std::time::SystemTime;

/// Enqueue a REAL domain event on `db` under the event feed consumer — the same path the
/// domain writes ride (`enqueue_domain_event` names this consumer), so the rows under
/// test are the actual ordered event stream, validated against the event catalog the
/// way production events are.
async fn append_event(db: &TestDatabase, env: &Env, scope: ironauth_store::Scope, key: &str) {
    let envelope = ironauth_store::event_catalog::envelope(
        key,
        "log_stream.replay_requested",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        0,
        &serde_json::json!({ "log_stream_id": format!("ls_repl_{key}") }),
    )
    .expect("a registered event type");
    db.store()
        .scoped(scope)
        .outbox()
        .append_event(
            env,
            &NewOutboxMessage {
                consumer: WEBHOOK_EVENT_CONSUMER,
                idempotency_key: key,
                ordering_key: "usr_repl_probe",
                payload: envelope,
            },
        )
        .await
        .expect("enqueue the event");
}

/// The follower's message rows, in follower drain order: (`id`, `consumer`, `idempotency_key`,
/// `ordering_key`, `payload`).
async fn follower_stream(
    db: &TestDatabase,
) -> Vec<(String, String, String, String, serde_json::Value)> {
    sqlx::query(
        "SELECT id, consumer, idempotency_key, ordering_key, payload \
         FROM outbox_messages ORDER BY sequence",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("read the follower stream")
    .into_iter()
    .map(|row| {
        (
            row.get("id"),
            row.get("consumer"),
            row.get("idempotency_key"),
            row.get("ordering_key"),
            row.get("payload"),
        )
    })
    .collect()
}

/// THE CONTRACT: home's ordered event stream lands on the follower in order, the cursor
/// tracks the real home positions, and lag drops to zero.
#[tokio::test]
async fn the_ordered_stream_replicates_and_lag_drops_to_zero() {
    let home = TestDatabase::start().await;
    let follower = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0C0A_0001);
    // The SAME deterministic env seeds the SAME (tenant, environment) ids on both
    // databases — the follower's replica must hold the pinned tenants' rows, which is
    // what the FKs require. TWO same-seeded envs, one per database: a SHARED env would
    // advance its entropy across the databases and seed DIFFERENT ids on the follower.
    let (follow_env, _follow_clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0C0A_0001);
    // BOTH scopes are seeded on BOTH databases BEFORE anything enqueues: the enqueue
    // draws message ids off the same env, and a draw between two seeds would shift one
    // database's sequence relative to the other.
    let scope = home.seed_scope(&env).await;
    follower.seed_scope(&follow_env).await;
    let other_scope = home.seed_scope(&env).await;
    follower.seed_scope(&follow_env).await;

    for index in 0..5 {
        append_event(&home, &env, scope, &format!("evt-repl-{index}")).await;
    }
    append_event(&home, &env, other_scope, "evt-repl-other").await;

    let shipper = ReplicationShipper::new(home.owner_pool().clone(), follower.owner_pool().clone());

    // The first pass: the fresh follower catches up.
    let report = shipper.ship(1_000).await.expect("the shipper runs");
    assert_eq!(report.partitions.len(), 2, "both partitions are shipped");
    for partition in &report.partitions {
        assert_eq!(
            partition.lag_messages, 0,
            "after a full pass the lag is zero for {:?}",
            partition.tenant_id
        );
    }

    // The follower holds the same rows. The WITHIN-partition order is the guarantee (the
    // shipper reads home's sequence order per partition); the CROSS-partition interleave
    // on the follower is its own identity sequence, which nothing promises, so the
    // assertion is per partition.
    let stream = follower_stream(&follower).await;
    assert_eq!(stream.len(), 6);
    let keys: Vec<&str> = stream
        .iter()
        .map(|(_, _, key, _, _)| key.as_str())
        .collect();
    assert!(
        keys.windows(5).any(|w| w
            == [
                "evt-repl-0",
                "evt-repl-1",
                "evt-repl-2",
                "evt-repl-3",
                "evt-repl-4"
            ]),
        "the scope's events arrive in home order, contiguously: {keys:?}"
    );
    assert!(
        keys.contains(&"evt-repl-other"),
        "the second partition's event is present"
    );
    for (id, consumer, _key, ordering, payload) in &stream {
        assert_eq!(consumer, WEBHOOK_EVENT_CONSUMER);
        assert_eq!(ordering, "usr_repl_probe");
        assert_eq!(
            payload["type"].as_str(),
            Some("log_stream.replay_requested"),
            "the envelope came over intact"
        );
        assert!(!id.is_empty());
    }

    // A second pass ships nothing new and reports zero lag (the idempotent no-op half).
    let again = shipper.ship(1_000).await.expect("the shipper re-runs");
    for partition in &again.partitions {
        assert_eq!(partition.copied, 0, "nothing new to ship");
        assert_eq!(partition.lag_messages, 0);
    }
    assert_eq!(
        follower_stream(&follower).await.len(),
        6,
        "no double copies"
    );
}

/// RESUMABILITY: an interrupted pass (a batch bound that stops mid-stream) is re-run
/// whole, and the follower converges without duplicates.
#[tokio::test]
async fn a_bounded_pass_is_resumable_and_converges() {
    let home = TestDatabase::start().await;
    let follower = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0C0A_0002);
    let (follow_env, _follow_clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0C0A_0002);
    let scope = home.seed_scope(&env).await;
    follower.seed_scope(&follow_env).await;
    for index in 0..7 {
        append_event(&home, &env, scope, &format!("evt-resume-{index}")).await;
    }
    let shipper = ReplicationShipper::new(home.owner_pool().clone(), follower.owner_pool().clone());

    // A batch bound of 3: the first pass copies only part of the stream.
    let first = shipper.ship(3).await.expect("first pass");
    let partition = first
        .partitions
        .iter()
        .find(|p| p.copied > 0)
        .expect("the partition is shipped");
    assert_eq!(partition.copied, 3);
    assert!(partition.lag_messages > 0, "lag is reported mid-catch-up");

    // The second pass continues from the follower's position.
    let second = shipper.ship(3).await.expect("second pass");
    let partition = second
        .partitions
        .iter()
        .find(|p| p.copied > 0)
        .expect("the partition continues");
    assert_eq!(partition.copied, 3);

    // The third pass finishes the stream, and the follower has all seven in order,
    // with no duplicates from the retried boundaries.
    let third = shipper.ship(1_000).await.expect("third pass");
    for partition in &third.partitions {
        assert_eq!(partition.lag_messages, 0);
    }
    let stream = follower_stream(&follower).await;
    assert_eq!(stream.len(), 7);
    assert_eq!(stream[6].2, "evt-resume-6");
}
