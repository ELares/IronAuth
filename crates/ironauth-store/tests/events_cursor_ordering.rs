// SPDX-License-Identifier: MIT OR Apache-2.0

//! A cursor over `sequence` skips events; a cursor gated on a visibility watermark does
//! not (issue #107).
//!
//! #107's first acceptance criterion is that replay from an arbitrary cursor yields
//! identical ordering across repeated reads, and its What section forbids silent gaps. A
//! cursor over `outbox_messages.sequence` delivers neither, for a reason `outbox.rs`
//! already documents about itself: sequences are assigned at INSERT, visibility happens at
//! COMMIT, and Postgres holds no lock across the gap. Two overlapping writers can therefore
//! commit in the opposite order to their sequences.
//!
//! The outbox survives that because it is CLAIM-based: a message that appears late is still
//! claimable, so out-of-order commit costs ordering and never delivery. A cursor reader has
//! no such protection. It advances a high-water mark, and an event that becomes visible
//! below that mark is never returned again.
//!
//! This file exists because that failure is invisible in ordinary testing. It needs two
//! overlapping writers and a specific interleaving, so it passes every single-writer test
//! and fails in production under load. The first test REPRODUCES the skip rather than
//! assuming it, so the second test's fix is measured against a demonstrated defect.

#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use sqlx::Row;

/// Seed a real (tenant, environment) so the table's foreign keys are satisfied.
async fn seeded_scope(db: &TestDatabase, env: &Env) -> (String, String) {
    let scope = db.seed_scope(env).await;
    (scope.tenant().to_string(), scope.environment().to_string())
}

/// Insert one outbox row inside `tx`, returning its assigned sequence.
///
/// The sequence is read back inside the transaction, which is the whole point: it is
/// assigned NOW, while the row is still invisible to everyone else.
async fn insert_returning_sequence(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    environment: &str,
    id: &str,
) -> i64 {
    let row = sqlx::query(
        "INSERT INTO outbox_messages \
         (id, tenant_id, environment_id, consumer, idempotency_key, ordering_key, payload, \
          next_attempt_at, enqueued_at) \
         VALUES ($1, $2, $3, 'events-test', $1, 'k', '{}'::jsonb, now(), now()) \
         RETURNING sequence",
    )
    .bind(id)
    .bind(tenant)
    .bind(environment)
    .fetch_one(&mut **tx)
    .await
    .expect("insert");
    row.get::<i64, _>("sequence")
}

/// The NAIVE read every cursor API reaches for first.
async fn read_after_naive(pool: &sqlx::PgPool, after: i64) -> Vec<i64> {
    sqlx::query("SELECT sequence FROM outbox_messages WHERE sequence > $1 ORDER BY sequence")
        .bind(after)
        .fetch_all(pool)
        .await
        .expect("naive read")
        .iter()
        .map(|row| row.get::<i64, _>("sequence"))
        .collect()
}

/// The WATERMARKED read: never serve a row that a still-in-flight transaction could be
/// interleaved with. `pg_snapshot_xmin(pg_current_snapshot())` is the oldest transaction
/// id still running, so a row whose `xmin` is below it is visible to everyone, and nothing
/// can ever commit beneath it afterwards.
async fn read_after_watermarked(pool: &sqlx::PgPool, after: i64) -> Vec<i64> {
    sqlx::query(
        "SELECT sequence FROM outbox_messages \
         WHERE sequence > $1 \
           AND xmin::text::bigint < pg_snapshot_xmin(pg_current_snapshot())::text::bigint \
         ORDER BY sequence",
    )
    .bind(after)
    .fetch_all(pool)
    .await
    .expect("watermarked read")
    .iter()
    .map(|row| row.get::<i64, _>("sequence"))
    .collect()
}

#[tokio::test]
async fn a_cursor_over_sequence_alone_skips_an_event_that_commits_late() {
    let db = TestDatabase::start().await;
    // The OWNER pool: row-level security is not what is under test here, and the property
    // being measured is a storage-layer ordering guarantee beneath it.
    let pool = db.owner_pool();

    let (tenant, environment) = seeded_scope(&db, &Env::system()).await;
    let (tenant, environment) = (tenant.as_str(), environment.as_str());

    // Two overlapping writers. `early` takes the LOWER sequence but commits SECOND, which
    // is the interleaving the outbox documentation warns about and which no lock prevents.
    let mut early = pool.begin().await.expect("begin early");
    let early_seq = insert_returning_sequence(&mut early, tenant, environment, "evt_early").await;

    let mut late = pool.begin().await.expect("begin late");
    let late_seq = insert_returning_sequence(&mut late, tenant, environment, "evt_late").await;

    assert!(
        early_seq < late_seq,
        "the fixture must actually assign the lower sequence to the transaction that \
         commits last, or this test proves nothing: {early_seq} vs {late_seq}"
    );

    // The later-sequenced row becomes visible first.
    late.commit().await.expect("commit late");

    // A consumer polls here and sees only the late row, so it advances its cursor past it.
    let first_poll = read_after_naive(pool, 0).await;
    assert_eq!(
        first_poll,
        vec![late_seq],
        "only the committed row is visible, which is correct so far"
    );
    let cursor = *first_poll.last().expect("a row");

    // Now the earlier-sequenced row commits.
    early.commit().await.expect("commit early");

    // THE DEFECT: it is below the cursor, so it is never returned again.
    let second_poll = read_after_naive(pool, cursor).await;
    assert!(
        !second_poll.contains(&early_seq),
        "this test asserts the BUG exists; if this fails the hazard is gone and the \
         watermark below may be unnecessary"
    );

    // And it is not that the row is missing: reading from the start finds it. It is
    // specifically unreachable to a consumer that already advanced.
    let from_scratch = read_after_naive(pool, 0).await;
    assert!(
        from_scratch.contains(&early_seq),
        "the row exists; a cursor consumer simply cannot reach it any more"
    );
}

#[tokio::test]
async fn a_watermarked_cursor_never_advances_past_an_in_flight_write() {
    let db = TestDatabase::start().await;
    // The OWNER pool: row-level security is not what is under test here, and the property
    // being measured is a storage-layer ordering guarantee beneath it.
    let pool = db.owner_pool();

    let (tenant, environment) = seeded_scope(&db, &Env::system()).await;
    let (tenant, environment) = (tenant.as_str(), environment.as_str());

    let mut early = pool.begin().await.expect("begin early");
    let early_seq = insert_returning_sequence(&mut early, tenant, environment, "evt_early2").await;

    let mut late = pool.begin().await.expect("begin late");
    let late_seq = insert_returning_sequence(&mut late, tenant, environment, "evt_late2").await;
    late.commit().await.expect("commit late");

    // The watermark refuses to serve the late row while `early` is still open, because a
    // row could still commit beneath it. A cursor that never sees it never advances past
    // it, which is exactly how the gap is prevented rather than detected.
    let held_back = read_after_watermarked(pool, 0).await;
    assert!(
        !held_back.contains(&late_seq),
        "serving {late_seq} while an older transaction is in flight is what creates the \
         gap; the watermark must hold it back. got {held_back:?}"
    );

    early.commit().await.expect("commit early");

    // With nothing in flight, BOTH become available, in sequence order, and a consumer
    // starting from zero receives the earlier one it would otherwise have lost.
    let after_settle = read_after_watermarked(pool, 0).await;
    assert!(
        after_settle.contains(&early_seq) && after_settle.contains(&late_seq),
        "both rows must appear once the writers settle: {after_settle:?}"
    );
    let early_at = after_settle.iter().position(|s| *s == early_seq);
    let late_at = after_settle.iter().position(|s| *s == late_seq);
    assert!(
        early_at < late_at,
        "and in sequence order, which is the ordering criterion 1 promises"
    );
}
