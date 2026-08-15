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
use ironauth_store::{EventCursor, EventPage};
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

/// Poll until `want` appears, or give up.
///
/// The wait is not test flakiness dressed up; it IS the semantics.
/// `pg_snapshot_xmin(pg_current_snapshot())` is CLUSTER-wide, so the feed advances only
/// once every transaction that was open anywhere on the instance has finished, including
/// ones touching other databases entirely. An event is therefore withheld for as long as
/// the longest unrelated transaction runs. That is the real cost of this remedy and it is
/// asserted rather than hidden: see `an_unrelated_open_transaction_stalls_the_whole_feed`.
async fn eventually_visible(pool: &sqlx::PgPool, after: i64, want: &[i64]) -> Vec<i64> {
    for _ in 0..100 {
        let seen = read_after_watermarked(pool, after).await;
        if want.iter().all(|s| seen.contains(s)) {
            return seen;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    read_after_watermarked(pool, after).await
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
    let after_settle = eventually_visible(pool, 0, &[early_seq, late_seq]).await;
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

#[tokio::test]
async fn the_repo_feed_holds_back_an_event_an_older_writer_could_still_precede() {
    // The same property, through the API a consumer will actually call rather than through
    // hand-written SQL. A test that only exercised the raw query would leave the shipped
    // method unmeasured, which is the gap between "the idea works" and "the code does it".
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let (tenant, environment) = (scope.tenant().to_string(), scope.environment().to_string());

    let mut early = pool.begin().await.expect("begin early");
    let early_seq =
        insert_returning_sequence(&mut early, &tenant, &environment, "evt_repo_early").await;

    let mut late = pool.begin().await.expect("begin late");
    let late_seq =
        insert_returning_sequence(&mut late, &tenant, &environment, "evt_repo_late").await;
    late.commit().await.expect("commit late");

    let outbox = db.store().scoped(scope).outbox();

    let held = outbox.events_after(0, 100).await.expect("read");
    let held_sequences: Vec<i64> = held.iter().map(|m| m.sequence).collect();
    assert!(
        !held_sequences.contains(&late_seq),
        "the committed event must be withheld while an older writer is in flight: \
         {held_sequences:?}"
    );

    early.commit().await.expect("commit early");

    // Same bounded wait, same reason: the watermark is cluster-wide.
    let mut settled_sequences: Vec<i64> = Vec::new();
    for _ in 0..100 {
        let settled = outbox.events_after(0, 100).await.expect("read");
        settled_sequences = settled.iter().map(|m| m.sequence).collect();
        if settled_sequences.contains(&early_seq) && settled_sequences.contains(&late_seq) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        settled_sequences.contains(&early_seq) && settled_sequences.contains(&late_seq),
        "both must appear once the writers settle: {settled_sequences:?}"
    );
    assert!(
        settled_sequences.windows(2).all(|pair| pair[0] < pair[1]),
        "and strictly in sequence order: {settled_sequences:?}"
    );
}

#[tokio::test]
async fn an_unrelated_open_transaction_stalls_the_whole_feed() {
    // The cost of the watermark, stated as a test rather than left for an operator to
    // discover under load.
    //
    // `pg_snapshot_xmin(pg_current_snapshot())` is CLUSTER-wide. It does not know which
    // table, tenant, or even DATABASE a transaction touches, so a long-running query with
    // nothing to do with events holds the feed back exactly as an overlapping writer would.
    // This is head-of-line blocking sourced from an unrelated workload, and it is the
    // reason a commit-ordered appender is worth weighing against this remedy rather than
    // assuming the watermark is free.
    //
    // I found this by accident: these tests began failing only when a third was added and
    // its open transaction held the watermark down from another database.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let (tenant, environment) = (scope.tenant().to_string(), scope.environment().to_string());

    // ORDER MATTERS, and getting it wrong is how this test first passed for the wrong
    // reason. The watermark is the oldest transaction id still running, so a row is
    // withheld only when an older transaction was ALREADY OPEN when the row was written.
    // Opening the bystander after the commit proves nothing: the row's xmin is already
    // below the watermark and it is served correctly. The first draft did exactly that and
    // passed anyway, because OTHER tests in this file happened to be holding older
    // transactions open. It was measuring the suite, not its own fixture.
    //
    // So: the bystander opens first, and takes a transaction id by writing nothing at all.
    let mut bystander = pool.begin().await.expect("begin bystander");
    sqlx::query("SELECT pg_current_xact_id()")
        .execute(&mut *bystander)
        .await
        .expect("bystander takes an xid");

    // Only now is the event written and committed, beneath a transaction already running.
    let mut writer = pool.begin().await.expect("begin");
    let committed =
        insert_returning_sequence(&mut writer, &tenant, &environment, "evt_unrelated").await;
    writer.commit().await.expect("commit");

    let stalled = read_after_watermarked(pool, 0).await;
    assert!(
        !stalled.contains(&committed),
        "a committed event is withheld while an UNRELATED transaction is open: {stalled:?}"
    );

    bystander.rollback().await.expect("bystander ends");

    // The release side is deliberately NOT asserted, and the reason is the finding itself.
    //
    // Ending this bystander does not release the feed, because the watermark is held down
    // by the OLDEST transaction anywhere on the cluster and the rest of this suite is
    // running concurrently. An assertion here failed exactly that way once the file grew to
    // seven tests. Pinning it would mean serialising the suite, which would hide the very
    // property being demonstrated: under any concurrent workload the feed advances on
    // somebody else's schedule.
    //
    // What IS deterministic, and what this test pins, is the withholding above.
}

/// Delete every event at or below `through`, standing in for the retention sweep.
async fn prune_through(pool: &sqlx::PgPool, tenant: &str, environment: &str, through: i64) {
    sqlx::query(
        "DELETE FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND sequence <= $3",
    )
    .bind(tenant)
    .bind(environment)
    .bind(through)
    .execute(pool)
    .await
    .expect("prune");
}

#[tokio::test]
async fn a_cursor_that_aged_out_is_told_so_rather_than_handed_an_empty_page() {
    // The distinction #107 forbids collapsing. A consumer whose cursor has been pruned past
    // must NOT receive an empty page: it would read that as "nothing new", resume from a
    // position that skipped everything pruned in between, and never learn it lost anything.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let (tenant, environment) = (scope.tenant().to_string(), scope.environment().to_string());

    let mut tx = pool.begin().await.expect("begin");
    let first = insert_returning_sequence(&mut tx, &tenant, &environment, "evt_r1").await;
    let second = insert_returning_sequence(&mut tx, &tenant, &environment, "evt_r2").await;
    let third = insert_returning_sequence(&mut tx, &tenant, &environment, "evt_r3").await;
    tx.commit().await.expect("commit");

    // A consumer sitting at `first` has not yet seen `second` or `third`.
    prune_through(pool, &tenant, &environment, second).await;

    let outbox = db.store().scoped(scope).outbox();
    let page = outbox
        .events_page_after(EventCursor::after_sequence(first), 100)
        .await
        .expect("read");

    match page {
        EventPage::Gone { oldest_retained } => assert_eq!(
            oldest_retained, third,
            "the reconcile point must be the oldest event that still exists"
        ),
        EventPage::Page(events) => panic!(
            "a pruned-past cursor must not be served a page; got {:?}",
            events.iter().map(|m| m.sequence).collect::<Vec<_>>()
        ),
    }
}

#[tokio::test]
async fn a_cursor_exactly_one_below_the_oldest_retained_event_has_missed_nothing() {
    // The off-by-one this whole rule turns on. A consumer sitting one below the oldest
    // retained event has missed NOTHING, and reporting Gone here would send a healthy
    // consumer into a full resync after every prune.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let (tenant, environment) = (scope.tenant().to_string(), scope.environment().to_string());

    let mut tx = pool.begin().await.expect("begin");
    let first = insert_returning_sequence(&mut tx, &tenant, &environment, "evt_b1").await;
    let second = insert_returning_sequence(&mut tx, &tenant, &environment, "evt_b2").await;
    tx.commit().await.expect("commit");

    prune_through(pool, &tenant, &environment, first).await;

    let outbox = db.store().scoped(scope).outbox();
    // The cursor is `first`; the oldest retained is `second` == first + 1. Nothing lost.
    let page = outbox
        .events_page_after(EventCursor::after_sequence(first), 100)
        .await
        .expect("read");
    assert!(
        matches!(page, EventPage::Page(_)),
        "a cursor one below the oldest retained event has missed nothing: {page:?}"
    );
    let _ = second;
}

#[tokio::test]
async fn an_empty_feed_is_a_page_not_a_gone() {
    // Nothing was pruned; there is simply nothing to send. Reporting Gone would send every
    // brand-new consumer into a reconcile before it had read anything at all.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let outbox = db.store().scoped(scope).outbox();
    let page = outbox
        .events_page_after(EventCursor::beginning(), 100)
        .await
        .expect("read");

    assert_eq!(page, EventPage::Page(Vec::new()));
}
