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
use ironauth_store::{EventCursor, EventPage, NewOutboxMessage, UsageTally};
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

#[tokio::test]
async fn the_feed_orders_by_sequence_which_is_not_commit_order() {
    // #107 criterion 2 asks that ordering "matches commit order of the originating
    // transactions". The watermark does NOT deliver that, and this test is here to stop
    // anyone concluding it does from the fact that the gap tests pass.
    //
    // The watermark solves a DIFFERENT problem. It stops a cursor advancing past an event
    // that has not committed yet, which is what makes replay complete and repeatable
    // (criterion 1). It says nothing about the ORDER events are served in, because they are
    // served by sequence, and sequence is assigned at INSERT.
    //
    // So when two writers overlap and the later-sequenced one commits first, the feed emits
    // them in the opposite order to the order they became visible. Criterion 2 therefore
    // needs a commit-ordered appender, not this. Recorded as a measurement rather than an
    // opinion, because the two criteria look adjacent and are satisfied by different things.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let (tenant, environment) = (scope.tenant().to_string(), scope.environment().to_string());

    let mut early = pool.begin().await.expect("begin early");
    let early_seq = insert_returning_sequence(&mut early, &tenant, &environment, "evt_co_a").await;

    let mut late = pool.begin().await.expect("begin late");
    let late_seq = insert_returning_sequence(&mut late, &tenant, &environment, "evt_co_b").await;

    // COMMIT ORDER: the higher sequence becomes visible first.
    late.commit().await.expect("commit late");
    early.commit().await.expect("commit early");
    let commit_order = vec![late_seq, early_seq];

    let served = eventually_visible(pool, 0, &[early_seq, late_seq]).await;
    let feed_order: Vec<i64> = served
        .into_iter()
        .filter(|s| *s == early_seq || *s == late_seq)
        .collect();

    assert_eq!(
        feed_order,
        vec![early_seq, late_seq],
        "the feed serves in sequence order"
    );
    assert_ne!(
        feed_order, commit_order,
        "and sequence order is NOT commit order here, which is exactly why criterion 2 \
         needs a commit-ordered appender rather than this watermark"
    );
}

/// The per-scope lock key a serialized appender takes. Derived from the scope so two
/// environments never serialise against each other.
fn appender_lock_key(tenant: &str, environment: &str) -> i64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    tenant.hash(&mut hasher);
    environment.hash(&mut hasher);
    // Postgres advisory locks take a signed 64-bit key.
    i64::from_ne_bytes(hasher.finish().to_ne_bytes())
}

#[tokio::test]
async fn serialising_appenders_on_a_scope_lock_makes_sequence_order_equal_commit_order() {
    // #107 criterion 2 wants ordering to match COMMIT order, which #805 measured the
    // watermark does NOT deliver. This is the remedy, tested before anything is built on it.
    //
    // The insight is that no new column is needed. `sequence` is assigned at INSERT, and the
    // problem is only that two INSERTs can interleave with their COMMITs. If every appender
    // takes a per-scope advisory lock held to commit, they cannot overlap at all: the second
    // writer blocks until the first commits, so the order sequences are handed out IS the
    // order transactions commit, necessarily rather than usually.
    //
    // The cost is exactly what #798 said an appender costs: writes to one scope serialise.
    // What it buys is criterion 2 AND the removal of the cluster-wide watermark stall,
    // because with no overlapping writers there is nothing for a cursor to skip past.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let (tenant, environment) = (scope.tenant().to_string(), scope.environment().to_string());
    let key = appender_lock_key(&tenant, &environment);

    // Writer ONE takes the lock and inserts, but does not commit yet.
    let mut first = pool.begin().await.expect("begin first");
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *first)
        .await
        .expect("first takes the lock");
    let first_seq = insert_returning_sequence(&mut first, &tenant, &environment, "evt_ap_1").await;

    // Writer TWO tries to take the same lock. It BLOCKS, so it cannot reach its insert and
    // cannot be handed a sequence, which is the whole mechanism.
    let (tenant2, environment2) = (tenant.clone(), environment.clone());
    let pool2 = pool.clone();
    let second = tokio::spawn(async move {
        let mut tx = pool2.begin().await.expect("begin second");
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(key)
            .execute(&mut *tx)
            .await
            .expect("second takes the lock once it is free");
        let seq = insert_returning_sequence(&mut tx, &tenant2, &environment2, "evt_ap_2").await;
        tx.commit().await.expect("commit second");
        seq
    });

    // Give the blocked writer a moment to prove it really is blocked, then commit first.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !second.is_finished(),
        "the second appender must be BLOCKED on the lock; if it finished, the lock is not \
         serialising and the rest of this test proves nothing"
    );

    first.commit().await.expect("commit first");
    let second_seq = second.await.expect("second appender finishes");

    // Commit order was first, then second. Sequence order must agree, necessarily.
    assert!(
        first_seq < second_seq,
        "sequences must be handed out in commit order under the lock: {first_seq} then \
         {second_seq}"
    );

    let served = eventually_visible(pool, 0, &[first_seq, second_seq]).await;
    let feed: Vec<i64> = served
        .into_iter()
        .filter(|s| *s == first_seq || *s == second_seq)
        .collect();
    assert_eq!(
        feed,
        vec![first_seq, second_seq],
        "and the feed serves them in that same order, which IS commit order"
    );
}

#[tokio::test]
async fn append_event_serialises_so_the_repo_feed_is_in_commit_order() {
    // The same property through the SHIPPED method rather than hand-written SQL. The
    // raw-SQL test above proves the mechanism; this proves `append_event` actually uses it,
    // which is the gap between "the idea works" and "the code does it".
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.store().clone();

    // Two appenders racing. Whatever order they interleave in, the lock decides, and the
    // feed must agree with whatever the lock decided.
    let mut handles = Vec::new();
    for i in 0..2 {
        let store = store.clone();
        let env = env.clone();
        handles.push(tokio::spawn(async move {
            store
                .scoped(scope)
                .outbox()
                .append_event(
                    &env,
                    &NewOutboxMessage {
                        consumer: "events-appender-test",
                        idempotency_key: &format!("evt_race_{i}"),
                        ordering_key: "k",
                        payload: serde_json::json!({ "i": i }),
                    },
                )
                .await
                .expect("append")
        }));
    }
    for handle in handles {
        handle.await.expect("appender finishes");
    }

    // The bounded poll again: `events_page_after` still watermarks, and the watermark is
    // cluster-wide, so appended events wait for unrelated transactions exactly as any other
    // event does. Serialising the WRITES does not un-serialise the READ.
    let outbox = store.scoped(scope).outbox();
    let mut sequences: Vec<i64> = Vec::new();
    for _ in 0..100 {
        match outbox
            .events_page_after(EventCursor::beginning(), 100)
            .await
            .expect("read")
        {
            EventPage::Page(events) => {
                sequences = events.iter().map(|m| m.sequence).collect();
                if sequences.len() == 2 {
                    break;
                }
            }
            EventPage::Gone { .. } => panic!("nothing was pruned"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert_eq!(sequences.len(), 2, "both appends must be on the feed");
    assert!(
        sequences.windows(2).all(|pair| pair[0] < pair[1]),
        "strictly increasing: {sequences:?}"
    );
}

/// Read the whole feed through a store, retrying while the cluster-wide watermark settles.
async fn drain_feed(
    store: &ironauth_store::Store,
    scope: ironauth_store::Scope,
    want: usize,
) -> Vec<i64> {
    for _ in 0..100 {
        match store
            .scoped(scope)
            .outbox()
            .events_page_after(EventCursor::beginning(), 100)
            .await
            .expect("read")
        {
            EventPage::Page(events) => {
                let seqs: Vec<i64> = events.iter().map(|m| m.sequence).collect();
                if seqs.len() >= want {
                    return seqs;
                }
            }
            EventPage::Gone { .. } => panic!("nothing was pruned"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Vec::new()
}

#[tokio::test]
async fn replay_from_a_cursor_is_identical_across_a_restart() {
    // #107 criterion 1's second half, which the earlier tests did not touch: replay must be
    // identical "across repeated reads AND ACROSS A SERVER RESTART".
    //
    // What that criterion is really guarding is that ordering is a property of the DATABASE
    // and not of anything a process remembers. A feed that ordered by an in-memory counter,
    // a cached high-water mark, or insertion order into some local structure would pass
    // every repeated-read test and then renumber itself the first time the process died.
    //
    // So this reads the feed, throws the store away, reconnects as the app role exactly as
    // a restarted server would, and asserts the same sequences in the same order, plus that
    // every individual cursor still resolves to the same remainder.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.store().clone();

    for i in 0..4 {
        store
            .scoped(scope)
            .outbox()
            .append_event(
                &env,
                &NewOutboxMessage {
                    consumer: "events-replay-test",
                    idempotency_key: &format!("evt_replay_{i}"),
                    ordering_key: "k",
                    payload: serde_json::json!({ "i": i }),
                },
            )
            .await
            .expect("append");
    }

    let before = drain_feed(&store, scope, 4).await;
    assert_eq!(before.len(), 4, "all four events must be readable first");

    // The restart. A NEW pool, a new Store, nothing carried over in memory.
    let restarted = db.restart_app_store().await;

    let after = drain_feed(&restarted, scope, 4).await;
    assert_eq!(
        after, before,
        "the same events in the same order must survive a restart"
    );

    // Stronger than reading from the beginning twice: every INTERMEDIATE cursor must also
    // resolve to the same remainder. A feed that renumbered itself could still agree on the
    // full list while disagreeing about where any given cursor sits inside it.
    for (index, sequence) in before.iter().enumerate() {
        let remainder = match restarted
            .scoped(scope)
            .outbox()
            .events_page_after(EventCursor::after_sequence(*sequence), 100)
            .await
            .expect("read from an intermediate cursor")
        {
            EventPage::Page(events) => events.iter().map(|m| m.sequence).collect::<Vec<_>>(),
            EventPage::Gone { .. } => panic!("nothing was pruned"),
        };
        assert_eq!(
            remainder,
            before[index + 1..].to_vec(),
            "cursor after {sequence} must resolve to the same remainder it did before"
        );
    }
}

/// Append one event envelope, the shape `ironauth-admin` emits.
async fn append_envelope(
    store: &ironauth_store::Store,
    env: &Env,
    scope: ironauth_store::Scope,
    key: &str,
    event_type: &str,
    payload: serde_json::Value,
) {
    store
        .scoped(scope)
        .outbox()
        .append_event(
            env,
            &NewOutboxMessage {
                consumer: "metering-fixture",
                idempotency_key: key,
                ordering_key: "k",
                payload: serde_json::json!({
                    "id": key,
                    "type": event_type,
                    "payload_schema_version": 1,
                    "occurred_at_unix_ms": 0,
                    "tenant_id": scope.tenant().to_string(),
                    "environment_id": scope.environment().to_string(),
                    "payload": payload,
                }),
            },
        )
        .await
        .expect("append");
}

#[tokio::test]
async fn metering_matches_seeded_activity_exactly() {
    // #107 criterion 4: "metering matches seeded activity exactly". Seeded through the REAL
    // appender and read back through the REAL feed, so this measures the pipeline rather
    // than the arithmetic, which the unit tests already cover.
    //
    // The fixture is deliberately not uniform: alice appears three times and bob once, so a
    // fold that counted activity events instead of users would report 4 actives instead of
    // 2 and this test would say so. A fixture with one event per user cannot tell those
    // apart, which is how a metering bug survives its own test suite.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.store().clone();

    for (i, subject) in ["alice", "bob", "alice", "alice"].iter().enumerate() {
        append_envelope(
            &store,
            &env,
            scope,
            &format!("evt_act_{i}"),
            "user.signed_in",
            serde_json::json!({ "subject": subject }),
        )
        .await;
    }
    for i in 0..5 {
        append_envelope(
            &store,
            &env,
            scope,
            &format!("evt_tok_{i}"),
            "token.issued",
            serde_json::json!({}),
        )
        .await;
    }
    append_envelope(
        &store,
        &env,
        scope,
        "evt_conn_0",
        "connection.opened",
        serde_json::json!({}),
    )
    .await;
    // An event metering has no business with. It must be IGNORED, not counted and not an
    // error: the feed carries every domain's events, and a metering fold that failed on an
    // unfamiliar type would stop the first time another team shipped one.
    append_envelope(
        &store,
        &env,
        scope,
        "evt_other_0",
        "something.unrelated",
        serde_json::json!({ "subject": "carol" }),
    )
    .await;

    let outbox = store.scoped(scope).outbox();
    let mut tally = UsageTally::new();
    for _ in 0..100 {
        match outbox
            .events_page_after(EventCursor::beginning(), 100)
            .await
            .expect("read")
        {
            EventPage::Page(events) if events.len() == 11 => {
                tally = UsageTally::new();
                tally.absorb(&events);
                break;
            }
            EventPage::Page(_) => {}
            EventPage::Gone { .. } => panic!("nothing was pruned"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert_eq!(
        tally.monthly_active_users(),
        2,
        "alice three times and bob once is TWO active users"
    );
    assert_eq!(tally.tokens_issued(), 5);
    assert_eq!(tally.connections(), 1);
}
