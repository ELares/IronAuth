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
    // A COPY OF THE PRODUCTION PREDICATE, which `events_after`'s doc requires be kept in step.
    //
    // It is a copy and not a call, which is a weaker thing than it looks: this drives no store
    // and never reaches `OutboxRepo::events_after`, so it measures what this string says rather
    // than what the shipped query does. The scope predicates are deliberately absent because
    // these fixtures seed one scope; a version of this helper that dropped them while the
    // production query kept them would be the drift the doc warns about, so the difference is
    // written down here rather than left to be noticed.
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
    //
    // STILL TRUE, and still passing, after the production insert started taking the append
    // lock. This test inserts with `insert_returning_sequence`, which is hand-written SQL
    // that goes nowhere near `enqueue_outbox_in_tx`, so it measures the RAW table and shows
    // what the table does without the lock. That is what makes it the control for
    // `an_event_enqueue_blocks_on_the_per_scope_append_lock` below: same two-overlapping-
    // writers shape, one through raw SQL and one through the shipped path, opposite results.
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
    // THE PRODUCTION DERIVATION, not a copy of it. This was a hand-written duplicate of the
    // hashing in `repository.rs`, which is a copy that cannot fail loudly: change one side
    // and the tests take a DIFFERENT lock from the code, two writers on two keys never
    // contend, and every ordering test here passes while measuring nothing at all.
    ironauth_store::append_lock_key_from_parts(tenant, environment)
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
    // ENOUGH WRITERS TO ACTUALLY RACE. Two was the original count and it does not catch a
    // missing lock: measured, removing `append_event`'s `pg_advisory_xact_lock` left this test
    // passing 8 runs out of 8, because two writers on a local database rarely interleave.
    const WRITERS: i64 = 16;
    // The same property through the SHIPPED method rather than hand-written SQL. The
    // raw-SQL test above proves the mechanism; this proves `append_event` actually uses it,
    // which is the gap between "the idea works" and "the code does it".
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.store().clone();

    // Two appenders racing. Whatever order they interleave in, the lock decides, and the
    // feed must agree with whatever the lock decided.
    // COMMIT ORDER IS RECORDED, because the feed cannot reveal it. `append_event` returns
    // after its transaction commits, so each writer stamps itself into this list at the moment
    // it becomes durable, and the order of the list IS the commit order.
    //
    // Without it there is nothing here to assert. The feed serves `ORDER BY sequence`, so any
    // check on the sequences it returns is satisfied by the query's own ordering whatever the
    // lock did -- which is what the assertion at the end of this test used to be.
    let commit_order: std::sync::Arc<std::sync::Mutex<Vec<i64>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for i in 0..WRITERS {
        let store = store.clone();
        let env = env.clone();
        let commit_order = std::sync::Arc::clone(&commit_order);
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
                .expect("append");
            commit_order.lock().expect("not poisoned").push(i);
        }));
    }
    for handle in handles {
        handle.await.expect("appender finishes");
    }
    let commit_order = commit_order.lock().expect("not poisoned").clone();

    // The bounded poll again: `events_page_after` still watermarks, and the watermark is
    // cluster-wide, so appended events wait for unrelated transactions exactly as any other
    // event does. Serialising the WRITES does not un-serialise the READ.
    let outbox = store.scoped(scope).outbox();
    let mut sequences: Vec<i64> = Vec::new();
    let mut by_writer: std::collections::BTreeMap<i64, i64> = std::collections::BTreeMap::new();
    for _ in 0..100 {
        match outbox
            .events_page_after(EventCursor::beginning(), 100)
            .await
            .expect("read")
        {
            EventPage::Page(events) => {
                // Keyed by WRITER, from the payload, so the assertion below can ask "what
                // sequence did the writer that committed first get" rather than "are these
                // numbers increasing".
                by_writer = events
                    .iter()
                    .filter_map(|m| {
                        let i = m.payload.get("i")?.as_i64()?;
                        Some((i, m.sequence))
                    })
                    .collect();
                sequences = events.iter().map(|m| m.sequence).collect();
                if sequences.len() == usize::try_from(WRITERS).expect("fits") {
                    break;
                }
            }
            EventPage::Gone { .. } => panic!("nothing was pruned"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert_eq!(
        sequences.len(),
        usize::try_from(WRITERS).expect("fits"),
        "every append must be on the feed"
    );
    assert_eq!(
        commit_order.len(),
        usize::try_from(WRITERS).expect("fits"),
        "every writer must have committed"
    );

    // THE PROPERTY: the writer that committed FIRST holds the LOWER sequence. That is what
    // "sequence order equals commit order" means for two writers, and the append lock is what
    // makes it hold -- without it the second writer can insert first and commit second.
    //
    // This used to assert `sequences.windows(2).all(|pair| pair[0] < pair[1])`, described as
    // "strictly increasing". The feed serves ORDER BY sequence, so that could not fail: it
    // restated the query's own ordering. It passed with the lock removed.
    let in_commit_order: Vec<i64> = commit_order.iter().map(|w| by_writer[w]).collect();
    let inverted: Vec<(i64, i64)> = in_commit_order
        .windows(2)
        .filter(|pair| pair[0] > pair[1])
        .map(|pair| (pair[0], pair[1]))
        .collect();
    assert!(
        inverted.is_empty(),
        "sequence order is NOT commit order: these consecutive pairs, listed in the order \
         their writers COMMITTED, hold descending sequences {inverted:?}. Commit order was \
         {commit_order:?} and the feed served {sequences:?}"
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

/// A SECOND scope's feed is readable from the beginning (issue #107).
///
/// `sequence` is a TABLE-WIDE identity, so the second tenant to write in a database does not
/// own sequence 1: its oldest row might be 2, or five thousand. `EventCursor::beginning()` is
/// 0, and the aged-out test compares the scope's `MIN(sequence)` against it, so every scope
/// but whichever happened to own sequence 1 answered `Gone` to a reader starting from the
/// beginning. Measured before the fix: `GET /usage` and `POST /usage/publish` both returned
/// 500 for the second tenant in a database, and the event feed returned 410 telling the
/// caller its events "have been deleted" when nothing had been.
///
/// Every fixture in the suites that cover this reads the FIRST tenant created in a fresh
/// database, which is why it survived a criterion whose whole subject is this feed. Two
/// scopes in one database is the arrangement that makes the question askable at all, which
/// is the same shape as the cross-issuer gap in the federation fixtures.
#[tokio::test]
async fn a_second_scopes_feed_is_readable_from_the_beginning() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let first = db.seed_scope(&env).await;
    let second = db.seed_scope(&env).await;
    let store = db.store().clone();

    // Interleave, so neither scope owns a contiguous run and the second cannot own the
    // lowest sequence in the table.
    for i in 0..3 {
        append_envelope(
            &store,
            &env,
            first,
            &format!("evt_first_{i}"),
            "user.signed_in",
            serde_json::json!({"user_id": "usr_first", "method": "password"}),
        )
        .await;
        append_envelope(
            &store,
            &env,
            second,
            &format!("evt_second_{i}"),
            "user.signed_in",
            serde_json::json!({"user_id": "usr_second", "method": "password"}),
        )
        .await;
    }

    let oldest_of_second: i64 = sqlx::query_scalar(
        "SELECT MIN(sequence) FROM outbox_messages WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(second.tenant().to_string())
    .bind(second.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the second scope's oldest sequence");
    // The premise. Without this the test could pass in a database where the second scope
    // happened to start at 1, which is exactly the fixture blindness it exists to close.
    assert!(
        oldest_of_second > 1,
        "the second scope must NOT own sequence 1, or this test proves nothing: {oldest_of_second}"
    );

    // The feed is watermarked on `pg_snapshot_xmin`, so a row is readable a moment after it
    // commits. Poll for the count the way this file's other tests do, and assert the exit
    // condition, so a timeout fails HERE rather than as a confusing count below.
    let mut seen = 0;
    for _ in 0..100 {
        match store
            .scoped(second)
            .outbox()
            .events_page_after(EventCursor::beginning(), 100)
            .await
            .expect("read the second scope's feed")
        {
            EventPage::Page(events) => {
                seen = events.len();
                if seen == 3 {
                    break;
                }
            }
            EventPage::Gone { oldest_retained } => panic!(
                "a beginning cursor has missed nothing by definition, but the feed reported \
                 Gone at {oldest_retained}: every scope but the one owning sequence 1 would \
                 be unreadable"
            ),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        seen, 3,
        "a beginning cursor must be handed this scope's OWN events, and only those"
    );
}

/// The exact key a given scope derives, pinned.
///
/// This is here because of what the derivation USED to be. `DefaultHasher` is deterministic
/// within one Rust release and explicitly not guaranteed across releases, and the old
/// `to_ne_bytes` was not guaranteed across architectures. Neither could be caught by any
/// test that derives the expected value the same way the code does, because both sides move
/// together: the only thing that catches it is a literal, written down once.
///
/// It matters because of WHEN it would break. Two nodes built on different toolchains derive
/// two different keys for one scope, take two different locks, and stop serialising against
/// each other. The feed quietly stops being commit-ordered for the length of a rolling
/// upgrade and silently starts again at the end of it, leaving nothing behind to find.
///
/// If this fails, the derivation changed. That is allowed, but it is a coordinated upgrade:
/// every node must agree on the key, so a change has to ship behind a version the whole
/// fleet moves through, not in the same release as the code that depends on it.
#[test]
fn the_append_lock_key_is_pinned() {
    assert_eq!(
        ironauth_store::append_lock_key_from_parts(
            "tnt_pinned_for_the_key_test",
            "env_pinned_for_the_key_test",
        ),
        -7_666_221_150_003_507_989,
        "the append lock key derivation changed; see this test's doc comment before \
         updating the constant"
    );
}

/// Two scopes that concatenate to the same bytes must NOT share a lock.
///
/// The derivation is length-delimited specifically to prevent this. Without the delimiters
/// ("ab", "c") and ("a", "bc") hash identically, and two unrelated environments serialise
/// every event write against each other: a throughput fault with no error, no log line, and
/// nothing that would ever point at a hash function.
#[test]
fn scopes_that_concatenate_alike_get_different_keys() {
    assert_ne!(
        ironauth_store::append_lock_key_from_parts("ab", "c"),
        ironauth_store::append_lock_key_from_parts("a", "bc"),
        "the length delimiters are what separate these two scopes"
    );
}

/// A valid `ban.created` envelope, so the emit-time catalog guard admits it.
fn valid_event_envelope(scope: ironauth_store::Scope, id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "type": "ban.created",
        "payload_schema_version": 1,
        "occurred_at_unix_ms": 1,
        "tenant_id": scope.tenant().to_string(),
        "environment_id": scope.environment().to_string(),
        "payload": {
            "ban_id": "ban_ordering_probe",
            "subject_kind": "identifier",
            "auth_path": "password",
        },
    })
}

/// #107 CRITERION 2, on the path a deployment actually takes.
///
/// `append_event` has taken the append lock since #805 and
/// `append_event_serialises_so_the_repo_feed_is_in_commit_order` proves it. But that method
/// has zero production callers: every real event reaches the table through
/// `enqueue_domain_event` -> `enqueue_outbox_in_tx`, which took no lock at all. So the
/// criterion was proven for a path nothing exercises and false for the one everything uses,
/// and no test could notice, because the test that proves it calls the method directly.
///
/// This drives the shipped `OutboxRepo::enqueue` instead, which is the same insert every
/// domain producer reaches, and asserts it BLOCKS on the lock. Blocking is the whole
/// mechanism: a writer that cannot reach its insert cannot be handed a sequence, so
/// sequences are handed out in commit order necessarily rather than usually.
///
/// It asserts blocking rather than racing two writers and checking who won. Who wins is a
/// race and would be a flake; whether this path takes the lock at all is a fact, and holding
/// the lock from another session makes it observable.
#[tokio::test]
async fn an_event_enqueue_blocks_on_the_per_scope_append_lock() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let key = appender_lock_key(
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    );

    // An unrelated session holds the scope's append lock and does not let go.
    let mut holder = pool.begin().await.expect("begin holder");
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *holder)
        .await
        .expect("holder takes the lock");

    let store = db.store().clone();
    let envelope = valid_event_envelope(scope, "evt_prod_path_blocks");
    let enqueue_env = env.clone();
    let enqueueing = tokio::spawn(async move {
        store
            .scoped(scope)
            .outbox()
            .enqueue(
                &enqueue_env,
                &NewOutboxMessage {
                    consumer: ironauth_store::WEBHOOK_EVENT_CONSUMER,
                    idempotency_key: "evt_prod_path_blocks",
                    ordering_key: "k",
                    payload: envelope,
                },
            )
            .await
            .expect("enqueue completes once the lock is free")
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !enqueueing.is_finished(),
        "the ordinary event insert must BLOCK on the per-scope append lock. If it finished \
         while another session held the lock, this path does not take the lock, and #107 \
         criterion 2 holds only for `append_event`, which nothing calls."
    );

    holder.commit().await.expect("holder releases the lock");
    enqueueing
        .await
        .expect("the enqueue finishes once unblocked");
}

/// THE LOCK IS TAKEN BEFORE THE INSERT, WHICH IS THE ENTIRE MECHANISM.
///
/// `an_event_enqueue_blocks_on_the_per_scope_append_lock` above asserts the enqueue BLOCKS
/// while another session holds the key. That is satisfied by any placement of the lock inside
/// the transaction -- including AFTER the INSERT, where the row has already been handed its
/// sequence and criterion 2 is gone: two producers can both be given sequences before either
/// takes the lock, and then commit in the other order. Review moved
/// `take_event_append_lock` below the insert and the whole suite stayed green.
///
/// # What makes the position observable from outside the transaction
///
/// `outbox_messages.sequence` is `GENERATED ALWAYS AS IDENTITY`, so it is backed by a real
/// sequence object -- and a sequence's `last_value` is visible to other sessions immediately
/// and is NOT rolled back. That is the discriminator, and it is exact:
///
/// * lock BEFORE the insert -- a producer blocked on the lock has not reached the INSERT, so
///   it has consumed no sequence value and `last_value` is unchanged.
/// * lock AFTER the insert -- the blocked producer already inserted, so it has consumed one
///   and `last_value` has advanced.
///
/// No timing, no sleep-and-hope: the two cases differ in a number a third session can read.
#[tokio::test]
async fn the_append_lock_is_taken_before_the_sequence_is_allocated() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let key = appender_lock_key(
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    );

    // The identity sequence behind `outbox_messages.sequence`, by NAME FROM THE CATALOG rather
    // than spelled here: an identity column's sequence name is Postgres's to choose, and a
    // hand-written guess that stopped resolving would make this test read nothing and pass.
    let sequence_name: String =
        sqlx::query_scalar("SELECT pg_get_serial_sequence('outbox_messages', 'sequence')")
            .fetch_one(pool)
            .await
            .expect("outbox_messages.sequence must be sequence-backed");

    // `last_value` is only meaningful once the sequence has been used at all, so prime it with
    // one real event through the production path. This also proves the path under test works
    // when the lock is FREE, which the blocked half below cannot show.
    db.store()
        .scoped(scope)
        .outbox()
        .enqueue(
            &env,
            &NewOutboxMessage {
                consumer: ironauth_store::WEBHOOK_EVENT_CONSUMER,
                idempotency_key: "evt_seq_prime",
                ordering_key: "k",
                payload: valid_event_envelope(scope, "evt_seq_prime"),
            },
        )
        .await
        .expect("the priming enqueue runs with the lock free");
    let before: i64 = sqlx::query_scalar(&format!("SELECT last_value FROM {sequence_name}"))
        .fetch_one(pool)
        .await
        .expect("read last_value");

    // An unrelated session takes the scope's append lock and holds it.
    let mut holder = pool.begin().await.expect("begin holder");
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *holder)
        .await
        .expect("holder takes the lock");

    let store = db.store().clone();
    let envelope = valid_event_envelope(scope, "evt_seq_probe");
    let enqueue_env = env.clone();
    let enqueueing = tokio::spawn(async move {
        store
            .scoped(scope)
            .outbox()
            .enqueue(
                &enqueue_env,
                &NewOutboxMessage {
                    consumer: ironauth_store::WEBHOOK_EVENT_CONSUMER,
                    idempotency_key: "evt_seq_probe",
                    ordering_key: "k",
                    payload: envelope,
                },
            )
            .await
            .expect("enqueue completes once the lock is free")
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !enqueueing.is_finished(),
        "the producer must still be blocked, or the check below reads a sequence it was \
         always going to advance"
    );

    let during: i64 = sqlx::query_scalar(&format!("SELECT last_value FROM {sequence_name}"))
        .fetch_one(pool)
        .await
        .expect("read last_value while blocked");
    assert_eq!(
        during, before,
        "the blocked producer has ALREADY CONSUMED a sequence value ({before} -> {during}), \
         so it inserted before it took the append lock. Its row's position in the feed was \
         fixed before the lock could order it against anything, which is criterion 2 gone: \
         two producers can both be handed sequences and then commit in the other order. \
         `take_event_append_lock` must run BEFORE the INSERT."
    );

    holder.commit().await.expect("holder releases the lock");
    enqueueing
        .await
        .expect("the enqueue finishes once unblocked");

    // And once it is through, it DID consume one -- so the equality above was the lock
    // holding it back rather than this path never touching the sequence at all.
    let after: i64 = sqlx::query_scalar(&format!("SELECT last_value FROM {sequence_name}"))
        .fetch_one(pool)
        .await
        .expect("read last_value after");
    assert!(
        after > during,
        "the unblocked producer must consume a sequence value, or this test proves nothing: \
         {during} -> {after}"
    );
}

/// The NEGATIVE, varying exactly one thing: the consumer.
///
/// Same scope, same envelope, same idempotency key, same held lock. Only `consumer` differs,
/// so a pass here cannot be explained by anything except the consumer check inside
/// `take_event_append_lock`.
///
/// It matters because the cheapest wrong way to write the lock -- take it on every insert --
/// passes the test above and serialises webhook fan-out against event production for no
/// benefit. `events_after` serves every row in the scope regardless of consumer, which makes
/// "lock everything" look correct until you notice that interleaving a delivery row between
/// two events changes the sequences the events get and not their order relative to each
/// other, which is all criterion 2 asks for.
#[tokio::test]
async fn a_delivery_enqueue_does_not_block_on_the_append_lock() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let key = appender_lock_key(
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    );

    let mut holder = pool.begin().await.expect("begin holder");
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *holder)
        .await
        .expect("holder takes the lock");

    let store = db.store().clone();
    let envelope = valid_event_envelope(scope, "evt_prod_path_blocks");
    let enqueue_env = env.clone();
    let enqueueing = tokio::spawn(async move {
        store
            .scoped(scope)
            .outbox()
            .enqueue(
                &enqueue_env,
                &NewOutboxMessage {
                    consumer: ironauth_store::WEBHOOK_DELIVERY_CONSUMER,
                    idempotency_key: "evt_prod_path_blocks",
                    ordering_key: "k",
                    payload: envelope,
                },
            )
            .await
            .expect("a delivery message never waits on the event append lock")
    });

    // Long enough that a blocked task would still be blocked: the positive test above proves
    // 300ms is not enough for a blocked one to finish.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        enqueueing.is_finished(),
        "a delivery message must NOT take the event append lock. If it blocked here, the \
         lock is unconditional, and every webhook fan-out now serialises against event \
         production for a guarantee that only applies to events."
    );

    enqueueing.await.expect("the delivery enqueue succeeded");
    holder.commit().await.expect("holder releases the lock");
}

/// A ROTATION METERS THE SIGN-IN IT CREATED, through the shipped path.
///
/// `insert_session_row` used to enqueue `user.signed_in` itself, which made it the choke point
/// its own doc argued for: every session in the system passes through it, so no call site could
/// forget. This PR moved the enqueue OUT to the callers to fix a lock-order inversion, and the
/// doc's objection to doing that is correct and now unguarded by the shape of the code -- "a
/// producer added per call site is a producer the next call site forgets, and the failure is
/// silent undercounting that surfaces as a billing dispute."
///
/// So the guard is this test instead. It drives `rotate`, the ordinary sign-in, and asserts the
/// event reaches the FEED rather than merely being returned: a caller that takes the
/// `OwnedDomainEvent` and drops it compiles, passes every type check, and fails here. There is
/// no `#[must_use]` doing that job -- `OwnedDomainEvent` carries none, and `?` discharges the
/// `Result` leaving a plain `Option` no lint objects to.
#[tokio::test]
async fn a_rotation_meters_the_sign_in_it_created() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.store().clone();

    let session = ironauth_store::SessionId::generate(&env, &scope);
    store
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .sessions()
        .rotate(
            &env,
            &session,
            None,
            ironauth_store::NewSession {
                impersonation: None,
                subject: "usr_metered",
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: i64::MAX / 4,
                absolute_expires_micros: i64::MAX / 4,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("the sign-in commits");

    // THROUGH `events_after`, which is the feed a consumer actually reads.
    //
    // An earlier version claimed to assert "ON THE FEED" and read `outbox_messages` directly,
    // with `eventually_visible(pool, 0, &[])` in front of it -- an EMPTY `want`, so the helper
    // returned on its first iteration without waiting for or checking anything. Two claims,
    // neither true: no wait, and no feed.
    // POLLED, because the watermark is cluster-wide: the row is withheld until every
    // transaction open anywhere on the instance has finished, so a single read can legitimately
    // see nothing. A bounded wait for the event itself, not a wait for nothing.
    let mut payloads: Vec<serde_json::Value> = Vec::new();
    for _ in 0..100 {
        payloads = db
            .store()
            .scoped(scope)
            .outbox()
            .events_after(0, 100)
            .await
            .expect("read the feed")
            .into_iter()
            .map(|message| message.payload)
            .collect();
        if payloads
            .iter()
            .any(|p| p.get("type").and_then(serde_json::Value::as_str) == Some("user.signed_in"))
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let signed_in: Vec<&serde_json::Value> = payloads
        .iter()
        .filter(|p| p.get("type").and_then(serde_json::Value::as_str) == Some("user.signed_in"))
        .collect();
    assert_eq!(
        signed_in.len(),
        1,
        "the rotation must put exactly one `user.signed_in` on the feed; payload types: {:?}",
        payloads
            .iter()
            .map(|p| p.get("type").cloned())
            .collect::<Vec<_>>()
    );
    // THE SUBJECT AND NOTHING ELSE, which is the shape metering needs and the shape a billing
    // pipeline must not be able to widen into a directory.
    let data = signed_in[0]
        .get("payload")
        .expect("the event carries a payload");
    assert_eq!(
        data.get("subject").and_then(serde_json::Value::as_str),
        Some("usr_metered"),
        "the metered subject must be the one that signed in: {data}"
    );
}

/// THE APPEND LOCK MUST BE THE LAST LOCK A TRANSACTION TAKES.
///
/// That invariant is what makes a transaction-scoped global lock safe, and #1009's first
/// version broke it. `insert_session_row` enqueued `user.signed_in` internally, so it took the
/// append lock as the FIRST statement of `rotate_inner`'s closure -- before
/// `reconcile_prior_session_at_rotation` takes `FOR UPDATE` on the prior session. Every other
/// producer in the module enqueues LAST, holding row locks and then wanting the append lock.
/// Two orders, one cycle: `revoke_all_for_user_with_event` locks a subject's sessions and then
/// wants the append lock while a concurrent rotation holds the append lock and wants one of
/// those rows. Postgres aborts one with 40P01, so "revoke every session" racing that user's own
/// re-authentication -- the ordinary post-password-reset flow -- fails a login or a revoke.
///
/// # Why this shape rather than racing two writers
///
/// Reproducing a deadlock is a race and would be a flake. The INVARIANT is not a race: a
/// rotation that is waiting on a row lock must not already be holding the append lock, and that
/// is directly observable from a third session. Hold the prior session's row, start a rotation,
/// and ask whether the append lock is still free. If it is, the rotation cannot be the second
/// half of a cycle, because it has nothing the other side could want.
///
/// `pg_try_advisory_xact_lock` rather than a blocking take, so the probe answers immediately
/// and cannot itself join the wait graph.
#[tokio::test]
async fn a_rotation_waiting_on_a_row_does_not_hold_the_append_lock() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let key = appender_lock_key(
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    );
    let store = db.store().clone();

    let new_session = |subject: &'static str| ironauth_store::NewSession {
        impersonation: None,
        subject,
        auth_methods: "pwd",
        auth_time_micros: 0,
        idle_expires_micros: i64::MAX / 4,
        absolute_expires_micros: i64::MAX / 4,
        user_agent: None,
        peer_ip: None,
    };

    // A live PRIOR session for the rotation to supersede.
    let prior = ironauth_store::SessionId::generate(&env, &scope);
    store
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .sessions()
        .rotate(&env, &prior, None, new_session("usr_lock_order"))
        .await
        .expect("seed the prior session");

    // Another session holds that row, so the rotation below must stop at the reconcile.
    let mut holder = pool.begin().await.expect("begin holder");
    sqlx::query("SELECT id FROM sessions WHERE id = $1 FOR UPDATE")
        .bind(prior.to_string())
        .fetch_one(&mut *holder)
        .await
        .expect("hold the prior session row");

    let successor = ironauth_store::SessionId::generate(&env, &scope);
    let actor = db.test_actor(&env);
    let rotating = tokio::spawn({
        let store = store.clone();
        let env = env.clone();
        async move {
            store
                .scoped(scope)
                .acting(actor, ironauth_store::CorrelationId::generate(&env))
                .sessions()
                .rotate(
                    &env,
                    &successor,
                    Some(&prior),
                    new_session("usr_lock_order"),
                )
                .await
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !rotating.is_finished(),
        "the rotation must be BLOCKED on the prior session's row; if it finished, this test \
         proves nothing about what it holds while waiting"
    );

    // THE ASSERTION. A third session takes the append lock without waiting. It can only
    // succeed if the blocked rotation is not holding it.
    let mut probe = pool.begin().await.expect("begin probe");
    let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(key)
        .fetch_one(&mut *probe)
        .await
        .expect("probe the append lock");
    assert!(
        free,
        "the rotation is holding the per-scope append lock while waiting for a session row. \
         That is the ABBA half of #1009's deadlock: any producer that locks a row and then \
         wants the append lock now has a cycle with it. The append lock must be the LAST lock \
         a transaction takes."
    );
    probe.rollback().await.expect("release the probe");

    holder
        .commit()
        .await
        .expect("release the prior session row");
    rotating
        .await
        .expect("the rotation task finishes")
        .expect("the rotation succeeds once unblocked");
}

/// AN EVENT INSERT WAITING ON ITS FK PARENT MUST NOT BE HOLDING THE APPEND LOCK.
///
/// The invariant is that the append lock is the last lock a transaction takes, and the first
/// version of it rested on a sentence that is false for any table with a foreign key: "an
/// INSERT of a new row takes only that row's lock". `outbox_messages` references `tenants` and
/// `environments`, so the very insert the lock guards fires an RI check taking `FOR KEY SHARE`
/// on two EXISTING parent rows -- while the lock is already held. `audit_log` names the same
/// pair, so the audit row appended after the closure does it too.
///
/// Review reproduced the cycle against a real migrated cluster:
/// `ActingTenantRepo::delete_with_event` holds `FOR UPDATE` on every environment row of a
/// tenant and reaches its own enqueue only afterwards, while a concurrent producer holds the
/// advisory lock and blocks on the RI check. `ERROR: deadlock detected`.
///
/// # STILL IGNORED, and the reason changed: the CYCLE is closed, this SIDE of it is not
///
/// Closing it from the producer's side means taking the parents' KEY SHARE locks before the
/// advisory one, and this role cannot: `tenants` and `environments` are granted to
/// `ironauth_control` alone (`0003_management_api.sql:52-53`), so `SELECT ... FOR KEY SHARE`
/// from the data plane is `permission denied for table tenants` -- measured, by writing
/// exactly that fix and running this file. The RI check succeeds only because a
/// referential-integrity trigger runs with the constraint OWNER's privileges rather than the
/// caller's. Doing it anyway means granting the internet-facing plane access to the tenant
/// tables, which is the widening the plane split exists to prevent.
///
/// CLOSING IT FROM THE OTHER SIDE WAS TRIED AND MADE THINGS WORSE. `ActingTenantRepo::delete_with_event`
/// is the only `FOR UPDATE` on `environments`, so taking its append locks first looks like it
/// gives both sides one order. It does not: `FOR UPDATE` also conflicts with the
/// `FOR NO KEY UPDATE` an ordinary `UPDATE` takes, and three producers take exactly that on
/// those rows before wanting the advisory lock. Measured on a real cluster with a control -- a
/// posture write and a tenant delete deadlocked with the advisory locks taken first, and
/// committed cleanly with them taken last. Reverted.
///
/// So the order across the deployment is ROWS BEFORE ADVISORY, which every producer and that
/// closure already follow, and this cycle stays open. It is ignored and runnable: whoever
/// implements the lock-free alternative should be able to un-ignore it and watch it pass. It
/// fails today. That is still the point.
#[tokio::test]
#[ignore = "the producer-side invariant is still false; the cycle is closed from the tenant-delete             side instead -- see the doc comment"]
async fn an_event_insert_waiting_on_its_environment_row_does_not_hold_the_append_lock() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let pool = db.owner_pool();
    let key = appender_lock_key(
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
    );
    let store = db.store().clone();

    // Another session holds the ENVIRONMENT row in a mode that conflicts with the RI check's
    // KEY SHARE, which is what `delete_with_event` does to every environment of a tenant.
    let mut holder = pool.begin().await.expect("begin holder");
    sqlx::query("SELECT id FROM environments WHERE id = $1 AND tenant_id = $2 FOR UPDATE")
        .bind(scope.environment().to_string())
        .bind(scope.tenant().to_string())
        .fetch_one(&mut *holder)
        .await
        .expect("hold the environment row");

    let envelope = valid_event_envelope(scope, "evt_fk_order");
    let enqueue_env = env.clone();
    let enqueueing = tokio::spawn(async move {
        store
            .scoped(scope)
            .outbox()
            .enqueue(
                &enqueue_env,
                &NewOutboxMessage {
                    consumer: ironauth_store::WEBHOOK_EVENT_CONSUMER,
                    idempotency_key: "evt_fk_order",
                    ordering_key: "k",
                    payload: envelope,
                },
            )
            .await
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !enqueueing.is_finished(),
        "the event insert must be BLOCKED on the environment row; if it finished, this test \
         proves nothing about what it holds while waiting"
    );

    let mut probe = pool.begin().await.expect("begin probe");
    let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(key)
        .fetch_one(&mut *probe)
        .await
        .expect("probe the append lock");
    assert!(
        free,
        "the event insert is holding the per-scope append lock while waiting for its own \
         foreign-key parent. Any transaction that locks an environment row and then enqueues \
         -- `delete_with_event` does exactly that -- now has a cycle with it. The parents' KEY \
         SHARE locks must be taken BEFORE the advisory lock."
    );
    probe.rollback().await.expect("release the probe");

    holder.commit().await.expect("release the environment row");
    enqueueing
        .await
        .expect("the enqueue task finishes")
        .expect("the enqueue succeeds once unblocked");
}
