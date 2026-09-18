// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-node hot-state invalidation over the shared feed (issue #147).
//!
//! # What these owe
//!
//! - **Criterion 1**: "a config change on one node invalidates the corresponding cache entries
//!   on all nodes ... verified by a multi-node integration test."
//! - **Criterion 2**: "invalidations are transactional with their mutation: a rolled-back
//!   mutation produces no invalidation, and a committed mutation's invalidation is never lost."
//! - **Criterion 5**: "a restarting node never serves stale config past the SLO: startup either
//!   resumes from its last position or cold-flushes."
//!
//! # What a "node" is here
//!
//! A node id and a cursor, over one shared database. That is the whole of what distinguishes two
//! IronAuth processes as far as this mechanism is concerned: they append to one feed and each
//! reads it from its own position. Two node ids in one test process therefore exercise the same
//! code two machines would, and the thing that would NOT be exercised by spawning two processes
//! is the part that matters -- the shared table -- which is shared either way.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{HOT_STATE_INVALIDATION_CONSUMER, InvalidationBatch};

/// Keep unrelated fixtures from holding down this binary's cluster-wide feed watermark.
///
/// A separate database does not isolate `pg_snapshot_xmin`: another test's migrations can
/// withhold a committed invalidation for longer than the polling budget. Acquire this before
/// creating the fixture and hold it for the whole test. Cargo runs test binaries sequentially,
/// so this guard only needs to cover this binary. Explicit concurrent transactions within a
/// test still exercise the watermark, as the blocked-reader test below demonstrates.
static CLUSTER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// An hour from the epoch, in microseconds: long enough that nothing in these tests expires.
const AN_HOUR: i64 = 3_600_000_000;

/// Read a batch, retrying while the feed withholds rows.
///
/// # Why a poll and not a single read
///
/// The feed gates every read on `xmin < pg_snapshot_xmin(pg_current_snapshot())`, and that
/// watermark is CLUSTER-WIDE: the oldest transaction anywhere holds it down, including one
/// belonging to a completely unrelated test running beside this one. A single read can therefore
/// return an empty page for rows that are committed and settled, and the suite fails under
/// `--test-threads=2` while passing alone -- which is exactly how this was found.
///
/// `events_cursor_ordering.rs` documents meeting the same wall and chose not to assert the
/// release side at all. These tests need the rows, so they poll instead, which is also what a
/// production applier does: "not yet" is an ordinary answer from this feed, and an applier that
/// gave up on the first empty page would be one that stops invalidating whenever somebody runs
/// a long report.
///
/// It is bounded, so a genuine failure to produce the rows still fails the test rather than
/// hanging.
/// Apply until something was actually forgotten, for the same watermark reason as
/// [`batch_with_rows`]. An applier that saw an empty page is not evidence the rows are absent.
async fn apply_until_forgotten(
    hot: &dyn ironauth_hot::HotState,
    store: &ironauth_store::Store,
    scope: ironauth_store::Scope,
    env: &Env,
    node: &str,
) -> ironauth_store::hot_state::Applied {
    use ironauth_store::hot_state::{Applied, apply_invalidations};
    for _ in 0..50 {
        let applied = apply_invalidations(hot, store, scope, env, node, 100)
            .await
            .expect("apply");
        if applied
            != (Applied::Forgot {
                keys: 0,
                unknown_uses: 0,
            })
        {
            return applied;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the feed never served a row: the watermark did not settle within five seconds")
}

async fn batch_with_rows(
    feed: &ironauth_store::HotStateInvalidationRepo<'_>,
    node: &str,
    limit: i64,
) -> InvalidationBatch {
    for _ in 0..50 {
        let batch = feed.next_batch(node, limit).await.expect("read");
        match &batch {
            InvalidationBatch::Apply { forget, .. } if forget.is_empty() => {}
            _ => return batch,
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the feed never served a row: the watermark did not settle within five seconds")
}

#[tokio::test]
async fn a_change_on_one_node_is_seen_by_every_other_node() {
    // CRITERION 1. Two nodes read one feed from their own positions, so both see the same
    // invalidation. A queue would have handed it to whichever claimed it first and completed it,
    // leaving the other node's accelerator serving the old value for its whole TTL.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    feed.write_and_announce(
        &env,
        "tenant_config",
        "config",
        b"v2",
        AN_HOUR,
        "mutation-1",
        false,
    )
    .await
    .expect("write and announce");

    for node in ["node-a", "node-b"] {
        let batch = batch_with_rows(&feed, node, 100).await;
        let InvalidationBatch::Apply { forget, through } = batch else {
            panic!("{node} was told to cold flush with a fresh feed");
        };
        assert_eq!(
            forget,
            vec![("tenant_config".to_owned(), "config".to_owned())],
            "{node} must be told to forget the changed key"
        );
        assert!(through > 0, "{node} must be given a position to checkpoint");
    }
}

#[tokio::test]
async fn a_node_that_has_applied_a_change_does_not_see_it_again() {
    // THE CURSOR ACTUALLY ADVANCES. Without this, "every node sees it" is satisfied by a reader
    // that returns the whole feed every time -- which also means a node re-forgets every key on
    // every pass, and the accelerator is useless under any invalidation traffic at all.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    feed.write_and_announce(&env, "jwks", "kid-1", b"v", AN_HOUR, "rotation-1", false)
        .await
        .expect("announce");

    let InvalidationBatch::Apply { forget, through } = batch_with_rows(&feed, "node-a", 100).await
    else {
        panic!("cold flush on a fresh feed")
    };
    assert_eq!(forget.len(), 1);
    feed.record_cursor(&env, "node-a", through)
        .await
        .expect("checkpoint");

    let InvalidationBatch::Apply { forget, .. } =
        feed.next_batch("node-a", 100).await.expect("second read")
    else {
        panic!("cold flush after a checkpoint")
    };
    assert!(
        forget.is_empty(),
        "a checkpointed node must not be told to forget the same key again: {forget:?}"
    );

    // AND THE OTHER NODE STILL SEES IT, which is what makes the cursor per node rather than per
    // feed. Without this assertion, a reader that advanced one shared position would pass the
    // check above and silently deprive every other node.
    let InvalidationBatch::Apply { forget, .. } = batch_with_rows(&feed, "node-b", 100).await
    else {
        panic!("cold flush for a node that has never read")
    };
    assert_eq!(
        forget,
        vec![("jwks".to_owned(), "kid-1".to_owned())],
        "node-b has its own position and must still be told"
    );
}

#[tokio::test]
async fn a_rolled_back_mutation_announces_nothing() {
    // CRITERION 2, the half that is easy to get wrong by opening a second transaction. Both
    // writes are abandoned together, so there must be neither a cache entry nor an invalidation
    // telling every node to forget a key that never changed.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    feed.write_and_announce(
        &env,
        "tenant_config",
        "config",
        b"never",
        AN_HOUR,
        "abandoned",
        true,
    )
    .await
    .expect("the call itself succeeds; the transaction is abandoned");

    let entries: i64 = sqlx::query_scalar("SELECT count(*) FROM hot_state")
        .fetch_one(db.owner_pool())
        .await
        .expect("count");
    assert_eq!(entries, 0, "the abandoned mutation must have left no entry");

    let announcements: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbox_messages WHERE consumer = $1")
            .bind(HOT_STATE_INVALIDATION_CONSUMER)
            .fetch_one(db.owner_pool())
            .await
            .expect("count");
    assert_eq!(
        announcements, 0,
        "and no invalidation: an announcement without its change makes every node forget a key \
         that never moved"
    );

    // THE CONTROL. Without it this test passes against a `write_and_announce` that writes
    // nothing at all under any argument.
    feed.write_and_announce(
        &env,
        "tenant_config",
        "config",
        b"v2",
        AN_HOUR,
        "kept",
        false,
    )
    .await
    .expect("committed");
    let announcements: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbox_messages WHERE consumer = $1")
            .bind(HOT_STATE_INVALIDATION_CONSUMER)
            .fetch_one(db.owner_pool())
            .await
            .expect("count");
    assert_eq!(announcements, 1, "a committed mutation DOES announce");
}

#[tokio::test]
async fn two_changes_to_one_key_announce_twice() {
    // THE IDEMPOTENCY KEY MUST BE PER MUTATION, NOT PER CACHE KEY. Derived from `(use, key)`
    // alone, the second change to one key is a unique violation: the first invalidation stands,
    // the second is refused, and every node goes on serving what the first change wrote. That is
    // a permanently stale cache produced by a dedup rule.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    feed.write_and_announce(
        &env,
        "tenant_config",
        "c",
        b"v2",
        AN_HOUR,
        "change-1",
        false,
    )
    .await
    .expect("first change");
    feed.write_and_announce(
        &env,
        "tenant_config",
        "c",
        b"v3",
        AN_HOUR,
        "change-2",
        false,
    )
    .await
    .expect("second change to the SAME key must also announce");

    let InvalidationBatch::Apply { forget, .. } = batch_with_rows(&feed, "node-a", 100).await
    else {
        panic!("cold flush")
    };
    assert_eq!(
        forget.len(),
        2,
        "both changes must be announced, or the later value is never propagated: {forget:?}"
    );
}

#[tokio::test]
async fn a_checkpoint_never_moves_backwards() {
    // A CURSOR THAT CAN GO BACKWARDS CAN LIVELOCK. Two overlapping passes for one node -- a slow
    // one holding an old position while a fast one has already advanced -- would have the loser
    // write the lower number, and a periodic overlap re-applies the same rows for ever.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    feed.record_cursor(&env, "node-a", 50).await.expect("ahead");
    feed.record_cursor(&env, "node-a", 10)
        .await
        .expect("a late, lower checkpoint is accepted and ignored");

    assert_eq!(
        feed.cursor_for("node-a").await.expect("read"),
        50,
        "the cursor must keep the higher position"
    );
}

#[tokio::test]
async fn a_node_with_no_cursor_starts_at_the_beginning() {
    // NOT AT THE HEAD. A new node starting at the head would treat its empty accelerator as
    // up to date with respect to invalidations it never saw -- which is only safe because the
    // accelerator IS empty, and stops being safe the moment it populates from a durable tier
    // whose keys were invalidated before the node joined.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    feed.write_and_announce(&env, "jwks", "kid", b"v", AN_HOUR, "before-join", false)
        .await
        .expect("announce before the node exists");

    assert_eq!(
        feed.cursor_for("brand-new-node").await.expect("read"),
        0,
        "a node that has never checkpointed starts before the first row"
    );
    let InvalidationBatch::Apply { forget, .. } =
        batch_with_rows(&feed, "brand-new-node", 100).await
    else {
        panic!("cold flush")
    };
    assert_eq!(
        forget.len(),
        1,
        "and is told about what happened before it joined"
    );
}

#[tokio::test]
async fn a_polling_node_reads_a_committed_invalidation_after_an_older_transaction_ends() {
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    // Take the older xid before committing the invalidation. An unrelated transaction
    // opened afterwards would not hold this row behind the watermark.
    let mut bystander = db.owner_pool().begin().await.expect("begin bystander");
    sqlx::query("SELECT pg_current_xact_id()")
        .execute(&mut *bystander)
        .await
        .expect("bystander takes an xid");
    feed.write_and_announce(&env, "jwks", "kid", b"v", AN_HOUR, "while-blocked", false)
        .await
        .expect("commit the invalidation while the older transaction remains open");

    let InvalidationBatch::Apply { forget, through } =
        feed.next_batch("waiting-node", 100).await.expect("read")
    else {
        panic!("cold flush on a fresh feed")
    };
    assert!(
        forget.is_empty(),
        "a committed invalidation is withheld while the older transaction remains open"
    );
    assert_eq!(through, 0, "an empty page must not advance the position");
    assert_eq!(
        feed.cursor_for("waiting-node").await.expect("read"),
        0,
        "the blocked node still starts at the beginning"
    );

    // Let the helper execute and retry while the bystander stays open. Borrowing the
    // pinned future keeps this same reader alive after the timeout and explicit rollback.
    // The existing helper keeps its original five-second bound.
    let waiting = batch_with_rows(&feed, "waiting-node", 100);
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), waiting.as_mut())
            .await
            .is_err(),
        "the polling read must wait while the older transaction remains open"
    );

    bystander.rollback().await.expect("release the watermark");
    let InvalidationBatch::Apply { forget, through } = waiting.await else {
        panic!("cold flush after releasing a fresh feed")
    };
    assert_eq!(
        forget,
        vec![("jwks".to_owned(), "kid".to_owned())],
        "the same polling read delivers exactly the committed invalidation after release"
    );
    assert!(through > 0, "the delivered row has a feed position");
    assert_eq!(
        feed.cursor_for("waiting-node").await.expect("read"),
        0,
        "reading the row does not checkpoint it before the node applies it"
    );
}

#[tokio::test]
async fn another_consumers_row_is_not_read_as_an_invalidation() {
    // THE CONSUMER FILTER, which nothing else pins: every other test here puts ONLY
    // invalidations in the feed, so a reader that returned every row would pass them all.
    // `events_page_after` deliberately serves every row in the scope and leaves filtering to
    // its readers, so this reader is the only thing standing between a webhook delivery row and
    // a node forgetting a cache key because of it.
    //
    // THE FOREIGN ROW CARRIES A PAYLOAD THAT WOULD OTHERWISE PARSE -- the same `use` and `key`
    // members an invalidation has. A row with a different payload shape would be dropped by the
    // field lookup rather than by the consumer check, so it would pin nothing: the mutant that
    // replaces the consumer comparison with a tautology survives it. This row is refused for
    // exactly one reason, which is the reason under test.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    sqlx::query(
        "INSERT INTO outbox_messages \
         (id, tenant_id, environment_id, consumer, idempotency_key, ordering_key, payload, \
          next_attempt_at, enqueued_at) \
         VALUES ($1, $2, $3, 'webhook.delivery', 'foreign-1', 'foreign-1', $4, now(), now())",
    )
    .bind("obm_Zm9yZWlnbi1yb3ctMDAwMDA")
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(serde_json::json!({ "use": "tenant_config", "key": "config" }))
    .execute(db.owner_pool())
    .await
    .expect("seed a foreign-consumer row");

    // WAIT FOR THE ROW TO BE VISIBLE BEFORE JUDGING IT. This test's subject is a row that the
    // reader must IGNORE, and "ignored" and "not served yet" are the same empty `forget` -- so
    // reading once would let the cluster-wide watermark make it pass without the row ever
    // having been offered. Polling on `through` advancing is what distinguishes the two: the
    // cursor moves only when the page actually contained the row.
    let mut seen = None;
    for _ in 0..50 {
        let InvalidationBatch::Apply { forget, through } =
            feed.next_batch("node-a", 100).await.expect("read")
        else {
            panic!("cold flush on a fresh feed")
        };
        if through > 0 {
            seen = Some((forget, through));
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let (forget, through) =
        seen.expect("the foreign row was never served: the watermark did not settle in 5s");

    assert!(
        forget.is_empty(),
        "a row belonging to another consumer must not be read as an invalidation: {forget:?}"
    );

    // AND THE CURSOR ADVANCED PAST IT. The page is a slice of the WHOLE feed, so a reader that
    // only checkpointed as far as the last INVALIDATION would re-read this row on every pass
    // for ever. That is the other half of why `through` is the page's last sequence.
    assert!(
        through > 0,
        "the cursor must advance past another consumer's row, not stall on it"
    );
}

#[tokio::test]
async fn a_node_behind_the_retained_window_is_told_to_cold_flush() {
    // CRITERION 5's OTHER BRANCH: "startup either resumes from its last position or
    // cold-flushes". Resuming is every other test in this file; this is the case where resuming
    // is not safe, because the invalidations between the node's position and the oldest retained
    // row have been pruned and it cannot enumerate what it missed.
    //
    // THE PRUNE IS DONE DIRECTLY, through the owner pool, because what matters here is the
    // STATE (a cursor before the oldest surviving row), not which component produced it. Driving
    // the reaper would make this a test of the reaper's schedule.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    // FOUR CHANGES, so that pruning two still leaves a page to come back. With three, pruning
    // through the second leaves one row and the arithmetic still works, but a test that is one
    // row from having nothing left is a test whose next edit breaks it silently.
    for change in 0..4 {
        feed.write_and_announce(
            &env,
            "tenant_config",
            "config",
            b"v",
            AN_HOUR,
            &format!("change-{change}"),
            false,
        )
        .await
        .expect("announce");
    }

    // THE NODE MUST HAVE READ SOMETHING FIRST, and finding out why is worth recording.
    //
    // `events_page_after` does NOT report a prune to a cursor at the beginning, deliberately:
    // position 0 means "I have read nothing", which is indistinguishable from a brand new node,
    // and telling every new node to cold flush would be a flush per deployment rather than per
    // data loss. `Gone` fires for a cursor whose OWN last-read row has been pruned -- a live
    // cursor row forces MIN <= after, so its absence is the signal.
    //
    // The first version of this test checkpointed nothing, pruned the oldest row and expected a
    // flush; it got a two-row page, which is the correct answer to the question it actually
    // asked.
    let InvalidationBatch::Apply { through, .. } = batch_with_rows(&feed, "node-a", 1).await else {
        panic!("cold flush on a fresh feed")
    };
    feed.record_cursor(&env, "node-a", through)
        .await
        .expect("checkpoint the first row");

    // THE CONTROL, before anything is pruned: a checkpointed node resumes rather than flushing.
    // Without it, an implementation that answered ColdFlush unconditionally would pass the
    // assertion below.
    assert!(
        matches!(
            feed.next_batch("node-a", 100).await.expect("read"),
            InvalidationBatch::Apply { .. }
        ),
        "with the whole feed retained, a checkpointed node must resume"
    );

    let oldest: i64 = sqlx::query_scalar("SELECT MIN(sequence) FROM outbox_messages")
        .fetch_one(db.owner_pool())
        .await
        .expect("min");

    // AN UNREAD ROW MUST GO, not merely a read one, and the difference is the whole condition.
    // The feed answers `Gone` when the oldest surviving sequence is more than one past the
    // cursor -- that is, when at least one row the node had NOT read is missing. Pruning only
    // the row it had already applied leaves the next sequence exactly where it expects, so
    // nothing was lost and a page is the correct answer. The second version of this test pruned
    // exactly that and got a page, which was right.
    sqlx::query("DELETE FROM outbox_messages WHERE sequence <= $1")
        .bind(through + 1)
        .execute(db.owner_pool())
        .await
        .expect("prune past the node's position, taking a row it never read");

    let batch = feed.next_batch("node-a", 100).await.expect("read");
    let InvalidationBatch::ColdFlush { resume_at } = batch else {
        panic!(
            "a node whose position is before the retained window must be told to flush: {batch:?}"
        );
    };
    let oldest_surviving: i64 = sqlx::query_scalar("SELECT MIN(sequence) FROM outbox_messages")
        .fetch_one(db.owner_pool())
        .await
        .expect("min after the prune");
    assert!(
        oldest_surviving > oldest,
        "the prune must actually have removed rows, or this test measures nothing"
    );
    assert!(
        resume_at < oldest_surviving,
        "the resumed position must sit BEFORE the oldest surviving row ({oldest_surviving}), or \
         the flush skips the very row it was compensating for; got {resume_at}"
    );
}

#[tokio::test]
async fn one_scope_s_invalidations_are_invisible_to_another() {
    // THE FEED IS SCOPED, like everything else. An invalidation naming `config` in one tenant
    // must not make another tenant's node forget its own `config`.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let mine = db.seed_scope(&env).await;
    let theirs = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;

    let my_feed = store.scoped(mine);
    let my_feed = my_feed.hot_state_invalidations();
    my_feed
        .write_and_announce(&env, "tenant_config", "config", b"v2", AN_HOUR, "m1", false)
        .await
        .expect("announce");

    let their_feed = store.scoped(theirs);
    let their_feed = their_feed.hot_state_invalidations();
    let InvalidationBatch::Apply { forget, .. } =
        their_feed.next_batch("node-a", 100).await.expect("read")
    else {
        panic!("cold flush")
    };
    assert!(
        forget.is_empty(),
        "another tenant's invalidation must not reach this scope: {forget:?}"
    );
}

#[tokio::test]
async fn applying_a_batch_forgets_the_key_on_this_node_and_checkpoints() {
    // CRITERION 1's OPERATIVE HALF, which the feed tests alone do not reach: they show the rows
    // come back, not that any cache entry is invalidated. This drives the applier, so a key
    // cached on this node is actually gone afterwards.
    use ironauth_hot::{HotState, Ttl, registry};
    use ironauth_store::hot_state::{Applied, PgHotState, apply_invalidations};

    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = std::sync::Arc::new(db.restart_app_store().await);
    let hot = PgHotState::new(std::sync::Arc::clone(&store), scope, &env);

    hot.put(
        &registry::TENANT_CONFIG,
        "config",
        b"cached",
        Ttl::of(std::time::Duration::from_secs(3600)),
    )
    .await
    .expect("cache it");
    assert_eq!(
        hot.get(&registry::TENANT_CONFIG, "config").await,
        Ok(Some(b"cached".to_vec())),
        "baseline: the entry is there, or the assertion below proves nothing"
    );

    let feed = store.scoped(scope);
    feed.hot_state_invalidations()
        .write_and_announce(
            &env,
            "tenant_config",
            "config",
            b"v2",
            AN_HOUR,
            "another-nodes-change",
            false,
        )
        .await
        .expect("another node announces");

    let applied = apply_until_forgotten(&hot, &store, scope, &env, "this-node").await;
    assert_eq!(
        applied,
        Applied::Forgot {
            keys: 1,
            unknown_uses: 0
        }
    );
    assert_eq!(
        hot.get(&registry::TENANT_CONFIG, "config").await,
        Ok(None),
        "the entry must be GONE from this node's hot state"
    );

    // AND THE CHECKPOINT LANDED, so a second pass finds nothing. Without this, an applier that
    // never advanced its cursor would re-delete the same key on every pass for ever.
    let again = apply_invalidations(&hot, &store, scope, &env, "this-node", 100)
        .await
        .expect("second pass");
    assert_eq!(
        again,
        Applied::Forgot {
            keys: 0,
            unknown_uses: 0
        },
        "a checkpointed node must not re-apply what it already applied"
    );
}

#[tokio::test]
async fn a_use_this_build_does_not_have_is_counted_and_skipped() {
    // THE ROLLING-UPGRADE CASE. A newer node announces a use this build does not know; there is
    // nothing here to forget, and that must not be an error, a panic, or a stalled cursor.
    use ironauth_hot::{HotState, Ttl, registry};
    use ironauth_store::hot_state::{Applied, PgHotState};

    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = std::sync::Arc::new(db.restart_app_store().await);
    let hot = PgHotState::new(std::sync::Arc::clone(&store), scope, &env);
    hot.put(
        &registry::JWKS,
        "kid",
        b"v",
        Ttl::of(std::time::Duration::from_secs(3600)),
    )
    .await
    .expect("cache something this build DOES know");

    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();
    feed.write_and_announce(
        &env,
        "a_use_from_the_future",
        "k",
        b"v",
        AN_HOUR,
        "m1",
        false,
    )
    .await
    .expect("announce an unknown use");
    feed.write_and_announce(&env, "jwks", "kid", b"v", AN_HOUR, "m2", false)
        .await
        .expect("announce a known one");

    let applied = apply_until_forgotten(&hot, &store, scope, &env, "this-node").await;
    assert_eq!(
        applied,
        Applied::Forgot {
            keys: 1,
            unknown_uses: 1
        },
        "the unknown use is counted and skipped, and the known one is still applied"
    );
    assert_eq!(
        hot.get(&registry::JWKS, "kid").await,
        Ok(None),
        "an unknown use earlier in the batch must not strand the ones after it"
    );
}

#[tokio::test]
async fn a_cold_flush_checkpoints_so_it_is_not_repeated_for_ever() {
    // THE APPLIER'S HALF OF CRITERION 5. Returning MustColdFlush without recording the position
    // would tell a caller to flush on every pass for ever, because the cursor would still sit
    // behind the retained window.
    use ironauth_hot::{HotState, Ttl, registry};
    use ironauth_store::hot_state::{Applied, PgHotState, apply_invalidations};

    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = std::sync::Arc::new(db.restart_app_store().await);
    let hot = PgHotState::new(std::sync::Arc::clone(&store), scope, &env);
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    for change in 0..4 {
        feed.write_and_announce(
            &env,
            "jwks",
            "kid",
            b"v",
            AN_HOUR,
            &format!("change-{change}"),
            false,
        )
        .await
        .expect("announce");
    }
    let InvalidationBatch::Apply { through, .. } = batch_with_rows(&feed, "node-a", 1).await else {
        panic!("cold flush on a fresh feed")
    };
    feed.record_cursor(&env, "node-a", through)
        .await
        .expect("checkpoint");
    sqlx::query("DELETE FROM outbox_messages WHERE sequence <= $1")
        .bind(through + 1)
        .execute(db.owner_pool())
        .await
        .expect("prune past the node's position");

    assert_eq!(
        apply_invalidations(&hot, &store, scope, &env, "node-a", 100)
            .await
            .expect("apply"),
        Applied::MustColdFlush,
        "a node behind the window must be told to flush"
    );

    // AND NOT AGAIN. The caller has flushed; a second pass must resume normally.
    assert!(
        matches!(
            apply_invalidations(&hot, &store, scope, &env, "node-a", 100)
                .await
                .expect("second pass"),
            Applied::Forgot { .. }
        ),
        "a flushed node must resume, not be told to flush for ever"
    );

    // AND THE CACHE IS UNTOUCHED BY THE FLUSH SIGNAL ITSELF. `apply_invalidations` must not
    // empty the durable tier: that is the copy the cold flush falls back ON, and deleting it
    // would turn a cache miss into data loss.
    hot.put(
        &registry::JWKS,
        "survivor",
        b"v",
        Ttl::of(std::time::Duration::from_secs(3600)),
    )
    .await
    .expect("write");
    let _ = apply_invalidations(&hot, &store, scope, &env, "node-b", 100).await;
    assert_eq!(
        hot.get(&registry::JWKS, "survivor").await,
        Ok(Some(b"v".to_vec())),
        "the applier must never empty the durable tier itself"
    );
}

#[tokio::test]
async fn broadcast_rows_are_reaped_by_age_because_nothing_completes_them() {
    // UNBOUNDED GROWTH, WHICH THIS FEATURE SHIPPED WITH. The reaper removes a row once it is
    // COMPLETED or DEAD-LETTERED; an invalidation is never either, so both predicates are false
    // for ever and the rows accumulate. Age is the only rule available, and it is the same
    // number that bounds how far a node may fall behind.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();
    // THE REAP IS A CONTROL-PLANE OPERATION. `ironauth_app` has no DELETE on
    // `outbox_messages`, so a data-plane handle answers `permission denied` -- which is how the
    // first version of this test failed, and why `reap_broadcast` lives on `OutboxRepo`.
    let control = db.control_store();
    let reaper = control.scoped(scope);
    let reaper = reaper.outbox();

    for change in 0..3 {
        feed.write_and_announce(
            &env,
            "jwks",
            "kid",
            b"v",
            AN_HOUR,
            &format!("c{change}"),
            false,
        )
        .await
        .expect("announce");
    }

    // A cutoff BEFORE every row: nothing is old enough yet, which is the control. Without it a
    // reap that deleted unconditionally would pass the assertion below.
    assert_eq!(
        reaper.reap_broadcast(0, 100).await.expect("reap"),
        0,
        "nothing is past a cutoff at the epoch"
    );

    let removed = reaper
        .reap_broadcast(i64::MAX, 100)
        .await
        .expect("reap everything older than the end of time");
    assert_eq!(removed, 3, "every broadcast row is removable by age");

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox_messages WHERE consumer = $1")
        .bind(HOT_STATE_INVALIDATION_CONSUMER)
        .fetch_one(db.owner_pool())
        .await
        .expect("count");
    assert_eq!(left, 0, "and they are gone from the table");
}

#[tokio::test]
async fn a_reap_does_not_touch_another_consumers_rows() {
    // THE CONSUMER FILTER ON THE REAP. Without it, an age-based delete over the shared feed
    // would remove webhook event rows that no consumer had delivered -- the exact thing the
    // reaper's own doc refuses age-based deletion for.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    let control = db.control_store();
    let reaper = control.scoped(scope);
    let reaper = reaper.outbox();

    feed.write_and_announce(&env, "jwks", "kid", b"v", AN_HOUR, "c1", false)
        .await
        .expect("announce");
    sqlx::query(
        "INSERT INTO outbox_messages \
         (id, tenant_id, environment_id, consumer, idempotency_key, ordering_key, payload, \
          next_attempt_at, enqueued_at) \
         VALUES ($1, $2, $3, 'webhook.delivery', 'keep-me', 'keep-me', '{}'::jsonb, now(), now())",
    )
    .bind("obm_a2VlcC1tZS0wMDAwMDAwMA")
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(db.owner_pool())
    .await
    .expect("seed another consumer's row");

    assert_eq!(
        reaper.reap_broadcast(i64::MAX, 100).await.expect("reap"),
        1,
        "only the invalidation goes"
    );
    let survivors: Vec<(String,)> =
        sqlx::query_as("SELECT consumer FROM outbox_messages ORDER BY consumer")
            .fetch_all(db.owner_pool())
            .await
            .expect("select");
    assert_eq!(
        survivors,
        vec![("webhook.delivery".to_owned(),)],
        "another consumer's undelivered row must survive an age-based reap"
    );
}

#[tokio::test]
async fn a_checkpoint_moves_a_cursor_forward_from_an_existing_row() {
    // THE UPDATE ARM, which nothing pinned: every other checkpoint in this file either creates
    // the row or tries to move it BACKWARDS. `ON CONFLICT DO NOTHING` would pass all of them,
    // and a cursor that never advances after its first write re-applies every invalidation for
    // ever.
    let _serialized = CLUSTER.lock().await;
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    feed.record_cursor(&env, "node-a", 10).await.expect("first");
    assert_eq!(feed.cursor_for("node-a").await.expect("read"), 10);
    feed.record_cursor(&env, "node-a", 20)
        .await
        .expect("advance");
    assert_eq!(
        feed.cursor_for("node-a").await.expect("read"),
        20,
        "a later, higher checkpoint must move the cursor forward"
    );
}
