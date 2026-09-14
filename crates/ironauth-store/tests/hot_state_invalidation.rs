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

/// An hour from the epoch, in microseconds: long enough that nothing in these tests expires.
const AN_HOUR: i64 = 3_600_000_000;

#[tokio::test]
async fn a_change_on_one_node_is_seen_by_every_other_node() {
    // CRITERION 1. Two nodes read one feed from their own positions, so both see the same
    // invalidation. A queue would have handed it to whichever claimed it first and completed it,
    // leaving the other node's accelerator serving the old value for its whole TTL.
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
        let batch = feed.next_batch(node, 100).await.expect("read");
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
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.restart_app_store().await;
    let feed = store.scoped(scope);
    let feed = feed.hot_state_invalidations();

    feed.write_and_announce(&env, "jwks", "kid-1", b"v", AN_HOUR, "rotation-1", false)
        .await
        .expect("announce");

    let InvalidationBatch::Apply { forget, through } =
        feed.next_batch("node-a", 100).await.expect("first read")
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
    let InvalidationBatch::Apply { forget, .. } =
        feed.next_batch("node-b", 100).await.expect("other node")
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

    let InvalidationBatch::Apply { forget, .. } =
        feed.next_batch("node-a", 100).await.expect("read")
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
        feed.next_batch("brand-new-node", 100).await.expect("read")
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

    let InvalidationBatch::Apply { forget, through } =
        feed.next_batch("node-a", 100).await.expect("read")
    else {
        panic!("cold flush on a fresh feed")
    };
    assert!(
        forget.is_empty(),
        "a row belonging to another consumer must not be read as an invalidation: {forget:?}"
    );

    // AND THE CURSOR STILL ADVANCES PAST IT. The page is a slice of the WHOLE feed, so a reader
    // that only checkpointed as far as the last INVALIDATION would re-read this row on every
    // pass for ever. That is the other half of why `through` is the page's last sequence.
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
    let InvalidationBatch::Apply { through, .. } =
        feed.next_batch("node-a", 1).await.expect("read one")
    else {
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
