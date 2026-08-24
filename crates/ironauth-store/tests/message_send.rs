// SPDX-License-Identifier: MIT OR Apache-2.0

//! Outbound message enqueue and its collapse window (issue #111 criteria 1 and 2).
//!
//! `message_prepare::prepare_message` and its ten sibling modules already decide everything
//! about a send: suppression, rate limiting, template resolution, rendering, MIME. They carry
//! 129 inline tests between them and, before this, not one production caller. What was absent
//! was somewhere to write the decision down and a job to act on it.
//!
//! These tests drive the store half of that: a send is recorded and a delivery job queued in
//! ONE transaction, and a duplicate inside the window collapses to one delivery rather than
//! two. The collapse is the criterion, and it is a UNIQUE constraint rather than a
//! read-then-write precisely because the doors it serves are where the race lives: a user
//! double-clicking "email me a code" issues two concurrent requests that both observe no row.

use ironauth_env::Env;
use ironauth_store::message_hygiene::{dedup_key, normalize_recipient, window_index};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{Enqueued, MESSAGE_DELIVERY_CONSUMER, MessageId, NewMessage, Scope};
use std::time::SystemTime;

/// The window every test below sends in, so a collapse is about the KEY rather than about
/// two sends happening to straddle a boundary.
const WINDOW_SECS: u64 = 300;

fn payload(kind: &str) -> serde_json::Value {
    serde_json::json!({ "kind": kind })
}

/// Enqueue one send, returning what the store did with it.
async fn send(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    kind: &str,
    recipient: &str,
    at_secs: u64,
) -> Enqueued {
    let normalized = normalize_recipient(recipient).expect("a deliverable address");
    let window = window_index(at_secs, WINDOW_SECS);
    let key = dedup_key(kind, recipient, window).expect("a dedup key");
    let id = MessageId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .messages()
        .enqueue(
            env,
            NewMessage {
                id: &id,
                kind,
                recipient: &normalized,
                dedup_key: &key,
            },
            &payload(kind),
        )
        .await
        .expect("enqueue")
}

/// How many delivery jobs are queued for this scope.
async fn queued(db: &TestDatabase, scope: Scope) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND consumer = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(MESSAGE_DELIVERY_CONSUMER)
    .fetch_one(db.owner_pool())
    .await
    .expect("count queued deliveries")
}

/// CRITERION 2. A second identical send inside the window collapses to one delivery.
#[tokio::test]
async fn a_second_identical_send_within_the_window_collapses_to_one_delivery() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x111);
    let scope = db.seed_scope(&env).await;

    let first = send(&db, &env, scope, "email_otp", "user@example.test", 1_000).await;
    assert_eq!(first, Enqueued::Accepted, "the first send is written");

    // Same kind, same address, same window. A user pressing the button twice.
    let second = send(&db, &env, scope, "email_otp", "user@example.test", 1_100).await;
    assert_eq!(
        second,
        Enqueued::Collapsed,
        "a duplicate inside the window must not be written again"
    );

    assert_eq!(
        db.store()
            .scoped(scope)
            .messages()
            .count()
            .await
            .expect("count"),
        1,
        "one message row, not two"
    );
    assert_eq!(
        queued(&db, scope).await,
        1,
        "and ONE delivery job: a collapse that still queued work would send the message twice"
    );
}

/// The collapse is per WINDOW, not forever: a later window is a new send.
#[tokio::test]
async fn the_same_recipient_in_a_later_window_is_a_new_send() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x112);
    let scope = db.seed_scope(&env).await;

    assert_eq!(
        send(&db, &env, scope, "email_otp", "user@example.test", 1_000).await,
        Enqueued::Accepted
    );
    // A full window later. The user genuinely asking again must not be silently ignored,
    // which is what a collapse with no time component would do.
    let later = 1_000 + WINDOW_SECS + WINDOW_SECS;
    assert_eq!(
        send(&db, &env, scope, "email_otp", "user@example.test", later).await,
        Enqueued::Accepted,
        "a send in a later window is a different key and must go out"
    );
    assert_eq!(queued(&db, scope).await, 2, "two windows, two deliveries");
}

/// The key carries the KIND, so two different messages to one person both go out.
#[tokio::test]
async fn two_different_kinds_to_one_recipient_do_not_collapse_into_each_other() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x113);
    let scope = db.seed_scope(&env).await;

    assert_eq!(
        send(&db, &env, scope, "email_otp", "user@example.test", 1_000).await,
        Enqueued::Accepted
    );
    assert_eq!(
        send(&db, &env, scope, "magic_link", "user@example.test", 1_000).await,
        Enqueued::Accepted,
        "a different message kind is a different send, not a duplicate"
    );
    assert_eq!(queued(&db, scope).await, 2);
}

/// Address NORMALIZATION is part of the key, so casing does not defeat the collapse.
#[tokio::test]
async fn a_differently_cased_address_is_the_same_recipient() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x114);
    let scope = db.seed_scope(&env).await;

    assert_eq!(
        send(&db, &env, scope, "email_otp", "User@Example.Test", 1_000).await,
        Enqueued::Accepted
    );
    assert_eq!(
        send(&db, &env, scope, "email_otp", "user@example.test", 1_000).await,
        Enqueued::Collapsed,
        "casing must not buy a second send: the key hashes the normalized address"
    );
    assert_eq!(queued(&db, scope).await, 1);
}

/// One scope's send does not collapse another's, and neither can see the other's rows.
#[tokio::test]
async fn a_send_in_one_environment_does_not_collapse_a_send_in_another() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x115);
    let first = db.seed_scope(&env).await;
    let second = db.seed_scope(&env).await;

    assert_eq!(
        send(&db, &env, first, "email_otp", "user@example.test", 1_000).await,
        Enqueued::Accepted
    );
    // Identical kind, address and window, different environment. The unique constraint is
    // per scope, so this is a different send and must go out.
    assert_eq!(
        send(&db, &env, second, "email_otp", "user@example.test", 1_000).await,
        Enqueued::Accepted,
        "the collapse window is per environment, not global"
    );
    assert_eq!(queued(&db, first).await, 1);
    assert_eq!(queued(&db, second).await, 1);
}

/// The record and its delivery job are written together or not at all.
#[tokio::test]
async fn a_collapsed_send_queues_no_delivery_job() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x116);
    let scope = db.seed_scope(&env).await;

    send(&db, &env, scope, "email_otp", "user@example.test", 1_000).await;
    let after_first = queued(&db, scope).await;
    send(&db, &env, scope, "email_otp", "user@example.test", 1_000).await;
    assert_eq!(
        queued(&db, scope).await,
        after_first,
        "a collapse must leave the queue untouched; a job without a row delivers a message \
         no operator can account for"
    );
}

/// What the row SAYS, read back the way an operator reads it.
///
/// Two claims the table makes about itself are checked here, because both are the kind that
/// stay true in the comment long after they stop being true in the column. The recipient is
/// stored NORMALIZED, so a listing groups by the mailbox a send addressed rather than by the
/// casing whichever caller happened to pass; and a fresh row is `pending` with no failure
/// reason, because a reason is the answer to "why did this not arrive" and a row that has not
/// been attempted yet has no answer to give.
#[tokio::test]
async fn a_recorded_send_reads_back_normalized_and_pending() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x117);
    let scope = db.seed_scope(&env).await;

    let written = "Ada@Example.TEST";
    let normalized = normalize_recipient(written).expect("a deliverable address");
    let key = dedup_key("email_otp", written, window_index(1_000, WINDOW_SECS)).expect("a key");
    let id = MessageId::generate(&env, &scope);
    let outcome = db
        .store()
        .scoped(scope)
        .messages()
        .enqueue(
            &env,
            NewMessage {
                id: &id,
                kind: "email_otp",
                recipient: &normalized,
                dedup_key: &key,
            },
            &payload("email_otp"),
        )
        .await
        .expect("enqueue");
    assert_eq!(outcome, Enqueued::Accepted);

    let record = db
        .store()
        .scoped(scope)
        .messages()
        .by_id(&id)
        .await
        .expect("read back")
        .expect("the row exists");
    assert_eq!(record.id, id);
    assert_eq!(record.kind, "email_otp");
    assert_eq!(
        record.recipient, "ada@example.test",
        "the row must hold the normalized mailbox, not the casing the caller wrote"
    );
    assert_ne!(
        record.recipient, written,
        "a row that stored the raw casing would still pass an equality check written \
         against that same raw casing"
    );
    assert_eq!(record.state, "pending");
    assert_eq!(record.failure_reason, None);
}

/// A read for an identifier minted under a DIFFERENT scope is not this scope's message,
/// however well-formed the identifier is.
#[tokio::test]
async fn a_message_id_from_another_scope_is_not_found() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x118);
    let here = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;

    let foreign = MessageId::generate(&env, &elsewhere);
    let outcome = db.store().scoped(here).messages().by_id(&foreign).await;
    assert!(
        outcome.is_err(),
        "an id declaring another scope must be refused rather than answered with None, \
         which reads identically to a message that simply has not been sent yet"
    );
}
