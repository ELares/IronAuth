// SPDX-License-Identifier: MIT OR Apache-2.0

//! The messaging ledger has a producer (issue #111).
//!
//! Before this, `MessageRepo::enqueue` had ZERO production callers. The ledger, the collapse,
//! the rate limit, the suppression check, the failover and both management endpoints were all
//! implemented, wired into the shipped binary, and covered by passing tests, and nothing ever
//! handed them a message.
//!
//! The door is `VerificationSender::send`, the one delivery method whose variables are safe to
//! write down: a scope, a coarse purpose, and a recipient, with the body coming from a template.
//! The other four carry a token -- an OTP code, a magic link, a disavowal link, a cancellation
//! link -- and `message_composer` excludes them from this path in as many words.

use ironauth_env::Env;
use ironauth_oidc::message_sender::{MessagingVerificationSender, NOTICE_WINDOW_SECS};
use ironauth_oidc::{VerificationPurpose, VerificationSender};
use ironauth_store::CorrelationId;
use ironauth_store::message_rate::RateBudget;
use ironauth_store::test_support::TestDatabase;
use sqlx::Row as _;

/// Provision the envelope keys the ledger seals a recipient with.
///
/// `enqueue` seals the recipient blind index, so without a KEK and DEK for the scope it fails
/// with `StoreError::Encryption` before writing anything -- which looks exactly like a producer
/// that does nothing. Every future door needs this.
async fn provision(db: &TestDatabase, env: &Env, scope: ironauth_store::Scope) {
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    acting
        .envelope()
        .provision_kek(env, &db.master_key())
        .await
        .expect("provision kek");
    acting
        .envelope()
        .provision_dek(env, &db.master_key())
        .await
        .expect("provision dek");
}

fn sender(db: &TestDatabase, env: &Env) -> MessagingVerificationSender {
    MessagingVerificationSender::new(db.store().clone(), env.clone(), RateBudget::new(100, 3_600))
}

async fn count(db: &TestDatabase, scope: ironauth_store::Scope, kind: Option<&str>) -> i64 {
    let sql = match kind {
        Some(_) => {
            "SELECT COUNT(*) AS n FROM messages WHERE tenant_id = $1 AND environment_id = $2 AND kind = $3"
        }
        None => "SELECT COUNT(*) AS n FROM messages WHERE tenant_id = $1 AND environment_id = $2",
    };
    let mut query = sqlx::query(sql)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string());
    if let Some(kind) = kind {
        query = query.bind(kind);
    }
    query
        .fetch_one(db.owner_pool())
        .await
        .expect("count")
        .get("n")
}

#[tokio::test]
async fn a_notice_lands_in_the_ledger_with_a_delivery_job() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;

    sender(&db, &env)
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;

    assert_eq!(
        count(
            &db,
            scope,
            Some(VerificationPurpose::AccountLinked.as_str())
        )
        .await,
        1,
        "a delivered notice must land a message; the ledger had no producer before this"
    );

    // The delivery job rides the SAME transaction as the row, which is why the outbox exists:
    // a message recorded without a job never sends.
    let jobs: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM outbox_messages WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count jobs")
    .get("n");
    assert!(jobs >= 1, "a queued message must have a delivery job");
}

/// The payload carries NO secret, and it composes.
///
/// Both halves matter and each was a separate blocker in review. A payload with a live token in
/// it publishes that token to anything reading the outbox; a payload with no `message_id`
/// composes to `Err("no_message_id")`, which the consumer marks Failed, so every notice
/// terminates without a provider ever being contacted.
#[tokio::test]
async fn the_payload_carries_no_secret_and_still_composes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;

    sender(&db, &env)
        .send(
            scope,
            VerificationPurpose::AccountUnlinked,
            "user@example.test",
        )
        .await;

    // From `outbox_messages`, which is where the payload actually lives -- and which is
    // exactly where a secret would be published: every consumer worker reads this table, and
    // the management events API serves it.
    let payload: serde_json::Value = sqlx::query(
        "SELECT payload FROM outbox_messages WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the payload")
    .get("payload");

    let object = payload.as_object().expect("an object");
    // Exactly what a coarse notice needs and nothing else. An allowlist rather than a denylist:
    // asserting "no token" would pass for any future field somebody adds.
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["message_id", "purpose"],
        "the payload rides a durable queue every consumer worker reads, so it carries only \
         variables that are safe to write down"
    );
    assert!(
        object["message_id"].as_str().is_some_and(|id| {
            !id.is_empty()
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        }),
        "the composer refuses a payload whose message_id is missing or not id-safe, and the \
         consumer marks that job Failed: {payload}"
    );
}

/// Two DIFFERENT purposes to one recipient do not collapse onto each other.
///
/// The dedup key is (kind, recipient, window), and the kind is the purpose. Sharing one kind
/// across purposes would suppress an alert about one event because an unrelated one had just
/// fired -- which is a security failure, not a deduplication.
#[tokio::test]
async fn two_purposes_to_one_recipient_do_not_collapse() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;
    let sender = sender(&db, &env);

    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;
    sender
        .send(
            scope,
            VerificationPurpose::AccountUnlinked,
            "user@example.test",
        )
        .await;

    assert_eq!(
        count(&db, scope, None).await,
        2,
        "different purposes are different messages"
    );
    assert_eq!(
        count(
            &db,
            scope,
            Some(VerificationPurpose::AccountLinked.as_str())
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &db,
            scope,
            Some(VerificationPurpose::AccountUnlinked.as_str())
        )
        .await,
        1
    );
}

/// A repeat of the SAME purpose inside the window collapses.
#[tokio::test]
async fn a_repeat_inside_the_window_collapses() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;
    let sender = sender(&db, &env);

    for _ in 0..3 {
        sender
            .send(
                scope,
                VerificationPurpose::AccountLinked,
                "user@example.test",
            )
            .await;
    }
    assert_eq!(
        count(&db, scope, None).await,
        1,
        "three identical notices in one window are one send"
    );
    // The window's FLOOR is asserted where the constant lives (`const _: () = assert!(...)`),
    // because a runtime assertion comparing a constant to a literal is a compile-time truth
    // dressed as a test. What this test pins is the collapse; `a_notice_in_a_later_window_is_a_
    // new_send` pins that the window moves.
}

/// An undeliverable recipient queues nothing and does not panic.
///
/// This door fires for every verified channel, and a tenant whose identifier type is a username
/// reaches it with something that is not an address.
#[tokio::test]
async fn an_undeliverable_recipient_queues_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;

    sender(&db, &env)
        .send(scope, VerificationPurpose::AccountLinked, "not-an-address")
        .await;

    assert_eq!(count(&db, scope, None).await, 0);
}

/// The recipient is stored blind-indexed, never as written.
#[tokio::test]
async fn the_recipient_is_not_stored_in_plaintext() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    provision(&db, &env, scope).await;

    sender(&db, &env)
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;

    // The whole row, rendered, must not contain the address as written.
    let recipient_bidx: Vec<u8> =
        sqlx::query("SELECT recipient_bidx FROM messages WHERE tenant_id = $1")
            .bind(scope.tenant().to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("read the row")
            .get("recipient_bidx");
    assert!(
        !String::from_utf8_lossy(&recipient_bidx).contains("user@example.test"),
        "the recipient is stored as a blind index, never as written"
    );

    let payload: serde_json::Value =
        sqlx::query("SELECT payload FROM outbox_messages WHERE tenant_id = $1")
            .bind(scope.tenant().to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("read the payload")
            .get("payload");
    assert!(
        !payload.to_string().contains("user@example.test"),
        "and the payload -- which every consumer worker reads -- must not carry it either"
    );
}

/// A notice in a LATER window is a new send, not a collapse.
///
/// The collapse test alone proves only that the dedup key is stable: freezing the window index
/// to a constant makes every notice for a recipient collapse forever -- a user who links an
/// account today and again next year is told once -- and it left that test green. This is the
/// half that pins the window as a WINDOW.
#[tokio::test]
async fn a_notice_in_a_later_window_is_a_new_send() {
    let db = TestDatabase::start().await;
    let system = Env::system();
    let scope = db.seed_scope(&system).await;
    provision(&db, &system, scope).await;

    // A controllable clock, so "a later window" is a fact about the code rather than about how
    // long the test took to run.
    let (env, clock) = Env::deterministic(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000),
        1,
    );
    let sender = MessagingVerificationSender::new(
        db.store().clone(),
        env.clone(),
        RateBudget::new(100, 3_600),
    );

    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;
    assert_eq!(count(&db, scope, None).await, 1);

    // Same purpose, same recipient, one whole window later.
    clock.advance(std::time::Duration::from_secs(NOTICE_WINDOW_SECS + 1));
    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;
    assert_eq!(
        count(&db, scope, None).await,
        2,
        "a later window is a new send; a window that never moves is a permanent mute"
    );
}

/// A differently-cased address lands the SAME blind index.
///
/// The collapse cannot show this and it is worth saying why: `dedup_key` normalizes internally,
/// so two spellings collapse whether or not the CALLER normalizes. What diverges is the blind
/// index, which `enqueue` computes from exactly what it was handed -- the store's own contract
/// says so. Two rows whose indexes disagree are one mailbox recorded as two recipients, and a
/// suppression keyed on one would miss the other.
///
/// So the two sends are put in DIFFERENT windows, which defeats the collapse and leaves two rows
/// to compare.
#[tokio::test]
async fn a_differently_cased_address_lands_the_same_blind_index() {
    let db = TestDatabase::start().await;
    let system = Env::system();
    let scope = db.seed_scope(&system).await;
    provision(&db, &system, scope).await;

    let (env, clock) = Env::deterministic(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000),
        1,
    );
    let sender = MessagingVerificationSender::new(
        db.store().clone(),
        env.clone(),
        RateBudget::new(100, 3_600),
    );

    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "User@Example.Test",
        )
        .await;
    clock.advance(std::time::Duration::from_secs(NOTICE_WINDOW_SECS + 1));
    sender
        .send(
            scope,
            VerificationPurpose::AccountLinked,
            "user@example.test",
        )
        .await;

    let rows = sqlx::query("SELECT recipient_bidx FROM messages WHERE tenant_id = $1")
        .bind(scope.tenant().to_string())
        .fetch_all(db.owner_pool())
        .await
        .expect("read the rows");
    assert_eq!(
        rows.len(),
        2,
        "different windows, so both sends are recorded"
    );
    let first: Vec<u8> = rows[0].get("recipient_bidx");
    let second: Vec<u8> = rows[1].get("recipient_bidx");
    assert_eq!(
        first, second,
        "one mailbox is one recipient however it was typed; differing indexes would make a \
         suppression keyed on one miss the other"
    );
}
