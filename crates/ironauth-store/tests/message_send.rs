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
use ironauth_store::message_feedback::SuppressionReason;
use ironauth_store::message_hygiene::{dedup_key, normalize_recipient, window_index};
use ironauth_store::message_rate::RateBudget;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, Enqueued, MESSAGE_DELIVERY_CONSUMER, MessageId, NewMessage, Resent, Resolution,
    Scope,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// The window every test below sends in, so a collapse is about the KEY rather than about
/// two sends happening to straddle a boundary.
const WINDOW_SECS: u64 = 300;

fn payload(kind: &str) -> serde_json::Value {
    serde_json::json!({ "kind": kind })
}

/// Provision the scope's envelope keys.
///
/// `enqueue` seals the recipient under the scope's active DEK, so a scope with no DEK cannot
/// accept a send. In production every path that reaches a send has already sealed PII for this
/// scope, so the keys exist; a bare `seed_scope` has not, so tests do it explicitly rather than
/// having `enqueue` provision keys as a side effect of sending a message.
async fn provision_keys(db: &TestDatabase, env: &Env, scope: Scope) {
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

/// As `send_with_id`, with a payload the caller chooses.
///
/// A resend re-queues the ORIGINAL job's variables. Asserting that with the shared
/// `payload(kind)` fixture proves little: a resend that RE-DERIVED the payload from the kind
/// would produce a byte-identical object and pass. A marker unique to this send is what makes
/// the comparison discriminate.
async fn send_with_payload(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    recipient: &str,
    at_secs: u64,
    payload: &serde_json::Value,
) -> MessageId {
    let normalized = normalize_recipient(recipient).expect("a deliverable address");
    let key =
        dedup_key("email_otp", recipient, window_index(at_secs, WINDOW_SECS)).expect("a dedup key");
    let id = MessageId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .messages()
        .enqueue(
            env,
            NewMessage {
                id: &id,
                kind: "email_otp",
                recipient: &normalized,
                dedup_key: &key,
            },
            payload,
            RateBudget::new(1_000, 3_600),
            at_secs,
        )
        .await
        .expect("enqueue");
    id
}

/// Enqueue one send, returning what the store did with it AND the id it minted.
async fn send_with_id(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    kind: &str,
    recipient: &str,
    at_secs: u64,
) -> (Enqueued, MessageId) {
    let normalized = normalize_recipient(recipient).expect("a deliverable address");
    let window = window_index(at_secs, WINDOW_SECS);
    let key = dedup_key(kind, recipient, window).expect("a dedup key");
    let id = MessageId::generate(env, &scope);
    let outcome = db
        .store()
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
            // A budget wide enough that these tests are about the COLLAPSE, not the rate
            // limit. The rate limit has its own tests.
            RateBudget::new(1_000, 3_600),
            at_secs,
        )
        .await
        .expect("enqueue");
    (outcome, id)
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
            // A budget wide enough that these tests are about the COLLAPSE, not the rate
            // limit. The rate limit has its own tests.
            RateBudget::new(1_000, 3_600),
            at_secs,
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
    provision_keys(&db, &env, scope).await;

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
    provision_keys(&db, &env, scope).await;

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
    provision_keys(&db, &env, scope).await;

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
    provision_keys(&db, &env, scope).await;

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
    provision_keys(&db, &env, first).await;
    // The SAME tenant, a second environment. Two `seed_scope` calls would differ on tenant
    // AND environment, and then dropping `environment_id` from the UNIQUE would still pass:
    // the fixture could not attribute the outcome to the half it is named for. `environments`
    // has a global primary key, so `environment_id` alone determines `tenant_id` and is the
    // load-bearing column here.
    let second = Scope::new(
        first.tenant(),
        db.seed_environment(&env, first.tenant()).await,
    );
    provision_keys(&db, &env, second).await;

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
    provision_keys(&db, &env, scope).await;

    send(&db, &env, scope, "email_otp", "user@example.test", 1_000).await;
    let after_first = queued(&db, scope).await;
    // An ABSOLUTE anchor, not just "unchanged". Comparing the count to itself is satisfied by
    // zero, so a defect that queued nothing at all -- or a helper that silently stopped
    // queueing -- would pass a test written only as `after == before`.
    assert_eq!(after_first, 1, "the first send queues exactly one delivery");
    send(&db, &env, scope, "email_otp", "user@example.test", 1_000).await;
    assert_eq!(
        queued(&db, scope).await,
        1,
        "a collapse must leave the queue untouched; a job without a row delivers a message \
         no operator can account for"
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .messages()
            .count()
            .await
            .expect("count"),
        1,
        "and must write no second row"
    );
}

/// What the row SAYS, read back the way an operator reads it.
///
/// The recipient is a BLIND INDEX, never the address. That is the claim worth pinning here,
/// because it is the one a future change is most likely to undo for convenience: the two
/// tables that mail these same people (`email_otp_codes`, `magic_link_tokens`) seal and
/// blind-index their recipient, and a ledger that accumulates rather than being consumed is
/// the worst place to keep the plaintext one.
///
/// An earlier version of this test asserted the row "reads back normalized" by lowercasing
/// the address in the test and comparing. The store does no normalizing, so that compared the
/// test's own work against itself and could not fail.
#[tokio::test]
async fn the_row_holds_a_blind_index_and_never_the_address() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x117);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let address = "ada@example.test";
    let key = dedup_key("email_otp", address, window_index(1_000, WINDOW_SECS)).expect("a key");
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
                recipient: address,
                dedup_key: &key,
            },
            &payload("email_otp"),
            RateBudget::new(1_000, 3_600),
            1_000,
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
    assert!(
        !record.recipient_bidx.is_empty(),
        "a blind index is what identifies the recipient here"
    );
    assert_eq!(record.state, "pending");
    assert_eq!(record.failure_reason, None);

    // The plaintext address must appear NOWHERE the row can be read from. Read through the
    // owner pool so this is a statement about what is ON DISK rather than what one role sees.
    //
    // `position(bytea in bytea)`, NOT a cast to text. Postgres renders bytea as `\x` plus hex
    // under the default `bytea_output`, and `@` and `.` are not hex digits, so
    // `recipient_bidx::text LIKE '%ada@example.test%'` is UNSATISFIABLE: it reports zero leaks
    // for ANY column content, the plaintext address included. Measured: with the address bound
    // straight into the column, all sixteen tests stayed green under that predicate.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages \
         WHERE tenant_id = $1 AND environment_id = $2 \
         AND position($3::bytea in recipient_bidx) > 0",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(address.as_bytes())
    .fetch_one(db.owner_pool())
    .await
    .expect("scan the stored index");
    assert_eq!(
        leaked, 0,
        "the address must not be recoverable from the row"
    );

    let ordering_keys: Vec<String> = sqlx::query_scalar(
        "SELECT ordering_key FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND consumer = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(MESSAGE_DELIVERY_CONSUMER)
    .fetch_all(db.owner_pool())
    .await
    .expect("read the queued ordering keys");
    assert_eq!(ordering_keys.len(), 1);

    // The job's PAYLOAD, which nothing else here looks at: an enqueue that shipped an empty
    // one would satisfy every other assertion in this file.
    let payloads: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND consumer = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(MESSAGE_DELIVERY_CONSUMER)
    .fetch_all(db.owner_pool())
    .await
    .expect("read the queued payloads");
    assert_eq!(
        payloads,
        vec![payload("email_otp")],
        "the caller's payload is what is queued"
    );
    assert!(
        !ordering_keys[0].contains(address) && !ordering_keys[0].contains("ada"),
        "`ordering_key` is a plaintext column every consumer worker reads: putting the \
         address in it leaks exactly what the blind index avoids storing, got {:?}",
        ordering_keys[0]
    );
    assert!(
        ordering_keys[0].chars().all(|c| c.is_ascii_hexdigit()),
        "the ordering key should be the index, hex-encoded, got {:?}",
        ordering_keys[0]
    );
}

/// Two sends to the SAME recipient share an ordering key, and two different recipients do
/// not. That is the whole content of "ordered per recipient", and without it a constant key
/// (every send serialised behind every other) passes every other test here.
#[tokio::test]
async fn the_ordering_key_groups_by_recipient_and_separates_recipients() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x11a);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    send(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;
    // A later window, so this is a second SEND to the same person rather than a collapse.
    send(&db, &env, scope, "email_otp", "ada@example.test", 9_000).await;
    send(&db, &env, scope, "email_otp", "grace@example.test", 1_000).await;

    let keys: Vec<String> = sqlx::query_scalar(
        "SELECT ordering_key FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND consumer = $3 ORDER BY id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(MESSAGE_DELIVERY_CONSUMER)
    .fetch_all(db.owner_pool())
    .await
    .expect("read the queued ordering keys");
    assert_eq!(keys.len(), 3);
    let distinct: std::collections::BTreeSet<&String> = keys.iter().collect();
    assert_eq!(
        distinct.len(),
        2,
        "two sends to one person must share a key and a third person must not join them; \
         a constant key collapses this to 1 and a per-message key inflates it to 3: {keys:?}"
    );
}

/// A read for an identifier minted under a DIFFERENT scope is not this scope's message,
/// however well-formed the identifier is.
#[tokio::test]
async fn a_message_id_from_another_scope_is_not_found() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x118);
    let here = db.seed_scope(&env).await;
    provision_keys(&db, &env, here).await;
    // One dimension again: same tenant, other environment. With two independent scopes the
    // guard could be narrowed to compare tenants only and this test would not notice.
    let elsewhere = Scope::new(
        here.tenant(),
        db.seed_environment(&env, here.tenant()).await,
    );
    provision_keys(&db, &env, elsewhere).await;

    let foreign = MessageId::generate(&env, &elsewhere);
    let outcome = db.store().scoped(here).messages().by_id(&foreign).await;
    assert!(
        outcome.is_err(),
        "an id declaring another scope must be refused rather than answered with None, \
         which reads identically to a message that simply has not been sent yet"
    );
}

/// `enqueue` refuses an identifier minted under another scope, and refuses it BEFORE writing.
///
/// Its twin in `by_id` was tested and this one was not, which is the more dangerous half: a
/// read that ignores scope returns nothing (the SELECT binds both halves anyway), while a
/// WRITE that ignores scope lands a row in a scope that did not ask for it and queues a real
/// send against it. Neither scope can then read the row back: the row's own columns say one
/// scope, the id says another.
#[tokio::test]
async fn enqueue_refuses_an_identifier_from_another_scope_and_writes_nothing() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x11b);
    let here = db.seed_scope(&env).await;
    provision_keys(&db, &env, here).await;
    let elsewhere = Scope::new(
        here.tenant(),
        db.seed_environment(&env, here.tenant()).await,
    );
    provision_keys(&db, &env, elsewhere).await;

    let foreign = MessageId::generate(&env, &elsewhere);
    let key = dedup_key(
        "email_otp",
        "ada@example.test",
        window_index(1_000, WINDOW_SECS),
    )
    .expect("a key");
    let outcome = db
        .store()
        .scoped(here)
        .messages()
        .enqueue(
            &env,
            NewMessage {
                id: &foreign,
                kind: "email_otp",
                recipient: "ada@example.test",
                dedup_key: &key,
            },
            &payload("email_otp"),
            RateBudget::new(1_000, 3_600),
            1_000,
        )
        .await;
    assert!(
        outcome.is_err(),
        "a foreign-scope identifier must be refused, not written"
    );
    assert_eq!(
        db.store()
            .scoped(here)
            .messages()
            .count()
            .await
            .expect("count"),
        0,
        "the refusal must happen before the INSERT"
    );
    assert_eq!(
        queued(&db, here).await,
        0,
        "and before the delivery job: a queued job for a row nobody can read is a send \
         nobody can account for"
    );
}

/// The row and its delivery job are written in ONE transaction. This is the PR's stated
/// reason for the design and nothing measured it.
///
/// Asserting "both are present after a success" does not measure atomicity: two sequential
/// commits produce that too. What distinguishes them is what a FAILURE leaves behind, so this
/// makes the SECOND write fail and requires the first to be gone with it.
///
/// The failure is induced with a row, not with DDL. An earlier version added a CHECK
/// constraint to `outbox_messages` and dropped it afterwards, which passed locally and hung
/// CI's ironbus lane for thirty minutes: `ALTER TABLE` takes an ACCESS EXCLUSIVE lock, and in
/// that lane a live consumer is polling the same table, so the ALTER queued behind it and
/// every later reader queued behind the ALTER. Occupying the outbox's unique
/// (tenant, environment, consumer, `idempotency_key`) with the id this enqueue is about to use
/// needs only a row lock, and fails the insert for exactly the reason the test is about.
#[tokio::test]
async fn a_failed_delivery_job_takes_the_message_row_with_it() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x11c);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    // The id this send will use, minted first so its delivery job's idempotency key can be
    // taken before the send is made.
    let id = MessageId::generate(&env, &scope);
    sqlx::query(
        "INSERT INTO outbox_messages \
         (id, tenant_id, environment_id, consumer, idempotency_key, ordering_key, payload, \
          next_attempt_at, enqueued_at) \
         VALUES ($1, $2, $3, $4, $5, 'squatter', '{}'::jsonb, now(), now())",
    )
    .bind("obx_squatter_probe")
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(MESSAGE_DELIVERY_CONSUMER)
    .bind(id.to_string())
    .execute(db.owner_pool())
    .await
    .expect("occupy the idempotency key this send will want");

    let key = dedup_key(
        "email_otp",
        "ada@example.test",
        window_index(1_000, WINDOW_SECS),
    )
    .expect("a key");
    let outcome = db
        .store()
        .scoped(scope)
        .messages()
        .enqueue(
            &env,
            NewMessage {
                id: &id,
                kind: "email_otp",
                recipient: "ada@example.test",
                dedup_key: &key,
            },
            &payload("email_otp"),
            RateBudget::new(1_000, 3_600),
            1_000,
        )
        .await;
    assert!(
        outcome.is_err(),
        "the delivery job could not be queued, so the enqueue must fail"
    );

    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count rows");
    assert_eq!(
        rows, 0,
        "a message recorded without its delivery job never sends, and an operator reading \
         the ledger would be told it did"
    );
}

/// Row-level security on `messages` is real, not merely declared.
///
/// The other tests here read through the OWNER pool, which bypasses RLS entirely, so every
/// one of them passes with the policy dropped. This one reads as the application role with
/// one scope's settings and requires the other scope's row to be invisible. Measured: it
/// fails both with the policy gutted to `USING (true)` and with `ENABLE ROW LEVEL SECURITY`
/// removed.
///
/// What it does NOT measure is the `FORCE` half, and that is worth saying rather than
/// leaving a reader to assume otherwise. `FORCE` extends RLS to the table's OWNER; the owner
/// connection in this harness is a superuser, and a superuser bypasses row-level security
/// unconditionally, `FORCE` or not. Removing `FORCE` from the migration leaves all of these
/// tests green. It still belongs in the migration, because the owner in a deployment need
/// not be a superuser, but nothing here can hold it.
#[tokio::test]
async fn the_row_level_security_policy_hides_another_scopes_rows() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x11d);
    let here = db.seed_scope(&env).await;
    provision_keys(&db, &env, here).await;
    let elsewhere = Scope::new(
        here.tenant(),
        db.seed_environment(&env, here.tenant()).await,
    );
    provision_keys(&db, &env, elsewhere).await;

    send(&db, &env, here, "email_otp", "ada@example.test", 1_000).await;
    send(
        &db,
        &env,
        elsewhere,
        "email_otp",
        "grace@example.test",
        1_000,
    )
    .await;

    // Both rows exist on disk.
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(db.owner_pool())
        .await
        .expect("count every row");
    assert_eq!(total, 2);

    // As the APP role, with this scope's settings, only one is visible.
    let mut conn = db.app_pool().acquire().await.expect("app connection");
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, false)")
        .bind(here.tenant().to_string())
        .execute(&mut *conn)
        .await
        .expect("set tenant");
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, false)")
        .bind(here.environment().to_string())
        .execute(&mut *conn)
        .await
        .expect("set environment");
    let visible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(&mut *conn)
        .await
        .expect("count visible rows");
    assert_eq!(
        visible, 1,
        "the policy must hide the other environment's row from the data plane; with it \
         dropped this reads 2 and every other test here still passes"
    );
}

/// The two GRANT paragraphs in the migration are claims about privilege, and a comment is not
/// a privilege. Both are checked here as behaviour.
///
/// The control plane must NOT be able to enqueue: a management surface that could write a row
/// to this table could use the product as a mailer aimed at anyone. And the data plane must
/// not be able to rewrite a recipient index or a dedup key, because a plane that can rewrite
/// a dedup key can replay a send the collapse already refused.
#[tokio::test]
async fn the_control_plane_cannot_enqueue_and_the_data_plane_cannot_rewrite_a_send() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x11e);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;
    send(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;

    // The control plane's privilege, asked of the catalogue rather than inferred from a
    // failed statement. An INSERT attempt fails here for row-level security whether or not
    // the grant exists, so a test built on `is_err()` passes with INSERT granted and
    // measures nothing. Measured: this fails when the migration grants INSERT.
    for privilege in ["INSERT", "UPDATE", "DELETE"] {
        let held: bool = sqlx::query_scalar("SELECT has_table_privilege($1, 'messages', $2)")
            .bind("ironauth_control")
            .bind(privilege)
            .fetch_one(db.owner_pool())
            .await
            .expect("ask the catalogue");
        assert!(
            !held,
            "the control plane holds SELECT only; {privilege} here makes the management \
             surface a mailer"
        );
    }
    let reads: bool = sqlx::query_scalar("SELECT has_table_privilege($1, 'messages', 'SELECT')")
        .bind("ironauth_control")
        .fetch_one(db.owner_pool())
        .await
        .expect("ask the catalogue");
    assert!(reads, "and it does need to read");

    let mut app = db.app_pool().acquire().await.expect("app connection");
    for (column, value) in [("dedup_key", "rewritten"), ("kind", "rewritten")] {
        let updated = sqlx::query(&format!("UPDATE messages SET {column} = $1"))
            .bind(value)
            .execute(&mut *app)
            .await;
        assert!(
            updated.is_err(),
            "the data plane's UPDATE is column-scoped to the resolution columns; being \
             able to rewrite `{column}` lets it replay a send the collapse refused"
        );
    }
}

/// The sealed recipient round-trips, and the seal is bound to its table.
///
/// A consumer cannot mail a blind index, so the address has to survive the enqueue; migration
/// 0155 seals it rather than putting it on the outbox payload every worker reads. Two things
/// are worth pinning: that what comes back out is what went in, and that the ciphertext is not
/// the address sitting in a bytea column with extra steps.
#[tokio::test]
async fn the_sealed_recipient_round_trips_and_is_not_the_address_in_disguise() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x120);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let address = "ada@example.test";
    let (_, id) = send_with_id(&db, &env, scope, "email_otp", address, 1_000).await;

    let row: (Vec<u8>, i32) = sqlx::query_as(
        "SELECT recipient_sealed, pii_dek_version FROM messages \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the sealed recipient");
    assert!(!row.0.is_empty(), "a queued send must carry its recipient");
    assert!(row.1 >= 1, "and the DEK version that sealed it");
    let as_text = String::from_utf8_lossy(&row.0);
    assert!(
        !as_text.contains(address) && !as_text.contains("ada"),
        "the stored bytes must be ciphertext, not the address with extra steps"
    );

    // And it ROUND TRIPS, which is the half the title claimed and the body did not measure:
    // this test read the column and looked at it, and never once opened it. `open_recipient`
    // could have returned a constant and nothing here would have noticed.
    let opened = db
        .store()
        .scoped(scope)
        .messages()
        .open_recipient(&id)
        .await
        .expect("open the sealed recipient")
        .expect("a queued send carries one");
    assert_eq!(
        opened, "ada@example.test",
        "what the consumer mails must be what the door addressed"
    );
}

/// `resolve` writes the outcome once, and a second attempt is refused.
///
/// The second half matters as much as the first: a consumer that could resolve an
/// already-resolved message could overwrite a `failed` with a `sent`, and an operator reading
/// the ledger would be told a message arrived that never did.
#[tokio::test]
async fn resolve_records_the_outcome_once_and_refuses_a_second() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x121);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (_, id) = send_with_id(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;
    let repo = db.store();
    let messages = repo.scoped(scope);
    messages
        .messages()
        .resolve(&id, generation_of(&db, scope, &id).await, Resolution::Sent)
        .await
        .expect("first resolve");
    let record = messages
        .messages()
        .by_id(&id)
        .await
        .expect("read back")
        .expect("row");
    assert_eq!(record.state, "sent");
    assert_eq!(record.failure_reason, None);

    let again = messages
        .messages()
        .resolve(
            &id,
            generation_of(&db, scope, &id).await,
            Resolution::Failed { reason: "bounced" },
        )
        .await;
    assert!(
        again.is_err(),
        "a resolved message is finished; letting a second attempt through would let a failure \
         overwrite a success, or the reverse"
    );
    let after = messages
        .messages()
        .by_id(&id)
        .await
        .expect("read back")
        .expect("row");
    assert_eq!(after.state, "sent", "and the first outcome stands");
}

/// A failure records WHY, and the reason is a classification an operator can group by.
#[tokio::test]
async fn a_failed_delivery_records_its_reason() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x122);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (_, id) = send_with_id(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;
    db.store()
        .scoped(scope)
        .messages()
        .resolve(
            &id,
            generation_of(&db, scope, &id).await,
            Resolution::Failed {
                reason: "all_providers_unavailable",
            },
        )
        .await
        .expect("resolve");

    let record = db
        .store()
        .scoped(scope)
        .messages()
        .by_id(&id)
        .await
        .expect("read back")
        .expect("row");
    assert_eq!(record.state, "failed");
    assert_eq!(
        record.failure_reason.as_deref(),
        Some("all_providers_unavailable")
    );
}

/// Enqueue with an explicit budget and clock, for the hygiene tests.
async fn send_at(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    recipient: &str,
    budget: RateBudget,
    now: u64,
    window_at: u64,
) -> Enqueued {
    send_kind_at(
        db,
        env,
        scope,
        "email_otp",
        recipient,
        budget,
        now,
        window_at,
    )
    .await
}

/// As `send_at`, with the kind chosen by the caller. The rate budget is per RECIPIENT, so a
/// second kind to an exhausted mailbox is refused too, which is what lets a test tell a
/// payload that reports the refused send's kind apart from one that hardcodes a spelling.
#[allow(clippy::too_many_arguments)]
async fn send_kind_at(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    kind: &str,
    recipient: &str,
    budget: RateBudget,
    now: u64,
    window_at: u64,
) -> Enqueued {
    let normalized = normalize_recipient(recipient).expect("a deliverable address");
    let key =
        dedup_key(kind, recipient, window_index(window_at, WINDOW_SECS)).expect("a dedup key");
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
            budget,
            now,
        )
        .await
        .expect("enqueue")
}

/// Suppress a recipient with a reason.
async fn suppress(db: &TestDatabase, scope: Scope, bidx: &[u8], reason: &str) {
    sqlx::query(
        "INSERT INTO message_suppressions \
         (tenant_id, environment_id, recipient_bidx, reason) VALUES ($1, $2, $3, $4)",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(bidx)
    .bind(reason)
    .execute(db.owner_pool())
    .await
    .expect("record a suppression");
}

/// CRITERION 6. A send to a suppressed address is BLOCKED and the reason is queryable.
///
/// Blocked means nothing is written and nothing is queued: continuing to mail an address that
/// hard bounced burns the sending domain's reputation for every other tenant on it, and
/// continuing to mail one that complained is what gets a sender blocklisted.
#[tokio::test]
async fn a_send_to_a_suppressed_recipient_is_blocked_with_its_reason() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x150);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    // Learn the blind index by making one accepted send, then suppress that recipient.
    let accepted = send_at(
        &db,
        &env,
        scope,
        "ada@example.test",
        RateBudget::new(1_000, 3_600),
        1_000,
        1_000,
    )
    .await;
    assert_eq!(accepted, Enqueued::Accepted);
    let bidx: Vec<u8> = sqlx::query_scalar(
        "SELECT recipient_bidx FROM messages WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("the index");
    suppress(&db, scope, &bidx, "hard_bounce").await;

    let before = queued(&db, scope).await;
    // A LATER window, so a collapse cannot be what blocks it.
    let refused = send_at(
        &db,
        &env,
        scope,
        "ada@example.test",
        RateBudget::new(1_000, 3_600),
        90_000,
        90_000,
    )
    .await;
    assert_eq!(
        refused,
        Enqueued::Suppressed {
            reason: "hard_bounce".to_owned()
        },
        "a suppressed recipient must be refused WITH the reason: the operator's question is \
         never whether it is suppressed, it is why their user gets no mail"
    );
    assert_eq!(
        queued(&db, scope).await,
        before,
        "a blocked send must queue no delivery"
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .messages()
            .count()
            .await
            .expect("count"),
        1,
        "and write no row: a blocked send that occupied the collapse window would swallow a \
         later legitimate one"
    );
}

/// A DIFFERENT recipient is unaffected: suppression is per mailbox, not per scope.
#[tokio::test]
async fn suppressing_one_recipient_does_not_block_another() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x151);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    send_at(
        &db,
        &env,
        scope,
        "ada@example.test",
        RateBudget::new(1_000, 3_600),
        1_000,
        1_000,
    )
    .await;
    let bidx: Vec<u8> = sqlx::query_scalar(
        "SELECT recipient_bidx FROM messages WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("the index");
    suppress(&db, scope, &bidx, "complaint").await;

    let other = send_at(
        &db,
        &env,
        scope,
        "grace@example.test",
        RateBudget::new(1_000, 3_600),
        90_000,
        90_000,
    )
    .await;
    assert_eq!(
        other,
        Enqueued::Accepted,
        "one suppressed mailbox must not silence the whole environment"
    );
}

/// CRITERION 5. Exceeding the per-recipient budget BLOCKS the send.
///
/// The budget counts accepted sends in the window. A refused send writes no row, so it does not
/// count against the budget that refused it -- otherwise one refusal would extend the block for
/// a full window every time the caller retried.
#[tokio::test]
async fn exceeding_the_per_recipient_budget_blocks_the_send() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x152);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let budget = RateBudget::new(2, 3_600);
    // The two clocks are decoupled ON PURPOSE. The rate clock stays close together so all
    // three sends fall inside one 3600-second budget window, while the dedup window index is
    // pushed far apart so none of them collapses onto another. Using one value for both makes
    // the sends age out of the budget before the third arrives, and the test then passes for
    // the wrong reason -- it did, before this comment.
    for (n, now, window_at) in [(1_u32, 1_000_u64, 1_000_u64), (2, 1_200, 90_000)] {
        let outcome = send_at(&db, &env, scope, "ada@example.test", budget, now, window_at).await;
        assert_eq!(outcome, Enqueued::Accepted, "send {n} is within budget");
    }

    let before = queued(&db, scope).await;
    let refused = send_at(&db, &env, scope, "ada@example.test", budget, 1_400, 180_000).await;
    match refused {
        Enqueued::RateLimited {
            retry_after_epoch_seconds,
        } => assert!(
            retry_after_epoch_seconds > 1_400,
            "the caller must be told WHEN to come back, not left to guess: {retry_after_epoch_seconds}"
        ),
        other => panic!("the third send must be rate limited, got {other:?}"),
    }
    assert_eq!(
        queued(&db, scope).await,
        before,
        "a blocked send queues nothing"
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .messages()
            .count()
            .await
            .expect("count"),
        2,
        "and writes no row, so the refusal does not extend its own block"
    );
}

/// A send OUTSIDE the window is allowed again, so the limit is a window rather than a cap.
#[tokio::test]
async fn the_budget_refills_once_the_window_passes() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x153);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    // A one-hour budget of one. The second send is inside it, the third is past it.
    let budget = RateBudget::new(1, 3_600);
    assert_eq!(
        send_at(&db, &env, scope, "ada@example.test", budget, 1_000, 1_000).await,
        Enqueued::Accepted
    );
    assert!(
        matches!(
            send_at(&db, &env, scope, "ada@example.test", budget, 2_000, 90_000).await,
            Enqueued::RateLimited { .. }
        ),
        "a second send inside the window is over budget"
    );
    assert_eq!(
        send_at(
            &db,
            &env,
            scope,
            "ada@example.test",
            budget,
            100_000,
            180_000
        )
        .await,
        Enqueued::Accepted,
        "and past the window the budget has refilled"
    );
}

/// The reason comes FROM THE TABLE, not from a constant. A hardcoded literal passed the
/// suppression test, so the column was never actually read back.
#[tokio::test]
async fn the_suppression_reason_is_the_one_that_was_recorded() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x154);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    // Two different recipients, suppressed for two DIFFERENT reasons. A constant cannot
    // satisfy both.
    for (address, reason) in [
        ("ada@example.test", SuppressionReason::HardBounce),
        ("grace@example.test", SuppressionReason::Complaint),
    ] {
        db.store()
            .scoped(scope)
            .messages()
            .suppress(&normalize_recipient(address).expect("address"), reason)
            .await
            .expect("suppress");
    }

    assert_eq!(
        send_at(
            &db,
            &env,
            scope,
            "ada@example.test",
            RateBudget::new(9, 3_600),
            1_000,
            1_000
        )
        .await,
        Enqueued::Suppressed {
            reason: "hard_bounce".to_owned()
        }
    );
    assert_eq!(
        send_at(
            &db,
            &env,
            scope,
            "grace@example.test",
            RateBudget::new(9, 3_600),
            1_000,
            2_000
        )
        .await,
        Enqueued::Suppressed {
            reason: "complaint".to_owned()
        },
        "the reason must be read back per recipient, not fixed"
    );
}

/// `suppress` is idempotent and the FIRST reason stands. A second hard bounce does not make an
/// address more suppressed, and two rows would make "why" ambiguous.
#[tokio::test]
async fn suppressing_twice_keeps_the_first_reason() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x155);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;
    let address = normalize_recipient("ada@example.test").expect("address");
    let repo = db.store();

    repo.scoped(scope)
        .messages()
        .suppress(&address, SuppressionReason::HardBounce)
        .await
        .expect("first");
    repo.scoped(scope)
        .messages()
        .suppress(&address, SuppressionReason::Complaint)
        .await
        .expect("second");

    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM message_suppressions WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count");
    assert_eq!(rows, 1, "one suppression per recipient");
    assert_eq!(
        send_at(
            &db,
            &env,
            scope,
            "ada@example.test",
            RateBudget::new(9, 3_600),
            1_000,
            1_000
        )
        .await,
        Enqueued::Suppressed {
            reason: "hard_bounce".to_owned()
        },
        "the first reason stands"
    );
}

/// EVERY reason the feedback module can produce must satisfy the CHECK. A variant the column
/// refuses is a suppression that cannot be recorded, discovered at the moment a provider
/// reports a bounce -- the worst moment to find a constraint mismatch. `unsubscribe` was
/// missing from the first version of the constraint.
#[tokio::test]
async fn every_suppression_reason_the_feedback_module_produces_is_storable() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x156);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    for (n, reason) in [
        SuppressionReason::Complaint,
        SuppressionReason::HardBounce,
        SuppressionReason::RepeatedSoftBounce,
        SuppressionReason::Unsubscribe,
    ]
    .into_iter()
    .enumerate()
    {
        let address = format!("user{n}@example.test");
        db.store()
            .scoped(scope)
            .messages()
            .suppress(&address, reason)
            .await
            .unwrap_or_else(|error| panic!("{reason:?} must be storable: {error:?}"));
    }
}

/// The budget is per RECIPIENT, not per scope. A scope-wide limit passed every test.
#[tokio::test]
async fn the_budget_is_per_recipient_not_per_scope() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x157);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let budget = RateBudget::new(1, 3_600);
    assert_eq!(
        send_at(&db, &env, scope, "ada@example.test", budget, 1_000, 1_000).await,
        Enqueued::Accepted
    );
    // A DIFFERENT recipient, same scope, same window. A scope-wide counter refuses this.
    assert_eq!(
        send_at(&db, &env, scope, "grace@example.test", budget, 1_100, 2_000).await,
        Enqueued::Accepted,
        "one recipient's budget must not spend another's: a scope-wide limit would silence \
         every user as soon as one of them was busy"
    );
    // And the FIRST recipient is still limited, so the budget is real.
    assert!(matches!(
        send_at(&db, &env, scope, "ada@example.test", budget, 1_200, 3_000).await,
        Enqueued::RateLimited { .. }
    ));
}

/// The RETRY INSTANT is derived from the oldest counted send, not invented. `now + 1` passed
/// both rate tests, which would tell a caller to come back before the window had moved.
#[tokio::test]
async fn the_retry_instant_is_when_the_oldest_counted_send_leaves_the_window() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x158);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let window = 3_600_u64;
    let budget = RateBudget::new(1, window);
    let first_sent_at = 10_000_u64;
    assert_eq!(
        send_at(
            &db,
            &env,
            scope,
            "ada@example.test",
            budget,
            first_sent_at,
            1_000
        )
        .await,
        Enqueued::Accepted
    );

    let now = first_sent_at + 100;
    match send_at(&db, &env, scope, "ada@example.test", budget, now, 90_000).await {
        Enqueued::RateLimited {
            retry_after_epoch_seconds,
        } => assert_eq!(
            retry_after_epoch_seconds,
            first_sent_at + window,
            "the retry instant is the oldest counted send plus one window, not a guess"
        ),
        other => panic!("expected a rate limit, got {other:?}"),
    }
}

/// The CONFIGURED window length is used. Doubling it passed every test, so a deployment's
/// window was decoration.
#[tokio::test]
async fn the_configured_window_length_decides_what_counts() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x159);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    // One send at t=10_000, then a second at t=10_500.
    assert_eq!(
        send_at(
            &db,
            &env,
            scope,
            "ada@example.test",
            RateBudget::new(1, 600),
            10_000,
            1_000
        )
        .await,
        Enqueued::Accepted
    );
    // A 600-second window still contains the first send, so this is refused.
    assert!(
        matches!(
            send_at(
                &db,
                &env,
                scope,
                "ada@example.test",
                RateBudget::new(1, 600),
                10_500,
                90_000
            )
            .await,
            Enqueued::RateLimited { .. }
        ),
        "500 seconds later is inside a 600-second window"
    );
    // A 300-second window does NOT, so the same instant is accepted. Same ledger, same clock,
    // different configured window: the window is what decides.
    assert_eq!(
        send_at(
            &db,
            &env,
            scope,
            "ada@example.test",
            RateBudget::new(1, 300),
            10_500,
            90_000
        )
        .await,
        Enqueued::Accepted,
        "and outside a 300-second one"
    );
}

/// A FUTURE-stamped row does not block a recipient. Counting it would make one bad timestamp a
/// permanent block with no remedy short of deleting the row.
#[tokio::test]
async fn a_future_stamped_send_does_not_block_the_present() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x15a);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let budget = RateBudget::new(1, 3_600);
    // A send stamped far in the future.
    assert_eq!(
        send_at(
            &db,
            &env,
            scope,
            "ada@example.test",
            budget,
            9_000_000,
            1_000
        )
        .await,
        Enqueued::Accepted
    );
    // A send NOW is unaffected by it.
    assert_eq!(
        send_at(&db, &env, scope, "ada@example.test", budget, 10_000, 90_000).await,
        Enqueued::Accepted,
        "a row stamped in the future is not yet a send and must not spend the budget"
    );
}

/// How many simultaneous sends the concurrency test races.
const RACERS: usize = 8;

/// CONCURRENT sends to one recipient cannot exceed the budget.
///
/// Measured before the fix: eight simultaneous enqueues all passed a budget of ONE and all
/// eight rows landed. Checking a budget in one transaction and inserting in another is a
/// read-then-act, and the gap is reachable.
///
/// The dedup keys DIFFER on purpose. Eight identical sends share one key and the `ON CONFLICT`
/// refuses seven of them, so a same-key fixture passes whether or not the budget is enforced
/// and cannot tell the collapse from the limit. Different keys is the shape that goes straight
/// through: two message kinds for one address, or a burst straddling a window edge.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_sends_to_one_recipient_cannot_exceed_the_budget() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x15b);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let budget = RateBudget::new(1, 3_600);
    let barrier = Arc::new(tokio::sync::Barrier::new(RACERS));
    let store = db.store().clone();

    let mut handles = Vec::with_capacity(RACERS);
    for n in 0..RACERS {
        let barrier = Arc::clone(&barrier);
        let store = store.clone();
        let env = env.clone();
        handles.push(tokio::spawn(async move {
            // Distinct dedup windows, so the UNIQUE cannot be what refuses them.
            let window_at = 1_000 + (n as u64) * 100_000;
            let normalized = normalize_recipient("ada@example.test").expect("address");
            let key = dedup_key(
                "email_otp",
                "ada@example.test",
                window_index(window_at, WINDOW_SECS),
            )
            .expect("key");
            let id = MessageId::generate(&env, &scope);
            barrier.wait().await;
            store
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
                    budget,
                    1_000,
                )
                .await
                .expect("enqueue")
        }));
    }

    let mut accepted = 0_usize;
    for handle in handles {
        if handle.await.expect("task") == Enqueued::Accepted {
            accepted += 1;
        }
    }

    assert_eq!(
        accepted, 1,
        "a budget of one must admit exactly one send however many arrive at once; without \
         serialising the count with the insert, all {RACERS} passed"
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .messages()
            .count()
            .await
            .expect("count"),
        1,
        "and exactly one row may land"
    );
}

/// CRITERION 5's other half: exceeding the limit BLOCKS the send AND EMITS the event.
///
/// The conjunction is the point. A block nobody can observe is indistinguishable to an
/// operator from mail that silently never arrived, which is the complaint the criterion exists
/// to answer.
#[tokio::test]
async fn a_rate_limited_send_emits_the_message_rate_limited_event() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x15c);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    // The env clock and the `now` handed to `enqueue` are two different clocks, and a fixture
    // that leaves the first at the epoch while the second sits at 10_100 emits an envelope
    // whose two timestamps disagree by three hours. Advance them together, so the envelope is
    // coherent AND `occurred_at_unix_ms` has a value an assertion can pin.
    clock.advance(Duration::from_secs(10_000));

    let budget = RateBudget::new(1, 3_600);
    assert_eq!(
        send_at(&db, &env, scope, "ada@example.test", budget, 10_000, 1_000).await,
        Enqueued::Accepted
    );
    // Sampled AFTER the accept and asserted absolutely: a baseline read here instead would
    // absorb a spurious emission on the accept path into the starting count, and this event
    // means "your send was refused". An accepted send must announce nothing.
    assert!(
        webhook_events(&db, scope).await.is_empty(),
        "an accepted send must not announce a rate limit"
    );

    clock.advance(Duration::from_secs(100));
    // A DIFFERENT kind, because the budget is per RECIPIENT: this is refused just as a repeat
    // `email_otp` would be, and it is what makes the payload's `kind` a measured field rather
    // than one constant compared against another.
    let refused = send_kind_at(
        &db,
        &env,
        scope,
        "magic_link",
        "ada@example.test",
        budget,
        10_100,
        90_000,
    )
    .await;
    assert!(matches!(refused, Enqueued::RateLimited { .. }));

    let events = webhook_events(&db, scope).await;
    assert_eq!(
        events.len(),
        1,
        "the refusal must announce itself: a block nobody can observe reads to an operator \
         exactly like mail that silently never arrived"
    );
    let emitted = events.last().expect("an event");
    assert_eq!(emitted["type"], "message.rate_limited");
    assert_eq!(
        emitted["occurred_at_unix_ms"],
        serde_json::json!(10_100_u64 * 1_000),
        "the envelope is stamped from the env clock at the moment of the refusal"
    );
    let payload = &emitted["payload"];
    assert_eq!(
        payload["kind"], "magic_link",
        "the payload reports the kind of the send that was REFUSED"
    );
    assert_eq!(
        payload["retry_after_unix_seconds"],
        serde_json::json!(10_000_u64 + 3_600),
        "the event carries the instant the oldest counted send leaves the window"
    );

    // The refused send wrote no ledger row, so `messages` holds exactly the accepted one, and
    // its `recipient_bidx` is the value the event is supposed to be carrying. Read it from the
    // TABLE rather than recomputing it with the same `hex_of` the producer calls: an
    // expectation derived from the code under test cannot fail.
    let ledger: Vec<String> = sqlx::query_scalar(
        "SELECT encode(recipient_bidx, 'hex') FROM messages \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the ledger blind index");
    assert_eq!(ledger.len(), 1, "only the accepted send is recorded");
    assert_eq!(
        payload["recipient_bidx"].as_str(),
        Some(ledger[0].as_str()),
        "the event's index must be THIS recipient's, so a reader can correlate it with the \
         ledger: an all-zero constant is hex-shaped too"
    );

    // The ADDRESS must not be in it. A rate-limit feed is by construction a list of the
    // mailboxes under most pressure, and the event stream is what a tenant hands to
    // third-party sync targets.
    let rendered = emitted.to_string();
    assert!(
        !rendered.contains("ada@example.test") && !rendered.contains("ada"),
        "the event must carry the blind index, never the address: {rendered}"
    );
}

/// Two refused recipients get two ordering keys, and each key is that recipient's own index.
///
/// The producer's comment claims the feed is "ordered per RECIPIENT, so one person's refusals
/// arrive in order and different people's never wait on each other". A constant subject
/// satisfies the first half and breaks the second, and nothing else in this file reads
/// `ordering_key` for the `webhook.event` consumer, so without this the sentence is unmeasured.
#[tokio::test]
async fn refusals_are_ordered_per_recipient_and_never_share_a_key() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x15d);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;
    clock.advance(Duration::from_secs(10_000));

    let budget = RateBudget::new(1, 3_600);
    for recipient in ["ada@example.test", "grace@example.test"] {
        assert_eq!(
            send_at(&db, &env, scope, recipient, budget, 10_000, 1_000).await,
            Enqueued::Accepted
        );
    }
    for recipient in ["ada@example.test", "grace@example.test"] {
        assert!(matches!(
            send_at(&db, &env, scope, recipient, budget, 10_100, 90_000).await,
            Enqueued::RateLimited { .. }
        ));
    }

    let rows = webhook_event_rows(&db, scope).await;
    assert_eq!(rows.len(), 2, "one event per refusal");

    let keys: std::collections::BTreeSet<&String> = rows.iter().map(|(key, _)| key).collect();
    assert_eq!(
        keys.len(),
        2,
        "a constant subject collapses both recipients into one serial group, so one person's \
         stuck refusal would hold up everyone else's: {keys:?}"
    );

    // Each key is its OWN row's index, which is the identity a per-recipient key has to
    // satisfy. Two distinct keys alone would also pass for a per-EVENT key, which would
    // inflate the groups to one apiece and order nothing.
    for (key, envelope) in &rows {
        assert_eq!(
            Some(key.as_str()),
            envelope["payload"]["recipient_bidx"].as_str(),
            "the ordering key must be the recipient's index, not merely distinct: {envelope}"
        );
    }

    let indexes: std::collections::BTreeSet<String> = rows
        .iter()
        .filter_map(|(_, envelope)| {
            envelope["payload"]["recipient_bidx"]
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    let ledger: std::collections::BTreeSet<String> = sqlx::query_scalar(
        "SELECT encode(recipient_bidx, 'hex') FROM messages \
         WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the ledger blind indexes")
    .into_iter()
    .collect();
    assert_eq!(
        indexes, ledger,
        "the two events name the two mailboxes the ledger recorded"
    );
}

/// Every event queued for the webhook fan-out in this scope, oldest first, with its ordering
/// key. `webhook_events` reads the envelope alone, which leaves the key it was filed under
/// unread by any assertion.
async fn webhook_event_rows(db: &TestDatabase, scope: Scope) -> Vec<(String, serde_json::Value)> {
    sqlx::query_as::<_, (String, serde_json::Value)>(
        "SELECT ordering_key, payload FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND consumer = 'webhook.event' \
         ORDER BY sequence",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the queued events")
}

/// Every event queued for the webhook fan-out in this scope, oldest first.
async fn webhook_events(db: &TestDatabase, scope: Scope) -> Vec<serde_json::Value> {
    sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT payload FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND consumer = 'webhook.event' \
         ORDER BY sequence",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the queued events")
}

// =========================================================================================
// Resend (issue #111 criterion 1: "per-message status and resend are available via API").
// =========================================================================================

/// The generation a resolve must carry: the row's current `resend_count`.
///
/// Production reads it from `claim_for_delivery`, which hands back the generation it granted.
/// These fixtures resolve without claiming, so they read the counter directly rather than
/// hardcoding 0 -- a literal would silently stop matching the moment a fixture resends first,
/// and the resolve would quietly affect no rows.
async fn generation_of(db: &TestDatabase, scope: Scope, id: &MessageId) -> i32 {
    sqlx::query_scalar("SELECT resend_count FROM messages WHERE id = $1 AND tenant_id = $2")
        .bind(id.to_string())
        .bind(scope.tenant().to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("read the generation")
}

/// Every delivery job queued for a message, by the idempotency key it was filed under.
async fn delivery_keys(db: &TestDatabase, scope: Scope) -> Vec<String> {
    delivery_jobs(db, scope)
        .await
        .into_iter()
        .map(|(key, _, _)| key)
        .collect()
}

/// Every delivery job as `(idempotency_key, ordering_key, payload)`, oldest first.
///
/// The key alone was all any assertion read, which left the resend free to queue a job with a
/// constant ordering key or somebody else's payload.
async fn delivery_jobs(
    db: &TestDatabase,
    scope: Scope,
) -> Vec<(String, String, serde_json::Value)> {
    sqlx::query_as(
        "SELECT idempotency_key, ordering_key, payload FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND consumer = $3 ORDER BY sequence",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(MESSAGE_DELIVERY_CONSUMER)
    .fetch_all(db.owner_pool())
    .await
    .expect("read the queued delivery jobs")
}

/// A failed message re-queues, under a delivery key of its OWN.
///
/// The key is the whole test. `enqueue` files the original under the bare message id and the
/// outbox is UNIQUE on it, so a resend that re-filed the same key would collapse into the
/// completed original and queue NOTHING: the operator sees success, the ledger says pending,
/// and no mail is ever sent. Asserting only "the state moved" would pass against exactly that.
#[tokio::test]
// One narrative: the key, the payload, the ordering key, the state, the count and the
// timestamp all belong to the SAME resend. Splitting it would put the act in one function and
// what it changed in another.
#[allow(clippy::too_many_lines)]
async fn a_failed_message_resends_under_a_delivery_key_of_its_own() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x160);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let id = send_with_payload(
        &db,
        &env,
        scope,
        "ada@example.test",
        1_000,
        &serde_json::json!({ "kind": "email_otp", "code": "hunter2" }),
    )
    .await;
    db.store()
        .scoped(scope)
        .messages()
        .resolve(
            &id,
            generation_of(&db, scope, &id).await,
            Resolution::Failed {
                reason: "all_providers_unavailable",
            },
        )
        .await
        .expect("resolve failed");

    // As epoch micros, because this crate carries no time type sqlx can decode a timestamptz
    // into. The comparison stays in SQL either way.
    let before_resend: i64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint FROM messages WHERE id = $1",
    )
    .bind(id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read updated_at before the resend");

    let resent = db
        .store()
        .scoped(scope)
        .messages()
        .resend(&env, &id)
        .await
        .expect("resend");
    assert_eq!(resent, Resent::Requeued { attempt: 1 });

    let jobs = delivery_jobs(&db, scope).await;
    assert_eq!(
        jobs.iter()
            .map(|(key, _, _)| key.clone())
            .collect::<Vec<_>>(),
        vec![id.to_string(), format!("{id}#1")],
        "the resend must be a SECOND job: re-filing the original key raises on the outbox \
         UNIQUE and aborts the whole resend"
    );
    let (_, original_order, original_payload) = &jobs[0];
    let (_, resend_order, resend_payload) = &jobs[1];
    assert_eq!(
        resend_payload, original_payload,
        "the resend re-queues the ORIGINAL variables: the ledger holds no body to re-render \
         from, so anything else delivers a message the caller never composed"
    );
    assert!(
        resend_payload["code"].as_str() == Some("hunter2"),
        "and the fixture's payload must be distinguishable, or two empty objects compare \
         equal and the assertion above is vacuous: {resend_payload}"
    );
    assert_eq!(
        resend_order, original_order,
        "the resend stays in this recipient's ordering group rather than overtaking their \
         other mail"
    );

    let record = db
        .store()
        .scoped(scope)
        .messages()
        .by_id(&id)
        .await
        .expect("read back")
        .expect("row");
    assert_eq!(record.state, "pending", "the row is deliverable again");
    let (_, never_resent) =
        send_with_id(&db, &env, scope, "email_otp", "grace@example.test", 1_000).await;
    assert_eq!(
        db.store()
            .scoped(scope)
            .messages()
            .by_id(&never_resent)
            .await
            .expect("read")
            .expect("row")
            .resend_count,
        0,
        "a message that was never resent reports zero, so the field cannot be a constant"
    );
    assert_eq!(
        record.failure_reason, None,
        "the old reason is cleared: a pending message with a failure reason reads as though \
         the resend already failed"
    );
    assert_eq!(record.resend_count, 1);
    // Compared against the instant captured BEFORE the resend, not against `created_at`. The
    // `resolve` above already moved `updated_at` past `created_at`, so the original form held
    // for any test that had touched the row at all and said nothing about the resend.
    let moved: bool = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM updated_at) * 1000000)::bigint > $2 \
         FROM messages WHERE id = $1",
    )
    .bind(id.to_string())
    .bind(before_resend)
    .fetch_one(db.owner_pool())
    .await
    .expect("compare the timestamps");
    assert!(
        moved,
        "the resend transition must stamp updated_at, which is what a status surface reports \
         as 'last changed'"
    );
}

/// A message can be resent AGAIN after failing again, and each attempt gets its own key.
#[tokio::test]
async fn a_second_resend_gets_a_second_key() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x161);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (_, id) = send_with_id(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;
    let messages = db.store().scoped(scope).messages();
    for attempt in 1..=2 {
        messages
            .resolve(
                &id,
                generation_of(&db, scope, &id).await,
                Resolution::Failed { reason: "bounced" },
            )
            .await
            .expect("resolve failed");
        assert_eq!(
            messages.resend(&env, &id).await.expect("resend"),
            Resent::Requeued { attempt }
        );
    }
    assert_eq!(
        delivery_keys(&db, scope).await,
        vec![id.to_string(), format!("{id}#1"), format!("{id}#2")],
        "each attempt is its own job"
    );
    assert_eq!(
        messages
            .by_id(&id)
            .await
            .expect("read")
            .expect("row")
            .resend_count,
        2,
        "the ledger records HOW MANY times an operator re-queued this, which is what the \
         question \"why did this person get four copies\" reduces to. Asserted at 2 as well as \
         at 0 elsewhere, so no single hardcoded constant satisfies the suite"
    );
}

/// A resend is refused for every state a resend cannot act on, and the answer names the state.
///
/// `pending` and `sent` are the two that matter and they are refused for opposite reasons: one
/// is already queued and will be delivered, and the other was delivered, so mailing it again is
/// a NEW send with its own dedup window rather than a resend of this one.
#[tokio::test]
async fn resending_a_pending_or_sent_message_is_refused_with_its_state() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x162);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (_, pending) = send_with_id(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;
    let messages = db.store().scoped(scope).messages();
    assert_eq!(
        messages.resend(&env, &pending).await.expect("resend"),
        Resent::NotResendable {
            state: "pending".to_owned()
        }
    );

    let (_, sent) = send_with_id(&db, &env, scope, "email_otp", "grace@example.test", 1_000).await;
    messages
        .resolve(
            &sent,
            generation_of(&db, scope, &sent).await,
            Resolution::Sent,
        )
        .await
        .expect("resolve sent");
    assert_eq!(
        messages.resend(&env, &sent).await.expect("resend"),
        Resent::NotResendable {
            state: "sent".to_owned()
        }
    );

    assert_eq!(
        delivery_keys(&db, scope).await,
        vec![pending.to_string(), sent.to_string()],
        "a refused resend queues nothing"
    );
}

/// A STUCK `sending` row is resendable, because refusing strands it for good.
///
/// Migration 0156 left this to a person: a worker that dies mid-delivery leaves a row no other
/// worker will ever claim, and the database cannot know whether the provider accepted. Refusing
/// here would make that row permanently undeliverable with no recovery path at all.
#[tokio::test]
async fn a_stuck_sending_message_can_be_recovered_by_an_operator() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x163);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (_, id) = send_with_id(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;
    let claimed = db
        .store()
        .scoped(scope)
        .messages()
        .claim_for_delivery(&id)
        .await
        .expect("claim");
    assert_eq!(
        claimed,
        Some(0),
        "the claim moved it to sending, at generation 0"
    );

    assert_eq!(
        db.store()
            .scoped(scope)
            .messages()
            .resend(&env, &id)
            .await
            .expect("resend"),
        Resent::Requeued { attempt: 1 },
        "a stuck sending row is the operator's to recover"
    );
}

/// A resend to a SUPPRESSED recipient is refused, and the refusal names the reason.
///
/// Being an operator does not override a hard bounce or a spam complaint: those are
/// obligations to the recipient, and criterion 6 does not carve out an authenticated caller.
#[tokio::test]
async fn a_resend_to_a_suppressed_recipient_is_blocked() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x164);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (_, id) = send_with_id(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;
    let messages = db.store().scoped(scope).messages();
    messages
        .resolve(
            &id,
            generation_of(&db, scope, &id).await,
            Resolution::Failed { reason: "bounced" },
        )
        .await
        .expect("resolve failed");

    let record = messages.by_id(&id).await.expect("read").expect("row");
    suppress(
        &db,
        scope,
        &record.recipient_bidx,
        SuppressionReason::HardBounce.token(),
    )
    .await;

    assert_eq!(
        messages.resend(&env, &id).await.expect("resend"),
        Resent::Suppressed {
            reason: SuppressionReason::HardBounce.token().to_owned()
        }
    );
    assert_eq!(
        delivery_keys(&db, scope).await,
        vec![id.to_string()],
        "a suppressed resend queues nothing"
    );
    assert_eq!(
        messages.by_id(&id).await.expect("read").expect("row").state,
        "failed",
        "and it does not move the row: a suppressed message is not pending delivery"
    );

    // THE NEGATIVE, varying one dimension. Another recipient in the SAME scope, suppressed
    // nowhere, must still resend: without this the lookup can ignore `recipient_bidx` entirely
    // and refuse every resend in a scope that has any suppression at all.
    let (_, other) = send_with_id(&db, &env, scope, "email_otp", "grace@example.test", 1_000).await;
    messages
        .resolve(
            &other,
            generation_of(&db, scope, &other).await,
            Resolution::Failed { reason: "bounced" },
        )
        .await
        .expect("resolve failed");
    assert_eq!(
        messages.resend(&env, &other).await.expect("resend"),
        Resent::Requeued { attempt: 1 },
        "one recipient's suppression must not block another's resend"
    );
}

/// Once the delivery payload has been reaped, a resend REFUSES rather than mailing a blank.
///
/// The ledger deliberately holds no rendered body (0154), so the template variables live only
/// on the outbox job. Re-queueing without them would deliver a message with empty placeholders,
/// which SENDS and is useless, and the recipient is the one who finds out.
#[tokio::test]
async fn a_resend_refuses_once_the_delivery_payload_is_gone() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x165);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (_, id) = send_with_id(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;
    let messages = db.store().scoped(scope).messages();
    messages
        .resolve(
            &id,
            generation_of(&db, scope, &id).await,
            Resolution::Failed { reason: "bounced" },
        )
        .await
        .expect("resolve failed");

    // What the retention sweep eventually does to a completed job.
    sqlx::query(
        "DELETE FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND consumer = $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(MESSAGE_DELIVERY_CONSUMER)
    .execute(db.owner_pool())
    .await
    .expect("reap the job");

    assert_eq!(
        messages.resend(&env, &id).await.expect("resend"),
        Resent::PayloadExpired
    );
    assert!(
        delivery_keys(&db, scope).await.is_empty(),
        "nothing is queued for a message whose variables are gone"
    );
    assert_eq!(
        messages.by_id(&id).await.expect("read").expect("row").state,
        "failed",
        "and the row is NOT left pending with no job to deliver it, which would read to an \
         operator exactly like mail that is merely slow"
    );
}

/// Reaping only the ORIGINAL job does not make a resent message unresendable.
///
/// The payload lookup reads the LAST attempt's job, and this is what pins that. Deleting every
/// delivery job (as the test above does) is satisfied by a lookup that ignores the attempt
/// discriminator entirely, or the message identity: with attempt 1's job still present, a
/// lookup keyed on the bare id finds nothing and refuses a resend that should succeed.
#[tokio::test]
async fn reaping_the_original_job_does_not_strand_a_message_that_was_already_resent() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x167);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (_, id) = send_with_id(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;
    let messages = db.store().scoped(scope);
    let messages = messages.messages();
    for attempt in 1..=2 {
        messages
            .resolve(
                &id,
                generation_of(&db, scope, &id).await,
                Resolution::Failed { reason: "bounced" },
            )
            .await
            .expect("resolve failed");
        if attempt == 2 {
            // Retention reaps the ORIGINAL only. Attempt 1's job is still there, and it is the
            // one the next resend must read.
            sqlx::query(
                "DELETE FROM outbox_messages \
                 WHERE tenant_id = $1 AND environment_id = $2 AND consumer = $3 \
                   AND idempotency_key = $4",
            )
            .bind(scope.tenant().to_string())
            .bind(scope.environment().to_string())
            .bind(MESSAGE_DELIVERY_CONSUMER)
            .bind(id.to_string())
            .execute(db.owner_pool())
            .await
            .expect("reap the original job only");
        }
        assert_eq!(
            messages.resend(&env, &id).await.expect("resend"),
            Resent::Requeued { attempt },
            "attempt {attempt} must find the previous attempt's payload"
        );
    }
}

/// A message id from another scope is not resendable, and queues nothing.
///
/// The third member of the family the two existing cross-scope tests belong to, varying one
/// dimension: a sibling ENVIRONMENT of the same tenant.
#[tokio::test]
async fn a_message_id_from_another_scope_cannot_be_resent() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x168);
    let scope = db.seed_scope(&env).await;
    // A sibling ENVIRONMENT of the SAME tenant, so exactly one dimension varies. `seed_scope`
    // mints a fresh tenant too, and a fixture that differs on both cannot say which one the
    // guard is reading -- a scope check that compared only tenants would pass it.
    let other = Scope::new(
        scope.tenant(),
        db.seed_environment(&env, scope.tenant()).await,
    );
    provision_keys(&db, &env, scope).await;

    let (_, id) = send_with_id(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;
    db.store()
        .scoped(scope)
        .messages()
        .resolve(
            &id,
            generation_of(&db, scope, &id).await,
            Resolution::Failed { reason: "bounced" },
        )
        .await
        .expect("resolve failed");

    assert!(
        db.store()
            .scoped(other)
            .messages()
            .resend(&env, &id)
            .await
            .is_err(),
        "a scope may not resend another scope's message"
    );
    assert_eq!(
        delivery_keys(&db, scope).await,
        vec![id.to_string()],
        "and nothing is queued"
    );
}

/// `resend_count` cannot go negative: the CHECK the migration adds is real.
#[tokio::test]
async fn the_resend_count_cannot_be_driven_negative() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x169);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;
    let (_, id) = send_with_id(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;

    let refused = sqlx::query("UPDATE messages SET resend_count = -1 WHERE id = $1")
        .bind(id.to_string())
        .execute(db.owner_pool())
        .await;
    assert!(
        refused.is_err(),
        "the CHECK must refuse a negative count even to the owner"
    );
}

/// Two concurrent resends of one message queue ONE job, not two.
///
/// The move out of a terminal state is the guard: predicate and write are ONE statement, so two
/// callers serialise on the row lock and the loser affects zero rows. A SELECT-then-UPDATE
/// would let both observe `failed` and both queue, mailing the same person twice through the
/// recovery path.
///
/// # Why this holds a lock instead of just spawning tasks
///
/// Spawning four tasks does not produce the race. Each `resend` awaits its own round trips and
/// they interleave in whatever order the runtime picks, so in practice the first finishes
/// before the second reads: review measured a SELECT-then-UPDATE passing that shape 25 times
/// out of 25. A test for a race that never occurs is a test of nothing.
///
/// So the interleaving is FORCED. An outside transaction takes `SELECT ... FOR UPDATE` on the
/// row. Both callers' opening reads are plain MVCC reads and pass straight through it, so BOTH
/// observe `failed`; both then block on the lock at their UPDATE. Releasing it lets exactly one
/// through, and the other re-evaluates its predicate under READ COMMITTED against the row the
/// winner left. That is precisely the interleaving a SELECT-then-UPDATE loses to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_resends_of_one_message_queue_one_job() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x166);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (_, id) = send_with_id(&db, &env, scope, "email_otp", "ada@example.test", 1_000).await;
    db.store()
        .scoped(scope)
        .messages()
        .resolve(
            &id,
            generation_of(&db, scope, &id).await,
            Resolution::Failed { reason: "bounced" },
        )
        .await
        .expect("resolve failed");

    // The barrier: hold the row until both callers have read it.
    let mut gate = db.owner_pool().begin().await.expect("begin the gate");
    sqlx::query("SELECT id FROM messages WHERE id = $1 FOR UPDATE")
        .bind(id.to_string())
        .fetch_one(&mut *gate)
        .await
        .expect("lock the row");

    let db = Arc::new(db);
    let env = Arc::new(env);
    let mut handles = Vec::new();
    for _ in 0..2 {
        let db = Arc::clone(&db);
        let env = Arc::clone(&env);
        handles.push(tokio::spawn(async move {
            db.store()
                .scoped(scope)
                .messages()
                .resend(&env, &id)
                .await
                .expect("resend")
        }));
    }

    // Both callers are now past their read and parked on the lock. Release it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    gate.commit().await.expect("release the gate");

    let mut requeued = 0_usize;
    for handle in handles {
        if matches!(handle.await.expect("task"), Resent::Requeued { .. }) {
            requeued += 1;
        }
    }
    assert_eq!(
        requeued, 1,
        "exactly one caller may re-queue a message, however they interleave"
    );
    assert_eq!(
        delivery_keys(&db, scope).await,
        vec![id.to_string(), format!("{id}#1")],
        "and exactly one extra job exists"
    );
}

/// Each re-queue emits `message.resent` carrying ITS OWN attempt number.
///
/// Issue #108 criterion 6: every management write announces itself. A resend is the one write
/// on this surface that causes mail, and it announced nothing -- `scripts/producer-coverage.py`
/// named it, and a write no event describes is invisible to every integrator watching the feed.
/// For a resend that is the difference between "an operator re-sent it" and "our provider
/// double-delivered".
///
/// The negative half lives in `a_resend_refused_by_suppression_announces_nothing`, which this
/// function used to contain before it was split for length.
#[tokio::test]
async fn each_requeue_announces_its_own_attempt_number() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x1_6e);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let id = send_with_payload(
        &db,
        &env,
        scope,
        "resent@example.test",
        1_000,
        &serde_json::json!({ "kind": "email_otp", "code": "hunter2" }),
    )
    .await;
    db.store()
        .scoped(scope)
        .messages()
        .resolve(
            &id,
            generation_of(&db, scope, &id).await,
            Resolution::Failed {
                reason: "all_providers_unavailable",
            },
        )
        .await
        .expect("resolve failed");

    // THE BUILDER, which is what the production handler passes. It reads the attempt off the
    // outcome the store hands it, so this test cannot supply a number of its own -- which is
    // the point: the first version wrote `attempt: 1` into its own fixture and asserted only
    // `message_id`, so a hard-coded 1 in the production builder was invisible to it.
    //
    // A DISTINCT event id per resend, as the production builder produces. Reusing one trips the
    // outbox's per-consumer idempotency constraint on the second enqueue.
    let subject = id.to_string();
    let build_event = |outcome: &Resent| {
        let Resent::Requeued { attempt } = outcome else {
            return None;
        };
        let event_id = format!("evt_message_resent_{attempt}");
        let envelope = ironauth_store::event_catalog::envelope(
            &event_id,
            "message.resent",
            &scope.tenant().to_string(),
            &scope.environment().to_string(),
            1,
            &serde_json::json!({ "message_id": subject, "attempt": attempt }),
        )?;
        Some(ironauth_store::OwnedDomainEvent {
            id: event_id,
            subject: subject.clone(),
            envelope,
        })
    };

    let resent = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .messages()
        .resend_with_event(&env, &id, Some(&build_event))
        .await
        .expect("resend");
    assert_eq!(resent, Resent::Requeued { attempt: 1 });

    // A SECOND re-queue must announce attempt 2. Review measured what its absence hid: the
    // production builder wrote a literal 1 into every event forever, so a subscriber reading 1
    // four times concluded four FIRST resends -- the provider-double-delivery story this event
    // exists to rule out.
    //
    // BOTH are drained together, AFTER both resends, so the in-order `(1, 2)` assertion below
    // is a single observation of the feed rather than two readings stitched together.
    //
    // NOT because draining in between would hide anything. An earlier version of this comment
    // said it "reports zero", and that is false of `drain_message_events`, which COMPLETES what
    // it claims and so releases the ordering group -- measured: draining between the resends
    // returns 1 then 1, both correct. It is true only of a claim-only drain, which is what the
    // helper's own doc explains it is not.
    db.store()
        .scoped(scope)
        .messages()
        .resolve(
            &id,
            generation_of(&db, scope, &id).await,
            Resolution::Failed {
                reason: "all_providers_unavailable",
            },
        )
        .await
        .expect("resolve failed a second time");
    let second = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .messages()
        .resend_with_event(&env, &id, Some(&build_event))
        .await
        .expect("second resend");
    assert_eq!(second, Resent::Requeued { attempt: 2 });

    let events = drain_message_events(&db, scope).await;
    assert_eq!(events.len(), 2, "one event per re-queue: {events:?}");
    for event in &events {
        assert_eq!(event["type"], "message.resent");
        assert_eq!(event["payload"]["message_id"], subject);
        ironauth_store::event_catalog::validate_event(event)
            .expect("the envelope validates against the registry the fan-out enforces");
    }
    assert_eq!(
        (
            events[0]["payload"]["attempt"].as_i64(),
            events[1]["payload"]["attempt"].as_i64()
        ),
        (Some(1), Some(2)),
        "the attempts are the store's own, in order. A builder handed in from outside can only \
         guess: {events:?}"
    );
}

/// The webhook-bound events for `scope`, claimed AND COMPLETED until the feed is empty.
///
/// Both halves matter. COMPLETING matters because the outbox refuses to hand out an event while
/// an earlier one for the same subject is incomplete, so a helper that only claimed would leave
/// every drained event blocking its successors -- and a later "nothing was announced" assertion
/// would then pass because the feed was BLOCKED rather than because nothing was written.
///
/// LOOPING matters for the same reason from the other side: one claim returns at most one event
/// per subject however large the batch, because inside a single statement the earlier event is
/// still incomplete. Draining N events about one message takes N rounds, and a single-shot
/// helper reports 1 and reads as "only one was written".
async fn drain_message_events(db: &TestDatabase, scope: Scope) -> Vec<serde_json::Value> {
    let env = Env::system();
    let mut payloads = Vec::new();
    loop {
        let claimed = db
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                &env,
                ironauth_store::WEBHOOK_EVENT_CONSUMER,
                Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim webhook events");
        if claimed.is_empty() {
            return payloads;
        }
        for message in claimed {
            db.store()
                .scoped(scope)
                .outbox()
                .complete(&env, &message)
                .await
                .expect("complete the claimed event");
            payloads.push(message.payload);
        }
    }
}

/// A resend refused by SUPPRESSION announces nothing.
///
/// The negative half of `each_requeue_announces_its_own_attempt_number`, and it is the guard
/// rather than a second spelling of it. A suppressed recipient is a hard bounce or a complaint,
/// and the store refuses the resend on the recipient's behalf: no mail is queued, so no event
/// may claim any was. A subscriber that counted a suppressed resend as a delivery would be
/// counting mail that does not exist.
#[tokio::test]
async fn a_resend_refused_by_suppression_announces_nothing() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x1_6f);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let id = send_with_payload(
        &db,
        &env,
        scope,
        "suppressed@example.test",
        1_000,
        &serde_json::json!({ "kind": "email_otp", "code": "hunter2" }),
    )
    .await;
    let subject = id.to_string();
    let build_event = |outcome: &Resent| {
        let Resent::Requeued { attempt } = outcome else {
            return None;
        };
        let event_id = format!("evt_message_resent_{attempt}");
        let envelope = ironauth_store::event_catalog::envelope(
            &event_id,
            "message.resent",
            &scope.tenant().to_string(),
            &scope.environment().to_string(),
            1,
            &serde_json::json!({ "message_id": subject, "attempt": attempt }),
        )?;
        Some(ironauth_store::OwnedDomainEvent {
            id: event_id,
            subject: subject.clone(),
            envelope,
        })
    };
    // Suppress the recipient before the resend.
    // Read the blind index off the row rather than recomputing it: the point is to suppress
    // THIS message's recipient, and a recomputation that drifted from what `enqueue` stored
    // would suppress nobody while the test still read as a suppression case.
    let bidx: Vec<u8> =
        sqlx::query_scalar("SELECT recipient_bidx FROM messages WHERE id = $1 AND tenant_id = $2")
            .bind(id.to_string())
            .bind(scope.tenant().to_string())
            .fetch_one(db.owner_pool())
            .await
            .expect("read the recipient blind index");
    suppress(&db, scope, &bidx, "hard_bounce").await;
    db.store()
        .scoped(scope)
        .messages()
        .resolve(
            &id,
            generation_of(&db, scope, &id).await,
            Resolution::Failed {
                reason: "all_providers_unavailable",
            },
        )
        .await
        .expect("resolve failed again");

    let refused = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .messages()
        .resend_with_event(&env, &id, Some(&build_event))
        .await
        .expect("the refusal is an outcome, not an error");
    assert!(
        matches!(refused, Resent::Suppressed { .. }),
        "the recipient is suppressed: {refused:?}"
    );
    assert!(
        drain_message_events(&db, scope).await.is_empty(),
        "a resend that queued no mail must announce nothing. Nothing was ever enqueued in this \
         scope -- this test has its own database and its only resend is the refused one -- so \
         an empty answer means nothing was written rather than that a read was blocked."
    );
}
