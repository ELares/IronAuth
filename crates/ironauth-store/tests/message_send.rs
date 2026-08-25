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
use ironauth_store::{
    CorrelationId, Enqueued, MESSAGE_DELIVERY_CONSUMER, MessageId, NewMessage, Resolution, Scope,
};
use std::time::SystemTime;

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

    // The plaintext address must appear NOWHERE the row can be read from, including the
    // delivery job the same transaction queued. Read through the owner pool so this is a
    // statement about what is ON DISK rather than about what one role can see.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages \
         WHERE tenant_id = $1 AND environment_id = $2 \
         AND recipient_bidx::text LIKE $3",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(format!("%{address}%"))
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
    send(&db, &env, scope, "email_otp", address, 1_000).await;

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
        .resolve(&id, Resolution::Sent)
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
        .resolve(&id, Resolution::Failed { reason: "bounced" })
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
