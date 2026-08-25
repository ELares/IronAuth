// SPDX-License-Identifier: MIT OR Apache-2.0

//! The delivery consumer end to end (issue #111 criterion 1).
//!
//! These are the first tests in which the messaging island does its job for real: a row is
//! enqueued, the consumer opens the sealed recipient, composes, walks the provider list, and
//! writes down what happened. Until this consumer existed, eleven modules decided everything
//! about a send and none of them ran outside a unit test.
//!
//! The four cases are the four an operator has to be able to tell apart, and the middle two are
//! the ones that are expensive to confuse: a message every provider will refuse must not be
//! retried at each of them in turn, and an outage must not be recorded as a permanent failure.

use ironauth_env::Env;
use ironauth_store::message_consumer::{MessageComposer, MessageDeliveryConsumer};
use ironauth_store::message_delivery::{MessageProvider, SendFuture};
use ironauth_store::message_failover::Outcome;
use ironauth_store::message_hygiene::{dedup_key, normalize_recipient, window_index};
use ironauth_store::message_prepare::PreparedMessage;
use ironauth_store::message_rate::RateBudget;
use ironauth_store::message_template::{Locale, TemplateLevel};
use ironauth_store::outbox::OutboxConsumer;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, MessageId, NewMessage, OutboxMessage, Scope};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

const WINDOW_SECS: u64 = 300;

/// A provider that returns a scripted outcome and counts its attempts.
#[derive(Debug)]
struct ScriptedProvider {
    name: String,
    outcome: Outcome,
    attempts: Arc<AtomicUsize>,
}

impl MessageProvider for ScriptedProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn send<'a>(&'a self, _message: &'a PreparedMessage) -> SendFuture<'a> {
        Box::pin(async move {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            self.outcome
        })
    }
}

/// A provider that counts entry and then PARKS, so a test can hold one worker inside its
/// delivery while it runs another. Counting at entry is the point: it records that a worker
/// reached a provider at all, which is what "mailed the recipient" means here.
#[derive(Debug)]
struct GatedProvider {
    entered: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Notify>,
}

impl MessageProvider for GatedProvider {
    fn name(&self) -> &'static str {
        "gated"
    }

    fn send<'a>(&'a self, _message: &'a PreparedMessage) -> SendFuture<'a> {
        Box::pin(async move {
            self.entered.fetch_add(1, Ordering::Relaxed);
            self.release.notified().await;
            Outcome::Delivered
        })
    }
}

fn provider(name: &str, outcome: Outcome) -> (Box<dyn MessageProvider>, Arc<AtomicUsize>) {
    let attempts = Arc::new(AtomicUsize::new(0));
    (
        Box::new(ScriptedProvider {
            name: name.to_owned(),
            outcome,
            attempts: Arc::clone(&attempts),
        }),
        attempts,
    )
}

/// Composes a fixed message, and records the recipient it was handed so a test can assert the
/// consumer opened the seal rather than inventing an address.
#[derive(Debug, Default)]
struct RecordingComposer {
    seen: std::sync::Mutex<Vec<String>>,
    /// How many CONFIGURED templates the consumer handed over on the last call.
    templates_seen: std::sync::Mutex<Vec<usize>>,
    refuse: Option<String>,
}

impl MessageComposer for RecordingComposer {
    fn compose(
        &self,
        _scope: Scope,
        kind: &str,
        recipient: &str,
        _payload: &serde_json::Value,
        configured: &[ironauth_store::MessageTemplateRecord],
    ) -> Result<PreparedMessage, String> {
        self.seen.lock().expect("lock").push(recipient.to_owned());
        self.templates_seen
            .lock()
            .expect("lock")
            .push(configured.len());
        if let Some(reason) = &self.refuse {
            return Err(reason.clone());
        }
        Ok(PreparedMessage {
            recipient: recipient.to_owned(),
            subject: format!("your {kind}"),
            message_id: "<probe@example.test>".to_owned(),
            body: "body".to_owned(),
            boundary: "b0undary".to_owned(),
            dedup_key: "k".to_owned(),
            template_level: TemplateLevel::Default,
            template_locale: Locale::new("en"),
            locale_fallback_applied: false,
        })
    }
}

async fn provision_keys(db: &TestDatabase, env: &Env, scope: Scope) {
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    acting
        .envelope()
        .provision_kek(env, &db.master_key())
        .await
        .expect("kek");
    acting
        .envelope()
        .provision_dek(env, &db.master_key())
        .await
        .expect("dek");
}

/// Enqueue one send and return the outbox job the consumer will be handed.
async fn enqueue_send(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    recipient: &str,
) -> (MessageId, OutboxMessage) {
    let normalized = normalize_recipient(recipient).expect("address");
    let key = dedup_key("email_otp", recipient, window_index(1_000, WINDOW_SECS)).expect("key");
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
            &serde_json::json!({ "code": "123456" }),
            RateBudget::new(1_000, 3_600),
            1_000,
        )
        .await
        .expect("enqueue");
    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            env,
            "message.delivery",
            std::time::Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim");
    let job = claimed.into_iter().next().expect("one queued job");
    (id, job)
}

async fn state_of(db: &TestDatabase, scope: Scope, id: &MessageId) -> (String, Option<String>) {
    let record = db
        .store()
        .scoped(scope)
        .messages()
        .by_id(id)
        .await
        .expect("read back")
        .expect("row");
    (record.state, record.failure_reason)
}

/// The happy path, and the proof the seal was opened: the composer is handed the real address,
/// which exists nowhere in the ledger or the outbox payload in readable form.
#[tokio::test]
async fn a_delivered_message_resolves_to_sent_and_the_composer_sees_the_real_address() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x130);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (id, job) = enqueue_send(&db, &env, scope, "Ada@Example.test").await;
    let (primary, primary_tries) = provider("primary", Outcome::Delivered);
    let composer = Arc::new(RecordingComposer::default());
    let consumer = MessageDeliveryConsumer::new(
        db.store().clone(),
        vec![primary],
        Arc::clone(&composer) as Arc<dyn MessageComposer>,
    );

    consumer.handle(&env, scope, &job).await.expect("handled");

    assert_eq!(primary_tries.load(Ordering::Relaxed), 1);
    assert_eq!(state_of(&db, scope, &id).await, ("sent".to_owned(), None));
    assert_eq!(
        composer.seen.lock().expect("lock").as_slice(),
        ["ada@example.test"],
        "the consumer must open the sealed recipient; the ledger holds only a blind index"
    );
}

/// CRITERION 1, first half. With the primary failing, the send completes via the fallback.
#[tokio::test]
async fn an_unavailable_primary_fails_over_to_the_next_provider() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x131);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (id, job) = enqueue_send(&db, &env, scope, "ada@example.test").await;
    let (primary, primary_tries) = provider("primary", Outcome::ProviderUnavailable);
    let (fallback, fallback_tries) = provider("fallback", Outcome::Delivered);
    let consumer = MessageDeliveryConsumer::new(
        db.store().clone(),
        vec![primary, fallback],
        Arc::new(RecordingComposer::default()) as Arc<dyn MessageComposer>,
    );

    consumer.handle(&env, scope, &job).await.expect("handled");

    assert_eq!(
        primary_tries.load(Ordering::Relaxed),
        1,
        "the primary is tried"
    );
    assert_eq!(
        fallback_tries.load(Ordering::Relaxed),
        1,
        "then the fallback"
    );
    assert_eq!(state_of(&db, scope, &id).await, ("sent".to_owned(), None));
}

/// A REJECTED message must not be offered to the next provider. Every provider is looking at
/// the same message and will agree, so failing over buys N bounces at N vendors and damages
/// sender reputation with each.
#[tokio::test]
async fn a_rejected_message_is_not_offered_to_the_next_provider() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x132);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (id, job) = enqueue_send(&db, &env, scope, "ada@example.test").await;
    let (primary, primary_tries) = provider("primary", Outcome::MessageRejected);
    let (fallback, fallback_tries) = provider("fallback", Outcome::Delivered);
    let consumer = MessageDeliveryConsumer::new(
        db.store().clone(),
        vec![primary, fallback],
        Arc::new(RecordingComposer::default()) as Arc<dyn MessageComposer>,
    );

    consumer.handle(&env, scope, &job).await.expect("handled");

    assert_eq!(primary_tries.load(Ordering::Relaxed), 1);
    assert_eq!(
        fallback_tries.load(Ordering::Relaxed),
        0,
        "a message the first provider refused is refused by all of them; trying the next one \
         mails a second bounce and costs sender reputation twice"
    );
    let (state, reason) = state_of(&db, scope, &id).await;
    assert_eq!(state, "failed");
    assert_eq!(reason.as_deref(), Some("message_rejected"));
}

/// Every provider down is the case that RETRIES. The row stays pending, because resolving it
/// failed would tell an operator the send is finished while the substrate is still going to
/// try again.
#[tokio::test]
async fn every_provider_unavailable_retries_and_leaves_the_row_pending() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x133);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (id, job) = enqueue_send(&db, &env, scope, "ada@example.test").await;
    let (primary, _) = provider("primary", Outcome::ProviderUnavailable);
    let (fallback, _) = provider("fallback", Outcome::ProviderUnavailable);
    let consumer = MessageDeliveryConsumer::new(
        db.store().clone(),
        vec![primary, fallback],
        Arc::new(RecordingComposer::default()) as Arc<dyn MessageComposer>,
    );

    let outcome = consumer.handle(&env, scope, &job).await;
    let error = outcome.expect_err("an outage is a retry, not a completion");
    assert!(
        error.is_retryable(),
        "the message is fine and the infrastructure is not, so this belongs in the retry \
         path and eventually the dead-letter queue, not in a permanent failure"
    );
    assert_eq!(
        state_of(&db, scope, &id).await,
        ("pending".to_owned(), None),
        "the row must stay pending while the substrate still intends to retry it"
    );
}

/// A composer refusal is recorded, not retried: a broken template or a policy block does not
/// improve on the next attempt.
#[tokio::test]
async fn a_refused_composition_is_recorded_and_finished() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x134);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (id, job) = enqueue_send(&db, &env, scope, "ada@example.test").await;
    let (primary, primary_tries) = provider("primary", Outcome::Delivered);
    let composer = Arc::new(RecordingComposer {
        seen: std::sync::Mutex::new(Vec::new()),
        templates_seen: std::sync::Mutex::new(Vec::new()),
        refuse: Some("suppressed".to_owned()),
    });
    let consumer = MessageDeliveryConsumer::new(
        db.store().clone(),
        vec![primary],
        composer as Arc<dyn MessageComposer>,
    );

    consumer.handle(&env, scope, &job).await.expect("handled");

    assert_eq!(
        primary_tries.load(Ordering::Relaxed),
        0,
        "nothing is handed to a provider when there is no message to send"
    );
    let (state, reason) = state_of(&db, scope, &id).await;
    assert_eq!(state, "failed");
    assert_eq!(reason.as_deref(), Some("suppressed"));
}

/// A job whose row is already resolved does nothing. At-least-once delivery of the JOB must not
/// become at-least-once delivery of the MAIL.
#[tokio::test]
async fn a_replayed_job_does_not_send_the_message_twice() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x135);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (id, job) = enqueue_send(&db, &env, scope, "ada@example.test").await;
    let (primary, primary_tries) = provider("primary", Outcome::Delivered);
    let consumer = MessageDeliveryConsumer::new(
        db.store().clone(),
        vec![primary],
        Arc::new(RecordingComposer::default()) as Arc<dyn MessageComposer>,
    );

    consumer.handle(&env, scope, &job).await.expect("first");
    consumer.handle(&env, scope, &job).await.expect("replay");

    assert_eq!(
        primary_tries.load(Ordering::Relaxed),
        1,
        "the second attempt must not mail the recipient again"
    );
    assert_eq!(state_of(&db, scope, &id).await, ("sent".to_owned(), None));
}

/// TWO WORKERS, ONE JOB. The case a lapsed lease produces, and the one the read-then-act
/// version got wrong: both observed `pending`, both delivered, and a person received the same
/// code twice.
///
/// The interleaving is FORCED rather than hoped for. `tokio::join!` on two handles is not
/// enough: the futures interleave only at await points, so the first can finish entirely
/// before the second starts and the race window never opens. Measured, a `join!` version of
/// this test passed against the read-then-act code it was written to catch.
///
/// So worker A is held INSIDE its provider while worker B runs start to finish. Under
/// read-then-act B also observes `pending`, reaches a provider, and the entry count goes to
/// two. Under the claim B loses the conditional UPDATE and returns without composing or
/// sending, so the count stays at one.
#[tokio::test]
async fn two_workers_holding_one_job_mail_the_recipient_once() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x136);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (id, job) = enqueue_send(&db, &env, scope, "ada@example.test").await;
    // ONE counter and ONE gate, shared by both workers: the question is how many times the
    // recipient was handed to a provider in total, not what either worker did alone.
    let entered = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let build = || {
        MessageDeliveryConsumer::new(
            db.store().clone(),
            vec![Box::new(GatedProvider {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }) as Box<dyn MessageProvider>],
            Arc::new(RecordingComposer::default()) as Arc<dyn MessageComposer>,
        )
    };
    let a = build();
    let b = build();

    // Start A and wait until it is parked inside the provider.
    let a_env = env.clone();
    let a_job = job.clone();
    let a_run = async move { a.handle(&a_env, scope, &a_job).await };
    tokio::pin!(a_run);
    let mut parked = false;
    for _ in 0..200 {
        tokio::select! {
            biased;
            _ = &mut a_run => break,
            () = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
        if entered.load(Ordering::Relaxed) >= 1 {
            parked = true;
            break;
        }
    }
    assert!(parked, "worker A should be inside its provider");

    // Now run B to completion while A is still mid-flight. Under the claim it returns at once
    // having sent nothing; under read-then-act it enters the provider and parks too, which the
    // timeout below turns into a visible failure rather than a hang.
    let b_outcome = tokio::time::timeout(Duration::from_secs(2), b.handle(&env, scope, &job)).await;
    let b_entered_provider = entered.load(Ordering::Relaxed) >= 2;

    release.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(5), a_run).await;
    if let Ok(outcome) = b_outcome {
        outcome.expect("worker b");
    }

    assert!(
        !b_entered_provider,
        "the second worker must not reach a provider: with a lapsed lease both workers hold \
         the same job, and two providers entered is the recipient mailed twice"
    );
    assert_eq!(
        entered.load(Ordering::Relaxed),
        1,
        "exactly one worker may hand this message to a provider"
    );
    assert_eq!(state_of(&db, scope, &id).await, ("sent".to_owned(), None));
}

/// A job naming a row that no longer exists completes rather than retrying. Retention pruned
/// it, or it never committed; either way re-reading finds the same absence.
#[tokio::test]
async fn a_job_for_a_missing_row_completes_rather_than_retrying() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x137);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (id, job) = enqueue_send(&db, &env, scope, "ada@example.test").await;
    sqlx::query("DELETE FROM messages WHERE id = $1")
        .bind(id.to_string())
        .execute(db.owner_pool())
        .await
        .expect("prune the row");

    let (primary, tries) = provider("primary", Outcome::Delivered);
    let consumer = MessageDeliveryConsumer::new(
        db.store().clone(),
        vec![primary],
        Arc::new(RecordingComposer::default()) as Arc<dyn MessageComposer>,
    );
    consumer
        .handle(&env, scope, &job)
        .await
        .expect("a missing row is finished, not deferred");
    assert_eq!(tries.load(Ordering::Relaxed), 0);
}

/// A row with no sealed recipient is recorded and finished. It predates migration 0155 and
/// there is no plaintext anywhere to seal it from, so no number of retries can make it sendable.
#[tokio::test]
async fn a_row_without_a_sealed_recipient_is_recorded_not_retried() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x138);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (id, job) = enqueue_send(&db, &env, scope, "ada@example.test").await;
    sqlx::query(
        "UPDATE messages SET recipient_sealed = NULL, pii_dek_version = NULL WHERE id = $1",
    )
    .bind(id.to_string())
    .execute(db.owner_pool())
    .await
    .expect("simulate a pre-0155 row");

    let (primary, tries) = provider("primary", Outcome::Delivered);
    let consumer = MessageDeliveryConsumer::new(
        db.store().clone(),
        vec![primary],
        Arc::new(RecordingComposer::default()) as Arc<dyn MessageComposer>,
    );
    consumer.handle(&env, scope, &job).await.expect("finished");

    assert_eq!(tries.load(Ordering::Relaxed), 0);
    let (state, reason) = state_of(&db, scope, &id).await;
    assert_eq!(state, "failed");
    assert_eq!(reason.as_deref(), Some("no_sealed_recipient"));
}

/// No providers configured is a DEPLOYMENT error: it dead-letters rather than retrying
/// forever, and the row is released so that configuring a provider and replaying the dead
/// letter finds a message it can still send.
#[tokio::test]
async fn no_providers_configured_dead_letters_and_leaves_the_row_sendable() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x139);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (id, job) = enqueue_send(&db, &env, scope, "ada@example.test").await;
    let consumer = MessageDeliveryConsumer::new(
        db.store().clone(),
        Vec::new(),
        Arc::new(RecordingComposer::default()) as Arc<dyn MessageComposer>,
    );

    let error = consumer
        .handle(&env, scope, &job)
        .await
        .expect_err("a deployment error is not a completion");
    assert!(
        !error.is_retryable(),
        "retrying a missing configuration forever is how a queue fills up silently"
    );
    assert_eq!(
        state_of(&db, scope, &id).await,
        ("pending".to_owned(), None),
        "the row must be sendable again once somebody configures a provider"
    );
}

/// The consumer LOADS the scope's templates and hands them to the composer.
///
/// Deleting the whole `candidates_for` call left every consumer test green, because nothing
/// looked at what the composer received. A composer handed an empty slice always composes from
/// the built-in, so every configured template in the deployment would be silently ignored and
/// the mail would still go out and still be recorded as sent.
#[tokio::test]
async fn the_consumer_hands_the_scopes_configured_templates_to_the_composer() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x140);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    // Two live templates for this kind, at different levels.
    for (level, locale, subject) in [("tenant", "en", "TENANT"), ("environment", "en", "ENV")] {
        sqlx::query(
            "INSERT INTO message_templates \
             (id, tenant_id, environment_id, level, kind, locale, subject, body_text, \
              created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'email_otp', $5, $6, 'body', now(), now())",
        )
        .bind(ironauth_store::MessageTemplateId::generate(&env, &scope).to_string())
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(level)
        .bind(locale)
        .bind(subject)
        .execute(db.owner_pool())
        .await
        .expect("seed a template");
    }

    let (_, job) = enqueue_send(&db, &env, scope, "ada@example.test").await;
    let (primary, _) = provider("primary", Outcome::Delivered);
    let composer = Arc::new(RecordingComposer::default());
    let consumer = MessageDeliveryConsumer::new(
        db.store().clone(),
        vec![primary],
        Arc::clone(&composer) as Arc<dyn MessageComposer>,
    );
    consumer.handle(&env, scope, &job).await.expect("handled");

    assert_eq!(
        composer.templates_seen.lock().expect("lock").as_slice(),
        [2],
        "both configured templates must reach the composer; an empty slice silently composes \
         every message from the built-in while still reporting success"
    );
}

/// A transient template read RELEASES the claim instead of stranding the row.
///
/// The claim moves the row to `sending`. A retryable error that leaves it there strands it: the
/// next attempt loses the claim, returns Ok, and the outbox marks the JOB complete. No send, no
/// failure, no dead letter, and the retry budget never spent.
#[tokio::test]
async fn a_template_read_failure_releases_the_claim_rather_than_stranding_the_row() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x141);
    let scope = db.seed_scope(&env).await;
    provision_keys(&db, &env, scope).await;

    let (id, job) = enqueue_send(&db, &env, scope, "ada@example.test").await;

    // Make the template read fail for this scope only, and only while the probe runs.
    sqlx::query("ALTER TABLE message_templates RENAME TO message_templates_probe_hidden")
        .execute(db.owner_pool())
        .await
        .expect("hide the table");

    let (primary, tries) = provider("primary", Outcome::Delivered);
    let consumer = MessageDeliveryConsumer::new(
        db.store().clone(),
        vec![primary],
        Arc::new(RecordingComposer::default()) as Arc<dyn MessageComposer>,
    );
    let outcome = consumer.handle(&env, scope, &job).await;

    sqlx::query("ALTER TABLE message_templates_probe_hidden RENAME TO message_templates")
        .execute(db.owner_pool())
        .await
        .expect("restore the table");

    let error = outcome.expect_err("a template read failure is not a completion");
    assert!(error.is_retryable());
    assert_eq!(tries.load(Ordering::Relaxed), 0, "nothing was sent");
    assert_eq!(
        state_of(&db, scope, &id).await,
        ("pending".to_owned(), None),
        "the row must be claimable again; left in `sending` it is sent by nobody and \
         finished by nobody"
    );
}
