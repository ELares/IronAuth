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
use ironauth_store::message_template::{Locale, TemplateLevel};
use ironauth_store::outbox::OutboxConsumer;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, MessageId, NewMessage, OutboxMessage, Scope};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

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
    refuse: Option<String>,
}

impl MessageComposer for RecordingComposer {
    fn compose(
        &self,
        _scope: Scope,
        kind: &str,
        recipient: &str,
        _payload: &serde_json::Value,
    ) -> Result<PreparedMessage, String> {
        self.seen.lock().expect("lock").push(recipient.to_owned());
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
