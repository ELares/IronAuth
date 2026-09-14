// SPDX-License-Identifier: MIT OR Apache-2.0

//! The user lifecycle to RISC fan-out (issue #144 criterion 3).
//!
//! # What this owes
//!
//! Criterion 3 asks that RISC lifecycle events emit on admin and SCIM actions. The
//! mapping itself is pinned in `risc`'s unit tests; what is pinned HERE is that a REAL
//! lifecycle write reaches a receiver as the documented RISC type.
//!

//! Every test drives an actual store write that emits the domain event -- a state change,
//! a deletion, an identifier change -- rather than hand-building an outbox message,
//! because the producer that writes the trigger lives inside those store calls. A trigger
//! that is never written, or written under a consumer name nothing drains, looks exactly
//! like a fan-out with nothing to do.
//!
//! # The admin and SCIM halves
//!
//! Both surfaces reach RISC through the same store calls these tests drive: the trigger is
//! written by `enqueue_domain_event`, which every emitting write already rides, so there
//! is no per-surface wiring that could be present for one and missing for the other. That
//! is the property worth having, and it is why the tests here drive the store rather than
//! two HTTP surfaces: a test per surface would measure the surfaces, and what can actually
//! break is the one shared producer.

#![cfg(feature = "testing")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::Harness;
use ironauth_oidc::ssf_set::SubjectIdentifier;
use ironauth_oidc::{SsfLifecycleFanOutConsumer, risc};
use ironauth_store::outbox::{DrainStats, OutboxConsumer, OutboxWorker, WorkerSettings};
use ironauth_store::{
    ClientId, CorrelationId, DomainEvent, NewSsfStream, OffboardingSchedule, RetryPolicy, Scope,
    SsfDelivery, SsfStreamId, SsfSubjectFormat, Store, UserId, UserState,
};

fn settings() -> WorkerSettings {
    WorkerSettings {
        concurrency: 1,
        visibility_timeout: Duration::from_secs(30),
        poll_interval: Duration::from_secs(5),
        batch: 64,
        retry: RetryPolicy {
            max_attempts: 5,
            retry_base: Duration::from_secs(10),
        },
    }
}

fn store_of(harness: &Harness) -> Store {
    harness.state().store().clone()
}

async fn provision_envelope(harness: &Harness) {
    let env = harness.state().env().clone();
    let store = store_of(harness);
    let acting = store
        .scoped(harness.scope())
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env));
    for (label, outcome) in [
        (
            "kek",
            acting
                .envelope()
                .provision_kek(&env, &harness.db().master_key())
                .await
                .map(|_| ()),
        ),
        (
            "dek",
            acting
                .envelope()
                .provision_dek(&env, &harness.db().master_key())
                .await
                .map(|_| ()),
        ),
    ] {
        match outcome {
            Ok(()) | Err(ironauth_store::StoreError::Conflict) => {}
            Err(error) => panic!("provision the scope {label}: {error:?}"),
        }
    }
}

async fn a_client(harness: &Harness) -> ClientId {
    harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await
        .0
}

async fn seed_stream(
    harness: &Harness,
    client: &ClientId,
    events_delivered: &[String],
) -> SsfStreamId {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    let id = SsfStreamId::generate(&env, &scope);
    let audience = vec!["https://receiver.example.com".to_owned()];
    store_of(harness)
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .create(
            &env,
            NewSsfStream {
                id: &id,
                client_id: client,
                delivery: &SsfDelivery::Poll,
                events_requested: events_delivered,
                events_delivered,
                subject_format: SsfSubjectFormat::Opaque,
                audience: &audience,
                description: None,
            },
            20,
            None,
        )
        .await
        .expect("seed a stream");
    id
}

/// Every RISC type this build emits, which is what a receiver would ask for.
fn all_risc() -> Vec<String> {
    risc::EMITTED_EVENT_TYPES
        .iter()
        .map(|t| (*t).to_owned())
        .collect()
}

/// Whether the producer wrote a lifecycle trigger at all.
///
/// CLAIMS THE QUEUE DIRECTLY rather than reading a drain's `completed` count, and the
/// difference is not cosmetic. A drain reports `completed: 0` both when there was no
/// message and when there WAS one that failed, and those are opposite outcomes for a
/// test about whether the producer wrote anything. Mutation-checking caught exactly that:
/// bypassing the producer's whitelist wrote a trigger for a `user.signed_in` event, whose
/// payload has no `user_id`, so the consumer failed it permanently and `completed` stayed
/// 0 while the test claiming "no trigger" went on passing.
async fn trigger_count(harness: &Harness, scope: Scope) -> usize {
    let env = harness.state().env().clone();
    store_of(harness)
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::SSF_LIFECYCLE_CONSUMER,
            Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim the lifecycle queue")
        .len()
}

async fn lifecycle_pass(harness: &Harness, scope: Scope) -> DrainStats {
    let consumer: Arc<dyn OutboxConsumer> = Arc::new(SsfLifecycleFanOutConsumer::new(
        store_of(harness),
        Arc::clone(harness.state().issuers()),
        1_000,
    ));
    OutboxWorker::new(
        store_of(harness),
        harness.env().clone(),
        consumer,
        settings(),
    )
    .run_once(scope)
    .await
    .expect("lifecycle pass")
}

fn claims_of(set: &str) -> serde_json::Value {
    use base64::Engine;
    let payload = set
        .split('.')
        .nth(1)
        .expect("a compact JWS has three parts");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url");
    serde_json::from_slice(&bytes).expect("json")
}

async fn owed_claims(harness: &Harness, stream: &SsfStreamId) -> Vec<serde_json::Value> {
    store_of(harness)
        .scoped(harness.scope())
        .ssf_stream_sets()
        .owed(stream, 50)
        .await
        .expect("read the queue")
        .iter()
        .map(|queued| claims_of(&queued.set_jws))
        .collect()
}

fn sole_event_type(claims: &serde_json::Value) -> String {
    let events = claims["events"].as_object().expect("an events object");
    assert_eq!(events.len(), 1, "one event per SET: {claims}");
    events.keys().next().expect("one entry").clone()
}

/// Seed a user and return its id.
async fn seed_user(harness: &Harness, identifier: &str) -> UserId {
    let subject = harness.seed_user(identifier, "correct horse battery").await;
    store_of(harness)
        .scoped(harness.scope())
        .users()
        .parse_id(&subject)
        .expect("parse the seeded user id")
}

/// Change a user's state through the REAL store call, emitting the domain event an admin
/// or SCIM write would emit.
async fn set_state(harness: &Harness, user: &UserId, to: UserState) {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    let id = format!("evt_{}_{}", user, to.as_str());
    let payload = serde_json::json!({
        "user_id": user.to_string(),
        "state": to.as_str(),
        "hard_kill": false,
    });
    let envelope = ironauth_admin::events::envelope(
        &id,
        "user.state_changed",
        scope,
        1_700_000_000_000,
        &payload,
    );
    store_of(harness)
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .users()
        .set_state_with_event(
            &env,
            user,
            to,
            OffboardingSchedule {
                at_unix_micros: None,
                wake_payload: None,
            },
            false,
            None,
            Some(&DomainEvent {
                id: &id,
                subject: &user.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("set the user state");
}

/// Move a user to scheduled offboarding, which needs an instant.
async fn set_state_scheduled(harness: &Harness, user: &UserId) {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    let id = format!("evt_{user}_scheduled");
    let payload = serde_json::json!({
        "user_id": user.to_string(),
        "state": UserState::ScheduledOffboarding.as_str(),
        "hard_kill": false,
    });
    let envelope = ironauth_admin::events::envelope(
        &id,
        "user.state_changed",
        scope,
        1_700_000_000_000,
        &payload,
    );
    let store = store_of(harness);
    store
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .users()
        .set_state_with_event(
            &env,
            user,
            UserState::ScheduledOffboarding,
            OffboardingSchedule {
                at_unix_micros: Some(4_102_444_800_000_000),
                wake_payload: None,
            },
            false,
            None,
            Some(&DomainEvent {
                id: &id,
                subject: &user.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("schedule the offboarding");
}

#[tokio::test]
async fn blocking_a_user_reaches_a_stream_as_risc_account_disabled() {
    // The whole path: a real state change, the real producer inside the store call, the
    // real consumer, and the real queue. This is also what proves the trigger is written
    // at all -- the producer is a few lines inside `enqueue_domain_event` and a fan-out
    // with nothing to drain looks identical to one that is working.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let client = a_client(&harness).await;
    let stream = seed_stream(&harness, &client, &all_risc()).await;
    let user = seed_user(&harness, "blocked@example.test").await;

    set_state(&harness, &user, UserState::Blocked).await;
    assert_eq!(lifecycle_pass(&harness, scope).await.completed, 1);

    let owed = owed_claims(&harness, &stream).await;
    assert_eq!(owed.len(), 1, "one lifecycle change is one SET");
    assert_eq!(sole_event_type(&owed[0]), risc::ACCOUNT_DISABLED);
    assert_eq!(
        owed[0]["sub_id"]["id"].as_str(),
        Some(user.to_string().as_str()),
        "the SET names the wrong user"
    );
}

#[tokio::test]
async fn restoring_a_user_reaches_a_stream_as_risc_account_enabled() {
    // The OTHER direction, which matters because a fan-out that answered
    // `account-disabled` to every state change would pass the test above.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let client = a_client(&harness).await;
    let stream = seed_stream(&harness, &client, &all_risc()).await;
    let user = seed_user(&harness, "restored@example.test").await;

    set_state(&harness, &user, UserState::Blocked).await;
    lifecycle_pass(&harness, scope).await;
    set_state(&harness, &user, UserState::Active).await;
    lifecycle_pass(&harness, scope).await;

    let owed = owed_claims(&harness, &stream).await;
    assert_eq!(owed.len(), 2, "two changes are two SETs");
    let types: Vec<String> = owed.iter().map(sole_event_type).collect();
    assert_eq!(
        types,
        vec![
            risc::ACCOUNT_DISABLED.to_owned(),
            risc::ACCOUNT_ENABLED.to_owned()
        ],
        "the two transitions did not arrive as their own RISC types, oldest first"
    );
}

#[tokio::test]
async fn a_state_change_risc_has_no_word_for_is_completed_and_not_dead_lettered() {
    // The producer's whitelist is COARSER than the mapping: `user.state_changed` is on it
    // because some of its transitions are RISC events. A transition that maps to nothing
    // must complete its message, not fail it -- failing would retry a transition that can
    // never map until the attempts budget ran out and then dead-letter it, and an
    // operator would be paged for a waitlisting.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let client = a_client(&harness).await;
    let stream = seed_stream(&harness, &client, &all_risc()).await;
    let user = seed_user(&harness, "offboarding@example.test").await;

    // SCHEDULED OFFBOARDING, which is the only unmapped state a transition can actually
    // reach: `UserState::can_transition_to` refuses `pending_verification` and
    // `waitlisted` as targets outright, so a `user.state_changed` can never carry them.
    set_state_scheduled(&harness, &user).await;
    let stats = lifecycle_pass(&harness, scope).await;
    assert_eq!(
        stats.completed, 1,
        "an unmapped transition failed its message instead of completing it"
    );
    assert_eq!(stats.dead_lettered, 0);
    assert!(
        owed_claims(&harness, &stream).await.is_empty(),
        "a scheduled offboarding was reported as an account transition, which would \
         cut the user off at the moment the schedule was SET rather than when it ran"
    );
}

#[tokio::test]
async fn an_event_risc_does_not_cover_writes_no_trigger_at_all() {
    // THE WHITELIST HALF, driven through the real producer. `enqueue_domain_event` decides
    // from the envelope's `type` and nothing else, so handing it a type outside the list
    // is exactly the measurement: this drives a real store write whose event is typed
    // `user.signed_in`, which is a `user.` event and emphatically not an account
    // lifecycle transition. A prefix test rather than a whitelist would turn every
    // sign-in in the environment into a Shared Signals fan-out.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let client = a_client(&harness).await;
    seed_stream(&harness, &client, &all_risc()).await;
    let user = seed_user(&harness, "signin@example.test").await;

    let id = format!("evt_signin_{user}");
    // THE CATALOG'S OWN SHAPE for this type, which is `subject` and not `user_id`. It is
    // validated at emit time, so a hand-built payload that merely looked plausible would
    // fail the write rather than reach the producer this test is about.
    let payload = serde_json::json!({ "subject": user.to_string() });
    let envelope =
        ironauth_admin::events::envelope(&id, "user.signed_in", scope, 1_700_000_000_000, &payload);
    let store = store_of(&harness);
    store
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .users()
        .set_state_with_event(
            &env,
            &user,
            UserState::Blocked,
            OffboardingSchedule {
                at_unix_micros: None,
                wake_payload: None,
            },
            false,
            None,
            Some(&DomainEvent {
                id: &id,
                subject: &user.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("a write carrying a non-lifecycle event");

    assert_eq!(
        trigger_count(&harness, scope).await,
        0,
        "an event type outside the lifecycle whitelist wrote a Shared Signals trigger"
    );
}

#[tokio::test]
async fn no_stream_means_no_trigger_for_a_lifecycle_change() {
    // The orphan-row property. This consumer runs only where `ssf.enabled` is set, so a
    // row written where no stream exists would sit in `outbox_messages` forever: nothing
    // reaps unclaimed work and the application role has no DELETE on that table.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let user = seed_user(&harness, "nostream@example.test").await;

    set_state(&harness, &user, UserState::Blocked).await;
    assert_eq!(
        trigger_count(&harness, scope).await,
        0,
        "a trigger was written with no stream to fan out to"
    );
}

#[tokio::test]
async fn a_stream_filtered_to_another_subject_is_not_told() {
    // The subject filter applies to RISC exactly as it does to CAEP, because both go
    // through one `StreamFanOut`. A second copy of the delivery rules would be a second
    // place for a receiver's filter to be forgotten, and this is what would notice.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let client = a_client(&harness).await;
    let stream = seed_stream(&harness, &client, &all_risc()).await;
    let wanted = SubjectIdentifier::Opaque {
        id: "usr_someone_else".to_owned(),
    };
    store_of(&harness)
        .scoped(scope)
        .ssf_stream_subjects()
        .add(
            &env,
            &stream,
            wanted.format(),
            &wanted.render().to_string(),
            true,
            10_000,
        )
        .await
        .expect("filter the stream to a different subject");

    let user = seed_user(&harness, "unwatched@example.test").await;
    set_state(&harness, &user, UserState::Blocked).await;
    assert_eq!(lifecycle_pass(&harness, scope).await.completed, 1);

    assert!(
        owed_claims(&harness, &stream).await.is_empty(),
        "a stream filtered to a different subject was told about this one"
    );
}

#[tokio::test]
async fn deleting_a_user_reaches_a_stream_as_risc_account_purged() {
    // `account-purged` had NO end-to-end coverage: every other test in this suite drives
    // a state change, so the whole `user.deleted` arm of the mapping was reachable only
    // through a unit assertion. A producer that never wrote a trigger for a deletion, or
    // a mapping that lost this arm, would have shipped green.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let client = a_client(&harness).await;
    let stream = seed_stream(&harness, &client, &all_risc()).await;
    let user = seed_user(&harness, "purged@example.test").await;

    let id = format!("evt_delete_{user}");
    let payload = serde_json::json!({ "user_id": user.to_string(), "hard_kill": false });
    let envelope =
        ironauth_admin::events::envelope(&id, "user.deleted", scope, 1_700_000_000_000, &payload);
    let store = store_of(&harness);
    store
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .users()
        .delete(
            &env,
            &user,
            false,
            None,
            Some(&DomainEvent {
                id: &id,
                subject: &user.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("delete the user");

    assert_eq!(lifecycle_pass(&harness, scope).await.completed, 1);
    let owed = owed_claims(&harness, &stream).await;
    assert_eq!(owed.len(), 1, "a deletion produced no SET");
    assert_eq!(sole_event_type(&owed[0]), risc::ACCOUNT_PURGED);
    assert_eq!(
        owed[0]["sub_id"]["id"].as_str(),
        Some(user.to_string().as_str())
    );
}

#[tokio::test]
async fn an_added_identifier_reaches_a_stream_without_the_identifier_in_it() {
    // `identifier-changed` had no end-to-end coverage either, and it is the arm with a
    // privacy property to protect: RISC's `new-value` is optional and this build declines
    // it, because a SET sits in a poll queue and is POSTed to an address the receiver
    // chose. The unit test pins the body; this pins that the body a RECEIVER actually
    // gets, after minting and sealing and reading back out of the queue, still has no
    // address in it.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let client = a_client(&harness).await;
    let stream = seed_stream(&harness, &client, &all_risc()).await;
    let user = seed_user(&harness, "identifier@example.test").await;

    let secret_address = "new.address@example.test";
    let id = format!("evt_ident_{user}");
    let payload = serde_json::json!({
        "user_id": user.to_string(),
        "identifier_id": "uid_probe",
        "identifier_type": "email",
    });
    let envelope = ironauth_admin::events::envelope(
        &id,
        "user.identifier_added",
        scope,
        1_700_000_000_000,
        &payload,
    );
    let store = store_of(&harness);
    store
        .scoped(scope)
        .outbox()
        .append_event(
            &env,
            &ironauth_store::NewOutboxMessage {
                consumer: ironauth_store::SSF_LIFECYCLE_CONSUMER,
                idempotency_key: &id,
                ordering_key: &user.to_string(),
                payload: envelope,
            },
        )
        .await
        .expect("enqueue the identifier change");

    assert_eq!(lifecycle_pass(&harness, scope).await.completed, 1);
    let owed = owed_claims(&harness, &stream).await;
    assert_eq!(owed.len(), 1, "an identifier change produced no SET");
    assert_eq!(sole_event_type(&owed[0]), risc::IDENTIFIER_CHANGED);
    let delivered = serde_json::to_string(&owed[0]).expect("serialise");
    assert!(
        !delivered.contains(secret_address) && !delivered.contains("new-value"),
        "the SET a receiver is handed republishes the changed identifier: {delivered}"
    );
}
