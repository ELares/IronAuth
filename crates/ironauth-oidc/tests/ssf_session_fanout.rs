// SPDX-License-Identifier: MIT OR Apache-2.0

//! The session end to CAEP `session-revoked` fan-out (issue #144).
//!
//! # What this owes
//!
//! This is the first GENERAL producer the Shared Signals subsystem has, and the suite is
//! built around the two things that makes newly checkable:
//!
//! - #144 criterion 2, that every internal revocation cause maps to the documented CAEP
//!   event. The pure table is pinned in `caep`'s own unit tests; what is pinned HERE is
//!   the other half, that the mapping is what actually reaches a stream. A table-driven
//!   test over the real substrate is the only place the two can be compared.
//! - #143 criterion 5, that a subject renders in the format ITS stream negotiated. Until
//!   this producer existed the only emitted event was the verification event, whose
//!   `sub_id` SSF 1.0 pins to `opaque` regardless of the stream, so the per-stream
//!   rendering had no end-to-end proof anywhere. Two streams on ONE event, negotiating
//!   different formats, is that proof.
//!
//! # The payload-key hazard these tests exist to catch
//!
//! The session-ended producer writes its payload with string literals, and the explode
//! consumer reads them with a SECOND set of literals. Nothing in the type system makes the
//! two agree. Every test here drives a REAL `sessions().revoke(..)` rather than
//! hand-building an outbox message, so a misspelling on either side shows up as a fan-out
//! that produces nothing instead of a suite that passes against its own typo.

#![cfg(feature = "testing")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::Harness;
use ironauth_env::Env;
use ironauth_oidc::caep;
use ironauth_oidc::{SessionEndedExplodeConsumer, SsfSessionFanOutConsumer};
use ironauth_store::outbox::{DrainStats, OutboxConsumer, OutboxWorker, WorkerSettings};
use ironauth_store::{
    ActorRef, ClientId, CorrelationId, NewSession, NewSsfStream, RetryPolicy, Scope, ServiceId,
    SessionEndCause, SessionId, SsfDelivery, SsfStreamId, SsfSubjectFormat, Store,
};

const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;
const SUBJECT: &str = "usr_fanout_subject";

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

fn actor(env: &Env) -> (ActorRef, CorrelationId) {
    (
        ActorRef::service(ServiceId::generate(env)),
        CorrelationId::generate(env),
    )
}

async fn create_session(store: &Store, env: &Env, scope: Scope, subject: &str) -> SessionId {
    let id = SessionId::generate(env, &scope);
    let (a, c) = actor(env);
    store
        .scoped(scope)
        .acting(a, c)
        .sessions()
        .rotate(
            env,
            &id,
            None,
            NewSession {
                impersonation: None,
                subject,
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: FAR_FUTURE_MICROS,
                absolute_expires_micros: FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("rotate session");
    id
}

/// End `session` with `cause`, through the REAL producer.
async fn end_session(
    store: &Store,
    env: &Env,
    scope: Scope,
    session: &SessionId,
    cause: SessionEndCause,
) {
    let (a, c) = actor(env);
    store
        .scoped(scope)
        .acting(a, c)
        .sessions()
        .revoke(env, session, cause, false, None)
        .await
        .expect("revoke session");
}

/// Seed one stream, negotiating `format` and agreeing to deliver `events_delivered`.
async fn seed_stream(
    harness: &Harness,
    client: &ClientId,
    delivery: SsfDelivery,
    format: SsfSubjectFormat,
    events_delivered: &[String],
) -> SsfStreamId {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    let id = SsfStreamId::generate(&env, &scope);
    let audience = vec!["https://receiver.example.com".to_owned()];
    harness
        .state()
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .create(
            &env,
            NewSsfStream {
                id: &id,
                client_id: client,
                delivery: &delivery,
                events_requested: events_delivered,
                events_delivered,
                subject_format: format,
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

fn poll_stream() -> SsfDelivery {
    SsfDelivery::Poll
}

fn revocation_only() -> Vec<String> {
    vec![caep::SESSION_REVOKED.to_owned()]
}

/// The MASTER-KEY-WIRED store, which is the one the fan-out needs: queuing a poll SET
/// seals it under the environment DEK, and a store with no master answers
/// `StoreError::Encryption` to every attempt.
fn store_of(harness: &Harness) -> Store {
    harness.state().store().clone()
}

fn worker(harness: &Harness, consumer: Arc<dyn OutboxConsumer>) -> OutboxWorker {
    OutboxWorker::new(
        store_of(harness),
        harness.env().clone(),
        consumer,
        settings(),
    )
}

async fn explode_pass(harness: &Harness, scope: Scope) -> DrainStats {
    worker(
        harness,
        Arc::new(SessionEndedExplodeConsumer::new(store_of(harness))),
    )
    .run_once(scope)
    .await
    .expect("explode pass")
}

async fn fanout_pass(harness: &Harness, scope: Scope) -> DrainStats {
    worker(
        harness,
        Arc::new(SsfSessionFanOutConsumer::new(
            store_of(harness),
            Arc::clone(harness.state().issuers()),
            1_000,
        )),
    )
    .run_once(scope)
    .await
    .expect("fan-out pass")
}

/// Everything a delivered SET says, read out of the compact JWS the queue holds.
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

/// What one stream is owed, as claim sets.
async fn owed_claims(harness: &Harness, stream: &SsfStreamId) -> Vec<serde_json::Value> {
    harness
        .state()
        .store()
        .scoped(harness.scope())
        .ssf_stream_sets()
        .owed(stream, 50)
        .await
        .expect("read the queue")
        .iter()
        .map(|queued| claims_of(&queued.set_jws))
        .collect()
}

/// The one event body inside a SET, and the type it is keyed under.
fn sole_event(claims: &serde_json::Value) -> (String, serde_json::Value) {
    let events = claims["events"].as_object().expect("an events object");
    assert_eq!(events.len(), 1, "one event per SET: {claims}");
    let (event_type, body) = events.iter().next().expect("one entry");
    (event_type.clone(), body.clone())
}

/// Provision the scope's envelope keys.
///
/// A poll SET is SEALED under the environment DEK, so without this every queue attempt
/// answers `StoreError::Encryption` and the fan-out reports a retryable store error. It is
/// the same provisioning the poll suite performs, and production does it at environment
/// creation.
async fn provision_envelope(harness: &Harness) {
    let env = harness.state().env().clone();
    let acting = harness
        .state()
        .store()
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

#[tokio::test]
async fn a_revoked_session_reaches_a_poll_stream_as_a_caep_session_revoked() {
    // The whole path, driven end to end: a real revoke, the real explode, the real
    // fan-out, and the real queue. This is also the test that catches a payload-key
    // misspelling on either side of the trigger, and it catches it SPECIFICALLY rather
    // than as "nothing arrived": the subject and the initiating entity both come out of
    // keys the explode had to read correctly, so a typo in `subject` or `cause` changes an
    // assertion below rather than merely emptying the queue.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let store = store_of(&harness);
    let client = a_client(&harness).await;
    let stream = seed_stream(
        &harness,
        &client,
        poll_stream(),
        SsfSubjectFormat::IssSub,
        &revocation_only(),
    )
    .await;

    let session = create_session(&store, &env, scope, SUBJECT).await;
    end_session(&store, &env, scope, &session, SessionEndCause::Revoked).await;
    assert_eq!(explode_pass(&harness, scope).await.completed, 1);
    assert_eq!(fanout_pass(&harness, scope).await.completed, 1);

    let owed = owed_claims(&harness, &stream).await;
    assert_eq!(owed.len(), 1, "one ended session is one SET");
    let (event_type, body) = sole_event(&owed[0]);
    assert_eq!(event_type, caep::SESSION_REVOKED);
    assert_eq!(
        body["initiating_entity"].as_str(),
        Some("admin"),
        "an operator revoke is an admin-initiated event: {body}"
    );
    assert_eq!(
        owed[0]["sub_id"]["format"].as_str(),
        Some("iss_sub"),
        "the subject renders in the format THIS stream negotiated"
    );
    assert_eq!(
        owed[0]["sub_id"]["sub"].as_str(),
        Some(SUBJECT),
        "the subject is the user whose session ended"
    );
}

#[tokio::test]
async fn every_end_cause_reaches_a_stream_as_its_documented_row() {
    // #144 criterion 2 over the REAL stream. The pure table is asserted in `caep`; this
    // drives each cause through an actual revoke and reads what a receiver would get, so a
    // mapping that is right in the table and lost on the way out fails here.
    //
    // `initiating_entity` is the column checked because it is the one that VARIES: all six
    // causes are one CAEP type, so asserting the type alone would pass against a fan-out
    // that ignored the cause entirely.
    for (cause, expected_entity) in [
        (SessionEndCause::Revoked, "admin"),
        (SessionEndCause::BulkRevoked, "admin"),
        (SessionEndCause::UserRevokedAll, "user"),
        (SessionEndCause::LoggedOut, "user"),
        (SessionEndCause::ReplacedByOtherSubject, "system"),
        (SessionEndCause::PasswordChanged, "user"),
    ] {
        let harness = Harness::start_store_backed().await;
        provision_envelope(&harness).await;
        let scope = harness.scope();
        let env = harness.state().env().clone();
        let store = store_of(&harness);
        let client = a_client(&harness).await;
        let stream = seed_stream(
            &harness,
            &client,
            poll_stream(),
            SsfSubjectFormat::Opaque,
            &revocation_only(),
        )
        .await;

        let session = create_session(&store, &env, scope, SUBJECT).await;
        end_session(&store, &env, scope, &session, cause).await;
        explode_pass(&harness, scope).await;
        fanout_pass(&harness, scope).await;

        let owed = owed_claims(&harness, &stream).await;
        assert_eq!(owed.len(), 1, "{} produced no SET", cause.as_str());
        let (event_type, body) = sole_event(&owed[0]);
        assert_eq!(event_type, caep::SESSION_REVOKED, "{}", cause.as_str());
        assert_eq!(
            body["initiating_entity"].as_str(),
            Some(expected_entity),
            "{} named the wrong initiator: {body}",
            cause.as_str()
        );
    }
}

#[tokio::test]
async fn one_event_renders_its_subject_per_stream() {
    // #143 CRITERION 5, END TO END, and the reason it could not be proven before this
    // producer existed: the verification event's `sub_id` is pinned to `opaque` by SSF
    // 1.0 whatever the stream negotiated, so a per-stream rendering had nothing to show.
    //
    // ONE event, TWO streams, different negotiated formats. A fan-out that rendered a
    // single identifier and reused it would give both streams the same `sub_id` and fail
    // exactly one of these assertions.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let store = store_of(&harness);
    let client = a_client(&harness).await;
    let as_iss_sub = seed_stream(
        &harness,
        &client,
        poll_stream(),
        SsfSubjectFormat::IssSub,
        &revocation_only(),
    )
    .await;
    let as_opaque = seed_stream(
        &harness,
        &client,
        poll_stream(),
        SsfSubjectFormat::Opaque,
        &revocation_only(),
    )
    .await;

    let session = create_session(&store, &env, scope, SUBJECT).await;
    end_session(&store, &env, scope, &session, SessionEndCause::LoggedOut).await;
    explode_pass(&harness, scope).await;
    fanout_pass(&harness, scope).await;

    let iss_sub = owed_claims(&harness, &as_iss_sub).await;
    let opaque = owed_claims(&harness, &as_opaque).await;
    assert_eq!(iss_sub.len(), 1, "the iss_sub stream is owed one SET");
    assert_eq!(opaque.len(), 1, "the opaque stream is owed one SET");
    assert_eq!(iss_sub[0]["sub_id"]["format"].as_str(), Some("iss_sub"));
    assert_eq!(iss_sub[0]["sub_id"]["sub"].as_str(), Some(SUBJECT));
    assert!(
        iss_sub[0]["sub_id"]["iss"]
            .as_str()
            .is_some_and(|iss| !iss.is_empty()),
        "iss_sub names the issuer that minted the subject: {}",
        iss_sub[0]
    );
    assert_eq!(opaque[0]["sub_id"]["format"].as_str(), Some("opaque"));
    assert_eq!(opaque[0]["sub_id"]["id"].as_str(), Some(SUBJECT));
    assert_ne!(
        iss_sub[0]["jti"], opaque[0]["jti"],
        "two streams' copies of one event are two SETs and must not collide on jti"
    );
}

#[tokio::test]
async fn a_stream_that_did_not_agree_to_the_event_is_not_sent_one() {
    // `events_delivered` is the intersection this transmitter computed when the stream was
    // created. A stream created before this producer existed has an EMPTY one, so this is
    // also the upgrade case: turning on a new event type must not start pushing it at
    // receivers that never asked.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let store = store_of(&harness);
    let client = a_client(&harness).await;
    let uninterested = seed_stream(
        &harness,
        &client,
        poll_stream(),
        SsfSubjectFormat::Opaque,
        &[],
    )
    .await;

    let session = create_session(&store, &env, scope, SUBJECT).await;
    end_session(&store, &env, scope, &session, SessionEndCause::LoggedOut).await;
    explode_pass(&harness, scope).await;
    assert_eq!(
        fanout_pass(&harness, scope).await.completed,
        1,
        "the trigger is still handled; it just produces nothing"
    );
    assert!(
        owed_claims(&harness, &uninterested).await.is_empty(),
        "a stream that did not agree to session revocation was sent one anyway"
    );
}

#[tokio::test]
async fn no_stream_means_no_trigger_at_all() {
    // The orphan-row property the trigger's gate exists for: this consumer runs only where
    // `ssf.enabled` is set, so a row written where no stream exists could sit in
    // `outbox_messages` forever. Nothing reaps unclaimed work and the application role has
    // no DELETE on that table.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let store = store_of(&harness);

    let session = create_session(&store, &env, scope, SUBJECT).await;
    end_session(&store, &env, scope, &session, SessionEndCause::LoggedOut).await;
    assert_eq!(
        explode_pass(&harness, scope).await.completed,
        1,
        "the session still explodes for the back-channel path"
    );
    assert_eq!(
        fanout_pass(&harness, scope).await.completed,
        0,
        "a trigger row was written with no stream to fan out to"
    );
}

#[tokio::test]
async fn a_re_run_after_a_lapsed_lease_leaves_one_event_and_not_two() {
    // At-least-once delivery: a handler that queues some streams and loses its lease is
    // re-run from the top, so it must tolerate finding its own earlier output. The
    // per-stream `jti` is derived from the trigger's own, so the second pass offers the
    // same handle and the queue's primary key skips it.
    //
    // A fresh `jti` per attempt would put TWO SETs in the queue for one event, and a
    // receiver deduplicating on `jti` -- the only handle RFC 8417 gives it -- could not
    // tell they were one.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let store = store_of(&harness);
    let client = a_client(&harness).await;
    let stream = seed_stream(
        &harness,
        &client,
        poll_stream(),
        SsfSubjectFormat::Opaque,
        &revocation_only(),
    )
    .await;

    let session = create_session(&store, &env, scope, SUBJECT).await;
    end_session(&store, &env, scope, &session, SessionEndCause::LoggedOut).await;
    explode_pass(&harness, scope).await;

    // The handler run directly, TWICE, over the same message: what a lapsed lease
    // produces. Going through the worker a second time would drain nothing, because the
    // first pass completed the message, and would prove nothing about re-entrancy.
    let message = store
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::SSF_SESSION_FANOUT_CONSUMER,
            Duration::from_secs(30),
            1,
        )
        .await
        .expect("claim the trigger")
        .pop()
        .expect("the trigger exists");
    let consumer =
        SsfSessionFanOutConsumer::new(store.clone(), Arc::clone(harness.state().issuers()), 1_000);
    consumer
        .handle(&env, scope, &message)
        .await
        .expect("first pass");
    consumer
        .handle(&env, scope, &message)
        .await
        .expect("the re-run tolerates its own earlier output");

    let owed = owed_claims(&harness, &stream).await;
    assert_eq!(
        owed.len(),
        1,
        "the re-run queued the event a second time under a second jti"
    );
}

#[tokio::test]
async fn a_receiver_at_its_ceiling_does_not_block_a_healthy_one() {
    // A refusal one receiver EARNED must not fail the trigger, because the trigger covers
    // every stream. A receiver that has stopped acknowledging holds the ceiling in owed
    // SETs; failing the whole fan-out over it would deny the revocation to every other
    // receiver in the environment, which is the opposite of what a security signal is for.
    //
    // The ceiling is passed to the consumer as ONE, and one stream is pre-filled to it, so
    // the refusal is real rather than simulated.
    let harness = Harness::start_store_backed().await;
    provision_envelope(&harness).await;
    let scope = harness.scope();
    let env = harness.state().env().clone();
    let store = store_of(&harness);
    let client = a_client(&harness).await;
    let full = seed_stream(
        &harness,
        &client,
        poll_stream(),
        SsfSubjectFormat::Opaque,
        &revocation_only(),
    )
    .await;
    let healthy = seed_stream(
        &harness,
        &client,
        poll_stream(),
        SsfSubjectFormat::Opaque,
        &revocation_only(),
    )
    .await;
    store
        .scoped(scope)
        .ssf_stream_sets()
        .queue(&env, &full, "evt_backlog", "header.payload.sig", 1)
        .await
        .expect("fill the stream to its ceiling");

    let session = create_session(&store, &env, scope, SUBJECT).await;
    end_session(&store, &env, scope, &session, SessionEndCause::LoggedOut).await;
    explode_pass(&harness, scope).await;
    let stats = worker(
        &harness,
        Arc::new(SsfSessionFanOutConsumer::new(
            store_of(&harness),
            Arc::clone(harness.state().issuers()),
            1,
        )),
    )
    .run_once(scope)
    .await
    .expect("fan-out pass");
    assert_eq!(
        stats.completed, 1,
        "one receiver's backlog failed the whole fan-out"
    );

    let healthy_owed = owed_claims(&harness, &healthy).await;
    assert_eq!(
        healthy_owed.len(),
        1,
        "the healthy receiver was denied the revocation because another was full"
    );
    let (event_type, _) = sole_event(&healthy_owed[0]);
    assert_eq!(event_type, caep::SESSION_REVOKED);
    // AND THE FULL ONE KEPT WHAT IT ALREADY HAD, rather than having the backlog evicted to
    // make room: the ceiling refuses the new write, it does not drop an owed event.
    // Counted rather than decoded, because the seeded backlog is a placeholder string and
    // not a real compact JWS.
    let still_owed = store
        .scoped(scope)
        .ssf_stream_sets()
        .owed_count(&full)
        .await
        .expect("count the backlog");
    assert_eq!(
        still_owed, 1,
        "the ceiling evicted an owed event instead of refusing the new one"
    );
}
