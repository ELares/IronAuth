// SPDX-License-Identifier: MIT OR Apache-2.0

//! OIDC Back-Channel Logout: the Logout Token and its two outbox consumers (issues #34
//! and #104), against a real Postgres.
//!
//! The store suite pins the fan-out's data model; these pin what a relying party actually
//! receives and how the consumers behave end to end:
//!
//! - a Logout Token carries the REQUIRED claims plus the RP's OWN `sid`, the `events`
//!   member, and the `typ = logout+jwt` header, and NO `nonce`; it verifies under the
//!   environment's published key;
//! - each participating RP gets its OWN token (no cross-client `sid` leak);
//! - delivery goes through the SSRF-hardened outbound fetcher, so an internal/loopback
//!   `backchannel_logout_uri` is REFUSED;
//! - the explode consumer drains the session-ended queue and fans it out per RP; the
//!   delivery consumer POSTs one of them and completes its message on a 2xx;
//! - a failing RP is retried on the substrate's bounded backoff (driven by the manual
//!   clock) and dead-lettered after the cap, WITHOUT blocking a healthy RP, and WITHOUT
//!   delaying a LATER logout to the same RP, which is what the per-message ordering key
//!   buys;
//! - a re-explode after a LAPSED LEASE notifies every RP exactly once and changes no
//!   `jti`, which is the property that keeps a re-run from dead-lettering a whole
//!   session's fan-out;
//! - the whole path works through the REAL `ConsumerRegistry` and REAL worker pools, which
//!   is the only way to catch a consumer name that matches no producer: that failure
//!   drains nothing and reports perfect health;
//! - a worker in tenant A never sends tenant B's logout tokens.

mod common;

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::Harness;
use ironauth_env::Env;
use ironauth_jose::verify;
use ironauth_oidc::{
    BACKCHANNEL_LOGOUT_EVENT, BackChannelLogoutConsumer, LogoutSender, SendFailure,
    SessionEndedExplodeConsumer,
};
use ironauth_store::outbox::{
    ConsumerRegistry, DrainStats, OutboxConsumer, OutboxObserver, OutboxWorker, OutboxWorkerPool,
    ScopeSource, SilentObserver, StaticScopes, WorkerSettings,
};
use ironauth_store::{
    ActorRef, BACKCHANNEL_LOGOUT_CONSUMER, ClientId, CorrelationId, NewSession, OutboxMessage,
    RetryPolicy, SESSION_ENDED_CONSUMER, Scope, ServiceId, SessionEndCause, SessionId, Store,
    UserId,
};
use serde_json::Value;

/// A far-future expiry (year 2100) in epoch microseconds.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// The worker tuning these tests drive: a bounded attempts cap so a dead letter is reached
/// in a few passes, and a lease comfortably longer than any handler here.
fn settings(max_attempts: u32) -> WorkerSettings {
    WorkerSettings {
        concurrency: 1,
        visibility_timeout: Duration::from_secs(30),
        poll_interval: Duration::from_secs(5),
        batch: 64,
        retry: RetryPolicy {
            max_attempts,
            retry_base: Duration::from_secs(10),
        },
    }
}

/// A recording, programmable Logout Token sender. Cheap to clone (shared inner), so a
/// test hands one clone to the consumer and keeps another to inspect what was delivered.
#[derive(Clone, Default)]
struct MockSender {
    inner: Arc<MockInner>,
}

#[derive(Default)]
struct MockInner {
    sent: Mutex<Vec<(String, String)>>,
    fail_uri: Mutex<HashSet<String>>,
    fail_sid: Mutex<HashSet<String>>,
}

impl MockSender {
    /// Program a URI to fail every delivery with a 5xx (a down RP).
    fn fail_uri(&self, uri: &str) {
        self.inner
            .fail_uri
            .lock()
            .expect("lock")
            .insert(uri.to_owned());
    }

    /// Program ONE `sid` to fail, which is how a test makes exactly one of several
    /// deliveries to the SAME relying party fail.
    fn fail_sid(&self, sid: &str) {
        self.inner
            .fail_sid
            .lock()
            .expect("lock")
            .insert(sid.to_owned());
    }

    /// The (uri, token) pairs delivered so far, in order.
    fn sent(&self) -> Vec<(String, String)> {
        self.inner.sent.lock().expect("lock").clone()
    }
}

impl LogoutSender for MockSender {
    fn deliver(
        &self,
        uri: &str,
        logout_token: &str,
    ) -> impl Future<Output = Result<(), SendFailure>> + Send {
        self.inner
            .sent
            .lock()
            .expect("lock")
            .push((uri.to_owned(), logout_token.to_owned()));
        let fails = self.inner.fail_uri.lock().expect("lock").contains(uri)
            || self
                .inner
                .fail_sid
                .lock()
                .expect("lock")
                .contains(&claim_of(logout_token, "sid"));
        async move {
            if fails {
                Err(SendFailure::Status(503))
            } else {
                Ok(())
            }
        }
    }
}

/// A fresh service actor and correlation id for a seeding write.
fn actor(env: &Env) -> (ActorRef, CorrelationId) {
    (
        ActorRef::service(ServiceId::generate(env)),
        CorrelationId::generate(env),
    )
}

/// Create a live SSO session in `scope`.
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

/// Register a client with a `backchannel_logout_uri` and bind its per-client session
/// (`sid`) to `session`. Returns the client id and its sid.
async fn participant(
    store: &Store,
    env: &Env,
    scope: Scope,
    session: &SessionId,
    uri: &str,
) -> (ClientId, String) {
    let (a, c) = actor(env);
    let client = store
        .scoped(scope)
        .acting(a, c)
        .clients()
        .create(env, "rp")
        .await
        .expect("create client");
    let (a, c) = actor(env);
    store
        .scoped(scope)
        .acting(a, c)
        .clients()
        .register_backchannel_logout(env, &client, Some(uri), false)
        .await
        .expect("register backchannel logout");
    let sid = bind_sid(store, env, scope, session, &client).await;
    (client, sid)
}

/// Bind an ALREADY registered client's per-client session (`sid`) to `session`: the shape
/// a second SSO session for the same relying party takes.
async fn bind_sid(
    store: &Store,
    env: &Env,
    scope: Scope,
    session: &SessionId,
    client: &ClientId,
) -> String {
    store
        .scoped(scope)
        .client_sessions()
        .ensure_sid(env, session, &client.to_string(), 0)
        .await
        .expect("ensure sid")
}

/// End `session` (enqueues one session-ended outbox message).
async fn end_session(store: &Store, env: &Env, scope: Scope, session: &SessionId) {
    let (a, c) = actor(env);
    store
        .scoped(scope)
        .acting(a, c)
        .sessions()
        .revoke(env, session, SessionEndCause::LoggedOut, false, None)
        .await
        .expect("revoke session");
}

/// The explode consumer, as the registry holds it.
fn explode_consumer(harness: &Harness) -> Arc<dyn OutboxConsumer> {
    Arc::new(SessionEndedExplodeConsumer::new(harness.store().clone()))
}

/// The delivery consumer over `sender`, as the registry holds it.
fn delivery_consumer<S: LogoutSender + 'static>(
    harness: &Harness,
    sender: S,
) -> Arc<dyn OutboxConsumer> {
    Arc::new(BackChannelLogoutConsumer::new(
        Arc::clone(harness.state().issuers()),
        sender,
    ))
}

/// The observer the pools in this suite report to: nothing. What the pool reports is the
/// store suite's property; this one is about what a relying party receives.
fn silent() -> Arc<dyn OutboxObserver> {
    Arc::new(SilentObserver)
}

/// A worker over one consumer, driving the REAL substrate one pass at a time.
fn worker(
    harness: &Harness,
    consumer: Arc<dyn OutboxConsumer>,
    tuning: WorkerSettings,
) -> OutboxWorker {
    OutboxWorker::new(
        harness.store().clone(),
        harness.env().clone(),
        consumer,
        tuning,
    )
}

/// Run ONE explode pass: turn every drained ended session into its per-RP messages.
async fn explode_pass(harness: &Harness, scope: Scope) -> DrainStats {
    worker(harness, explode_consumer(harness), settings(5))
        .run_once(scope)
        .await
        .expect("explode pass")
}

/// Run ONE delivery pass over `sender` with an attempts cap of `max_attempts`.
async fn deliver_pass<S: LogoutSender + Clone + 'static>(
    harness: &Harness,
    scope: Scope,
    sender: &S,
    max_attempts: u32,
) -> DrainStats {
    worker(
        harness,
        delivery_consumer(harness, sender.clone()),
        settings(max_attempts),
    )
    .run_once(scope)
    .await
    .expect("delivery pass")
}

/// Explode then deliver, the two stages one after the other.
async fn drain_both<S: LogoutSender + Clone + 'static>(
    harness: &Harness,
    scope: Scope,
    sender: &S,
    max_attempts: u32,
) -> (DrainStats, DrainStats) {
    let exploded = explode_pass(harness, scope).await;
    let delivered = deliver_pass(harness, scope, sender, max_attempts).await;
    (exploded, delivered)
}

/// Every back-channel delivery message in `scope`, in any state.
async fn delivery_messages(store: &Store, scope: Scope) -> Vec<OutboxMessage> {
    store
        .scoped(scope)
        .outbox()
        .list(BACKCHANNEL_LOGOUT_CONSUMER, 100)
        .await
        .expect("list delivery messages")
}

/// A string field off a delivery message's payload.
fn payload_of(message: &OutboxMessage, key: &str) -> String {
    message
        .payload
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Decode a compact JWS header as JSON.
fn header_of(token: &str) -> Value {
    let segment = token.split('.').next().expect("header segment");
    let bytes = URL_SAFE_NO_PAD.decode(segment).expect("base64 header");
    serde_json::from_slice(&bytes).expect("header json")
}

/// Decode a compact JWS payload and return one string claim.
fn claim_of(token: &str, claim: &str) -> String {
    let Some(segment) = token.split('.').nth(1) else {
        return String::new();
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(segment) else {
        return String::new();
    };
    let Ok(claims) = serde_json::from_slice::<Value>(&bytes) else {
        return String::new();
    };
    claims
        .get(claim)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn a_logout_token_carries_the_rp_sid_the_events_claim_and_no_nonce() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let store = harness.store().clone();
    let env = harness.env().clone();
    let subject = UserId::generate(&env, &scope).to_string();

    let session = create_session(&store, &env, scope, &subject).await;
    let (client, sid) = participant(&store, &env, scope, &session, "https://rp.example/bc").await;
    end_session(&store, &env, scope, &session).await;

    let sender = MockSender::default();
    let (exploded, delivered) = drain_both(&harness, scope, &sender, 5).await;
    assert_eq!(exploded.completed, 1, "the ended session is exploded once");
    assert_eq!(delivered.completed, 1);

    let sent = sender.sent();
    assert_eq!(sent.len(), 1, "exactly one token was delivered");
    let (uri, token) = &sent[0];
    assert_eq!(uri, "https://rp.example/bc");

    // The header carries the logout+jwt type.
    assert_eq!(header_of(token)["typ"], "logout+jwt");

    // The token verifies under the environment's published key, with the RP as audience.
    let verified = verify(
        token,
        &harness.logout_token_policy(&client.to_string()),
        &common::verify_clock(),
    )
    .expect("logout token verifies under the environment key");
    let claims = verified.claims();
    assert_eq!(
        claims.get("iss").and_then(Value::as_str),
        Some(harness.issuer())
    );
    assert_eq!(
        claims.get("aud").and_then(Value::as_str),
        Some(client.to_string().as_str())
    );
    assert_eq!(
        claims.get("sid").and_then(Value::as_str),
        Some(sid.as_str()),
        "the token carries the RP's own sid"
    );
    assert!(claims.get("exp").is_some(), "a logout token carries exp");
    assert!(claims.get("jti").is_some(), "a logout token carries jti");
    // The events member names the back-channel-logout event and maps to an empty object.
    let events = claims.get("events").expect("events claim");
    assert!(
        events.get(BACKCHANNEL_LOGOUT_EVENT).is_some(),
        "events names the back-channel-logout event"
    );
    // A logout token MUST NOT carry a nonce.
    assert!(claims.get("nonce").is_none(), "a logout token has no nonce");
}

#[tokio::test]
async fn each_participating_rp_gets_its_own_token_with_no_cross_client_sid_leak() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let store = harness.store().clone();
    let env = harness.env().clone();
    let subject = UserId::generate(&env, &scope).to_string();

    // Two RPs on the SAME SSO session, each with its own sid.
    let session = create_session(&store, &env, scope, &subject).await;
    let (client_a, sid_a) =
        participant(&store, &env, scope, &session, "https://a.example/bc").await;
    let (client_b, sid_b) =
        participant(&store, &env, scope, &session, "https://b.example/bc").await;
    assert_ne!(sid_a, sid_b);
    end_session(&store, &env, scope, &session).await;

    let sender = MockSender::default();
    let (_, delivered) = drain_both(&harness, scope, &sender, 5).await;
    assert_eq!(delivered.completed, 2, "each RP gets its own token");

    // Each RP's token carries ITS OWN sid (never the other client's).
    for (uri, token) in sender.sent() {
        let (expected_client, expected_sid) = if uri == "https://a.example/bc" {
            (&client_a, &sid_a)
        } else {
            (&client_b, &sid_b)
        };
        let verified = verify(
            &token,
            &harness.logout_token_policy(&expected_client.to_string()),
            &common::verify_clock(),
        )
        .expect("verifies");
        let claims = verified.claims();
        assert_eq!(
            claims.get("sid").and_then(Value::as_str),
            Some(expected_sid.as_str()),
            "{uri} carries only its own client's sid"
        );
        // The OTHER client's sid never appears in this token.
        let other_sid = if uri == "https://a.example/bc" {
            &sid_b
        } else {
            &sid_a
        };
        assert_ne!(
            claims.get("sid").and_then(Value::as_str),
            Some(other_sid.as_str())
        );
    }
}

#[tokio::test]
async fn an_internal_logout_uri_is_refused_by_the_ssrf_guard() {
    use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
    use ironauth_oidc::FetchLogoutSender;

    // The production sender routes every POST through the SSRF-hardened fetcher. A URI
    // that resolves to a loopback address is refused BEFORE any connection, uniformly.
    let resolver = Arc::new(StaticResolver::new(vec!["127.0.0.1".parse().expect("ip")]));
    let dialer = Arc::new(RecordingDialer::new("127.0.0.1:9".parse().expect("addr")));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver, dialer);
    let sender = FetchLogoutSender::new(Arc::new(fetcher));

    let result = sender
        .deliver("https://rp.internal/backchannel", "logout.token.jwt")
        .await;
    assert_eq!(
        result,
        Err(SendFailure::Blocked),
        "an internal/loopback backchannel_logout_uri is refused by the SSRF guard"
    );

    // And through the consumers: a loopback-resolving RP is never delivered; its message
    // is retried and records the SSRF block as its last error.
    let harness = Harness::start().await;
    let scope = harness.scope();
    let store = harness.store().clone();
    let env = harness.env().clone();
    let subject = UserId::generate(&env, &scope).to_string();
    let session = create_session(&store, &env, scope, &subject).await;
    participant(
        &store,
        &env,
        scope,
        &session,
        "https://rp.internal/backchannel",
    )
    .await;
    end_session(&store, &env, scope, &session).await;

    let resolver = Arc::new(StaticResolver::new(vec!["127.0.0.1".parse().expect("ip")]));
    let dialer = Arc::new(RecordingDialer::new("127.0.0.1:9".parse().expect("addr")));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver, dialer);
    let sender = FetchLogoutSender::new(Arc::new(fetcher));

    explode_pass(&harness, scope).await;
    let delivered = worker(&harness, delivery_consumer(&harness, sender), settings(5))
        .run_once(scope)
        .await
        .expect("delivery pass");
    assert_eq!(
        delivered.completed, 0,
        "an SSRF-blocked RP is never delivered"
    );
    assert_eq!(delivered.retried, 1, "it is retried, not silently dropped");

    let listed = delivery_messages(&store, scope).await;
    assert_eq!(listed.len(), 1);
    assert!(listed[0].completed_at_unix_micros.is_none());
    assert_eq!(
        listed[0].last_error.as_deref(),
        Some("blocked_by_ssrf_policy")
    );
}

#[tokio::test]
async fn a_failing_rp_is_retried_with_backoff_and_dead_letters_without_blocking_others() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let store = harness.store().clone();
    let env = harness.env().clone();
    let clock = Arc::clone(harness.clock());
    let subject = UserId::generate(&env, &scope).to_string();

    // Two RPs on one session: a healthy one and a down one.
    let session = create_session(&store, &env, scope, &subject).await;
    let (good_client, _) =
        participant(&store, &env, scope, &session, "https://good.example/bc").await;
    participant(&store, &env, scope, &session, "https://down.example/bc").await;
    end_session(&store, &env, scope, &session).await;

    let sender = MockSender::default();
    sender.fail_uri("https://down.example/bc");
    // A small attempts cap so the dead-letter is reached quickly.
    let cap = 3;

    // Pass 1: the healthy RP is delivered; the down RP fails and is scheduled for retry.
    let (exploded, pass1) = drain_both(&harness, scope, &sender, cap).await;
    assert_eq!(exploded.completed, 1);
    assert_eq!(
        pass1.completed, 1,
        "the healthy RP is delivered immediately"
    );
    assert_eq!(
        pass1.retried, 1,
        "the down RP is scheduled for a backoff retry"
    );
    assert_eq!(pass1.dead_lettered, 0);

    // The backoff gate is driven by the clock: WITHOUT advancing it, the down RP is not
    // due, so a repeat pass does nothing (determinism under the manual clock).
    let idle = deliver_pass(&harness, scope, &sender, cap).await;
    assert_eq!(
        idle.retried, 0,
        "the down RP is not due until its backoff elapses"
    );
    assert_eq!(idle.completed, 0);

    // Pass 2: advance past the backoff; the down RP fails again (attempt 2).
    clock.advance(Duration::from_secs(120));
    let pass2 = deliver_pass(&harness, scope, &sender, cap).await;
    assert_eq!(pass2.retried, 1);
    assert_eq!(pass2.dead_lettered, 0);

    // Pass 3: advance again; the down RP hits the cap and is dead-lettered.
    clock.advance(Duration::from_secs(120));
    let pass3 = deliver_pass(&harness, scope, &sender, cap).await;
    assert_eq!(
        pass3.dead_lettered, 1,
        "the down RP dead-letters at the cap"
    );
    assert_eq!(pass3.completed, 0);

    // The healthy RP got exactly one token; the down RP was tried three times and never
    // succeeded. A slow/failing RP never blocked the healthy one.
    let sent = sender.sent();
    let good_hits = sent
        .iter()
        .filter(|(u, _)| u == "https://good.example/bc")
        .count();
    let down_hits = sent
        .iter()
        .filter(|(u, _)| u == "https://down.example/bc")
        .count();
    assert_eq!(good_hits, 1, "the healthy RP is delivered exactly once");
    assert_eq!(down_hits, 3, "the down RP is tried up to the attempts cap");

    // Terminal states: the healthy RP completed, the down RP dead-lettered, never both.
    let listed = delivery_messages(&store, scope).await;
    let good = listed
        .iter()
        .find(|m| payload_of(m, "client_id") == good_client.to_string())
        .expect("good delivery");
    let down = listed
        .iter()
        .find(|m| payload_of(m, "logout_uri") == "https://down.example/bc")
        .expect("down delivery");
    assert!(good.completed_at_unix_micros.is_some());
    assert!(good.dead_lettered_at_unix_micros.is_none());
    assert!(down.dead_lettered_at_unix_micros.is_some());
    assert!(down.completed_at_unix_micros.is_none());
    assert_eq!(down.attempts, 3);
}

#[tokio::test]
async fn a_dead_rp_never_delays_a_later_logout_to_the_same_rp() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let store = harness.store().clone();
    let env = harness.env().clone();
    let subject = UserId::generate(&env, &scope).to_string();

    // ONE relying party, TWO SSO sessions. This is the case an ordering key of `client_id`
    // would break: both deliveries would land in one group, only the group's HEAD is ever
    // leased, and the first session's failing delivery would stall the second session's
    // logout to the same RP for the whole backoff schedule. The per-delivery ordering key
    // makes each its own singleton group, so the second is claimable immediately.
    let uri = "https://shared.example/bc";
    let first = create_session(&store, &env, scope, &subject).await;
    let (client, first_sid) = participant(&store, &env, scope, &first, uri).await;
    end_session(&store, &env, scope, &first).await;
    // The first session's fan-out is enqueued FIRST, so it holds the lower sequence and
    // would be the group head under a per-client ordering key.
    let exploded_first = explode_pass(&harness, scope).await;
    assert_eq!(exploded_first.completed, 1);

    let second = create_session(&store, &env, scope, &subject).await;
    let second_sid = bind_sid(&store, &env, scope, &second, &client).await;
    assert_ne!(first_sid, second_sid, "each session has its own sid");
    end_session(&store, &env, scope, &second).await;
    let exploded_second = explode_pass(&harness, scope).await;
    assert_eq!(exploded_second.completed, 1);

    // Only the FIRST session's logout fails. The RP itself is reachable.
    let sender = MockSender::default();
    sender.fail_sid(&first_sid);

    let pass = deliver_pass(&harness, scope, &sender, 3).await;
    assert_eq!(
        pass.claimed, 2,
        "both deliveries to one RP are claimable in the SAME pass: nothing serializes them"
    );
    assert_eq!(
        pass.completed, 1,
        "the second session's logout is delivered while the first is still failing"
    );
    assert_eq!(pass.retried, 1);

    let sids: Vec<String> = sender
        .sent()
        .iter()
        .map(|(_, token)| claim_of(token, "sid"))
        .collect();
    assert!(
        sids.contains(&second_sid),
        "the later logout reached the RP on the FIRST pass, not after the earlier one gave up"
    );

    // And in the durable record: the second is terminal while the first is not.
    let listed = delivery_messages(&store, scope).await;
    let second_message = listed
        .iter()
        .find(|m| payload_of(m, "sid") == second_sid)
        .expect("the second session's delivery");
    let first_message = listed
        .iter()
        .find(|m| payload_of(m, "sid") == first_sid)
        .expect("the first session's delivery");
    assert!(second_message.completed_at_unix_micros.is_some());
    assert!(first_message.completed_at_unix_micros.is_none());
    assert_eq!(first_message.attempts, 1);
}

#[tokio::test]
async fn a_re_explode_after_a_lapsed_lease_notifies_every_rp_exactly_once() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let store = harness.store().clone();
    let env = harness.env().clone();
    let clock = Arc::clone(harness.clock());
    let subject = UserId::generate(&env, &scope).to_string();

    // Three RPs, so a partial fan-out would be visible as a missing recipient.
    let session = create_session(&store, &env, scope, &subject).await;
    participant(&store, &env, scope, &session, "https://a.example/bc").await;
    participant(&store, &env, scope, &session, "https://b.example/bc").await;
    participant(&store, &env, scope, &session, "https://c.example/bc").await;
    end_session(&store, &env, scope, &session).await;

    // A worker claims the session-ended message and DOES the explode, then loses its lease
    // before it can record the completion. That is the ordinary crash path, not an exotic
    // one: the message stays non-terminal and is re-claimed by the next worker.
    let claimed = store
        .scoped(scope)
        .outbox()
        .claim(&env, SESSION_ENDED_CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim the session-ended message");
    assert_eq!(claimed.len(), 1);
    let consumer = explode_consumer(&harness);
    consumer
        .handle(&env, scope, &claimed[0])
        .await
        .expect("the first explode succeeds");

    let after_first = delivery_messages(&store, scope).await;
    assert_eq!(after_first.len(), 3, "all three RPs are enqueued");
    let first_jtis: Vec<String> = {
        let mut jtis: Vec<String> = after_first.iter().map(|m| payload_of(m, "jti")).collect();
        jtis.sort();
        jtis
    };

    // The lease lapses. The session-ended message becomes claimable again and the SAME
    // work re-runs. It must SUCCEED: a re-explode that raised on its own earlier output
    // would fail identically on every attempt and dead-letter this session's whole
    // fan-out, leaving any RP the first pass had not reached permanently un-notified.
    clock.advance(Duration::from_secs(120));
    let re_explode = explode_pass(&harness, scope).await;
    assert_eq!(
        re_explode.claimed, 1,
        "the un-completed message is re-claimed"
    );
    assert_eq!(
        re_explode.completed, 1,
        "the re-explode COMPLETES rather than failing on its own earlier output"
    );
    assert_eq!(re_explode.dead_lettered, 0, "and it never dead-letters");

    let after_second = delivery_messages(&store, scope).await;
    assert_eq!(
        after_second.len(),
        3,
        "the re-explode enqueues no duplicate: each RP is notified exactly once"
    );
    let second_jtis: Vec<String> = {
        let mut jtis: Vec<String> = after_second.iter().map(|m| payload_of(m, "jti")).collect();
        jtis.sort();
        jtis
    };
    assert_eq!(
        first_jtis, second_jtis,
        "the payload is immutable, so a re-explode changes no jti and the RP's dedup holds"
    );

    // The session-ended message is now terminal, so it never drains again.
    assert!(
        store
            .scoped(scope)
            .outbox()
            .pending(SESSION_ENDED_CONSUMER, 100)
            .await
            .expect("pending")
            .is_empty()
    );
}

#[tokio::test]
async fn a_delivery_keeps_one_stable_jti_across_retries_while_distinct_deliveries_differ() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let store = harness.store().clone();
    let env = harness.env().clone();
    let clock = Arc::clone(harness.clock());
    let subject = UserId::generate(&env, &scope).to_string();

    // One ended session, two RPs: a down one (retried across attempts) and a healthy one.
    let session = create_session(&store, &env, scope, &subject).await;
    participant(&store, &env, scope, &session, "https://down.example/bc").await;
    participant(&store, &env, scope, &session, "https://healthy.example/bc").await;
    end_session(&store, &env, scope, &session).await;

    let sender = MockSender::default();
    sender.fail_uri("https://down.example/bc");

    // Attempt 1: the down RP fails and is retried; the healthy RP is delivered.
    drain_both(&harness, scope, &sender, 5).await;
    // Attempt 2: advance past the backoff so the down RP is due again; it fails again.
    clock.advance(Duration::from_secs(120));
    deliver_pass(&harness, scope, &sender, 5).await;

    let sent = sender.sent();
    let down_jtis: Vec<String> = sent
        .iter()
        .filter(|(uri, _)| uri == "https://down.example/bc")
        .map(|(_, token)| claim_of(token, "jti"))
        .collect();
    assert_eq!(
        down_jtis.len(),
        2,
        "the down RP was attempted twice: a first-attempt failure then a retry"
    );
    // The SAME delivery message keeps ONE jti across attempts, so at-least-once redelivery
    // re-POSTs the SAME token and the RP dedups a retry on the jti. A fresh per-attempt
    // jti (the pre-fix behaviour) would make these two differ and defeat that dedup.
    assert_eq!(
        down_jtis[0], down_jtis[1],
        "two attempts of one delivery carry the identical jti"
    );

    // A DISTINCT delivery (a different RP) carries a DIFFERENT jti.
    let healthy_jti = sent
        .iter()
        .find(|(uri, _)| uri == "https://healthy.example/bc")
        .map(|(_, token)| claim_of(token, "jti"))
        .expect("the healthy RP was delivered");
    assert_ne!(
        down_jtis[0], healthy_jti,
        "distinct deliveries carry distinct jtis"
    );
}

#[tokio::test]
async fn the_registered_consumers_drain_an_ended_session_end_to_end() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let store = harness.store().clone();
    let env = harness.env().clone();
    let subject = UserId::generate(&env, &scope).to_string();

    let session = create_session(&store, &env, scope, &subject).await;
    let (client, sid) = participant(&store, &env, scope, &session, "https://rp.example/bc").await;
    end_session(&store, &env, scope, &session).await;

    let sender = MockSender::default();

    // The REAL registry and the REAL pool type, because this is the only shape that
    // catches the failure mode a hand-constructed worker hides: a consumer whose `name`
    // does not equal the `consumer` discriminator its producers write claims nothing at
    // all, silently, while every pool reports full health. Both names here come from the
    // exported constants, and the assertion is that a delivery actually arrives.
    //
    // It is NOT the binary's boot seam, and saying so is the point. The registration, the
    // per consumer tuning and the one-pool-per-consumer loop live in
    // `spawn_backchannel_logout_pools` and `spawn_consumer_pools`, in the `ironauth`
    // binary crate, which this crate cannot call and does not depend on. That seam is
    // driven and asserted where it lives, in `crates/ironauth/src/outbox_wiring_tests.rs`.
    // What is re-implemented here is the two-stage CHAINING, which is this crate's
    // property: an ended session becomes per-RP messages and one of them becomes a POST.
    let mut registry = ConsumerRegistry::new();
    registry
        .register(explode_consumer(&harness))
        .expect("register the explode consumer");
    registry
        .register(delivery_consumer(&harness, sender.clone()))
        .expect("register the delivery consumer");
    assert_eq!(
        registry.len(),
        2,
        "two consumers, registered under distinct names"
    );

    let scopes: Arc<dyn ScopeSource> = Arc::new(StaticScopes::new(vec![scope]));
    let tuning = WorkerSettings {
        // A short poll so the two stages chain within the test's patience. The messages
        // are due the instant they are enqueued, so nothing here depends on wall time
        // beyond the poll cadence itself.
        poll_interval: Duration::from_millis(20),
        ..settings(5)
    };
    let pools: Vec<OutboxWorkerPool> = registry
        .all()
        .into_iter()
        .map(|consumer| {
            let worker = OutboxWorker::new(store.clone(), env.clone(), consumer, tuning);
            OutboxWorkerPool::spawn(&worker, &scopes, &silent())
        })
        .collect();
    assert_eq!(pools.len(), 2, "one pool per registered consumer");
    // No `size() == configured_size()` assertion here: `live` is incremented
    // synchronously inside `spawn` and `StaticScopes` cannot fail, so at this point that
    // comparison is true by construction and could not go red for any reason. The place
    // where it MEASURES something is the store suite, which kills the workers with a
    // panicking scope source and watches the live count fall.

    // Wait for a delivery to arrive through the pools rather than asserting immediately:
    // the two stages are independent loops, so the fan-out and the POST are at least one
    // poll apart.
    let mut arrived = Vec::new();
    for _ in 0..200 {
        arrived = sender.sent();
        if !arrived.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    for pool in pools {
        pool.shutdown().await;
    }

    assert_eq!(
        arrived.len(),
        1,
        "the registered consumers delivered the logout end to end; an empty result here is \
         the silent no-op a name that matches no producer produces"
    );
    let (uri, token) = &arrived[0];
    assert_eq!(uri, "https://rp.example/bc");

    // The exact names, asserted AFTER the arrival and deliberately so. Asserted first they
    // would be the only thing a drifted name ever tripped, and the wait above would never
    // be exercised as a check; measured with the delivery consumer renamed, that is exactly
    // what happened. Arriving here means the arrival assertion is the live one.
    let mut names = registry.names();
    names.sort_unstable();
    assert_eq!(names, [BACKCHANNEL_LOGOUT_CONSUMER, SESSION_ENDED_CONSUMER]);
    let verified = verify(
        token,
        &harness.logout_token_policy(&client.to_string()),
        &common::verify_clock(),
    )
    .expect("the delivered token verifies");
    assert_eq!(
        verified.claims().get("sid").and_then(Value::as_str),
        Some(sid.as_str())
    );
}

#[tokio::test]
async fn a_worker_in_tenant_a_never_sends_tenant_b_logout_tokens() {
    let harness = Harness::start().await;
    let scope_a = harness.scope();
    let scope_b = harness.provision_foreign_scope().await;
    let store = harness.store().clone();
    let env = harness.env().clone();

    // A participant + ended session in EACH tenant.
    let subject_a = UserId::generate(&env, &scope_a).to_string();
    let session_a = create_session(&store, &env, scope_a, &subject_a).await;
    let (client_a, _) =
        participant(&store, &env, scope_a, &session_a, "https://a.example/bc").await;
    end_session(&store, &env, scope_a, &session_a).await;

    let subject_b = UserId::generate(&env, &scope_b).to_string();
    let session_b = create_session(&store, &env, scope_b, &subject_b).await;
    participant(&store, &env, scope_b, &session_b, "https://b.example/bc").await;
    end_session(&store, &env, scope_b, &session_b).await;

    // Drain ONLY tenant A.
    let sender = MockSender::default();
    let (_, delivered) = drain_both(&harness, scope_a, &sender, 5).await;
    assert_eq!(delivered.completed, 1, "only A's single RP is delivered");

    // Every delivered token is for an A-scope client; B's URI never appears.
    let sent = sender.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "https://a.example/bc");
    let verified = verify(
        &sent[0].1,
        &harness.logout_token_policy(&client_a.to_string()),
        &common::verify_clock(),
    )
    .expect("A's token verifies");
    assert_eq!(
        verified.claims().get("aud").and_then(Value::as_str),
        Some(client_a.to_string().as_str())
    );

    // Tenant B is untouched: its session-ended message is still undrained and it has no
    // delivery messages (the A workers never crossed the tenant boundary).
    assert_eq!(
        store
            .scoped(scope_b)
            .outbox()
            .pending(SESSION_ENDED_CONSUMER, 100)
            .await
            .expect("B pending events")
            .len(),
        1,
        "B's session-ended message is undrained"
    );
    assert!(
        delivery_messages(&store, scope_b).await.is_empty(),
        "B has no deliveries: the A workers never touched B"
    );
}
