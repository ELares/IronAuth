// SPDX-License-Identifier: MIT OR Apache-2.0

//! OIDC Back-Channel Logout: the Logout Token and the delivery worker (issue #34),
//! against a real Postgres.
//!
//! The store suite pins the delivery queue's data model; these pin what a relying party
//! actually receives and how the worker behaves end to end:
//!
//! - a Logout Token carries the REQUIRED claims plus the RP's OWN `sid`, the `events`
//!   member, and the `typ = logout+jwt` header, and NO `nonce`; it verifies under the
//!   environment's published key;
//! - each participating RP gets its OWN token (no cross-client `sid` leak);
//! - delivery goes through the SSRF-hardened outbound fetcher, so an internal/loopback
//!   `backchannel_logout_uri` is REFUSED;
//! - the worker drains the session-ended outbox, explodes it per RP, and marks delivered
//!   on a 2xx;
//! - a failing RP is retried with a bounded backoff (driven by the manual clock) and
//!   dead-lettered after the cap, WITHOUT blocking a healthy RP;
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
    BACKCHANNEL_LOGOUT_EVENT, BackChannelLogoutWorker, LogoutSender, SendFailure, WorkerSettings,
};
use ironauth_store::{
    ActorRef, ClientId, CorrelationId, NewSession, Scope, ServiceId, SessionEndCause, SessionId,
    Store, UserId,
};
use serde_json::Value;

/// A far-future expiry (year 2100) in epoch microseconds.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// A recording, programmable Logout Token sender. Cheap to clone (shared inner), so a
/// test hands one clone to the worker and keeps another to inspect what was delivered.
#[derive(Clone, Default)]
struct MockSender {
    inner: Arc<MockInner>,
}

#[derive(Default)]
struct MockInner {
    sent: Mutex<Vec<(String, String)>>,
    fail: Mutex<HashSet<String>>,
}

impl MockSender {
    /// Program a URI to fail every delivery with a 5xx (a down RP).
    fn fail_uri(&self, uri: &str) {
        self.inner.fail.lock().expect("lock").insert(uri.to_owned());
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
        let fails = self.inner.fail.lock().expect("lock").contains(uri);
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
    let sid = store
        .scoped(scope)
        .client_sessions()
        .ensure_sid(env, session, &client.to_string(), 0)
        .await
        .expect("ensure sid");
    (client, sid)
}

/// End `session` (enqueues one session-ended outbox event).
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

/// Build a worker over the harness store, env, and pre-populated issuer registry, with
/// the injected `sender` and `settings`.
fn worker<S: LogoutSender>(
    harness: &Harness,
    sender: S,
    settings: WorkerSettings,
) -> BackChannelLogoutWorker<S> {
    BackChannelLogoutWorker::new(
        harness.store().clone(),
        harness.env().clone(),
        Arc::clone(harness.state().issuers()),
        sender,
        settings,
    )
}

/// Decode a compact JWS header as JSON.
fn header_of(token: &str) -> Value {
    let segment = token.split('.').next().expect("header segment");
    let bytes = URL_SAFE_NO_PAD.decode(segment).expect("base64 header");
    serde_json::from_slice(&bytes).expect("header json")
}

/// Decode a compact JWS payload and return its `jti` claim.
fn jti_of(token: &str) -> String {
    let segment = token.split('.').nth(1).expect("payload segment");
    let bytes = URL_SAFE_NO_PAD.decode(segment).expect("base64 payload");
    let claims: Value = serde_json::from_slice(&bytes).expect("payload json");
    claims
        .get("jti")
        .and_then(Value::as_str)
        .expect("jti claim")
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
    let stats = worker(&harness, sender.clone(), WorkerSettings::default())
        .run_once(scope)
        .await
        .expect("drain pass");
    assert_eq!(stats.events_exploded, 1);
    assert_eq!(stats.delivered, 1);

    let sent = sender.sent();
    assert_eq!(sent.len(), 1, "exactly one token was delivered");
    let (uri, token) = &sent[0];
    assert_eq!(uri, "https://rp.example/bc");

    // The header carries the logout+jwt type.
    assert_eq!(header_of(token)["typ"], "logout+jwt");

    // The token verifies under the environment's published key, with the RP as audience.
    let verified = verify(
        token,
        &harness.policy(&client.to_string()),
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
    let stats = worker(&harness, sender.clone(), WorkerSettings::default())
        .run_once(scope)
        .await
        .expect("drain pass");
    assert_eq!(stats.delivered, 2, "each RP gets its own token");

    // Each RP's token carries ITS OWN sid (never the other client's).
    for (uri, token) in sender.sent() {
        let (expected_client, expected_sid) = if uri == "https://a.example/bc" {
            (&client_a, &sid_a)
        } else {
            (&client_b, &sid_b)
        };
        let verified = verify(
            &token,
            &harness.policy(&expected_client.to_string()),
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

    // And through the worker: a loopback-resolving RP is never delivered; its delivery is
    // retried and records the SSRF block as its last error.
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
    let stats = worker(&harness, sender, WorkerSettings::default())
        .run_once(scope)
        .await
        .expect("drain pass");
    assert_eq!(stats.delivered, 0, "an SSRF-blocked RP is never delivered");
    assert_eq!(stats.retried, 1, "it is retried, not silently dropped");

    let listed = store
        .scoped(scope)
        .backchannel_deliveries()
        .list(100)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert!(listed[0].delivered_at_unix_micros.is_none());
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
    let settings = WorkerSettings {
        max_attempts: 3,
        retry_base: Duration::from_secs(10),
        lease: Duration::from_secs(30),
        batch: 64,
    };
    let worker = worker(&harness, sender.clone(), settings);

    // Pass 1: the healthy RP is delivered; the down RP fails and is scheduled for retry.
    let pass1 = worker.run_once(scope).await.expect("pass 1");
    assert_eq!(
        pass1.delivered, 1,
        "the healthy RP is delivered immediately"
    );
    assert_eq!(
        pass1.retried, 1,
        "the down RP is scheduled for a backoff retry"
    );
    assert_eq!(pass1.dead_lettered, 0);

    // The backoff gate is driven by the clock: WITHOUT advancing it, the down RP is not
    // due, so a repeat pass does nothing (determinism under the manual clock).
    let idle = worker.run_once(scope).await.expect("idle pass");
    assert_eq!(
        idle.retried, 0,
        "the down RP is not due until its backoff elapses"
    );
    assert_eq!(idle.delivered, 0);

    // Pass 2: advance past the backoff; the down RP fails again (attempt 2).
    clock.advance(Duration::from_secs(120));
    let pass2 = worker.run_once(scope).await.expect("pass 2");
    assert_eq!(pass2.retried, 1);
    assert_eq!(pass2.dead_lettered, 0);

    // Pass 3: advance again; the down RP hits the cap and is dead-lettered.
    clock.advance(Duration::from_secs(120));
    let pass3 = worker.run_once(scope).await.expect("pass 3");
    assert_eq!(
        pass3.dead_lettered, 1,
        "the down RP dead-letters at the cap"
    );
    assert_eq!(pass3.delivered, 0);

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

    // Terminal states: the healthy RP delivered, the down RP dead-lettered, never both.
    let listed = store
        .scoped(scope)
        .backchannel_deliveries()
        .list(100)
        .await
        .expect("list");
    let good = listed
        .iter()
        .find(|d| d.client_id == good_client.to_string())
        .expect("good delivery");
    let down = listed
        .iter()
        .find(|d| d.logout_uri == "https://down.example/bc")
        .expect("down delivery");
    assert!(good.delivered_at_unix_micros.is_some());
    assert!(good.dead_lettered_at_unix_micros.is_none());
    assert!(down.dead_lettered_at_unix_micros.is_some());
    assert!(down.delivered_at_unix_micros.is_none());
    assert_eq!(down.attempts, 3);
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
    let settings = WorkerSettings {
        max_attempts: 5,
        retry_base: Duration::from_secs(10),
        lease: Duration::from_secs(30),
        batch: 64,
    };
    let worker = worker(&harness, sender.clone(), settings);

    // Attempt 1: the down RP fails and is retried; the healthy RP is delivered.
    worker.run_once(scope).await.expect("pass 1");
    // Attempt 2: advance past the backoff so the down RP is due again; it fails again.
    clock.advance(Duration::from_secs(120));
    worker.run_once(scope).await.expect("pass 2");

    let sent = sender.sent();
    let down_jtis: Vec<String> = sent
        .iter()
        .filter(|(uri, _)| uri == "https://down.example/bc")
        .map(|(_, token)| jti_of(token))
        .collect();
    assert_eq!(
        down_jtis.len(),
        2,
        "the down RP was attempted twice: a first-attempt failure then a retry"
    );
    // The SAME delivery row keeps ONE jti across attempts, so at-least-once redelivery
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
        .map(|(_, token)| jti_of(token))
        .expect("the healthy RP was delivered");
    assert_ne!(
        down_jtis[0], healthy_jti,
        "distinct deliveries carry distinct jtis"
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
    let stats = worker(&harness, sender.clone(), WorkerSettings::default())
        .run_once(scope_a)
        .await
        .expect("drain A");
    assert_eq!(stats.delivered, 1, "only A's single RP is delivered");

    // Every delivered token is for an A-scope client; B's URI never appears.
    let sent = sender.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "https://a.example/bc");
    let verified = verify(
        &sent[0].1,
        &harness.policy(&client_a.to_string()),
        &common::verify_clock(),
    )
    .expect("A's token verifies");
    assert_eq!(
        verified.claims().get("aud").and_then(Value::as_str),
        Some(client_a.to_string().as_str())
    );

    // Tenant B is untouched: its session-ended event is still undrained and it has no
    // delivery rows (the A worker never crossed the tenant boundary).
    assert_eq!(
        store
            .scoped(scope_b)
            .session_events()
            .pending(100)
            .await
            .expect("B pending events")
            .len(),
        1,
        "B's session-ended event is undrained"
    );
    assert!(
        store
            .scoped(scope_b)
            .backchannel_deliveries()
            .pending(100)
            .await
            .expect("B pending deliveries")
            .is_empty(),
        "B has no deliveries: the A worker never touched B"
    );
}
