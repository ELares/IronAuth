// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CIBA ping worker (issue #131 criterion 2), over a real database.
//!
//! What these assert is the OUTCOME CLASSIFICATION, because that is the part with real
//! consequences: a failure wrongly called permanent discards a notification the client was
//! promised, and one wrongly called retryable spends the whole budget re-deciding a question
//! whose answer will not change.

use std::sync::{Arc, Mutex};

use ironauth_admin::ciba_ping::{CibaPingConsumer, PingSender};
use ironauth_admin::webhook_delivery::DeliveryOutcome;
use ironauth_env::Env;
use ironauth_oidc::SendFailure;
use ironauth_store::ciba::DeliveryMode;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    BackchannelApprovalLinkage, BackchannelAuthRequestId, CIBA_PING_CONSUMER,
    NewBackchannelRequest, OutboxMessage, Scope,
};

const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// The stored digest for a request id.
///
/// Derived from the ID, not from its LENGTH: every generated id is the same length, so a
/// length-based digest collides on the primary key the moment a test seeds twice. Shared so a
/// test that seeds a request can also address it for redemption.
fn digest_of(id: &BackchannelAuthRequestId) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    id.to_string().hash(&mut hasher);
    format!("{:064x}", hasher.finish())
}

/// A sender that records what it was handed and answers a scripted outcome.
struct ScriptedSender {
    outcome: DeliveryOutcome,
    seen: Mutex<Vec<(String, String, String)>>,
}

impl ScriptedSender {
    fn new(outcome: DeliveryOutcome) -> Self {
        Self {
            outcome,
            seen: Mutex::new(Vec::new()),
        }
    }
}

impl PingSender for ScriptedSender {
    async fn deliver(&self, url: &str, token: &str, body: &str) -> DeliveryOutcome {
        self.seen
            .lock()
            .expect("lock")
            .push((url.to_owned(), token.to_owned(), body.to_owned()));
        self.outcome.clone()
    }
}

/// Seed an APPROVED ping request and return the queued message for it.
async fn seed_and_queue(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
) -> (BackchannelAuthRequestId, OutboxMessage) {
    let id = BackchannelAuthRequestId::generate(env, &scope);
    let digest = digest_of(&id);
    db.store()
        .scoped(scope)
        .backchannel_auth()
        .create(&NewBackchannelRequest {
            auth_req_id_digest: &digest,
            id: &id,
            client_id: "cli_owner",
            delivery_mode: DeliveryMode::Ping,
            client_notification_url: Some("https://client.test/ciba"),
            client_notification_token: Some(b"nt-secret"),
            requested_scope: None,
            authorization_details: None,
            binding_message: None,
            subject: "usr_ada",
            interval_secs: 5,
            expires_at_micros: FAR_FUTURE_MICROS,
        })
        .await
        .expect("create");
    // An approval must open a grant: `decide` refuses one whose linkage names none, because a
    // spine-less approval is unredeemable and the client would be told to collect anyway.
    // Not seeded, because `decide` INSERTs it.
    let grant = ironauth_store::GrantId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .backchannel_auth()
        .decide(
            env,
            &id,
            "usr_ada",
            true,
            BackchannelApprovalLinkage {
                grant_id: Some(&grant),
                consent_ref: None,
                auth_methods: None,
                auth_time_micros: None,
            },
            1_800_000_000_000_000,
        )
        .await
        .expect("approve");
    let mut claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            env,
            CIBA_PING_CONSUMER,
            std::time::Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1, "approval must queue exactly one ping");
    (id, claimed.remove(0))
}

/// A successful send carries the endpoint, the token, and a body with NO tokens in it.
///
/// The body assertion is the one that matters. A ping that carried tokens would be push --
/// the mode this deployment refuses precisely because it delivers credentials to an endpoint
/// whose only authentication is a bearer token the client handed us.
#[tokio::test]
async fn a_successful_ping_carries_the_token_and_a_body_with_no_credentials() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (id, message) = seed_and_queue(&db, &env, scope).await;

    let sender = Arc::new(ScriptedSender::new(DeliveryOutcome::success(204)));
    let consumer = CibaPingConsumer::new(db.store().clone(), Arc::clone(&sender), Arc::new(env));
    consumer.handle(scope, &message).await.expect("delivered");

    let seen = sender.seen.lock().expect("lock");
    assert_eq!(seen.len(), 1);
    let (url, token, body) = &seen[0];
    assert_eq!(url, "https://client.test/ciba");
    assert_eq!(
        token, "nt-secret",
        "the client's own token authenticates the ping"
    );
    let parsed: serde_json::Value = serde_json::from_str(body).expect("json body");
    assert_eq!(parsed["auth_req_id"], id.to_string());
    for forbidden in ["access_token", "id_token", "refresh_token"] {
        assert!(
            parsed.get(forbidden).is_none(),
            "a ping carrying {forbidden} would BE push: {body}"
        );
    }
}

/// An SSRF-blocked destination is PERMANENT, and every other failure is retryable.
///
/// Both halves, because the classification is the whole point. Blocked will never succeed --
/// the answer is a property of the URL -- so retrying spends the budget re-deciding it. A 404
/// or a timeout is usually a deploy in progress, and calling that permanent would discard a
/// ping a thirty-second rollout would have delivered.
#[tokio::test]
async fn only_an_ssrf_block_is_permanent() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let cases = [
        (SendFailure::Blocked, true),
        (SendFailure::Status(404), false),
        (SendFailure::Status(500), false),
        (SendFailure::Timeout, false),
        (SendFailure::Transport, false),
    ];
    for (failure, expect_permanent) in cases {
        let (_id, message) = seed_and_queue(&db, &env, scope).await;
        let sender = Arc::new(ScriptedSender::new(DeliveryOutcome::failed(None, failure)));
        let consumer = CibaPingConsumer::new(
            db.store().clone(),
            Arc::clone(&sender),
            Arc::new(Env::system()),
        );
        let error = consumer
            .handle(scope, &message)
            .await
            .expect_err("a failed send must not report success");
        assert_eq!(
            !error.is_retryable(),
            expect_permanent,
            "{failure:?} should be {}",
            if expect_permanent {
                "permanent"
            } else {
                "retryable"
            }
        );
    }
}

/// A malformed payload is permanent, and never reaches the network.
///
/// Retrying cannot add a field to a row that is already written, so a retryable
/// classification here would only delay the dead letter while re-reading the same row.
#[tokio::test]
async fn a_malformed_payload_is_permanent_and_sends_nothing() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (_id, mut message) = seed_and_queue(&db, &env, scope).await;
    message.payload = serde_json::json!({ "wrong_field": "x" });

    let sender = Arc::new(ScriptedSender::new(DeliveryOutcome::success(204)));
    let consumer = CibaPingConsumer::new(db.store().clone(), Arc::clone(&sender), Arc::new(env));
    let error = consumer
        .handle(scope, &message)
        .await
        .expect_err("a payload with no auth_req_id cannot be delivered");
    assert!(!error.is_retryable());
    assert!(
        sender.seen.lock().expect("lock").is_empty(),
        "nothing may be sent for a message we cannot even address"
    );
}

/// A request that has since been REDEEMED is not pinged, and that is a SUCCESS.
///
/// Found by mutation: removing the `still_deliverable` guard changed nothing, because nothing
/// covered it. Worth having for two separate reasons. Telling a client to come and fetch
/// tokens it can no longer obtain sends it into a redemption guaranteed to fail. And
/// classifying this as a failure instead would spend the entire retry budget on a request
/// whose outcome is already settled -- the queue would keep re-asking a question that has been
/// answered.
#[tokio::test]
async fn a_request_redeemed_before_the_ping_is_sent_is_not_pinged() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let (id, message) = seed_and_queue(&db, &env, scope).await;

    // The client polled and redeemed between the approval and the ping being drained.
    let redeemed = db
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem(&digest_of(&id), "cli_owner", 1_800_000_000_000_000)
        .await
        .expect("redeem");
    assert!(redeemed.is_some(), "the request must actually be redeemed");

    let sender = Arc::new(ScriptedSender::new(DeliveryOutcome::success(204)));
    let consumer = CibaPingConsumer::new(db.store().clone(), Arc::clone(&sender), Arc::new(env));
    consumer
        .handle(scope, &message)
        .await
        .expect("a settled request is a success with nothing to do, never a failure");
    assert!(
        sender.seen.lock().expect("lock").is_empty(),
        "a redeemed request must not be pinged"
    );
}
