// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CIBA ping notification worker (issue #131 criterion 2): turns one queued message into
//! one POST to the client's registered notification endpoint.
//!
//! # What a ping is, and what it deliberately is not
//!
//! CIBA Core section 10.2 says the ping notification tells the client "the request you made
//! is ready" and nothing else. It carries the `auth_req_id` and no tokens. The client then
//! comes to the token endpoint and authenticates itself there, exactly as a polling client
//! would, which is the whole reason ping is safe and push is not: the credential still leaves
//! only through an authenticated fetch.
//!
//! So this worker sends a two-field body. Anything richer would be pushing authorization
//! state to an endpoint whose only authentication is a bearer token the client gave us.
//!
//! # Where the token comes from
//!
//! Not from the queue. The `client_notification_token` is a live bearer credential and an
//! outbox row is readable by anything that can read the queue, so the producer deliberately
//! left it out of the payload and this worker reads it from the request row it has to fetch
//! anyway.

use std::sync::Arc;

use ironauth_env::Env;
use ironauth_store::outbox::ConsumerError;
use ironauth_store::{BackchannelAuthRequestId, OutboxMessage, Scope, Store};

use ironauth_oidc::SendFailure;

use crate::webhook_delivery::DeliveryOutcome;

/// The outbound half, kept behind a trait so the worker is testable without a network.
pub trait PingSender: Send + Sync {
    /// POST `body` to `url`, authenticating the notification with `token` as a bearer.
    ///
    /// Returns what the receiver SAID rather than merely whether the call worked, matching
    /// the webhook sender: a 204 and a 200 are both successes an operator may need to tell
    /// apart when debugging why a client claims it was never notified.
    fn deliver(
        &self,
        url: &str,
        token: &str,
        body: &str,
    ) -> impl std::future::Future<Output = DeliveryOutcome> + Send;
}

/// A shared sender is itself a sender, so a test can keep a handle to inspect what was sent
/// while the consumer owns one.
impl<T: PingSender> PingSender for Arc<T> {
    fn deliver(
        &self,
        url: &str,
        token: &str,
        body: &str,
    ) -> impl std::future::Future<Output = DeliveryOutcome> + Send {
        (**self).deliver(url, token, body)
    }
}

/// The consumer that turns one queued ping into one delivered notification.
pub struct CibaPingConsumer<S> {
    store: Store,
    sender: S,
    env: Arc<Env>,
}

impl<S: PingSender> CibaPingConsumer<S> {
    /// Build the consumer over a DATA-plane store and an outbound sender.
    #[must_use]
    pub fn new(store: Store, sender: S, env: Arc<Env>) -> Self {
        Self { store, sender, env }
    }

    /// Deliver one queued ping.
    ///
    /// # Errors
    ///
    /// [`ConsumerError::permanent`] when the message can never succeed -- a malformed
    /// payload, or a request that no longer exists -- because retrying cannot add a field to
    /// a row that is already written, and only delays the dead letter.
    ///
    /// [`ConsumerError::retryable`] when the receiver or the network failed, which is what
    /// the outbox's bounded backoff exists for.
    pub async fn handle(&self, scope: Scope, message: &OutboxMessage) -> Result<(), ConsumerError> {
        let raw = message
            .payload
            .get("auth_req_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ConsumerError::permanent("payload_missing_auth_req_id"))?;
        let id = BackchannelAuthRequestId::parse_in_scope(raw, &scope)
            .map_err(|_| ConsumerError::permanent("auth_req_id_out_of_scope"))?;

        let now_micros = epoch_micros(&self.env);
        let delivery = self
            .store
            .scoped(scope)
            .backchannel_auth()
            .ping_delivery(&id, now_micros)
            .await
            .map_err(|_| ConsumerError::retryable("ping_delivery_read_failed"))?
            .ok_or_else(|| ConsumerError::permanent("request_gone"))?;

        // A request that has since been redeemed, denied or expired is a SUCCESS with nothing
        // to do, not a failure. Telling a client to come and fetch tokens it can no longer
        // obtain would send it into a redemption that is guaranteed to fail, and retrying
        // would burn the whole budget on a request whose outcome is already settled.
        if !delivery.still_deliverable {
            return Ok(());
        }

        // The token is bytes at rest because it is replayed, not compared. A token that is
        // not valid UTF-8 cannot be placed in an Authorization header at all, and no retry
        // changes that.
        let token = std::str::from_utf8(&delivery.notification_token)
            .map_err(|_| ConsumerError::permanent("notification_token_not_utf8"))?;

        // Two fields, per CIBA Core section 10.2. No tokens: the client authenticates at the
        // token endpoint to get those, which is what keeps ping distinct from push.
        let body = serde_json::json!({ "auth_req_id": id.to_string() }).to_string();

        let outcome = self
            .sender
            .deliver(&delivery.notification_url, token, &body)
            .await;
        match outcome.failure {
            None => Ok(()),
            // BLOCKED is PERMANENT, and it is the only one. The SSRF policy refused the
            // destination -- a loopback, private or metadata address -- and no amount of
            // retrying turns a forbidden address into an allowed one. Retrying would spend
            // the whole budget re-deciding a question whose answer is a property of the URL,
            // and the dead letter is what an operator needs to see: this client registered an
            // endpoint we will never call.
            Some(SendFailure::Blocked) => Err(ConsumerError::permanent("ping_blocked_by_ssrf")),
            // Everything else is retryable, INCLUDING a 4xx. A notification endpoint
            // answering 404 today is usually a deploy in progress rather than a settled
            // refusal, and the outbox already bounds how long we keep believing that before
            // dead-lettering. Treating a 4xx as permanent would discard a ping that a
            // thirty-second rollout would have delivered.
            Some(failure) => Err(ConsumerError::retryable(failure_label(failure))),
        }
    }
}

/// A stable, low-cardinality label for an attempt failure.
///
/// Low cardinality on purpose: this ends up on a dead-letter row and in metrics, and a label
/// carrying the receiver's own message would make every distinct error string its own series.
fn failure_label(failure: SendFailure) -> &'static str {
    match failure {
        SendFailure::Status(_) => "ping_status",
        SendFailure::Transport => "ping_transport",
        SendFailure::Timeout => "ping_timeout",
        SendFailure::Blocked => "ping_blocked_by_ssrf",
    }
}

/// Now, in epoch microseconds, from the environment clock seam.
fn epoch_micros(env: &Env) -> i64 {
    env.clock()
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(i64::MAX)
}
