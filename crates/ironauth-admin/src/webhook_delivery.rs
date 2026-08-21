//! Webhook DISPATCH: the outbox consumer that signs a queued delivery and POSTs it
//! (issue #105, the last slice).
//!
//! The other three slices built everything one delivery needs and mounted none of it on a
//! worker: `ironauth_jose::webhooks` is the Standard Webhooks signing contract, migrations
//! 0111 and 0112 hold the endpoints and their sealed secrets, and the management API
//! registers, rotates and deletes them. This is where those become deliveries.
//!
//! It rides the generic transactional outbox (#104) rather than a bespoke queue, so a
//! webhook inherits at-least-once delivery, per-aggregate ordering, bounded retry with
//! backoff, dead-lettering and the scope fencing already proven there. What is webhook
//! specific is only what is in this file: which secrets to sign under, what the three
//! headers are, and how a delivery failure is classified.
//!
//! The outbound POST goes through [`ironauth_fetch`] and nowhere else. An endpoint URL is
//! operator supplied and therefore an SSRF vector, so it gets the same resolve-once-pin,
//! deny-internal, no-redirect, size-and-time-capped treatment back-channel logout gets.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ironauth_env::Env;
use ironauth_jose::webhooks::{WebhookSecret, sign_delivery};
use ironauth_oidc::SendFailure;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    DeliveryTargetLookup, NewDeliveryAttempt, OutboxMessage, Scope, Store,
    WEBHOOK_DELIVERY_CONSUMER, WEBHOOK_REPLAY_CONSUMER, WebhookEndpointId,
};

/// The payload key naming the endpoint this message is destined for.
const PAYLOAD_ENDPOINT_ID: &str = "endpoint_id";
/// The payload key bounding a replay command to messages enqueued at or after an instant.
const PAYLOAD_SINCE: &str = "since_unix_micros";
/// The payload key carrying the JSON body to POST.
const PAYLOAD_BODY: &str = "body";

/// The `webhook-id` header: the receiver's deduplication handle.
const HEADER_ID: &str = "webhook-id";
/// The `webhook-timestamp` header: Unix seconds, and part of the signed input.
const HEADER_TIMESTAMP: &str = "webhook-timestamp";
/// The `webhook-signature` header: the space-delimited `v1,<base64>` list.
const HEADER_SIGNATURE: &str = "webhook-signature";

/// The single outbound seam a delivery leaves the process through.
///
/// It exists so the consumer is testable without a network: the production implementor
/// wraps the SSRF-hardened [`ironauth_fetch::Fetcher`], and a test implementor records
/// what it was handed and returns programmable outcomes. Everything ABOVE this trait, the
/// part that decides which secrets sign a delivery and what the headers say, is then
/// exercised for real rather than mocked out alongside the transport.
///
/// The returned future is declared `Send` so a worker built on this seam stays spawnable
/// on a multi-threaded runtime.
pub trait WebhookSender: Send + Sync {
    /// POST `body` to `url` under the three Standard Webhooks headers. This is the ONLY
    /// outbound path the consumer has.
    ///
    /// It returns what the RECEIVER said rather than merely whether the call worked,
    /// because the attempt history (#106) records the status code on a success as well as
    /// on a failure. A boolean outcome would have left "it returned 204" and "it returned
    /// 200" indistinguishable in the record an operator debugs from.
    ///
    /// `headers` is NOT optional. Every delivery carries `webhook-id`; what varies is whether
    /// [`DeliveryHeaders::signature`] is present. Optionality lives one level down for a
    /// reason measured here: making the whole set optional dropped the dedup handle along with
    /// the signature, and an unsigned receiver then could not tell a redelivery from a second
    /// event on an at-least-once queue.
    ///
    /// One sender rather than two, so the header-encoding refusal below stays in ONE place: a
    /// second outbound path is a second chance to send a delivery the receiver cannot verify.
    fn deliver(
        &self,
        url: &str,
        headers: &DeliveryHeaders,
        body: &str,
    ) -> impl Future<Output = DeliveryOutcome> + Send;
}

/// What ONE delivery attempt produced.
///
/// `status` is `None` when the attempt never reached a response at all: a destination the
/// SSRF policy refused, a timeout, a transport fault. That absence is itself the useful
/// fact in a history, and `failure` names which of those it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryOutcome {
    /// The HTTP status the receiver returned, if it returned one.
    pub status: Option<u16>,
    /// `None` on success; otherwise why the attempt did not succeed.
    pub failure: Option<SendFailure>,
}

impl DeliveryOutcome {
    /// A 2xx.
    #[must_use]
    pub fn success(status: u16) -> Self {
        Self {
            status: Some(status),
            failure: None,
        }
    }

    /// A failure, carrying the receiver's status when there was one.
    #[must_use]
    pub fn failed(status: Option<u16>, failure: SendFailure) -> Self {
        Self {
            status,
            failure: Some(failure),
        }
    }
}

/// The three Standard Webhooks headers one delivery carries.
///
/// A struct rather than three parameters because the values are not interchangeable and
/// two of them are strings: transposing the id and the signature at a call site would
/// produce deliveries no consumer could verify and nothing in the type system would have
/// objected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryHeaders {
    /// `webhook-id`: stable across every retry of the same delivery.
    ///
    /// ALWAYS sent, signed or not. This is the delivery's IDENTITY, not part of its
    /// signature: it is the handle a receiver deduplicates an at-least-once queue on, and a
    /// delivery without one cannot be deduplicated at all. An earlier revision made the whole
    /// header set optional so an unsigned flow target could be delivered, which dropped this
    /// with the other two and left an unsigned receiver unable to tell a redelivery from a
    /// second event.
    pub id: String,
    /// The signature pair, or [`None`] for a deliberately UNSIGNED delivery.
    ///
    /// A webhook endpoint always has a secret, so this is always `Some` from that consumer;
    /// an HTTP flow target may legitimately have none (issue #112) and the store permits it.
    pub signature: Option<SignaturePair>,
}

/// The two headers that carry a signature, present together or not at all.
///
/// One type rather than two `Option`s, because a timestamp without a signature and a signature
/// without a timestamp are both unverifiable: `verify_delivery` needs the pair to reconstruct
/// what was signed, so a shape that can express one without the other can express a delivery
/// no receiver can check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignaturePair {
    /// `webhook-timestamp`: Unix seconds, as a decimal string.
    pub timestamp: String,
    /// `webhook-signature`: the space-delimited `v1,<base64>` list.
    pub signature: String,
}

/// The production sender: a POST through the SSRF-hardened outbound fetcher.
pub struct FetchWebhookSender {
    fetcher: Arc<ironauth_fetch::Fetcher>,
    /// Which outbound purpose the metric series is attributed to. A webhook delivery and a
    /// flow-target delivery are different destinations with different operators behind them,
    /// and one series covering both would make neither debuggable.
    purpose: ironauth_fetch::FetchPurpose,
}

impl FetchWebhookSender {
    /// Wrap a shared hardened fetcher.
    #[must_use]
    pub fn new(fetcher: Arc<ironauth_fetch::Fetcher>) -> Self {
        Self {
            fetcher,
            purpose: ironauth_fetch::FetchPurpose::WebhookDelivery,
        }
    }

    /// The same sender, attributing its calls to a different outbound purpose.
    #[must_use]
    pub fn for_purpose(mut self, purpose: ironauth_fetch::FetchPurpose) -> Self {
        self.purpose = purpose;
        self
    }

    /// Build a production sender whose per-delivery time budget is `total_timeout`, so a
    /// slow receiver cannot wedge the worker. Constructs the one sanctioned outbound
    /// fetcher internally, so the binary wiring this does not itself reach an HTTP client.
    ///
    /// # Errors
    ///
    /// [`ironauth_fetch::TlsSetupError`] if the OS trust store yields no usable roots.
    pub fn with_timeout(total_timeout: Duration) -> Result<Self, ironauth_fetch::TlsSetupError> {
        let limits = ironauth_fetch::FetchLimits {
            total_timeout,
            ..ironauth_fetch::FetchLimits::default()
        };
        Ok(Self::new(Arc::new(ironauth_fetch::Fetcher::new(limits)?)))
    }
}

impl WebhookSender for FetchWebhookSender {
    fn deliver(
        &self,
        url: &str,
        headers: &DeliveryHeaders,
        body: &str,
    ) -> impl Future<Output = DeliveryOutcome> + Send {
        let fetcher = Arc::clone(&self.fetcher);
        let purpose = self.purpose;
        let url = url.to_owned();
        let body = body.to_owned();
        let headers = headers.clone();
        async move {
            let mut request = ironauth_fetch::FetchRequest::new(purpose, http::Method::POST, url)
                .header(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/json"),
                )
                .body(body);
            // The id first and unconditionally; the signature pair only when the delivery is
            // signed.
            let mut emit = vec![(HEADER_ID, headers.id.as_str())];
            if let Some(signed) = headers.signature.as_ref() {
                emit.push((HEADER_TIMESTAMP, signed.timestamp.as_str()));
                emit.push((HEADER_SIGNATURE, signed.signature.as_str()));
            }
            for (name, value) in emit {
                // A header value that will not encode means the delivery cannot be made
                // correctly, and sending it WITHOUT the header would present an unsigned
                // POST to the receiver. Refusing is the only safe answer.
                let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(name.as_bytes()),
                    http::HeaderValue::from_str(value),
                ) else {
                    return DeliveryOutcome::failed(None, SendFailure::Transport);
                };
                request = request.header(name, value);
            }
            match fetcher.fetch(request).await {
                Ok(response) if response.status().is_success() => {
                    DeliveryOutcome::success(response.status().as_u16())
                }
                Ok(response) => {
                    let status = response.status().as_u16();
                    DeliveryOutcome::failed(Some(status), SendFailure::Status(status))
                }
                Err(ironauth_fetch::FetchError::Blocked) => {
                    DeliveryOutcome::failed(None, SendFailure::Blocked)
                }
                Err(ironauth_fetch::FetchError::Timeout) => {
                    DeliveryOutcome::failed(None, SendFailure::Timeout)
                }
                Err(_) => DeliveryOutcome::failed(None, SendFailure::Transport),
            }
        }
    }
}

/// The consumer that turns one queued message into one signed, delivered webhook.
pub struct WebhookDeliveryConsumer<S> {
    store: Store,
    sender: S,
    auto_disable_after: u32,
}

impl<S: WebhookSender> WebhookDeliveryConsumer<S> {
    /// Build the consumer over a DATA-plane store and an outbound sender.
    ///
    /// The store must carry a master key, since opening an endpoint's sealed signing
    /// secret is the whole point of the read; without one every delivery fails retryably
    /// rather than silently going out unsigned.
    #[must_use]
    pub fn new(store: Store, sender: S) -> Self {
        Self::with_auto_disable(store, sender, 0)
    }

    /// Build the consumer with automatic endpoint disabling after `auto_disable_after`
    /// consecutive failed attempts. `0` turns the behaviour off.
    ///
    /// A separate constructor rather than a fourth argument on [`Self::new`], so the
    /// existing callers that do not want it read as deliberately opting out rather than
    /// passing a magic zero.
    #[must_use]
    pub fn with_auto_disable(store: Store, sender: S, auto_disable_after: u32) -> Self {
        Self {
            store,
            sender,
            auto_disable_after,
        }
    }

    /// Read a required string off the message payload.
    fn payload_str<'m>(message: &'m OutboxMessage, key: &str) -> Result<&'m str, ConsumerError> {
        message
            .payload
            .get(key)
            .and_then(serde_json::Value::as_str)
            // A malformed payload is PERMANENT: no number of retries will add a field to
            // a row that is already written, so retrying only delays the dead letter.
            .ok_or_else(|| ConsumerError::permanent(format!("payload_missing_{key}")))
    }

    /// Disable `endpoint` if its last `auto_disable_after` attempts ALL failed.
    ///
    /// Nothing is lost by disabling, which is what makes it safe to do automatically: the
    /// messages already queued for the endpoint dead-letter on the paused arm of
    /// [`Self::deliver_one`] rather than being dropped, so an operator resumes and replays
    /// them. Without that, auto-disable would silently discard every event in flight.
    ///
    /// Every failure here is swallowed. The delivery has already happened and its outcome
    /// is the caller's to report; not disabling on this pass is harmless, because the next
    /// failure asks the same question again.
    async fn maybe_auto_disable(&self, env: &Env, scope: Scope, endpoint: &WebhookEndpointId) {
        if self.auto_disable_after == 0 {
            return;
        }
        let exhausted = self
            .store
            .scoped(scope)
            .webhook_delivery_attempts()
            .last_attempts_all_failed(endpoint, i64::from(self.auto_disable_after))
            .await
            .unwrap_or(false);
        if !exhausted {
            return;
        }
        match self
            .store
            .scoped(scope)
            .webhook_endpoints()
            .auto_disable(env, endpoint, "consecutive_delivery_failures")
            .await
        {
            Ok(true) => tracing::warn!(
                %endpoint,
                consecutive_failures = self.auto_disable_after,
                "webhook endpoint auto-disabled after sustained delivery failure; queued \
                 deliveries dead-letter and are replayable once it is resumed"
            ),
            // Already disabled, or resumed by an operator in between. Neither is an error
            // and neither should be reported as one.
            Ok(false) => {}
            Err(error) => tracing::warn!(
                %error,
                %endpoint,
                "webhook endpoint could not be auto-disabled; deliveries continue"
            ),
        }
    }

    /// Deliver ONE message: resolve the endpoint, sign, POST.
    async fn deliver_one(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let endpoint_raw = Self::payload_str(message, PAYLOAD_ENDPOINT_ID)?;
        let body = message
            .payload
            .get(PAYLOAD_BODY)
            .ok_or_else(|| ConsumerError::permanent(format!("payload_missing_{PAYLOAD_BODY}")))?;
        // Serialize ONCE and sign these exact bytes, because the signature is over what
        // goes on the wire. Re-serializing for the send could reorder a map and produce a
        // signature no receiver could reproduce.
        let body = serde_json::to_string(body)
            .map_err(|_| ConsumerError::permanent("payload_body_not_serializable"))?;

        let repo = self.store.scoped(scope).webhook_endpoints();
        let id = repo
            .parse_id(endpoint_raw)
            .map_err(|_| ConsumerError::permanent("endpoint_id_malformed"))?;
        let now = env.clock().now_utc();
        let now_secs = unix_secs(now);
        let target = repo
            .delivery_target(&id, now_secs.saturating_mul(1_000_000))
            .await
            // A read that failed can succeed later (a database that was unreachable, an
            // envelope key not provisioned yet), so this is retryable. The substrate's
            // finite attempt budget is what turns a persistent failure into a dead letter.
            .map_err(|_| ConsumerError::retryable("endpoint_read_failed"))?;
        // The two ways there is nothing to deliver to are handled DIFFERENTLY, and the
        // difference is the whole of #106's rule that nothing is dropped without landing
        // somewhere replayable.
        //
        // ABSENT: the endpoint was deleted. There is nowhere to deliver, nothing to
        // resume, and its signing secret is gone, so the message is completed. Retrying
        // would burn the attempt budget reaching a destination that no longer exists.
        //
        // PAUSED: deliveries are turned off, but the endpoint and its secret survive and
        // an operator can turn it back on. Completing here would DROP a real event with no
        // dead letter behind it, and once auto-disable exists that is not a rare corner:
        // it is what happens to every message in flight the moment an endpoint is
        // disabled. So it dead-letters instead, which is the state the replay surface
        // (#559) recovers from.
        let target = match target {
            DeliveryTargetLookup::Deliverable(target) => target,
            DeliveryTargetLookup::Absent => return Ok(()),
            DeliveryTargetLookup::Paused => {
                return Err(ConsumerError::permanent("endpoint_paused"));
            }
        };

        let secrets: Vec<WebhookSecret> = target
            .secrets
            .iter()
            .map(|raw| WebhookSecret::from_bytes(raw.clone()))
            .collect();
        let headers = DeliveryHeaders {
            // The producer's dedup handle, which is derived from the domain fact and is
            // therefore IDENTICAL on every retry of this message. That is exactly what
            // `webhook-id` has to be for a receiver to deduplicate at-least-once delivery.
            id: message.idempotency_key.clone(),
            // Always `Some` here: a webhook endpoint always carries a secret.
            signature: Some(SignaturePair {
                timestamp: now_secs.to_string(),
                signature: sign_delivery(
                    &secrets,
                    &message.idempotency_key,
                    now_secs,
                    body.as_bytes(),
                ),
            }),
        };

        // Latency is measured across the send through the CLOCK SEAM rather than a
        // monotonic timer, for the same reason every other instant in this tree comes from
        // the seam: a test drives it deterministically instead of asserting on real
        // elapsed time. It is a wall clock, so it can in principle step; the subtraction
        // saturates at zero rather than recording a negative duration, which the column's
        // CHECK would refuse anyway.
        let started_micros = unix_micros(now);
        let outcome = self.sender.deliver(&target.url, &headers, &body).await;
        let finished_micros = unix_micros(env.clock().now_utc());
        let latency_ms = finished_micros.saturating_sub(started_micros) / 1000;

        // The attempt is recorded BEFORE the outcome is turned into a retry, so a failure
        // that will be retried still leaves its record behind. Recording only terminal
        // outcomes would produce a history that omits precisely the attempts an operator
        // opens it to see.
        //
        // A history write that fails does NOT fail the delivery. The delivery either
        // reached the receiver or did not, and turning a bookkeeping fault into a retry
        // would resend a webhook that already arrived. The loss is logged, which is the
        // honest trade: history is best effort, delivery is not.
        let attempt = NewDeliveryAttempt {
            message_id: &message.id,
            endpoint: &target.id,
            webhook_id: &message.idempotency_key,
            // `attempts` counts the failures RECORDED so far, so this attempt is the next
            // one; a message on its first pass has zero and this is attempt 1.
            attempt_number: message.attempts.saturating_add(1),
            attempted_at_unix_micros: started_micros,
            status_code: outcome.status,
            latency_ms,
            error: outcome.failure.map(SendFailure::label),
        };
        if let Err(error) = self
            .store
            .scoped(scope)
            .webhook_delivery_attempts()
            .record(env, &attempt)
            .await
        {
            tracing::warn!(
                %error,
                webhook_id = %message.idempotency_key,
                "the webhook delivery attempt history could not be written; the delivery \
                 itself is unaffected"
            );
        }

        let Some(failure) = outcome.failure else {
            return Ok(());
        };

        // Sustained failure disables the endpoint. Evaluated after the attempt is
        // recorded, so the run it reads includes the attempt that just failed.
        self.maybe_auto_disable(env, scope, &target.id).await;

        // A refused destination, a timeout, a non-2xx and a transport fault are all
        // retryable: the attempts cap is what turns a persistently dead receiver into a
        // dead letter, so nothing here needs a second way to give up.
        Err(ConsumerError::retryable(failure.label()))
    }
}

impl<S: WebhookSender> OutboxConsumer for WebhookDeliveryConsumer<S> {
    fn name(&self) -> &str {
        WEBHOOK_DELIVERY_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(async move { self.deliver_one(env, scope, message).await })
    }
}

/// The consumer that executes an operator's dead-letter REPLAY command (issue #106).
///
/// It exists because the plane that may ask for a replay and the plane that may perform
/// one are deliberately different. The management API holds INSERT on the queue and no
/// UPDATE (migration 0099, so that the role holding the retention DELETE can never have
/// been the role that marked a message terminal), while the drain holds the lifecycle
/// columns. An operator's request therefore travels as a message, and this is what picks
/// it up on the data plane and does the revive with grants that already existed.
pub struct WebhookReplayConsumer {
    store: Store,
}

impl WebhookReplayConsumer {
    /// Build the consumer over a DATA-plane store.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Execute ONE replay command.
    async fn replay_one(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let endpoint = message
            .payload
            .get(PAYLOAD_ENDPOINT_ID)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ConsumerError::permanent(format!("payload_missing_{PAYLOAD_ENDPOINT_ID}"))
            })?;
        // Absent means "everything", which is a legitimate command rather than a malformed
        // one, so only a present-but-not-a-number value is refused.
        let since = match message.payload.get(PAYLOAD_SINCE) {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_i64()
                    .ok_or_else(|| ConsumerError::permanent("payload_since_not_an_integer"))?,
            ),
        };
        let revived = self
            .store
            .scoped(scope)
            .outbox()
            .revive_dead_lettered(env, WEBHOOK_DELIVERY_CONSUMER, Some(endpoint), since)
            .await
            // A failed revive can succeed later, so this retries rather than dropping the
            // operator's request; the substrate's attempt budget is what bounds it.
            .map_err(|_| ConsumerError::retryable("replay_failed"))?;
        tracing::info!(
            endpoint,
            revived,
            "replayed dead-lettered webhook deliveries"
        );
        Ok(())
    }
}

impl OutboxConsumer for WebhookReplayConsumer {
    fn name(&self) -> &str {
        WEBHOOK_REPLAY_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(async move { self.replay_one(env, scope, message).await })
    }
}

/// Microseconds since the Unix epoch for a wall-clock instant (saturating).
fn unix_micros(at: std::time::SystemTime) -> i64 {
    match at.duration_since(std::time::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Seconds since the Unix epoch for a wall-clock instant (saturating).
fn unix_secs(at: std::time::SystemTime) -> i64 {
    match at.duration_since(std::time::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}
