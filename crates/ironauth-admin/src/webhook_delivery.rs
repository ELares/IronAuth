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
    OutboxMessage, Scope, Store, WEBHOOK_DELIVERY_CONSUMER, WEBHOOK_REPLAY_CONSUMER,
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
    /// POST `body` to `url` under the three Standard Webhooks headers, returning `Ok(())`
    /// on a 2xx and a [`SendFailure`] otherwise. This is the ONLY outbound path the
    /// consumer has.
    fn deliver(
        &self,
        url: &str,
        headers: &DeliveryHeaders,
        body: &str,
    ) -> impl Future<Output = Result<(), SendFailure>> + Send;
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
    pub id: String,
    /// `webhook-timestamp`: Unix seconds, as a decimal string.
    pub timestamp: String,
    /// `webhook-signature`: the space-delimited `v1,<base64>` list.
    pub signature: String,
}

/// The production sender: a POST through the SSRF-hardened outbound fetcher.
pub struct FetchWebhookSender {
    fetcher: Arc<ironauth_fetch::Fetcher>,
}

impl FetchWebhookSender {
    /// Wrap a shared hardened fetcher.
    #[must_use]
    pub fn new(fetcher: Arc<ironauth_fetch::Fetcher>) -> Self {
        Self { fetcher }
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
    ) -> impl Future<Output = Result<(), SendFailure>> + Send {
        let fetcher = Arc::clone(&self.fetcher);
        let url = url.to_owned();
        let body = body.to_owned();
        let headers = headers.clone();
        async move {
            let mut request = ironauth_fetch::FetchRequest::new(
                ironauth_fetch::FetchPurpose::WebhookDelivery,
                http::Method::POST,
                url,
            )
            .header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/json"),
            )
            .body(body);
            for (name, value) in [
                (HEADER_ID, headers.id.as_str()),
                (HEADER_TIMESTAMP, headers.timestamp.as_str()),
                (HEADER_SIGNATURE, headers.signature.as_str()),
            ] {
                // A header value that will not encode means the delivery cannot be made
                // correctly, and sending it WITHOUT the header would present an unsigned
                // POST to the receiver. Refusing is the only safe answer.
                let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(name.as_bytes()),
                    http::HeaderValue::from_str(value),
                ) else {
                    return Err(SendFailure::Transport);
                };
                request = request.header(name, value);
            }
            match fetcher.fetch(request).await {
                Ok(response) if response.status().is_success() => Ok(()),
                Ok(response) => Err(SendFailure::Status(response.status().as_u16())),
                Err(ironauth_fetch::FetchError::Blocked) => Err(SendFailure::Blocked),
                Err(ironauth_fetch::FetchError::Timeout) => Err(SendFailure::Timeout),
                Err(_) => Err(SendFailure::Transport),
            }
        }
    }
}

/// The consumer that turns one queued message into one signed, delivered webhook.
pub struct WebhookDeliveryConsumer<S> {
    store: Store,
    sender: S,
}

impl<S: WebhookSender> WebhookDeliveryConsumer<S> {
    /// Build the consumer over a DATA-plane store and an outbound sender.
    ///
    /// The store must carry a master key, since opening an endpoint's sealed signing
    /// secret is the whole point of the read; without one every delivery fails retryably
    /// rather than silently going out unsigned.
    #[must_use]
    pub fn new(store: Store, sender: S) -> Self {
        Self { store, sender }
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
        // No target means the endpoint was DELETED or DEACTIVATED after this message was
        // enqueued. Both are an operator saying "stop delivering here", so the message is
        // completed rather than retried: retrying would burn the attempt budget to reach
        // a destination that has been withdrawn, and dead-lettering would report an
        // operator's own deliberate action as a delivery failure.
        let Some(target) = target else {
            return Ok(());
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
            timestamp: now_secs.to_string(),
            signature: sign_delivery(
                &secrets,
                &message.idempotency_key,
                now_secs,
                body.as_bytes(),
            ),
        };

        self.sender
            .deliver(&target.url, &headers, &body)
            .await
            // A refused destination, a timeout, a non-2xx and a transport fault are all
            // retryable: the attempts cap is what turns a persistently dead receiver into
            // a dead letter, so nothing here needs a second way to give up.
            .map_err(|failure| ConsumerError::retryable(failure.label()))
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

/// Seconds since the Unix epoch for a wall-clock instant (saturating).
fn unix_secs(at: std::time::SystemTime) -> i64 {
    match at.duration_since(std::time::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}
