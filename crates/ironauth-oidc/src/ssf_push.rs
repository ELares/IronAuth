// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8935 push delivery: one Security Event Token to one Shared Signals receiver (#143).
//!
//! It rides the generic transactional outbox (#104) rather than a bespoke queue, so a push
//! inherits at-least-once delivery, per-stream ordering, bounded retry with backoff,
//! dead-lettering and the scope fencing that substrate already has. What is here is only what
//! is specific to SSF: which stream a message names, how its SET is minted, and what a
//! receiver's answer means.
//!
//! # The `jti` is minted once, by the producer
//!
//! RFC 8417 requires a `jti` and receivers dedup on it, so a redelivery MUST carry the same
//! one. It therefore travels on the message's immutable payload and the SET is minted around
//! it at each attempt, which is the shape `backchannel` records for its Logout Token: minting
//! here would give every retry a fresh id and turn one event into N events in the receiver's
//! log. That is also what makes at-least-once delivery safe to expose to a receiver -- the
//! duplicate is detectable BY the receiver, which is the only place it can be.
//!
//! # The stream is re-read at delivery, not carried
//!
//! Only the `stream_id` travels. The endpoint, the audience, the credential name and the
//! status are read from the row at each attempt, so a receiver that re-points its endpoint
//! while a message is queued is delivered to at the NEW address, and one that deletes its
//! stream stops being delivered to at all. Carrying them would have pinned a snapshot taken
//! before the outage that caused the retry.
//!
//! # What a receiver's answer means
//!
//! RFC 8935 section 2.2: a receiver that accepts a SET answers `202 Accepted` with an empty
//! body. This treats any 2xx as accepted, because transmitters meet receivers that answer
//! `200`, and refusing those would be refusing to interoperate over a distinction RFC 8935
//! itself does not make load bearing.
//!
//! A 4xx is the receiver saying the SET is wrong, which a retry cannot fix, so it is PERMANENT
//! and the message dead-letters. A 5xx, a timeout, and a transport fault are the receiver being
//! down, which is exactly what the retry schedule exists for. One exception: `429` is
//! retryable, because it is the receiver asking for less rather than saying no.

use std::sync::Arc;

use ironauth_env::Env;
use ironauth_jose::MasterKey;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    OutboxMessage, SSF_PUSH_CONSUMER, Scope, SsfDelivery, SsfStreamId, Store, StoreError,
};

use crate::backchannel::SendFailure;
use crate::issuer::IssuerRegistry;
use crate::ssf_set::{MintError, SecurityEvent, SetToMint, SubjectIdentifier, mint_set};

/// The payload key naming the stream this SET belongs to.
pub const PAYLOAD_STREAM_ID: &str = "stream_id";
/// The payload key carrying the SET's dedup handle.
pub const PAYLOAD_JTI: &str = "jti";
/// The payload key carrying the RFC 9493 subject identifier, already rendered.
pub const PAYLOAD_SUB_ID: &str = "sub_id";
/// The payload key carrying the event type URI.
pub const PAYLOAD_EVENT_TYPE: &str = "event_type";
/// The payload key carrying the event's own members.
pub const PAYLOAD_EVENT: &str = "event";

/// Queue one SET for one push stream.
///
/// The producer's entry point. #143 ships the delivery machinery and the CAEP and RISC
/// vocabularies are the next issue's, so the only callers today are tests and the fan-out that
/// lands with those vocabularies; this is the shape it will call.
///
/// # The two keys carry the two guarantees
///
/// `ordering_key` is the STREAM, so the outbox keeps one receiver's events in order and never
/// two of them in flight at once, while a second receiver is a second group that a first one's
/// outage cannot block.
///
/// `idempotency_key` is the stream and the `jti` together. The `jti` alone would collide across
/// streams for one event fanned out to several receivers -- which is the ordinary case -- and
/// the stream alone would collapse every event for a receiver into one message. Together they
/// make a redelivery of one event to one receiver a no-op, which is what
/// [`OutboxRepo::enqueue_once`] answers `false` for.
///
/// # Errors
///
/// Whatever the outbox enqueue returns.
pub async fn enqueue_push(
    store: &Store,
    env: &Env,
    scope: Scope,
    queued: &QueuedPush<'_>,
) -> Result<bool, StoreError> {
    let ordering = queued.stream_id.to_string();
    let idempotency = format!("{}:{}", queued.stream_id, queued.jti);
    store
        .scoped(scope)
        .outbox()
        .enqueue_once(
            env,
            &ironauth_store::NewOutboxMessage {
                consumer: SSF_PUSH_CONSUMER,
                idempotency_key: &idempotency,
                ordering_key: &ordering,
                payload: serde_json::json!({
                    PAYLOAD_STREAM_ID: ordering,
                    PAYLOAD_JTI: queued.jti,
                    PAYLOAD_SUB_ID: queued.subject.render(),
                    PAYLOAD_EVENT_TYPE: queued.event.event_type,
                    PAYLOAD_EVENT: serde_json::Value::Object(queued.event.payload.clone()),
                }),
            },
        )
        .await
}

/// One SET to queue for one stream.
#[derive(Debug, Clone)]
pub struct QueuedPush<'a> {
    /// The stream to deliver to. Also the ordering group.
    pub stream_id: &'a SsfStreamId,
    /// The SET's dedup handle, minted ONCE here so every retry re-POSTs the same token.
    pub jti: &'a str,
    /// Who the event is about, in the format this stream negotiated.
    pub subject: &'a SubjectIdentifier,
    /// What happened.
    pub event: &'a SecurityEvent,
}

/// What one push attempt produced.
///
/// It reports what the RECEIVER said rather than merely whether the call worked, because the
/// status is what separates "reject this SET" from "come back later" and the consumer cannot
/// make that call without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushOutcome {
    /// The HTTP status the receiver returned, if it returned one.
    pub status: Option<u16>,
    /// `None` when the receiver accepted it; otherwise why not.
    pub failure: Option<SendFailure>,
}

impl PushOutcome {
    /// A 2xx.
    #[must_use]
    pub fn accepted(status: u16) -> Self {
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

/// The outbound seam a SET is pushed through.
///
/// The production implementor wraps the SSRF-hardened [`ironauth_fetch::Fetcher`]; a test
/// implementor records what it was handed and returns programmable outcomes without a socket.
/// ONE sender rather than two, so there is exactly one place that can POST a SET.
pub trait SsfPushSender: Send + Sync {
    /// POST `set` to `url` as `application/secevent+jwt`.
    ///
    /// `bearer` is the plaintext credential the receiver asked to be presented, already
    /// resolved, or `None` when the receiver relies on the SET's signature alone -- which
    /// RFC 8935 permits and which is the honest default: the signature IS the authentication
    /// and a bearer is at most a second gate.
    fn push(
        &self,
        url: &str,
        bearer: Option<&str>,
        set: &str,
    ) -> impl Future<Output = PushOutcome> + Send;
}

/// The production sender: the one sanctioned outbound path.
pub struct FetchSsfPushSender {
    fetcher: Arc<ironauth_fetch::Fetcher>,
}

impl FetchSsfPushSender {
    /// Wrap a shared hardened fetcher.
    #[must_use]
    pub fn new(fetcher: Arc<ironauth_fetch::Fetcher>) -> Self {
        Self { fetcher }
    }

    /// Build a production sender whose per-push time budget is `total_timeout`, so a slow
    /// receiver cannot wedge the worker.
    ///
    /// Constructs the one sanctioned outbound fetcher internally, so the binary wiring this
    /// never itself reaches an HTTP client -- which is what `scripts/http-audit.sh` enforces.
    ///
    /// # Errors
    ///
    /// [`ironauth_fetch::TlsSetupError`] when the platform trust store cannot be loaded.
    pub fn with_timeout(
        total_timeout: std::time::Duration,
    ) -> Result<Self, ironauth_fetch::TlsSetupError> {
        let limits = ironauth_fetch::FetchLimits {
            total_timeout,
            ..ironauth_fetch::FetchLimits::default()
        };
        Ok(Self::new(Arc::new(ironauth_fetch::Fetcher::new(limits)?)))
    }
}

impl SsfPushSender for FetchSsfPushSender {
    async fn push(&self, url: &str, bearer: Option<&str>, set: &str) -> PushOutcome {
        use ironauth_fetch::{FetchError, FetchPurpose, FetchRequest};

        let mut request = FetchRequest::new(FetchPurpose::SsfPush, http::Method::POST, url)
            .header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/secevent+jwt"),
            )
            .body(set.to_owned());
        if let Some(bearer) = bearer {
            // A CREDENTIAL THE RECEIVER CHOSE, refused here if it cannot be a header value
            // rather than sent mangled: a receiver that gets a truncated bearer sees an
            // authentication failure it cannot explain.
            let Ok(value) = http::HeaderValue::from_str(&format!("Bearer {bearer}")) else {
                return PushOutcome::failed(None, SendFailure::Transport);
            };
            request = request.header(http::header::AUTHORIZATION, value);
        }
        match self.fetcher.fetch(request).await {
            Ok(response) => {
                let status = response.status().as_u16();
                if response.status().is_success() {
                    PushOutcome::accepted(status)
                } else {
                    PushOutcome::failed(Some(status), SendFailure::Status(status))
                }
            }
            Err(FetchError::Blocked) => PushOutcome::failed(None, SendFailure::Blocked),
            Err(FetchError::Timeout) => PushOutcome::failed(None, SendFailure::Timeout),
            Err(_) => PushOutcome::failed(None, SendFailure::Transport),
        }
    }
}

/// The outbox consumer that pushes one queued SET.
pub struct SsfPushConsumer<S> {
    store: Store,
    issuers: Arc<IssuerRegistry>,
    /// Opens the receiver's bearer, when it asked for one. The stream row holds a NAME; the
    /// value is opened per attempt and lives only as long as the POST.
    master: Arc<MasterKey>,
    sender: S,
}

impl<S: SsfPushSender> SsfPushConsumer<S> {
    /// Build the consumer over a store, the per-environment issuer registry that signs SETs,
    /// and one outbound seam.
    #[must_use]
    pub fn new(
        store: Store,
        issuers: Arc<IssuerRegistry>,
        master: Arc<MasterKey>,
        sender: S,
    ) -> Self {
        Self {
            store,
            issuers,
            master,
            sender,
        }
    }

    /// Deliver ONE queued SET.
    async fn deliver_one(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let stream_text = payload_str(message, PAYLOAD_STREAM_ID)?;
        let jti = payload_str(message, PAYLOAD_JTI)?;
        let event_type = payload_str(message, PAYLOAD_EVENT_TYPE)?;
        let subject = message
            .payload
            .get(PAYLOAD_SUB_ID)
            .and_then(SubjectIdentifier::from_rendered)
            .ok_or_else(|| ConsumerError::permanent("payload_subject_unreadable"))?;
        let event_body = message
            .payload
            .get(PAYLOAD_EVENT)
            .and_then(serde_json::Value::as_object)
            .cloned()
            .unwrap_or_default();

        let id = SsfStreamId::parse_in_scope(&stream_text, &scope)
            .map_err(|_| ConsumerError::permanent("stream_id_malformed"))?;

        // RE-READ, not carried. See the module header: a receiver that re-points its endpoint
        // during an outage is delivered to at the new address.
        let stream = match self
            .store
            .scoped(scope)
            .ssf_streams()
            .for_delivery(&id)
            .await
        {
            Ok(stream) => stream,
            // THE RECEIVER DELETED IT. Nothing to deliver to and nothing a retry recovers, so
            // this is permanent rather than a message that retries until it dead-letters on a
            // schedule that means something else.
            Err(StoreError::NotFound) => return Err(ConsumerError::permanent("stream_deleted")),
            Err(_) => return Err(ConsumerError::retryable("stream_read_failed")),
        };

        // A PAUSED STREAM IS NOT A FAILURE, it is a receiver asking to be left alone. Retrying
        // is exactly right: the schedule holds the event until the receiver resumes, which is
        // what `paused` means as against `disabled`.
        if !stream.status.delivers() {
            if stream.status.retains() {
                return Err(ConsumerError::retryable("stream_paused"));
            }
            return Err(ConsumerError::permanent("stream_disabled"));
        }

        let SsfDelivery::Push {
            endpoint_url,
            secret_name,
        } = &stream.delivery
        else {
            // A POLL STREAM IS NOT PUSHED TO. Its receiver collects; a message queued here for
            // one is a producer bug, and delivering it anywhere would be worse than refusing.
            return Err(ConsumerError::permanent("stream_is_not_push"));
        };

        let set = mint_set(
            &self.issuers,
            env,
            scope,
            &SetToMint {
                audience: &stream.audience,
                jti: &jti,
                subject: &subject,
                event: &SecurityEvent {
                    event_type,
                    payload: event_body,
                },
            },
        )
        .await
        .map_err(|error| match error {
            // NO KEY YET is a wait, not a rejection: an environment whose signing key has not
            // loaded will have one.
            MintError::NoSigningKey => ConsumerError::retryable("no_signing_key"),
            MintError::Signing => ConsumerError::permanent("set_could_not_be_signed"),
        })?;

        let bearer = match secret_name {
            None => None,
            Some(name) => Some(self.resolve_secret(scope, name).await?),
        };

        let outcome = self
            .sender
            .push(endpoint_url, bearer.as_deref(), &set)
            .await;
        match outcome.failure {
            None => Ok(()),
            // A 4xx IS THE RECEIVER REJECTING THIS SET, which a retry cannot fix -- except 429,
            // which asks for less rather than saying no. Everything else is the receiver being
            // down, which is what the schedule is for.
            Some(SendFailure::Status(status)) if (400..500).contains(&status) && status != 429 => {
                Err(ConsumerError::permanent(
                    SendFailure::Status(status).label(),
                ))
            }
            Some(failure) => Err(ConsumerError::retryable(failure.label())),
        }
    }

    /// Open the environment secret the receiver asked to be presented.
    async fn resolve_secret(&self, scope: Scope, name: &str) -> Result<String, ConsumerError> {
        // THE FENCE AT THE READ, and this is the one that matters. The create door refuses a
        // name outside `ssf::PUSH_SECRET_PREFIX`, but a row written before that rule existed,
        // or restored by a config import, never passed the door -- and this is the code that
        // would open the secret and POST it to an address the receiver chose. PERMANENT rather
        // than retryable: no amount of waiting makes a name legal.
        if !name.starts_with(crate::ssf::PUSH_SECRET_PREFIX) {
            return Err(ConsumerError::permanent("push_secret_outside_namespace"));
        }
        let sealed = self
            .store
            .scoped(scope)
            .environment_secrets()
            .open_value(&self.master, name)
            .await
            // A NAMED SECRET THAT IS NOT THERE is retryable rather than permanent: an operator
            // who has not created it yet, or has rotated it, is a state that resolves. Dropping
            // the event would be silently ceasing to deliver a customer's security signals.
            .map_err(|_| ConsumerError::retryable("push_secret_unavailable"))?;
        String::from_utf8(sealed).map_err(|_| ConsumerError::permanent("push_secret_is_not_text"))
    }
}

impl<S: SsfPushSender> OutboxConsumer for SsfPushConsumer<S> {
    fn name(&self) -> &str {
        SSF_PUSH_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(self.deliver_one(env, scope, message))
    }
}

/// One required string off the message payload.
fn payload_str(message: &OutboxMessage, key: &str) -> Result<String, ConsumerError> {
    message
        .payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ConsumerError::permanent(format!("payload_missing_{key}")))
}
