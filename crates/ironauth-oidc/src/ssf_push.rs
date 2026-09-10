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
//! The TOKEN is not byte-identical across attempts, and the claim is not that it is: `iat` is
//! stamped at each mint, so the JWS differs. What is stable is the `jti`, which is the handle a
//! receiver dedups on, and that is the whole of what at-least-once requires.
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
//! RFC 8935 section 2.2 is normative here: a receiver that accepts a SET SHALL respond with
//! `202 Accepted` and an empty body. This transmitter nonetheless treats any 2xx as accepted,
//! which is a DEVIATION and is named as one rather than dressed up as latitude the spec gives:
//! receivers in the field answer `200`, and failing those would retry a SET the receiver
//! already holds until it dead-lettered.
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
/// The payload key carrying the SIGNED token, minted once at enqueue.
///
/// THE TOKEN AND NOT THE INGREDIENTS, which is a change from the first version and the point
/// of issue #1200. The consumer used to mint on every attempt, so a retry re-sent a DIFFERENT
/// token under the same `jti`: a fresh `iat`, and a fresh signature for any algorithm that is
/// not deterministic. 0217 argues the opposite for poll delivery in as many words -- "a
/// receiver comparing two deliveries of one event must see the same token: re-minting would
/// restamp `iat` and change the JWS while the `jti` stayed put, which is a difference a
/// receiver cannot explain" -- and there was no reason for push to disagree.
pub const PAYLOAD_SET: &str = "set";

/// Queue one SET for one push stream.
///
/// The producer's entry point. Its first production caller is the SSF 1.0 verification
/// endpoint, which needs no event vocabulary; the general fan-out lands with the CAEP and RISC
/// vocabularies in the next issue, and this is the shape it will call too.
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
/// # The token is minted HERE, once
///
/// Every retry then re-POSTs the same bytes, which is what a receiver deduplicating by `jti`
/// and comparing what it was sent requires. It also means a key rotation between the first
/// attempt and a later one cannot re-sign a SET the receiver already half-processed: the
/// retired key stays in the published JWKS for its retention window, so the original token
/// keeps verifying.
///
/// WHAT THIS DOES NOT CHANGE is where the SET goes. The consumer still RE-READS the stream on
/// every attempt, so a receiver that re-points its endpoint during an outage is delivered to
/// at the new address; only the token itself is fixed.
///
/// # Errors
///
/// [`PushEnqueueError::Mint`] if the environment cannot sign, and
/// [`PushEnqueueError::Store`] for whatever the outbox enqueue returns.
pub async fn enqueue_push(
    store: &Store,
    issuers: &IssuerRegistry,
    env: &Env,
    scope: Scope,
    queued: &QueuedPush<'_>,
) -> Result<bool, PushEnqueueError> {
    let ordering = queued.stream_id.to_string();
    let idempotency = format!("{}:{}", queued.stream_id, queued.jti);
    // THE AUDIENCE COMES FROM THE STREAM, read by the caller. It is transmitter-supplied and no
    // update can change it, so freezing it here cannot go stale.
    let set = mint_set(
        issuers,
        env,
        scope,
        &SetToMint {
            audience: queued.audience,
            jti: queued.jti,
            subject: queued.subject,
            event: queued.event,
        },
    )
    .await
    .map_err(PushEnqueueError::Mint)?;
    store
        .scoped(scope)
        .outbox()
        .enqueue_once(
            env,
            &ironauth_store::NewOutboxMessage {
                consumer: SSF_PUSH_CONSUMER,
                idempotency_key: &idempotency,
                ordering_key: &ordering,
                // THE SUBJECT IS NO LONGER A SEPARATE MEMBER, which is a small improvement and
                // not a fix: `outbox_messages.payload` is plaintext jsonb, and the subject is
                // still readable inside the token's base64url payload. What changes is that
                // there is now ONE copy of it here rather than two.
                payload: serde_json::json!({
                    PAYLOAD_STREAM_ID: ordering,
                    PAYLOAD_JTI: queued.jti,
                    PAYLOAD_SET: set,
                }),
            },
        )
        .await
        .map_err(PushEnqueueError::Store)
}

/// Why a SET could not be queued for push delivery.
#[derive(Debug)]
pub enum PushEnqueueError {
    /// The environment could not sign it.
    Mint(MintError),
    /// The outbox refused the write.
    Store(StoreError),
}

impl std::fmt::Display for PushEnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mint(_) => f.write_str("the security event token could not be signed"),
            Self::Store(_) => f.write_str("the delivery queue refused the write"),
        }
    }
}

impl std::error::Error for PushEnqueueError {}

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
    /// The `aud` its SET is minted for, from the stream.
    ///
    /// PASSED IN RATHER THAN READ HERE, because the caller has already resolved the stream to
    /// decide it is a push stream at all, and a second read could see a different row.
    pub audience: &'a [String],
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
    /// resolved, or `None` when the receiver asked for none.
    ///
    /// The two authenticate DIFFERENT things, and an earlier version of this comment conflated
    /// them. The SET's SIGNATURE authenticates the ISSUER of the event: it proves this
    /// environment minted it, and a receiver checks it against the published JWKS. The BEARER
    /// authenticates the TRANSMITTER to the receiver's endpoint, which is the separate question
    /// of who may POST there at all. RFC 8935 leaves the second to the receiver; omitting it is
    /// a choice the receiver makes, not a claim that the signature covers it.
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
///
/// NO ISSUER REGISTRY, since issue #1200. It held one while it minted the token on every
/// attempt; the token is minted once at enqueue now, so a registry here would be a capability
/// nothing exercises. Dropping it also makes the shape of the fix visible in the type: a
/// consumer that cannot sign cannot re-sign.
pub struct SsfPushConsumer<S> {
    store: Store,
    /// Opens the receiver's bearer, when it asked for one. The stream row holds a NAME; the
    /// value is opened per attempt and lives only as long as the POST.
    master: Arc<MasterKey>,
    sender: S,
}

impl<S: SsfPushSender> SsfPushConsumer<S> {
    /// Build the consumer over a store, the master key that opens a receiver's bearer, and one
    /// outbound seam.
    #[must_use]
    pub fn new(store: Store, master: Arc<MasterKey>, sender: S) -> Self {
        Self {
            store,
            master,
            sender,
        }
    }

    /// Deliver ONE queued SET.
    async fn deliver_one(
        &self,
        // UNUSED SINCE THE TOKEN STOPPED BEING MINTED HERE (issue #1200), and kept because the
        // `OutboxConsumer` seam hands one to every consumer and a signature that drops it
        // would be the odd one out.
        _env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let stream_text = payload_str(message, PAYLOAD_STREAM_ID)?;
        let jti = payload_str(message, PAYLOAD_JTI)?;
        // THE TOKEN AS IT WAS MINTED, not ingredients to re-mint one. Every attempt POSTs
        // these same bytes; see `PAYLOAD_SET`.
        let set = payload_str(message, PAYLOAD_SET)?;
        let _ = &jti;

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

        // A PAUSED STREAM IS NOT A FAILURE, it is a receiver asking to be left alone, so this
        // retries rather than discarding.
        //
        // AND THE HOLD IS BOUNDED, which is worth stating because `paused` is documented as the
        // state that RETAINS. A retryable failure spends one of a finite attempts budget: at
        // the shipped defaults (`outbox.max_attempts = 14`, `retry_base_secs = 30`, capped by
        // `OUTBOX_MAX_BACKOFF_SECS`) the thirteen backoffs span about 37 hours, after which the
        // message dead-letters. Because the ordering key is the stream, only the HEAD of a
        // paused stream's queue spends attempts, so a pause of length D silently loses roughly
        // D/37h of its OLDEST events and delivers the rest on resume.
        //
        // That is a real gap and it is NOT closed here: durable retention across a long pause
        // belongs with the store that RFC 8936 poll delivery needs anyway, and inventing a
        // second one in the push consumer would be the wrong place for it. Tracked separately;
        // this comment exists so the bound is known rather than discovered.
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

        let bearer = match secret_name {
            None => None,
            Some(name) => Some(self.resolve_secret(scope, &stream.client_id, name).await?),
        };

        let outcome = self
            .sender
            .push(endpoint_url, bearer.as_deref(), &set)
            .await;
        match outcome.failure {
            None => Ok(()),
            Some(SendFailure::Status(status)) if permanent_status(status) => Err(
                ConsumerError::permanent(SendFailure::Status(status).label()),
            ),
            Some(failure) => Err(ConsumerError::retryable(failure.label())),
        }
    }

    /// Open the environment secret the receiver asked to be presented.
    async fn resolve_secret(
        &self,
        scope: Scope,
        owner: &ironauth_store::ClientId,
        name: &str,
    ) -> Result<String, ConsumerError> {
        // THE FENCE AT THE READ, and this is the one that matters. The create door refuses a
        // name outside the receiver's own namespace, but a row written before that rule existed,
        // or restored by a config import, never passed the door -- and this is the code that
        // would open the secret and POST it to an address the receiver chose.
        //
        // IT COMPARES AGAINST THE STREAM'S OWN OWNER, not against a subsystem-wide prefix: a
        // namespace every receiver shares stops none of them naming another's bearer. PERMANENT
        // rather than retryable, because no amount of waiting makes a name legal.
        if !name.starts_with(&crate::ssf::push_secret_prefix(owner)) {
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

/// Whether a receiver's status means "this SET is wrong" rather than "come back later".
///
/// See the module header: RFC 8935 section 2.3 has a receiver answer `400` for an AUTHENTICATION
/// failure and section 4 names that class transient, so treating every 4xx as final would
/// discard a receiver's events over a rotated bearer.
///
/// `401` and `403` are the same fact under a different code, and `429` asks for less rather than
/// saying no. A bare `400` is permanent HERE because [`PushOutcome`] carries only the status and
/// not the receiver's `err` body -- a deliberate bound, stated rather than hidden: the transient
/// `400` is the case this gets wrong, and reading that body is what would fix it.
fn permanent_status(status: u16) -> bool {
    !matches!(status, 401 | 403 | 429) && (400..500).contains(&status)
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
