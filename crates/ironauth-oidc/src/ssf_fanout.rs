//! The session end to Shared Signals fan-out (issue #144).
//!
//! ONE ENDED SESSION IN, ONE SET PER INTERESTED STREAM OUT. This is the first general
//! producer the Shared Signals subsystem has: until it landed, the only SET this build
//! could emit was the verification event a receiver asked for about itself, so every queue
//! under it was exercised only by a receiver testing its own plumbing.
//!
//! # Why this is its own consumer
//!
//! [`SESSION_ENDED_CONSUMER`] already has a handler: the back-channel logout fan-out. The
//! obvious move is to do this work there, and it is the wrong one. A minting failure --
//! an environment with no usable signing key is the realistic one -- would fail that
//! handler, and its retries and its dead letter are shared with every relying party's
//! logout. Shared Signals being broken would then stop back-channel logout, which is a
//! different subsystem with a different operator and no stake in the outcome.
//!
//! So the back-channel fan-out writes ONE trigger message for this consumer, in the same
//! atomic slice as its own output, and the two subsystems fail apart from each other.
//!
//! # Delivery is at-least-once and the `jti` is what makes that safe
//!
//! A handler that queues some streams and loses its lease is re-run from the top, so it
//! MUST tolerate finding its own earlier output. Each stream's `jti` is derived from the
//! trigger's own `jti` and the stream id, so a re-run offers the same handle for the same
//! (event, stream) pair: the poll queue's primary key and the outbox's idempotency key
//! both skip it. Minting a fresh `jti` per attempt instead would deliver the same event
//! two and three times over, and a receiver deduplicating on `jti` -- which is the only
//! thing RFC 8417 gives it to deduplicate on -- could not tell that they were one event.
//!
//! # It takes the SHARED attempts cap, unlike the back-channel fan-out beside it
//!
//! `session_ended` is exempted from the configured `max_attempts` and retries effectively
//! forever, because losing one of its messages loses logout for every relying party at
//! once. This consumer has the same all-or-nothing shape and deliberately does NOT take
//! that exemption. The difference is the failure mode: the back-channel fan-out can only
//! fail on a store read, which is transient, while this one also MINTS, and an
//! environment with no usable signing key fails every attempt identically forever. Under
//! the exemption that becomes an hourly retry that never terminates and never reports,
//! so Shared Signals would stop delivering and nothing would say so. The finite cap turns
//! that into a dead letter, which is an alert an operator sees.
//!
//! # What a stream has to do to be sent one
//!
//! Three things, and all three are checked:
//!
//! - it has to be RETAINING, which is enabled or paused;
//! - its `events_delivered` has to name the CAEP type. That is not a formality:
//!   `events_delivered` is the intersection this transmitter computed at stream creation
//!   between what the receiver asked for and what this build emits, so a receiver that
//!   never asked for session revocation does not get it, and a stream created before this
//!   producer existed does not silently begin receiving a new event type;
//! - its SUBJECT FILTER has to admit the subject, where it declared one. The add-subject
//!   and remove-subject endpoints shipped with the transmitter and this producer is the
//!   first place their list can take effect. An empty list means no filter and admits
//!   everything, which is why the count is asked before the membership. See
//!   [`Self::stream_wants`](SsfSessionFanOutConsumer::stream_wants).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ironauth_env::Env;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    OutboxMessage, SSF_SESSION_FANOUT_CONSUMER, Scope, SessionEndCause, SsfDelivery, SsfStream,
    SsfStreamId, SsfSubjectFormat, Store, StoreError,
};

use crate::caep;
use crate::issuer::IssuerRegistry;
use crate::ssf_set::{SetToMint, SubjectIdentifier};

/// The ended session, carried so an operator reading a dead letter can find it.
pub const PAYLOAD_SESSION_ID: &str = "session_id";
/// The user the ended session belonged to.
pub const PAYLOAD_SUBJECT: &str = "subject";
/// The internal end cause, as [`SessionEndCause::as_str`] spells it.
pub const PAYLOAD_CAUSE: &str = "cause";
/// When the session ended, in microseconds.
pub const PAYLOAD_OCCURRED_AT: &str = "occurred_at_unix_micros";
/// The base every per-stream `jti` is derived from.
pub const PAYLOAD_JTI: &str = "jti";
/// How the session-ended record spells the principal that ended it: `human`, `service`,
/// or `agent`. It is what decides CAEP's `initiating_entity`, and where it cannot decide,
/// the member is omitted rather than guessed. See [`crate::caep::initiating_entity`].
pub const PAYLOAD_ACTOR_KIND: &str = "actor_kind";

const MALFORMED_PAYLOAD_LABEL: &str = "malformed_payload";
const STORE_ERROR_LABEL: &str = "store_error";
const MINT_LABEL: &str = "set_mint_failed";
/// The environment has no active envelope key, so a poll SET cannot be SEALED at rest.
/// Distinct from [`MINT_LABEL`], which is about signing: an operator chasing one would
/// look in the wrong place for the other.
const NO_ENVELOPE_KEY_LABEL: &str = "no_envelope_key";

/// How many streams one ended session can fan out to.
///
/// A bound rather than an unpaginated read because the handler holds the result in memory
/// and writes one row per entry. It is deliberately far above
/// `ssf.max_streams_per_client`, which is the per-client bound an operator tunes: this one
/// is the structural ceiling on an environment.
///
/// REACHING IT IS REPORTED, not silent. An environment with more retaining streams than
/// this would otherwise be served in part, and a Shared Signals receiver cannot tell a
/// revocation it was never sent from a quiet period. The handler logs when the read comes
/// back full, which is the only honest thing it can do without paginating.
const MAX_STREAMS_PER_EVENT: i64 = 512;

/// Derive the `jti` for one stream's copy of one event.
///
/// STABLE ACROSS RETRIES and unique per (event, stream), which is exactly the pair the two
/// idempotency mechanisms downstream key on. It is not secret and does not need to be: RFC
/// 8417 uses `jti` for deduplication, and a receiver learns the stream id from the token's
/// own delivery.
fn stream_jti(trigger_jti: &str, stream_id: &SsfStreamId) -> String {
    format!("{trigger_jti}-{stream_id}")
}

/// Render the subject in the format the stream negotiated (issue #143 criterion 5).
///
/// `None` for a format this producer cannot honestly fill. Today that is exactly
/// [`SsfSubjectFormat::Email`]: a session end names the user by id, and there is no read
/// here that turns a user id into an address the receiver would recognise. The caller
/// SKIPS such a stream rather than substituting another format, because a subject rendered
/// as `opaque` into a stream expecting `email` is not a degraded signal, it is a signal
/// about a different person as far as the receiver's matching logic is concerned.
fn render_subject(
    format: SsfSubjectFormat,
    issuer: &str,
    subject: &str,
) -> Option<SubjectIdentifier> {
    match format {
        SsfSubjectFormat::Opaque => Some(SubjectIdentifier::Opaque {
            id: subject.to_owned(),
        }),
        SsfSubjectFormat::IssSub => Some(SubjectIdentifier::IssSub {
            iss: issuer.to_owned(),
            sub: subject.to_owned(),
        }),
        SsfSubjectFormat::Email => None,
    }
}

/// Deliver ONE security event about ONE subject to every stream that should receive it.
///
/// Shared by every producer in this subsystem rather than reimplemented per event type.
/// The selection rules, the per-stream subject rendering, the subject filter and the
/// poll-versus-push routing are identical whatever happened; only the decision of WHAT
/// happened differs, and that is the producer's own. Two copies of this would be two
/// places for a receiver's filter to be forgotten.
pub(crate) struct StreamFanOut {
    store: Store,
    issuers: Arc<IssuerRegistry>,
    owed_ceiling: u32,
}

impl StreamFanOut {
    pub(crate) fn new(store: Store, issuers: Arc<IssuerRegistry>, owed_ceiling: u32) -> Self {
        Self {
            store,
            issuers,
            owed_ceiling,
        }
    }

    /// Every stream that is retaining, agreed to `event`'s type, and whose subject filter
    /// admits `subject`, gets one SET.
    ///
    /// `trigger_jti` is the handle the per-stream `jti` is derived from, so a re-run
    /// offers the same handle for the same (event, stream) pair.
    pub(crate) async fn deliver_to_streams(
        &self,
        env: &Env,
        scope: Scope,
        subject: &str,
        event: &crate::ssf_set::SecurityEvent,
        trigger_jti: &str,
    ) -> Result<(), ConsumerError> {
        let issuer = self.issuers.issuer_for(&scope);
        let streams = self
            .store
            .scoped(scope)
            .ssf_streams()
            .retaining_in_scope(MAX_STREAMS_PER_EVENT)
            .await
            .map_err(|_| ConsumerError::retryable(STORE_ERROR_LABEL))?;
        if i64::try_from(streams.len()).unwrap_or(i64::MAX) >= MAX_STREAMS_PER_EVENT {
            tracing::error!(
                bound = MAX_STREAMS_PER_EVENT,
                event_type = %event.event_type,
                "Shared Signals fan-out reached its stream bound: this environment has at \
                 least this many retaining streams and any beyond the bound were NOT sent \
                 this event"
            );
        }

        for stream in &streams {
            if !stream
                .events_delivered
                .iter()
                .any(|delivered| delivered == &event.event_type)
            {
                continue;
            }
            let Some(rendered) = render_subject(stream.subject_format, &issuer, subject) else {
                tracing::warn!(
                    stream = %stream.id,
                    format = stream.subject_format.as_str(),
                    event_type = %event.event_type,
                    "event not delivered: this producer cannot render the stream's \
                     negotiated subject format"
                );
                continue;
            };
            if !self.stream_wants(scope, &stream.id, &rendered).await? {
                continue;
            }
            let jti = stream_jti(trigger_jti, &stream.id);
            self.deliver(env, scope, stream, &jti, &rendered, event)
                .await?;
        }
        Ok(())
    }

    /// Whether this stream's SUBJECT FILTER admits `rendered` (issue #143).
    ///
    /// The add-subject and remove-subject endpoints let a receiver narrow a stream to the
    /// subjects it actually cares about, and this producer is the first and only place
    /// that narrowing can take effect. Without this read the filter is a list the surface
    /// writes and nothing consults, and a receiver that asked to hear about ONE user is
    /// sent every user in the environment.
    ///
    /// THE COUNT IS ASKED FIRST, and that ordering is not an optimisation. An empty list
    /// means the receiver expressed no filter and wants everything, so `contains` alone
    /// would answer `false` for every stream that never filtered and deliver nothing at
    /// all. The store documents both halves on
    /// [`SsfStreamSubjectRepo::count`](ironauth_store::SsfStreamSubjectRepo::count).
    ///
    /// The rendering compared is the same one the SET will carry, produced by the same
    /// [`SubjectIdentifier::render`], so a stream whose filter names a subject in its
    /// negotiated format matches by construction rather than by two spellings agreeing.
    async fn stream_wants(
        &self,
        scope: Scope,
        stream_id: &SsfStreamId,
        rendered: &SubjectIdentifier,
    ) -> Result<bool, ConsumerError> {
        let subjects = self.store.scoped(scope).ssf_stream_subjects();
        let filtered = subjects
            .count(stream_id)
            .await
            .map_err(|_| ConsumerError::retryable(STORE_ERROR_LABEL))?;
        if filtered == 0 {
            return Ok(true);
        }
        subjects
            .contains(stream_id, &rendered.render().to_string())
            .await
            .map_err(|_| ConsumerError::retryable(STORE_ERROR_LABEL))
    }

    /// Make one stream's copy durable by the method that stream negotiated.
    ///
    /// The same two-armed routing the verification endpoint performs, for the same reason:
    /// poll stores the signed token in `ssf_stream_sets` and push stores it on the outbox,
    /// and BOTH store the token rather than the ingredients, so a redelivery is
    /// byte-identical whichever method carries it (issue #1200).
    ///
    /// # A refusal about ONE stream must not fail the message
    ///
    /// The `Err` arm fails the whole trigger, and the trigger covers every stream. So only
    /// a condition that is genuinely about the ENVIRONMENT belongs there: an unsignable
    /// environment or a database that is not answering, both of which will be as true for
    /// the next stream as for this one and are worth retrying.
    ///
    /// A refusal the receiver earned is not that, and there are two:
    ///
    /// - `Conflict` means this stream has already been queued this `jti`. That is the
    ///   expected outcome of a re-run after a lapsed lease -- it is what at-least-once
    ///   delivery looks like from the inside -- and treating it as a failure would make
    ///   every re-run fail identically until the message dead-lettered, losing the event
    ///   for every OTHER stream too.
    /// - `QuotaExceeded` means this receiver has stopped collecting and is holding the
    ///   ceiling in unacknowledged SETs. Its backlog is its own doing and must not stop a
    ///   healthy receiver beside it from being told about the revocation.
    async fn deliver(
        &self,
        env: &Env,
        scope: Scope,
        stream: &SsfStream,
        jti: &str,
        subject: &SubjectIdentifier,
        event: &crate::ssf_set::SecurityEvent,
    ) -> Result<(), ConsumerError> {
        let outcome = match &stream.delivery {
            SsfDelivery::Poll => {
                let token = crate::ssf_set::mint_set(
                    &self.issuers,
                    env,
                    scope,
                    &SetToMint {
                        audience: &stream.audience,
                        jti,
                        subject,
                        event,
                    },
                )
                .await
                .map_err(|_| ConsumerError::retryable(MINT_LABEL))?;
                self.store
                    .scoped(scope)
                    .ssf_stream_sets()
                    .queue(env, &stream.id, jti, &token, self.owed_ceiling)
                    .await
            }
            SsfDelivery::Push { .. } => {
                // A MINT FAILURE KEEPS ITS OWN LABEL. Folding it into the store outcome
                // below would report an unsignable environment under whatever label the
                // store arm carries, and an operator reading a dead letter would go
                // looking at the database for a signing-key problem.
                match crate::ssf_push::enqueue_push(
                    &self.store,
                    &self.issuers,
                    env,
                    scope,
                    &crate::ssf_push::QueuedPush {
                        stream_id: &stream.id,
                        jti,
                        subject,
                        event,
                        audience: &stream.audience,
                    },
                )
                .await
                {
                    Ok(_) => Ok(()),
                    Err(crate::ssf_push::PushEnqueueError::Mint(_)) => {
                        return Err(ConsumerError::retryable(MINT_LABEL));
                    }
                    Err(crate::ssf_push::PushEnqueueError::Store(error)) => Err(error),
                }
            }
        };
        match outcome {
            Ok(())
            // ALREADY OWED. The re-run found its own earlier output, which is the whole
            // point of deriving the jti from the trigger's.
            | Err(StoreError::Conflict) => Ok(()),
            Err(StoreError::QuotaExceeded) => {
                tracing::warn!(
                    stream = %stream.id,
                    "session revocation not queued: this receiver is holding the ceiling                      in unacknowledged events"
                );
                Ok(())
            }
            // AN ENVIRONMENT WITH NO ENVELOPE KEY, which is what the poll arm answers when
            // it cannot seal. It is a configuration problem rather than a signing one and
            // says so, because the two send an operator to different places. A mint
            // failure never reaches here: both arms label it before this match.
            Err(StoreError::Encryption) => Err(ConsumerError::retryable(NO_ENVELOPE_KEY_LABEL)),
            Err(_) => Err(ConsumerError::retryable(STORE_ERROR_LABEL)),
        }
    }
}

/// The fan-out consumer: one ended session becomes one CAEP `session-revoked` per
/// interested stream.
///
/// It decides WHAT happened; [`StreamFanOut`] decides who hears about it.
pub struct SsfSessionFanOutConsumer {
    core: StreamFanOut,
}

impl SsfSessionFanOutConsumer {
    /// Build the fan-out over the data store, the shared issuer registry, and the
    /// per-stream owed-set ceiling.
    ///
    /// `owed_ceiling` is `ssf.max_owed_sets_per_stream`, threaded in rather than read
    /// here, so this consumer and the verification endpoint enforce the SAME number: two
    /// readers of one setting can disagree, two callers passing one value cannot.
    #[must_use]
    pub fn new(store: Store, issuers: Arc<IssuerRegistry>, owed_ceiling: u32) -> Self {
        Self {
            core: StreamFanOut::new(store, issuers, owed_ceiling),
        }
    }

    async fn fan_out(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let text = |key: &str| {
            message
                .payload
                .get(key)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| ConsumerError::permanent(MALFORMED_PAYLOAD_LABEL))
        };
        let subject = text(PAYLOAD_SUBJECT)?;
        let trigger_jti = text(PAYLOAD_JTI)?;
        // A cause this build cannot parse can never become parseable, so it is permanent:
        // retrying would burn the attempts budget to reach the same dead letter.
        let cause = SessionEndCause::from_wire(text(PAYLOAD_CAUSE)?)
            .ok_or_else(|| ConsumerError::permanent(MALFORMED_PAYLOAD_LABEL))?;
        let occurred = message
            .payload
            .get(PAYLOAD_OCCURRED_AT)
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| ConsumerError::permanent(MALFORMED_PAYLOAD_LABEL))?;

        // A message written before this key existed has no actor, and an empty kind reaches
        // `initiating_entity` as "not a service and not an agent", which yields `None`.
        // That is the same answer a human gets, and it is the right one: an unknown
        // principal is exactly what must not be reported as a known one.
        let actor_kind = message
            .payload
            .get(PAYLOAD_ACTOR_KIND)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let event = caep::session_end_event(cause, actor_kind, occurred);
        self.core
            .deliver_to_streams(env, scope, subject, &event, trigger_jti)
            .await
    }
}

impl OutboxConsumer for SsfSessionFanOutConsumer {
    fn name(&self) -> &str {
        SSF_SESSION_FANOUT_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(async move { self.fan_out(env, scope, message).await })
    }
}

/// The lifecycle fan-out consumer: one user lifecycle change becomes one RISC SET per
/// interested stream (issue #144 criterion 3).
///
/// A SIBLING OF [`SsfSessionFanOutConsumer`], not a branch inside it. The two drain
/// different queues so that a RISC event this build cannot mint does not hold up a
/// session revocation, which is the more urgent of the two signals: a receiver that
/// learns late that an account was disabled is behind, while one that learns late that a
/// session was revoked is still honouring a token it should have dropped.
///
/// They share [`StreamFanOut`], which is everything about WHO hears an event. Only the
/// decision of what happened differs.
pub struct SsfLifecycleFanOutConsumer {
    core: StreamFanOut,
}

impl SsfLifecycleFanOutConsumer {
    /// Build the lifecycle fan-out. See
    /// [`SsfSessionFanOutConsumer::new`] for what `owed_ceiling` is.
    #[must_use]
    pub fn new(store: Store, issuers: Arc<IssuerRegistry>, owed_ceiling: u32) -> Self {
        Self {
            core: StreamFanOut::new(store, issuers, owed_ceiling),
        }
    }

    async fn fan_out(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        // THE PAYLOAD IS THE DOMAIN EVENT ENVELOPE, forwarded verbatim by the producer
        // rather than re-shaped, so this reads the same members the webhook fan-out reads
        // from the same bytes.
        let envelope = &message.payload;
        let event_type = envelope
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ConsumerError::permanent(MALFORMED_PAYLOAD_LABEL))?;
        let payload = envelope
            .get("payload")
            .ok_or_else(|| ConsumerError::permanent(MALFORMED_PAYLOAD_LABEL))?;
        let occurred = envelope
            .get("occurred_at_unix_ms")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| ConsumerError::permanent(MALFORMED_PAYLOAD_LABEL))?;
        // The envelope's own id, minted once by the domain producer. Every per-stream
        // `jti` derives from it, so a re-run after a lapsed lease offers the same handle.
        let trigger_jti = envelope
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ConsumerError::permanent(MALFORMED_PAYLOAD_LABEL))?;
        let subject = crate::risc::subject_of(payload)
            .ok_or_else(|| ConsumerError::permanent(MALFORMED_PAYLOAD_LABEL))?;

        // NOTHING TO SAY IS A SUCCESS, not a failure. The producer's whitelist is coarser
        // than the mapping: `user.state_changed` is on it because SOME of its transitions
        // are RISC events, and the ones that are not must complete the message rather
        // than dead-letter it. Failing here would retry a transition that will never map
        // until the attempts budget ran out.
        let Some(event) = crate::risc::map_domain_event(event_type, payload, occurred) else {
            return Ok(());
        };
        self.core
            .deliver_to_streams(env, scope, subject, &event, trigger_jti)
            .await
    }
}

impl OutboxConsumer for SsfLifecycleFanOutConsumer {
    fn name(&self) -> &str {
        ironauth_store::SSF_LIFECYCLE_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(async move { self.fan_out(env, scope, message).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_per_stream_jti_is_stable_across_retries_and_distinct_per_stream() {
        // Both halves matter and they pull in opposite directions. Stability is what makes
        // a re-run idempotent; distinctness is what stops two streams' copies of one event
        // colliding on the outbox idempotency key, which would silently drop one of them.
        let env = Env::system();
        let scope = Scope::new(
            ironauth_store::TenantId::generate(&env),
            ironauth_store::EnvironmentId::generate(&env),
        );
        let first = SsfStreamId::generate(&env, &scope);
        let second = SsfStreamId::generate(&env, &scope);
        assert_eq!(stream_jti("base", &first), stream_jti("base", &first));
        assert_ne!(stream_jti("base", &first), stream_jti("base", &second));
        assert_ne!(stream_jti("other", &first), stream_jti("base", &first));
    }

    #[test]
    fn the_negotiated_format_is_the_one_rendered() {
        // The pairing that matters is format-in to format-out. Asserting only that SOME
        // identifier came back would pass a renderer that answered `opaque` to everything,
        // which is the exact substitution the doc on `render_subject` refuses.
        let opaque = render_subject(SsfSubjectFormat::Opaque, "https://issuer.example", "usr_1")
            .expect("opaque is renderable");
        assert_eq!(opaque.format(), SsfSubjectFormat::Opaque);
        assert_eq!(opaque, SubjectIdentifier::Opaque { id: "usr_1".into() });

        let iss_sub = render_subject(SsfSubjectFormat::IssSub, "https://issuer.example", "usr_1")
            .expect("iss_sub is renderable");
        assert_eq!(iss_sub.format(), SsfSubjectFormat::IssSub);
        assert_eq!(
            iss_sub,
            SubjectIdentifier::IssSub {
                iss: "https://issuer.example".into(),
                sub: "usr_1".into(),
            }
        );
    }

    #[test]
    fn an_email_stream_is_skipped_rather_than_rendered_as_something_else() {
        assert!(
            render_subject(SsfSubjectFormat::Email, "https://issuer.example", "usr_1").is_none(),
            "a user id is not an address, and substituting a format misidentifies the subject"
        );
    }
}
