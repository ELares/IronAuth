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
//! It has to be retaining (enabled or paused), and its `events_delivered` has to name the
//! CAEP type. That second check is not a formality: `events_delivered` is the intersection
//! this transmitter computed at stream creation between what the receiver asked for and
//! what this build emits, so a receiver that never asked for session revocation does not
//! get it, and a stream created before this producer existed does not silently begin
//! receiving a new event type.

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

const MALFORMED_PAYLOAD_LABEL: &str = "malformed_payload";
const STORE_ERROR_LABEL: &str = "store_error";
const MINT_LABEL: &str = "set_mint_failed";

/// How many streams one ended session can fan out to.
///
/// A bound rather than an unpaginated read because the handler holds the result in memory
/// and writes one row per entry. It is deliberately far above
/// `ssf.max_streams_per_client`, which is the per-client bound an operator tunes: this one
/// is the structural ceiling on an environment, and a deployment that reaches it has more
/// receivers than this fan-out was designed for and should be told rather than quietly
/// served in part.
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

/// The fan-out consumer: one ended session becomes one SET per interested stream.
pub struct SsfSessionFanOutConsumer {
    store: Store,
    issuers: Arc<IssuerRegistry>,
    owed_ceiling: u32,
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
            store,
            issuers,
            owed_ceiling,
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

        let event = caep::session_end_event(cause, occurred);
        let issuer = self.issuers.issuer_for(&scope);

        let streams = self
            .store
            .scoped(scope)
            .ssf_streams()
            .retaining_in_scope(MAX_STREAMS_PER_EVENT)
            .await
            .map_err(|_| ConsumerError::retryable(STORE_ERROR_LABEL))?;

        for stream in &streams {
            if !stream
                .events_delivered
                .iter()
                .any(|delivered| delivered == caep::SESSION_REVOKED)
            {
                continue;
            }
            let Some(rendered) = render_subject(stream.subject_format, &issuer, subject) else {
                tracing::warn!(
                    stream = %stream.id,
                    format = stream.subject_format.as_str(),
                    "session revocation not delivered: this producer cannot render the \
                     stream's negotiated subject format"
                );
                continue;
            };
            let jti = stream_jti(trigger_jti, &stream.id);
            self.deliver(env, scope, stream, &jti, &rendered, &event)
                .await?;
        }
        Ok(())
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
            SsfDelivery::Push { .. } => crate::ssf_push::enqueue_push(
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
            .map(|_| ())
            .map_err(|error| match error {
                crate::ssf_push::PushEnqueueError::Mint(_) => StoreError::Encryption,
                crate::ssf_push::PushEnqueueError::Store(error) => error,
            }),
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
            // An unsignable environment reaches here as `Encryption` from the push arm,
            // and it is the one case that is worth retrying for every stream at once.
            Err(StoreError::Encryption) => Err(ConsumerError::retryable(MINT_LABEL)),
            Err(_) => Err(ConsumerError::retryable(STORE_ERROR_LABEL)),
        }
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
