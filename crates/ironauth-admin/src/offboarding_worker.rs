//! The worker that EXECUTES scheduled offboardings (issue #52).
//!
//! `ActingUserRepo::execute_scheduled_offboardings` has been in the tree since #52 and
//! nothing ever called it. The management API meanwhile accepts a user state change to
//! `scheduled_offboarding` with an instant, so an operator could schedule a deletion, get
//! a 200, and have it silently never happen. That is worse than a missing feature: it is a
//! promise the API makes and does not keep, and the kind an operator only discovers by
//! auditing what should already be gone.
//!
//! ## Why a delayed message rather than a periodic sweep
//!
//! Executing an offboarding writes an audit row, and a background sweep has no actor to
//! attribute it to. Scheduling one, by contrast, is a request an operator made, so the
//! wake-up is enqueued in the SAME transaction as the state change and carries that
//! operator with it. The execution is then attributable to the person who asked for it,
//! which is what the audit log exists for, and no synthetic system actor has to be
//! invented for the whole tree to accommodate one worker.
//!
//! It also costs nothing when nothing is scheduled. A periodic sweep queries every scope on
//! a timer forever; a delayed message exists only when there is something to do.

use std::future::Future;
use std::pin::Pin;

use ironauth_env::Env;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    ActorRef, AgentId, CorrelationId, HumanId, OFFBOARDING_CONSUMER, OutboxMessage, Scope,
    ServiceId, Store,
};

/// The payload key carrying the actor whose request this offboarding is.
const PAYLOAD_ACTOR_KIND: &str = "actor_kind";
/// The payload key carrying that actor's id.
const PAYLOAD_ACTOR_ID: &str = "actor_id";
/// The payload key naming the subject the wake-up was scheduled for.
const PAYLOAD_SUBJECT: &str = "subject";

/// Build the payload a scheduled-offboarding wake-up carries.
///
/// Shared with the producer so the two cannot disagree about key names: a producer writing
/// one spelling where the consumer reads another fails on every message and presents as a
/// queue that simply never delivers.
#[must_use]
pub fn wake_payload(subject: &str, actor: &ActorRef) -> serde_json::Value {
    serde_json::json!({
        PAYLOAD_SUBJECT: subject,
        PAYLOAD_ACTOR_KIND: actor.kind_str(),
        PAYLOAD_ACTOR_ID: actor.id_string(),
    })
}

/// The consumer that executes offboardings which have come due.
pub struct OffboardingConsumer {
    store: Store,
}

impl OffboardingConsumer {
    /// Build the consumer over a DATA-plane store.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Read a required string off the message payload.
    fn payload_str<'m>(message: &'m OutboxMessage, key: &str) -> Result<&'m str, ConsumerError> {
        message
            .payload
            .get(key)
            .and_then(serde_json::Value::as_str)
            // Permanent: no retry adds a field to a row that is already written.
            .ok_or_else(|| ConsumerError::permanent(format!("payload_missing_{key}")))
    }

    /// Reconstruct the operator whose request this execution continues.
    fn actor_of(message: &OutboxMessage) -> Result<ActorRef, ConsumerError> {
        let kind = Self::payload_str(message, PAYLOAD_ACTOR_KIND)?;
        let id = Self::payload_str(message, PAYLOAD_ACTOR_ID)?;
        let malformed = || ConsumerError::permanent("payload_actor_malformed");
        match kind {
            "human" => HumanId::parse(id)
                .map(ActorRef::human)
                .map_err(|_| malformed()),
            "service" => ServiceId::parse(id)
                .map(ActorRef::service)
                .map_err(|_| malformed()),
            "agent" => AgentId::parse(id)
                .map(ActorRef::agent)
                .map_err(|_| malformed()),
            _ => Err(malformed()),
        }
    }

    /// Execute whatever is due in this scope.
    async fn execute_due(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let subject = Self::payload_str(message, PAYLOAD_SUBJECT)?.to_owned();
        let actor = Self::actor_of(message)?;

        // The scope-wide executor rather than a per-user call, because it is what exists
        // and it is idempotent: it acts only on users still in the scheduled state whose
        // instant has arrived. So a wake-up whose own subject was rescheduled or cancelled
        // finds nothing for it and completes, and a wake-up that arrives late sweeps up any
        // sibling that a lost message would otherwise have stranded.
        let executed = self
            .store
            .scoped(scope)
            .acting(actor, CorrelationId::generate(env))
            .users()
            .execute_scheduled_offboardings(env, unix_micros(env.clock().now_utc()))
            .await
            // Retryable: a database that was briefly unreachable succeeds on the next
            // attempt, and the substrate's finite budget is what turns a persistent
            // failure into a dead letter rather than an infinite loop.
            .map_err(|_| ConsumerError::retryable("offboarding_execute_failed"))?;

        tracing::info!(
            %subject,
            executed,
            "scheduled offboardings executed for a due wake-up"
        );
        Ok(())
    }
}

impl OutboxConsumer for OffboardingConsumer {
    fn name(&self) -> &str {
        OFFBOARDING_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(async move { self.execute_due(env, scope, message).await })
    }
}

/// Microseconds since the Unix epoch for a wall-clock instant (saturating).
fn unix_micros(at: std::time::SystemTime) -> i64 {
    match at.duration_since(std::time::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}
