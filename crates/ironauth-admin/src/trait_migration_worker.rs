//! The worker that ADVANCES trait migration jobs (issue #53).
//!
//! The store shipped `create`, `get` and a batched, resumable `advance` and nothing in the
//! tree ever called them: a complete layer with no consumer, which is the shape this
//! codebase keeps removing. This is the consumer.
//!
//! It rides the transactional outbox (#104), which named "migration jobs" as one of the
//! async paths it exists to carry. One message advances the job by ONE batch and enqueues
//! the next, rather than looping until the job finishes. That is what keeps every handler
//! inside the visibility lease no matter how many identities a job covers: a 100k-identity
//! migration is two hundred short messages, not one handler holding a lease for an hour.
//!
//! Progress is durable in the job row, so a worker that dies mid-job loses at most the
//! batch it was inside, and `advance` is idempotent on a terminal job.

use std::future::Future;
use std::pin::Pin;

use ironauth_env::Env;
use ironauth_store::outbox::{ConsumerError, OutboxConsumer};
use ironauth_store::{
    ActorRef, AgentId, CorrelationId, HumanId, NewOutboxMessage, OutboxMessage, Scope, ServiceId,
    Store, TRAIT_MIGRATION_CONSUMER, TraitMigrationJobId,
};

/// The payload key naming the job a message advances.
const PAYLOAD_JOB_ID: &str = "job_id";
/// The payload key carrying the actor whose request this job is a continuation of.
const PAYLOAD_ACTOR_KIND: &str = "actor_kind";
/// The payload key carrying that actor's id.
const PAYLOAD_ACTOR_ID: &str = "actor_id";

/// Build the payload one batch message carries.
///
/// Shared with the producer so the two cannot disagree about the key names, which is the
/// same reason the consumer NAME is a shared constant: a producer writing `job` where the
/// consumer reads `job_id` fails on every message and looks like a dead queue.
#[must_use]
pub fn batch_payload(job_id: &TraitMigrationJobId, actor: &ActorRef) -> serde_json::Value {
    serde_json::json!({
        PAYLOAD_JOB_ID: job_id.to_string(),
        PAYLOAD_ACTOR_KIND: actor.kind_str(),
        PAYLOAD_ACTOR_ID: actor.id_string(),
    })
}

/// The consumer that advances one batch of a trait migration job.
pub struct TraitMigrationConsumer {
    store: Store,
    batch_size: i64,
}

impl TraitMigrationConsumer {
    /// Build the consumer over a DATA-plane store.
    ///
    /// `batch_size` is how many identities ONE message processes. It is a configured value
    /// rather than a constant because the right number depends on how long an identity
    /// takes to validate and transform, which depends on the schema.
    #[must_use]
    pub fn new(store: Store, batch_size: u32) -> Self {
        Self {
            store,
            batch_size: i64::from(batch_size.max(1)),
        }
    }

    /// Read a required string off the message payload.
    fn payload_str<'m>(message: &'m OutboxMessage, key: &str) -> Result<&'m str, ConsumerError> {
        message
            .payload
            .get(key)
            .and_then(serde_json::Value::as_str)
            // A malformed payload is PERMANENT: no retry adds a field to a row that is
            // already written, so retrying only delays the dead letter.
            .ok_or_else(|| ConsumerError::permanent(format!("payload_missing_{key}")))
    }

    /// Reconstruct the actor this job's batches are attributed to.
    ///
    /// The actor travels ON THE MESSAGE rather than being invented here, because
    /// `advance` writes an audit row and a background worker has no actor of its own. A
    /// migration's batches are continuations of the operator's request, so they are
    /// attributed to the operator who asked for it, which is what the audit log is for.
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

    /// Advance ONE batch, and queue the next if the job has not finished.
    async fn advance_one(
        &self,
        env: &Env,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let raw = Self::payload_str(message, PAYLOAD_JOB_ID)?;
        let job_id = TraitMigrationJobId::parse_in_scope(raw, &scope)
            .map_err(|_| ConsumerError::permanent("job_id_malformed"))?;
        let actor = Self::actor_of(message)?;

        let job = self
            .store
            .scoped(scope)
            .acting(actor, CorrelationId::generate(env))
            .trait_migration_jobs()
            .advance(env, &job_id, self.batch_size)
            .await
            // A batch that failed can succeed later (a database that was unreachable, an
            // envelope key not provisioned yet), so this retries; the substrate's attempt
            // budget is what turns a persistent failure into a dead letter. It is safe to
            // retry because `advance` resumes from the job's own cursor rather than
            // reprocessing from the start.
            .map_err(|_| ConsumerError::retryable("advance_failed"))?;

        if job.status.is_terminal() {
            tracing::info!(
                job = %job_id,
                status = job.status.as_str(),
                processed = job.processed_count,
                migrated = job.migrated_count,
                failures = job.failure_count,
                "trait migration job finished"
            );
            return Ok(());
        }

        // Queue the next batch. The key carries the progress counter, so each batch has a
        // distinct domain fact: without that the second message would collide with the
        // first on the unique index and the job would stall after one batch.
        //
        // Enqueued only after `advance` COMMITTED, so a message can never describe
        // progress that was rolled back. The cost of that ordering is the one crash window
        // worth naming: a worker that dies between the commit and this enqueue leaves the
        // job short of a follow-up message. The job is not lost or corrupt, and re-queuing
        // it is a fresh create against the same job; the progress it already made stands.
        self.store
            .scoped(scope)
            .outbox()
            .enqueue(
                env,
                &NewOutboxMessage {
                    consumer: TRAIT_MIGRATION_CONSUMER,
                    idempotency_key: &format!("job:{job_id}:{}", job.processed_count),
                    // The JOB, so its batches are delivered in order and never at once:
                    // two workers advancing one job concurrently would double-count it.
                    ordering_key: &job_id.to_string(),
                    payload: batch_payload(&job_id, &actor),
                },
            )
            .await
            .map_err(|_| ConsumerError::retryable("enqueue_next_batch_failed"))?;
        Ok(())
    }
}

impl OutboxConsumer for TraitMigrationConsumer {
    fn name(&self) -> &str {
        TRAIT_MIGRATION_CONSUMER
    }

    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>> {
        Box::pin(async move { self.advance_one(env, scope, message).await })
    }
}
