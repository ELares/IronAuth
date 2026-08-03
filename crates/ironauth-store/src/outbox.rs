// SPDX-License-Identifier: MIT OR Apache-2.0

//! The outbox consumer framework (issue #104): the registration seam every async path
//! implements, the horizontally scalable worker pool that drives it, and the periodic
//! reaper that bounds the queue's TERMINAL tail (PR 3, at the bottom of this file).
//!
//! The reaper is deliberately NOT a consumer and shares nothing with the pool but the
//! `ScopeSource`, so it reaps the rows of consumers this binary does not run. What it
//! bounds and what it does NOT is set out at [`RetentionSweeper`]; the short version is
//! that it removes rows a consumer already RETIRED, so a deployment that drains nothing
//! has nothing here for it to remove.
//!
//! ## Why this is a pool and never a singleton
//!
//! The field's cautionary example is Ory Kratos's courier: a MANDATORY SINGLETON, which
//! made it the most brittle component of that system. It has no health endpoint (their
//! #4579), and running a second copy by accident duplicates sends because nothing in the
//! queue prevents two couriers from taking the same work. A singleton is also a
//! throughput ceiling and a single point of failure that an operator cannot scale out of.
//!
//! Nothing here is a singleton, and the safety comes from the QUEUE rather than from a
//! promise about deployment:
//!
//! - every claim is `FOR UPDATE SKIP LOCKED` under a visibility lease, and every
//!   lifecycle write is FENCED on the exact lease it was handed, so two workers never
//!   hold one message for longer than a visibility timeout and at most one of them can
//!   ever record its outcome;
//! - a crashed worker's messages reappear when the lease lapses, so losing a worker costs
//!   latency, not work;
//! - a CONSUMER PANIC is caught and recorded as a retryable failure rather than killing
//!   the worker task, so one poison message costs that message its attempts and costs the
//!   pool nothing;
//! - per-aggregate ordering is enforced by the claim itself (only a group's head is ever
//!   eligible), so adding workers cannot reorder an aggregate's messages.
//!
//! So `concurrency` workers in one process and N replicas of that process are both safe,
//! and neither needs coordination, a leader election, or a lock service.
//!
//! ## Nothing here is silent
//!
//! The other half of Kratos's cautionary example is that its courier has no health
//! surface at all. Two things answer that here, and both are required rather than
//! optional: [`OutboxWorkerPool::size`] is the LIVE worker count measured against
//! [`OutboxWorkerPool::configured_size`], and every drain pass, every persistence fault
//! and every failed scope sweep is reported to an [`OutboxObserver`] the caller must
//! supply. This crate takes no logging dependency, so the observer is how a dead letter
//! reaches an operator; a pool whose outcomes are discarded is a queue that looks idle
//! while it silently gives work up.
//!
//! The one number an operator still owns is the visibility timeout, and what it has to
//! exceed is ONE handler's duration, not a batch of them: [`OutboxWorker::run_once`]
//! re-stamps each message's lease immediately before handing it over, so the batch size
//! does not multiply into the deadline.
//!
//! ## Why this lives in the store crate
//!
//! It is a thin loop over the queue in `repository.rs`, and `scripts/query-audit.sh`
//! confines the queue's SQL to that module, so the framework has to sit on the same side
//! of that boundary. It is also the only crate every future consumer (webhook delivery,
//! SIEM sinks, migration jobs, notification fan-out) already depends on. The tokio
//! dependency it adds is the workspace's existing runtime with only the `rt` and `time`
//! features, which the crate already pulled in through sqlx.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ironauth_env::Env;

use crate::error::StoreError;
use crate::repository::{FailureOutcome, OutboxMessage, RetryPolicy, epoch_micros};
use crate::scope::Scope;
use crate::store::Store;

/// Why a consumer could not handle a message (issue #104).
///
/// The distinction the substrate acts on is not the reason text but whether another
/// attempt could plausibly succeed. A `retryable` failure (an unreachable endpoint, a
/// 503, a timeout) is scheduled for a bounded backoff retry; a `permanent` failure (a
/// payload the consumer cannot parse, a target that no longer exists) is DEAD-LETTERED
/// immediately, because burning five attempts on a message that can never succeed only
/// delays the dead-letter and, when the message is not alone in its ordering group,
/// blocks its whole aggregate for the length of the backoff schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerError {
    label: String,
    retryable: bool,
}

impl ConsumerError {
    /// A failure another attempt could plausibly recover from. Scheduled for a bounded
    /// backoff retry, then dead-lettered once the attempts bound is reached.
    ///
    /// `label` is recorded verbatim as the message's `last_error` and is read by
    /// operators, so it must be a bounded, non-secret token (`http_status_503`,
    /// `transport_error`), never a response body or anything derived from a credential.
    #[must_use]
    pub fn retryable(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            retryable: true,
        }
    }

    /// A failure no further attempt can recover from. Dead-lettered on the spot.
    #[must_use]
    pub fn permanent(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            retryable: false,
        }
    }

    /// The bounded, non-secret failure label recorded on the message.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Whether another attempt could plausibly succeed.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        self.retryable
    }
}

/// The registration seam every async path implements to receive messages off the outbox
/// (issue #104): webhook delivery, back-channel logout delivery, SIEM sinks, migration
/// jobs, notification fan-out.
///
/// The future is boxed rather than an `impl Future` so the trait is DYN COMPATIBLE, which
/// is what lets [`ConsumerRegistry`] hold consumers of different concrete types behind
/// one name lookup. It is declared `Send` so a worker built on this seam is spawnable on
/// a multi-threaded runtime.
///
/// # The contract an implementor is held to
///
/// Delivery is AT-LEAST-ONCE, so [`handle`](OutboxConsumer::handle) MUST be idempotent:
/// a worker that acts and then crashes before completing the message sees the same
/// message again once its lease lapses. Dedup on `message.idempotency_key` (or on
/// `message.id`, which is equally stable).
///
/// It is also called CONCURRENTLY, by several workers in one process and by several
/// processes, so an implementor must hold no per-consumer mutable state that assumes a
/// single caller.
///
/// # The ordering an implementor may assume, exactly
///
/// This is the sentence eight consumers will build on, so it states what the substrate
/// KEEPS rather than what it aims at. Unconditionally, for every consumer:
///
/// - of the messages of one `(consumer, ordering_key)` group that were VISIBLE when a
///   claim ran, only the lowest-sequenced non-terminal one is ever leased, and it keeps
///   blocking its group until it is completed or dead-lettered;
/// - a worker whose lease has lapsed cannot record an outcome for a message another
///   worker now holds, so a group is never released by a stale holder.
///
/// The stronger reading, "two messages sharing an `ordering_key` are never handled at
/// the same time and arrive in enqueue order", additionally requires something the
/// substrate cannot enforce and the PRODUCERS must provide:
///
/// > Two enqueues under one `(consumer, ordering_key)` must not have overlapping
/// > transactions.
///
/// Sequences are assigned at INSERT, so two overlapping producers can commit in the
/// opposite order to their sequences; the later-sequenced message can then be claimed and
/// handled first, and the earlier one becomes claimable while it is still in flight. A
/// domain write that takes the aggregate's own row lock in the transaction it enqueues
/// from meets the precondition by construction; a scheduled job, a replay, or anything
/// using `OutboxRepo::enqueue` does not, and a consumer whose producers are of that shape
/// must be written to the unconditional list above.
///
/// A consumer that wants no ordering at all passes a per-message `ordering_key`, which
/// makes every group a singleton and makes the whole question moot.
///
/// # Panics are contained, not blessed
///
/// A panic out of [`handle`](OutboxConsumer::handle) is caught, recorded as a retryable
/// failure labelled `consumer_panic`, and counted as an attempt, so a poison message
/// eventually dead-letters instead of wedging its aggregate, and the worker survives. It
/// is still a defect: the message is retried, so the panic re-runs, and any partial
/// external effect the handler had before it panicked is repeated.
pub trait OutboxConsumer: Send + Sync {
    /// The registered consumer name. It must equal the `consumer` discriminator its
    /// producers write, or this consumer drains nothing at all, silently.
    fn name(&self) -> &str;

    /// Handle ONE message. `Ok(())` completes it; a [`ConsumerError`] retries or
    /// dead-letters it according to [`ConsumerError::is_retryable`].
    fn handle<'a>(
        &'a self,
        env: &'a Env,
        scope: Scope,
        message: &'a OutboxMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), ConsumerError>> + Send + 'a>>;
}

/// Two consumers were registered under one name (issue #104).
///
/// This is refused rather than resolved, because either resolution is wrong: the second
/// registration silently replacing the first makes one subsystem's messages disappear
/// into another's handler, and both coexisting makes each see an arbitrary half of the
/// queue. Both are the kind of defect that shows up in production as "some events just
/// never arrive".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateConsumer {
    /// The name that was registered twice.
    pub name: String,
}

impl std::fmt::Display for DuplicateConsumer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "two consumers are registered under the outbox name `{}`",
            self.name
        )
    }
}

impl std::error::Error for DuplicateConsumer {}

/// The set of registered consumers, keyed by name (issue #104).
///
/// The registry is a startup-time structure: a binary builds it once, then spawns a pool
/// per registered consumer. It is deliberately NOT consulted per message, because the
/// claim already filters by consumer name in SQL and a per-message lookup would invite
/// the mistake of one pool draining a name it does not own.
#[derive(Default)]
pub struct ConsumerRegistry {
    consumers: BTreeMap<String, Arc<dyn OutboxConsumer>>,
}

impl ConsumerRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            consumers: BTreeMap::new(),
        }
    }

    /// Register `consumer` under its own [`OutboxConsumer::name`].
    ///
    /// # Errors
    ///
    /// [`DuplicateConsumer`] if that name is already registered.
    pub fn register(&mut self, consumer: Arc<dyn OutboxConsumer>) -> Result<(), DuplicateConsumer> {
        let name = consumer.name().to_owned();
        if self.consumers.contains_key(&name) {
            return Err(DuplicateConsumer { name });
        }
        self.consumers.insert(name, consumer);
        Ok(())
    }

    /// The consumer registered under `name`, if any.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Arc<dyn OutboxConsumer>> {
        self.consumers.get(name).map(Arc::clone)
    }

    /// Every registered consumer name, in a stable order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.consumers.keys().map(String::as_str).collect()
    }

    /// Every registered consumer, in a stable order by name: what a binary iterates to
    /// spawn one pool each.
    #[must_use]
    pub fn all(&self) -> Vec<Arc<dyn OutboxConsumer>> {
        self.consumers.values().map(Arc::clone).collect()
    }

    /// How many consumers are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.consumers.len()
    }

    /// Whether no consumer is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.consumers.is_empty()
    }
}

/// The tuning knobs for a consumer's workers (issue #104), sourced from the `[outbox]`
/// configuration section rather than baked in, per the tunability principle.
#[derive(Debug, Clone, Copy)]
pub struct WorkerSettings {
    /// How many workers this process runs for one consumer. Every worker claims
    /// independently, so this is a straight throughput knob with no coordination cost;
    /// the ceiling that matters is the number of distinct ordering keys with due work,
    /// not this number.
    pub concurrency: u32,
    /// The visibility timeout: how long a claim hides a message from other workers. A
    /// crashed worker's message reappears this long after it was last stamped, so this is
    /// the worst-case redelivery latency.
    ///
    /// It must exceed the slowest SINGLE handler call, and that is the whole condition
    /// because [`OutboxWorker::run_once`] re-stamps each message's lease immediately
    /// before handing it over. Without that re-stamp the batch would share one lease and
    /// the condition would be `batch * handler duration`, which at the shipped defaults
    /// (64 and 30s) is any handler slower than about 469ms.
    pub visibility_timeout: Duration,
    /// How long a worker waits after an empty pass before polling again.
    pub poll_interval: Duration,
    /// The largest number of messages one pass claims. Larger batches amortize the claim
    /// round trip; they do NOT shorten the effective deadline on any one handler, because
    /// each message's lease is re-stamped before it is handled.
    pub batch: i64,
    /// The bounded-retry schedule a failed attempt is held to.
    pub retry: RetryPolicy,
}

impl Default for WorkerSettings {
    fn default() -> Self {
        Self {
            concurrency: 2,
            visibility_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(5),
            batch: 64,
            retry: RetryPolicy::default(),
        }
    }
}

/// What one drain pass did, for observability and tests (issue #104).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainStats {
    /// Messages leased this pass.
    pub claimed: u64,
    /// Messages the consumer handled successfully and that are now terminal.
    pub completed: u64,
    /// Messages that failed and were scheduled for a backoff retry.
    pub retried: u64,
    /// Messages that failed terminally (the attempts bound, or a permanent error).
    pub dead_lettered: u64,
    /// Messages this pass claimed but did NOT handle, or handled and could not record,
    /// because their lease had already been taken by another worker.
    ///
    /// It is not an error and nothing is lost: the other worker owns the outcome. It is
    /// the signal that this consumer's handlers are slow relative to
    /// [`WorkerSettings::visibility_timeout`], which is otherwise invisible; a pass that
    /// keeps reporting a nonzero value is telling an operator to raise the timeout or
    /// lower the batch.
    pub lease_lost: u64,
}

/// One worker for one consumer (issue #104): claim a batch, hand each message to the
/// consumer, and record the outcome.
///
/// Cheap to clone and safe to run many of, in one process and across replicas. It holds
/// no cursor and no in-memory queue state: everything that decides what happens next
/// lives in the row.
#[derive(Clone)]
pub struct OutboxWorker {
    store: Store,
    env: Env,
    consumer: Arc<dyn OutboxConsumer>,
    settings: WorkerSettings,
}

impl OutboxWorker {
    /// Build a worker over the data-plane `store`, the environment seam, a registered
    /// `consumer`, and its tuning `settings`.
    #[must_use]
    pub fn new(
        store: Store,
        env: Env,
        consumer: Arc<dyn OutboxConsumer>,
        settings: WorkerSettings,
    ) -> Self {
        Self {
            store,
            env,
            consumer,
            settings,
        }
    }

    /// The consumer this worker drains for.
    #[must_use]
    pub fn consumer_name(&self) -> &str {
        self.consumer.name()
    }

    /// Run ONE drain pass for `scope`. A production loop calls this on a cadence; a test
    /// calls it directly, advancing a manual clock to exercise the lease and the backoff
    /// schedule.
    ///
    /// A single message's failure is NOT an error: it is retried or dead-lettered, so one
    /// bad message never aborts the pass or blocks the messages of other aggregates. Nor
    /// is a consumer PANIC: it is caught here and recorded as a retryable failure, so it
    /// costs the message an attempt rather than costing the process a worker.
    ///
    /// Each message's lease is re-stamped immediately before it is handed over, so the
    /// visibility timeout is a deadline on one handler rather than on the whole batch.
    /// A message whose lease has already gone to another worker is skipped, counted in
    /// [`DrainStats::lease_lost`], and left entirely to that worker. A FENCED scope is not
    /// drained at all: see [`run_once_until`](OutboxWorker::run_once_until), which this
    /// calls with a flag nothing ever sets.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a persistence fault.
    pub async fn run_once(&self, scope: Scope) -> Result<DrainStats, StoreError> {
        self.run_once_until(scope, &AtomicBool::new(false)).await
    }

    /// [`run_once`](OutboxWorker::run_once), abandoning the rest of the claimed batch as
    /// soon as `stop` is set. The pool hands its shutdown flag here.
    ///
    /// # The stop check sits BETWEEN MESSAGES, not only around the batch
    ///
    /// A pass that only checked the flag around its whole batch had to run every message
    /// the last claim took before it could return, so a stop cost one claim batch of
    /// handlers rather than one handler. At the shipped `claim_batch` of 64 and a logout
    /// request timeout of 10 seconds that is about ten minutes of `shutdown().await`,
    /// which an orchestrator resolves with SIGKILL. Measured here at a smaller scale, in
    /// `a_stop_between_messages_abandons_the_rest_of_the_claimed_batch`.
    ///
    /// Nothing is lost by abandoning them. A claimed message that is neither completed nor
    /// failed keeps its lease until it lapses and is then re-claimed, by another worker or
    /// by the next boot, which is the same path a crash takes. [`DrainStats::claimed`]
    /// still reports what the claim leased, because that is what it means.
    ///
    /// # A FENCED scope is skipped before anything is claimed
    ///
    /// A suspended or offboarded scope ([`ScopedStore::environment_state`]) is not drained
    /// at all, and this is a correctness property rather than an optimization. The data
    /// plane fences such a scope, so every handler that touches it fails; those failures
    /// are retryable, and retryable failures burn a FINITE attempts budget, so a
    /// suspension that outlasts the backoff schedule DEAD-LETTERS everything queued in the
    /// scope. The work would be discarded precisely because an operator paused the tenant,
    /// and resuming would not bring it back. Skipping leaves it queued and due, so a
    /// resume drains it.
    ///
    /// It also makes the [`ScopeSource`] documentation true: that seam resolves scopes per
    /// sweep so "a suspended one must stop", and until this check existed nothing stopped.
    ///
    /// The cost is one indexed, scope-local lookup per scope per pass, which is the same
    /// order as the claim it guards and is paid only while a pool is running.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a persistence fault.
    pub async fn run_once_until(
        &self,
        scope: Scope,
        stop: &AtomicBool,
    ) -> Result<DrainStats, StoreError> {
        let mut stats = DrainStats::default();
        let scoped = self.store.scoped(scope);
        if scoped.environment_state().await?.is_fenced() {
            return Ok(stats);
        }
        let queue = scoped.outbox();
        let mut claimed = queue
            .claim(
                &self.env,
                self.consumer.name(),
                self.settings.visibility_timeout,
                self.settings.batch,
            )
            .await?;
        stats.claimed = u64::try_from(claimed.len()).unwrap_or(u64::MAX);
        for message in &mut claimed {
            // The stop check, BEFORE the renewal rather than after the handler, so a
            // shutdown costs at most the handler already running and never one more.
            if stop.load(Ordering::Relaxed) {
                break;
            }
            // Re-stamp before handing over, and skip anything whose lease is no longer
            // ours. Doing this per message is what keeps the batch from sharing one
            // deadline; doing it BEFORE the handler is what makes the skip free, because
            // nothing has been done yet that another worker would repeat.
            if !queue.renew_lease(&self.env, message).await? {
                stats.lease_lost += 1;
                continue;
            }
            match self.handle_catching_panics(scope, message).await {
                Ok(()) => {
                    if queue.complete(&self.env, message).await? {
                        stats.completed += 1;
                    } else {
                        // The handler outran its renewed lease and another worker has the
                        // message. The work happened, at-least-once delivery says it may
                        // happen again, and the outcome is not ours to write.
                        stats.lease_lost += 1;
                    }
                }
                Err(failure) => {
                    // A permanent failure skips the schedule entirely: it is expressed as
                    // a one-attempt policy, so the very next decision the queue makes is
                    // to dead-letter. That keeps ONE place (the queue) deciding what a
                    // terminal state is, rather than giving the worker a second way to
                    // write one.
                    let policy = if failure.is_retryable() {
                        self.settings.retry
                    } else {
                        RetryPolicy {
                            max_attempts: 1,
                            ..self.settings.retry
                        }
                    };
                    let outcome = queue
                        .fail(&self.env, message, failure.label(), policy)
                        .await?;
                    match outcome {
                        FailureOutcome::Retrying { .. } => stats.retried += 1,
                        FailureOutcome::DeadLettered { .. } => stats.dead_lettered += 1,
                        // The message went terminal, or its lease moved, under another
                        // worker between our renewal and our failure report. Nothing to
                        // record: that worker owns the outcome.
                        FailureOutcome::NotFound => stats.lease_lost += 1,
                    }
                }
            }
        }
        Ok(stats)
    }

    /// Call the consumer, converting a PANIC into a retryable failure.
    ///
    /// Without this the panic unwinds out of the spawned task and takes the worker with
    /// it: the pool keeps reporting its configured size, `shutdown` discards the
    /// `JoinError`, and the poison message is left at `attempts = 0` forever, because the
    /// only thing that counts an attempt is a call to `fail` that never happens. The
    /// aggregate behind it is then wedged permanently, and so is every other aggregate
    /// that consumer serves once enough workers have died. Measured before the fix: two
    /// workers, one poison message, and healthy work in a DIFFERENT ordering group was
    /// never handled again.
    ///
    /// Mapping the panic to `retryable` rather than `permanent` is deliberate. A panic is
    /// a bug, and the two plausible readings of a bug (a transient state the next attempt
    /// will not hit, or a payload this code can never process) are indistinguishable from
    /// here; `retryable` lets the first heal itself and still dead-letters the second once
    /// the finite bound is reached, whereas `permanent` would discard the first on one
    /// unlucky attempt.
    ///
    /// This is the UNWIND case, which is what the workspace ships: no profile sets a panic
    /// strategy, so the default `unwind` applies to every target here. Under
    /// `panic = "abort"` there is nothing to catch, in this or any other Rust code: the
    /// process dies, the leases lapse, and recovery is the ordinary crash path (another
    /// replica, or this one after a restart, re-claims and re-handles). That path is safe
    /// but it is not contained, so an operator who sets `abort` gives this property up.
    async fn handle_catching_panics(
        &self,
        scope: Scope,
        message: &OutboxMessage,
    ) -> Result<(), ConsumerError> {
        let mut handling = self.consumer.handle(&self.env, scope, message);
        // `catch_unwind` per POLL rather than around one blocking call, because the thing
        // that can panic is an async body that suspends: only the poll that panics is
        // caught, and the future is then dropped without being polled again, which is
        // exactly what a combinator-based catch does. `AssertUnwindSafe` is the assertion
        // that a half-run handler leaving shared state inconsistent is the consumer's
        // problem and not silently ours; the message is retried, so any partial external
        // effect is repeated, which the at-least-once contract already requires
        // implementors to tolerate.
        std::future::poll_fn(|cx| {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handling.as_mut().poll(cx)
            })) {
                Ok(polled) => polled,
                Err(_payload) => {
                    std::task::Poll::Ready(Err(ConsumerError::retryable(CONSUMER_PANIC_LABEL)))
                }
            }
        })
        .await
    }
}

/// The `last_error` a caught consumer panic is recorded under (issue #104). A bounded,
/// non-secret token like every other label, and a distinctive one: an operator reading it
/// off the dead-letter tail is reading a BUG report, not a failing endpoint.
pub const CONSUMER_PANIC_LABEL: &str = "consumer_panic";

/// The scopes a pool drains, resolved fresh on every sweep (issue #104).
///
/// It is a seam rather than a fixed list because the set of live `(tenant, environment)`
/// scopes changes while the process runs: a tenant created after boot must start being
/// drained without a restart, and a suspended one must stop. Resolving it per sweep is
/// also what keeps this crate from having to know whether the scope list comes from the
/// control plane, a static configuration, or a test fixture.
///
/// An implementor does NOT have to filter out suspended scopes, and
/// [`ControlPlaneScopes`] deliberately does not: the serving state lives on a
/// row-level-security scoped table that a cross-scope control-plane read cannot see, so
/// the stop is enforced one layer down, per scope, in
/// [`OutboxWorker::run_once_until`].
pub trait ScopeSource: Send + Sync {
    /// The scopes to drain on this sweep.
    fn scopes(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Scope>, StoreError>> + Send + '_>>;
}

/// A fixed scope list, for a single-tenant deployment and for tests.
pub struct StaticScopes(Vec<Scope>);

impl StaticScopes {
    /// Drain exactly these scopes, forever.
    #[must_use]
    pub fn new(scopes: Vec<Scope>) -> Self {
        Self(scopes)
    }
}

impl ScopeSource for StaticScopes {
    fn scopes(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Scope>, StoreError>> + Send + '_>> {
        let scopes = self.0.clone();
        Box::pin(async move { Ok(scopes) })
    }
}

/// The live `(tenant, environment)` scopes, read from the CONTROL plane on every sweep
/// (issue #104): the production [`ScopeSource`], and the counterpart to [`StaticScopes`].
///
/// Scope enumeration reads the `environments` table, which is NOT row-level-security
/// scoped and which only the `ironauth_control` role may read, so this holds a control
/// plane [`Store`] while the workers it feeds drain through a separate data plane one. A
/// binary therefore connects twice, and that separation is the point: a pool that could
/// enumerate scopes from its data-plane connection would be a data-plane role with a
/// cross-tenant read.
///
/// It lives here rather than in the binary because every consumer of this framework needs
/// exactly this and would otherwise write it again, differently, and at least one of
/// those copies would panic on the error path.
///
/// It reports every environment, INCLUDING suspended ones, and that is not an oversight.
/// The serving state lives on `environment_states`, which FORCES row-level security keyed
/// on the scope, so a control-plane connection that has set no scope reads nothing there
/// and a set-based filter here would either return every scope or none. The stop for a
/// suspended scope is therefore enforced per scope, on the data plane, in
/// [`OutboxWorker::run_once_until`], which already holds a scoped store.
pub struct ControlPlaneScopes {
    control: Store,
}

impl ControlPlaneScopes {
    /// Enumerate scopes on `control`, which must be a store connected with the
    /// control-plane role.
    #[must_use]
    pub fn new(control: Store) -> Self {
        Self { control }
    }
}

impl ScopeSource for ControlPlaneScopes {
    /// # A database fault here is an `Err`, never a panic
    ///
    /// That is a hard requirement of this seam and not a style preference. A panic out of
    /// [`ScopeSource::scopes`] unwinds through the worker loop, which has no
    /// `catch_unwind` around it (the one in [`OutboxWorker::run_once`] wraps the CONSUMER,
    /// not the sweep), so the task dies. The pool then keeps its
    /// [`configured_size`](OutboxWorkerPool::configured_size) while its
    /// [`size`](OutboxWorkerPool::size) falls, and a control plane that is briefly
    /// unreachable at the wrong moment permanently costs the process its workers.
    /// Returning `Err` costs one sweep instead: the loop abandons the pass and retries
    /// after `poll_interval`.
    fn scopes(&self) -> Pin<Box<dyn Future<Output = Result<Vec<Scope>, StoreError>> + Send + '_>> {
        Box::pin(async move { self.control.management().list_environment_scopes().await })
    }
}

/// What a pool's drain passes did, reported OUT of this crate (issue #104).
///
/// The pool would otherwise discard every outcome it produces, and that is not a
/// hypothetical: the loop's inner call read `let _ = worker.run_once(scope).await;`, and
/// this crate takes no logging dependency at all, so a dead-lettered message, a pass that
/// failed on a persistence fault, and a [`ScopeSource`] that never returned a scope were
/// all indistinguishable, from outside the process, from a queue with no work in it. The
/// pool reports through this seam and the BINARY decides what a log line, a metric or an
/// alert is; the store crate keeps its freedom from a logging framework.
///
/// Every method takes the consumer name, because a process runs one pool per consumer and
/// a report that does not say which one is not actionable.
///
/// An implementor must not block or panic: it is called on the worker task, between
/// passes, and a panic here kills that worker exactly as a panicking [`ScopeSource`] does
/// (the `catch_unwind` in [`OutboxWorker::run_once`] wraps the CONSUMER, nothing else).
pub trait OutboxObserver: Send + Sync {
    /// One drain pass over one scope finished. [`DrainStats::dead_lettered`] is the number
    /// an alert fires on: a dead letter is work that will never happen unless an operator
    /// replays it, and for a fan-out consumer one dead letter can be a whole session's
    /// worth of notifications.
    fn pass_finished(&self, consumer: &str, scope: Scope, stats: &DrainStats);

    /// One drain pass failed on a persistence fault. Nothing is lost, because the queue
    /// still holds the work and the next pass retries, but a pass that keeps failing is a
    /// pool draining nothing while reporting full health.
    fn pass_failed(&self, consumer: &str, scope: Scope, error: &StoreError);

    /// The sweep could not resolve its scopes, so NO scope was drained this pass. This is
    /// the one that most needs saying: [`OutboxWorkerPool::size`] cannot see it (the
    /// workers are alive and looping), so a `ScopeSource` that always errors is a
    /// permanently idle pool at full reported health.
    fn scopes_unavailable(&self, consumer: &str, error: &StoreError);
}

/// An observer that reports nothing (issue #104): for tests, and for a caller that has
/// deliberately decided a pool's outcomes are not worth surfacing.
///
/// Named rather than made the default, so that choosing silence is a line of code somebody
/// wrote and a reviewer can see, instead of the absence of an argument.
pub struct SilentObserver;

impl OutboxObserver for SilentObserver {
    fn pass_finished(&self, _consumer: &str, _scope: Scope, _stats: &DrainStats) {}

    fn pass_failed(&self, _consumer: &str, _scope: Scope, _error: &StoreError) {}

    fn scopes_unavailable(&self, _consumer: &str, _error: &StoreError) {}
}

/// A running pool of workers for ONE consumer (issue #104).
///
/// [`spawn`](OutboxWorkerPool::spawn) starts `settings.concurrency` independent tasks.
/// Each sweeps every scope the [`ScopeSource`] reports, running one pass per scope,
/// reporting each outcome to the [`OutboxObserver`], then waits `poll_interval` and
/// sweeps again. The tasks share nothing: they are safe because every claim is leased and
/// skip-locked, which is the same reason a second REPLICA of the whole process is safe.
pub struct OutboxWorkerPool {
    consumer: String,
    handles: Vec<tokio::task::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    live: Arc<AtomicUsize>,
}

/// Decrements the pool's LIVE worker count when its task ends, however it ends.
///
/// A `Drop` rather than a decrement at the bottom of the loop, because the ending that
/// matters is the one nobody wrote code for: a panic unwinding out of the task body. That
/// is the whole reason [`OutboxWorkerPool::size`] cannot be the length of the handle
/// vector, which keeps reporting the configured count while the tasks behind it die.
struct WorkerLiveness(Arc<AtomicUsize>);

impl Drop for WorkerLiveness {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl OutboxWorkerPool {
    /// Spawn the pool. Returns immediately; the workers run until
    /// [`shutdown`](OutboxWorkerPool::shutdown) is awaited or the pool is dropped.
    ///
    /// A `concurrency` of 0 is treated as 1: a configured pool that silently drains
    /// nothing is the failure mode that makes a queue look healthy while it fills.
    ///
    /// `observer` is REQUIRED rather than optional, and [`SilentObserver`] is the way to
    /// say "nothing". An optional observer is one a caller can forget, and forgetting it
    /// reproduces exactly the state this seam exists to end: a pool whose every outcome,
    /// including a dead letter, is discarded by a `let _ =`.
    #[must_use]
    pub fn spawn(
        worker: &OutboxWorker,
        scopes: &Arc<dyn ScopeSource>,
        observer: &Arc<dyn OutboxObserver>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let workers = usize::try_from(worker.settings.concurrency.max(1)).unwrap_or(1);
        let poll = worker.settings.poll_interval;
        let live = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let worker = worker.clone();
            let scopes = Arc::clone(scopes);
            let observer = Arc::clone(observer);
            let stop = Arc::clone(&stop);
            // Counted UP here rather than inside the task, so `size` is the configured
            // count the instant `spawn` returns and only ever falls from a real death.
            // The guard is moved into the task, so it is dropped whether the task returns
            // normally, is cancelled before its first poll, or unwinds.
            live.fetch_add(1, Ordering::Relaxed);
            let liveness = WorkerLiveness(Arc::clone(&live));
            handles.push(tokio::spawn(async move {
                let _liveness = liveness;
                while !stop.load(Ordering::Relaxed) {
                    // A failure to resolve the scope list, or to drain one scope, is a
                    // transient database fault from this loop's point of view: the work
                    // is still durably in the queue, so the pass is abandoned and the
                    // next one retries. Nothing is dropped and nothing is retried here in
                    // a tight loop. Every one of those outcomes is REPORTED rather than
                    // discarded, because a loop that swallows them makes a permanently
                    // failing pool indistinguishable from an idle one.
                    match scopes.scopes().await {
                        Ok(scopes) => {
                            for scope in scopes {
                                if stop.load(Ordering::Relaxed) {
                                    break;
                                }
                                match worker.run_once_until(scope, &stop).await {
                                    Ok(stats) => {
                                        observer.pass_finished(
                                            worker.consumer_name(),
                                            scope,
                                            &stats,
                                        );
                                    }
                                    Err(error) => {
                                        observer.pass_failed(worker.consumer_name(), scope, &error);
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            observer.scopes_unavailable(worker.consumer_name(), &error);
                        }
                    }
                    tokio::time::sleep(poll).await;
                }
            }));
        }
        Self {
            consumer: worker.consumer_name().to_owned(),
            handles,
            stop,
            live,
        }
    }

    /// The consumer this pool drains for. A process runs one pool per registered consumer,
    /// so this is what makes a VECTOR of pools something a caller can assert about by name
    /// rather than only by length.
    #[must_use]
    pub fn consumer_name(&self) -> &str {
        &self.consumer
    }

    /// How many of this pool's worker tasks are still ALIVE.
    ///
    /// The LIVE count, not the configured one, and that distinction is the point. A task
    /// that unwinds is gone: nothing restarts it, `shutdown` discards its `JoinError`,
    /// and a pool that reported its spawn count would go on claiming to have four workers
    /// with one left. Compare against [`configured_size`](OutboxWorkerPool::configured_size)
    /// to see whether a pool has lost workers; a health surface that reports them equal is
    /// reporting something it has actually measured.
    ///
    /// A consumer panic does NOT show up here, because [`OutboxWorker::run_once`] catches
    /// it. What does is a panic in the surrounding loop, which in practice means a
    /// [`ScopeSource`] or an [`OutboxObserver`] that panics.
    #[must_use]
    pub fn size(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// How many worker tasks this pool STARTED: the ceiling `size` is measured against.
    #[must_use]
    pub fn configured_size(&self) -> usize {
        self.handles.len()
    }

    /// Signal every worker to stop and wait for the current passes to finish.
    ///
    /// A worker checks the flag between sweeps, between scopes, and between the MESSAGES
    /// of one claimed batch, so shutdown takes at most one poll interval plus ONE handler.
    ///
    /// The last of those three is not a refinement. Without it the bound is one poll
    /// interval plus a whole CLAIM BATCH of handlers, which at the shipped `claim_batch`
    /// of 64 and a logout request timeout of 10 seconds is about ten minutes: long enough
    /// that an orchestrator stops waiting and SIGKILLs the process, so a stop that was
    /// meant to be graceful is not. [`OutboxWorker::run_once_until`] is where the flag is
    /// read, and `a_stop_between_messages_abandons_the_rest_of_the_claimed_batch` measures
    /// that it is read there.
    ///
    /// Messages already claimed but not completed are NOT lost: their leases lapse and
    /// another worker (or the next boot) picks them up, which is the same path a crash
    /// takes.
    ///
    /// A worker that DIED rather than stopped is joined here too, and its `JoinError` is
    /// discarded rather than propagated, because shutdown has nothing useful to do with a
    /// death it is told about after the fact. The death is not swallowed: it already
    /// showed up in [`size`](OutboxWorkerPool::size), which is where a health surface
    /// reads it while the process is still running and can act.
    pub async fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Taken rather than consumed: this type has a `Drop` that re-signals the flag, so
        // its fields cannot be moved out. Draining the vector in place leaves the drop
        // with nothing left to do and keeps the belt-and-braces signal for the path where
        // a caller drops the pool instead of awaiting it.
        for handle in std::mem::take(&mut self.handles) {
            let _ = handle.await;
        }
    }
}

impl Drop for OutboxWorkerPool {
    fn drop(&mut self) {
        // A dropped pool must not leave detached tasks claiming messages behind an
        // operator's back. The flag stops them at the next check; a caller that needs to
        // WAIT for them uses `shutdown`.
        self.stop.store(true, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Retention (issue #104, PR 3).
//
// `outbox_messages` grew monotonically: nothing removed a completed or dead-lettered row
// and no role held DELETE. PR 2 multiplied the volume by roughly `1 + N_relying_parties`
// per session end. What follows is the reaper, and it is deliberately NOT a consumer of
// the queue it reaps.
//
// # Why this is a separate task and not an outbox consumer
//
// A reaper registered as a consumer, or folded into `OutboxWorker::run_once_until`, would
// only ever reap the consumers THIS BINARY drains, and would only run where their pools
// run. Both halves of that are wrong for retention.
//
// The rows are not the registry's. A consumer retired in an earlier release, or one this
// replica does not run because its own feature switch is off, has rows in the table and no
// registration; a registry-driven sweep leaves exactly those unreapable forever. So the
// sweep enumerates the TABLE (`OutboxRepo::consumers_in_scope`), not the registry.
//
// And the pools' gate is not retention's gate. Today's pools are spawned behind
// `oidc.enabled && oidc.backchannel_logout_enabled`, both default OFF. The outbox is a
// GENERIC substrate: the next consumer to register (webhook delivery, a SIEM sink, a
// migration job) will run behind a different switch, and retention must not have to be
// re-wired for each one. A reaper on the pools' path would be one feature switch away from
// being present, reviewed, tested and inert, which is the dead-surface shape PR 2 was
// written to end.
//
// # What this does NOT solve, stated because an earlier draft of this comment claimed it did
//
// The growth that is worst in a DEFAULT deployment is not the growth this removes, and the
// two must not be confused. `oidc.backchannel_logout_enabled` defaults off, the producer
// that enqueues `session_ended` runs regardless, and the consumer pools are the ONLY thing
// in the tree that ever writes `completed_at` or `dead_lettered_at`. Both reap methods key
// on those columns, and they MUST (a non-terminal row of any age is undelivered work, not
// a stale one: see `OutboxRepo::reap_completed`). So in exactly that deployment this
// reaper removes ZERO rows, on every pass, forever, and it is correct to.
//
// Where it is valuable is where the consumers DO run, and that is the volume PR 2
// multiplied: ending one session there enqueues roughly `1 + N_relying_parties` rows,
// every one of which becomes terminal, and before this nothing removed any of them.
//
// The remaining gap is therefore real and is recorded rather than papered over. A
// deployment with the logout switch off still accumulates undrained `session_ended`
// messages without bound, and no setting here changes that. The answer lives on the
// PRODUCER side (not enqueuing work no consumer will ever take), which is an owner decision
// already deferred and is written up in `docs/design/RETENTION.md`. Widening this reaper to
// non-terminal rows is NOT the answer and must not be done: those rows are precisely the
// backlog that turning the switch on begins by draining.
// ---------------------------------------------------------------------------

/// How long a retired outbox message is kept, and how much of the backlog one pass may
/// remove (issue #104, PR 3).
///
/// The two windows are NOT symmetric and the asymmetry is the design. A completed message
/// is delivery evidence and is retired on a default window; a dead letter is work GIVEN UP
/// ON, which for the back-channel logout fan-out is an entire session's relying parties
/// that will never be notified, so it is kept forever unless an operator deliberately
/// chooses otherwise.
#[derive(Debug, Clone, Copy)]
pub struct RetentionSettings {
    /// How long a COMPLETED message is kept after its `completed_at`.
    pub completed_retention: Duration,
    /// How long a DEAD-LETTERED message is kept after its `dead_lettered_at`, or [`None`]
    /// to keep it forever, which is the default.
    ///
    /// An [`Option`] rather than a duration with a magic zero, because in this crate the
    /// distinction has to be un-mistakable: a zero-second window would mean "delete every
    /// dead letter on the next pass", which is the opposite of the shipped posture and the
    /// exact reading a caller coming from a diagnostics-style retention would assume.
    pub dead_letter_retention: Option<Duration>,
    /// The largest number of rows ONE pass removes per (scope, consumer) per tail.
    ///
    /// A hard bound rather than a chunk size to loop over. An unbounded delete across a
    /// first run's accumulated backlog holds a long lock and produces one enormous WAL
    /// record, which stalls a replica; the pass stops at this bound and reports
    /// [`RetentionStats::saturated`] instead.
    ///
    /// This struct is publicly constructible, so a caller CAN write `batch: 0` here, and
    /// nothing rejects it: a sweeper built that way runs on its cadence and removes
    /// nothing, which looks exactly like a healthy idle one. It is not reachable from
    /// configuration (`outbox.reap_batch` is refused below 1 and above
    /// `OUTBOX_MAX_REAP_BATCH`), and the binary is the only production constructor, so this
    /// is a note for a future in-tree caller rather than an operator-facing hazard. It is
    /// not validated in this crate because a `Result` on a plain settings struct would
    /// move the refusal off the boot path, where an operator can read it, and onto the
    /// sweep, where nobody would.
    pub batch: i64,
    /// How long the sweeper waits between passes.
    pub interval: Duration,
}

impl Default for RetentionSettings {
    /// The same numbers `ironauth_config::OutboxConfig::default` ships, written here
    /// because this crate deliberately does not depend on the configuration crate. The two
    /// are pinned against each other in the `ironauth` crate, which depends on both.
    fn default() -> Self {
        Self {
            completed_retention: Duration::from_secs(7 * 24 * 60 * 60),
            dead_letter_retention: None,
            batch: 1_000,
            interval: Duration::from_secs(60 * 60),
        }
    }
}

/// What one retention pass removed for ONE consumer in ONE scope (issue #104, PR 3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionStats {
    /// Completed messages removed.
    pub completed_reaped: u64,
    /// Dead-lettered messages removed. Zero at the shipped default, where dead letters are
    /// kept forever.
    pub dead_letters_reaped: u64,
    /// Whether either delete hit [`RetentionSettings::batch`] exactly, meaning the pass ran
    /// out of budget rather than out of work.
    ///
    /// A distinct signal rather than an inference a reader might not make. Without it
    /// "removed 1000 rows" is the same report whether the reaper is keeping up or has been
    /// falling permanently behind for a month, and the two need different actions: the
    /// second wants a larger batch or a shorter interval, and until it gets one the table
    /// grows despite a reaper that reports work every pass.
    pub saturated: bool,
}

/// What the retention sweeper's passes did, reported OUT of this crate (issue #104, PR 3).
///
/// A SIBLING of [`OutboxObserver`] rather than methods added to it, deliberately. The two
/// report different work at different cadences (a drain pass per poll interval, a
/// retention pass per hour) and a caller may want one loud and the other quiet. Folding
/// them together would also mean every future non-outbox retention target widens the one
/// trait that every outbox consumer's observer has to implement.
///
/// REQUIRED rather than optional, for the reason [`OutboxWorkerPool::spawn`] gives about
/// its own: an optional observer is one a caller can forget, and a forgotten one restores
/// exactly the silence this seam exists to end. [`SilentRetentionObserver`] is how a caller
/// says "nothing" in a line of code a reviewer can see.
///
/// An implementor must not block or panic: it is called on the sweeper task, and a panic
/// here kills that task.
pub trait RetentionObserver: Send + Sync {
    /// One retention pass over one consumer in one scope finished.
    fn pass_finished(&self, scope: Scope, consumer: &str, stats: &RetentionStats);

    /// One retention pass failed on a persistence fault. `consumer` is [`None`] when the
    /// fault was in the per-SCOPE work that precedes any consumer (reading the scope's
    /// serving state, or enumerating the consumers with rows in it), because attributing
    /// that to a consumer name would be a guess an operator would then chase.
    ///
    /// Nothing is lost: the rows are still there and the next pass retries. A pass that
    /// keeps failing is a table that keeps growing while a sweeper reports it is running,
    /// which is the failure this method exists to make visible. The "permission denied"
    /// from a deployment whose control-plane role never received the 0102 DELETE grant
    /// arrives here.
    fn pass_failed(&self, scope: Scope, consumer: Option<&str>, error: &StoreError);

    /// The sweep could not resolve its scopes, so NO scope was reaped this pass. Nothing
    /// about the sweeper's liveness can reveal this: the task is alive and looping.
    fn scopes_unavailable(&self, error: &StoreError);
}

/// A [`RetentionObserver`] that reports nothing (issue #104, PR 3): for tests, and for a
/// caller that has deliberately decided a sweeper's outcomes are not worth surfacing.
///
/// Named rather than made the default, so that choosing silence is a line of code somebody
/// wrote and a reviewer can see, instead of the absence of an argument.
pub struct SilentRetentionObserver;

impl RetentionObserver for SilentRetentionObserver {
    fn pass_finished(&self, _scope: Scope, _consumer: &str, _stats: &RetentionStats) {}

    fn pass_failed(&self, _scope: Scope, _consumer: Option<&str>, _error: &StoreError) {}

    fn scopes_unavailable(&self, _error: &StoreError) {}
}

/// The bounded retention reaper for `outbox_messages` (issue #104, PR 3).
///
/// It holds a CONTROL-plane [`Store`], because `0102_outbox_retention.sql` grants DELETE on
/// this table to `ironauth_control` and to no other role. The reason is separation of duty
/// rather than convenience: `ironauth_app` holds the column-scoped UPDATE that writes
/// `dead_lettered_at`, so a data plane with DELETE could give up on a message and then
/// erase the record of having given up.
#[derive(Clone)]
pub struct OutboxReaper {
    store: Store,
    env: Env,
    settings: RetentionSettings,
}

impl OutboxReaper {
    /// Build a reaper over a CONTROL-plane `store`, the environment seam, and its windows.
    #[must_use]
    pub fn new(store: Store, env: Env, settings: RetentionSettings) -> Self {
        Self {
            store,
            env,
            settings,
        }
    }

    /// The windows this reaper runs to.
    #[must_use]
    pub fn settings(&self) -> RetentionSettings {
        self.settings
    }

    /// Run ONE bounded retention pass for `consumer` in `scope`.
    ///
    /// At most [`RetentionSettings::batch`] rows are removed from each tail, and the
    /// predicates key on the TERMINAL columns (`completed_at`, `dead_lettered_at`), never
    /// on `enqueued_at`. See [`OutboxRepo::reap_completed`](crate::repository::OutboxRepo::reap_completed)
    /// for why an age-based predicate would delete undelivered work and reorder the
    /// messages it left behind.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on a persistence fault.
    pub async fn reap_once(
        &self,
        scope: Scope,
        consumer: &str,
    ) -> Result<RetentionStats, StoreError> {
        let queue = self.store.scoped(scope).outbox();
        let now_micros = epoch_micros(self.env.clock().now_utc());
        let batch = self.settings.batch;

        let completed_cutoff = cutoff_micros(now_micros, self.settings.completed_retention);
        let completed_reaped = queue
            .reap_completed(consumer, completed_cutoff, batch)
            .await?;

        // The dead-letter tail is reaped ONLY when an operator has chosen a window. `None`
        // is "keep forever", which is the shipped default, so this branch does not run at
        // all in a deployment that never opened the setting.
        let dead_letters_reaped = match self.settings.dead_letter_retention {
            Some(window) => {
                queue
                    .reap_dead_lettered(consumer, cutoff_micros(now_micros, window), batch)
                    .await?
            }
            None => 0,
        };

        let saturated = u64::try_from(batch)
            .is_ok_and(|batch| completed_reaped >= batch || dead_letters_reaped >= batch);
        Ok(RetentionStats {
            completed_reaped,
            dead_letters_reaped,
            saturated,
        })
    }

    /// Run one retention pass over EVERY consumer with rows in `scope`, reporting each to
    /// `observer`, and abandoning the rest as soon as `stop` is set.
    ///
    /// # A FENCED scope is skipped entirely, before anything is deleted
    ///
    /// A suspended or offboarded scope is one an operator PAUSED, and quietly deleting its
    /// data while it is paused is the last thing a pause should do. The drain already
    /// refuses a fenced scope ([`OutboxWorker::run_once_until`]), which means a fenced
    /// scope's queue does not move: its completed tail is exactly the delivery evidence an
    /// operator investigating the suspension reads, and its dead letters are exactly the
    /// work that was lost. Reaping through a pause would also make resumption
    /// unreconstructable, because nothing else records that those messages existed.
    ///
    /// A per-consumer fault is REPORTED and the sweep moves to the next consumer, so one
    /// consumer whose delete fails does not cost the scope's other consumers their pass.
    /// The two per-scope reads that precede any consumer (the serving state and the
    /// consumer enumeration) return `Err` instead, because with either of them unanswered
    /// there is no list to continue down.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the scope's serving state or its consumer list cannot be read.
    pub async fn sweep_scope_until(
        &self,
        scope: Scope,
        stop: &AtomicBool,
        observer: &dyn RetentionObserver,
    ) -> Result<(), StoreError> {
        let scoped = self.store.scoped(scope);
        if scoped.environment_state().await?.is_fenced() {
            return Ok(());
        }
        let consumers = scoped.outbox().consumers_in_scope().await?;
        for consumer in consumers {
            // Checked BETWEEN consumers as well as between scopes, so a shutdown costs at
            // most one bounded delete rather than a whole scope's worth of them.
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match self.reap_once(scope, &consumer).await {
                Ok(stats) => observer.pass_finished(scope, &consumer, &stats),
                Err(error) => observer.pass_failed(scope, Some(consumer.as_str()), &error),
            }
        }
        Ok(())
    }
}

/// The cutoff instant a retention window puts on `now`, in epoch microseconds.
///
/// A cutoff BEFORE the epoch is negative and that is correct rather than a special case: a
/// deterministic clock starts at the Unix epoch, so a seven day window subtracted from time
/// zero is seven days before it, and every row is newer than that, which is exactly "nothing
/// is old enough yet". What the saturating subtraction protects against is the arithmetic
/// wrapping instead, which would turn a window into an instant far in the FUTURE and make
/// every row reapable at once.
fn cutoff_micros(now_micros: i64, window: Duration) -> i64 {
    let window_micros = i64::try_from(window.as_micros()).unwrap_or(i64::MAX);
    now_micros.saturating_sub(window_micros)
}

/// The longest a sweeper sleeps without looking at its stop flag.
const RETENTION_STOP_CHECK_SLICE: Duration = Duration::from_millis(250);

/// Sleep `total`, in slices, returning early once `stop` is set.
///
/// A single `sleep(interval).await` would be correct and unusable. The drain's poll
/// interval is five seconds, so a pool that sleeps it whole costs a shutdown five seconds;
/// retention's interval is an HOUR, so the same shape would make `shutdown().await` take up
/// to an hour, which an orchestrator resolves with SIGKILL. The stop checks between scopes
/// and between consumers bound the WORKING part of a pass and say nothing about the
/// waiting part, which is almost all of it.
async fn sleep_watching_stop(total: Duration, stop: &AtomicBool) {
    let mut remaining = total;
    while !remaining.is_zero() && !stop.load(Ordering::Relaxed) {
        let slice = remaining.min(RETENTION_STOP_CHECK_SLICE);
        tokio::time::sleep(slice).await;
        remaining -= slice;
    }
}

/// A running retention sweeper for `outbox_messages` (issue #104, PR 3).
///
/// # What it bounds, and what it leaves growing
///
/// It removes rows a consumer already RETIRED: completed past their window, and
/// dead-lettered past a window an operator deliberately set. It removes nothing else, ever,
/// and a non-terminal row of any age is undelivered work rather than a stale one.
///
/// The consequence is worth stating at the type rather than leaving a reader to derive it.
/// In a deployment where no consumer runs, nothing writes a terminal column, so this
/// sweeper removes ZERO rows on every pass and the queue still grows. That is not a defect
/// in the sweeper; it is the shape of the problem, and the remaining half of it is a
/// producer-side owner decision recorded in `docs/design/RETENTION.md`. Where consumers DO
/// run, this is what stops a table that previously only ever grew.
///
/// # ONE task, not a pool
///
/// A considered difference from [`OutboxWorkerPool`].
/// The drain is a throughput problem, so it scales out; retention is a bounded periodic
/// delete on an hourly cadence, so a second task would contend for the same rows to remove
/// the same bounded number of them. Concurrent sweepers are still SAFE (the delete is
/// scoped, bounded and idempotent, and a row another sweeper already removed simply is not
/// matched), so several replicas each running one are fine; there is just nothing to buy
/// by running two in one process.
pub struct RetentionSweeper {
    handle: Option<tokio::task::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    live: Arc<AtomicUsize>,
}

impl RetentionSweeper {
    /// Spawn the sweeper. Returns immediately; it runs until
    /// [`shutdown`](RetentionSweeper::shutdown) is awaited or it is dropped.
    ///
    /// `observer` is REQUIRED, and [`SilentRetentionObserver`] is the way to say "nothing".
    #[must_use]
    pub fn spawn(
        reaper: &OutboxReaper,
        scopes: &Arc<dyn ScopeSource>,
        observer: &Arc<dyn RetentionObserver>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let interval = reaper.settings.interval;
        let live = Arc::new(AtomicUsize::new(1));
        let reaper = reaper.clone();
        let scopes = Arc::clone(scopes);
        let observer = Arc::clone(observer);
        let task_stop = Arc::clone(&stop);
        let liveness = WorkerLiveness(Arc::clone(&live));
        let handle = tokio::spawn(async move {
            let _liveness = liveness;
            while !task_stop.load(Ordering::Relaxed) {
                match scopes.scopes().await {
                    Ok(resolved) => {
                        for scope in resolved {
                            // Checked BETWEEN scopes, and again between consumers inside
                            // the pass, so a stop is bounded by one delete.
                            if task_stop.load(Ordering::Relaxed) {
                                break;
                            }
                            if let Err(error) = reaper
                                .sweep_scope_until(scope, &task_stop, observer.as_ref())
                                .await
                            {
                                observer.pass_failed(scope, None, &error);
                            }
                        }
                    }
                    Err(error) => observer.scopes_unavailable(&error),
                }
                sleep_watching_stop(interval, &task_stop).await;
            }
        });
        Self {
            handle: Some(handle),
            stop,
            live,
        }
    }

    /// Whether the sweeper task is still ALIVE.
    ///
    /// The LIVE state, not "was spawned", for the reason [`OutboxWorkerPool::size`] gives:
    /// a task that unwinds is gone and nothing restarts it, so a handle that reported its
    /// own existence would go on claiming a reaper was running with none left. A panicking
    /// [`ScopeSource`] or [`RetentionObserver`] is what gets here.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.live.load(Ordering::Relaxed) > 0
    }

    /// Signal the sweeper to stop and wait for the current pass to finish.
    ///
    /// The flag is read between sweeps, between scopes, and between the CONSUMERS of one
    /// scope, so a shutdown takes at most one interval plus one bounded delete. Nothing is
    /// lost by stopping mid-sweep: retention is idempotent and the rows the pass did not
    /// reach are still there for the next one.
    pub async fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for RetentionSweeper {
    fn drop(&mut self) {
        // A dropped sweeper must not leave a detached task deleting rows behind an
        // operator's back. A caller that needs to WAIT for it uses `shutdown`.
        self.stop.store(true, Ordering::Relaxed);
    }
}
