// SPDX-License-Identifier: MIT OR Apache-2.0

//! One pass of the outbound SCIM sync for one connection (issue #137).
//!
//! # What a pass is, and why it is a function rather than a loop
//!
//! The scheduling half of a worker (which connections, how often, on how many threads) is a
//! deployment question. The half that can corrupt a directory is what happens in ONE pass, and
//! that is what this module is: a single function, driven directly by tests, with the loop left
//! to the caller.
//!
//! # The order of operations is the safety argument
//!
//! Every step here is placed to survive being killed between any two steps, because #137's
//! criterion 3 is exactly that:
//!
//!   1. READ the checkpoint first, and remember it. It is the compare-and-set value the final
//!      write uses, so a second worker that checkpoints in between makes this pass fail rather
//!      than overwrite.
//!   2. PUSH each event's subject downstream BEFORE the checkpoint moves. A crash here re-reads
//!      the same events next pass, and the push is idempotent (the client looks a subject up by
//!      `externalId` first), so a replay converges instead of duplicating.
//!   3. RECORD THE LINK immediately after each successful push, not at the end of the page. A
//!      crash between the push and the link would otherwise lose the downstream id for a resource
//!      that exists, and the next deprovision would have to fall back to a filtered lookup, which
//!      a lagging replica answers with nothing.
//!   4. CHECKPOINT LAST, once, for the whole page.
//!
//! The consequence is at-least-once delivery, which is the only thing a cursor consumer can offer
//! without a distributed transaction across an HTTP boundary. Exactly-once is not available; what
//! makes at-least-once safe is that every downstream write is a converge.

use ironauth_store::{
    EventCursor, EventPage, NewScimPushLink, ScimPushConnection, ScimPushConnectionId,
    ScimPushLinkId, ScimPushResourceType, StoreError,
};

use crate::scim_push_client::{Converged, DeletionPolicy, PushError, ScimPushClient};
use crate::scim_push_events::{
    Collection, Ignored, PushIntent, ScopeDecision, collection_path, intent_for, scope_decision,
};
use crate::scim_push_transport::ScimTransport;

/// What one pass did, so a caller can log it and a test can assert on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    /// Events read from the feed.
    pub read: usize,
    /// Subjects converged downstream.
    pub converged: usize,
    /// Subjects deprovisioned downstream.
    pub deprovisioned: usize,
    /// Events that carried no provisioning meaning.
    pub ignored: usize,
    /// Subjects skipped because they are out of this connection's scope and were never pushed.
    pub out_of_scope: usize,
    /// Whether the checkpoint moved. False when the page was empty or the pass was refused.
    pub checkpointed: bool,
}

/// Why a pass stopped early.
#[derive(Debug)]
pub enum WorkerError {
    /// The store refused something. Includes the compare-and-set losing to another worker, which
    /// is not a fault: it means this connection is somebody else's right now.
    Store(StoreError),
    /// The downstream could not be converged and the failure is worth retrying.
    ///
    /// The cursor is deliberately NOT advanced, so the events stay ahead of the checkpoint.
    Retryable(String),
    /// The downstream refused permanently, or the connection is misconfigured.
    Permanent(String),
}

impl From<StoreError> for WorkerError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<PushError> for WorkerError {
    fn from(error: PushError) -> Self {
        match error {
            PushError::Retryable(why) => Self::Retryable(why),
            PushError::Permanent(why) => Self::Permanent(why),
        }
    }
}

/// What the worker needs to know about a subject, supplied by the caller.
///
/// A trait rather than a store query because the answer differs per collection and per
/// connection: whether a subject is in scope depends on the connection's filter, and the SCIM
/// body depends on its attribute mapping. Keeping it a seam is also what lets this module's tests
/// drive a real downstream and a real database without a full directory behind them.
pub trait SubjectSource {
    /// The SCIM body for a subject, or `None` if it no longer exists.
    ///
    /// # Errors
    ///
    /// Whatever the implementation needs to report; the worker treats it as retryable.
    fn resource(
        &self,
        collection: Collection,
        subject_id: &str,
    ) -> impl Future<Output = Result<Option<serde_json::Value>, String>> + Send;

    /// Whether the subject is inside this connection's scoping filter.
    ///
    /// # Errors
    ///
    /// Whatever the implementation needs to report; the worker treats it as retryable.
    fn in_scope(
        &self,
        collection: Collection,
        subject_id: &str,
    ) -> impl Future<Output = Result<bool, String>> + Send;

    /// The next page of IN-SCOPE subject ids, in a stable order, after `after`.
    ///
    /// # Why the order has to be stable and the caller has to say where it stopped
    ///
    /// #137 requires the backfill to be RESUMABLE, and a resumable enumeration is exactly one
    /// that can be restarted from a recorded position. That needs a total order the source will
    /// not change between passes: an implementation that returned subjects in whatever order the
    /// database found them would make `after` meaningless, and a worker killed halfway would
    /// either repeat people or skip them. Repeating is survivable because a push is a converge;
    /// SKIPPING is not, because nothing would ever come back for them.
    ///
    /// # Errors
    ///
    /// Whatever the implementation needs to report; the worker treats it as retryable.
    fn enumerate(
        &self,
        collection: Collection,
        after: Option<&str>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<String>, String>> + Send;
}

use std::future::Future;

/// Everything one pass needs, so the signature does not grow a dozen arguments.
pub struct Pass<'a, T: ScimTransport, S: SubjectSource> {
    /// The connection being synced.
    pub connection_id: &'a ScimPushConnectionId,
    /// The outbound client, already carrying this connection's base URL and credential.
    pub client: &'a ScimPushClient<T>,
    /// Where the SCIM bodies and the scope answers come from.
    pub subjects: &'a S,
    /// What a departure means for this connection.
    pub deletion_policy: DeletionPolicy,
    /// How many events to read.
    pub limit: i64,
    /// The scope the connection lives in, for minting link ids.
    pub scope: ironauth_store::Scope,
    /// The time this pass is running at, for deciding whether a pause has expired.
    pub now_unix_micros: i64,
}

/// Runs one tailing pass: read a page of events, apply each, checkpoint once.
///
/// # Errors
///
/// [`WorkerError`] as described on its variants. A [`StoreError::NotFound`] from the final
/// checkpoint means another worker moved the cursor while this pass was running, and the correct
/// response is to do nothing: that worker has the connection.
///
/// # Panics
///
/// Never. The `expect` below is on a state row this function has already read.
pub async fn run_tail_pass<T: ScimTransport, S: SubjectSource>(
    store: &ironauth_store::ScopedStore<'_>,
    pass: Pass<'_, T, S>,
) -> Result<Progress, WorkerError> {
    let state = store
        .scim_push_sync_state()
        .get(pass.connection_id)
        .await?
        .ok_or(StoreError::NotFound)?;

    // A PAUSED CONNECTION IS NOT AN ERROR, and it must not advance. #137 says an outage pauses
    // the cursor rather than dropping events, so a pass that arrives during one does nothing at
    // all: it does not read, does not push, and does not checkpoint.
    if is_paused(&state, pass.now_unix_micros) {
        return Ok(Progress::default());
    }

    // TAILING REQUIRES A FINISHED BACKFILL. Reading the feed for a connection that has not
    // enumerated its scope means the first event for an unprovisioned subject creates a resource
    // that the backfill then creates again.
    let Some(cursor_sequence) = state.cursor_sequence else {
        return Err(WorkerError::Permanent(
            "this connection has not finished its backfill, so it must not tail the feed"
                .to_owned(),
        ));
    };
    // THE SEQUENCE RE-ENTERS THE FEED ONLY THROUGH `EventCursor`, never as a number this module
    // does arithmetic on. #107 made the wire cursor opaque so a consumer could not compute
    // `cursor + 1`; storing the sequence gives that up at the column, and keeping the conversion
    // in exactly one place is what recovers it at the boundary.
    let cursor = EventCursor::after_sequence(cursor_sequence);

    let page = match store.outbox().events_page_after(cursor, pass.limit).await? {
        EventPage::Page(events) => events,
        // The consumer's own position has been pruned. Retryable is wrong (it will never come
        // back) and silently restarting is worse (it re-pushes everything), so this is reported
        // and an operator decides whether to re-enumerate.
        EventPage::Gone { oldest_retained } => {
            return Err(WorkerError::Permanent(format!(
                "this connection's position has been pruned from the feed, which now starts at \
                 {oldest_retained}; a backfill restart is needed before it can tail again"
            )));
        }
    };

    let mut progress = Progress {
        read: page.len(),
        ..Progress::default()
    };
    if page.is_empty() {
        // AN EMPTY POLL MOVES last_polled_at AND NOTHING ELSE, which is what lets a health
        // surface tell a quiet feed from a wedged worker.
        store
            .scim_push_sync_state()
            .record_poll(pass.connection_id)
            .await?;
        return Ok(progress);
    }

    let mut last_sequence = None;
    for message in &page {
        let envelope = &message.payload;
        let event_type = envelope
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let payload = envelope.get("payload").unwrap_or(&serde_json::Value::Null);
        apply_one(store, &pass, event_type, payload, &mut progress).await?;
        last_sequence = Some(message.sequence);
    }

    // CHECKPOINT LAST, AND ONLY ONCE. `expected_cursor` is the value read at the top of this
    // function, so a second worker that checkpointed in between makes this fail rather than
    // overwrite its position.
    let next = last_sequence.expect("the page is not empty");
    store
        .scim_push_sync_state()
        .advance(pass.connection_id, Some(cursor_sequence), next)
        .await?;
    progress.checkpointed = true;
    Ok(progress)
}

/// Whether the connection's pause is still running at `now_unix_micros`.
///
/// # Why the time is an argument
///
/// Reading the system clock here would make the pause boundary the one thing in this module a
/// test cannot address: "resumes when the deadline passes" would need a sleep, and "does not
/// resume a microsecond early" would be untestable at all. The caller already knows the time it
/// is running at, so it says so.
const fn is_paused(state: &ScimPushConnection, now_unix_micros: i64) -> bool {
    match state.paused_until_unix_micros {
        Some(until) => until > now_unix_micros,
        None => false,
    }
}

/// Applies one event, recording what it did in `progress`.
async fn apply_one<T: ScimTransport, S: SubjectSource>(
    store: &ironauth_store::ScopedStore<'_>,
    pass: &Pass<'_, T, S>,
    event_type: &str,
    payload: &serde_json::Value,
    progress: &mut Progress,
) -> Result<(), WorkerError> {
    let intent = intent_for(event_type, payload);
    let (collection, subject_id, departing) = match intent {
        PushIntent::Converge {
            collection,
            subject_id,
        } => (collection, subject_id, false),
        PushIntent::Deprovision {
            collection,
            subject_id,
        } => (collection, subject_id, true),
        PushIntent::Ignore(Ignored::MalformedPayload) => {
            // A registered event missing its own required property means a producer and the
            // catalog disagree. Counted, not fatal: one bad row must not stall a page.
            progress.ignored += 1;
            return Ok(());
        }
        PushIntent::Ignore(_) => {
            progress.ignored += 1;
            return Ok(());
        }
    };

    let resource_type = match collection {
        Collection::User => ScimPushResourceType::User,
        Collection::Group => ScimPushResourceType::Group,
    };
    let link = store
        .scim_push_links()
        .find(pass.connection_id, resource_type, &subject_id)
        .await?;

    // SCOPE IS DECIDED BEFORE ANYTHING IS SENT, and the link's presence is half the decision:
    // criterion 4's "never pushed" and "deactivated on leaving" are one rule, not two.
    let in_scope = pass
        .subjects
        .in_scope(collection, &subject_id)
        .await
        .map_err(WorkerError::Retryable)?;
    let decision = scope_decision(in_scope, link.is_some());
    let withdraw = departing || decision == ScopeDecision::Withdraw;
    if decision == ScopeDecision::Skip {
        progress.out_of_scope += 1;
        return Ok(());
    }

    if withdraw {
        let known = link.as_ref().map(|l| l.downstream_id.clone());
        pass.client
            .deprovision(
                collection_path(collection),
                &subject_id,
                pass.deletion_policy,
                known.as_deref(),
            )
            .await?;
        progress.deprovisioned += 1;
        return Ok(());
    }

    let Some(resource) = pass
        .subjects
        .resource(collection, &subject_id)
        .await
        .map_err(WorkerError::Retryable)?
    else {
        // The subject vanished between the event and this read. The next pass will carry its
        // deletion event, so nothing is done here rather than guessing.
        progress.ignored += 1;
        return Ok(());
    };

    let converged = pass
        .client
        .converge(collection_path(collection), &subject_id, &resource)
        .await?;
    let downstream_id = match &converged {
        Converged::Created(id) | Converged::Updated(id) => id.clone(),
        Converged::AlreadyGone => {
            progress.ignored += 1;
            return Ok(());
        }
    };

    // THE LINK IS RECORDED IMMEDIATELY, not at the end of the page. A crash between the push and
    // this write loses the downstream id for a resource that exists, and the next deprovision
    // would fall back to a filtered lookup that a lagging replica answers with nothing.
    let external_id = resource
        .get("externalId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&subject_id)
        .to_owned();
    let id = ScimPushLinkId::generate(&ironauth_env::Env::system(), &pass.scope);
    store
        .scim_push_links()
        .upsert(NewScimPushLink {
            id: &id,
            connection_id: pass.connection_id,
            resource_type,
            subject_id: &subject_id,
            downstream_id: &downstream_id,
            external_id: &external_id,
        })
        .await?;
    progress.converged += 1;
    Ok(())
}

/// Runs one backfill pass: provision the next page of in-scope subjects, and record where it got.
///
/// # Why the feed position is taken BEFORE the enumeration, not after
///
/// A backfill that finished and then read the feed head would lose every event that happened
/// while it was running: those events are behind the new head, and the enumeration may not have
/// seen the change either. Taking the position FIRST means the tail resumes from a point the
/// backfill has already covered, so the overlap is re-applied. Re-applying is free, because every
/// push is a converge; losing is not.
///
/// The caller supplies `feed_position_at_start` for that reason: it is read once, before the
/// first page, and passed to every pass until the last one completes.
///
/// # Errors
///
/// [`WorkerError`] as described on its variants.
pub async fn run_backfill_pass<T: ScimTransport, S: SubjectSource>(
    store: &ironauth_store::ScopedStore<'_>,
    pass: Pass<'_, T, S>,
    collection: Collection,
    feed_position_at_start: i64,
) -> Result<Progress, WorkerError> {
    let state = store
        .scim_push_sync_state()
        .get(pass.connection_id)
        .await?
        .ok_or(StoreError::NotFound)?;
    if is_paused(&state, pass.now_unix_micros) {
        return Ok(Progress::default());
    }
    if !state.backfill_state.is_enumerating() {
        return Err(WorkerError::Permanent(
            "this connection is not enumerating, so a backfill pass has nothing to resume"
                .to_owned(),
        ));
    }

    let limit = usize::try_from(pass.limit).unwrap_or(usize::MAX);
    let subjects = pass
        .subjects
        .enumerate(collection, state.backfill_after_id.as_deref(), limit)
        .await
        .map_err(WorkerError::Retryable)?;

    // AN EMPTY PAGE MEANS THE ENUMERATION IS DONE, and only then does the connection start
    // tailing, from the position that was read before any of this began.
    if subjects.is_empty() {
        store
            .scim_push_sync_state()
            .complete_backfill(pass.connection_id, feed_position_at_start)
            .await?;
        return Ok(Progress {
            checkpointed: true,
            ..Progress::default()
        });
    }

    let mut progress = Progress {
        read: subjects.len(),
        ..Progress::default()
    };
    let mut furthest = None;
    for subject_id in &subjects {
        push_one(store, &pass, collection, subject_id, &mut progress).await?;
        // RECORDED AFTER EACH SUBJECT, so a crash resumes from the last one that actually
        // landed rather than from the start of the page.
        furthest = Some(subject_id.clone());
        store
            .scim_push_sync_state()
            .record_backfill_progress(pass.connection_id, subject_id)
            .await?;
    }
    debug_assert!(furthest.is_some(), "a non-empty page recorded no progress");
    Ok(progress)
}

/// Provisions one subject during a backfill.
async fn push_one<T: ScimTransport, S: SubjectSource>(
    store: &ironauth_store::ScopedStore<'_>,
    pass: &Pass<'_, T, S>,
    collection: Collection,
    subject_id: &str,
    progress: &mut Progress,
) -> Result<(), WorkerError> {
    let Some(resource) = pass
        .subjects
        .resource(collection, subject_id)
        .await
        .map_err(WorkerError::Retryable)?
    else {
        // Enumerated and then deleted. The tail will carry its deletion event.
        progress.ignored += 1;
        return Ok(());
    };
    let converged = pass
        .client
        .converge(collection_path(collection), subject_id, &resource)
        .await?;
    let downstream_id = match &converged {
        Converged::Created(id) | Converged::Updated(id) => id.clone(),
        Converged::AlreadyGone => {
            progress.ignored += 1;
            return Ok(());
        }
    };
    let resource_type = match collection {
        Collection::User => ScimPushResourceType::User,
        Collection::Group => ScimPushResourceType::Group,
    };
    let external_id = resource
        .get("externalId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(subject_id)
        .to_owned();
    let id = ScimPushLinkId::generate(&ironauth_env::Env::system(), &pass.scope);
    store
        .scim_push_links()
        .upsert(NewScimPushLink {
            id: &id,
            connection_id: pass.connection_id,
            resource_type,
            subject_id,
            downstream_id: &downstream_id,
            external_id: &external_id,
        })
        .await?;
    progress.converged += 1;
    Ok(())
}
