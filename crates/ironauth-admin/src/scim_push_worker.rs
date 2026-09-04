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
    EventCursor, EventPage, NewScimPushLink, ScimBackfillState, ScimPushConnection,
    ScimPushConnectionId, ScimPushLinkId, ScimPushResourceType, StoreError,
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
    /// Subjects the downstream refused PERMANENTLY, recorded against the subject and stepped over.
    ///
    /// A permanent refusal is about one person, not about the connection: a duplicate userName, a
    /// body the downstream will not accept, a policy it enforces. Counting them separately is what
    /// lets a caller tell "this connection is broken" from "these three people are".
    pub refused: usize,
    /// Whether the checkpoint moved. False when the page was empty or the pass was refused.
    pub checkpointed: bool,
}

/// Why a pass stopped early.
#[derive(Debug)]
pub enum WorkerError {
    /// The store refused something. A genuine fault: a database error, a missing state row, a
    /// connection that is out of scope.
    ///
    /// NOT the compare-and-set losing. That has its own variant, because this one is recorded as
    /// a connection failure and pauses the connection.
    Store(StoreError),
    /// This pass lost the checkpoint race to another worker, so its page was already applied.
    ///
    /// SEPARATE FROM `Store` BECAUSE IT IS NOT A FAULT, and treating it as one was a defect that
    /// fed itself. Losing the race answers `StoreError::NotFound`, which reached
    /// `record_connection_failure` like any other store error: the loser wrote
    /// `consecutive_failures + 1`, an error string naming an internal condition, and a doubling
    /// pause -- so two healthy workers on one healthy connection produced a paused connection
    /// whose downstream had never returned anything but success.
    ///
    /// The checkpoint guard makes it compound. It compares `consecutive_failures`, so the failure
    /// the loser records invalidates the checkpoint of every OTHER pass still in flight against
    /// that connection, and each of those records a failure of its own.
    ///
    /// The correct response is to do nothing at all: the work was done, by whoever won.
    Contended,
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

    /// The next page of subject ids, in a stable order, after `after`, IN SCOPE OR NOT.
    ///
    /// # Why this page is not filtered
    ///
    /// It said IN-SCOPE, and that contract could not be implemented. An empty page ends the
    /// collection (see [`run_backfill_pass`]), so a source that honestly filtered a page down to
    /// nothing would announce the enumeration was finished with the rest of the directory
    /// unread -- and every person after that page would be skipped, permanently, which is the
    /// one failure the paragraph below says must not happen. Returning them anyway needs an
    /// unbounded read per page, because the number of rows between here and the next in-scope
    /// subject has no ceiling.
    ///
    /// It went unnoticed because the only implementor was a test double whose enumeration
    /// filtered a whole in-memory map and then took a page, so it could always fill one. A
    /// keyset read over a table cannot.
    ///
    /// So scope is decided per subject, by [`Self::in_scope`], in both passes: the tail already
    /// worked that way, and the backfill now does too.
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
    /// The organization whose directory this connection pushes.
    ///
    /// Compared against the organization an event names, so one organization's departure cannot
    /// reach another's downstream through the environment-wide feed.
    pub organization_id: String,
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
    // A DISABLED CONNECTION DOES NOTHING. `active` is the operator's switch, and neither pass
    // consulted it: a connection an operator had turned off kept pushing to the downstream and
    // kept advancing its cursor, so "disabled" meant only that the management surface said so.
    // Checked after the row is read and before anything is sent, in both passes.
    if !connection_is_active(&state) {
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
        // A PERMANENT REFUSAL IS ABOUT ONE SUBJECT, AND MUST NOT STALL THE PAGE.
        //
        // The first version propagated it with `?`, so the pass returned before the checkpoint and
        // the cursor did not move. The next pass then read the identical page and died on the
        // identical event, for ever: every user create, update and departure sitting behind that
        // one event was never delivered. Worse than idle, it was a request LOOP, because every
        // retry re-pushed the whole page ahead of the poisoned row.
        //
        // The default deletion policy guaranteed it. A group deprovision under `deactivate` is a
        // permanent refusal by construction (RFC 7643 section 4.2 gives Group no `active`), so a
        // connection created without naming a policy wedged on the first group deletion.
        //
        // Recording it against the SUBJECT is what makes stepping over it safe: the failure is
        // visible on the per-resource health surface (criterion 2), which is the surface that
        // exists to answer "which people are failing".
        match apply_one(store, &pass, event_type, payload, &mut progress).await {
            Ok(()) => {}
            Err(WorkerError::Permanent(why)) => {
                record_subject_failure(store, &pass, event_type, payload, &why).await?;
                progress.refused += 1;
            }
            // A RETRYABLE failure still stops the page, and must: the cursor may not advance past
            // work that has not been done, and a downstream that is down will refuse the next
            // subject too. This is the outage path, and pausing is what criterion 3 asks for.
            Err(other) => return Err(other),
        }
        last_sequence = Some(message.sequence);
    }

    // CHECKPOINT LAST, AND ONLY ONCE. Both compared values are read at the top of this function,
    // so a second worker that checkpointed in between makes this fail rather than overwrite its
    // position.
    //
    // The failure count is compared as well as the cursor because the checkpoint CLEARS it, along
    // with the error, its time, and the pause. `record_failure` moves those columns without
    // moving the cursor, so a cursor-only guard could not see it: a pass that began before an
    // outage, ran slowly, and then succeeded against a stale view would erase a pause set while
    // it was in flight and resume into a downstream that was still down.
    let next = last_sequence.expect("the page is not empty");
    // MAPPED HERE, at the ONE call whose `NotFound` means contention rather than a fault. Doing it
    // in `From<StoreError>` would have swallowed every other `NotFound` in the pass -- a missing
    // state row, a connection out of scope -- and called those contention too.
    match store
        .scim_push_sync_state()
        .advance(
            pass.connection_id,
            Some(cursor_sequence),
            state.consecutive_failures,
            next,
            // WHETHER ANYTHING WAS ACTUALLY DELIVERED, which is not the same as whether the pass
            // succeeded. Most pages carry no provisioning signal at all, and a page whose every
            // subject was refused delivered nothing either.
            progress.converged + progress.deprovisioned > 0,
        )
        .await
    {
        Ok(()) => {}
        Err(StoreError::NotFound) => return Err(WorkerError::Contended),
        Err(other) => return Err(WorkerError::Store(other)),
    }
    progress.checkpointed = true;
    Ok(progress)
}

/// Whether an operator has left this connection switched on.
const fn connection_is_active(state: &ScimPushConnection) -> bool {
    state.active
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

/// Records a permanent refusal against the subject the event names.
///
/// # Why this exists at all
///
/// `ScimPushLinkRepo::record_failure` had NO caller outside the tests. Criterion 2 asks for
/// "per-resource errors via the management API", the columns were there, the route publishing
/// them was there, and nothing ever wrote them: the surface reported `last_error: null` for every
/// subject no matter how many times its push had been refused. A health surface fed by nothing is
/// worse than an absent one, because it answers.
///
/// A subject with no link is skipped rather than invented: `record_failure` requires the row, and
/// a refusal for somebody never provisioned has no downstream id to attach to.
async fn record_subject_failure<T: ScimTransport, S: SubjectSource>(
    store: &ironauth_store::ScopedStore<'_>,
    pass: &Pass<'_, T, S>,
    event_type: &str,
    payload: &serde_json::Value,
    why: &str,
) -> Result<(), WorkerError> {
    let (collection, subject_id) = match intent_for(event_type, payload) {
        PushIntent::Converge {
            collection,
            subject_id,
            ..
        }
        | PushIntent::Deprovision {
            collection,
            subject_id,
            ..
        } => (collection, subject_id),
        PushIntent::Ignore(_) => return Ok(()),
    };
    let resource_type = match collection {
        Collection::User => ScimPushResourceType::User,
        Collection::Group => ScimPushResourceType::Group,
    };
    match store
        .scim_push_links()
        .record_failure(pass.connection_id, resource_type, &subject_id, why)
        .await
    {
        Ok(()) => Ok(()),
        // No link means this connection never provisioned the subject, so there is no per-resource
        // row to carry the error. Counted in `refused` regardless, so the pass still reports it.
        Err(StoreError::NotFound) => Ok(()),
        Err(error) => Err(error.into()),
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
    let (collection, subject_id, organization_id, departing) = match intent {
        PushIntent::Converge {
            collection,
            subject_id,
            organization_id,
        } => (collection, subject_id, organization_id, false),
        PushIntent::Deprovision {
            collection,
            subject_id,
            organization_id,
        } => (collection, subject_id, organization_id, true),
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

    // ANOTHER ORGANIZATION'S EVENT IS NOT THIS CONNECTION'S BUSINESS.
    //
    // The feed is ENVIRONMENT-wide and a connection is ORGANIZATION-scoped, so without this a
    // departure in organization B deprovisions that person from organization A's downstream too:
    // one tenant's offboarding reaching another tenant's directory, through a worker that was
    // behaving exactly as written.
    //
    // Only events whose schema NAMES an organization can be filtered here. The plain `user.*`
    // lifecycle events carry none, and those are decided by the connection's scope filter below,
    // which is the mechanism criterion 4 describes.
    if let Some(named) = &organization_id {
        if named != &pass.organization_id {
            progress.out_of_scope += 1;
            return Ok(());
        }
    }

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
    // A LINK THAT HAS BEEN WITHDRAWN IS NOT A PROVISIONED SUBJECT. `scope_decision` reads the
    // link as "this connection provisioned them", and 0190 keeps the row after a withdrawal so a
    // rehire can resolve through it. Reading mere PRESENCE therefore made every later event for a
    // departed subject send another deprovision, for ever.
    let provisioned = link
        .as_ref()
        .is_some_and(|l| l.deprovisioned_at_unix_micros.is_none());
    let decision = scope_decision(in_scope, provisioned);
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
        // RECORDED, so the next event for this subject does not withdraw them again and the
        // per-resource health surface stops reporting a departed person as a healthy success.
        // A subject with no link has nothing to record against, which is the NotFound arm.
        match store
            .scim_push_links()
            .record_deprovision(pass.connection_id, resource_type, &subject_id)
            .await
        {
            Ok(()) | Err(StoreError::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
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
) -> Result<Progress, WorkerError> {
    let state = store
        .scim_push_sync_state()
        .get(pass.connection_id)
        .await?
        .ok_or(StoreError::NotFound)?;
    if is_paused(&state, pass.now_unix_micros) {
        return Ok(Progress::default());
    }
    // A DISABLED CONNECTION DOES NOTHING. `active` is the operator's switch, and neither pass
    // consulted it: a connection an operator had turned off kept pushing to the downstream and
    // kept advancing its cursor, so "disabled" meant only that the management surface said so.
    // Checked after the row is read and before anything is sent, in both passes.
    if !connection_is_active(&state) {
        return Ok(Progress::default());
    }
    // THE STATE CHOOSES THE COLLECTION, not the caller.
    //
    // The first version took `collection` as an argument and completed the whole backfill on the
    // first empty page whatever it had been handed. So a caller that ran Users saw the backfill
    // finish with no group ever provisioned, and one that ran Groups saw it finish with no user:
    // the state machine 0189 designed to distinguish the two halves was decided by a parameter
    // instead, and either order silently truncated the other collection.
    let collection = match state.backfill_state {
        ScimBackfillState::Users => Collection::User,
        ScimBackfillState::Groups => Collection::Group,
        ScimBackfillState::Pending | ScimBackfillState::Done => {
            return Err(WorkerError::Permanent(
                "this connection is not enumerating, so a backfill pass has nothing to resume"
                    .to_owned(),
            ));
        }
    };
    let limit = usize::try_from(pass.limit).unwrap_or(usize::MAX);
    let subjects = pass
        .subjects
        .enumerate(collection, state.backfill_after_id.as_deref(), limit)
        .await
        .map_err(WorkerError::Retryable)?;

    // AN EMPTY PAGE MEANS THE ENUMERATION IS DONE, and only then does the connection start
    // tailing, from the position that was read before any of this began.
    // AN EMPTY PAGE ENDS THIS COLLECTION, not the backfill. Users hand over to groups; only
    // groups finish, and only then does a cursor appear.
    if subjects.is_empty() {
        match collection {
            Collection::User => {
                store
                    .scim_push_sync_state()
                    .begin_group_backfill(pass.connection_id)
                    .await?;
                return Ok(Progress::default());
            }
            Collection::Group => {
                store
                    .scim_push_sync_state()
                    .complete_backfill(pass.connection_id)
                    .await?;
                return Ok(Progress {
                    checkpointed: true,
                    ..Progress::default()
                });
            }
        }
    }

    let mut progress = Progress {
        read: subjects.len(),
        ..Progress::default()
    };
    let mut furthest = None;
    // THE FAILURE COUNT THIS PASS HOLDS, which the first successful record clears to zero. The
    // checkpoint compares it, so carrying the value read at the top of the pass through the whole
    // loop would make every record after the first one lose its own guard.
    let mut expected_failures = state.consecutive_failures;
    for subject_id in &subjects {
        let pushed_before = progress.converged;
        push_one(store, &pass, collection, subject_id, &mut progress).await?;
        // RECORDED AFTER EACH SUBJECT, so a crash resumes from the last one that actually
        // landed rather than from the start of the page.
        furthest = Some(subject_id.clone());
        store
            .scim_push_sync_state()
            .record_backfill_progress(
                pass.connection_id,
                subject_id,
                expected_failures,
                // WHETHER THIS SUBJECT REACHED THE DOWNSTREAM. `push_one` returns Ok without
                // sending anything when the subject was deleted between the enumeration and the
                // read, or when the downstream already has no copy of it.
                progress.converged > pushed_before,
            )
            .await?;
        expected_failures = 0;
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
    // SCOPE IS DECIDED HERE, per subject, exactly as the tail decides it. The enumeration hands
    // over its page unfiltered because filtering it can empty a page while the directory still
    // has people in it, and an empty page ends the collection.
    if !pass
        .subjects
        .in_scope(collection, subject_id)
        .await
        .map_err(WorkerError::Retryable)?
    {
        progress.out_of_scope += 1;
        return Ok(());
    }
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

/// Runs one pass for every connection in `scope` that is due, and records what happened.
///
/// # Why this exists, and what it closes
///
/// [`run_tail_pass`] and [`run_backfill_pass`] had NO caller outside the tests. Issue #137's
/// criteria 1, 3 and 4 were therefore satisfied by code that nothing ran: the suites called those
/// functions directly, which is exactly why they passed and exactly why they proved less than
/// they appeared to. The repository has a `dormant-module-scan` gate for that shape and it failed
/// on this module.
///
/// This is the seam between the passes and a deployment. It decides WHICH pass a connection needs
/// from its own stored state, so no caller can run the wrong one, and it is where a failure turns
/// into a recorded pause rather than a log line nobody reads.
///
/// # The backoff, and why a failure has to be written down
///
/// A retryable failure pauses the connection for a bounded, growing interval. That is the whole
/// mechanism behind #137's "a downstream outage pauses the cursor rather than dropping events":
/// the cursor stays where it is, the connection is skipped until its deadline passes, and the
/// deadline clears itself so an outage that ends unattended recovers with no intervention.
///
/// Before this, `record_failure` was called by nothing in `src`, so `consecutive_failures` stayed
/// zero, `paused_until` stayed NULL, and criterion 2's health surface reported a healthy
/// connection through an outage of any length.
///
/// # Errors
///
/// [`StoreError`] if the due listing itself cannot be read. A failure on one CONNECTION is
/// recorded against that connection and does not stop the others: one downstream being unreachable
/// is not a reason to stop syncing every other customer.
pub async fn run_due_connections<T, S, F>(
    store: &ironauth_store::ScopedStore<'_>,
    scope: ironauth_store::Scope,
    now_unix_micros: i64,
    limit: i64,
    mut build: F,
) -> Result<Vec<(ScimPushConnectionId, Result<Progress, WorkerError>)>, StoreError>
where
    T: ScimTransport,
    S: SubjectSource,
    F: FnMut(&ScimPushConnection) -> Option<(ScimPushClient<T>, S, String)>,
{
    let due = store
        .scim_push_connections()
        .due_for_sync(now_unix_micros, limit)
        .await?;

    let mut outcomes = Vec::with_capacity(due.len());
    for connection in due {
        // The caller supplies the client and the directory for THIS connection, because both
        // depend on its own configuration: its base URL, the secret its credential lives in, and
        // the scope filters that decide who is in it. Returning `None` means the caller could not
        // build them, which is a configuration problem rather than a sync failure.
        let Some((client, subjects, organization_id)) = build(&connection) else {
            continue;
        };
        let pass = Pass {
            connection_id: &connection.id,
            client: &client,
            subjects: &subjects,
            deletion_policy: connection.deletion_policy,
            limit,
            scope,
            now_unix_micros,
            organization_id,
        };
        let outcome = if connection.backfill_state.is_done() {
            run_tail_pass(store, pass).await
        } else {
            run_backfill_pass(store, pass).await
        };
        if let Err(error) = &outcome {
            record_connection_failure(store, &connection, error, now_unix_micros).await?;
        }
        outcomes.push((connection.id.clone(), outcome));
    }
    Ok(outcomes)
}

/// The backoff ceiling, so a long outage does not push a connection's next attempt past the point
/// where anybody is still watching.
const MAX_BACKOFF_MICROS: i64 = 15 * 60 * 1_000_000;

/// Records a connection-level failure and pauses it for a growing interval.
async fn record_connection_failure(
    store: &ironauth_store::ScopedStore<'_>,
    connection: &ScimPushConnection,
    error: &WorkerError,
    now_unix_micros: i64,
) -> Result<(), StoreError> {
    let (why, pause) = match error {
        // A PERMANENT failure is not a backoff candidate: retrying reproduces it exactly, and a
        // pause would only delay the moment an operator sees it. Recorded without one, so the
        // health surface shows the reason and the connection keeps being picked up.
        WorkerError::Permanent(why) => (why.clone(), None),
        WorkerError::Retryable(why) => (why.clone(), Some(())),
        WorkerError::Store(error) => (format!("the store refused the pass: {error:?}"), Some(())),
        // NOT RECORDED AT ALL. Another worker checkpointed this connection's page; nothing failed,
        // and the health surface must not say something did.
        WorkerError::Contended => return Ok(()),
    };
    let deadline = pause.map(|()| {
        // Doubling from a second, capped. `consecutive_failures` is the count BEFORE this failure,
        // so the first outage waits one second rather than none.
        let exponent = u32::try_from(connection.consecutive_failures)
            .unwrap_or(u32::MAX)
            .min(20);
        let micros = 1_000_000_i64.saturating_mul(1_i64 << exponent.min(20));
        now_unix_micros.saturating_add(micros.min(MAX_BACKOFF_MICROS))
    });
    store
        .scim_push_sync_state()
        .record_failure(&connection.id, &why, deadline)
        .await
}
