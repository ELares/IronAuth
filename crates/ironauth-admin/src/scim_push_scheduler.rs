// SPDX-License-Identifier: MIT OR Apache-2.0

//! The background task that actually runs outbound SCIM connections (issue #137).
//!
//! # Why this file is the difference between shipped and working
//!
//! Everything below it existed and was tested: the client, the mapper, the event translator, the
//! directory, the passes, and `run_due_connections` itself. None of it had a caller in a running
//! server. Every acceptance criterion was satisfied by code a deployment would never execute,
//! which is a milestone that reports itself complete and provisions nobody.
//!
//! # A tick is a QUERY, not a list
//!
//! The scheduler holds no connection state. Each tick asks `due_for_sync` which connections are
//! due right now, and that query is what the pause, the backoff and the operator's switch all
//! act through. A scheduler that cached its connections would keep running one an operator had
//! just disabled, and would keep hammering one that had just been paused.
//!
//! # The secret is resolved PER TICK, not once
//!
//! A downstream credential is rotated at the downstream and then here, in that order, and the
//! window between them is exactly when the connection starts failing. Reading the secret every
//! tick means the fix takes effect on the next one; caching it means an operator updates the
//! secret and nothing changes until a restart.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ironauth_store::outbox::ScopeSource;
use ironauth_store::{
    ScimBackfillState, ScimPushConnection, ScimPushConnectionId, ScimWriteMode, Scope, Store,
    StoreError,
};

use crate::scim_push_client::{ScimPushClient, WriteMode};
use crate::scim_push_directory::PushDirectory;
use crate::scim_push_transport::{FetchScimTransport, ScimTransport};
use crate::scim_push_worker::{Progress, WorkerError, run_due_connections};

/// How many feed events, or enumerated subjects, one pass handles.
///
/// A CEILING ON ONE PASS, not on the work. A connection with more to do is simply due again on
/// the next tick, and every pass checkpoints, so the bound costs latency and never progress.
/// Unbounded pages would let one busy connection hold the tick for as long as its backlog lasts
/// while every other connection in the environment waits.
const DEFAULT_PAGE: i64 = 100;

/// What a caller wants told about each pass.
///
/// # Why the scheduler reports rather than logs
///
/// It runs in a library that must not choose a logging framework for its embedder, and the
/// interesting events here are ones an operator alerts on: a connection that cannot be built at
/// all is invisible on the health surface, because the surface is written by passes that RAN.
pub trait ScimPushObserver: Send + Sync {
    /// A pass finished, successfully or not.
    fn pass_finished(
        &self,
        _scope: Scope,
        _connection: &ScimPushConnectionId,
        _outcome: &Result<Progress, WorkerError>,
    ) {
    }
    /// A due connection could not be prepared, so no pass ran for it.
    ///
    /// SEPARATE FROM A FAILED PASS. A missing secret, an unreadable credential or an unparseable
    /// scope filter means `run_due_connections` skips the connection silently: no pass runs, so
    /// nothing writes `last_error`, and the health surface shows a connection that looks idle.
    /// This is the only place that fact exists.
    fn connection_unavailable(
        &self,
        _scope: Scope,
        _connection: &ScimPushConnectionId,
        _why: &str,
    ) {
    }
    /// The due listing itself failed.
    fn tick_failed(&self, _scope: Scope, _error: &StoreError) {}
    /// The scope enumeration failed, so no scope was served this tick.
    fn enumeration_failed(&self, _error: &StoreError) {}
}

/// An observer that does nothing, for a deployment that only wants the health surface.
pub struct SilentObserver;
impl ScimPushObserver for SilentObserver {}

/// What one tick needs, captured once.
pub struct ScimPushSchedulerInputs {
    /// The data-plane store the passes read and write through.
    pub store: Arc<Store>,
    /// The scopes to serve.
    pub scopes: Arc<dyn ScopeSource>,
    /// The SSRF-hardened fetcher every outbound request goes through.
    pub fetcher: Arc<ironauth_fetch::Fetcher>,
    /// The platform master key, which is what opens a connection's sealed credential.
    ///
    /// PASSED IN RATHER THAN READ OFF THE STORE, because the store's accessor for it is
    /// crate-private: the key reaches the repository layer and nothing else, which is the
    /// property that keeps it out of every other module's reach. A caller that has one already
    /// built the store with it.
    pub master: Arc<ironauth_jose::MasterKey>,
    /// How long between ticks.
    pub interval: Duration,
    /// Where the pass outcomes go.
    pub observer: Arc<dyn ScimPushObserver>,
}

/// The background task that runs due connections on an interval.
pub struct ScimPushScheduler {
    handle: Option<tokio::task::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl ScimPushScheduler {
    /// Spawn the scheduler. Returns immediately; it runs until
    /// [`shutdown`](ScimPushScheduler::shutdown) is awaited or it is dropped.
    #[must_use]
    pub fn spawn(inputs: ScimPushSchedulerInputs) -> Self {
        let ScimPushSchedulerInputs {
            store,
            scopes,
            fetcher,
            master,
            interval,
            observer,
        } = inputs;
        let stop = Arc::new(AtomicBool::new(false));
        let task_stop = Arc::clone(&stop);
        let handle = tokio::spawn(async move {
            while !task_stop.load(Ordering::Relaxed) {
                match scopes.scopes().await {
                    Ok(resolved) => {
                        for scope in resolved {
                            // CHECKED BETWEEN SCOPES, so a shutdown is bounded by one scope's
                            // bounded pass rather than by the whole tick.
                            if task_stop.load(Ordering::Relaxed) {
                                break;
                            }
                            tick(
                                &store,
                                scope,
                                &FetchScimTransport::new(Arc::clone(&fetcher)),
                                &master,
                                observer.as_ref(),
                            )
                            .await;
                        }
                    }
                    Err(error) => observer.enumeration_failed(&error),
                }
                // Slept in short slices so shutdown does not wait out a whole interval.
                let mut slept = Duration::ZERO;
                while slept < interval && !task_stop.load(Ordering::Relaxed) {
                    let slice = Duration::from_millis(200).min(interval.saturating_sub(slept));
                    tokio::time::sleep(slice).await;
                    slept += slice;
                }
            }
        });
        Self {
            handle: Some(handle),
            stop,
        }
    }

    /// Stop the scheduler and wait for the in-flight tick to finish.
    pub async fn shutdown(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for ScimPushScheduler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// One scope's tick: find the due connections, prepare each, run them.
///
/// # The credentials are resolved BEFORE the driver runs, and that is forced
///
/// `run_due_connections` takes a SYNCHRONOUS builder, because building a client from a connection
/// is meant to be a pure function of it. Reading a sealed secret is not: it is a database read and
/// a decryption. So the due listing is read here, each connection's credential is opened, and the
/// builder the driver gets is a lookup in what this function already resolved.
///
/// The cost is that a connection which becomes due BETWEEN the two reads is not served this tick.
/// It is served on the next one, and `due_for_sync` is idempotent, so nothing is lost -- the
/// alternative, holding a decrypted credential across a tick, keeps plaintext alive for the
/// interval to save one round of latency.
/// # Generic over the transport, so the seam is testable
///
/// Production passes [`FetchScimTransport`], which is the SSRF-hardened fetcher and refuses a
/// plaintext target -- correctly, and it is also what made this function untestable end to end:
/// a test would have to stand up TLS to observe anything. Everything this function does that is
/// worth proving is on THIS side of the transport: opening a sealed credential, building the
/// directory, telling an observer about a connection that could not be prepared, and reaching
/// the driver at all. The transport's own suite proves it speaks HTTP.
pub async fn tick<T: ScimTransport + Clone>(
    store: &Store,
    scope: Scope,
    transport: &T,
    master: &ironauth_jose::MasterKey,
    observer: &dyn ScimPushObserver,
) {
    let scoped = store.scoped(scope);
    let env = ironauth_env::Env::system();
    let Ok(now) = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    ) else {
        // Unreachable this side of the year 294247, and an `expect` in a background loop is a
        // process abort. Skipping the tick is the only harmless answer.
        return;
    };
    let due = match scoped
        .scim_push_connections()
        .due_for_sync(now, DEFAULT_PAGE)
        .await
    {
        Ok(due) => due,
        Err(error) => {
            observer.tick_failed(scope, &error);
            return;
        }
    };
    if due.is_empty() {
        return;
    }

    // A CONNECTION HAS TO BE STARTED BEFORE IT CAN RUN, and nothing started one.
    //
    // 0189 creates every connection `backfill_state = 'pending'`, and `run_backfill_pass` refuses
    // a connection that is not enumerating: "this connection is not enumerating, so a backfill
    // pass has nothing to resume". `begin_backfill` had no caller outside tests, so a connection
    // an operator created stayed pending for ever and this scheduler would have provisioned
    // nobody, in every environment, while reporting a clean pass for each one.
    //
    // Started HERE rather than at create time, deliberately. The feed position it captures is the
    // point the tail resumes from, and an operator may create a connection days before enabling
    // the worker: capturing it at create time would make the connection replay every event since,
    // and capturing nothing would make it skip everything that happened in between. The first
    // tick that can actually serve the connection is the only moment where "now" is the right
    // answer.
    // The credential for each due connection, by id, and which ids this tick tried at all.
    let attempted: Vec<ScimPushConnectionId> = due.iter().map(|c| c.id).collect();
    let mut credentials: Vec<(ScimPushConnectionId, String)> = Vec::with_capacity(due.len());
    for connection in &due {
        // THE CONFINEMENT IS ENFORCED AT THE READ, not only at the write.
        //
        // `check_secret_name` refuses a name outside the connection namespace when a connection
        // is created, and that door is the only one the API offers. It is not the only way a row
        // arrives: a config import, a snapshot restore, or a row written before the rule existed
        // all reach this table without passing it. A bound that only holds for rows that came
        // through one door is a bound on that door, and what it is protecting -- the write-only
        // secret store -- is read HERE.
        if !connection
            .credential_secret_name
            .starts_with(crate::scim_push_connections::CREDENTIAL_SECRET_PREFIX)
        {
            observer.connection_unavailable(
                scope,
                &connection.id,
                &format!(
                    "this connection names the secret {:?}, which is outside the {:?} namespace \
                     a connection may read",
                    connection.credential_secret_name,
                    crate::scim_push_connections::CREDENTIAL_SECRET_PREFIX
                ),
            );
            continue;
        }
        match scoped
            .environment_secrets()
            .open_value(master, &connection.credential_secret_name)
            .await
        {
            Ok(value) => match String::from_utf8(value) {
                Ok(token) => credentials.push((connection.id.clone(), token)),
                Err(_) => observer.connection_unavailable(
                    scope,
                    &connection.id,
                    "the secret this connection names is not text, so it cannot be a bearer token",
                ),
            },
            Err(error) => observer.connection_unavailable(
                scope,
                &connection.id,
                &format!(
                    "the secret {:?} this connection names could not be opened: {error:?}",
                    connection.credential_secret_name
                ),
            ),
        }
    }

    // STARTED ONLY FOR A CONNECTION THIS TICK CAN ACTUALLY SERVE, which is why this runs after
    // the credentials and not before them.
    //
    // The head captured here is where the tail resumes, and `begin_backfill` is guarded on
    // `pending` so it is captured exactly once and never again. Stamping it on a tick that then
    // skips the connection -- because its secret is missing, or is not text -- means the position
    // is frozen at a moment nothing was sent, and every event between then and the day an
    // operator fixes the secret is enumerated by the backfill as current state rather than
    // replayed. The comment that used to sit here said "the first tick that can actually serve
    // the connection" while the loop ran before anything that decides whether it can.
    let pending: Vec<&ScimPushConnection> = due
        .iter()
        .filter(|c| c.backfill_state == ScimBackfillState::Pending)
        .filter(|c| credentials.iter().any(|(id, _)| id == &c.id))
        .collect();
    if !pending.is_empty() {
        // READ ONCE PER TICK, not once per connection. The head is a property of the SCOPE's
        // feed, so asking per connection issues the same scope-wide query N times and, worse,
        // gives two connections started in the same tick two different starting positions for no
        // reason. Read only when there is something to start, so an environment with no pending
        // connection pays nothing.
        let head = match scoped.outbox().newest_sequence().await {
            Ok(head) => head,
            Err(error) => {
                observer.tick_failed(scope, &error);
                return;
            }
        };
        // AN EMPTY FEED IS POSITION ZERO, NOT "NO POSITION", and passing the `None` through
        // wedged the connection for ever.
        //
        // `newest_sequence` answers `None` when the scope's feed is empty, which is the ordinary
        // state of a new environment. `begin_backfill` stores it as `backfill_from_sequence`,
        // `complete_backfill` copies that into `cursor_sequence`, and `run_tail_pass` refuses a
        // connection whose cursor is NULL with "this connection has not finished its backfill".
        // So a connection created before the first event in its environment would enumerate its
        // directory once and then never tail, permanently, and no retry would fix it because the
        // backfill would already be `done`.
        //
        // Zero is the position before the first event, which is exactly what an empty feed means
        // and what every test that starts a connection has always passed.
        let head = Some(head.unwrap_or(0));
        for connection in pending {
            if let Err(error) = scoped
                .scim_push_sync_state()
                .begin_backfill(&connection.id, head)
                .await
            {
                observer.connection_unavailable(
                    scope,
                    &connection.id,
                    &format!("this connection's backfill could not be started: {error:?}"),
                );
            }
        }
    }

    let outcomes = run_due_connections(&scoped, scope, now, DEFAULT_PAGE, |connection| {
        let Some(token) = credentials
            .iter()
            .find(|(id, _)| id == &connection.id)
            .map(|(_, token)| token.clone())
        else {
            // TWO DIFFERENT REASONS REACH THIS ARM, and reporting the wrong one is worse than
            // reporting nothing: an operator chasing "became due later" for a connection whose
            // secret is simply missing looks at the scheduler instead of at the secret.
            //
            // A connection this tick already TRIED to resolve was reported by the loop above,
            // with the reason. Only a connection that was not in the first listing at all became
            // due in between.
            if !attempted.iter().any(|id| id == &connection.id) {
                observer.connection_unavailable(
                    scope,
                    &connection.id,
                    "this connection became due after its tick had resolved credentials, so it \
                     is served on the next one",
                );
            }
            return None;
        };
        // A CONNECTION WHOSE FILTER DOES NOT PARSE IS NOT SILENTLY IDLE. The management surface
        // refuses those at write time, so reaching this means one was stored before that check
        // existed; either way an operator has to be told, because no pass will run and nothing
        // else will say so.
        let directory = match PushDirectory::new(&scoped, connection) {
            Ok(directory) => directory,
            Err(error) => {
                observer.connection_unavailable(scope, &connection.id, &error.to_string());
                return None;
            }
        };
        let client = ScimPushClient::new(
            transport.clone(),
            &connection.base_url,
            &token,
            write_mode(connection),
        );
        Some((client, directory, connection.organization_id.to_string()))
    })
    .await;

    match outcomes {
        Ok(outcomes) => {
            for (id, outcome) in &outcomes {
                observer.pass_finished(scope, id, outcome);
            }
        }
        Err(error) => observer.tick_failed(scope, &error),
    }
}

/// The client's write mode, from the connection's stored one.
///
/// Two enums rather than one, and the conversion is here rather than in either of them: the store
/// enum is a persisted vocabulary a migration pins, and the client enum is a protocol choice. A
/// shared type would make a CHECK constraint and an HTTP verb the same declaration.
const fn write_mode(connection: &ScimPushConnection) -> WriteMode {
    match connection.write_mode {
        ScimWriteMode::Patch => WriteMode::Patch,
        ScimWriteMode::Put => WriteMode::Put,
    }
}
