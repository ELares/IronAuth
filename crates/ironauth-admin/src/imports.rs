// SPDX-License-Identifier: MIT OR Apache-2.0

//! The streaming bulk-import JOB surface (issue #55).
//!
//! `POST .../imports` creates a migration run and streams a newline-delimited identity
//! record set into it; `POST .../imports/{run_id}` resumes that run with more records.
//! Together they are the write half the import engine never had: before this, both
//! `ironauth_import::import_stream` and `ironauth_import::import_into_run` existed, were
//! tested, and had ZERO production callers, so nothing that ships could perform an
//! import at all.
//!
//! The body is the SAME format `GET .../export` emits (issue #58), one JSON record per
//! line, so an export re-imports here byte for byte.
//!
//! # Three properties, and why the shape is what it is
//!
//! ## Streaming, at the transport as well as in the engine
//!
//! The body is read ONE FRAME AT A TIME through [`BodyLines`] and handed to
//! `ironauth_import::import_lines_into_run` as a pull source, so nothing between the
//! socket and the `INSERT` holds more than one record plus one frame. axum's `Bytes`
//! extractor (which every other write on this surface uses) buffers the WHOLE body
//! before the handler runs, which for a 100k-record upload is the exact allocation the
//! acceptance criterion forbids. A single line is capped at [`MAX_LINE_BYTES`], so a
//! body carrying no newline at all cannot grow the reader without bound either.
//!
//! A body that cannot be read to the end (a line over the cap, or a transport failure
//! mid-upload) TRUNCATES the record set rather than damaging one record, so it is the one
//! input condition these handlers refuse outright: `400`, naming the cause and the run to
//! resume. Everything the reader did deliver stays durable and accounted. Recording the
//! fault and answering `202` anyway (which the first cut did) tells a caller its upload
//! finished when most of it was never seen.
//!
//! ## Resumable, keyed on the record and not on a position
//!
//! There is no byte offset, no page token, and no server-side cursor into the caller's
//! file, and that is a decision rather than an omission. A resume RE-PRESENTS records,
//! and both layers absorb it: a record whose id, external id, or login handle already
//! exists in the scope is refused by the scope's unique constraints and reported as an
//! idempotent SKIP, and the run's ledger accounts every record under its LOGIN HANDLE
//! with an `ON CONFLICT DO NOTHING`, so re-presenting an already-accounted record adds no
//! second row. The caller may therefore resume from anywhere, including from the very
//! beginning, and neither duplicate nor lose a record. A byte offset would be strictly
//! weaker: it is only correct if the caller can compute exactly where the kill landed,
//! which a killed caller generally cannot.
//!
//! The handle and not the id or the external id, because only the handle is REQUIRED:
//! a key drawn from an optional field is stable only while the SOURCE is unedited, and the
//! recovery procedure this surface documents is to post the source again, which an
//! operator will do from whatever export they have now. See `ironauth_import::run` for
//! the two keys that were measured breaking.
//!
//! The ledger IS the durable cursor, and it is readable: `GET .../migration-runs/{run_id}`
//! reports `accounted` against the declared `source_total`, which is how far the job has
//! got.
//!
//! One condition still leaves a run unable to finish, and it is not an interruption: a
//! source carrying TWO records under one login handle is one ledger subject, so it writes
//! one row against a `source_total` of two and the count invariant can never be satisfied.
//! That is a defect in the source rather than in the job, and the way out is
//! `POST .../migration-runs/{run_id}/abandon`, which records an audited, operator-supplied
//! reason. Nothing else on this plane can move a run's declared ground truth: migration
//! 0101 withholds `UPDATE (source_total)` and `DELETE` from the control role deliberately.
//!
//! ## Progress is the surface that already exists
//!
//! These handlers answer `202 Accepted` with a JOB HANDLE (the run id and where to read
//! it) and NO counters. The counters live on the migration-run operator view (issue #59)
//! that shipped before this, and there is exactly one projection of them.
//!
//! That is not only tidiness. The `Idempotency-Key` record must commit in the SAME
//! transaction as the write it guards, and the response body is what gets stored under
//! the key, so the body has to be fully known BEFORE the import runs. A counter in the
//! body is a body that cannot be known before the import runs, so it would force the key
//! record into a transaction of its own, which is the un-joined two-write shape issue
//! #247 exists to refuse. The handle is knowable at run-creation time, so it commits with
//! the run.
//!
//! # What a replay does
//!
//! Replaying the create under the same key returns the same run id and does NOT create a
//! second run. It does not re-stream the body (the stored response is returned before any
//! body is read), so a caller who wants to resume calls the resume route with that run
//! id, which is what the handle tells them to do. The resume route requires no key: it is
//! idempotent by construction, exactly as `POST .../admin/sudo/elevate` documents for the
//! same reason, and requiring one would mean a killed caller had to invent a fresh key
//! per attempt to be allowed to retry at all.
//!
//! # Trait-schema validation is NOT bypassed here
//!
//! The engine validates every imported traits document against the target scope's ACTIVE
//! trait schema when the scope HAS one (issue #53, PR 1), failing the offending RECORD
//! and no other. This surface adds no second path around that: it drives the same
//! `import_lines_into_run` the engine tests drive. The one documented carve-out is
//! unchanged and belongs to the exit covenant: a scope with NO active schema validates
//! nothing, because a full export must re-import losslessly into a fresh instance that
//! has registered no schema.
//!
//! # One input shape, deliberately
//!
//! The route accepts the first-party line-delimited record format ONLY. It does not
//! accept a Keycloak realm export, an Auth0 bulk export, or a Firebase `auth:export`,
//! even though `ironauth-importers` parses all three.
//!
//! The reason is the THREAT MODEL and nothing else: a vendor-shaped route puts a second
//! parser of attacker-supplied documents on the network surface, and those parsers consume
//! whole documents rather than a line at a time, so they also give up this route's memory
//! bound. Wiring the vendor front-ends to a transport is its own change with its own
//! threat model; it is not smuggled into the job surface.
//!
//! What must NOT be claimed is that a vendor route would buy no capability, because that
//! is false twice over. `ironauth-importers` today has no dependent in the shipped graph
//! (its only reverse dependency is its own fuzz harness), no `[[bin]]`, and no
//! command-line entry point, so there is nothing shipped that an operator could run to
//! produce the translated output this route accepts: the translator is TRANSPORT-LESS, and
//! any instruction to "pipe its output here" names a program that does not exist. And
//! `ironauth_importers::gap` reports the issue-#57 validation-only gap, which is a fact
//! about the VENDOR document (which of its records this instance would refuse, and why)
//! that the line-delimited format structurally cannot carry. Both are real capabilities
//! this route does not have. They are deferred, not absent by design.

use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use bytes::Bytes;
use http_body_util::BodyExt;
use ironauth_import::{ImportContext, LineSource, import_lines_into_run};
use ironauth_store::{
    ActorRef, CorrelationId, IdempotencyWrite, MigrationKind, MigrationRunId, MigrationState,
    NewMigrationRun, Scope, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::response::json;
use crate::state::AdminState;

/// The largest single import LINE the reader will assemble, in bytes.
///
/// A record is one JSON object on one line; the biggest legitimate one carries a traits
/// document, a claims document, and a credential registry, which is kilobytes. The cap is
/// generous against that and still bounds the reader: without it, a body with no newline
/// in it would grow the pending-line buffer to the size of the upload, which is precisely
/// the allocation streaming the body exists to avoid. A line over the cap fails the whole
/// request rather than the record, because a reader that has lost the line boundary
/// cannot tell where the next record starts.
const MAX_LINE_BYTES: usize = 1 << 20;

/// The largest `source_total` a run may declare.
///
/// It is the caller's assertion about a data set, not a measurement of one, so it is
/// bounded like any other caller-supplied number. Ten million is far above the 100k the
/// issue names and far below anything that would overflow the ledger's `i64` arithmetic.
const MAX_SOURCE_TOTAL: i64 = 10_000_000;

/// The query parameters of the import-create endpoint.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CreateImportQuery {
    /// The number of records the SOURCE holds: the ground truth the run reconciles
    /// against. Required, and taken as a string so a malformed value is a precise 400
    /// rather than a framework rejection.
    pub source_total: String,
}

/// The handle a bulk-import job answers with (issue #55).
///
/// Deliberately counter free: progress belongs to the migration-run operator view (issue
/// #59) and is read at `progress_path`. See this module's header for why that is also
/// what lets the `Idempotency-Key` record share a transaction with the run creation.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportJobView {
    /// The migration run this import feeds (an `mgr_` id). Resume by posting more
    /// records to `.../imports/{run_id}`.
    pub run_id: String,
    /// The declared ground-truth source record count the run reconciles against.
    pub source_total: i64,
    /// Where to read this job's live progress: the run's state, its per-outcome record
    /// counts (`imported`, `failed`, `skipped`, `inconsistent`, `unmarked_backfill`, and
    /// their `accounted` sum), and the live invariant evaluations with the blocking ones
    /// named. The ONE projection of those numbers. How far the job has to go is
    /// `source_total` less `accounted`, both of which that view publishes; there is no
    /// separate `processed` or `remaining` field, and this description said there was.
    pub progress_path: String,
}

/// Why a body stopped yielding lines before it ended.
///
/// It is an OUTCOME of the read, not a log line: the handler answers with it, so a caller
/// whose upload was truncated learns that it was. [`BodyLines::fault`] records what
/// happened while it was written and never read.
#[derive(Debug, Clone)]
struct BodyFault {
    /// An operator-safe explanation.
    message: String,
}

/// Read an `application/x-ndjson` request body ONE FRAME AT A TIME, yielding complete
/// lines, so the transport holds one frame plus one pending line and never the body.
struct BodyLines {
    body: Body,
    /// The bytes of the line currently being assembled (never more than
    /// [`MAX_LINE_BYTES`]).
    pending: Vec<u8>,
    /// The most recent frame, and how far into it the reader has consumed.
    frame: Bytes,
    at: usize,
    /// Whether the body has yielded its last frame.
    drained: bool,
    /// Set when the body errored or a line exceeded the cap. The reader then yields
    /// nothing more, and because the cell is SHARED with the handler, the handler reads it
    /// after the stream drains and REFUSES the request.
    ///
    /// The first cut kept the fault private to the reader, where nothing ever read it. A
    /// truncated upload was then indistinguishable from a finished one: MEASURED with one
    /// good record, an oversized line, and four more good records against a declared
    /// `source_total` of 6, the caller got `202 Accepted` and one user, with no signal
    /// anywhere that five records had been dropped on the floor. The same silent path
    /// absorbed a mid-upload TRANSPORT error, which is the common production case.
    fault: Arc<OnceLock<BodyFault>>,
}

impl LineSource for BodyLines {
    /// The next complete line's bytes, or [`None`] at end of body (or after a fault).
    ///
    /// A trailing line with no final newline is yielded; a blank line is yielded too and
    /// the engine treats it as the benign separator it is. The bytes are handed over
    /// UNDECODED: the engine owns the UTF-8 decision, because only the engine can fail one
    /// RECORD. Decoding lossily here (which the first cut did) turned a Latin-1 login
    /// handle into one carrying U+FFFD, imported it, counted it as a success, and produced
    /// an account nobody can log in to, with no error anywhere (MEASURED).
    async fn next_line(&mut self) -> Option<Vec<u8>> {
        self.read_line().await
    }
}

impl BodyLines {
    fn new(body: Body, fault: Arc<OnceLock<BodyFault>>) -> Self {
        Self {
            body,
            pending: Vec::new(),
            frame: Bytes::new(),
            at: 0,
            drained: false,
            fault,
        }
    }

    /// Record the first fault and stop the reader.
    fn fail(&mut self, message: String) -> Option<Vec<u8>> {
        // `set` fails only if a fault is already recorded, and the FIRST one is the cause.
        let _ = self.fault.set(BodyFault { message });
        None
    }

    /// The line reader itself; [`LineSource::next_line`] is the trait face of it.
    async fn read_line(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.fault.get().is_some() {
                return None;
            }
            // Consume from the frame in hand first.
            if self.at < self.frame.len() {
                let rest = &self.frame[self.at..];
                if let Some(index) = rest.iter().position(|byte| *byte == b'\n') {
                    if self.pending.len() + index > MAX_LINE_BYTES {
                        return self.fail(format!(
                            "an import line exceeded the {MAX_LINE_BYTES} byte cap"
                        ));
                    }
                    self.pending.extend_from_slice(&rest[..index]);
                    self.at += index + 1;
                    return Some(self.take_pending());
                }
                if self.pending.len() + rest.len() > MAX_LINE_BYTES {
                    return self.fail(format!(
                        "an import line exceeded the {MAX_LINE_BYTES} byte cap"
                    ));
                }
                self.pending.extend_from_slice(rest);
                self.at = self.frame.len();
            }
            if self.drained {
                // End of body: a trailing line with no newline is still a record.
                if self.pending.is_empty() {
                    return None;
                }
                return Some(self.take_pending());
            }
            match self.body.frame().await {
                None => self.drained = true,
                Some(Err(error)) => {
                    return self.fail(format!("the import body could not be read: {error}"));
                }
                Some(Ok(frame)) => {
                    // A trailer frame carries no data; skip it and keep pulling.
                    self.frame = frame.into_data().unwrap_or_else(|_| Bytes::new());
                    self.at = 0;
                }
            }
        }
    }

    /// Take the assembled line's bytes.
    fn take_pending(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }
}

/// Resolve and authorize the `(tenant, environment)` scope from the path (issue #55). The
/// operator passes; a management key must be scoped to exactly this environment
/// (otherwise the LOUD wrong-scope error). A malformed tenant or environment id is the
/// uniform not-found.
async fn resolve_scope(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ActorRef), ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(state.bootstrap_operator_id(), tenant)
        .parse_id(environment_id)?;
    // Issue #185: the caller's OPERATOR fences the pair. `tenants` and `environments`
    // sit ABOVE row-level security (RLS fences the pair these tables define), so without
    // this a caller naming another operator's tenant reached that tenant's environments
    // and everything under them: measured returning another operator's organization
    // document in full.
    //
    // ADDRESSABILITY, not liveness. A soft-deleted environment must stay readable (see
    // `EnvironmentAccess`), so this asks only whether the pair exists under this
    // operator; whether it is live is each endpoint's own question.
    if !state
        .store()
        .management()
        .environments(state.bootstrap_operator_id(), tenant)
        .exists_in_any_state(&environment)
        .await
        .map_err(|_| ApiError::Internal)?
    {
        return Err(ApiError::NotFound);
    }
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// Normalize the declared source total, or a precise 400.
fn parse_source_total(raw: &str) -> Result<i64, ApiError> {
    let parsed: i64 = raw.trim().parse().map_err(|_| {
        ApiError::BadRequest("source_total must be a non-negative integer".to_owned())
    })?;
    if !(0..=MAX_SOURCE_TOTAL).contains(&parsed) {
        return Err(ApiError::BadRequest(format!(
            "source_total must be between 0 and {MAX_SOURCE_TOTAL}"
        )));
    }
    Ok(parsed)
}

/// The progress endpoint for a run: the one place its counters are published.
fn progress_path(scope: Scope, run_id: &MigrationRunId) -> String {
    format!(
        "/v1/tenants/{}/environments/{}/migration-runs/{run_id}",
        scope.tenant(),
        scope.environment()
    )
}

/// Stream `body` into `run_id`, then move the run as far towards completion as its
/// invariants allow.
///
/// The completion attempt is here rather than on a route of its own because a job that
/// can never finish is not a job. When every declared source record is accounted the run
/// goes `running -> reconciling` and the GATED completion re-evaluates every invariant
/// LIVE under the run's row lock; when it is not, the run is left `running` and the next
/// resume continues it. A blocked completion is not an error (the operator reads which
/// invariant blocked on the progress view), so neither the transition nor the attempt can
/// turn a successful import into a failed request.
///
/// A BODY FAULT is a different matter and IS an error. A line over the cap or a transport
/// failure mid-upload truncates the record set, and answering `202` to a truncated upload
/// tells the caller its records are durable when most of them were never seen. The
/// refusal comes AFTER the drain, so everything the reader did deliver is already
/// committed and accounted, and the message names the run to resume: the records are not
/// lost, the caller is simply told the truth about where it got to.
async fn stream_into_run(
    state: &AdminState,
    scope: Scope,
    actor: ActorRef,
    run_id: &MigrationRunId,
    body: Body,
) -> Result<(), ApiError> {
    let context = ImportContext {
        store: state.store(),
        scope,
        env: state.env(),
        actor,
    };
    let fault: Arc<OnceLock<BodyFault>> = Arc::new(OnceLock::new());
    let lines = BodyLines::new(body, Arc::clone(&fault));
    import_lines_into_run(&context, run_id, lines).await?;
    if let Some(fault) = fault.get() {
        return Err(ApiError::BadRequest(format!(
            "{}; the records delivered before it are durable and accounted in run \
             {run_id}, which you may resume",
            fault.message
        )));
    }

    // Everything below is best effort ADVANCEMENT of the state machine, never a gate on
    // the import that already happened: the records are durable, and a run left short of
    // completion is exactly the resumable state this surface exists to serve.
    let accounted = state
        .store()
        .scoped(scope)
        .migration_runs()
        .tallies(run_id)
        .await?
        .accounted;
    let source_total = state
        .store()
        .scoped(scope)
        .migration_runs()
        .get(run_id)
        .await?
        .source_total;
    if accounted < source_total {
        return Ok(());
    }
    let runs = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()));
    if runs
        .migration_runs()
        .transition(state.env(), run_id, MigrationState::Reconciling)
        .await
        .is_ok()
    {
        // A blocked completion leaves the run in `reconciling` with nothing written; the
        // operator reads the blocking invariants from the progress view.
        let _ = runs
            .migration_runs()
            .try_complete(state.env(), run_id)
            .await;
    }
    Ok(())
}

/// Start a streaming bulk identity import.
///
/// Creates a migration run declaring `source_total` as the ground truth its invariants
/// reconcile against, then streams the newline-delimited request body into it, creating
/// each identity through the same audited, isolation-scoped, schema-validated admin
/// create path `POST .../users` uses.
///
/// The response is the job HANDLE and carries no counters: progress is read from the
/// migration-run view the handle names. Answering `202 Accepted` rather than `200` is
/// literal: the records this call ingested are durable, but the JOB may well be
/// unfinished, and the next call is a resume.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/imports",
    operation_id = "createIdentityImport",
    tag = "imports",
    request_body(
        content = String,
        description = "Newline-delimited identity records (application/x-ndjson), one JSON \
         object per line, in exactly the format `exportIdentities` emits. Read one frame at \
         a time: the body is never buffered whole, so a 100k-record upload holds one record \
         at a time. A single line may not exceed 1 MiB.",
        content_type = "application/x-ndjson"
    ),
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        CreateImportQuery,
        ("Idempotency-Key" = String, Header, description = "Required. Stored in the SAME \
         transaction as the run creation, so a replay returns the ORIGINAL run id and never \
         creates a second run. A replay does not re-stream the body; resume by posting the \
         remaining records to `.../imports/{run_id}`.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 202, description = "The import job handle. The records carried by THIS \
         request are durable; the job may be unfinished, and progress is read at \
         `progress_path`.", body = ImportJobView),
        (status = 400, description = "A malformed or out-of-range source_total, a missing \
         Idempotency-Key, or a body that could not be read to the end (a line over the 1 \
         MiB cap, or a transport failure mid-upload). In the last case the run was created \
         and the records delivered before the fault ARE durable and accounted: the error \
         names the run id to resume.", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or soft-deleted", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_identity_import(
    State(state): State<AdminState>,
    principal: Principal,
    uri: Uri,
    headers: HeaderMap,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<CreateImportQuery>,
    body: Body,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_users`.
    // USER authority: an import PROVISIONS identities in bulk.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteUsers)?;
    // A bulk import writes identities, credential material, and MFA enrollments straight
    // into an environment, which is at least as security relevant as any single admin
    // user write, so it demands fresh privilege exactly like them.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let source_total = parse_source_total(&query.source_total)?;

    let key = idempotency::required_key(&headers)?;
    // The fingerprint covers the method, the path, and the declared source total, and NOT
    // the body: the body is a stream this handler must not buffer, and hashing it would
    // require exactly the whole-body allocation the job exists to avoid. What the key
    // guards is the creation of a run, and the run is fully described by the path and the
    // source total. Every downstream write is idempotent on the record key, so a replay
    // that carried different records would be a resume rather than a duplication.
    let fingerprint =
        idempotency::fingerprint("POST", uri.path(), source_total.to_string().as_bytes());
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // The environment must exist and be live (issues #443, #451), AFTER the replay so a
    // genuine retry of a create that already succeeded still returns its original handle.
    crate::org_context::require_live_environment(&state, &scope).await?;

    // The run id is minted HERE, before the write, so the whole response is known and can
    // be stored under the Idempotency-Key IN THE SAME transaction as the run row and its
    // audit row. That is what `create_with_id` exists for: the plain `create` mints its
    // own id and returns it, which is one round trip too late for a joined key record.
    let created_at_micros = state.now_unix_micros();
    let run_id = {
        let minted = MigrationRunId::generate(state.env(), &scope);
        let view = ImportJobView {
            run_id: minted.to_string(),
            source_total,
            progress_path: progress_path(scope, &minted),
        };
        let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
        let write = IdempotencyWrite {
            credential_ref: &credential_ref,
            key: &key,
            request_fingerprint: &fingerprint,
            response_status: 202,
            response_body: &body_string,
        };
        let pending = identity_import_event(&state, scope, &minted.to_string(), None);
        match state
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(state.env()))
            .migration_runs()
            .create_with_id_with_event(
                state.env(),
                &minted,
                NewMigrationRun {
                    kind: MigrationKind::BulkImport,
                    source_total,
                    // Every ledger row this job writes is marked accounted, so requiring
                    // the sentinel to see `source_total` marked records is a SECOND live
                    // gate on the same ground truth rather than a vacuous one.
                    backfill_expected: source_total,
                    subject_ref: None,
                },
                created_at_micros,
                Some(write),
                pending
                    .as_ref()
                    .map(crate::events::PendingEvent::domain_event)
                    .as_ref(),
            )
            .await
        {
            Ok(()) => minted,
            Err(StoreError::IdempotencyConflict) => {
                return idempotency::replay_after_conflict(
                    &state,
                    &credential_ref,
                    &key,
                    &fingerprint,
                )
                .await;
            }
            Err(error) => return Err(error.into()),
        }
    };

    // `defined -> validating -> running`: the state machine's own edges, taken before any
    // record is ingested because `ingest_outcomes` refuses a terminal run and the ledger
    // belongs to a run that has started.
    for state_to in [MigrationState::Validating, MigrationState::Running] {
        state
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(state.env()))
            .migration_runs()
            .transition(state.env(), &run_id, state_to)
            .await?;
    }

    stream_into_run(&state, scope, actor, &run_id, body).await?;

    let view = ImportJobView {
        run_id: run_id.to_string(),
        source_total,
        progress_path: progress_path(scope, &run_id),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::ACCEPTED, body_string))
}

/// Resume a streaming bulk identity import.
///
/// Streams more newline-delimited records into an EXISTING run. Safe to call with records
/// the run has already imported, which is the point: a caller resuming after a kill
/// generally cannot know where it landed, so it may re-present anything, including the
/// whole source. A record already present in the scope is an idempotent skip, and a
/// record already accounted in this run adds no second ledger row.
///
/// No `Idempotency-Key` is required, for the same reason `elevateAdminSudo` requires
/// none: the operation is idempotent by construction, and requiring a key would mean a
/// killed caller had to mint a fresh one per attempt merely to be allowed to retry.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/imports/{run_id}",
    operation_id = "resumeIdentityImport",
    tag = "imports",
    request_body(
        content = String,
        description = "Newline-delimited identity records (application/x-ndjson), the same \
         format the create takes. May safely repeat records the run already imported.",
        content_type = "application/x-ndjson"
    ),
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("run_id" = String, Path, description = "The migration run to resume"),
        ("Idempotency-Key" = Option<String>, Header, description = "Optional. Resuming is \
         idempotent by construction, so a retry needs no key.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 202, description = "The import job handle; progress is read at `progress_path`", body = ImportJobView),
        (status = 400, description = "The body could not be read to the end (a line over \
         the 1 MiB cap, or a transport failure mid-upload). The records delivered before \
         the fault are durable and accounted.", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The run does not exist in this scope, or the environment is absent or soft-deleted", body = ErrorBody),
        (status = 409, description = "The run is already complete or abandoned; a terminal \
         run cannot be resumed, and the refusal happens BEFORE any identity is created", body = ErrorBody)
    )
)]
pub async fn resume_identity_import(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, run_id)): Path<(String, String, String)>,
    body: Body,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_users`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteUsers)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    crate::org_context::require_live_environment(&state, &scope).await?;
    // A malformed or cross-scope run id is the uniform not-found, exactly as the
    // migration-run reads answer it.
    let run_id = MigrationRunId::parse_in_scope(&run_id, &scope).map_err(|_| ApiError::NotFound)?;
    let run = state
        .store()
        .scoped(scope)
        .migration_runs()
        .get(&run_id)
        .await?;
    if run.kind != MigrationKind::BulkImport {
        // A run wrapping a different workload is not an import job, and answering
        // anything but the uniform not-found here would make this route an oracle for
        // which runs exist and what they wrap.
        return Err(ApiError::NotFound);
    }
    // A TERMINAL run is refused HERE, before a single identity is created. The refusal
    // used to arrive from `ingest_outcomes` at the first batch FLUSH, which is up to
    // `INGEST_BATCH` audited `admin_create` calls too late: MEASURED, resuming a
    // `complete` run with five records answered 409 and took the environment from one user
    // to SIX, every one of them accounted in no ledger anywhere, because the ledger write
    // is what refused and the creates had already committed. A run's terminal state is
    // known from the row already read; nothing is written before it is checked.
    if run.state.is_terminal() {
        return Err(ApiError::Conflict(format!(
            "run {run_id} is {} and cannot be resumed",
            run.state.as_str()
        )));
    }
    // A run that has been driven to `reconciling` (by a previous call that accounted
    // every declared record but could not complete) takes the state machine's own back
    // edge before more records are ingested.
    if run.state == MigrationState::Reconciling {
        let pending = identity_import_event(
            &state,
            scope,
            &run_id.to_string(),
            Some(MigrationState::Running.as_str()),
        );
        state
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(state.env()))
            .migration_runs()
            .transition_with_event(
                state.env(),
                &run_id,
                MigrationState::Running,
                pending
                    .as_ref()
                    .map(crate::events::PendingEvent::domain_event)
                    .as_ref(),
            )
            .await?;
    }

    stream_into_run(&state, scope, actor, &run_id, body).await?;

    let view = ImportJobView {
        run_id: run_id.to_string(),
        source_total: run.source_total,
        progress_path: progress_path(scope, &run_id),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::ACCEPTED, body_string))
}

/// The event a bulk identity import emits (issue #108).
///
/// `state` present means the run MOVED; absent means it was ACCEPTED. The create announces the
/// run beginning rather than its outcome, which is not knowable when the request returns.
///
/// NO COUNTS AND NO RECORDS. An import's progress belongs to the run resource an operator
/// polls; putting a snapshot on the wire would publish a number that is stale before it is
/// delivered, and the records themselves are the identities being imported.
///
/// The transition is ONE type with a state rather than one per edge, so the state machine can
/// gain a state without minting a new event type -- which would otherwise make a purely
/// internal addition a breaking registry change.
fn identity_import_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    run_id: &str,
    to_state: Option<&str>,
) -> Option<crate::events::PendingEvent> {
    let id = format!(
        "evt_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    let (event_type, payload) = match to_state {
        Some(to) => (
            "identity_import.state_changed",
            serde_json::json!({ "migration_run_id": run_id, "state": to }),
        ),
        None => (
            "identity_import.created",
            serde_json::json!({ "migration_run_id": run_id }),
        ),
    };
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject: run_id.to_owned(),
        envelope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the line reader over a body assembled from explicit CHUNKS, so a record
    /// split across two frames is exercised rather than assumed. The lines are compared as
    /// text, which every chunk in these cases is.
    async fn lines_of(chunks: Vec<&'static [u8]>) -> Vec<String> {
        let body = Body::from(chunks.concat());
        let mut reader = BodyLines::new(body, Arc::new(OnceLock::new()));
        let mut out = Vec::new();
        while let Some(line) = reader.read_line().await {
            out.push(String::from_utf8(line).expect("these fixtures are text"));
        }
        out
    }

    #[tokio::test]
    async fn the_reader_yields_whole_lines_including_a_record_split_across_frames() {
        let lines = lines_of(vec![
            b"{\"identifier\":\"a@x.test\"}\n{\"identi",
            b"fier\":\"b@x.test\"}\n",
            b"{\"identifier\":\"c@x.test\"}",
        ])
        .await;
        assert_eq!(
            lines,
            vec![
                "{\"identifier\":\"a@x.test\"}".to_owned(),
                // Reassembled across the frame boundary: the second record's bytes
                // arrived in two pieces.
                "{\"identifier\":\"b@x.test\"}".to_owned(),
                // A trailing line with NO final newline is still a record.
                "{\"identifier\":\"c@x.test\"}".to_owned(),
            ]
        );
    }

    #[tokio::test]
    async fn a_blank_line_is_yielded_and_an_empty_body_yields_nothing() {
        let lines = lines_of(vec![b"{\"identifier\":\"a@x.test\"}\n\n"]).await;
        assert_eq!(
            lines.len(),
            2,
            "the blank separator reaches the engine: {lines:?}"
        );
        assert_eq!(lines[1], "");
        assert!(lines_of(vec![b""]).await.is_empty());
    }

    #[tokio::test]
    async fn a_line_over_the_cap_stops_the_reader_rather_than_growing_it() {
        // One record, then a second line of MAX_LINE_BYTES + 1 bytes with no newline.
        let body = Body::from(
            [
                b"{\"identifier\":\"a@x.test\"}\n".to_vec(),
                vec![b'x'; MAX_LINE_BYTES + 1],
            ]
            .concat(),
        );
        let fault = Arc::new(OnceLock::new());
        let mut reader = BodyLines::new(body, Arc::clone(&fault));
        assert_eq!(
            reader.read_line().await.as_deref(),
            Some(&b"{\"identifier\":\"a@x.test\"}"[..])
        );
        assert!(
            reader.read_line().await.is_none(),
            "the oversized line is refused"
        );
        // And the refusal reaches the CALLER'S cell, not a private field the handler
        // cannot see. This is the difference between a truncated upload that is reported
        // and one that answers 202.
        let recorded = fault
            .get()
            .expect("the refusal is recorded where the handler reads it");
        assert!(
            recorded.message.contains("exceeded"),
            "the fault names the cap: {}",
            recorded.message
        );
        assert!(
            reader.pending.len() <= MAX_LINE_BYTES,
            "the pending buffer never exceeds the cap: {}",
            reader.pending.len()
        );
    }

    #[tokio::test]
    async fn the_reader_hands_over_undecodable_bytes_rather_than_rewriting_them() {
        // A Latin-1 byte in a login handle. The reader must not decide what it means: a
        // lossy decode here silently creates an account whose identifier carries U+FFFD.
        let body = Body::from([b"{\"identifier\":\"caf\xe9@x.test\"}\n".to_vec()].concat());
        let mut reader = BodyLines::new(body, Arc::new(OnceLock::new()));
        let line = reader.read_line().await.expect("a line");
        assert!(
            line.contains(&0xe9),
            "the undecodable byte reaches the engine intact: {line:?}"
        );
        assert!(
            String::from_utf8(line).is_err(),
            "and it is genuinely not valid UTF-8"
        );
    }

    #[test]
    fn source_total_is_bounded_and_malformed_values_are_precise_bad_requests() {
        assert_eq!(parse_source_total("0").expect("zero is legal"), 0);
        assert_eq!(parse_source_total("100000").expect("100k"), 100_000);
        assert_eq!(parse_source_total(" 42 ").expect("trimmed"), 42);
        for bad in ["", "-1", "nope", "1e6", "10000001"] {
            assert!(
                matches!(parse_source_total(bad), Err(ApiError::BadRequest(_))),
                "{bad} must be a precise 400"
            );
        }
    }
}
