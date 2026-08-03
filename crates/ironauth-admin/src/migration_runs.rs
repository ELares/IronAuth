// SPDX-License-Identifier: MIT OR Apache-2.0

//! The migration state-machine operator view (issue #59), and its one write (issue #55).
//!
//! Management endpoints over the invariant-checked migration state machine: list a scope's
//! runs, read one run's current state with its per-state record counts and its LIVE
//! invariant evaluations (the exact evaluation the gated completion path runs, re-derived
//! from the database on every call), and page the specific records violating an invariant.
//! Nearly all of it is READ ONLY, because the transitions that advance a run (define,
//! advance, ingest, complete) are audited store operations driven by the migration
//! machinery rather than by an operator.
//!
//! The exception is ABANDONMENT, and it is here because it is not an advancement: it is the
//! only exit from a run whose invariants can never be satisfied, and a bulk import can
//! reach that state without anyone doing anything wrong. Everything else that could
//! unwedge such a run (rewriting its declared `source_total`, editing a ledger row,
//! deleting one) is deliberately withheld from this plane by migration 0101, so without an
//! abandon route the answer to "this run can never finish" would be silence.
//!
//! Authorization is environment-scoped: the operator plane, or the environment's own
//! management key, may read it (the same `require_environment` gate the other
//! per-environment reads use); the abandonment additionally demands fresh privilege, like
//! every other environment-scoped mutation. A record's natural subject is opened from its
//! sealed value for the authorized operator; the store never returns a plaintext subject
//! for a non-violating record.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use bytes::Bytes;
use ironauth_store::{
    CorrelationId, InvariantEvaluation, InvariantKind, MigrationRun, MigrationRunId,
    MigrationRunTallies, MigrationState, OffendingRecord, Scope, TenantId,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::input::{parse_json, require_non_empty};
use crate::pagination::{ListQuery, Pagination};
use crate::response::json;
use crate::state::AdminState;

/// One run in the paginated list view (issue #59).
#[derive(Serialize, ToSchema)]
pub struct MigrationRunSummaryView {
    /// The run identifier (an `mgr_` id).
    pub id: String,
    /// The wrapped-workload kind (`bulk_import` or `schema_migration`).
    pub kind: String,
    /// The current lifecycle state.
    pub state: String,
    /// The declared ground-truth source record count.
    pub source_total: i64,
    /// The number of records a backfill must mark.
    pub backfill_expected: i64,
    /// The non-PII link back to the wrapped job, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
}

/// A page of migration runs (issue #59).
#[derive(Serialize, ToSchema)]
pub struct MigrationRunList {
    /// The runs on this page.
    pub items: Vec<MigrationRunSummaryView>,
    /// The opaque cursor for the next page, or null on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The per-state record counts of a run (issue #59), re-derived live.
#[derive(Serialize, ToSchema)]
pub struct MigrationRunCountsView {
    /// Records in the `imported` bucket.
    pub imported: i64,
    /// Records in the `failed` bucket.
    pub failed: i64,
    /// Records in the `skipped` bucket.
    pub skipped: i64,
    /// Records flagged inconsistent.
    pub inconsistent: i64,
    /// Records not yet backfill-marked.
    pub unmarked_backfill: i64,
    /// The total accounted records (the sum of the three buckets).
    pub accounted: i64,
}

/// One invariant's live evaluation (issue #59).
#[derive(Serialize, ToSchema)]
pub struct InvariantView {
    /// The invariant family (`count`, `consistency`, or `backfill_sentinel`).
    pub invariant: String,
    /// Whether the invariant is currently satisfied.
    pub satisfied: bool,
    /// An operator-safe description of the invariant's current values (no PII).
    pub current_value: String,
    /// The number of records currently violating this invariant.
    pub offending_count: i64,
}

/// One run's full operator view (issue #59): its state, per-state counts, and the LIVE
/// invariant evaluations, with the blocking invariants surfaced.
#[derive(Serialize, ToSchema)]
pub struct MigrationRunDetailView {
    /// The run identifier.
    pub id: String,
    /// The wrapped-workload kind.
    pub kind: String,
    /// The current lifecycle state.
    pub state: String,
    /// The declared ground-truth source record count.
    pub source_total: i64,
    /// The number of records a backfill must mark.
    pub backfill_expected: i64,
    /// The non-PII link back to the wrapped job, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    /// The operator-safe abandonment reason, when abandoned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abandoned_reason: Option<String>,
    /// The per-state record counts.
    pub counts: MigrationRunCountsView,
    /// Every invariant's live evaluation.
    pub invariants: Vec<InvariantView>,
    /// The names of the invariants currently BLOCKING completion (empty when the run
    /// could complete).
    pub blocking: Vec<String>,
}

/// One record violating an invariant (issue #59).
#[derive(Serialize, ToSchema)]
pub struct OffendingRecordView {
    /// The record identifier (an `mrr_` id).
    pub id: String,
    /// The record's natural subject, opened from its sealed value.
    pub subject: String,
    /// The accounting bucket.
    pub outcome: String,
    /// Whether the identity is in a consistent state.
    pub consistent: bool,
    /// Whether a backfill has marked this record.
    pub backfilled: bool,
    /// An operator-safe reason, when recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A page of the records violating one invariant (issue #59).
#[derive(Serialize, ToSchema)]
pub struct MigrationRunViolationList {
    /// The invariant these records violate.
    pub invariant: String,
    /// The offending records on this page.
    pub items: Vec<OffendingRecordView>,
    /// The opaque cursor for the next page, or null on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// The query parameters of the violations endpoint: the pagination controls plus the
/// invariant to enumerate.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ViolationsQuery {
    /// The desired page size, a positive integer.
    #[param(value_type = Option<u32>)]
    pub limit: Option<String>,
    /// The opaque cursor from a previous page's `next_cursor`.
    pub cursor: Option<String>,
    /// Which invariant's offending records to enumerate: `count`, `consistency`, or
    /// `backfill_sentinel`. Defaults to `consistency`. The count invariant is a scalar
    /// discrepancy with no enumerable rows, so it returns an empty page.
    pub invariant: Option<String>,
}

impl From<MigrationRunTallies> for MigrationRunCountsView {
    fn from(tallies: MigrationRunTallies) -> Self {
        Self {
            imported: tallies.imported,
            failed: tallies.failed,
            skipped: tallies.skipped,
            inconsistent: tallies.inconsistent,
            unmarked_backfill: tallies.unmarked_backfill,
            accounted: tallies.accounted,
        }
    }
}

impl From<&InvariantEvaluation> for InvariantView {
    fn from(eval: &InvariantEvaluation) -> Self {
        Self {
            invariant: eval.kind.as_str().to_owned(),
            satisfied: eval.satisfied,
            current_value: eval.current_value.clone(),
            offending_count: eval.offending_count,
        }
    }
}

impl From<MigrationRun> for MigrationRunSummaryView {
    fn from(run: MigrationRun) -> Self {
        Self {
            id: run.id.to_string(),
            kind: run.kind.as_str().to_owned(),
            state: run.state.as_str().to_owned(),
            source_total: run.source_total,
            backfill_expected: run.backfill_expected,
            subject_ref: run.subject_ref,
        }
    }
}

impl From<OffendingRecord> for OffendingRecordView {
    fn from(record: OffendingRecord) -> Self {
        Self {
            id: record.id.to_string(),
            subject: record.subject,
            outcome: record.outcome.as_str().to_owned(),
            consistent: record.consistent,
            backfilled: record.backfilled,
            detail: record.detail,
        }
    }
}

/// Resolve the `(tenant, environment)` scope from the path.
fn scope_from_path(
    state: &AdminState,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(TenantId, Scope), ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(tenant)
        .parse_id(environment_id)?;
    Ok((tenant, Scope::new(tenant, environment)))
}

/// Parse a run id within scope (a malformed or cross-scope id is the uniform not-found).
fn parse_run_id(raw: &str, scope: Scope) -> Result<MigrationRunId, ApiError> {
    MigrationRunId::parse_in_scope(raw, &scope).map_err(|_| ApiError::NotFound)
}

/// Parse the `invariant` query value, defaulting to `consistency`.
fn parse_invariant(raw: Option<&str>) -> Result<InvariantKind, ApiError> {
    match raw.unwrap_or("consistency") {
        "count" => Ok(InvariantKind::Count),
        "consistency" => Ok(InvariantKind::Consistency),
        "backfill_sentinel" => Ok(InvariantKind::BackfillSentinel),
        other => Err(ApiError::BadRequest(format!(
            "unknown invariant '{other}' (expected count, consistency, or backfill_sentinel)"
        ))),
    }
}

/// List a scope's migration runs (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs",
    operation_id = "listMigrationRuns",
    tag = "migration",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of the environment's migration runs", body = MigrationRunList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn list_migration_runs(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    principal.require_environment(tenant, scope.environment())?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .scoped(scope)
        .migration_runs()
        .list(page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) =
        page.finish(rows, |run| (run.created_at_unix_micros, run.id.to_string()));
    let list = MigrationRunList {
        items: rows
            .into_iter()
            .map(MigrationRunSummaryView::from)
            .collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Read one migration run: its state, per-state counts, and LIVE invariant evaluations.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs/{run_id}",
    operation_id = "getMigrationRun",
    tag = "migration",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("run_id" = String, Path, description = "The migration-run identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The run's current state, per-state record counts, and the \
         live invariant evaluations (re-derived from the database on every call), with the \
         blocking invariants surfaced. A run cannot complete while any invariant is unsatisfied.", body = MigrationRunDetailView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Run or environment not found", body = ErrorBody)
    )
)]
pub async fn get_migration_run(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, run_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    principal.require_environment(tenant, scope.environment())?;
    let run_id = parse_run_id(&run_id, scope)?;
    let view = detail_view(&state, scope, &run_id).await?;
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// The body of an abandon request (issue #55): the operator's reason, recorded on the run
/// and on its audit row.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AbandonMigrationRunRequest {
    /// Why this run is being given up on. Required, non-blank, at most
    /// [`MAX_ABANDON_REASON_CHARS`] characters. It is stored verbatim and served back on
    /// the run's operator view, so it must be operator-safe: a sentence about the JOB, not
    /// a record's contents.
    pub reason: String,
}

/// The longest abandonment reason accepted. Generous for a sentence naming the blocking
/// condition and the decision, and bounded because it is caller-supplied text that is
/// stored and served back.
const MAX_ABANDON_REASON_CHARS: usize = 500;

/// Build one run's full operator view, live.
async fn detail_view(
    state: &AdminState,
    scope: Scope,
    run_id: &MigrationRunId,
) -> Result<MigrationRunDetailView, ApiError> {
    let runs = state.store().scoped(scope).migration_runs();
    let run = runs.get(run_id).await?;
    let tallies = runs.tallies(run_id).await?;
    let evals = runs.evaluate(run_id).await?;
    let blocking: Vec<String> = evals
        .iter()
        .filter(|eval| !eval.satisfied)
        .map(|eval| eval.kind.as_str().to_owned())
        .collect();
    Ok(MigrationRunDetailView {
        id: run.id.to_string(),
        kind: run.kind.as_str().to_owned(),
        state: run.state.as_str().to_owned(),
        source_total: run.source_total,
        backfill_expected: run.backfill_expected,
        subject_ref: run.subject_ref,
        abandoned_reason: run.abandoned_reason,
        counts: MigrationRunCountsView::from(tallies),
        invariants: evals.iter().map(InvariantView::from).collect(),
        blocking,
    })
}

/// Abandon a migration run: the audited, reason-carrying terminal giving-up.
///
/// # Why this route exists
///
/// Without it a wedged run is wedged FOREVER, and a run can be wedged by conditions the
/// import job cannot prevent. A source carrying two records under one login handle is one
/// ledger subject, so it accounts one row against a `source_total` of two and the count
/// invariant can never be satisfied; a record that FAILED is accounted inconsistent, and
/// the consistency invariant blocks until something reconciles it, which on this plane
/// nothing does. Neither the run's declared ground truth nor its rows can be corrected
/// through this API by design: migration 0101 withholds `UPDATE (source_total)` and
/// `DELETE` from the control role, and `UPDATE` on `migration_run_records` with it. So the
/// state machine's own `abandoned` edge is the only correct exit, and this is it.
///
/// It is deliberately NOT a way to make a bad run look finished: `abandoned` is terminal
/// and distinct from `complete`, it carries the operator's reason, and it writes a
/// `migration_run.abandon` audit row. A stuck half-applied migration stays legible.
///
/// # No `Idempotency-Key`
///
/// Abandoning is idempotent by construction, exactly as `resumeIdentityImport` and
/// `elevateAdminSudo` are: a run already abandoned answers `200` with its existing view
/// and the FIRST reason (the stored one is never overwritten, so a retry cannot rewrite
/// history). A `complete` run is a `409`: completion is a statement that every invariant
/// re-evaluated satisfied, and nothing may quietly take that back.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs/{run_id}/abandon",
    operation_id = "abandonMigrationRun",
    tag = "migration",
    request_body = AbandonMigrationRunRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("run_id" = String, Path, description = "The migration-run identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The run's operator view after the abandonment, \
         carrying its recorded reason. Idempotent: a run already abandoned answers with \
         its existing view and its FIRST reason.", body = MigrationRunDetailView),
        (status = 400, description = "A missing, blank, or over-long reason", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Run or environment not found", body = ErrorBody),
        (status = 409, description = "The run is COMPLETE; a completed run cannot be abandoned", body = ErrorBody)
    )
)]
pub async fn abandon_migration_run(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, run_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    let actor = principal.require_environment(tenant, scope.environment())?;
    // Terminating a migration run is an environment-scoped management mutation, so it
    // demands fresh privilege exactly like the import that created the run.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    crate::org_context::require_live_environment(&state, &scope).await?;
    let run_id = parse_run_id(&run_id, scope)?;

    let request: AbandonMigrationRunRequest = parse_json(&body)?;
    let reason = require_non_empty(&request.reason, "reason")?;
    if reason.chars().count() > MAX_ABANDON_REASON_CHARS {
        return Err(ApiError::BadRequest(format!(
            "reason must be at most {MAX_ABANDON_REASON_CHARS} characters"
        )));
    }

    let run = state
        .store()
        .scoped(scope)
        .migration_runs()
        .get(&run_id)
        .await?;
    match run.state {
        // Already given up on: answer with what is recorded rather than rewriting it.
        MigrationState::Abandoned => {}
        MigrationState::Complete => {
            return Err(ApiError::Conflict(format!(
                "run {run_id} is complete and cannot be abandoned"
            )));
        }
        _ => {
            state
                .store()
                .scoped(scope)
                .acting(actor, CorrelationId::generate(state.env()))
                .migration_runs()
                .abandon(state.env(), &run_id, &reason)
                .await?;
        }
    }

    let view = detail_view(&state, scope, &run_id).await?;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Page the specific records violating one of a run's invariants (cursor paginated).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/migration-runs/{run_id}/violations",
    operation_id = "listMigrationRunViolations",
    tag = "migration",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("run_id" = String, Path, description = "The migration-run identifier"),
        ViolationsQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of the records violating the selected invariant, \
         each naming the offending identity (opened) and its reason", body = MigrationRunViolationList),
        (status = 400, description = "Malformed cursor or unknown invariant", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Run or environment not found", body = ErrorBody)
    )
)]
pub async fn list_migration_run_violations(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, run_id)): Path<(String, String, String)>,
    Query(query): Query<ViolationsQuery>,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    principal.require_environment(tenant, scope.environment())?;
    let run_id = parse_run_id(&run_id, scope)?;
    let invariant = parse_invariant(query.invariant.as_deref())?;
    let list_query = ListQuery {
        limit: query.limit,
        cursor: query.cursor,
    };
    let page = Pagination::resolve(
        &list_query,
        state.default_page_size(),
        state.max_page_size(),
    )?;
    let rows = state
        .store()
        .scoped(scope)
        .migration_runs()
        .list_violations(&run_id, invariant, page.fetch_limit(), page.after())
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = MigrationRunViolationList {
        invariant: invariant.as_str().to_owned(),
        items: rows.into_iter().map(OffendingRecordView::from).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
