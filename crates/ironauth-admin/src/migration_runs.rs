// SPDX-License-Identifier: MIT OR Apache-2.0

//! The migration state-machine operator view (issue #59).
//!
//! Read-only management endpoints over the invariant-checked migration state machine:
//! list a scope's runs, read one run's current state with its per-state record counts
//! and its LIVE invariant evaluations (the exact evaluation the gated completion path
//! runs, re-derived from the database on every call), and page the specific records
//! violating an invariant. The transitions themselves (define, advance, ingest,
//! complete, abandon) are audited store operations driven by the migration machinery;
//! this is the observability surface the issue's acceptance criteria require.
//!
//! Authorization is environment-scoped: the operator plane, or the environment's own
//! management key, may read it (the same `require_environment` gate the other
//! per-environment reads use). A record's natural subject is opened from its sealed
//! value for the authorized operator; the store never returns a plaintext subject for
//! a non-violating record.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{
    InvariantEvaluation, InvariantKind, MigrationRun, MigrationRunId, MigrationRunTallies,
    OffendingRecord, Scope, TenantId,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
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
    let runs = state.store().scoped(scope).migration_runs();
    let run = runs.get(&run_id).await?;
    let tallies = runs.tallies(&run_id).await?;
    let evals = runs.evaluate(&run_id).await?;
    let blocking: Vec<String> = evals
        .iter()
        .filter(|eval| !eval.satisfied)
        .map(|eval| eval.kind.as_str().to_owned())
        .collect();
    let view = MigrationRunDetailView {
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
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
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
