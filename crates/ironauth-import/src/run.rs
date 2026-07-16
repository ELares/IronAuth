// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wrapping a streaming bulk import in the migration state machine (issue #59).
//!
//! [`import_into_run`] is the adapter that applies the invariant-checked state machine
//! (issue #59) to the streaming bulk import (issue #55): it drives [`import_stream`],
//! translates each per-record outcome (`Created` / `Skipped` / `Failed`) into the run's
//! accounting ledger, and ingests the batch. The run's COUNT invariant then measures
//! the ingested accounting (imported + failed + skipped) against the caller's declared
//! `source_total`, so a run whose accounted records do not reconcile with the source
//! cannot be completed, and the operator view exposes every per-record failure.
//!
//! The caller owns the lifecycle: create the run (declaring `source_total`), drive it to
//! `running`, call this, then transition to `reconciling` and attempt the gated
//! completion. The engine writes no run state itself; this adapter only feeds the
//! machine's ledger.

use ironauth_store::{
    CorrelationId, MigrationRecordOutcome, MigrationRunId, RecordOutcomeInput, StoreError,
};

use crate::engine::{ImportContext, ImportReport, RecordOutcome, import_stream};

/// One translated per-record outcome, held until the stream drains and the whole batch
/// is ingested in one audited call.
struct CollectedOutcome {
    subject: String,
    outcome: MigrationRecordOutcome,
    detail: Option<String>,
}

/// Translate a streaming-import per-record outcome into the migration-run ledger's
/// accounting. A created user is accounted by its `usr_` id; a skipped or failed record
/// by its stable record key (sealed and blind-indexed on ingest, never plaintext).
fn translate(outcome: RecordOutcome) -> CollectedOutcome {
    match outcome {
        RecordOutcome::Created { id, .. } => CollectedOutcome {
            subject: id,
            outcome: MigrationRecordOutcome::Imported,
            detail: None,
        },
        RecordOutcome::Skipped { key } => CollectedOutcome {
            subject: key,
            outcome: MigrationRecordOutcome::Skipped,
            detail: None,
        },
        RecordOutcome::Failed(error) => CollectedOutcome {
            subject: error.key,
            outcome: MigrationRecordOutcome::Failed,
            detail: Some(error.reason),
        },
    }
}

/// Run a streaming bulk import (issue #55) INTO an existing migration run (issue #59),
/// ingesting each per-record outcome into the run's accounting ledger and returning the
/// import's aggregate report.
///
/// The run must be non-terminal (typically `running`). Each imported record is marked
/// accounted (`backfilled`) and consistent: a failed import LINE is an accounted
/// failure (it created no half-formed identity), so the COUNT invariant is the primary
/// gate for a bulk import, while the per-record failures remain visible in the operator
/// view.
///
/// # Errors
///
/// [`StoreError`] if the run is absent or terminal, no master key is configured, or the
/// ledger ingest fails. The users themselves are created by [`import_stream`] regardless
/// (per-record failures are reported, never fatal); only the ledger ingest can error
/// here.
pub async fn import_into_run<I>(
    ctx: &ImportContext<'_>,
    run_id: &MigrationRunId,
    lines: I,
) -> Result<ImportReport, StoreError>
where
    I: IntoIterator<Item = String>,
{
    // import_stream's observer is synchronous, so collect the translated outcomes and
    // ingest them in one audited batch after the stream drains.
    let mut collected: Vec<CollectedOutcome> = Vec::new();
    let report = import_stream(ctx, lines, |outcome| collected.push(translate(outcome))).await;

    let inputs: Vec<RecordOutcomeInput<'_>> = collected
        .iter()
        .map(|entry| RecordOutcomeInput {
            subject: &entry.subject,
            outcome: entry.outcome,
            consistent: true,
            backfilled: true,
            detail: entry.detail.as_deref(),
        })
        .collect();

    ctx.store
        .scoped(ctx.scope)
        .acting(ctx.actor, CorrelationId::generate(ctx.env))
        .migration_runs()
        .ingest_outcomes(ctx.env, run_id, &inputs)
        .await?;
    Ok(report)
}
