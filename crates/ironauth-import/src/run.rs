// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wrapping a streaming bulk import in the migration state machine (issue #59).
//!
//! [`import_into_run`] is the adapter that applies the invariant-checked state machine
//! (issue #59) to the streaming bulk import (issue #55): it drives [`import_stream_lines`],
//! translates each per-record outcome (`Created` / `Skipped` / `Failed`) into the run's
//! accounting ledger, and ingests them INCREMENTALLY as the stream drains. The run's
//! COUNT invariant then measures the ingested accounting (imported + failed + skipped)
//! against the caller's declared `source_total`, so a run whose accounted records do not
//! reconcile with the source cannot be completed, and the operator view exposes every
//! per-record failure.
//!
//! The caller owns the lifecycle: create the run (declaring `source_total`), drive it to
//! `running`, call this, then transition to `reconciling` and attempt the gated
//! completion. The engine writes no run state itself; this adapter only feeds the
//! machine's ledger.
//!
//! # The ledger is the resume cursor, and the subject is what makes it one
//!
//! A record is accounted under its STABLE RECORD KEY, which is its LOGIN HANDLE
//! ([`crate::record::ImportRecord::record_key`]): the one field of a record that is
//! REQUIRED, and therefore the only one that is the same string every time that identity
//! is presented. `ingest_outcomes` blind-indexes the subject and inserts `ON CONFLICT
//! (tenant, environment, run, subject_bidx) DO NOTHING`, so re-presenting a record already
//! accounted in this run adds NO second ledger row. That, and not a byte offset, is the
//! resumability mechanism: a resume may safely re-present anything, including records it
//! already imported, because the ledger deduplicates on the record's own identity.
//!
//! Two earlier keys both broke it, in opposite directions, and both are worth keeping
//! written down because the failure is silent in each case.
//!
//! * The MINTED `usr_` id. That is not a property of the input at all: on a resume the
//!   same source record is refused by the scope's unique constraint, reported as
//!   `Skipped`, and accounted under its record key, a DIFFERENT blind index from the
//!   `usr_` id the first pass stored. The ledger then held two rows for one source record
//!   and `accounted` OVERSHOT `source_total`. MEASURED by MUTATION: reverting `translate`
//!   to the minted id is killed by
//!   `run::tests::every_outcome_is_accounted_under_the_stable_record_key`, by
//!   `a_killed_import_resumes_without_duplicating_or_losing_records` in `tests/engine.rs`,
//!   and by `an_interrupted_import_resumes_without_duplicating_or_losing_records` in
//!   `ironauth-admin`'s `tests/imports.rs`. The `usr_` id is still reported to the caller
//!   on the [`RecordOutcome::Created`] outcome; it is simply not what the ledger is keyed
//!   on.
//! * "The id, else the external id, else the handle." That is a property of the input only
//!   while the INPUT DOES NOT CHANGE, and the documented recovery procedure is to post the
//!   source again, which an operator will happily do from a corrected export. MEASURED:
//!   pass 1 delivers a record with no external id, pass 2 re-presents the same identity
//!   now carrying one, and `accounted` reaches 3 against a `source_total` of 2 with
//!   `remainder == -1`, unsatisfiable forever. The population stayed correct; only the
//!   ledger broke, which is the worst shape for this defect to have.
//!
//! # A run can still be wedged, and there is a way out
//!
//! Keying on the handle removes every wedge an EDITED source could cause, but not the one
//! a DUPLICATED source causes: two records carrying the same login handle are one subject,
//! so they write one ledger row against a `source_total` of two and the count invariant can
//! never be satisfied. [`RunImportReport::ledger_deduped`] is what makes that condition
//! legible rather than mysterious, and the management `abandon` route is the way out of a
//! run that legitimately cannot finish.
//!
//! # Memory
//!
//! Bounded by one batch of 256 translated outcomes (`INGEST_BATCH`), NOT by the record
//! count. The observer is awaited per record ([`import_stream_lines`]), so this adapter flushes a
//! full batch into one audited ingest and starts a fresh one. The first cut collected
//! EVERY outcome into a `Vec` before ingesting any, because the observer was
//! synchronous; the engine below it was bounded and this adapter was O(n), which is the
//! opposite of the streaming memory profile the issue's acceptance criterion asks for.

use std::future::Future;

use ironauth_store::{
    CorrelationId, MigrationRecordOutcome, MigrationRunId, RecordOutcomeInput, StoreError,
};

use crate::engine::{
    ImportContext, ImportReport, IterLines, LineSource, OutcomeSink, RecordOutcome,
    import_stream_lines,
};

/// How many translated outcomes are held before one audited ingest flushes them.
///
/// This is the adapter's whole memory footprint, and it is a CONSTANT: peak memory does
/// not grow with the number of records imported. It is a batch rather than one row per
/// ingest because `ingest_outcomes` writes one `migration_run.ingest` audit row per CALL,
/// so a per-record ingest would write one audit row per imported user and turn the audit
/// log into a second copy of the ledger. 256 keeps the held set small (a few tens of
/// kilobytes of keys) while amortizing the transaction and the audit row over a batch.
const INGEST_BATCH: usize = 256;

/// One translated per-record outcome, held until the batch flushes.
struct CollectedOutcome {
    subject: String,
    outcome: MigrationRecordOutcome,
    detail: Option<String>,
}

/// Where a FULL batch goes. A trait rather than an async closure for the reason
/// [`crate::engine::LineSource`] records: a borrowing async closure's future has no general
/// `Send` implementation, and everything here is driven from an axum handler.
///
/// It exists so that [`LedgerBatch::accept`] can own the ONE decision that bounds this
/// adapter's memory ("take it, and flush if that filled the batch") while staying drivable
/// without a database. The shipped sink flushes into the run's ledger; the memory probe
/// flushes into nothing. Both go through the same `accept`.
trait BatchFlush {
    /// Write `held` out and clear it. Called ONLY by [`LedgerBatch::accept`].
    fn flush(
        &mut self,
        held: &mut Vec<CollectedOutcome>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// The bounded accumulator both entry points feed: it holds translated outcomes and
/// flushes itself the moment a batch is full.
///
/// It exists as a named type rather than a bare `Vec` so its memory bound is MEASURABLE
/// without a database. `peak_held` is the exact quantity that used to grow with the
/// record count (the old adapter's `Vec<CollectedOutcome>` collected every outcome of the
/// whole run before ingesting any of them), so a unit test can drive the shipped
/// accumulator across record counts and read the curve off it.
///
/// The FLUSH DECISION lives in [`LedgerBatch::accept`], the ONE method both the shipped
/// [`LedgerSink::record`] and the memory probe call, and that placement is the whole point.
/// When the sink owned the decision and hard-wired the ledger, the memory test could not
/// reach the sink at all: it drove `LedgerBatch` directly and substituted its own flush, so
/// the loop under test was not the loop that ships. MEASURED by mutation, rewriting the
/// sink so it NEVER flushed put production back to O(N) in the record count and left the
/// whole crate green. Both mutants die now: the accumulator refusing to flush, and the sink
/// bypassing the accumulator.
struct LedgerBatch {
    held: Vec<CollectedOutcome>,
    /// The high-water mark of `held.len()` over this batch's whole life.
    peak_held: usize,
}

impl LedgerBatch {
    fn new() -> Self {
        Self {
            held: Vec::with_capacity(INGEST_BATCH),
            peak_held: 0,
        }
    }

    /// Take one translated outcome and flush the batch when that filled it, which is what
    /// holds `held.len()` at or below [`INGEST_BATCH`] forever.
    ///
    /// # Errors
    ///
    /// Whatever the flush returns.
    async fn accept<F: BatchFlush>(
        &mut self,
        outcome: RecordOutcome,
        sink: &mut F,
    ) -> Result<(), StoreError> {
        self.held.push(translate(outcome));
        self.peak_held = self.peak_held.max(self.held.len());
        if self.held.len() >= INGEST_BATCH {
            sink.flush(&mut self.held).await?;
        }
        Ok(())
    }
}

/// Translate a streaming-import per-record outcome into the migration-run ledger's
/// accounting. EVERY outcome is accounted by its stable record key (sealed and
/// blind-indexed on ingest, never plaintext), which is what makes a resumed ingest
/// idempotent; see this module's header for what keying a create on the minted id
/// instead cost.
fn translate(outcome: RecordOutcome) -> CollectedOutcome {
    match outcome {
        RecordOutcome::Created { key, .. } => CollectedOutcome {
            subject: key,
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

/// The SHIPPED flush: ingest one batch of translated outcomes into the run's ledger and
/// clear it, keeping the written and deduped row counts.
struct LedgerFlush<'a> {
    ctx: &'a ImportContext<'a>,
    run_id: &'a MigrationRunId,
    /// Ledger rows actually written across every flush.
    written: u64,
    /// Presented outcomes the ledger's conflict clause absorbed.
    deduped: u64,
}

impl BatchFlush for LedgerFlush<'_> {
    /// Each record is marked accounted (`backfilled`). A record that FAILED is marked
    /// INCONSISTENT, which is what puts it on the violations surface an operator reads.
    ///
    /// Writing `consistent: true` for a failed record is what the first cut did, and it
    /// made the consistency invariant vacuous for every bulk import: a run could report
    /// `failed=1` while both violation queries returned an empty page, because the only
    /// surface that enumerates records pages `consistent = false` or `backfilled = false`
    /// (MEASURED). Issue #55 requires every failure be REPORTED with its record identity,
    /// and a durable row nothing can read is not a report. `false` is also what the store's
    /// own schema-migration ingest has always written for a failed record, so the two
    /// producers of the same table now agree.
    async fn flush(&mut self, held: &mut Vec<CollectedOutcome>) -> Result<(), StoreError> {
        if held.is_empty() {
            return Ok(());
        }
        let inputs: Vec<RecordOutcomeInput<'_>> = held
            .iter()
            .map(|entry| RecordOutcomeInput {
                subject: &entry.subject,
                outcome: entry.outcome,
                consistent: entry.outcome != MigrationRecordOutcome::Failed,
                backfilled: true,
                detail: entry.detail.as_deref(),
            })
            .collect();
        let presented = u64::try_from(inputs.len()).unwrap_or(u64::MAX);
        let written = self
            .ctx
            .store
            .scoped(self.ctx.scope)
            .acting(self.ctx.actor, CorrelationId::generate(self.ctx.env))
            .migration_runs()
            .ingest_outcomes(self.ctx.env, self.run_id, &inputs)
            .await?;
        drop(inputs);
        self.written += written;
        self.deduped += presented.saturating_sub(written);
        held.clear();
        Ok(())
    }
}

/// What one pass of a run's import did, to the identities AND to the ledger.
///
/// The two halves are separate because they can disagree, and the disagreement is the only
/// evidence of the one condition that leaves a run PERMANENTLY unable to complete. Two
/// SOURCE records sharing one stable key produce two `records` outcomes and ONE ledger
/// row: the second is absorbed by the ingest's `ON CONFLICT DO NOTHING`, `accounted` stays
/// one short of `source_total` forever, and nothing in the run itself says why (MEASURED:
/// two records carrying one login handle gave `accounted=1` against `source_total=2`, and
/// re-presenting the whole source changed nothing). `ledger_deduped` is that "why".
///
/// On a RESUME a non-zero `ledger_deduped` is expected and benign: it counts exactly the
/// records an earlier pass already accounted, which is the resume mechanism working. On a
/// FIRST pass over a fresh run there is nothing to dedup against but the pass itself, so
/// any non-zero value there is a duplicate key IN THE SOURCE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunImportReport {
    /// The import's own tally: processed, succeeded, skipped, failed.
    pub records: ImportReport,
    /// Ledger rows this pass WROTE.
    pub ledger_written: u64,
    /// Outcomes this pass presented that the ledger already accounted, and therefore did
    /// not write.
    pub ledger_deduped: u64,
}

/// Run a streaming bulk import (issue #55) INTO an existing migration run (issue #59)
/// from a SYNCHRONOUS line iterator, ingesting per-record outcomes into the run's
/// accounting ledger as the stream drains and returning what the pass did to the
/// identities and to the ledger.
///
/// The run must be non-terminal (typically `running`).
///
/// # Errors
///
/// [`StoreError`] if the run is absent or terminal, no master key is configured, or a
/// ledger ingest fails. An ingest failure STOPS the import: everything ingested before it
/// is durably accounted and a later call resumes from there, which is strictly better
/// than importing users nothing is recording.
pub async fn import_into_run<I>(
    ctx: &ImportContext<'_>,
    run_id: &MigrationRunId,
    lines: I,
) -> Result<RunImportReport, StoreError>
where
    I: IntoIterator<Item = String>,
    I::IntoIter: Send,
{
    import_lines_into_run(ctx, run_id, IterLines::new(lines.into_iter())).await
}

/// Run a streaming bulk import INTO an existing migration run from an ASYNCHRONOUS pull
/// source (issue #55): the form a transport uses.
///
/// `lines` is awaited once per line and yields [`None`] at end of input. A source that
/// stops early (a truncated upload, a killed producer) is not an error: the records
/// already ingested are durably accounted and a later call resumes.
///
/// # Errors
///
/// As [`import_into_run`].
pub async fn import_lines_into_run<N>(
    ctx: &ImportContext<'_>,
    run_id: &MigrationRunId,
    lines: N,
) -> Result<RunImportReport, StoreError>
where
    N: LineSource,
{
    let mut sink = LedgerSink {
        batch: LedgerBatch::new(),
        ledger: LedgerFlush {
            ctx,
            run_id,
            written: 0,
            deduped: 0,
        },
    };
    let records = import_stream_lines(ctx, lines, &mut sink).await?;
    // The tail: whatever the last full batch left behind.
    sink.ledger.flush(&mut sink.batch.held).await?;
    Ok(RunImportReport {
        records,
        ledger_written: sink.ledger.written,
        ledger_deduped: sink.ledger.deduped,
    })
}

/// The shipped observer: hand each outcome to the bounded batch, which translates it,
/// holds it, and flushes a full batch through `F`.
///
/// GENERIC over the flush destination, so the memory probe can drive THIS type, with THIS
/// `record` body, over a flush that needs no database. The previous shape hard-wired the
/// ledger here, which left the probe no way to reach the sink at all: it drove the
/// accumulator directly and substituted its own flush, so the loop under test was not the
/// loop that shipped, and a `record` rewritten to never flush left the whole crate green
/// while production was O(N) in the record count (MEASURED by mutation).
struct LedgerSink<F> {
    batch: LedgerBatch,
    ledger: F,
}

impl<F: BatchFlush + Send> OutcomeSink for &mut LedgerSink<F> {
    async fn record(&mut self, outcome: RecordOutcome) -> Result<(), StoreError> {
        self.batch.accept(outcome, &mut self.ledger).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::RecordError;

    #[test]
    fn every_outcome_is_accounted_under_the_stable_record_key() {
        // The invariant the resume mechanism rests on: whichever outcome a record
        // produces, the ledger subject is the same string, so re-presenting it hits the
        // ingest's ON CONFLICT and adds no second row. A `Created` outcome carries BOTH
        // the record key and the minted id; keying on the id is what broke resume.
        let created = translate(RecordOutcome::Created {
            key: "carol@example.test".to_owned(),
            id: "usr_01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned(),
        });
        assert_eq!(created.subject, "carol@example.test");
        assert_eq!(created.outcome, MigrationRecordOutcome::Imported);

        let skipped = translate(RecordOutcome::Skipped {
            key: "carol@example.test".to_owned(),
        });
        assert_eq!(skipped.subject, "carol@example.test");
        assert_eq!(skipped.outcome, MigrationRecordOutcome::Skipped);

        let failed = translate(RecordOutcome::Failed(RecordError {
            key: "carol@example.test".to_owned(),
            reason: "foreign hash rejected".to_owned(),
        }));
        assert_eq!(failed.subject, "carol@example.test");
        assert_eq!(failed.outcome, MigrationRecordOutcome::Failed);
        assert_eq!(failed.detail.as_deref(), Some("foreign hash rejected"));

        // All three subjects are byte identical: one source record, one ledger row,
        // however many times it is presented and whatever it resolves to.
        assert_eq!(created.subject, skipped.subject);
        assert_eq!(skipped.subject, failed.subject);
    }

    /// The STREAMING MEMORY PROFILE, measured on the shipped accumulator (issue #55's
    /// first acceptance criterion).
    ///
    /// The adapter's peak held-outcome count is the quantity that used to grow with the
    /// record count: the previous cut pushed every translated outcome of the whole run
    /// into one `Vec` and ingested the lot afterwards, so importing 100k users held 100k
    /// outcomes. This drives the SHIPPED [`LedgerBatch`] over four record counts spanning
    /// three orders of magnitude and reads the curve off it. A flat curve at
    /// [`INGEST_BATCH`] is the streaming profile; the old code's curve is the identity
    /// function, which the final assertion refuses.
    ///
    /// It measures the accumulator and not process RSS deliberately: RSS is page
    /// granular and confounded by the connection pool, the runtime, and the allocator's
    /// own caching, so it can neither confirm nor refute a bound this small. The held
    /// count is exact, and it is the only thing in this adapter that was ever unbounded.
    ///
    /// # It drives the SHIPPED loop
    ///
    /// The probe substitutes only the DESTINATION of a flush (a counter instead of a
    /// database), never the decision to flush: that lives in [`LedgerBatch::accept`], which
    /// [`LedgerSink::record`] also calls and does nothing else. The previous version of
    /// this test substituted the decision too, calling `batch.held.clear()` itself, and it
    /// therefore measured a loop that did not ship: MEASURED by MUTATION, a
    /// `LedgerSink::record` rewritten to never flush left the whole crate green while
    /// production was back to O(N).
    #[tokio::test]
    async fn peak_held_outcomes_do_not_grow_with_the_record_count() {
        /// The probe's flush: it writes the batch NOWHERE and counts the flushes, which is
        /// the only part of the shipped flush that needs a database.
        struct CountingFlush(usize);
        impl BatchFlush for CountingFlush {
            async fn flush(&mut self, held: &mut Vec<CollectedOutcome>) -> Result<(), StoreError> {
                self.0 += 1;
                held.clear();
                Ok(())
            }
        }

        /// Drive `records` outcomes through the SHIPPED SINK, whose `record` body and
        /// whose accumulator are the ones production runs, and return the accumulator's
        /// high-water mark and the number of flushes the sink decided to take.
        async fn peak_for(records: usize) -> (usize, usize) {
            let mut sink = LedgerSink {
                batch: LedgerBatch::new(),
                ledger: CountingFlush(0),
            };
            for n in 0..records {
                (&mut sink)
                    .record(RecordOutcome::Created {
                        key: format!("user-{n}@example.test"),
                        id: format!("usr_{n}"),
                    })
                    .await
                    .expect("the counting flush never fails");
            }
            (sink.batch.peak_held, sink.ledger.0)
        }

        let mut curve: Vec<(usize, usize)> = Vec::new();
        for records in [256_usize, 1_000, 25_000, 200_000] {
            let (peak, flushes) = peak_for(records).await;
            assert_eq!(
                flushes,
                records / INGEST_BATCH,
                "the accumulator must flush once per full batch at {records} records; a \
                 loop that never flushes is the O(N) accumulator this bound replaced"
            );
            curve.push((records, peak));
        }

        for (records, peak) in &curve {
            assert_eq!(
                *peak, INGEST_BATCH,
                "peak held outcomes at {records} records must be the batch bound, not the \
                 record count; the measured curve is {curve:?}"
            );
        }
        // Stated as a ratio too, because that is the shape of the defect: an O(n)
        // accumulator's peak grows by the same factor the input does. Across a 781x
        // range of record counts this curve is flat.
        let (_, smallest) = curve.first().copied().expect("the curve is non-empty");
        let (_, largest) = curve.last().copied().expect("the curve is non-empty");
        assert_eq!(
            largest, smallest,
            "781x the records must not move the peak at all: {curve:?}"
        );
    }
}
