// SPDX-License-Identifier: MIT OR Apache-2.0

//! The 100k-user load harness for the streaming bulk import (issue #55).
//!
//! # Why it is `#[ignore]`d
//!
//! It imports one hundred thousand identities into a real database, which is a minute
//! or two of wall clock and hundreds of megabytes of Postgres, so it does not belong in
//! a suite every change runs. It is the same shape as
//! `crates/ironauth-admin/tests/outbound_timing_probe.rs`: a harness that MEASURES,
//! kept in the tree and run by hand rather than deleted after one use.
//!
//! ```text
//! scripts/with-test-db.sh cargo test -p ironauth-import --features testing \
//!     --test hundred_k_import -- --ignored --nocapture
//! ```
//!
//! # What it measures, and what it does not
//!
//! It asserts the CORRECTNESS half of the acceptance criterion at the stated scale (one
//! hundred thousand identities created, one hundred thousand ledger rows accounted, the
//! run completing through the gated transition), and it PRINTS the process's peak
//! resident set alongside its baseline so the memory claim can be read rather than
//! assumed.
//!
//! Resident set is a coarse instrument and is reported as one: it is page granular and
//! includes the connection pool, the async runtime, and the allocator's own retained
//! arenas, none of which this code controls. What it can settle is the ORDER of the
//! question, which is whether a hundred thousand records are being accumulated. The
//! EXACT bound is measured elsewhere, on the accumulator itself and without a database,
//! by `run::tests::peak_held_outcomes_do_not_grow_with_the_record_count`.
//!
//! No input is materialized: [`Generated`] mints each line on demand, so the harness's
//! own memory is one line and cannot be mistaken for the engine's.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ironauth_env::Env;
use ironauth_import::{ImportContext, LineSource, import_lines_into_run};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CompletionOutcome, CorrelationId, MigrationKind, MigrationState, NewMigrationRun,
};

/// One hundred thousand records, minted one at a time and never collected.
struct Generated {
    next: usize,
    total: usize,
}

impl LineSource for Generated {
    async fn next_line(&mut self) -> Option<Vec<u8>> {
        if self.next >= self.total {
            return None;
        }
        let line = format!(r#"{{"identifier":"load-{}@example.test"}}"#, self.next);
        self.next += 1;
        Some(line.into_bytes())
    }
}

/// This process's resident set in kibibytes, read from `ps`. Returns `None` where `ps`
/// is unavailable or its output is not a number, so the harness degrades to the
/// correctness assertions rather than failing on a missing tool.
fn resident_kib() -> Option<u64> {
    let pid = std::process::id().to_string();
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()?;
    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}

// A linear harness: set up a run, sample, import, assert, print. Splitting it would put
// the measurement in one function and its subject in another.
#[allow(clippy::too_many_lines)]
#[tokio::test]
#[ignore = "a 100k-record load harness: minutes of wall clock and a large database, run it by hand"]
async fn a_hundred_thousand_user_import_completes_as_a_run() {
    const TOTAL: usize = 100_000;

    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(std::time::SystemTime::UNIX_EPOCH, 0x100);
    let scope = db.seed_scope(&env).await;
    let store = db.store();
    let source_total = i64::try_from(TOTAL).expect("source total fits");

    let run = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .create(
            &env,
            NewMigrationRun {
                kind: MigrationKind::BulkImport,
                source_total,
                backfill_expected: source_total,
                subject_ref: Some("load:100k"),
            },
            1_000_000,
        )
        .await
        .expect("create run");
    for state in [MigrationState::Validating, MigrationState::Running] {
        store
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .migration_runs()
            .transition(&env, &run, state)
            .await
            .expect("transition");
    }

    // Sample the resident set on a plain thread while the import runs. It records a
    // maximum and asserts nothing; the printed baseline is what makes the peak readable.
    let baseline = resident_kib();
    let peak = Arc::new(AtomicU64::new(baseline.unwrap_or(0)));
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let peak = Arc::clone(&peak);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                if let Some(rss) = resident_kib() {
                    peak.fetch_max(rss, Ordering::SeqCst);
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        })
    };

    let context = ImportContext {
        store,
        scope,
        env: &env,
        actor: db.test_actor(&env),
    };
    let report = import_lines_into_run(
        &context,
        &run,
        Generated {
            next: 0,
            total: TOTAL,
        },
    )
    .await
    .expect("the 100k import runs to completion");

    stop.store(true, Ordering::SeqCst);
    sampler.join().expect("the sampler thread joins");

    assert_eq!(report.records.processed, TOTAL as u64);
    assert_eq!(report.records.succeeded, TOTAL as u64, "{report:?}");
    assert_eq!(report.records.failed, 0, "{report:?}");
    // One ledger row WRITTEN per source record, and nothing deduped: a first pass over a
    // source with no repeated login handle has nothing to dedup against.
    assert_eq!(report.ledger_written, TOTAL as u64, "{report:?}");
    assert_eq!(report.ledger_deduped, 0, "{report:?}");

    let tallies = store
        .scoped(scope)
        .migration_runs()
        .tallies(&run)
        .await
        .expect("tallies");
    assert_eq!(
        tallies.accounted, source_total,
        "one ledger row per source record: {tallies:?}"
    );

    store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .transition(&env, &run, MigrationState::Reconciling)
        .await
        .expect("-> reconciling");
    let outcome = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .migration_runs()
        .try_complete(&env, &run)
        .await
        .expect("try_complete");
    assert_eq!(
        outcome,
        CompletionOutcome::Completed,
        "a 100k import completes through the gated transition"
    );

    println!(
        "100k import: baseline rss {:?} KiB, peak rss {} KiB, report {report:?}, tallies {tallies:?}",
        baseline,
        peak.load(Ordering::SeqCst)
    );
}
