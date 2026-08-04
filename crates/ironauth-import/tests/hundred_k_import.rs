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
//! # The conjunction, which is the part that was missing
//!
//! M6's exit criterion reads "100k-user import WITH FOREIGN HASHES completes with
//! verify-then-rehash working". Both halves were measured, and never together: this
//! harness imported one hundred thousand records that carried NO password hash at all,
//! while `engine.rs` proved verify-then-rehash across five schemes at a scale of about
//! thirty. A criterion stated as a conjunction is not met by proving its halves apart,
//! so every record here now carries an algorithm-tagged FOREIGN hash, and after the run
//! one of those hundred thousand imported users is driven through the full
//! verify-then-rehash landing.
//!
//! The foreign hash is minted ONCE, before the run, and the same PHC string is reused on
//! every line. That is deliberate and costs the measurement nothing: import stores the
//! tagged hash without verifying it, so per-record cost is unchanged, and the harness's
//! own memory stays one line. Hashing a hundred thousand distinct bcrypt values would
//! measure bcrypt, not the importer.
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

use argon2::PasswordVerifier;
use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
use ironauth_env::Env;
use ironauth_import::{ForeignHash, ImportContext, LineSource, import_lines_into_run};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CompletionOutcome, CorrelationId, MigrationKind, MigrationState, NewMigrationRun,
};

/// The password every imported record's foreign hash is over.
const PASSWORD: &str = "load-harness-password";

/// A cheap bcrypt (cost 4) foreign hash, the same shape `engine.rs` uses. Cost 4 keeps
/// the ONE mint and the ONE verify in this harness negligible beside the import itself;
/// the cost BOUNDS are a separate contract with their own tests, and nothing here
/// measures bcrypt.
fn bcrypt_hash(password: &str) -> String {
    bcrypt::hash_with_result(password, 4)
        .expect("bcrypt hash")
        .format_for_version(bcrypt::Version::TwoB)
}

/// Whether the row's NATIVE verifier actually authenticates `password`. Attempting the
/// verification is stronger than reading a flag: it is what the login path does, so an
/// unusable sentinel and a wrong hash both answer false for the same reason they would
/// in production.
fn native_verify(record: &ironauth_store::UserRecord, password: &str) -> bool {
    match PasswordHash::new(&record.password_hash) {
        Ok(parsed) => argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A native Argon2id verifier, the rehash target.
fn argon2_hash(password: &str) -> String {
    let salt = SaltString::from_b64("c29tZXNhbHQ").expect("salt");
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hash")
        .to_string()
}

/// One hundred thousand records, minted one at a time and never collected. Each carries
/// the SAME algorithm-tagged foreign hash, minted once by the caller.
struct Generated {
    next: usize,
    total: usize,
    foreign_hash: String,
}

impl LineSource for Generated {
    async fn next_line(&mut self) -> Option<Vec<u8>> {
        if self.next >= self.total {
            return None;
        }
        let line = format!(
            r#"{{"identifier":"load-{}@example.test","password_hash":"{}"}}"#,
            self.next, self.foreign_hash
        );
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

    let foreign_hash = bcrypt_hash(PASSWORD);
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
            foreign_hash: foreign_hash.clone(),
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

    // The second half of the criterion, on a user that came out of the hundred thousand
    // rather than out of a fixture built for this assertion. Picked from the MIDDLE of the
    // stream: the first record is the one a partially-working importer is most likely to
    // get right, and the last is the one an off-by-one is most likely to drop.
    let identifier = format!("load-{}@example.test", TOTAL / 2);
    let imported = store
        .scoped(scope)
        .users()
        .by_identifier(&identifier)
        .await
        .expect("look the imported user up")
        .expect("the middle record of the hundred thousand exists");
    assert_eq!(
        imported.foreign_password_algo.as_deref(),
        Some("bcrypt"),
        "the imported row carries its algorithm TAG, which is what verification \
         dispatches on"
    );
    let stored_foreign = imported
        .foreign_password_hash
        .as_deref()
        .expect("a foreign hash before the first login");
    assert!(
        !native_verify(&imported, PASSWORD),
        "the native verifier is the unusable import sentinel until the first login"
    );
    assert!(
        ForeignHash::parse(stored_foreign)
            .expect("parse the stored foreign hash")
            .verify(PASSWORD.as_bytes()),
        "the original password verifies against the imported foreign hash"
    );

    // The landing, exactly as the login handler performs it.
    let upgraded = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .users()
        .upgrade_foreign_password(&env, &imported.id, &argon2_hash(PASSWORD))
        .await
        .expect("upgrade the foreign hash");
    assert!(upgraded, "the first upgrade flips the row");

    let after = store
        .scoped(scope)
        .users()
        .by_identifier(&identifier)
        .await
        .expect("re-read")
        .expect("still present");
    assert!(
        after.foreign_password_hash.is_none() && after.foreign_password_algo.is_none(),
        "the foreign hash is RETIRED once rehashed, so the second login has only \
         Argon2id to verify against"
    );
    assert!(
        native_verify(&after, PASSWORD),
        "and the ORIGINAL password now authenticates against Argon2id alone, which is \
         what makes the migration lossless"
    );

    println!(
        "100k import: baseline rss {:?} KiB, peak rss {} KiB, report {report:?}, tallies {tallies:?}",
        baseline,
        peak.load(Ordering::SeqCst)
    );
    println!(
        "verify-then-rehash: {identifier} imported on a foreign bcrypt hash, verified, \
         rehashed to Argon2id, foreign hash retired"
    );
}
