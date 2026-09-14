// SPDX-License-Identifier: MIT OR Apache-2.0

//! The contract-phase gate: a minor release rolls back cleanly before its removal step
//! (issue #148).
//!
//! Expand and Migrate are additive, so a binary that has applied them can be replaced by
//! the previous one and lose nothing. Contract is the step that removes the old shape, and
//! it is the one that cannot be taken back: once the column is dropped, rolling the binary
//! back does not bring the data with it.
//!
//! So the claim under test is not "the runner skips a phase". It is that there EXISTS a
//! state in which the new schema is in place and the OLD binary's reads and writes still
//! work, and that the runner stops there by default. Every test here checks the state, not
//! just the stopping.

use std::time::Duration;

use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ContractPolicy, Migration, MigrationRunner, Phase};
use sqlx::Row;

/// v1: the shape the PREVIOUS release serves.
const V1: &str = "CREATE TABLE parts (id bigint PRIMARY KEY, old_name text NOT NULL);";
/// v2 (expand): the new column, additive, both binaries fine.
const V2: &str = "ALTER TABLE parts ADD COLUMN new_name text;";
/// v3 (migrate): backfill, still additive.
const V3: &str = "UPDATE parts SET new_name = old_name WHERE new_name IS NULL;";
/// v4 (contract): the removal. This is the one-way door.
const V4: &str = "ALTER TABLE parts DROP COLUMN old_name;";

fn chain() -> Vec<Migration> {
    vec![
        Migration {
            version: 1,
            name: "create parts",
            phase: Phase::Expand,
            sql: V1,
        },
        Migration {
            version: 2,
            name: "add new_name",
            phase: Phase::Expand,
            sql: V2,
        },
        Migration {
            version: 3,
            name: "backfill new_name",
            phase: Phase::Migrate,
            sql: V3,
        },
        Migration {
            version: 4,
            name: "drop old_name",
            phase: Phase::Contract,
            sql: V4,
        },
    ]
}

/// The release the operator is upgrading FROM: v1 only.
fn previous_release() -> Vec<Migration> {
    chain().into_iter().take(1).collect()
}

async fn old_binary_can_still_serve(pool: &sqlx::PgPool) -> bool {
    // Exactly what the previous binary does: it writes old_name and reads it back. If the
    // contract migration has run, both statements fail.
    if sqlx::query("INSERT INTO parts (id, old_name) VALUES (99, 'written by the old binary')")
        .execute(pool)
        .await
        .is_err()
    {
        return false;
    }
    sqlx::query("SELECT old_name FROM parts WHERE id = 99")
        .fetch_one(pool)
        .await
        .is_ok_and(|row| row.get::<String, _>("old_name") == "written by the old binary")
}

/// The criterion: an upgrade stops before the removal, and in the state it stops in, the
/// PREVIOUS release still works. That second half is what makes the rollback safe, and a
/// test that only asserted "version 4 is not applied" would not have checked it.
#[tokio::test]
async fn an_upgrade_stops_before_the_contract_phase_and_the_previous_release_still_serves() {
    let pool = TestDatabase::fresh_owner_pool().await;
    MigrationRunner::from_migrations(&pool, previous_release())
        .run()
        .await
        .expect("the previous release applies");
    sqlx::query("INSERT INTO parts (id, old_name) VALUES (1, 'a'), (2, 'b')")
        .execute(&pool)
        .await
        .expect("seed the rows the previous release wrote");

    let report = MigrationRunner::from_migrations(&pool, chain())
        .run()
        .await
        .expect("the upgrade applies its additive half");

    assert_eq!(
        report.newly_applied(),
        &[2, 3],
        "expand and migrate apply; the contract migration does not"
    );
    assert_eq!(
        report.deferred_from(),
        Some(4),
        "and it says which one it stopped before"
    );

    // The new shape is in place...
    let backfilled: i64 = sqlx::query("SELECT count(*) AS n FROM parts WHERE new_name IS NOT NULL")
        .fetch_one(&pool)
        .await
        .expect("the backfill ran")
        .get("n");
    assert_eq!(backfilled, 2);

    // ...and the old one still works, which is the whole point.
    assert!(
        old_binary_can_still_serve(&pool).await,
        "the previous release must still read and write its own column in the deferred state"
    );
}

/// Without this, the test above is satisfied by a runner that never applies a contract
/// migration at all, which would be a different bug.
#[tokio::test]
async fn the_operator_confirming_applies_the_contract_migration() {
    let pool = TestDatabase::fresh_owner_pool().await;
    MigrationRunner::from_migrations(&pool, previous_release())
        .run()
        .await
        .expect("the previous release applies");
    sqlx::query("INSERT INTO parts (id, old_name) VALUES (1, 'a')")
        .execute(&pool)
        .await
        .expect("seed");

    let deferred = MigrationRunner::from_migrations(&pool, chain())
        .run()
        .await
        .expect("the additive half applies");
    assert_eq!(deferred.deferred_from(), Some(4));

    let confirmed = MigrationRunner::from_migrations(&pool, chain())
        .with_contract(ContractPolicy::Allowed)
        .run()
        .await
        .expect("the confirmed run applies the removal");

    assert_eq!(confirmed.newly_applied(), &[4]);
    assert_eq!(confirmed.deferred_from(), None);
    assert!(
        !old_binary_can_still_serve(&pool).await,
        "after the removal the previous release can no longer serve, which is why it is gated"
    );
}

/// A fresh install is not an upgrade: no previous binary is serving it, so there is no old
/// shape to protect. Deferring there would leave a brand-new database permanently short of
/// its own schema.
#[tokio::test]
async fn a_fresh_install_applies_the_whole_chain_including_contract() {
    let pool = TestDatabase::fresh_owner_pool().await;

    let report = MigrationRunner::from_migrations(&pool, chain())
        .run()
        .await
        .expect("a fresh install applies");

    assert_eq!(report.newly_applied(), &[1, 2, 3, 4]);
    assert_eq!(report.deferred_from(), None);
}

/// Stopping, not skipping, when a deferral does happen.
///
/// The ordering rule refuses to apply a version while a lower one is pending, so a runner
/// that skipped a contract migration and carried on would leave a chain the NEXT run
/// rejects outright. The deferral must therefore withhold everything behind it -- which is
/// safe only because the rule now defers ONLY a trailing run of removals, so everything
/// withheld is itself a removal. Two adjacent contract migrations are that shape.
#[tokio::test]
async fn a_deferral_withholds_the_removals_behind_it_without_breaking_the_next_run() {
    let pool = TestDatabase::fresh_owner_pool().await;
    MigrationRunner::from_migrations(&pool, previous_release())
        .run()
        .await
        .expect("the previous release applies");

    let mut two_removals = chain();
    two_removals.push(Migration {
        version: 5,
        name: "drop the backfilled column too",
        phase: Phase::Contract,
        sql: "ALTER TABLE parts DROP COLUMN new_name;",
    });

    let report = MigrationRunner::from_migrations(&pool, two_removals.clone())
        .run()
        .await
        .expect("the additive half applies");
    assert_eq!(report.newly_applied(), &[2, 3]);
    assert_eq!(report.deferred_from(), Some(4));

    // Version 5 is withheld with 4, and it is itself a removal, so nothing the new binary
    // needs is missing.
    let column: i64 = sqlx::query(
        "SELECT count(*) AS n FROM information_schema.columns \
         WHERE table_name = 'parts' AND column_name = 'new_name'",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog read")
    .get("n");
    assert_eq!(
        column, 1,
        "the additive column is present; only the removals wait"
    );

    // The next run is not an out-of-order refusal, which is what skipping would cause.
    let again = MigrationRunner::from_migrations(&pool, two_removals.clone())
        .run()
        .await
        .expect("a second deferred run is still a valid chain");
    assert_eq!(again.newly_applied(), &[] as &[i64]);
    assert_eq!(again.deferred_from(), Some(4));

    // Confirming releases both removals.
    let confirmed = MigrationRunner::from_migrations(&pool, two_removals)
        .with_contract(ContractPolicy::Allowed)
        .run()
        .await
        .expect("confirmed");
    assert_eq!(confirmed.newly_applied(), &[4, 5]);
}

/// The unattended form, measured against a REAL elapsed time rather than the two degenerate
/// windows that prove nothing.
///
/// The first version of this test used only a 24h window (never elapsed) and `Duration::ZERO`
/// (always elapsed). Replacing the entire soak query with `soak.is_zero()` passed it, so the
/// predecessor scope, the aggregate, the choice of the database clock, and `>=` were all
/// unmeasured. Here the ledger is backdated by a known amount and the window is placed on
/// either side of it, so the comparison itself is what decides.
#[tokio::test]
async fn a_soak_window_is_compared_against_how_long_the_schema_has_been_in_place() {
    let pool = TestDatabase::fresh_owner_pool().await;
    MigrationRunner::from_migrations(&pool, previous_release())
        .run()
        .await
        .expect("the previous release applies");
    MigrationRunner::from_migrations(&pool, chain())
        .run()
        .await
        .expect("the additive half applies");

    // The schema has now been in place for two hours, as the database measures it.
    sqlx::query("UPDATE _schema_migrations SET applied_at = now() - interval '2 hours'")
        .execute(&pool)
        .await
        .expect("backdate the ledger");

    let too_long = MigrationRunner::from_migrations(&pool, chain())
        .with_contract(ContractPolicy::AfterSoak(Duration::from_secs(3 * 3600)))
        .run()
        .await
        .expect("runs");
    assert_eq!(
        too_long.deferred_from(),
        Some(4),
        "a three-hour window against a two-hour-old schema must stay shut"
    );

    let elapsed = MigrationRunner::from_migrations(&pool, chain())
        .with_contract(ContractPolicy::AfterSoak(Duration::from_secs(3600)))
        .run()
        .await
        .expect("runs");
    assert_eq!(
        elapsed.newly_applied(),
        &[4],
        "a one-hour window against a two-hour-old schema must open"
    );
    assert_eq!(elapsed.deferred_from(), None);
}

/// The window must measure the DEPLOYMENT, not this run's own work.
///
/// Each migration the runner applies commits a ledger row stamped `now()`. Reading the newest
/// `applied_at` per-migration therefore re-armed the window against a row the gate had just
/// written: the additive half lands seconds before the contract migration is considered, so
/// an elapsed-time check made after it would see seconds however long the operator waited.
#[tokio::test]
async fn the_soak_window_is_not_restarted_by_this_runs_own_additive_migrations() {
    let pool = TestDatabase::fresh_owner_pool().await;
    MigrationRunner::from_migrations(&pool, previous_release())
        .run()
        .await
        .expect("the previous release applies");
    // The PREVIOUS release has been in place for two hours.
    sqlx::query("UPDATE _schema_migrations SET applied_at = now() - interval '2 hours'")
        .execute(&pool)
        .await
        .expect("backdate");

    // One run, with the additive half and the removal considered together. The additive
    // migrations land NOW; the removal must still be judged against the two-hour-old
    // schema, not against the rows this very run just wrote.
    let report = MigrationRunner::from_migrations(&pool, chain())
        .with_contract(ContractPolicy::AfterSoak(Duration::from_secs(3600)))
        .run()
        .await
        .expect("runs");

    assert_eq!(
        report.newly_applied(),
        &[2, 3, 4],
        "the window was open when the run began, so the whole chain applies in one pass"
    );
    assert_eq!(report.deferred_from(), None);
}

/// THE PREMISE, as a test. Whatever the gate withholds must itself be a removal.
///
/// The first version of this gate stopped at the first pending contract migration whatever
/// followed it, justified by "the migrations after a removal presume the removal". That is
/// false for the shipped chain, whose first contract migration is version 168 of 228: the
/// 60 behind it are ordinary additive ones, and one of them creates a table the login path
/// queries. Stopping there would have handed a deployment a schema its new binary cannot
/// run against, while reporting that it had stopped somewhere safe.
#[tokio::test]
async fn nothing_additive_is_ever_withheld_by_a_deferral() {
    let pool = TestDatabase::fresh_owner_pool().await;
    MigrationRunner::from_migrations(&pool, previous_release())
        .run()
        .await
        .expect("the previous release applies");

    // A contract migration with ordinary additive work behind it: the shape the shipped
    // chain actually has.
    let mut interleaved = chain();
    interleaved.push(Migration {
        version: 5,
        name: "a later additive migration",
        phase: Phase::Expand,
        sql: "ALTER TABLE parts ADD COLUMN added_later text;",
    });

    let report = MigrationRunner::from_migrations(&pool, interleaved)
        .run()
        .await
        .expect("runs");

    assert_eq!(
        report.deferred_from(),
        None,
        "a removal with additive work behind it must APPLY: the chain cannot reach that \
         work otherwise, and withholding it leaves the new binary without its schema"
    );
    assert_eq!(report.newly_applied(), &[2, 3, 4, 5]);
}

/// The shipped chain, which is the case the premise was wrong about.
///
/// Its contract migrations sit at versions 168, 193 and 194 of 228, so every one of them
/// has additive work behind it and the gate applies the lot. That is the correct answer for
/// a jump across many releases: a removal from sixty versions back is not the rollback
/// boundary of the release being installed. Asserting it here pins that the rule is keyed
/// on what FOLLOWS a removal rather than on the removal itself.
#[tokio::test]
async fn the_shipped_chain_applies_removals_that_have_additive_work_behind_them() {
    let pool = TestDatabase::fresh_owner_pool_with_roles().await;
    let full = ironauth_store::chain();
    let first_contract = *full
        .iter()
        .find(|migration| migration.phase == Phase::Contract)
        .expect("the shipped chain has a contract migration");
    assert!(
        full.iter()
            .any(|m| m.version > first_contract.version && m.phase != Phase::Contract),
        "this test is about a removal with additive work behind it; if the chain ever ends \
         in its removals, rewrite it rather than deleting it"
    );

    let before: Vec<Migration> = full
        .iter()
        .take_while(|migration| migration.version < first_contract.version)
        .copied()
        .collect();
    MigrationRunner::from_migrations(&pool, before)
        .run()
        .await
        .expect("the previous release applies");

    let report = MigrationRunner::from_migrations(&pool, full)
        .run()
        .await
        .expect("the upgrade runs");

    assert_eq!(
        report.deferred_from(),
        None,
        "withholding version {} would also withhold the additive migrations behind it",
        first_contract.version
    );
    // And the schema really is current, which is the thing the old rule quietly broke.
    let highest: i64 = sqlx::query("SELECT MAX(version) AS v FROM _schema_migrations")
        .fetch_one(&pool)
        .await
        .expect("ledger read")
        .get("v");
    assert_eq!(
        highest,
        ironauth_store::chain().last().expect("non-empty").version,
        "the upgrade must leave the schema at the chain head"
    );
}
