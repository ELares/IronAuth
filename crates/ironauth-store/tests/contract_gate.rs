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

/// Stopping, not skipping. The ordering rule refuses to apply a version while a lower one
/// is pending, so a runner that skipped the contract migration and carried on would leave a
/// chain the NEXT run rejects outright. This pins that everything behind it waits too.
#[tokio::test]
async fn everything_behind_a_deferred_contract_migration_waits_with_it() {
    let pool = TestDatabase::fresh_owner_pool().await;
    MigrationRunner::from_migrations(&pool, previous_release())
        .run()
        .await
        .expect("the previous release applies");

    let mut longer = chain();
    longer.push(Migration {
        version: 5,
        name: "after the removal",
        phase: Phase::Expand,
        sql: "ALTER TABLE parts ADD COLUMN added_after text;",
    });

    let report = MigrationRunner::from_migrations(&pool, longer.clone())
        .run()
        .await
        .expect("the additive half applies");
    assert_eq!(report.newly_applied(), &[2, 3]);
    assert_eq!(report.deferred_from(), Some(4));

    let column: i64 = sqlx::query(
        "SELECT count(*) AS n FROM information_schema.columns \
         WHERE table_name = 'parts' AND column_name = 'added_after'",
    )
    .fetch_one(&pool)
    .await
    .expect("catalog read")
    .get("n");
    assert_eq!(
        column, 0,
        "version 5 sits behind the deferred contract migration"
    );

    // And the next run is not refused as out of order, which is what skipping would cause.
    let again = MigrationRunner::from_migrations(&pool, longer.clone())
        .run()
        .await
        .expect("a second deferred run is still a valid chain, not an out-of-order refusal");
    assert_eq!(again.newly_applied(), &[] as &[i64]);
    assert_eq!(again.deferred_from(), Some(4));

    // Confirming releases both.
    let confirmed = MigrationRunner::from_migrations(&pool, longer)
        .with_contract(ContractPolicy::Allowed)
        .run()
        .await
        .expect("confirmed");
    assert_eq!(confirmed.newly_applied(), &[4, 5]);
}

/// The unattended form. A soak longer than the schema has existed must NOT open the door,
/// and one shorter than it must. Both directions, because a window that always opens and a
/// window that never opens are each satisfied by only checking one.
#[tokio::test]
async fn a_soak_window_opens_only_once_it_has_elapsed() {
    let pool = TestDatabase::fresh_owner_pool().await;
    MigrationRunner::from_migrations(&pool, previous_release())
        .run()
        .await
        .expect("the previous release applies");
    MigrationRunner::from_migrations(&pool, chain())
        .run()
        .await
        .expect("the additive half applies");

    let too_soon = MigrationRunner::from_migrations(&pool, chain())
        .with_contract(ContractPolicy::AfterSoak(Duration::from_secs(86_400)))
        .run()
        .await
        .expect("runs");
    assert_eq!(
        too_soon.deferred_from(),
        Some(4),
        "a 24h soak on a schema applied seconds ago must not open"
    );

    let elapsed = MigrationRunner::from_migrations(&pool, chain())
        .with_contract(ContractPolicy::AfterSoak(Duration::ZERO))
        .run()
        .await
        .expect("runs");
    assert_eq!(
        elapsed.newly_applied(),
        &[4],
        "a zero soak has always elapsed"
    );
    assert_eq!(elapsed.deferred_from(), None);
}

/// The shipped chain has three contract migrations, so this gate is not theoretical: an
/// existing deployment upgrading across one of them stops, rather than dropping a column
/// the running binary still reads.
#[tokio::test]
async fn the_shipped_chain_defers_its_real_contract_migrations_on_an_upgrade() {
    let pool = TestDatabase::fresh_owner_pool_with_roles().await;
    let full = ironauth_store::chain();
    let first_contract = full
        .iter()
        .find(|migration| migration.phase == Phase::Contract)
        .expect("the shipped chain has a contract migration");

    // A database at the release just before that removal.
    let before: Vec<Migration> = full
        .iter()
        .take_while(|migration| migration.version < first_contract.version)
        .copied()
        .collect();
    MigrationRunner::from_migrations(&pool, before)
        .run()
        .await
        .expect("the previous release applies");

    let report = MigrationRunner::from_migrations(&pool, full.clone())
        .run()
        .await
        .expect("the upgrade runs");
    assert_eq!(
        report.deferred_from(),
        Some(first_contract.version),
        "the real chain stops at its real removal"
    );

    // Confirmed, the whole chain applies, so the gate is not a permanent block.
    let confirmed = MigrationRunner::from_migrations(&pool, full)
        .with_contract(ContractPolicy::Allowed)
        .run()
        .await
        .expect("confirmed");
    assert_eq!(confirmed.deferred_from(), None);
}
