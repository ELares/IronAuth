// SPDX-License-Identifier: MIT OR Apache-2.0

//! What `/readyz` asks the database, against a real one (issue #149).
//!
//! `Store::probe_readiness` is the half of the readiness change that can only be tested with a
//! database in the loop. The HTTP contract is covered in `ironauth-server`; this covers whether
//! the answer it is handed is right.
//!
//! The defect being closed: readiness used to open a bare TCP socket and call that ready, so a
//! database that was reachable but unmigrated reported healthy. The second test here is that
//! case, and it is the one that would have passed before.

#![cfg(feature = "testing")]

use ironauth_store::test_support::TestDatabase;
use ironauth_store::{Phase, SchemaReadiness, Store};

/// A fully migrated database is serving.
#[tokio::test]
async fn a_migrated_database_is_serving() {
    let db = TestDatabase::start().await;
    let store = db.restart_app_store().await;
    assert_eq!(
        store.probe_readiness().await.expect("the probe to answer"),
        SchemaReadiness::Serving
    );
}

/// THE DEFECT, as a test: a reachable database with no schema is NOT ready.
///
/// This is the deployment a socket check called healthy. The pool connects, the server accepts,
/// and not one table the code reads exists. An orchestrator seeing `ready` here routes traffic
/// into a pod that answers every request with an error.
#[tokio::test]
async fn a_reachable_but_unmigrated_database_is_not_ready() {
    let pool = TestDatabase::fresh_owner_pool_with_roles().await;
    let store = Store::from_pool(pool);
    assert_eq!(
        store.probe_readiness().await.expect(
            "an unmigrated database must ANSWER rather than error: it is reachable, which is \
             exactly why the socket check passed and why this state needs its own verdict"
        ),
        SchemaReadiness::NotMigrated
    );
}

/// A database whose ledger EXISTS but is missing a migration is not ready either.
///
/// Distinct from the empty case on purpose. A partially applied chain is what a rollout that
/// failed midway leaves behind, and it is the state most likely to be mistaken for finished:
/// the ledger is there, tables are there, and a check that only asked "does the ledger exist"
/// would pass. It is also why the implementation requires EVERY version to be present rather
/// than comparing the highest one, which a gap in the middle would slip past.
#[tokio::test]
async fn a_partially_migrated_database_is_not_ready() {
    let db = TestDatabase::start().await;
    let store = db.restart_app_store().await;
    // Established first, so the deletion below is what changes the answer rather than the
    // fixture never having been ready at all.
    assert_eq!(
        store.probe_readiness().await.expect("the probe to answer"),
        SchemaReadiness::Serving
    );

    // Remove ONE applied NON-CONTRACT migration from the middle of the ledger, leaving its
    // tables in place. The schema is intact; only the record of it is incomplete, which is
    // precisely the case a highest-version comparison cannot see.
    //
    // NOT `OFFSET 1` AND NOT ANY ROW. A contract migration is allowed to be unapplied, so
    // deleting one at random would sometimes assert the exact opposite of the rule and pass or
    // fail by luck of the chain's ordering. The phase is chosen here rather than assumed.
    let owner = db.owner_pool();
    let target = ironauth_store::chain()
        .into_iter()
        .find(|migration| migration.phase != Phase::Contract)
        .expect("the chain to contain a non-contract migration")
        .version;
    let removed: i64 =
        sqlx::query_scalar("DELETE FROM _schema_migrations WHERE version = $1 RETURNING version")
            .bind(target)
            .fetch_one(owner)
            .await
            .expect("a migration to remove");

    assert_eq!(
        store.probe_readiness().await.expect("the probe to answer"),
        SchemaReadiness::NotMigrated,
        "version {removed} is missing from the ledger, so this build's chain is not fully applied"
    );
}

/// A database running AHEAD of this build is ready, and that is deliberate.
///
/// During a rolling upgrade the new version migrates first and the old pods keep serving. If an
/// unrecognised version read as not-ready, every old replica would leave rotation the moment the
/// migration landed: an outage caused by the readiness check rather than detected by it.
#[tokio::test]
async fn a_database_ahead_of_this_build_is_still_serving() {
    let db = TestDatabase::start().await;
    let store = db.restart_app_store().await;
    let owner = db.owner_pool();
    sqlx::query(
        "INSERT INTO _schema_migrations (version, name, checksum, phase) \
         VALUES (99999999, 'from-a-newer-build', 'x', 'expand')",
    )
    .execute(owner)
    .await
    .expect("a future migration row");

    assert_eq!(
        store.probe_readiness().await.expect("the probe to answer"),
        SchemaReadiness::Serving
    );
}

/// A DEPLOYMENT WITH ITS CONTRACT MIGRATIONS DEFERRED IS SERVING, and this is the regression
/// test for the worst defect this change nearly shipped.
///
/// `ContractPolicy::Deferred` is the DEFAULT. The runner stops before the first pending contract
/// migration on purpose, because a removal is a one-way door an operator opens deliberately
/// rather than by restarting a pod, and until they do "the new binary and the old one can BOTH
/// serve, which is what makes a minor release rollback-safe".
///
/// The first version of `probe_readiness` required every version in the chain. Against a
/// correctly upgraded deployment sitting in exactly that supported state, it would have reported
/// not-ready and taken EVERY replica out of rotation at once, which is a far worse failure than
/// the socket check it replaced. A readiness check must not be the thing that causes the outage.
#[tokio::test]
async fn a_deployment_with_contract_migrations_deferred_is_still_serving() {
    let db = TestDatabase::start().await;
    let store = db.restart_app_store().await;
    let owner = db.owner_pool();

    // Establish the baseline first, so the deletion below is what the assertion turns on.
    assert_eq!(
        store.probe_readiness().await.expect("the probe to answer"),
        SchemaReadiness::Serving
    );

    // Un-apply EVERY contract migration, which is the state the default policy leaves behind.
    let contracts: Vec<i64> = ironauth_store::chain()
        .into_iter()
        .filter(|migration| migration.phase == Phase::Contract)
        .map(|migration| migration.version)
        .collect();
    assert!(
        !contracts.is_empty(),
        "the chain must contain a contract migration for this test to mean anything: with none, \
         it would pass against an implementation that ignores phase entirely"
    );
    for version in &contracts {
        sqlx::query("DELETE FROM _schema_migrations WHERE version = $1")
            .bind(version)
            .execute(owner)
            .await
            .expect("to un-apply a contract migration");
    }

    assert_eq!(
        store.probe_readiness().await.expect("the probe to answer"),
        SchemaReadiness::Serving,
        "{} contract migrations are pending, which is the DEFAULT and rollback-safe state; \
         reporting not-ready here would 503 every replica of a correctly upgraded deployment",
        contracts.len()
    );
}

/// A LEDGER THIS ROLE CANNOT READ is reported as not-migrated, not as a dead database.
///
/// This is the rolling-upgrade case the SQLSTATE 42501 arm exists for, and it had no test. The
/// grant that lets the serving role read the ledger ships as migration 0230, so a deployment
/// part-way through adopting this build has the new binary and not yet the grant. Reporting
/// that as "database unreachable" would send an operator to the database owner during a
/// perfectly ordinary upgrade.
///
/// Revoking is how the state is reached here. The cause a revoke shares with an unapplied 0230
/// is the only thing the probe can see, which is why `DatabaseHealth::SchemaNotReady` is
/// documented as "cannot confirm the schema" rather than as "is unmigrated".
#[tokio::test]
async fn a_ledger_this_role_cannot_read_is_not_migrated_rather_than_unreachable() {
    let db = TestDatabase::start().await;
    let store = db.restart_app_store().await;
    let owner = db.owner_pool();

    // Established first, so the revoke below is what the assertion turns on.
    assert_eq!(
        store.probe_readiness().await.expect("the probe to answer"),
        SchemaReadiness::Serving
    );

    sqlx::query("REVOKE SELECT ON _schema_migrations FROM ironauth_app")
        .execute(owner)
        .await
        .expect("to revoke the ledger grant");

    assert_eq!(
        store.probe_readiness().await.expect(
            "a permission error must be an ANSWER, not an error: the instance is \
                     connected and querying, and only this one grant is missing"
        ),
        SchemaReadiness::NotMigrated
    );
}
