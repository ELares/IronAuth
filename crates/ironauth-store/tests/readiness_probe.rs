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
use ironauth_store::{SchemaReadiness, Store};

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

    // Remove ONE applied migration from the middle of the ledger, leaving its tables in place.
    // The schema is intact; only the record of it is incomplete, which is precisely the case a
    // highest-version comparison cannot see.
    let owner = db.owner_pool();
    let removed: i64 = sqlx::query_scalar(
        "DELETE FROM _schema_migrations WHERE version = \
         (SELECT version FROM _schema_migrations ORDER BY version OFFSET 1 LIMIT 1) \
         RETURNING version",
    )
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
