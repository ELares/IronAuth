// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the binary's own `DatabaseProbe` answers, against a real database (issue #149).
//!
//! The server-side tests drive the readiness CONTRACT through a fixture probe, which is right
//! for asserting what each state renders. What they cannot cover is the production mapping:
//! `StoreReadinessProbe` is the only implementation that ships, and it turns a real store's
//! answer into the `DatabaseHealth` the endpoint acts on. A review found it untested, and the
//! stake is that reporting a serving database as unreachable takes every replica out of its
//! Service at once.

use ironauth_server::readiness::{DatabaseHealth, DatabaseProbe};
use ironauth_store::test_support::TestDatabase;

use crate::StoreReadinessProbe;

/// A migrated database, through the REAL probe, is `Serving`.
#[tokio::test]
async fn the_shipped_probe_reports_a_migrated_database_as_serving() {
    let db = TestDatabase::start().await;
    let probe = StoreReadinessProbe {
        store: db.restart_app_store().await,
    };
    assert_eq!(probe.check().await, DatabaseHealth::Serving);
}

/// An unmigrated database, through the REAL probe, is `SchemaNotReady` and NOT `Unreachable`.
///
/// The distinction is the one an operator acts on: it sends them to the rollout rather than to
/// the database. A mapping that collapsed these would page the wrong person on every failed
/// upgrade, and nothing outside this file would have noticed.
#[tokio::test]
async fn the_shipped_probe_separates_an_unmigrated_schema_from_an_unreachable_database() {
    let pool = TestDatabase::fresh_owner_pool_with_roles().await;
    // SQLx returns the role-provisioning connection through a spawned task. Wait for that
    // return before testing the schema: the production probe deliberately answers Serving
    // when a live pool has no idle connection, which is a different readiness scenario.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while pool.num_idle() == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|error| {
        panic!(
            "the unmigrated-schema fixture must have an idle connection before probing: \
             {error}; size={}, idle={}, closed={}",
            pool.size(),
            pool.num_idle(),
            pool.is_closed()
        )
    });
    let probe = StoreReadinessProbe {
        store: ironauth_store::Store::from_pool(pool),
    };
    assert_eq!(probe.check().await, DatabaseHealth::SchemaNotReady);
    assert_ne!(
        probe.check().await,
        DatabaseHealth::Unreachable,
        "an unmigrated database is reachable; reporting it as unreachable sends the operator to \
         the database owner instead of to the rollout"
    );
}

/// A CLOSED pool, through the REAL probe, is `Unreachable`.
///
/// The control for the case above: without it, a probe hard-wired to return `SchemaNotReady`
/// would pass every other test in this file.
#[tokio::test]
async fn the_shipped_probe_reports_a_closed_pool_as_unreachable() {
    let db = TestDatabase::start().await;
    let store = db.restart_app_store().await;
    let probe = StoreReadinessProbe { store };
    // Established first, so the close below is what the assertion turns on.
    assert_eq!(probe.check().await, DatabaseHealth::Serving);
    probe.store.close_pool_for_test().await;
    assert_eq!(probe.check().await, DatabaseHealth::Unreachable);
}
