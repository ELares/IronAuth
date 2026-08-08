// SPDX-License-Identifier: MIT OR Apache-2.0

//! Org-scoped clients are inert until opted into (issue #103, bet 1, criterion 2).
//!
//! Criterion 2 is that with the flag off there is ZERO behaviour change attributable to
//! this issue. The flag half is pinned in `ironauth-config`; this is the SCHEMA half, and
//! it is the half that can break silently.
//!
//! Migration 0121 adds `clients.organization_id` as NULLABLE with no default. That single
//! property is what makes the migration safe on a populated database: no row is
//! rewritten, and every client that existed keeps an owner of NULL, which means "owned by
//! the environment" and is exactly what those clients are.
//!
//! # Why this needs a test rather than a reading of the migration
//!
//! A mutation making the column `NOT NULL DEFAULT 'org_forced'` passed the entire
//! migration suite. It applied cleanly, the chain count matched, every subject was
//! present. It passed only because the test database has no `clients` rows: the same
//! statement against a populated database would fail the foreign key, or, with a default
//! naming a real organization, would silently hand every existing client to one
//! organization. The suite that exists cannot see the difference, which is why this is
//! here.

use ironauth_store::test_support::TestDatabase;

/// The column is nullable and defaulted to nothing.
#[tokio::test]
async fn the_owner_column_is_nullable_with_no_default() {
    let db = TestDatabase::start().await;
    let row: (String, Option<String>) = sqlx::query_as(
        "SELECT is_nullable, column_default FROM information_schema.columns \
         WHERE table_name = 'clients' AND column_name = 'organization_id'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("the organization_id column exists on clients");

    assert_eq!(
        row.0, "YES",
        "clients.organization_id must be NULLABLE. NOT NULL forces every client that \
         already exists to acquire an owner at upgrade, which is either a failed \
         migration or, worse, a silent reassignment of every client to one organization"
    );
    assert_eq!(
        row.1, None,
        "clients.organization_id must have NO default. A default applies to every INSERT \
         regardless of intent, so an environment-owned client created tomorrow would \
         silently acquire an owner. Got default {:?}",
        row.1
    );
}

/// An environment-owned client is representable and is the ordinary case.
///
/// NULL here is a MEANINGFUL value, not an absence to be tidied away: the
/// environment-owned client stays the default forever and org-ownership is the opt-in.
#[tokio::test]
async fn a_client_with_no_owner_is_representable_and_unremarkable() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;

    let id = ironauth_store::ClientId::generate(&env, &scope);
    // The APP role, not the control role: clients are registered by the data plane and
    // the control role holds no INSERT on them (the #31 least-privilege split).
    db.store()
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .clients()
        .create(&env, "an ordinary client")
        .await
        .expect("a client created through the ordinary path still works");
    let _ = id;

    let unowned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM clients \
         WHERE tenant_id = $1 AND environment_id = $2 AND organization_id IS NULL",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count unowned clients");

    assert!(
        unowned >= 1,
        "a client created through the ordinary path must land with NO owner, or migration \
         0121 changed behaviour for callers that never asked for org-scoped clients"
    );
}
