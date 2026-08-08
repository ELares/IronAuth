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

/// An owner is assigned, read back through the issuance path's own reader, and cleared.
///
/// The read is `owning_organization`, the exact method `resolve_access_token_target` calls,
/// rather than a direct SELECT: a test that queried the column itself would keep passing if
/// the reader were pointed at the wrong column or dropped its scope predicate.
#[tokio::test]
async fn an_owner_is_assigned_read_back_and_cleared() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "acme").await;

    let client = db
        .store()
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .clients()
        .create(&env, "a client to be owned")
        .await
        .expect("create client");

    assert_eq!(
        db.store()
            .scoped(scope)
            .clients()
            .owning_organization(&client)
            .await
            .expect("read the owner"),
        None,
        "a freshly created client is environment-owned"
    );

    acting(&db, &env, scope)
        .set_owning_organization(&env, &client, Some(&org))
        .await
        .expect("assign the owner");
    assert_eq!(
        db.store()
            .scoped(scope)
            .clients()
            .owning_organization(&client)
            .await
            .expect("read the owner"),
        Some(org.to_string())
    );

    acting(&db, &env, scope)
        .set_owning_organization(&env, &client, None)
        .await
        .expect("clear the owner");
    assert_eq!(
        db.store()
            .scoped(scope)
            .clients()
            .owning_organization(&client)
            .await
            .expect("read the owner"),
        None,
        "clearing returns the client to environment-owned rather than to an empty string"
    );

    let actions = client_audit_actions(&db, scope, &client.to_string()).await;
    assert_eq!(
        actions
            .iter()
            .filter(|action| *action == "client.owning_organization.set")
            .count(),
        2,
        "the assignment and the clear are each audited, got {actions:?}"
    );
}

/// Re-assigning the SAME owner writes no second audit row.
///
/// The change-only `IS DISTINCT FROM` write is what makes this true, and a NULLABLE column
/// is where it earns its keep: `organization_id <> $1` answers NULL rather than true when
/// either side is NULL, so a clear-on-an-already-cleared client would match no row at all
/// and a plain equality guard would read that as a real change.
#[tokio::test]
async fn re_stating_the_same_owner_is_a_silent_no_op() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope, "acme").await;

    let client = db
        .store()
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .clients()
        .create(&env, "a client to be owned twice")
        .await
        .expect("create client");

    // Clearing an ALREADY environment-owned client: NULL to NULL, no row, no audit.
    acting(&db, &env, scope)
        .set_owning_organization(&env, &client, None)
        .await
        .expect("clearing an unowned client succeeds");
    for _ in 0..3 {
        acting(&db, &env, scope)
            .set_owning_organization(&env, &client, Some(&org))
            .await
            .expect("assign the owner");
    }

    let actions = client_audit_actions(&db, scope, &client.to_string()).await;
    assert_eq!(
        actions
            .iter()
            .filter(|action| *action == "client.owning_organization.set")
            .count(),
        1,
        "four writes and one real change must produce ONE audit row, got {actions:?}"
    );
}

/// An organization belonging to ANOTHER environment is refused.
///
/// Load-bearing rather than tidy. Migration 0121's foreign key references
/// `organizations (id)` and nothing else, so the FOREIGN KEY accepts a cross-scope owner.
/// The issuance path resolves the owner with `parse_in_scope` and fails CLOSED when it does
/// not parse in scope, so an assignment accepted here would stop that client issuing tokens
/// at all: a management write would have silently bricked a client.
///
/// What this measures is the OUTCOME, not one mechanism. A mutation sweep showed the
/// refusal survives deleting the Rust scope guard and gutting the probe's scope predicate,
/// because forced row-level security refuses the read underneath both. That is the answer
/// this test wants: no reachable single edit makes a foreign organization assignable.
#[tokio::test]
async fn an_organization_from_another_environment_is_refused() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let here = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    assert_ne!(here.environment(), elsewhere.environment());
    let foreign = create_org(&db, &env, elsewhere, "somebody else").await;

    let client = db
        .store()
        .scoped(here)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .clients()
        .create(&env, "a client that must not leave its scope")
        .await
        .expect("create client");

    let refusal = acting(&db, &env, here)
        .set_owning_organization(&env, &client, Some(&foreign))
        .await;
    assert!(
        matches!(refusal, Err(ironauth_store::StoreError::NotFound)),
        "a cross-scope owner must be the uniform not-found, got {refusal:?}"
    );
    assert_eq!(
        db.store()
            .scoped(here)
            .clients()
            .owning_organization(&client)
            .await
            .expect("read the owner"),
        None,
        "the refused write must leave the client environment-owned"
    );
}

/// An organization that does not exist is refused, and so is one that was soft-deleted.
///
/// The soft-deleted half is the one the foreign key cannot see: the row is still present,
/// so `REFERENCES organizations (id)` is satisfied, and only the explicit `deleted_at IS
/// NULL` probe refuses it.
#[tokio::test]
async fn an_absent_or_deleted_organization_is_refused() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;

    let client = db
        .store()
        .scoped(scope)
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .clients()
        .create(&env, "a client")
        .await
        .expect("create client");

    let never_created = ironauth_store::OrganizationId::generate(&env, &scope);
    assert!(
        matches!(
            acting(&db, &env, scope)
                .set_owning_organization(&env, &client, Some(&never_created))
                .await,
            Err(ironauth_store::StoreError::NotFound)
        ),
        "an organization that was never created must be refused"
    );

    let removed = create_org(&db, &env, scope, "briefly here").await;
    db.control_store()
        .management()
        .acting(
            db.test_actor(&env),
            ironauth_store::CorrelationId::generate(&env),
        )
        .organizations(scope)
        .delete(&env, &removed)
        .await
        .expect("soft delete the organization");
    assert!(
        matches!(
            acting(&db, &env, scope)
                .set_owning_organization(&env, &client, Some(&removed))
                .await,
            Err(ironauth_store::StoreError::NotFound)
        ),
        "a soft-deleted organization must be refused, which the foreign key cannot do"
    );
}

/// The acting client repository reached through the CONTROL store.
///
/// Migration 0121 grants `UPDATE (organization_id)` on `clients` to `ironauth_control` and
/// to nobody else, so the same repository method reached through the app store is refused
/// by the engine with a bare permission error. `ActingClientRepo` is deliberately reachable
/// from both stores and holds whichever it was reached through, exactly as the DCR
/// verification write already does.
fn acting<'a>(
    db: &'a TestDatabase,
    env: &ironauth_env::Env,
    scope: ironauth_store::Scope,
) -> ironauth_store::ActingClientRepo<'a> {
    db.control_store()
        .scoped(scope)
        .acting(
            db.test_actor(env),
            ironauth_store::CorrelationId::generate(env),
        )
        .clients()
}

/// Create an organization in `scope` through the control plane.
async fn create_org(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: ironauth_store::Scope,
    display_name: &str,
) -> ironauth_store::OrganizationId {
    let id = ironauth_store::OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(
            db.test_actor(env),
            ironauth_store::CorrelationId::generate(env),
        )
        .organizations(scope)
        .create(
            env,
            &id,
            i64::try_from(
                env.clock()
                    .now_utc()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .expect("after the epoch")
                    .as_micros(),
            )
            .expect("fits i64"),
            display_name,
            None,
        )
        .await
        .expect("create organization");
    id
}

/// The audit actions recorded against `target_id` in `scope`.
async fn client_audit_actions(
    db: &TestDatabase,
    scope: ironauth_store::Scope,
    target_id: &str,
) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT action FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND target_id = $3 \
         ORDER BY occurred_at",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(target_id)
    .fetch_all(db.owner_pool())
    .await
    .expect("read the audit log")
}
