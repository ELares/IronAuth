// SPDX-License-Identifier: MIT OR Apache-2.0

//! Outbound SCIM connections: where an environment PUSHES an organization's directory
//! (issue #137), over a real database (`DATABASE_URL`).
//!
//! # The mirror of the inbound table, and the inversion is what needs testing
//!
//! Inbound, an identity provider holds a token and writes INTO IronAuth, and the security
//! question is whether a credential for organization A can reach organization B. Outbound,
//! IronAuth holds a credential and writes into somebody ELSE'S application, and the question
//! turns around: whose directory can a given connection read, and can a control-plane caller
//! point a credential at an organization that is not theirs.
//!
//! Postgres referential integrity BYPASSES row-level security, so the `organizations` foreign
//! key resolves any globally existing organization -- including one in another tenant. The typed
//! `OrganizationId` is what stops that, and this file measures it rather than trusting it.
//!
//! # The credential is not here, and that is a property worth a test
//!
//! The row names an `environment_secrets` entry; it has no column that could hold a token. A
//! test that greps the stored row for a secret VALUE is how that stays true.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewScimPushConnection, OrganizationId, ScimBackfillState, ScimDeletionPolicy,
    ScimPushConnectionId, ScimWriteMode, Scope, StoreError,
};

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now_micros(env), name, None)
        .await
        .expect("create organization");
    id
}

/// Create a connection with everything at its default, returning the handle.
async fn push_to(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
) -> ScimPushConnectionId {
    let id = ScimPushConnectionId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .scim_push_connections()
        .create(
            env,
            NewScimPushConnection {
                id: &id,
                organization_id: organization,
                display_name: "Downstream SaaS",
                base_url: "https://downstream.example/scim/v2",
                credential_secret_name: "scim_push_downstream",
                attribute_mapping: &serde_json::json!({}),
                user_scope_filter: None,
                group_scope_filter: None,
                write_mode: ScimWriteMode::Patch,
                deletion_policy: ScimDeletionPolicy::Deactivate,
            },
            None,
            None,
        )
        .await
        .expect("create the connection");
    id
}

/// The value stored under the connection's secret name, so the "no credential in the row" guard
/// has something it could actually find. A distinctive literal rather than a realistic token:
/// what matters is that a substring search can distinguish present from absent.
const DOWNSTREAM_TOKEN: &str = "downstream-token-must-not-appear-in-a-row";

/// A connection round-trips with every field, and carries no credential.
#[tokio::test]
async fn a_connection_round_trips_and_holds_no_credential() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Acme").await;
    let id = push_to(&db, &env, scope, &org).await;

    let stored = db
        .store()
        .scoped(scope)
        .scim_push_connections()
        .get(&id)
        .await
        .expect("the connection reads back");
    assert_eq!(stored.id, id);
    assert_eq!(stored.organization_id, org);
    assert_eq!(stored.display_name, "Downstream SaaS");
    assert_eq!(stored.base_url, "https://downstream.example/scim/v2");
    assert_eq!(stored.credential_secret_name, "scim_push_downstream");
    assert_eq!(stored.write_mode, ScimWriteMode::Patch);
    assert_eq!(stored.deletion_policy, ScimDeletionPolicy::Deactivate);
    assert!(stored.active, "a new connection serves by default");
    assert_eq!(stored.cursor_sequence, None, "nothing has been pushed yet");
    assert_eq!(stored.backfill_state, ScimBackfillState::Pending);
    assert_eq!(stored.consecutive_failures, 0);
    assert_eq!(stored.last_error, None);

    // NO CREDENTIAL ANYWHERE IN THE ROW, and the test is arranged so that claim can FAIL.
    //
    // The first version searched the rendered row for the word "bearer" against a fixture that
    // had no secret in it at all: nothing existed that could have leaked, so the assertion was
    // satisfied by absence and would have passed against a struct with a credential field
    // holding any other value. A guard whose subject does not exist is not a guard.
    //
    // So the secret is REAL here. `DOWNSTREAM_TOKEN` is put into `environment_secrets` under
    // exactly the name this connection carries, and what the row is searched for is that VALUE.
    // Now the assertion has something to find, and a field that resolved the named secret --
    // the convenience field this exists to catch -- fails it.
    let (actor, corr) = (db.test_actor(&env), CorrelationId::generate(&env));
    db.store()
        .scoped(scope)
        .acting(actor, corr)
        .environment_secrets()
        .put(
            &env,
            &db.master_key(),
            "scim_push_downstream",
            DOWNSTREAM_TOKEN.as_bytes(),
            None,
        )
        .await
        .expect("the downstream credential is stored as an environment secret");

    let reread = db
        .store()
        .scoped(scope)
        .scim_push_connections()
        .get(&id)
        .await
        .expect("still reads back once the secret exists");
    let rendered = format!("{reread:?}");
    assert!(
        rendered.contains("scim_push_downstream"),
        "the secret NAME is the point of the column"
    );
    assert!(
        !rendered.contains(DOWNSTREAM_TOKEN),
        "the row resolved the secret it only names: {rendered}"
    );
}

/// A connection in another scope is invisible, not merely unreadable.
///
/// # WHAT ENFORCES THIS, and what this test can and cannot separate
///
/// THREE independent mechanisms deliver this outcome, and THIS TEST CANNOT TELL THEM APART.
/// Saying so is the point of the section: two earlier versions of this note each credited one
/// of them, and a mutation run falsified each in turn.
///
///   1. The REPOSITORY'S OWN GUARD. `get` opens with `if id.scope() != self.scope`, and the
///      listing with the same comparison on the organization. Both return before any SQL is
///      issued, which is why the two mechanisms below are not reached here at all -- the claim
///      that this test observes them was simply wrong.
///   2. The SELECT'S PREDICATES on `tenant_id` and `environment_id`.
///   3. The RLS POLICY, which binds even for the owner because the table is
///      `FORCE ROW LEVEL SECURITY`.
///
/// Deleting ANY ONE of the three leaves this test green, because the remaining two produce the
/// same answer. That is defence in depth working as intended and a test that cannot audit it.
/// Measured, all three ways, rather than asserted.
///
/// So what this test pins is the OUTCOME an operator depends on: a connection in one scope is
/// invisible in another, through `get` and through the listing alike. The POLICY'S EXISTENCE is
/// pinned where it can be, structurally, by
/// `migration.rs::every_scim_table_carries_its_isolation_structurally`, which reads
/// `pg_policies` directly instead of trying to observe the policy through a query that three
/// things already answer.
#[tokio::test]
async fn a_connection_of_another_scope_is_invisible() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let here = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, here, "Acme").await;
    let id = push_to(&db, &env, here, &org).await;

    // The SAME id, read through the other scope's store.
    let stray = ScimPushConnectionId::parse_in_scope(&id.to_string(), &here).expect("parses here");
    assert!(
        matches!(
            db.store()
                .scoped(elsewhere)
                .scim_push_connections()
                .get(&stray)
                .await,
            Err(StoreError::NotFound)
        ),
        "a connection from another scope must not resolve"
    );
    // AND THE LISTING AGREES. A `get` fence with a leaky list is a fence with a door beside it.
    assert!(
        db.store()
            .scoped(elsewhere)
            .scim_push_connections()
            .list_for_org(&org, 100, None)
            .await
            .expect("listing succeeds")
            .is_empty()
    );
}

/// A foreign organization cannot be named, even though the foreign key would resolve it.
///
/// # This is the whole reason the id is typed
///
/// Postgres referential integrity does not see row-level security, so an untyped string would
/// resolve any globally existing organization and bind a credential that pushes another tenant's
/// directory. The refusal is in the code because it cannot be in the constraint.
#[tokio::test]
async fn a_foreign_organization_cannot_be_named() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let here = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    let foreign_org = seed_org(&db, &env, elsewhere, "Somebody else").await;

    let id = ScimPushConnectionId::generate(&env, &here);
    let outcome = db
        .control_store()
        .scoped(here)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_push_connections()
        .create(
            &env,
            NewScimPushConnection {
                id: &id,
                organization_id: &foreign_org,
                display_name: "Cross tenant",
                base_url: "https://downstream.example/scim/v2",
                credential_secret_name: "scim_push_downstream",
                attribute_mapping: &serde_json::json!({}),
                user_scope_filter: None,
                group_scope_filter: None,
                write_mode: ScimWriteMode::Patch,
                deletion_policy: ScimDeletionPolicy::Deactivate,
            },
            None,
            None,
        )
        .await;
    assert!(
        matches!(outcome, Err(StoreError::NotFound)),
        "a foreign organization must be refused, got {outcome:?}"
    );
    // AND NOTHING WAS WRITTEN. A refusal that left the row behind would be worse than none.
    assert!(
        matches!(
            db.store()
                .scoped(here)
                .scim_push_connections()
                .get(&id)
                .await,
            Err(StoreError::NotFound)
        ),
        "the refusal must write nothing"
    );
}

/// Every value of every stored vocabulary is accepted, and one outside it is not.
///
/// # The Rust enum and the CHECK constraint can drift
///
/// A variant added in Rust without touching the constraint compiles and fails at INSERT in
/// production rather than in CI. Iterating `ALL` is what turns that into a test failure, and the
/// raw-string arm is the other direction: a value the column would accept and the enum cannot
/// name would mean the constraint had been widened without anybody noticing.
#[tokio::test]
async fn the_stored_vocabularies_match_the_check_constraints() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Acme").await;

    for write_mode in ScimWriteMode::ALL {
        for deletion_policy in ScimDeletionPolicy::ALL {
            let id = ScimPushConnectionId::generate(&env, &scope);
            db.control_store()
                .scoped(scope)
                .acting(db.test_actor(&env), CorrelationId::generate(&env))
                .scim_push_connections()
                .create(
                    &env,
                    NewScimPushConnection {
                        id: &id,
                        organization_id: &org,
                        display_name: "Downstream SaaS",
                        base_url: "https://downstream.example/scim/v2",
                        credential_secret_name: "scim_push_downstream",
                        attribute_mapping: &serde_json::json!({}),
                        user_scope_filter: None,
                        group_scope_filter: None,
                        write_mode: *write_mode,
                        deletion_policy: *deletion_policy,
                    },
                    None,
                    None,
                )
                .await
                .unwrap_or_else(|error| {
                    panic!("{write_mode:?}/{deletion_policy:?} must be storable: {error:?}")
                });
            let stored = db
                .store()
                .scoped(scope)
                .scim_push_connections()
                .get(&id)
                .await
                .expect("reads back");
            assert_eq!(stored.write_mode, *write_mode);
            assert_eq!(stored.deletion_policy, *deletion_policy);
        }
    }

    // THE THIRD VOCABULARY. `backfill_state` is not settable through `NewScimPushConnection`
    // (the row is created `pending` and the worker advances it), so it is driven through the
    // column directly. Without this arm `ScimBackfillState::ALL` had ZERO callers anywhere in
    // the workspace while its own doc said it existed so a test could drive it against the
    // CHECK, and three of its four spellings were unverified against the constraint.
    let pool = db.owner_pool();
    for state in ScimBackfillState::ALL {
        let updated = sqlx::query("UPDATE scim_push_connections SET backfill_state = $1")
            .bind(state.as_str())
            .execute(pool)
            .await
            .unwrap_or_else(|error| panic!("{state:?} must satisfy the CHECK: {error:?}"));
        assert!(updated.rows_affected() > 0, "{state:?} reached no row");
    }

    // AND THE OTHER DIRECTION, which is the half that makes the two above mean anything. A
    // vocabulary test that only writes the values the enum can name passes just as well against
    // a column with no CHECK at all: what pins the constraint is a value the column must
    // REFUSE. One per vocabulary, by raw string, because the typed API cannot express them.
    for (column, rejected) in [
        ("write_mode", "patch_maybe"),
        ("deletion_policy", "archive"),
        ("backfill_state", "halfway"),
    ] {
        let outcome = sqlx::query(&format!("UPDATE scim_push_connections SET {column} = $1"))
            .bind(rejected)
            .execute(pool)
            .await;
        assert!(
            outcome.is_err(),
            "the column accepted {rejected:?} for {column}, so its CHECK constrains nothing \
             and the Rust vocabulary above is free to drift from it"
        );
    }
}

/// Pausing a connection keeps it, and deleting it removes it.
#[tokio::test]
async fn a_connection_pauses_and_deletes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Acme").await;
    let id = push_to(&db, &env, scope, &org).await;
    let acting = || {
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    acting()
        .scim_push_connections()
        .set_active(&env, &org, &id, false, None)
        .await
        .expect("pause");
    let paused = db
        .store()
        .scoped(scope)
        .scim_push_connections()
        .get(&id)
        .await
        .expect("a paused connection is still there");
    assert!(!paused.active);

    acting()
        .scim_push_connections()
        .set_active(&env, &org, &id, true, None)
        .await
        .expect("resume");
    assert!(
        db.store()
            .scoped(scope)
            .scim_push_connections()
            .get(&id)
            .await
            .expect("reads back")
            .active
    );

    acting()
        .scim_push_connections()
        .delete(&env, &org, &id, None)
        .await
        .expect("delete");
    assert!(matches!(
        db.store()
            .scoped(scope)
            .scim_push_connections()
            .get(&id)
            .await,
        Err(StoreError::NotFound)
    ));
    // AND DELETING IT AGAIN IS NOT FOUND, not a silent success. An idempotent-looking delete
    // hides a caller deleting the wrong thing.
    assert!(matches!(
        acting()
            .scim_push_connections()
            .delete(&env, &org, &id, None)
            .await,
        Err(StoreError::NotFound)
    ));
}

/// A mutation aimed at another scope's connection is refused, and changes nothing.
#[tokio::test]
async fn a_mutation_cannot_reach_another_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let here = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, here, "Acme").await;
    let id = push_to(&db, &env, here, &org).await;

    let acting_elsewhere = db
        .control_store()
        .scoped(elsewhere)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    assert!(matches!(
        acting_elsewhere
            .scim_push_connections()
            .set_active(&env, &org, &id, false, None)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        acting_elsewhere
            .scim_push_connections()
            .delete(&env, &org, &id, None)
            .await,
        Err(StoreError::NotFound)
    ));
    // UNTOUCHED. A refusal that had already written would be the worst of both.
    let stored = db
        .store()
        .scoped(here)
        .scim_push_connections()
        .get(&id)
        .await
        .expect("still there");
    assert!(stored.active);
}

/// A connection cannot be reached through ANOTHER organization's handle.
///
/// # The IDOR the inbound slice exists to prevent, in its mirror
///
/// The first version of the management handler resolved the organization from the path, bound it
/// to `_org_id`, and then deleted by connection id alone -- so a handle belonging to organization
/// B was reachable through organization A's path and answered 204. The API test caught it; this
/// one pins the fence where it now lives, in the store, so no future handler can forget.
#[tokio::test]
async fn a_connection_cannot_be_reached_through_another_organization() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mine = seed_org(&db, &env, scope, "Acme").await;
    let theirs = seed_org(&db, &env, scope, "Globex").await;
    let id = push_to(&db, &env, scope, &theirs).await;
    let acting = || {
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    // BOTH mutations, because a fence on one is a fence with a door beside it.
    assert!(matches!(
        acting()
            .scim_push_connections()
            .set_active(&env, &mine, &id, false, None)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        acting()
            .scim_push_connections()
            .delete(&env, &mine, &id, None)
            .await,
        Err(StoreError::NotFound)
    ));

    // UNTOUCHED, and still theirs.
    let stored = db
        .store()
        .scoped(scope)
        .scim_push_connections()
        .get(&id)
        .await
        .expect("still there");
    assert!(stored.active);
    assert_eq!(stored.organization_id, theirs);

    // CONTROL: the RIGHT organization works, so the refusals are about the pairing rather than
    // about the mutation being broken.
    acting()
        .scim_push_connections()
        .set_active(&env, &theirs, &id, false, None)
        .await
        .expect("the owning organization may pause it");
    acting()
        .scim_push_connections()
        .delete(&env, &theirs, &id, None)
        .await
        .expect("the owning organization may delete it");
}
