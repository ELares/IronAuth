// SPDX-License-Identifier: MIT OR Apache-2.0

//! Time-boxed access requests: the constraints, not the handlers (issue #145 criterion 4).
//!
//! # What this file is for
//!
//! The criterion asks that self-approval be IMPOSSIBLE and that a grant AUTO-EXPIRE. Both
//! claims are about the store, and both are easy to make falsely: a handler comparing two
//! principals is impossible only along the paths that call it, and a grant that expires
//! because a sweeper relabelled it still grants access whenever the sweeper is not running.
//!
//! So these drive the repository and, where the claim is about the database itself,
//! SQL directly through the owner pool. A test that could only reach the table through the
//! handler would be testing the handler.

use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_store::access_request::AccessRequestState;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AccessRequestId, ActorRef, CorrelationId, OrganizationId, Scope, ServiceId, StoreError,
};

fn actor(env: &Env) -> ActorRef {
    ActorRef::service(ServiceId::generate(env))
}

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after the epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

async fn create_org(db: &TestDatabase, env: &Env, scope: Scope) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now_micros(env), "Requesters Inc", None)
        .await
        .expect("create organization");
    id
}

/// Raise a request, returning its id.
async fn raise(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
    requested_by: &str,
) -> AccessRequestId {
    let id = AccessRequestId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .access_requests(scope)
        .raise(
            env,
            &id,
            ironauth_store::NewAccessRequest {
                organization_id: &org.to_string(),
                subject_id: "usr_subject",
                role_slug: "billing-admin",
                requested_by,
                reason: "quarter close",
            },
        )
        .await
        .expect("raise the request");
    id
}

/// THE CRITERION'S CENTRAL CLAIM, tested against the database rather than a handler.
///
/// The UPDATE below is the one a compromised or careless path would issue: it names the
/// requester as the decider. It runs on the OWNER pool, which is the most privileged
/// connection this deployment has and bypasses row-level security entirely. If the
/// separation held only in application code, this statement would succeed.
#[tokio::test]
async fn postgres_itself_refuses_a_self_approval_even_from_the_owner_connection() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;
    let id = raise(&db, &env, scope, &org, "prn_asker").await;

    let refused = sqlx::query(
        "UPDATE access_grant_requests \
            SET state = 'approved', decided_by = 'prn_asker', decided_at = now(), \
                granted_until = now() + interval '1 hour' \
          WHERE id = $1",
    )
    .bind(id.to_string())
    .execute(db.owner_pool())
    .await;

    let error = refused.expect_err(
        "the owner connection approved a request on behalf of the person who raised it. \
         Separation of duties that holds only in a handler is not separation of duties: \
         every other door onto this table, a later handler, a bulk import, a support \
         script, a repair query, reaches it without passing that check",
    );
    let message = error.to_string();
    assert!(
        message.contains("access_grant_requests_decider_is_not_requester"),
        "the refusal must come from the separation constraint and not from something \
         else that happened to fail: {message}"
    );

    // AND THE ROW IS UNTOUCHED. A refusal that left the state approved would satisfy the
    // assertion above and be the whole defect.
    let after = db
        .control_store()
        .scoped(scope)
        .access_requests()
        .get(&id.to_string())
        .await
        .expect("read it back");
    assert_eq!(after.state, AccessRequestState::Pending);
    assert_eq!(after.decided_by, None);
    assert_eq!(after.granted_until_micros, None);
}

/// A DIFFERENT principal may approve, so the refusal above is the separation and not the
/// route being closed.
#[tokio::test]
async fn a_different_principal_may_approve_and_the_grant_carries_its_deadline() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;
    let id = raise(&db, &env, scope, &org, "prn_asker").await;
    let now = now_micros(&env);
    let until = now + 3_600_000_000;

    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .access_requests(scope)
        .decide(&env, &id, true, "prn_approver", now, Some(until))
        .await
        .expect("a different principal approves");

    let after = db
        .control_store()
        .scoped(scope)
        .access_requests()
        .get(&id.to_string())
        .await
        .expect("read it back");
    assert_eq!(after.state, AccessRequestState::Approved);
    assert_eq!(after.decided_by.as_deref(), Some("prn_approver"));
    assert_eq!(after.granted_until_micros, Some(until));
    assert!(after.grants_now(now), "inside the window it grants");
    assert!(
        !after.grants_now(until),
        "at the deadline it stops, with no sweeper involved"
    );
}

/// The repository refuses a self-approval too, BEFORE the database does.
///
/// Not redundant with the constraint test: this one pins that the refusal is the
/// comprehensible [`StoreError`] a handler can turn into a 403, rather than a raw
/// constraint violation surfacing as a 500 on a healthy deployment.
#[tokio::test]
async fn the_repository_refuses_a_self_approval_as_a_not_found_rather_than_a_database_error() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;
    let id = raise(&db, &env, scope, &org, "prn_asker").await;
    let now = now_micros(&env);

    let outcome = db
        .control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .access_requests(scope)
        .decide(&env, &id, true, "prn_asker", now, Some(now + 1_000_000))
        .await;

    assert!(
        matches!(outcome, Err(StoreError::SelfApproval)),
        "a self-approval must be refused as its own error, so the edge can say why: \
         {outcome:?}"
    );
}

/// An approval must carry a deadline and a denial must not, and the database says so.
#[tokio::test]
async fn an_approval_without_a_deadline_is_refused_by_the_database() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;
    let id = raise(&db, &env, scope, &org, "prn_asker").await;

    let refused = sqlx::query(
        "UPDATE access_grant_requests \
            SET state = 'approved', decided_by = 'prn_approver', decided_at = now() \
          WHERE id = $1",
    )
    .bind(id.to_string())
    .execute(db.owner_pool())
    .await;

    let message = refused
        .expect_err("an approval that grants for ever is the standing access this replaces")
        .to_string();
    assert!(
        message.contains("access_grant_requests_granted_until_iff_approved"),
        "the refusal must come from the deadline constraint: {message}"
    );
}

/// A decision cannot be overwritten by a second approver.
#[tokio::test]
async fn only_the_first_decision_lands() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;
    let id = raise(&db, &env, scope, &org, "prn_asker").await;
    let now = now_micros(&env);
    let store = db.control_store();
    let acting = store
        .management()
        .acting(actor(&env), CorrelationId::generate(&env));

    acting
        .access_requests(scope)
        .decide(&env, &id, false, "prn_first", now, None)
        .await
        .expect("the first decision lands");

    let second = acting
        .access_requests(scope)
        .decide(&env, &id, true, "prn_second", now, Some(now + 1_000_000))
        .await;
    assert!(
        matches!(second, Err(StoreError::NotFound)),
        "a decided request is no longer pending, so a second approver must not silently \
         replace the first's decision and deadline: {second:?}"
    );

    let after = store
        .scoped(scope)
        .access_requests()
        .get(&id.to_string())
        .await
        .expect("read it back");
    assert_eq!(after.state, AccessRequestState::Denied);
    assert_eq!(after.decided_by.as_deref(), Some("prn_first"));
}
