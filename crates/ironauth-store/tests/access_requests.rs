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
            None,
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
        .decide(
            &env,
            &id,
            ironauth_store::AccessDecision {
                approve: true,
                decided_by: "prn_approver",
                decided_at_micros: now,
                granted_until_micros: Some(until),
            },
            None,
        )
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
        .decide(
            &env,
            &id,
            ironauth_store::AccessDecision {
                approve: true,
                decided_by: "prn_asker",
                decided_at_micros: now,
                granted_until_micros: Some(now + 1_000_000),
            },
            None,
        )
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
        message.contains("access_grant_requests_granted_until_iff_granted"),
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
        .decide(
            &env,
            &id,
            ironauth_store::AccessDecision {
                approve: false,
                decided_by: "prn_first",
                decided_at_micros: now,
                granted_until_micros: None,
            },
            None,
        )
        .await
        .expect("the first decision lands");

    let second = acting
        .access_requests(scope)
        .decide(
            &env,
            &id,
            ironauth_store::AccessDecision {
                approve: true,
                decided_by: "prn_second",
                decided_at_micros: now,
                granted_until_micros: Some(now + 1_000_000),
            },
            None,
        )
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

/// A grant ends ON SCHEDULE, and the sweep records that it ended (issue #145 criterion 4).
///
/// # Why the clock is driven rather than waited on
///
/// The criterion's verification section asks for clock-controlled expiry, and the reason
/// is not just speed. A test that slept would be asserting that a duration elapsed, which
/// is a property of the test runner; driving the seam asserts that the DEADLINE is what
/// decides, which is the property of the code.
///
/// # Why both halves are asserted
///
/// The access ending and the record saying so are two different claims with two different
/// failure modes. If only the sweep were checked, an implementation where relabelling is
/// what revokes would pass, and it would leak access for as long as the sweeper was late
/// or stopped. If only `grants_now` were checked, the listing could show a live-looking
/// grant for ever.
#[tokio::test]
async fn a_grant_stops_granting_at_its_deadline_and_the_sweep_records_it() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0145_0004);
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;
    let id = raise(&db, &env, scope, &org, "prn_asker").await;

    let granted_at = now_micros(&env);
    let until = granted_at + 3_600_000_000;
    let store = db.control_store();
    store
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .access_requests(scope)
        .decide(
            &env,
            &id,
            ironauth_store::AccessDecision {
                approve: true,
                decided_by: "prn_approver",
                decided_at_micros: granted_at,
                granted_until_micros: Some(until),
            },
            None,
        )
        .await
        .expect("approve");

    let read = || async {
        store
            .scoped(scope)
            .access_requests()
            .get(&id.to_string())
            .await
            .expect("read it back")
    };
    let sweep = || async {
        store
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .access_requests(scope)
            .expire_elapsed(&env, now_micros(&env), 100)
            .await
            .expect("sweep")
    };

    // INSIDE THE WINDOW: it grants, and a sweep must not touch it.
    clock.advance(std::time::Duration::from_secs(59 * 60));
    assert!(read().await.grants_now(now_micros(&env)));
    assert_eq!(sweep().await, 0, "a live grant must survive a sweep");
    assert_eq!(read().await.state, AccessRequestState::Approved);

    // PAST THE DEADLINE, AND BEFORE ANY SWEEP. The row still says `approved` because
    // nothing has relabelled it; the access is already gone. This is the assertion that
    // separates "the deadline revokes" from "the sweeper revokes".
    clock.advance(std::time::Duration::from_secs(2 * 60));
    let elapsed = read().await;
    assert_eq!(
        elapsed.state,
        AccessRequestState::Approved,
        "nothing has swept yet, so the label is deliberately stale"
    );
    assert!(
        !elapsed.grants_now(now_micros(&env)),
        "the DEADLINE ends the grant. If this needed the sweeper to have run, every \
         deployment whose sweeper is stopped, unconfigured or a tick behind would keep \
         granting elevated access past its expiry"
    );
    assert!(
        store
            .scoped(scope)
            .access_requests()
            .live_grants_for_subject(&org.to_string(), "usr_subject", now_micros(&env))
            .await
            .expect("read live roles")
            .is_empty(),
        "and the query a token path would ask must agree with the row"
    );

    // NOW THE SWEEP, which changes the RECORD and not the access.
    assert_eq!(sweep().await, 1, "the elapsed grant is swept exactly once");
    let swept = read().await;
    assert_eq!(swept.state, AccessRequestState::Expired);
    assert_eq!(
        swept.granted_until_micros,
        Some(until),
        "the sweep must KEEP the deadline. Nulling it erases the only record of when the \
         grant ended, and a row recording a one-hour elevation becomes indistinguishable \
         from one recording a month"
    );
    assert!(
        !swept.grants_now(now_micros(&env)),
        "and keeping the deadline must not keep the access: the state decides too"
    );
    assert_eq!(
        sweep().await,
        0,
        "a second pass must find nothing: sweeping is idempotent, and a row counted twice \
         would write a second `access_request.expire` for one expiry"
    );
}

/// The sweep writes an audit row per expiry, so the trail shows the END of a grant.
#[tokio::test]
async fn every_swept_grant_leaves_an_audit_row_naming_it() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0145_0005);
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;
    let store = db.control_store();

    // TWO grants, so "one audit row per expiry" is distinguishable from "one per sweep".
    let mut ids = Vec::new();
    for asker in ["prn_one", "prn_two"] {
        let id = raise(&db, &env, scope, &org, asker).await;
        store
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .access_requests(scope)
            .decide(
                &env,
                &id,
                ironauth_store::AccessDecision {
                    approve: true,
                    decided_by: "prn_approver",
                    decided_at_micros: now_micros(&env),
                    granted_until_micros: Some(now_micros(&env) + 60_000_000),
                },
                None,
            )
            .await
            .expect("approve");
        ids.push(id.to_string());
    }

    clock.advance(std::time::Duration::from_secs(120));
    let swept = store
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .access_requests(scope)
        .expire_elapsed(&env, now_micros(&env), 100)
        .await
        .expect("sweep");
    assert_eq!(swept, 2);

    let targets: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'access_request.expire' \
         ORDER BY target_id",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the audit trail");

    ids.sort();
    assert_eq!(
        targets, ids,
        "each expiry must name the grant that ended. One row for the pass would tell an \
         auditor that something expired without saying what"
    );
}

/// WHO ASKED cannot be rewritten after the fact, and that is a GRANT property
/// (issue #145 criterion 4).
///
/// # Why this is not a convention
///
/// The separation constraint compares `decided_by` to `requested_by` per statement, never
/// retroactively. With a table-wide UPDATE grant the control role could rewrite
/// `requested_by` on a decided row to a third string: the CHECK stays satisfied, the row
/// still reads as though two parties were involved, and the audit answer to "who agreed to
/// it" has been edited. Migration 0225 therefore grants UPDATE on four columns and not on
/// the table, so the question is closed by Postgres rather than by nobody having tried.
///
/// Driven as `ironauth_control`, which is the role the management plane authenticates as.
/// The owner connection is deliberately not used: it holds every privilege, so it would
/// prove nothing about what the application's own role may do.
#[tokio::test]
async fn the_control_role_cannot_rewrite_who_asked() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;
    let id = raise(&db, &env, scope, &org, "prn_asker").await;

    // THE CONTROL LEG FIRST: this role CAN decide, so the refusal below is the column list
    // and not the role being unable to touch the table at all.
    let now = now_micros(&env);
    db.control_store()
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .access_requests(scope)
        .decide(
            &env,
            &id,
            ironauth_store::AccessDecision {
                approve: true,
                decided_by: "prn_approver",
                decided_at_micros: now,
                granted_until_micros: Some(now + 3_600_000_000),
            },
            None,
        )
        .await
        .expect("the control role may decide");

    for (column, value) in [
        ("requested_by", "prn_somebody_else"),
        ("subject_id", "usr_somebody_else"),
        ("role_slug", "something-else"),
        ("reason", "a different reason"),
    ] {
        let refused = sqlx::query(&format!(
            "UPDATE access_grant_requests SET {column} = $2 WHERE id = $1"
        ))
        .bind(id.to_string())
        .bind(value)
        .execute(db.control_pool())
        .await;
        let message = refused
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(
            message.contains("permission denied"),
            "the control role rewrote {column} on a decided request. The audit answer to \
             'who agreed to this elevation' is then editable by any statement that role \
             can issue: {message}"
        );
    }

    // AND THE ROW IS AS IT WAS. Four refusals that changed something anyway would satisfy
    // the assertions above.
    let after = db
        .control_store()
        .scoped(scope)
        .access_requests()
        .get(&id.to_string())
        .await
        .expect("read it back");
    assert_eq!(after.requested_by, "prn_asker");
    assert_eq!(after.subject_id, "usr_subject");
    assert_eq!(after.role_slug, "billing-admin");
    assert_eq!(after.reason, "quarter close");
}
