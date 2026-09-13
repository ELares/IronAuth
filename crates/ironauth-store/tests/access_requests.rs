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
        let message = refused.map_or_else(|error| error.to_string(), |_| String::new());
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

/// Create the role, the user and the membership a time-boxed grant needs to resolve.
///
/// Split out for the crate's function-length bound. Returns the user, which is the key the
/// effective-role closure is seeded on.
async fn seed_member_with_role(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    org: &OrganizationId,
) -> ironauth_store::UserId {
    use ironauth_store::{
        NewAdminUser, NewMembership, NewOrgRole, OrgMembershipId, OrgRoleId, UserState,
    };

    let store = db.control_store();
    let role_id = OrgRoleId::generate(env, &scope);
    store
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_roles(scope)
        .create(
            env,
            NewOrgRole {
                id: &role_id,
                organization_id: org,
                slug: "billing-admin",
                display_name: "Billing",
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create the role");

    let user = store
        .scoped(scope)
        .acting(actor(env), CorrelationId::generate(env))
        .users()
        .admin_create(
            env,
            NewAdminUser {
                id: None,
                identifier: "elevated@example.test",
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::Active,
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create the user");

    let membership_id = OrgMembershipId::generate(env, &scope);
    store
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_memberships(scope)
        .create(
            env,
            NewMembership {
                id: &membership_id,
                organization_id: org,
                user_id: &user,
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create the membership");
    user
}

/// The time-boxed ARM stops granting at the deadline, judged in SQL
/// (issue #145 criterion 4).
///
/// # Why this is not covered by the `grants_now` test above
///
/// That one drives the Rust read rule. This drives the SQL: the arm's
/// `agr.granted_until > $6` is a second place the deadline is decided, and the two can
/// disagree. Deleting the predicate from the arm leaves every HTTP test green, because the
/// management harness runs on the system clock and cannot step past a one-hour grant.
///
/// Both bounds are half-open at the same instant, so a grant does not survive its own
/// deadline in either.
#[tokio::test]
async fn the_time_boxed_arm_stops_granting_at_the_deadline() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0145_0006);
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;
    let store = db.control_store();

    let user = seed_member_with_role(&db, &env, scope, &org).await;

    // A one-hour grant for THIS user.
    let id = AccessRequestId::generate(&env, &scope);
    store
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .access_requests(scope)
        .raise(
            &env,
            &id,
            ironauth_store::NewAccessRequest {
                organization_id: &org.to_string(),
                subject_id: &user.to_string(),
                role_slug: "billing-admin",
                requested_by: "prn_asker",
                reason: "quarter close",
            },
            None,
        )
        .await
        .expect("raise");
    let granted_at = now_micros(&env);
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
                granted_until_micros: Some(granted_at + 3_600_000_000),
            },
            None,
        )
        .await
        .expect("approve");

    let held = || async {
        store
            .management()
            .org_groups(scope)
            .effective_role_grants_at(&org, &user, 8, now_micros(&env))
            .await
            .expect("resolve")
            .into_iter()
            .any(|grant| {
                matches!(
                    grant.source,
                    ironauth_store::EffectiveRoleSource::TimeBoxed { .. }
                )
            })
    };

    clock.advance(std::time::Duration::from_secs(59 * 60));
    assert!(held().await, "inside the window the arm grants");

    clock.advance(std::time::Duration::from_secs(2 * 60));
    assert!(
        !held().await,
        "past the deadline the ARM must stop granting. The Rust read rule stopping is not \
         enough: this is a second place the deadline is decided, and a query that kept \
         returning the row would hand an elevation to every caller that trusts the \
         resolution rather than re-checking"
    );
}

/// TWO overlapping live grants are TWO rows, in an order that does not move
/// (issue #145 criterion 4).
///
/// # What this pins that the arm's other tests do not
///
/// [`EFFECTIVE_ROLE_GRANTS_TAIL`]'s sort key is documented as a TOTAL order -- no two rows
/// share `(slug, source, via_group_id)` -- and both the `roles` array and the access-review
/// export publish byte-stability on the strength of it. The fourth arm emits one row per
/// approved REQUEST, so two live approvals for one `(subject, role)` agree on all three and
/// the inherited key leaves them tied. Nothing in migration 0225 forbids the pair, and
/// raising an extension before the first lapses is the ordinary way to reach it.
///
/// So this asserts both halves: that every row survives (collapsing them would show an
/// operator one of several approvals to revoke) and that the answer comes back in request-id
/// order, repeatedly.
///
/// WHAT IT DOES NOT ESTABLISH, measured rather than assumed: removing `via_request_id` from
/// the tail's `ORDER BY` leaves this test green. The grants are minted here and inserted in
/// DESCENDING id order precisely so that sorted order is not insertion order, and it still
/// passes, because each arm's `SELECT DISTINCT` covers a column list that includes
/// `via_request_id` and so already hands the outer sort an id-ordered input. That is a plan
/// detail, not a property of the statement. The conjunct is a guarantee this test cannot
/// currently observe; the constant's own docs say the same thing, and neither should be
/// deleted on the strength of the surviving mutation.
#[tokio::test]
async fn two_live_grants_for_one_role_are_two_rows_in_a_stable_order() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0145_0009);
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;
    let user = seed_member_with_role(&db, &env, scope, &org).await;
    let store = db.control_store();

    // Two approvals for the SAME role: the short one and the extension raised before it
    // lapses. Both live at the instant read below.
    //
    // INSERTED IN DESCENDING ID ORDER, deliberately. The ids are minted here rather than by
    // the store, so the test can make creation order the REVERSE of sort order. Inserted
    // ascending, the rows come back sorted whether or not the sort key mentions them --
    // Postgres hands back a small `UNION ALL` in the order it built it -- and the assertion
    // would pass against a query with no fourth sort column at all. Reversed, the sorted
    // answer is one the plan does not produce by accident.
    let mut minted: Vec<_> = (0..8)
        .map(|_| AccessRequestId::generate(&env, &scope))
        .collect();
    minted.sort_by_key(ToString::to_string);
    let request_ids: Vec<String> = minted.iter().map(ToString::to_string).collect();
    for (index, id) in minted.iter().rev().enumerate() {
        let hours = 1_i64 + i64::try_from(index).expect("small") * 24;
        store
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .access_requests(scope)
            .raise(
                &env,
                id,
                ironauth_store::NewAccessRequest {
                    organization_id: &org.to_string(),
                    subject_id: &user.to_string(),
                    role_slug: "billing-admin",
                    requested_by: "prn_asker",
                    reason: "quarter close",
                },
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("raise {index}: {error}"));
        let at = now_micros(&env);
        store
            .management()
            .acting(actor(&env), CorrelationId::generate(&env))
            .access_requests(scope)
            .decide(
                &env,
                id,
                ironauth_store::AccessDecision {
                    approve: true,
                    decided_by: "prn_approver",
                    decided_at_micros: at,
                    granted_until_micros: Some(at + hours * 3_600_000_000),
                },
                None,
            )
            .await
            .unwrap_or_else(|error| panic!("approve {index}: {error}"));
    }

    let read = || async {
        store
            .management()
            .org_groups(scope)
            .effective_role_grants_at(&org, &user, 8, now_micros(&env))
            .await
            .expect("resolve")
            .into_iter()
            .filter_map(|grant| match grant.source {
                ironauth_store::EffectiveRoleSource::TimeBoxed { request_id, .. } => {
                    Some(request_id)
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    let first = read().await;
    assert_eq!(
        first.len(),
        minted.len(),
        "both live approvals have to appear. One row for two approvals shows an operator a \
         single grant to revoke, they revoke it, and the elevation survives by the approval \
         that was hidden: {first:?}"
    );
    assert_eq!(
        first, request_ids,
        "the rows must come back ordered by request id, which is what makes the sort key \
         total again: {first:?}"
    );

    // REPEATED, because the claim is about two reads of unchanged state and one read cannot
    // establish it.
    for round in 0..4 {
        assert_eq!(
            read().await,
            first,
            "read {round} disagreed with the first about the order of two tied rows, so the \
             byte-stability the export publishes does not hold"
        );
    }
}

/// Give `elsewhere` a role of the SAME slug carrying a permission of its own, then plant an
/// `org_role_permissions` row addressed to `here` whose `role_id` points at it.
///
/// Planted with SQL through the owner pool because no repository method will write this row:
/// the containment migration 0092 names as an APPLICATION invariant is enforced by the write
/// path's own lookup, which is exactly why a READ cannot assume nobody bypassed it.
async fn plant_foreign_role_mapping(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    here: &OrganizationId,
    elsewhere: &OrganizationId,
) {
    use ironauth_store::{
        NewOrgRole, NewPermission, OrgRoleId, OrgRolePermissionId, PermissionId,
    };

    let store = db.control_store();
    let foreign_role = OrgRoleId::generate(env, &scope);
    store
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .org_roles(scope)
        .create(
            env,
            NewOrgRole {
                id: &foreign_role,
                organization_id: elsewhere,
                slug: "billing-admin",
                display_name: "Billing, over there",
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create the sibling's role");

    let permission = PermissionId::generate(env, &scope);
    store
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .permissions(scope)
        .create(
            env,
            NewPermission {
                id: &permission,
                slug: "billing.write.elsewhere",
                display_name: "Somebody else's billing",
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("create the sibling's permission");

    sqlx::query(
        "INSERT INTO org_role_permissions \
         (id, tenant_id, environment_id, organization_id, role_id, permission_id, \
          created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, now(), now())",
    )
    .bind(OrgRolePermissionId::generate(env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(here.to_string())
    .bind(foreign_role.to_string())
    .bind(permission.to_string())
    .execute(db.owner_pool())
    .await
    .expect("plant the cross-organization mapping");
}

/// A role row belonging to ANOTHER organization cannot carry its permissions into this
/// organization's answer, even reached through the time-boxed disjunct
/// (issue #145 criterion 4).
///
/// # Why a corrupt row is the right fixture
///
/// Migration 0092 states this as a named non-guarantee: `org_role_permissions.role_id` has a
/// foreign key to `org_roles` and that key does NOT prove the role belongs to this
/// organization or even to this environment, so same-organization containment is an
/// APPLICATION invariant that every read repeats. RLS fences `(tenant, environment)` and
/// nothing finer, so the organization predicate is the only thing keeping one organization's
/// mapping out of a sibling's queries inside one environment.
///
/// The first version of the time-boxed permissions disjunct did not repeat it: it fenced
/// `org_roles` on `deleted_at` alone and bound the access request to the ROLE's scope columns
/// rather than to the bound one, so which organization's approved requests counted was
/// decided by a row whose organization had never been checked. The plain disjunct beside it
/// was immune, because it reaches roles only through the fenced closure.
///
/// Planted with SQL through the owner pool on purpose: no repository method will write this
/// row, which is exactly why the read cannot assume nobody did.
#[tokio::test]
async fn a_foreign_role_mapping_cannot_reach_this_organizations_permissions() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0145_0010);
    let scope = db.seed_scope(&env).await;
    let store = db.control_store();

    // TWO organizations of ONE environment, which is the containment RLS does not provide.
    let here = create_org(&db, &env, scope).await;
    let elsewhere = create_org(&db, &env, scope).await;
    let user = seed_member_with_role(&db, &env, scope, &here).await;

    plant_foreign_role_mapping(&db, &env, scope, &here, &elsewhere).await;

    // An approved live grant for the slug, raised in a NAMED organization. The store's
    // `raise` does not check membership -- that is the handler's job -- so a request may
    // exist in an organization the subject does not belong to, which is the state the first
    // case below needs and a thing an operator can reach by raising before a membership is
    // removed.
    let approve_in = |organization: String| {
        let store = store.clone();
        let env = &env;
        async move {
            let id = AccessRequestId::generate(env, &scope);
            store
                .management()
                .acting(actor(env), CorrelationId::generate(env))
                .access_requests(scope)
                .raise(
                    env,
                    &id,
                    ironauth_store::NewAccessRequest {
                        organization_id: &organization,
                        subject_id: &user.to_string(),
                        role_slug: "billing-admin",
                        requested_by: "prn_asker",
                        reason: "quarter close",
                    },
                    None,
                )
                .await
                .expect("raise");
            let at = now_micros(env);
            store
                .management()
                .acting(actor(env), CorrelationId::generate(env))
                .access_requests(scope)
                .decide(
                    env,
                    &id,
                    ironauth_store::AccessDecision {
                        approve: true,
                        decided_by: "prn_approver",
                        decided_at_micros: at,
                        granted_until_micros: Some(at + 3_600_000_000),
                    },
                    None,
                )
                .await
                .expect("approve");
        }
    };

    let leaked = || async {
        store
            .management()
            .org_groups(scope)
            .effective_permissions_at(&here, &user, 8, now_micros(&env))
            .await
            .expect("resolve the permissions")
            .into_iter()
            .any(|slug| slug == "billing.write.elsewhere")
    };

    // CASE A: the grant is recorded in the SIBLING organization.
    //
    // This is what the ACCESS REQUEST's own fence has to stop. Bound to the role row's
    // scope columns rather than to $1/$2/$3, the predicate reads "an approved request in
    // whatever organization this role belongs to", and the role belongs to the sibling --
    // so a grant nobody in this organization ever approved decides this organization's
    // answer.
    approve_in(elsewhere.to_string()).await;
    assert!(
        !leaked().await,
        "an approved request recorded in ANOTHER organization granted a permission here. \
         The access-request fence has to name the bound scope, not the scope of a role row \
         that was never checked"
    );

    // CASE B: the grant is recorded in THIS organization, for the same slug.
    //
    // A separate failure with a separate fence. Here the request is legitimate and it is
    // the ROLE that is foreign: the corrupt mapping row is addressed to this organization
    // while its `role_id` points at the sibling's row, so a disjunct that fences `r` on
    // `deleted_at` alone resolves the sibling's permissions through this organization's own
    // approved grant. The two cases fail independently, which is why neither fence is
    // redundant.
    approve_in(here.to_string()).await;
    assert!(
        !leaked().await,
        "a permission mapped through ANOTHER organization's role reached this \
         organization's answer. The time-boxed disjunct is the one projection over this \
         closure that does not inherit the CTE's fence, so it is the one that has to spell \
         the organization predicate on the role itself"
    );
}

/// The ACCESS REVIEW carries a live time-boxed elevation, in its own columns
/// (issue #145 criteria 1 and 4).
///
/// # Why the export is the place this matters most
///
/// The effective-roles endpoint answers one member at a time and somebody has to ask. The
/// access review is the artifact handed to an auditor, and its question is "who has which
/// role". A live elevation IS a role somebody has, so an export omitting it does not merely
/// leave something out: it answers its own question falsely, and it is the one surface
/// where nobody is looking for what is missing.
///
/// The first version of this feature had a `time_boxed` render arm that nothing could
/// reach, because the export resolved through the plain closure.
#[tokio::test]
async fn the_access_review_export_carries_a_live_time_boxed_grant() {
    let db = TestDatabase::start().await;
    let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0145_0007);
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;
    let user = seed_member_with_role(&db, &env, scope, &org).await;
    let store = db.control_store();

    let id = AccessRequestId::generate(&env, &scope);
    store
        .management()
        .acting(actor(&env), CorrelationId::generate(&env))
        .access_requests(scope)
        .raise(
            &env,
            &id,
            ironauth_store::NewAccessRequest {
                organization_id: &org.to_string(),
                subject_id: &user.to_string(),
                role_slug: "billing-admin",
                requested_by: "prn_asker",
                reason: "quarter close",
            },
            None,
        )
        .await
        .expect("raise");
    let granted_at = now_micros(&env);
    let until = granted_at + 3_600_000_000;
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

    let review = |at: Option<i64>| async move {
        store
            .management()
            .access_review(scope, &org, 8, at)
            .await
            .expect("export")
    };

    // WITHOUT THE INSTANT the export is what it always was: the feature is off for that
    // caller and nothing about the evidence changes.
    let plain = review(None).await;
    assert!(
        plain.iter().all(|row| row.source != "time_boxed"),
        "an unacknowledged deployment's export must be unchanged: {plain:?}"
    );

    // WITH IT, the elevation is in the evidence, in its OWN columns.
    let rows = review(Some(now_micros(&env))).await;
    let elevated = rows
        .iter()
        .find(|row| row.source == "time_boxed")
        .unwrap_or_else(|| panic!("the review omitted a role the member holds: {rows:?}"));
    assert_eq!(elevated.role_slug, "billing-admin");
    assert_eq!(elevated.subject_id, user.to_string());
    assert_eq!(
        elevated.via_request_id.as_deref(),
        Some(id.to_string().as_str()),
        "the request belongs in its own column: a consumer reading an `agr_` id out of \
         `via_group_id` would join it against the group list and find nothing"
    );
    assert_eq!(
        elevated.via_group_id, None,
        "a time-boxed grant reaches nobody through a group"
    );
    assert_eq!(
        elevated.granted_until_unix_ms,
        Some(until / 1000),
        "an auditor asking 'and for how long' has no other column to read"
    );

    // AND PAST THE DEADLINE IT IS GONE, so the evidence does not report a standing grant.
    clock.advance(std::time::Duration::from_secs(3 * 3600));
    let later = review(Some(now_micros(&env))).await;
    assert!(
        later.iter().all(|row| row.source != "time_boxed"),
        "the export reported an elevation past its own deadline: {later:?}"
    );
}
