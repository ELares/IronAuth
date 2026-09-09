// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-connector sync health (issue #142).
//!
//! # What this owes
//!
//! The isolation was already real: one unreachable server degrades only its own connector. What
//! this adds is the half an operator can SEE, and its failure modes are the ones that make a
//! health surface worse than none:
//!
//! - the failure counter must be computed IN THE STATEMENT, because two replicas with the sweep
//!   switched on both write it, and a read-modify-write would let a directory down for ten passes
//!   report one failure;
//! - recovery must clear itself. "Resumes without manual intervention" is a property of the first
//!   successful pass, not of somebody acknowledging an alert;
//! - a connector that binds fine and fails to apply every principal is unhealthy too, so
//!   `is_healthy` cannot key on reachability alone.

#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, LdapAbsencePolicy, LdapConnectorId, LdapRunOutcome, LdapTlsMode,
    NewLdapConnector, NewLdapRun, OrganizationId, Scope,
};
use sqlx::Row;

fn now(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_micros(),
    )
    .expect("in range")
}

async fn seed_connector(db: &TestDatabase, env: &Env, scope: Scope) -> LdapConnectorId {
    let org = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &org, now(env), "Directory Co", None)
        .await
        .expect("create organization");
    let id = LdapConnectorId::generate(env, &scope);
    let mapping = serde_json::json!({ "userName": "uid" });
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .ldap_connectors()
        .create(
            env,
            NewLdapConnector {
                id: &id,
                organization_id: &org,
                display_name: "Contoso AD",
                host: "ad.contoso.test",
                port: 636,
                tls_mode: LdapTlsMode::Ldaps,
                bind_dn: "cn=svc,dc=contoso,dc=test",
                bind_secret_name: "contoso-bind",
                user_base_dn: "ou=people,dc=contoso,dc=test",
                group_base_dn: "",
                user_filter: "(objectClass=user)",
                group_filter: "",
                attribute_mapping: &mapping,
                absence_policy: LdapAbsencePolicy::Deactivate,
                max_group_depth: 5,
            },
        )
        .await
        .expect("create connector");
    id
}

fn run<'a>(
    connector: &'a LdapConnectorId,
    at: i64,
    outcome: LdapRunOutcome,
    error: Option<&'a str>,
) -> NewLdapRun<'a> {
    NewLdapRun {
        connector_id: connector,
        started_at_unix_micros: at,
        duration_ms: 1_200,
        outcome,
        error,
        provisioned: 0,
        already_present: 0,
        deactivated: 0,
        deleted: 0,
        already_absent: 0,
        already_removed: 0,
        apply_failures: 0,
    }
}

async fn record(db: &TestDatabase, env: &Env, scope: Scope, run: &NewLdapRun<'_>) {
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .ldap_sync_runs()
        .record(run)
        .await
        .expect("record the run");
}

/// A SUCCESSFUL PASS ROUND-TRIPS, counts and all. The counts are what an operator reads to tell a
/// quiet directory from a churning one.
#[tokio::test]
async fn a_successful_run_round_trips_with_its_counts() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;
    let at = now(&env);

    record(
        &db,
        &env,
        scope,
        &NewLdapRun {
            provisioned: 3,
            already_present: 40,
            deactivated: 2,
            deleted: 1,
            already_absent: 5,
            already_removed: 6,
            apply_failures: 0,
            ..run(&connector, at, LdapRunOutcome::Planned, None)
        },
    )
    .await;

    let health = db
        .control_store()
        .scoped(scope)
        .ldap_sync_runs()
        .get(&connector)
        .await
        .expect("read")
        .expect("present");

    assert_eq!(health.outcome, LdapRunOutcome::Planned);
    assert_eq!(
        health.error, None,
        "a successful run has nothing to explain"
    );
    assert_eq!(
        (
            health.provisioned,
            health.already_present,
            health.deactivated,
            health.deleted,
            health.already_absent,
            health.already_removed
        ),
        (3, 40, 2, 1, 5, 6),
        "a count was lost or crossed with another"
    );
    assert_eq!(health.duration_ms, 1_200);
    assert_eq!(health.started_at_unix_micros, at);
    assert_eq!(health.consecutive_failures, 0);
    assert_eq!(health.last_success_at_unix_micros, Some(at));
    assert!(health.is_healthy());
}

/// THE FAILURE COUNTER ACCUMULATES ACROSS PASSES, and that is the number that tells a blip from
/// an outage. A row rewritten each pass has no history to count from, so the count is kept in the
/// column and advanced in the statement.
#[tokio::test]
async fn consecutive_failures_accumulate_and_recovery_clears_them() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;
    let first = now(&env);

    record(
        &db,
        &env,
        scope,
        &run(&connector, first, LdapRunOutcome::Planned, None),
    )
    .await;
    for pass in 1..=3 {
        record(
            &db,
            &env,
            scope,
            &run(
                &connector,
                first + pass * 3_600_000_000,
                LdapRunOutcome::Unreachable,
                Some("connection refused"),
            ),
        )
        .await;
    }

    let down = db
        .control_store()
        .scoped(scope)
        .ldap_sync_runs()
        .get(&connector)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(
        down.consecutive_failures, 3,
        "three failed passes must read as three, not as one"
    );
    assert_eq!(down.outcome, LdapRunOutcome::Unreachable);
    assert_eq!(down.error.as_deref(), Some("connection refused"));
    assert!(!down.is_healthy());
    assert_eq!(
        down.last_success_at_unix_micros,
        Some(first),
        "the last good pass must survive the outage, or staleness is unreadable"
    );

    // RECOVERY, with nobody acknowledging anything.
    let recovered_at = first + 4 * 3_600_000_000;
    record(
        &db,
        &env,
        scope,
        &run(&connector, recovered_at, LdapRunOutcome::Planned, None),
    )
    .await;
    let back = db
        .control_store()
        .scoped(scope)
        .ldap_sync_runs()
        .get(&connector)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(
        back.consecutive_failures, 0,
        "the first successful pass must clear the counter with no manual intervention"
    );
    assert_eq!(back.last_success_at_unix_micros, Some(recovered_at));
    assert!(back.is_healthy());
}

/// A CONNECTOR THAT BINDS AND CANNOT APPLY IS UNHEALTHY TOO. It reports `Planned`, so a health
/// check keyed on reachability alone calls it fine while every principal fails to write.
#[tokio::test]
async fn a_reachable_connector_that_fails_every_principal_is_unhealthy() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;

    record(
        &db,
        &env,
        scope,
        &NewLdapRun {
            provisioned: 0,
            apply_failures: 12,
            ..run(&connector, now(&env), LdapRunOutcome::Planned, None)
        },
    )
    .await;

    let health = db
        .control_store()
        .scoped(scope)
        .ldap_sync_runs()
        .get(&connector)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(health.outcome, LdapRunOutcome::Planned, "it did bind");
    assert_eq!(health.consecutive_failures, 0, "and it did produce a plan");
    assert!(
        !health.is_healthy(),
        "a connector failing every principal reads as healthy"
    );
    assert_eq!(
        db.control_store()
            .scoped(scope)
            .ldap_sync_runs()
            .unhealthy_in_scope()
            .await
            .expect("read")
            .len(),
        1,
        "the unhealthy listing missed it"
    );
}

/// ONE UNHEALTHY CONNECTOR DOES NOT MAKE ITS NEIGHBOUR UNHEALTHY. The listing is the operator's
/// answer to "which of my directories is broken", so it has to name exactly those.
#[tokio::test]
async fn the_unhealthy_listing_names_only_the_broken_connectors() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let good = seed_connector(&db, &env, scope).await;
    let bad = seed_connector(&db, &env, scope).await;
    let at = now(&env);

    record(
        &db,
        &env,
        scope,
        &run(&good, at, LdapRunOutcome::Planned, None),
    )
    .await;
    record(
        &db,
        &env,
        scope,
        &run(&bad, at, LdapRunOutcome::TimedOut, Some("deadline elapsed")),
    )
    .await;

    let unhealthy = db
        .control_store()
        .scoped(scope)
        .ldap_sync_runs()
        .unhealthy_in_scope()
        .await
        .expect("read");
    assert_eq!(unhealthy.len(), 1, "{unhealthy:?}");
    assert_eq!(unhealthy[0].connector_id, bad.to_string());
    assert_eq!(unhealthy[0].outcome, LdapRunOutcome::TimedOut);

    let all = db
        .control_store()
        .scoped(scope)
        .ldap_sync_runs()
        .in_scope()
        .await
        .expect("read");
    assert_eq!(all.len(), 2, "the full listing must still show both");
}

/// THE OUTCOME SET IS CLOSED AT THE DATABASE, so a health state nothing renders cannot be stored.
#[tokio::test]
async fn an_outcome_outside_the_closed_set_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;
    record(
        &db,
        &env,
        scope,
        &run(&connector, now(&env), LdapRunOutcome::Planned, None),
    )
    .await;

    let refused =
        sqlx::query("UPDATE ldap_sync_runs SET outcome = 'weird' WHERE connector_id = $1")
            .bind(connector.to_string())
            .execute(db.owner_pool())
            .await;
    assert!(refused.is_err(), "an unrenderable health state was stored");
}

/// AND AN OUTCOME AND ITS REASON CANNOT DISAGREE. A failure with no reason is a row an operator
/// cannot act on; a success carrying one is a row they cannot trust.
#[tokio::test]
async fn a_failure_needs_a_reason_and_a_success_refuses_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;

    let no_reason = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_sync_runs()
        .record(&run(
            &connector,
            now(&env),
            LdapRunOutcome::Unreachable,
            None,
        ))
        .await;
    assert!(no_reason.is_err(), "a failure with no reason was stored");

    let stray_reason = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_sync_runs()
        .record(&run(
            &connector,
            now(&env),
            LdapRunOutcome::Planned,
            Some("nothing went wrong, honestly"),
        ))
        .await;
    assert!(
        stray_reason.is_err(),
        "a successful run carrying an error was stored"
    );
}

/// HEALTH IS INVISIBLE FROM ANOTHER ENVIRONMENT, like every other scoped row -- and this one
/// names hosts and bind failures.
#[tokio::test]
async fn health_is_invisible_from_another_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let mine = db.seed_scope(&env).await;
    let theirs = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, mine).await;
    record(
        &db,
        &env,
        mine,
        &run(&connector, now(&env), LdapRunOutcome::Planned, None),
    )
    .await;

    assert!(
        db.control_store()
            .scoped(theirs)
            .ldap_sync_runs()
            .in_scope()
            .await
            .expect("read")
            .is_empty(),
        "another environment can read this deployment's directory health"
    );
    assert_eq!(
        db.control_store()
            .scoped(theirs)
            .ldap_sync_runs()
            .get(&connector)
            .await
            .expect("read"),
        None
    );
}

/// HEALTH DIES WITH ITS CONNECTOR.
#[tokio::test]
async fn removing_the_connector_removes_its_health() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let connector = seed_connector(&db, &env, scope).await;
    record(
        &db,
        &env,
        scope,
        &run(&connector, now(&env), LdapRunOutcome::Planned, None),
    )
    .await;

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .ldap_connectors()
        .delete(&env, &connector)
        .await
        .expect("delete the connector");

    let left: i64 = sqlx::query("SELECT count(*) AS c FROM ldap_sync_runs WHERE connector_id = $1")
        .bind(connector.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("count")
        .get("c");
    assert_eq!(left, 0, "health outlived its directory");
}
