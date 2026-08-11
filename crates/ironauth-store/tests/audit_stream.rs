// SPDX-License-Identifier: MIT OR Apache-2.0

//! Audit stream separation, against real rows (issue #109).
//!
//! [`ironauth_store::ocsf`]'s own tests prove the mapping is exhaustive and that the classes
//! carry their OCSF uids. They cannot prove the mapping REACHES storage, and a classifier
//! nothing calls is the failure this file exists to rule out: every assertion here reads the
//! `stream` column off a row a real mutation wrote, through the owner pool.
//!
//! Two directions matter and both are checked. An admin mutation must land in the admin
//! stream, an authentication mutation in the authentication stream, and no row may carry a
//! stream that disagrees with what the classifier says its action maps to. The last of those
//! is the one that survives new actions being added: it re-derives the expected value from
//! `ocsf` for whatever rows the test happened to write, so a writer that starts hardcoding a
//! stream fails it.

use ironauth_env::Env;
use ironauth_store::ocsf::{self, AuditStream};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, NewSession, Scope, SessionId};
use sqlx::Row;

/// A far-future expiry (year 2100) in epoch microseconds, so the session is live.
const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// Every audit row as `(action, stream)`, read through the owner pool so row-level
/// security cannot hide one.
async fn audit_rows(db: &TestDatabase) -> Vec<(String, String)> {
    sqlx::query("SELECT action, stream FROM audit_log ORDER BY occurred_at, id")
        .fetch_all(db.owner_pool())
        .await
        .expect("read audit rows")
        .into_iter()
        .map(|row| (row.get("action"), row.get("stream")))
        .collect()
}

/// Create a live SSO session, which is an authentication-domain mutation.
async fn create_session(db: &TestDatabase, env: &Env, scope: Scope) -> SessionId {
    let id = SessionId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .sessions()
        .rotate(
            env,
            &id,
            None,
            NewSession {
                impersonation: None,
                subject: "usr_stream_probe",
                auth_methods: "pwd",
                auth_time_micros: 0,
                idle_expires_micros: FAR_FUTURE_MICROS,
                absolute_expires_micros: FAR_FUTURE_MICROS,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("rotate a session");
    id
}

#[tokio::test]
async fn an_admin_mutation_and_an_authentication_mutation_land_in_different_streams() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "stream-probe")
        .await
        .expect("create a client");
    create_session(&db, &env, scope).await;

    let rows = audit_rows(&db).await;
    assert!(
        rows.len() >= 2,
        "both mutations must have written an audit row: {rows:?}"
    );

    let admin: Vec<&(String, String)> = rows.iter().filter(|(_, s)| s == "admin_action").collect();
    let authn: Vec<&(String, String)> =
        rows.iter().filter(|(_, s)| s == "authentication").collect();
    assert!(
        !admin.is_empty(),
        "the client create must land in the admin stream: {rows:?}"
    );
    assert!(
        !authn.is_empty(),
        "the session rotate must land in the authentication stream: {rows:?}"
    );
    // The point of the split: neither stream is where everything went.
    assert_eq!(
        admin.len() + authn.len(),
        rows.len(),
        "every row belongs to one of the two streams: {rows:?}"
    );

    assert!(
        admin
            .iter()
            .any(|(action, _)| action.starts_with("client.")),
        "the client mutation is the admin-stream row: {admin:?}"
    );
    assert!(
        authn
            .iter()
            .any(|(action, _)| action.starts_with("session.")),
        "the session mutation is the authentication-stream row: {authn:?}"
    );
}

#[tokio::test]
async fn no_stored_row_disagrees_with_the_classifier() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "agreement-probe")
        .await
        .expect("create a client");
    create_session(&db, &env, scope).await;

    let rows = audit_rows(&db).await;
    assert!(!rows.is_empty(), "the probe wrote no rows to check");
    for (action, stored) in &rows {
        let class = ocsf::class_for_wire(action)
            .unwrap_or_else(|| panic!("a stored audit action `{action}` classifies as nothing"));
        assert_eq!(
            class.stream().as_str(),
            stored,
            "the stored stream for `{action}` disagrees with the classifier"
        );
    }
}

#[tokio::test]
async fn the_stream_column_refuses_a_value_that_is_neither_stream() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "check-probe")
        .await
        .expect("create a client");

    // Through the OWNER pool, which bypasses row-level security: the CHECK is the last
    // thing standing between a typo and a row that no retention policy governs, so it has
    // to hold even for a writer that is not the application role.
    let result = sqlx::query("UPDATE audit_log SET stream = 'authentification'")
        .execute(db.owner_pool())
        .await;
    assert!(
        result.is_err(),
        "a third stream value must be refused by the CHECK constraint"
    );

    // And the two real values are both accepted, so the CHECK is not simply rejecting
    // every update.
    for stream in [AuditStream::AdminAction, AuditStream::Authentication] {
        sqlx::query("UPDATE audit_log SET stream = $1")
            .bind(stream.as_str())
            .execute(db.owner_pool())
            .await
            .unwrap_or_else(|error| panic!("`{}` must be accepted: {error}", stream.as_str()));
    }
}

/// The organization dimension (issue #110) records what the acting context established,
/// and NULL otherwise.
///
/// NULL is a fact, not missing data: it means "not an organization's event". A per-org
/// stream matching NULL rows would deliver a tenant-level configuration change to every
/// organization's SIEM, which is the leak the column exists to prevent.
#[tokio::test]
async fn an_audit_row_records_the_acting_organization_and_null_when_there_is_none() {
    use ironauth_store::OrganizationId;

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let organization = OrganizationId::generate(&env, &scope);

    // Attributed.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .in_organization(organization)
        .clients()
        .create(&env, "org-attributed")
        .await
        .expect("create a client in an organization");
    // Unattributed: the ordinary path, which must stay NULL.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "not-attributed")
        .await
        .expect("create a client with no organization");

    let rows: Vec<(String, Option<String>)> =
        sqlx::query("SELECT target_id, organization_id FROM audit_log ORDER BY occurred_at, id")
            .fetch_all(db.owner_pool())
            .await
            .expect("read audit rows")
            .into_iter()
            .map(|row| (row.get("target_id"), row.get("organization_id")))
            .collect();

    let attributed: Vec<&Option<String>> = rows
        .iter()
        .filter(|(_, org)| org.is_some())
        .map(|(_, org)| org)
        .collect();
    assert_eq!(
        attributed.len(),
        1,
        "exactly the attributed write carries an organization: {rows:?}"
    );
    assert_eq!(
        attributed[0].as_deref(),
        Some(organization.to_string().as_str()),
        "and it carries the one the acting context established"
    );
    assert!(
        rows.iter().any(|(_, org)| org.is_none()),
        "the unattributed write must stay NULL rather than inheriting the other's org: \
         {rows:?}"
    );
}
