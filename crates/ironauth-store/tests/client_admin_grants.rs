// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment, per-client admin consent pre-authorizations over a real database
//! (`DATABASE_URL`) (issue #88, PR 4).
//!
//! Proves the load-bearing properties of the admin-consent-grant data plane against a live
//! database:
//!
//! - **Control-plane set, data-plane read.** A pre-authorization is set on the control-plane role
//!   that owns the lifecycle and read back on the data-plane role the consent gate uses.
//! - **Overwrite idempotent on the client id, reusing the row id.** A repeat write to the same
//!   client overwrites in place and keeps the row's id (a stable audit target).
//! - **Delete (revoke) and cross-scope isolation.** A delete removes the pre-authorization; a
//!   pre-authorization set in scope A never appears in scope B, and a cross-scope delete is a
//!   uniform not-found.
//! - **Audited writes.** Set writes exactly one `admin_consent.grant` audit row; delete writes
//!   exactly one `admin_consent.revoke` row; both target the pre-authorization id.
//! - **Pure coverage predicate.** `admin_grant_covers_scope` is subset containment.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ClientAdminGrantId, ClientId, CorrelationId, NewClientAdminGrant, StoreError,
    admin_grant_covers_scope,
};

fn grant<'a>(client_id: &'a str, scope: Option<&'a str>) -> NewClientAdminGrant<'a> {
    NewClientAdminGrant {
        client_id,
        granted_scope: scope,
        granted_by: "admin_test",
    }
}

#[tokio::test]
async fn set_reads_back_on_the_data_plane_and_is_audited() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let app = db.store();

    let client = ClientId::generate(&env, &scope).to_string();
    let id = ClientAdminGrantId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_admin_grants()
        .set(&env, &id, 1_000_000, grant(&client, Some("openid profile")))
        .await
        .expect("set admin grant");

    // Read back on the DATA-plane role (the consent gate's role).
    let record = app
        .scoped(scope)
        .client_admin_grants()
        .get(&client)
        .await
        .expect("read grant")
        .expect("a grant exists");
    assert_eq!(record.client_id, client);
    assert_eq!(record.granted_scope.as_deref(), Some("openid profile"));

    // The set wrote exactly one admin_consent.grant audit row targeting the pre-authorization id.
    let rows = app.scoped(scope).audit().list().await.expect("audit list");
    assert_eq!(rows.len(), 1, "set writes one audit row");
    assert_eq!(rows[0].action, "admin_consent.grant");
    assert_eq!(rows[0].target_kind, "cag");
    assert_eq!(rows[0].target_id, id.to_string());
}

#[tokio::test]
async fn an_overwrite_reuses_the_row_id_and_a_delete_removes_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let client = ClientId::generate(&env, &scope).to_string();

    let id = ClientAdminGrantId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_admin_grants()
        .set(&env, &id, 1_000_000, grant(&client, Some("openid")))
        .await
        .expect("first set");

    // A repeat write to the same client (a fresh id) overwrites in place and REUSES the row's id.
    let id2 = ClientAdminGrantId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_admin_grants()
        .set(
            &env,
            &id2,
            2_000_000,
            grant(&client, Some("openid profile")),
        )
        .await
        .expect("overwrite");

    let all = control
        .scoped(scope)
        .client_admin_grants()
        .list_all()
        .await
        .expect("list");
    assert_eq!(all.len(), 1, "an overwrite keeps a single row per client");
    assert_eq!(
        all[0].id,
        id.to_string(),
        "the row id is reused, not the second one"
    );
    assert_eq!(all[0].granted_scope.as_deref(), Some("openid profile"));

    // Delete by the stored id (reused across the overwrite): the pre-authorization is gone.
    let stored_id =
        ClientAdminGrantId::parse_in_scope(&all[0].id, &scope).expect("parse stored id");
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_admin_grants()
        .delete(&env, &stored_id)
        .await
        .expect("delete");
    assert!(
        control
            .scoped(scope)
            .client_admin_grants()
            .get(&client)
            .await
            .expect("get after delete")
            .is_none(),
        "the pre-authorization is deleted"
    );

    // The delete wrote an admin_consent.revoke audit row targeting the pre-authorization id.
    let rows = control
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit list");
    let revokes: Vec<_> = rows
        .iter()
        .filter(|row| row.action == "admin_consent.revoke")
        .collect();
    assert_eq!(revokes.len(), 1, "exactly one revoke audit row");
    assert_eq!(revokes[0].target_id, stored_id.to_string());
}

#[tokio::test]
async fn a_delete_of_an_absent_or_cross_scope_grant_is_a_uniform_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let control = db.control_store();

    // A delete of a client with no pre-authorization in scope A is NotFound.
    let absent = ClientAdminGrantId::generate(&env, &scope_a);
    let result = control
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_admin_grants()
        .delete(&env, &absent)
        .await;
    assert!(matches!(result, Err(StoreError::NotFound)), "{result:?}");

    // An id minted in scope B is out of scope A: a uniform NotFound (no cross-scope delete).
    let foreign = ClientAdminGrantId::generate(&env, &scope_b);
    let result = control
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_admin_grants()
        .delete(&env, &foreign)
        .await;
    assert!(matches!(result, Err(StoreError::NotFound)), "{result:?}");
}

#[tokio::test]
async fn a_grant_is_scoped_and_never_leaks_across_environments() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let control = db.control_store();

    let client = ClientId::generate(&env, &scope_a).to_string();
    let id = ClientAdminGrantId::generate(&env, &scope_a);
    control
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_admin_grants()
        .set(&env, &id, 1_000_000, grant(&client, Some("openid")))
        .await
        .expect("set grant in scope A");

    // Scope B sees no grant for the same client id and an empty list.
    assert!(
        control
            .scoped(scope_b)
            .client_admin_grants()
            .get(&client)
            .await
            .expect("get in B")
            .is_none(),
        "scope B has no grant"
    );
    assert!(
        control
            .scoped(scope_b)
            .client_admin_grants()
            .list_all()
            .await
            .expect("list in B")
            .is_empty(),
        "scope B lists no grant"
    );
}

#[test]
fn admin_grant_covers_scope_is_subset_containment() {
    // Exact and subset are covered; a superset request is not; the empty request is always
    // covered; an absent grant covers only the empty request.
    assert!(admin_grant_covers_scope(
        Some("openid profile"),
        Some("openid profile")
    ));
    assert!(admin_grant_covers_scope(
        Some("openid profile email"),
        Some("openid profile")
    ));
    assert!(!admin_grant_covers_scope(
        Some("openid"),
        Some("openid profile")
    ));
    assert!(admin_grant_covers_scope(Some("openid"), None));
    assert!(!admin_grant_covers_scope(None, Some("openid")));
}
