// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one data-plane-to-control-plane crossing (issue #96, criterion 5).
//!
//! What is worth testing here is not that the happy path works, which the login-flow tests drive
//! end to end, but the two properties the seam's design rests on: that it genuinely requires the
//! control plane, and that the split it crosses is still in place.

use ironauth_store::org_provisioning::OrgProvisioningSeam;
use ironauth_store::test_support::TestDatabase;

/// Register a passwordless user in `scope`, since the seam only needs a `usr_` id to enroll.
async fn seed_user(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: ironauth_store::Scope,
    handle: &str,
) -> ironauth_store::UserId {
    let id = ironauth_store::UserId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(
            db.test_actor(env),
            ironauth_store::CorrelationId::generate(env),
        )
        .users()
        .register_passwordless(env, &id, handle)
        .await
        .expect("register user");
    id
}

fn now_micros(env: &ironauth_env::Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// The split the seam exists to cross is still there.
///
/// Pinned against `information_schema` rather than read off the migrations, because 0001's grants
/// are not what later migrations left in place and a survey of the SQL says the opposite of the
/// truth. If a future migration hands the data plane INSERT on `organizations`, the seam stops
/// being necessary and this test is where that shows up, with the reason attached.
#[tokio::test]
async fn the_data_plane_still_holds_no_insert_on_organizations() {
    let db = TestDatabase::start().await;
    let grants: Vec<String> = sqlx::query_scalar(
        "SELECT privilege_type::text FROM information_schema.role_table_grants \
         WHERE table_name = 'organizations' AND grantee = 'ironauth_app' \
         ORDER BY privilege_type",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("read the grants");

    assert_eq!(
        grants,
        vec!["SELECT".to_owned()],
        "the data plane's grants on `organizations` changed. It anchors every org-scoped \
         authorization decision, and the plane serving unauthenticated traffic holding INSERT on \
         it is what `OrgProvisioningSeam` exists to avoid. Got {grants:?}"
    );
}

/// A seam built over the DATA-plane store fails at the write.
///
/// The seam's constructor cannot tell which store it was handed, so this is the behaviour a
/// caller gets when it passes the wrong one. It fails loudly at the INSERT rather than silently
/// degrading, which is what makes the constructor's documented contract enforceable.
#[tokio::test]
async fn the_seam_refuses_to_work_through_the_data_plane_store() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "founder@example.test").await;

    let seam = OrgProvisioningSeam::new(db.store().clone());
    let outcome = seam
        .create_and_enroll(
            &env,
            scope,
            db.test_actor(&env),
            "Should Not Exist",
            &user,
            now_micros(&env),
        )
        .await;

    assert!(
        outcome.is_err(),
        "a seam over the data-plane store created an organization, which means the data plane \
         holds INSERT on `organizations` after all"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organizations WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count organizations");
    assert_eq!(count, 0, "the failed write left a row behind");
}

/// Over the CONTROL store it creates the organization and enrolls the user, and the enrollment is
/// a real membership rather than an organization nobody belongs to.
#[tokio::test]
async fn the_seam_creates_an_organization_and_enrolls_its_creator() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "founder@example.test").await;

    let seam = OrgProvisioningSeam::new(db.control_store().clone());
    let organization = seam
        .create_and_enroll(
            &env,
            scope,
            db.test_actor(&env),
            "Founders Inc",
            &user,
            now_micros(&env),
        )
        .await
        .expect("the control plane may create an organization");

    assert!(
        db.store()
            .scoped(scope)
            .org_memberships()
            .exists(&organization, &user)
            .await
            .expect("membership lookup"),
        "the creator must be enrolled, or the seam leaves an organization nobody belongs to"
    );
}

/// A user from ANOTHER scope is refused before anything is written.
///
/// The seam takes a scope and a user separately, so nothing but this check stops a caller pairing
/// them wrongly, and the failure mode would be an organization created in one environment holding
/// a member from another.
#[tokio::test]
async fn a_user_from_another_scope_creates_nothing() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let here = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    let foreign_user = seed_user(&db, &env, elsewhere, "foreign@example.test").await;

    let seam = OrgProvisioningSeam::new(db.control_store().clone());
    let outcome = seam
        .create_and_enroll(
            &env,
            here,
            db.test_actor(&env),
            "Cross Scope Ltd",
            &foreign_user,
            now_micros(&env),
        )
        .await;
    assert!(
        matches!(outcome, Err(ironauth_store::StoreError::NotFound)),
        "a cross-scope user must be the uniform not-found, got {outcome:?}"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organizations WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(here.tenant().to_string())
    .bind(here.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count organizations");
    assert_eq!(
        count, 0,
        "the refused call created the organization before checking the user"
    );
}
