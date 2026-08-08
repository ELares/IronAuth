// SPDX-License-Identifier: MIT OR Apache-2.0

//! A membership may bind a service account (issue #99, criterion 3), schema half.
//!
//! Migration 0124 makes the row representable. Resolution deliberately does NOT yet include
//! it, and the last test here asserts that rather than leaving it to be discovered: the
//! resolution change is `EFFECTIVE_CLOSURE_CTE`'s anchor and lands separately so its diff can
//! be reviewed and mutation-swept on its own.

use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, Scope, UserId};

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

async fn seed_user(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    handle: &str,
) -> UserId {
    let id = UserId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register_passwordless(env, &id, handle)
        .await
        .expect("register user");
    id
}

/// An existing user membership is untouched by the migration.
///
/// The whole safety claim of an EXPAND: `user_id` was relaxed from NOT NULL and a discriminator
/// was added with a default, so every row that existed keeps its user, its foreign key, and now
/// says `owner_kind = 'user'` without having been rewritten.
#[tokio::test]
async fn an_existing_user_membership_still_says_it_binds_a_user() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "member@example.test").await;
    let org = ironauth_store::OrganizationId::generate(&env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org, now_micros(&env), "acme", None)
        .await
        .expect("create org");
    let membership = ironauth_store::OrgMembershipId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_memberships()
        .create(
            &env,
            ironauth_store::NewMembership {
                id: &membership,
                organization_id: &org,
                user_id: &user,
                metadata: None,
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("create membership");

    let (kind, user_id, service_account_id): (String, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT owner_kind, user_id, service_account_id FROM org_memberships WHERE id = $1",
        )
        .bind(membership.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("read the membership");
    assert_eq!(
        kind, "user",
        "an ordinary membership must default to 'user'"
    );
    assert_eq!(user_id.as_deref(), Some(user.to_string().as_str()));
    assert_eq!(service_account_id, None);
}

/// The exclusive arc refuses every malformed combination.
///
/// Written against the ENGINE rather than through a repository, because there is no write path
/// for a service-account membership yet and the CHECK is the thing under test. Each case is a
/// row a future writer could produce by wiring the discriminator to the wrong column.
#[tokio::test]
async fn the_owner_arc_refuses_every_malformed_combination() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "arc@example.test").await;
    let org = ironauth_store::OrganizationId::generate(&env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org, now_micros(&env), "acme", None)
        .await
        .expect("create org");

    let client = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "a machine client")
        .await
        .expect("create client");
    let principal = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .service_accounts()
        .ensure(&env, &client)
        .await
        .expect("mint the principal");

    assert_arc_refuses_and_accepts(&db, &env, scope, &org, &user, &principal).await;
}

// A plain async fn rather than a closure: a closure capturing `db` by move cannot be
// called five times, and threading the borrow through is noise beside what is measured.
async fn insert(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    org: &ironauth_store::OrganizationId,
    kind: &str,
    u: Option<String>,
    sa: Option<String>,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let org = org.to_string();
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let id = ironauth_store::OrgMembershipId::generate(env, &scope).to_string();
    sqlx::query(
        "INSERT INTO org_memberships \
             (id, tenant_id, environment_id, organization_id, user_id, \
              service_account_id, owner_kind) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(tenant)
    .bind(environment)
    .bind(org)
    .bind(u)
    .bind(sa)
    .bind(kind)
    .execute(db.owner_pool())
    .await
}

/// The arc cases, split out because the fixture above and the six probes below together
/// exceed the function-length lint, and because the probes are the part worth reading.
async fn assert_arc_refuses_and_accepts(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    org: &ironauth_store::OrganizationId,
    user: &UserId,
    principal: &ironauth_store::ServiceAccountId,
) {
    // A 'user' row with no user, and one that also names a service account.
    assert!(
        insert(db, env, scope, org, "user", None, None)
            .await
            .is_err()
    );
    assert!(
        insert(
            db,
            env,
            scope,
            org,
            "user",
            Some(user.to_string()),
            Some(principal.to_string())
        )
        .await
        .is_err(),
        "a user membership that ALSO names a service account is ambiguous and must be refused"
    );
    // A 'service_account' row with no service account, and one that also names a user.
    assert!(
        insert(db, env, scope, org, "service_account", None, None)
            .await
            .is_err()
    );
    assert!(
        insert(
            db,
            env,
            scope,
            org,
            "service_account",
            Some(user.to_string()),
            Some(principal.to_string()),
        )
        .await
        .is_err(),
        "a service-account membership that ALSO names a user is ambiguous and must be refused"
    );
    // An unknown discriminator.
    assert!(
        insert(
            db,
            env,
            scope,
            org,
            "robot",
            None,
            Some(principal.to_string())
        )
        .await
        .is_err()
    );

    // The well-formed service-account row IS accepted. Without this the four refusals above
    // could all be a column that rejects everything, which measures nothing.
    assert!(
        insert(
            db,
            env,
            scope,
            org,
            "service_account",
            None,
            Some(principal.to_string())
        )
        .await
        .is_ok(),
        "a well-formed service-account membership must be representable"
    );
}

/// A service-account membership does NOT yet resolve permissions, and that is asserted here
/// rather than left to be discovered.
///
/// Migration 0124 makes the ROW representable; `EFFECTIVE_CLOSURE_CTE` still anchors on
/// `JOIN users u ON u.id = m.user_id`, so a service-account membership matches nothing. This
/// test is the pin that the schema landed WITHOUT changing what any token carries, and it is
/// the test the resolution change will flip.
#[tokio::test]
async fn a_service_account_membership_does_not_yet_resolve_permissions() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let org = ironauth_store::OrganizationId::generate(&env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org, now_micros(&env), "acme", None)
        .await
        .expect("create org");
    let client = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "a machine client")
        .await
        .expect("create client");
    let principal = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .service_accounts()
        .ensure(&env, &client)
        .await
        .expect("mint the principal");

    sqlx::query(
        "INSERT INTO org_memberships \
         (id, tenant_id, environment_id, organization_id, service_account_id, owner_kind) \
         VALUES ($1, $2, $3, $4, $5, 'service_account')",
    )
    .bind(ironauth_store::OrgMembershipId::generate(&env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(org.to_string())
    .bind(principal.to_string())
    .execute(db.owner_pool())
    .await
    .expect("insert the service-account membership");

    // The resolution anchor joins `users`, so this row is invisible to it. When the anchor
    // learns about service accounts this assertion flips, and flipping it deliberately is the
    // point: nothing about what a token carries changed in this migration.
    let resolved: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM org_memberships m \
         JOIN users u ON u.id = m.user_id \
         WHERE m.organization_id = $1",
    )
    .bind(org.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count resolvable memberships");
    assert_eq!(
        resolved, 0,
        "the service-account membership resolved through the user anchor, which means this \
         migration changed what a token carries and it must not have"
    );
}
