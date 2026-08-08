// SPDX-License-Identifier: MIT OR Apache-2.0

//! A membership may bind a service account (issue #99, criterion 3), schema half.
//!
//! Migration 0124 made the row representable; this file's last test is the one that says
//! resolution reaches it. That test replaced a pin asserting the opposite, so the flip is the
//! evidence the anchor rewrite in `EFFECTIVE_CLOSURE_CTE` landed rather than something quietly
//! starting to match.

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

/// A service-account membership resolves permissions through the SAME projection a user's
/// does (issue #99, criterion 3).
///
/// This replaces a pin that asserted the opposite while the anchor still read `JOIN users`.
///
/// The two branches are NOT symmetric and could not be written by copying. `users` is
/// soft-deleted and its branch enforces `deleted_at IS NULL`; `service_accounts` carries
/// neither `deleted_at` nor `state`, so liveness there IS existence, expressed as
/// `s.id IS NOT NULL` past a LEFT JOIN.
#[tokio::test]
async fn a_service_account_membership_resolves_the_same_permissions_a_user_would() {
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

    let role = grant_reader_role(&db, &env, scope, &org).await;

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

    let membership = ironauth_store::OrgMembershipId::generate(&env, &scope);
    sqlx::query(
        "INSERT INTO org_memberships \
         (id, tenant_id, environment_id, organization_id, service_account_id, owner_kind) \
         VALUES ($1, $2, $3, $4, $5, 'service_account')",
    )
    .bind(membership.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(org.to_string())
    .bind(principal.to_string())
    .execute(db.owner_pool())
    .await
    .expect("insert the service-account membership");
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_membership_roles(scope)
        .assign(
            &env,
            ironauth_store::NewOrgMembershipRole {
                id: &ironauth_store::OrgMembershipRoleId::generate(&env, &scope),
                organization_id: &org,
                membership_id: &membership,
                role_id: &role,
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("grant the role to the membership");

    let resolved = db
        .control_store()
        .management()
        .org_groups(scope)
        .effective_permissions_for_service_account(&org, &principal, 8)
        .await
        .expect("resolve");
    assert!(
        resolved.contains("billing.invoice.read"),
        "a service account holding a role must resolve that role's permissions, got {resolved:?}"
    );
}

/// Define one permission, one role, and bind them. Split out only for the length lint.
async fn grant_reader_role(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    org: &ironauth_store::OrganizationId,
) -> ironauth_store::OrgRoleId {
    let permission = ironauth_store::PermissionId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .permissions(scope)
        .create(
            env,
            ironauth_store::NewPermission {
                id: &permission,
                slug: "billing.invoice.read",
                display_name: "Read invoices",
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("define the permission");
    let role = ironauth_store::OrgRoleId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .org_roles(scope)
        .create(
            env,
            ironauth_store::NewOrgRole {
                id: &role,
                organization_id: org,
                slug: "reader",
                display_name: "Reader",
                metadata: None,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("define the role");
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .org_role_permissions(scope)
        .assign(
            env,
            ironauth_store::NewOrgRolePermission {
                id: &ironauth_store::OrgRolePermissionId::generate(env, &scope),
                organization_id: org,
                role_id: &role,
                permission_id: &permission,
            },
            now_micros(env),
            None,
        )
        .await
        .expect("grant the permission to the role");
    role
}

/// A membership naming a service-account ROW that lives in another scope resolves to nothing.
///
/// This is the case that makes `s.id IS NOT NULL` load-bearing rather than decorative, and it
/// has to be built deliberately. A well-formed foreign principal never reaches the SQL at all:
/// `ServiceAccountId` carries its scope in the identifier, so `resolve_effective`'s Rust fence
/// rejects it before a statement is prepared. The row below defeats that fence the only way it
/// can be defeated, by giving the principal an identifier minted in THIS scope while its row
/// sits in the other one. The foreign key on `service_account_id` references
/// `service_accounts (id)` alone and cannot see tenant or environment, so nothing in the schema
/// objects.
///
/// The scope predicates sit on the LEFT JOIN, so the join misses, `s.id` is NULL, and the
/// disjunct refuses the membership. Delete `AND s.id IS NOT NULL` and this test fails while
/// every other test in the tree still passes, which is why it is written separately from the
/// resolution test.
#[tokio::test]
async fn a_membership_naming_a_service_account_row_in_another_scope_resolves_to_nothing() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    assert_ne!(
        scope.environment(),
        elsewhere.environment(),
        "the two scopes must actually differ or this test proves nothing"
    );
    let org = ironauth_store::OrganizationId::generate(&env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org, now_micros(&env), "acme", None)
        .await
        .expect("create org");
    let role = grant_reader_role(&db, &env, scope, &org).await;

    // A client next door, to satisfy the composite foreign key the planted row needs.
    let client = db
        .store()
        .scoped(elsewhere)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "a machine client next door")
        .await
        .expect("create client");
    // The identifier is minted in THIS scope so the Rust fence lets the call through; the row
    // it names is planted next door.
    let principal = ironauth_store::ServiceAccountId::generate(&env, &scope);
    sqlx::query(
        "INSERT INTO service_accounts (id, tenant_id, environment_id, client_id) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(principal.to_string())
    .bind(elsewhere.tenant().to_string())
    .bind(elsewhere.environment().to_string())
    .bind(client.to_string())
    .execute(db.owner_pool())
    .await
    .expect("plant the cross-scope principal row");

    let membership = ironauth_store::OrgMembershipId::generate(&env, &scope);
    sqlx::query(
        "INSERT INTO org_memberships \
         (id, tenant_id, environment_id, organization_id, service_account_id, owner_kind) \
         VALUES ($1, $2, $3, $4, $5, 'service_account')",
    )
    .bind(membership.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(org.to_string())
    .bind(principal.to_string())
    .execute(db.owner_pool())
    .await
    .expect("the arc and the foreign key both admit a cross-scope principal");
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_membership_roles(scope)
        .assign(
            &env,
            ironauth_store::NewOrgMembershipRole {
                id: &ironauth_store::OrgMembershipRoleId::generate(&env, &scope),
                organization_id: &org,
                membership_id: &membership,
                role_id: &role,
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("grant the role to the membership");

    let resolved = db
        .control_store()
        .management()
        .org_groups(scope)
        .effective_permissions_for_service_account(&org, &principal, 8)
        .await
        .expect("resolve");
    assert!(
        resolved.is_empty(),
        "a principal whose row lives in another scope must resolve to nothing, got {resolved:?}"
    );
}
