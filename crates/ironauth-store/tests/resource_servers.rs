// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resource-server registry persistence and isolation (issue #29), over a real
//! database (`DATABASE_URL`).
//!
//! Proves the audience-to-format registry round-trips, is scope-isolated (a
//! registration in one scope never resolves under another), rejects a duplicate
//! audience per environment, and audits every registration.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewResourceServer, ResourceServerId, Scope, StoreError, TokenFormat,
};

/// Register a resource server in `scope` and return its id.
async fn register(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    audience: &str,
    format: TokenFormat,
    ttl: Option<i64>,
) -> ResourceServerId {
    let id = ResourceServerId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .resource_servers()
        .register(
            env,
            NewResourceServer {
                id: &id,
                audience,
                token_format: format,
                access_token_ttl_secs: ttl,
            },
        )
        .await
        .expect("register resource server");
    id
}

#[tokio::test]
async fn register_and_fetch_by_audience_round_trips_both_formats() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // One at+jwt resource server with no custom lifetime, one opaque with a custom
    // lifetime, in the SAME environment (the per-RS format-choice acceptance).
    let jwt_id = register(
        &db,
        &env,
        scope,
        "https://api.example/reports",
        TokenFormat::AtJwt,
        None,
    )
    .await;
    let opaque_id = register(
        &db,
        &env,
        scope,
        "https://api.example/orders",
        TokenFormat::Opaque,
        Some(120),
    )
    .await;

    let repo = db.store().scoped(scope);
    let jwt = repo
        .resource_servers()
        .by_audience("https://api.example/reports")
        .await
        .expect("fetch")
        .expect("present");
    assert_eq!(jwt.id, jwt_id);
    assert_eq!(jwt.audience, "https://api.example/reports");
    assert_eq!(jwt.token_format, TokenFormat::AtJwt);
    assert_eq!(jwt.access_token_ttl_secs, None, "falls back to env default");

    let opaque = repo
        .resource_servers()
        .by_audience("https://api.example/orders")
        .await
        .expect("fetch")
        .expect("present");
    assert_eq!(opaque.id, opaque_id);
    assert_eq!(opaque.token_format, TokenFormat::Opaque);
    assert_eq!(opaque.access_token_ttl_secs, Some(120));

    // An unregistered audience is a uniform None.
    assert!(
        repo.resource_servers()
            .by_audience("https://api.example/unknown")
            .await
            .expect("fetch")
            .is_none()
    );
}

#[tokio::test]
async fn a_duplicate_audience_in_one_environment_is_a_conflict() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    register(
        &db,
        &env,
        scope,
        "https://api.example/dup",
        TokenFormat::AtJwt,
        None,
    )
    .await;

    // A second registration of the SAME audience in the same environment is a
    // caller-facing conflict (the audience selects at most one format).
    let second = ResourceServerId::generate(&env, &scope);
    let outcome = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .resource_servers()
        .register(
            &env,
            NewResourceServer {
                id: &second,
                audience: "https://api.example/dup",
                token_format: TokenFormat::Opaque,
                access_token_ttl_secs: None,
            },
        )
        .await;
    assert!(
        matches!(outcome, Err(StoreError::Conflict)),
        "a duplicate audience must be a conflict, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_resource_server_is_not_visible_across_scopes() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // The SAME audience string registered in two different scopes must resolve to
    // each scope's OWN row, never leak across (the audience is scope-local).
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let env_a2 = db.seed_environment(&env, scope_a.tenant()).await;
    let scope_a2 = Scope::new(scope_a.tenant(), env_a2);

    let shared_audience = "https://api.example/shared";
    register(
        &db,
        &env,
        scope_a,
        shared_audience,
        TokenFormat::AtJwt,
        None,
    )
    .await;
    let in_b = register(
        &db,
        &env,
        scope_b,
        shared_audience,
        TokenFormat::Opaque,
        None,
    )
    .await;

    // Scope B sees ITS registration (opaque), never scope A's (at+jwt).
    let from_b = db
        .store()
        .scoped(scope_b)
        .resource_servers()
        .by_audience(shared_audience)
        .await
        .expect("fetch")
        .expect("present in b");
    assert_eq!(from_b.id, in_b);
    assert_eq!(from_b.token_format, TokenFormat::Opaque);

    // A second environment of the SAME tenant that never registered the audience
    // resolves to None: environment isolation, not just tenant isolation.
    assert!(
        db.store()
            .scoped(scope_a2)
            .resource_servers()
            .by_audience(shared_audience)
            .await
            .expect("fetch")
            .is_none(),
        "a sibling environment must not see another environment's resource server"
    );
}

#[tokio::test]
async fn registering_a_resource_server_writes_its_audit_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let id = register(
        &db,
        &env,
        scope,
        "https://api.example/audited",
        TokenFormat::AtJwt,
        None,
    )
    .await;

    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("list audit");
    let rows: Vec<_> = audit
        .iter()
        .filter(|row| row.action == "resource_server.register")
        .collect();
    assert_eq!(rows.len(), 1, "exactly one register audit row");
    assert_eq!(rows[0].target_kind, "rsv");
    assert_eq!(rows[0].target_id, id.to_string());
}
