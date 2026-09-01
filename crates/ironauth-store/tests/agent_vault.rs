// SPDX-License-Identifier: MIT OR Apache-2.0

//! The agent token vault (issue #132), criteria 1, 2 and 3.
//!
//! Criterion 2 is the load-bearing one and it is stated as a property of a RAW DUMP: the
//! contents are encrypted at rest with per-tenant keys, and a dump yields no usable
//! third-party credential. That is not a property of how carefully callers behave, so the
//! test reads the row back as the database owner, bypassing every repository, and looks for
//! the plaintext in EVERY column rather than in the one column expected to hold it. A column
//! added later to carry a hint or a label is exactly how a secret ends up persisted by
//! accident, and a test that checked only the sealed column would not notice.

use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AgentPrincipalId, AgentVaultConnectionId, CorrelationId, NewAgent, NewVaultConnection,
    OrganizationId, Scope, UserId,
};

/// A downstream access token that is unmistakable if it ever appears in a column.
const DOWNSTREAM_ACCESS: &str = "ya29.PLAINTEXT-GOOGLE-ACCESS-TOKEN-do-not-persist";
/// And its refresh token, sealed under a DIFFERENT purpose than the access token.
const DOWNSTREAM_REFRESH: &str = "1//PLAINTEXT-GOOGLE-REFRESH-TOKEN-do-not-persist";

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

/// Seed an organization, a user, and an agent, returning the agent.
async fn seed_agent(db: &TestDatabase, env: &ironauth_env::Env, scope: Scope) -> AgentPrincipalId {
    let organization = OrganizationId::generate(env, &scope);
    sqlx::query(
        "INSERT INTO organizations /* query-audit-allow: owner test seed */ \
         (id, tenant_id, environment_id, display_name) VALUES ($1, $2, $3, 'vault org')",
    )
    .bind(organization.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(db.owner_pool())
    .await
    .expect("seed organization");

    let user = UserId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        // The identifier is derived from the user id, so seeding TWO agents in one scope
        // does not collide on the unique login handle. The per-agent scoping test needs two.
        .register_passwordless(env, &user, &format!("{user}@example.test"), None)
        .await
        .expect("register user");

    let agent = AgentPrincipalId::generate(env, &scope);
    // The CONTROL plane writes. The data-plane role holds only SELECT on `agents` and
    // SELECT + UPDATE on the vault, which is the design: a token door reads a connection and
    // marks one failed, and may not create a principal or store a credential. Routing the
    // fixture through the data plane would ask for a privilege the product deliberately
    // withholds, and the first draft of this test failed with exactly that permission error.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .agents()
        .register(
            env,
            NewAgent {
                id: &agent,
                organization_id: &organization,
                linked_user_id: &user,
                display_name: "vault agent",
                tool_scopes: &["deploy".to_owned()],
                client_id: None,
            },
            now_micros(env),
            None,
            None,
        )
        .await
        .expect("register agent");
    agent
}

/// Store a Google connection for `agent`.
async fn store_connection(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    agent: &AgentPrincipalId,
    provider: &str,
) -> AgentVaultConnectionId {
    let id = AgentVaultConnectionId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .agent_vault()
        .store_connection(
            env,
            NewVaultConnection {
                id: &id,
                agent_id: agent,
                provider,
                access_token: DOWNSTREAM_ACCESS,
                refresh_token: Some(DOWNSTREAM_REFRESH),
                granted_scopes: &["https://www.googleapis.com/auth/drive.readonly".to_owned()],
                expires_at_unix_micros: None,
            },
            now_micros(env),
        )
        .await
        .expect("store connection");
    id
}

/// AC2: a raw dump of the vault yields no usable third-party credential.
#[tokio::test]
async fn no_column_of_a_stored_connection_holds_the_downstream_plaintext() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    store_connection(&db, &env, scope, &agent, "google").await;

    // Read as the OWNER, bypassing every repository and the row-level policy: this is what a
    // dump sees. Every column is rendered to text, including the bytea ones, so a plaintext
    // hiding in a column nobody thought about is still caught.
    let columns: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT unnest(ARRAY[id, tenant_id, environment_id, agent_id, provider, \
                            encode(access_token_sealed, 'escape'), \
                            encode(coalesce(refresh_token_sealed, ''::bytea), 'escape'), \
                            array_to_string(granted_scopes, ','), state, \
                            coalesce(last_error, '')]) \
         FROM agent_vault_connections WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the row");

    assert!(!columns.is_empty(), "the connection was stored");
    for value in columns.into_iter().flatten() {
        assert!(
            !value.contains(DOWNSTREAM_ACCESS),
            "the downstream access token is readable in a column: {value}"
        );
        assert!(
            !value.contains(DOWNSTREAM_REFRESH),
            "the downstream refresh token is readable in a column: {value}"
        );
    }
}

/// AC2, the other half: the seal OPENS for the scope that wrote it.
///
/// Without this the test above passes on a vault that stored nothing recoverable, which is
/// encryption at rest in the least useful sense.
#[tokio::test]
async fn the_stored_connection_opens_for_the_scope_that_wrote_it() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    store_connection(&db, &env, scope, &agent, "google").await;

    let opened = db
        .store()
        .scoped(scope)
        .agent_vault()
        .connection(&agent, "google")
        .await
        .expect("read the connection")
        .expect("a connection exists");
    assert_eq!(opened.access_token, DOWNSTREAM_ACCESS);
    assert_eq!(opened.refresh_token.as_deref(), Some(DOWNSTREAM_REFRESH));
    assert!(opened.is_usable(), "a freshly stored connection is usable");
}

/// AC1: per-agent scoping. One agent cannot be handed another's connection.
#[tokio::test]
async fn an_agent_cannot_read_another_agents_connection() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let first = seed_agent(&db, &env, scope).await;
    let second = seed_agent(&db, &env, scope).await;
    store_connection(&db, &env, scope, &first, "google").await;

    let theirs = db
        .store()
        .scoped(scope)
        .agent_vault()
        .connection(&second, "google")
        .await
        .expect("read");
    assert!(
        theirs.is_none(),
        "the second agent must not see the first agent's connection"
    );
}

/// AC3: one failing connection isolates. Marking Google failed leaves GitHub usable, and the
/// failed one stays readable so an operator can see WHICH broke and why.
#[tokio::test]
async fn a_failed_connection_isolates_and_stays_visible() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let google = store_connection(&db, &env, scope, &agent, "google").await;
    store_connection(&db, &env, scope, &agent, "github").await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault()
        .mark_failed(&env, &google, "refresh rejected upstream", now_micros(&env))
        .await
        .expect("mark failed");

    let broken = db
        .store()
        .scoped(scope)
        .agent_vault()
        .connection(&agent, "google")
        .await
        .expect("read")
        .expect("the failed connection is still readable, not deleted");
    assert!(!broken.is_usable(), "the failed connection is not usable");

    let other = db
        .store()
        .scoped(scope)
        .agent_vault()
        .connection(&agent, "github")
        .await
        .expect("read")
        .expect("the other connection exists");
    assert!(
        other.is_usable(),
        "one failing downstream must not disable the agent's other connections"
    );
}

/// Re-establishing a connection returns it to active, so an operator's repair takes effect.
#[tokio::test]
async fn re_storing_a_failed_connection_repairs_it() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let google = store_connection(&db, &env, scope, &agent, "google").await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault()
        .mark_failed(&env, &google, "refresh rejected upstream", now_micros(&env))
        .await
        .expect("mark failed");
    store_connection(&db, &env, scope, &agent, "google").await;

    let repaired = db
        .store()
        .scoped(scope)
        .agent_vault()
        .connection(&agent, "google")
        .await
        .expect("read")
        .expect("exists");
    assert!(
        repaired.is_usable(),
        "re-establishing a connection is how a failed one is repaired"
    );
}
