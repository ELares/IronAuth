// SPDX-License-Identifier: MIT OR Apache-2.0

//! The agent token vault (issue #132).
//!
//! # What these tests cover, stated so the labels below are not read as more than they are
//!
//! The `AC4` labels name the predicate `VaultApproval::authorizes`, which is what an approval
//! DECIDES. They do not establish that anything CONSULTS it: no exchange path calls it, and
//! criterion 4's blocking half is not implemented. That is stated in the PR and it is stated
//! here, because a test file is where somebody will look for what is covered.
//!
//! The `AC5` label is narrower still. It shows the row is durable across a fresh store handle
//! over the same database, which is a property of reading from Postgres with no cache rather
//! than of surviving a delivery worker. There is no delivery worker, no IronBus integration,
//! and no notification of any kind: nothing tells a human an approval is pending.
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
    AgentPrincipalId, AgentVaultApprovalId, AgentVaultConnectionId, CorrelationId, NewAgent,
    NewVaultConnection, OrganizationId, Scope, UserId, VaultApproval,
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
                refresh: None,
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
    //
    // EVERY column, resolved by the database rather than listed here. The list used to be
    // hand-written and named 10 of the 15 columns the migration declares, so "a column added
    // later to carry a hint or a label" -- the exact case the paragraph above says this
    // catches -- was the one case it could not catch. `to_jsonb(t)` expands the whole row and
    // `jsonb_each_text` yields one value per column, so a column added tomorrow is scanned
    // with no edit here.
    let columns: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT value FROM agent_vault_connections t, jsonb_each_text(to_jsonb(t)) \
         WHERE t.tenant_id = $1 AND t.environment_id = $2",
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
    assert!(
        opened.refresh_token.is_none(),
        "the ordinary read does not open the refresh token, because nothing reads one: a \
         refresh token outlives the access token it renews, so decrypting it into process \
         memory on every exchange in order to drop it is the wrong default"
    );
    assert!(
        opened.is_usable(now_micros(&env)),
        "a freshly stored connection is usable"
    );

    // And the explicit read DOES open it, so the round trip is still pinned. Without this the
    // assertion above would be satisfied by a seal that never stored the refresh token at all.
    let with_refresh = db
        .store()
        .scoped(scope)
        .agent_vault()
        .connection_with_refresh(&agent, "google")
        .await
        .expect("read the connection")
        .expect("a connection exists");
    assert_eq!(
        with_refresh.refresh_token.as_deref(),
        Some(DOWNSTREAM_REFRESH)
    );
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
    assert!(
        !broken.is_usable(now_micros(&env)),
        "the failed connection is not usable"
    );

    let other = db
        .store()
        .scoped(scope)
        .agent_vault()
        .connection(&agent, "github")
        .await
        .expect("read")
        .expect("the other connection exists");
    assert!(
        other.is_usable(now_micros(&env)),
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
        repaired.is_usable(now_micros(&env)),
        "re-establishing a connection is how a failed one is repaired"
    );
}

/// The RFC 9396 details a sensitive action asks for.
fn requested_details() -> serde_json::Value {
    serde_json::json!([{
        "type": "https://ironauth.test/agent-action",
        "actions": ["transfer"],
        "locations": ["https://api.example/accounts"],
    }])
}

/// AC4: a held action authorizes nothing until it is approved.
#[tokio::test]
async fn a_held_action_authorizes_nothing_while_it_is_pending() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let now = now_micros(&env);

    let id = AgentVaultApprovalId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .request(
            &env,
            &id,
            &agent,
            "google",
            &requested_details(),
            now + 60_000_000,
        )
        .await
        .expect("hold the action");

    let held = db
        .store()
        .scoped(scope)
        .agent_vault_approvals()
        .get(&id)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(held.state, "pending");
    assert!(
        !held.authorizes(now),
        "a pending action must authorize nothing"
    );
    assert!(
        held.approved_details.is_none(),
        "and must carry no approved details"
    );
}

/// AC4: an approval renders the details, and they are what the APPROVER agreed to.
///
/// The approver narrows the request here, and the narrowed set is what the row carries.
/// Asserting only that some details appeared would pass on an implementation that stored the
/// REQUEST back, which would make the approval surface decorative: an approver who cannot
/// narrow is acknowledging, not approving.
#[tokio::test]
async fn an_approval_renders_the_details_the_approver_agreed_to() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let now = now_micros(&env);

    let id = AgentVaultApprovalId::generate(&env, &scope);
    let control = db.control_store().scoped(scope);
    control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .request(
            &env,
            &id,
            &agent,
            "google",
            &requested_details(),
            now + 60_000_000,
        )
        .await
        .expect("hold");

    // NARROWED: read-only, where the request asked to transfer.
    let narrowed = serde_json::json!([{
        "type": "https://ironauth.test/agent-action",
        "actions": ["read"],
        "locations": ["https://api.example/accounts"],
    }]);
    control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .decide(&env, &id, true, Some(&narrowed), "opr_reviewer", now)
        .await
        .expect("approve");

    let decided = db
        .store()
        .scoped(scope)
        .agent_vault_approvals()
        .get(&id)
        .await
        .expect("read")
        .expect("exists");
    assert!(decided.authorizes(now), "an approved action authorizes");
    assert_eq!(
        decided.approved_details.as_ref(),
        Some(&narrowed),
        "the APPROVED details are the approver's, not the requester's"
    );
}

/// AC4: a denial authorizes nothing and renders no details.
#[tokio::test]
async fn a_denial_authorizes_nothing_and_renders_no_details() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let now = now_micros(&env);

    let id = AgentVaultApprovalId::generate(&env, &scope);
    let control = db.control_store().scoped(scope);
    control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .request(
            &env,
            &id,
            &agent,
            "google",
            &requested_details(),
            now + 60_000_000,
        )
        .await
        .expect("hold");
    control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .decide(
            &env,
            &id,
            false,
            Some(&requested_details()),
            "opr_reviewer",
            now,
        )
        .await
        .expect("deny");

    let decided = db
        .store()
        .scoped(scope)
        .agent_vault_approvals()
        .get(&id)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(decided.state, "denied");
    assert!(!decided.authorizes(now), "a denial authorizes nothing");
    assert!(
        decided.approved_details.is_none(),
        "and carries no details even though some were passed to the decision"
    );
}

/// AC4: a TIMEOUT authorizes nothing, and is final.
///
/// Both halves. An expired request must not authorize, and a slow approver must not be able
/// to resurrect it: if a decision after the deadline succeeded, the timeout would be a
/// suggestion rather than a refusal.
#[tokio::test]
async fn a_timed_out_action_authorizes_nothing_and_cannot_be_decided_late() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let now = now_micros(&env);

    let id = AgentVaultApprovalId::generate(&env, &scope);
    let control = db.control_store().scoped(scope);
    control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .request(&env, &id, &agent, "google", &requested_details(), now + 1)
        .await
        .expect("hold");

    let after = now + 60_000_000;
    let held = db
        .store()
        .scoped(scope)
        .agent_vault_approvals()
        .get(&id)
        .await
        .expect("read")
        .expect("exists");
    assert!(
        !held.authorizes(after),
        "a request past its deadline authorizes nothing, with no sweep having run"
    );
    // The deadline must be what refuses it, not the STATE. The row above is still `pending`,
    // so an `authorizes` that only checked the state would refuse it too and this assertion
    // would pass with the deadline check deleted. Approving it first makes the state say yes
    // and leaves the deadline as the only thing that can say no, which is what the first
    // mutation run of this file missed: it removed the deadline from `decide` and never
    // touched `authorizes`.
    let approved_but_stale = VaultApproval {
        id,
        agent_id: agent,
        provider: "google".to_owned(),
        state: "approved".to_owned(),
        approved_details: Some(requested_details()),
        expires_at_unix_micros: now + 1,
    };
    assert!(
        approved_but_stale.authorizes(now),
        "the control: before the deadline an approved action does authorize"
    );
    assert!(
        !approved_but_stale.authorizes(after),
        "an APPROVED action past its deadline authorizes nothing"
    );

    let late = control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .decide(
            &env,
            &id,
            true,
            Some(&requested_details()),
            "opr_slow",
            after,
        )
        .await;
    assert!(
        late.is_err(),
        "a decision after the deadline must be refused, or the timeout is a suggestion"
    );

    let unchanged = db
        .store()
        .scoped(scope)
        .agent_vault_approvals()
        .get(&id)
        .await
        .expect("read")
        .expect("exists");
    // The STATE, not `authorizes`. `authorizes(now)` is `state == "approved" && now < expiry`,
    // and `after` is past the expiry, so the deadline half is false whatever the state is:
    // the old assertion passed identically whether the late decision landed or was refused,
    // which is the one thing it was there to tell apart.
    assert_eq!(
        unchanged.state, "pending",
        "the late decision left the row untouched"
    );
    assert!(
        unchanged.approved_details.is_none(),
        "and agreed to nothing"
    );
}

/// A pending approval survives a fresh store handle over the same database.
///
/// Deliberately NOT labelled AC5. The criterion is "with IronBus enabled, pending approvals
/// survive a delivery worker restart", and there is no delivery worker to restart: `get()`
/// reads Postgres on every call with no cache, so this assertion is true by construction of
/// the read path. It is worth having as a regression pin on durability; it is not evidence
/// for the criterion, and labelling it AC5 claimed that it was.
///
/// Modelled the way the criterion means it: the row is durable, so a NEW store handle over
/// the same database sees the same pending request. Nothing is in flight to lose, which is
/// why this holds with or without a messaging backbone rather than because of one.
#[tokio::test]
async fn a_pending_approval_survives_a_restart_with_no_bus_configured() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let now = now_micros(&env);

    let id = AgentVaultApprovalId::generate(&env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .request(
            &env,
            &id,
            &agent,
            "google",
            &requested_details(),
            now + 60_000_000,
        )
        .await
        .expect("hold");

    // The harness's own restart primitive: a fresh connection over the same database as the
    // low-privilege app role, which is exactly what a restarted process gets. It exists
    // because this repo already proves the same shape for sessions, and the argument is
    // identical here: the authoritative state is in Postgres, so a restart loses nothing.
    let restarted = db.restart_app_store().await;
    let survived = restarted
        .scoped(scope)
        .agent_vault_approvals()
        .get(&id)
        .await
        .expect("read after restart")
        .expect("the pending approval is still there");
    assert_eq!(survived.state, "pending");
    assert!(!survived.authorizes(now), "and still authorizes nothing");
}

/// The seal's ASSOCIATED DATA binds the agent and the provider, not just the scope.
///
/// This test exists because the review pointed out that the PR's headline crypto fix could
/// not be checked by anything in the suite. `agent_vault_seal_aad` is called by BOTH the seal
/// and the open, so deleting a field from it changes the two symmetrically and every
/// round-trip test still passes. The binding is only observable by MOVING a ciphertext.
///
/// Two moves, because the AAD binds two things and a test that made only one of them would
/// leave the other in exactly the state that made this necessary:
///
///   - agent A's sealed bytes onto agent B's row. Without the agent in the AAD the DEK is
///     per-scope, so B opens A's live third-party credential.
///   - the `google` row's sealed bytes onto the `github` row of the SAME agent. Without the
///     provider in the AAD the open succeeds and the caller is handed a Google credential
///     labelled `github`, which it then presents to GitHub. Migration 0178 grants the
///     data-plane role `UPDATE` on this table with no column restriction, so this is a move a
///     single stray write performs.
///
/// Both are written as the OWNER, which is the point: the test is asking what the CRYPTO
/// guarantees when the row-level checks have already been bypassed.
#[tokio::test]
async fn a_sealed_credential_does_not_open_on_another_agents_or_another_providers_row() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;

    let agent_a = seed_agent(&db, &env, scope).await;
    let agent_b = seed_agent(&db, &env, scope).await;
    store_connection(&db, &env, scope, &agent_a, "google").await;
    store_connection(&db, &env, scope, &agent_b, "google").await;
    store_connection(&db, &env, scope, &agent_a, "github").await;

    // Both rows open normally first. Without this the assertions below could pass because
    // NOTHING opens, which would make the whole test vacuous.
    for (agent, provider) in [
        (&agent_a, "google"),
        (&agent_b, "google"),
        (&agent_a, "github"),
    ] {
        assert!(
            db.store()
                .scoped(scope)
                .agent_vault()
                .connection(agent, provider)
                .await
                .expect("read")
                .is_some(),
            "the {provider} connection for this agent opens before anything is moved"
        );
    }

    let sealed_a: Vec<u8> = sqlx::query_scalar(
        "SELECT access_token_sealed /* query-audit-allow: owner test read */ \
         FROM agent_vault_connections WHERE agent_id = $1 AND provider = 'google'",
    )
    .bind(agent_a.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read agent A's sealed access token");

    // MOVE ONE: onto another agent's row.
    sqlx::query(
        "UPDATE agent_vault_connections /* query-audit-allow: owner test write */ \
         SET access_token_sealed = $1 WHERE agent_id = $2 AND provider = 'google'",
    )
    .bind(&sealed_a)
    .bind(agent_b.to_string())
    .execute(db.owner_pool())
    .await
    .expect("move the ciphertext");

    assert!(
        matches!(
            db.store()
                .scoped(scope)
                .agent_vault()
                .connection(&agent_b, "google")
                .await,
            Err(ironauth_store::StoreError::Encryption)
        ),
        "agent B must not be able to open agent A's credential"
    );

    // MOVE TWO: onto the SAME agent's row for a different provider.
    sqlx::query(
        "UPDATE agent_vault_connections /* query-audit-allow: owner test write */ \
         SET access_token_sealed = $1 WHERE agent_id = $2 AND provider = 'github'",
    )
    .bind(&sealed_a)
    .bind(agent_a.to_string())
    .execute(db.owner_pool())
    .await
    .expect("move the ciphertext");

    assert!(
        matches!(
            db.store()
                .scoped(scope)
                .agent_vault()
                .connection(&agent_a, "github")
                .await,
            Err(ironauth_store::StoreError::Encryption)
        ),
        "a credential sealed for one provider must not open as another provider's"
    );
}

/// The DATA PLANE may raise an approval and may not decide one (issue #132, criterion 4).
///
/// Migration 0179 states this as its reason for existing, and the first version of the policy
/// enforcing it did nothing at all: it was PERMISSIVE, and Postgres OR's permissive policies
/// for one command, so it was combined with the table's scope policy -- which has no `FOR` and
/// no `TO` clause, and whose `WITH CHECK` is the bare scope predicate an already-approved
/// INSERT satisfies. The narrowing admitted every row it was written to refuse.
///
/// A permissive/restrictive slip is invisible without a probe, which is exactly how it
/// shipped. This is the probe, modelled on the one migration 0100 carries for its identical
/// construction, including the anti-vacuity control: without a positive case a policy that
/// refused EVERYTHING would satisfy every negative below.
#[tokio::test]
async fn the_data_plane_may_raise_an_approval_and_may_not_decide_one() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();

    // As the APP role, with the scope bound the way the repository layer binds it.
    let mut tx = db.app_pool().begin().await.expect("app transaction");
    for (key, value) in [
        ("ironauth.tenant_id", &tenant),
        ("ironauth.environment_id", &environment),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(key)
            .bind(value)
            .execute(&mut *tx)
            .await
            .expect("bind the scope");
    }

    // 1. A PENDING row is writable. The anti-vacuity control: the data plane raising a request
    //    is the whole point of it holding INSERT, and a policy that refused this would be
    //    "secure" in the way a disconnected cable is.
    let pending = AgentVaultApprovalId::generate(&env, &scope);
    sqlx::query(
        "INSERT INTO agent_vault_approvals \
         (id, tenant_id, environment_id, agent_id, provider, requested_details, state, \
          expires_at) \
         VALUES ($1, $2, $3, $4, 'google', '{}'::jsonb, 'pending', now() + interval '1 hour')",
    )
    .bind(pending.to_string())
    .bind(&tenant)
    .bind(&environment)
    .bind(agent.to_string())
    .execute(&mut *tx)
    .await
    .expect("the data plane may raise a pending approval");

    // 2. An already-APPROVED row is refused. This is the attack: an agent approving its own
    //    sensitive action. Withholding UPDATE blocks deciding an EXISTING row and does nothing
    //    about inserting one that arrives decided, so before the RESTRICTIVE policy the only
    //    thing in the way was a hardcoded 'pending' literal in one Rust function.
    let approved = AgentVaultApprovalId::generate(&env, &scope);
    let refused = sqlx::query(
        "INSERT INTO agent_vault_approvals \
         (id, tenant_id, environment_id, agent_id, provider, requested_details, state, \
          decided_at, decided_by, approved_details, expires_at) \
         VALUES ($1, $2, $3, $4, 'google', '{}'::jsonb, 'approved', now(), 'self', \
                 '{\"everything\":true}'::jsonb, now() + interval '1 hour')",
    )
    .bind(approved.to_string())
    .bind(&tenant)
    .bind(&environment)
    .bind(agent.to_string())
    .execute(&mut *tx)
    .await;
    assert!(
        refused.is_err(),
        "the data plane must not insert an already-approved row"
    );
}
