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
    NewVaultApproval, NewVaultConnection, OrganizationId, Scope, UserId, VaultApproval,
};

/// A downstream access token that is unmistakable if it ever appears in a column.
const DOWNSTREAM_ACCESS: &str = "ya29.PLAINTEXT-GOOGLE-ACCESS-TOKEN-do-not-persist";
/// And its refresh token, sealed under a DIFFERENT purpose than the access token.
const DOWNSTREAM_REFRESH: &str = "1//PLAINTEXT-GOOGLE-REFRESH-TOKEN-do-not-persist";
/// And the DOWNSTREAM CLIENT SECRET, the third secret this row holds.
const DOWNSTREAM_CLIENT_SECRET: &str = "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ot-persist";

/// The digest of the action these approvals are raised for.
///
/// An approval is keyed on (agent, provider, ACTION) so that approving one action does not
/// authorize every other action at that provider. These tests exercise the row's own
/// behaviour rather than the digest function, so one fixed well-shaped digest is enough --
/// the column's CHECK requires 64 lowercase hex characters.
const TEST_DIGEST: &str = "\
1111111111111111111111111111111111111111111111111111111111111111";

/// A materially DIFFERENT action, for the tests that prove one approval does not cover another.
const OTHER_DIGEST: &str = "\
2222222222222222222222222222222222222222222222222222222222222222";

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
    seed_agent_in_org(db, env, scope).await.0
}

/// The same, handing back the ORGANIZATION it was registered in.
///
/// The queue reads one organization's approvals, so a test that means to prove the filter has
/// to be able to name two organizations and put an agent in each.
async fn seed_agent_in_org(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
) -> (AgentPrincipalId, OrganizationId) {
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
    (agent, organization)
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
                requires_approval: Some(false),
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
            NewVaultApproval {
                id: &id,
                agent_id: &agent,
                provider: "google",
                requested_details: &requested_details(),
                action_digest: TEST_DIGEST,
                expires_at_unix_micros: now + 60_000_000,
            },
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
            NewVaultApproval {
                id: &id,
                agent_id: &agent,
                provider: "google",
                requested_details: &requested_details(),
                action_digest: TEST_DIGEST,
                expires_at_unix_micros: now + 60_000_000,
            },
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
            NewVaultApproval {
                id: &id,
                agent_id: &agent,
                provider: "google",
                requested_details: &requested_details(),
                action_digest: TEST_DIGEST,
                expires_at_unix_micros: now + 60_000_000,
            },
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
        .request(
            &env,
            NewVaultApproval {
                id: &id,
                agent_id: &agent,
                provider: "google",
                requested_details: &requested_details(),
                action_digest: TEST_DIGEST,
                expires_at_unix_micros: now + 1,
            },
        )
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
        requested_details: requested_details(),
        action_digest: TEST_DIGEST.to_owned(),
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
            NewVaultApproval {
                id: &id,
                agent_id: &agent,
                provider: "google",
                requested_details: &requested_details(),
                action_digest: TEST_DIGEST,
                expires_at_unix_micros: now + 60_000_000,
            },
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

/// A connection's REFRESH CONFIGURATION round-trips, and the ordinary read says it exists
/// without opening the client secret (issue #132, criterion 3).
///
/// The test that would have caught the blocker immediately. The refresh path guarded on
/// `connection.refresh.is_some()`, which the ordinary read never populates, so the whole
/// branch was dead code and an expired connection fell through to a 409 forever. `can_refresh`
/// is the field that answers "is a refresh possible" and it must be true on the read that does
/// NOT open the secret -- otherwise the caller deciding whether to refresh decides no, always.
#[tokio::test]
async fn the_ordinary_read_knows_a_refresh_is_possible_without_opening_the_client_secret() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;

    let id = AgentVaultConnectionId::generate(&env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault(scope)
        .store_connection(
            &env,
            NewVaultConnection {
                id: &id,
                agent_id: &agent,
                provider: "google",
                access_token: DOWNSTREAM_ACCESS,
                refresh_token: Some(DOWNSTREAM_REFRESH),
                granted_scopes: &["mail.read".to_owned()],
                expires_at_unix_micros: None,
                requires_approval: Some(false),
                refresh: Some(ironauth_store::VaultRefreshConfig {
                    token_endpoint: "https://oauth2.example.test/token",
                    client_id: "downstream-client",
                    client_secret: DOWNSTREAM_CLIENT_SECRET,
                }),
            },
            now_micros(&env),
        )
        .await
        .expect("store a refreshable connection");

    let plain = db
        .store()
        .scoped(scope)
        .agent_vault()
        .connection(&agent, "google")
        .await
        .expect("read")
        .expect("a connection exists");
    assert!(
        plain.can_refresh,
        "the ordinary read must know a refresh is POSSIBLE, or the refresh path is unreachable"
    );
    assert!(
        plain.refresh.is_none(),
        "and it must not have opened the client secret to answer that"
    );

    let opened = db
        .store()
        .scoped(scope)
        .agent_vault()
        .connection_with_refresh(&agent, "google")
        .await
        .expect("read")
        .expect("a connection exists");
    let config = opened
        .refresh
        .expect("the explicit read opens the configuration");
    assert_eq!(config.token_endpoint, "https://oauth2.example.test/token");
    assert_eq!(config.client_id, "downstream-client");
    assert_eq!(
        config.client_secret, DOWNSTREAM_CLIENT_SECRET,
        "the client secret round-trips through its own purpose tag"
    );
}

/// The client secret is sealed under its OWN associated data.
///
/// Three secrets now share one row and one key. A ciphertext moved between any two of the
/// three columns must fail to open rather than open as the other thing, and the only way to
/// observe that is to move one.
#[tokio::test]
async fn a_client_secret_does_not_open_as_an_access_token_or_the_reverse() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;

    let id = AgentVaultConnectionId::generate(&env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault(scope)
        .store_connection(
            &env,
            NewVaultConnection {
                id: &id,
                agent_id: &agent,
                provider: "google",
                access_token: DOWNSTREAM_ACCESS,
                refresh_token: Some(DOWNSTREAM_REFRESH),
                granted_scopes: &["mail.read".to_owned()],
                expires_at_unix_micros: None,
                requires_approval: Some(false),
                refresh: Some(ironauth_store::VaultRefreshConfig {
                    token_endpoint: "https://oauth2.example.test/token",
                    client_id: "downstream-client",
                    client_secret: DOWNSTREAM_CLIENT_SECRET,
                }),
            },
            now_micros(&env),
        )
        .await
        .expect("store");

    // It opens before anything is moved. Without this the assertion below could pass because
    // NOTHING opens, which would make the test vacuous.
    assert!(
        db.store()
            .scoped(scope)
            .agent_vault()
            .connection_with_refresh(&agent, "google")
            .await
            .expect("read")
            .is_some(),
        "the connection opens before the move"
    );

    // The CLIENT SECRET's ciphertext into the ACCESS TOKEN's column, as the owner.
    let secret_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT refresh_client_secret_sealed /* query-audit-allow: owner test read */ \
         FROM agent_vault_connections WHERE id = $1",
    )
    .bind(id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the sealed client secret");
    sqlx::query(
        "UPDATE agent_vault_connections /* query-audit-allow: owner test write */ \
         SET access_token_sealed = $1 WHERE id = $2",
    )
    .bind(&secret_bytes)
    .bind(id.to_string())
    .execute(db.owner_pool())
    .await
    .expect("move the ciphertext");

    assert!(
        matches!(
            db.store()
                .scoped(scope)
                .agent_vault()
                .connection(&agent, "google")
                .await,
            Err(ironauth_store::StoreError::Encryption)
        ),
        "a client secret must not open as an access token"
    );
}

/// Raise one approval, handing back whatever the store said.
///
/// A free function rather than a closure because these tests call it after taking a borrow of
/// the database, and the failing call is the POINT of one of them: the caller must be able to
/// distinguish "lost the race" from any other error.
async fn raise(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    control: &ironauth_store::ScopedStore<'_>,
    agent: &AgentPrincipalId,
    id: AgentVaultApprovalId,
    digest: &str,
    now: i64,
) -> Result<(), ironauth_store::StoreError> {
    control
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .agent_vault_approvals()
        .request(
            env,
            NewVaultApproval {
                id: &id,
                agent_id: agent,
                provider: "google",
                requested_details: &requested_details(),
                action_digest: digest,
                expires_at_unix_micros: now + 60_000_000,
            },
        )
        .await
}

/// An approval is found for the action it names and no other (issue #132, criterion 4).
///
/// The store half of the F4 defect. `latest_for` was keyed on (agent, provider), so the row
/// raised for one action was returned for every other action at that provider, and the caller
/// -- correctly, given what it was handed -- issued. Nothing about the exchange could fix that
/// while the read itself could not tell two actions apart.
#[tokio::test]
async fn an_approval_is_found_only_for_the_action_it_names() {
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
            NewVaultApproval {
                id: &id,
                agent_id: &agent,
                provider: "google",
                requested_details: &requested_details(),
                action_digest: TEST_DIGEST,
                expires_at_unix_micros: now + 60_000_000,
            },
        )
        .await
        .expect("raise");

    let approvals = db.store().scoped(scope);
    let approvals = approvals.agent_vault_approvals();
    assert_eq!(
        approvals
            .latest_for(&agent, "google", TEST_DIGEST)
            .await
            .expect("read")
            .map(|a| a.id),
        Some(id),
        "the control: the action it was raised for finds it"
    );
    assert!(
        approvals
            .latest_for(&agent, "google", OTHER_DIGEST)
            .await
            .expect("read")
            .is_none(),
        "a DIFFERENT action finds nothing, so approving one action does not authorize another"
    );
    assert!(
        approvals
            .latest_for(&agent, "github", TEST_DIGEST)
            .await
            .expect("read")
            .is_none(),
        "and the provider still separates them"
    );
}

/// Two concurrent requests for one action leave ONE pending row, and the loser can read it.
///
/// Both racers read "no approval" and both insert. Without the unique index the exchange then
/// polls the newer row, so an approver who answers the older one has decided something nothing
/// reads and the agent waits forever for a decision that already happened.
#[tokio::test]
async fn only_one_pending_approval_exists_per_action_and_a_decided_one_may_be_reraised() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let now = now_micros(&env);
    let control = db.control_store().scoped(scope);

    let first = AgentVaultApprovalId::generate(&env, &scope);
    raise(&db, &env, &control, &agent, first, TEST_DIGEST, now)
        .await
        .expect("the first request wins");

    let second = AgentVaultApprovalId::generate(&env, &scope);
    assert!(
        matches!(
            raise(&db, &env, &control, &agent, second, TEST_DIGEST, now).await,
            Err(ironauth_store::StoreError::Conflict)
        ),
        "a second pending request for the SAME action loses, and says so distinctly enough \
         for the caller to re-read the winner"
    );

    // A different action is unaffected: the index is per-action, not a lock on the provider.
    let other = AgentVaultApprovalId::generate(&env, &scope);
    raise(&db, &env, &control, &agent, other, OTHER_DIGEST, now)
        .await
        .expect("a different action raises its own request");

    // And once the first is DECIDED it stops occupying the slot, which is what the partial
    // predicate buys: an agent approved, expired, and asking again must be able to ask again.
    control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .decide(&env, &first, true, None, "operator", now + 1)
        .await
        .expect("decide the first");
    let again = AgentVaultApprovalId::generate(&env, &scope);
    raise(&db, &env, &control, &agent, again, TEST_DIGEST, now)
        .await
        .expect("the same action may be raised again once the previous one is decided");
}

/// The approver's queue lists what is still answerable, and nothing else.
#[tokio::test]
async fn the_queue_omits_decided_and_timed_out_requests() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let (agent, org) = seed_agent_in_org(&db, &env, scope).await;
    // A SECOND agent, in a DIFFERENT organization, whose request must not appear in this
    // organization's queue. The filter moved into SQL when the route stopped resolving each
    // agent's organization one query at a time, and a filter is only as good as the case that
    // proves it excludes something.
    let (stranger, _other_org) = seed_agent_in_org(&db, &env, scope).await;
    let now = now_micros(&env);
    let control = db.control_store().scoped(scope);

    let live = AgentVaultApprovalId::generate(&env, &scope);
    let decided = AgentVaultApprovalId::generate(&env, &scope);
    let stale = AgentVaultApprovalId::generate(&env, &scope);
    for (id, digest, expires) in [
        (live, TEST_DIGEST, now + 60_000_000),
        (decided, OTHER_DIGEST, now + 60_000_000),
        (
            stale,
            "3333333333333333333333333333333333333333333333333333333333333333",
            now + 1,
        ),
    ] {
        control
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .agent_vault_approvals()
            .request(
                &env,
                NewVaultApproval {
                    id: &id,
                    agent_id: &agent,
                    provider: "google",
                    requested_details: &requested_details(),
                    action_digest: digest,
                    expires_at_unix_micros: expires,
                },
            )
            .await
            .expect("raise");
    }
    control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .decide(&env, &decided, true, None, "operator", now + 2)
        .await
        .expect("decide");

    // The stranger's request: pending, live, and in another organization.
    let elsewhere = AgentVaultApprovalId::generate(&env, &scope);
    control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .request(
            &env,
            NewVaultApproval {
                id: &elsewhere,
                agent_id: &stranger,
                provider: "google",
                requested_details: &requested_details(),
                action_digest: TEST_DIGEST,
                expires_at_unix_micros: now + 60_000_000,
            },
        )
        .await
        .expect("raise the stranger's request");

    let queue: Vec<_> = db
        .store()
        .scoped(scope)
        .agent_vault_approvals()
        .pending_for_organization(&org, now + 30_000_000, 50)
        .await
        .expect("list the queue")
        .into_iter()
        .map(|a| a.id)
        .collect();
    assert_eq!(
        queue,
        vec![live],
        "only the request that is still pending, still answerable, and in THIS organization \
         is queued"
    );
}

/// A decision is TERMINAL: the second one is refused, in both directions.
///
/// Not "a denial cannot be re-denied" but "a denial cannot be turned into an approval". The
/// gate reads the LATEST row for an action, so an approver -- or anything holding the write
/// role -- flipping a denial after the fact would hand over the credential the denial refused,
/// with the audit trail showing a decision that was already made.
#[tokio::test]
async fn a_decided_approval_cannot_be_decided_again() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let now = now_micros(&env);
    let control = db.control_store().scoped(scope);

    let id = AgentVaultApprovalId::generate(&env, &scope);
    raise(&db, &env, &control, &agent, id, TEST_DIGEST, now)
        .await
        .expect("raise");
    control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .decide(&env, &id, false, None, "operator", now + 1)
        .await
        .expect("the first decision lands");

    let flipped = control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .decide(
            &env,
            &id,
            true,
            Some(&requested_details()),
            "operator",
            now + 2,
        )
        .await;
    assert!(
        matches!(flipped, Err(ironauth_store::StoreError::NotFound)),
        "a denial must not be flipped to an approval by a second decision"
    );

    let after = db
        .store()
        .scoped(scope)
        .agent_vault_approvals()
        .get(&id)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(after.state, "denied", "and the row still says denied");
    assert!(
        after.approved_details.is_none(),
        "with nothing attached that a gate could hand over"
    );
    assert!(!after.authorizes(now + 3), "so the action is still refused");
}

/// Migration 0181's CHECKs refuse what the code is written never to send.
///
/// A constraint the application always satisfies is still worth a test, because the
/// application is not the only writer: a migration, an operator's psql session, or a future
/// handler all reach this table, and these three are the invariants the refresh path assumes
/// rather than verifies. Driven as the OWNER so the RLS policies are not what refuses them --
/// a test that cannot tell a CHECK from a policy proves neither.
#[tokio::test]
async fn the_refresh_configuration_constraints_refuse_a_partial_or_plaintext_endpoint() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let id = store_connection(&db, &env, scope, &agent, "google").await;

    // 1. HALF a configuration. The four travel together or a refresh fails at the provider
    //    rather than at the edge, which turns incomplete operator input into a downstream
    //    error nobody can act on.
    let partial = sqlx::query(
        "UPDATE agent_vault_connections /* query-audit-allow: owner constraint probe */ \
         SET refresh_token_endpoint = 'https://oauth2.example.test/token' WHERE id = $1",
    )
    .bind(id.to_string())
    .execute(db.owner_pool())
    .await;
    assert!(
        partial.is_err(),
        "a refresh configuration missing its client credentials was accepted"
    );

    // 2. A PLAINTEXT endpoint. This URL is dereferenced with a refresh token in the body.
    let plaintext = sqlx::query(
        "UPDATE agent_vault_connections /* query-audit-allow: owner constraint probe */ \
         SET refresh_token_endpoint = 'http://oauth2.example.test/token', \
             refresh_client_id = 'downstream-client', \
             refresh_client_secret_sealed = '\\x00'::bytea, \
             refresh_client_secret_dek_version = 1 \
         WHERE id = $1",
    )
    .bind(id.to_string())
    .execute(db.owner_pool())
    .await;
    assert!(
        plaintext.is_err(),
        "a plaintext token endpoint would put the refresh token on the wire"
    );

    // 3. The control: the COMPLETE https configuration is accepted, so the two refusals above
    //    are the constraints doing their job rather than the row being unwritable.
    sqlx::query(
        "UPDATE agent_vault_connections /* query-audit-allow: owner constraint probe */ \
         SET refresh_token_endpoint = 'https://oauth2.example.test/token', \
             refresh_client_id = 'downstream-client', \
             refresh_client_secret_sealed = '\\x00'::bytea, \
             refresh_client_secret_dek_version = 1 \
         WHERE id = $1",
    )
    .bind(id.to_string())
    .execute(db.owner_pool())
    .await
    .expect("a complete https configuration is accepted");
}

/// An action digest is 64 hex characters or the empty string, and nothing else.
///
/// The empty string is the ROLLOUT value: the column is NOT NULL with a `''` default so an old
/// binary mid-deploy can still raise an approval, and an empty digest matches no lookup, so
/// such a row is invisible to the gate rather than a pass for every action.
#[tokio::test]
async fn an_action_digest_is_a_digest_or_the_rollout_default() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let now = now_micros(&env);
    let control = db.control_store().scoped(scope);
    let id = AgentVaultApprovalId::generate(&env, &scope);
    raise(&db, &env, &control, &agent, id, TEST_DIGEST, now)
        .await
        .expect("raise");

    for bad in [
        "not-a-digest",
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
        "0123",
    ] {
        let refused = sqlx::query(
            "UPDATE agent_vault_approvals /* query-audit-allow: owner constraint probe */ \
             SET action_digest = $1 WHERE id = $2",
        )
        .bind(bad)
        .bind(id.to_string())
        .execute(db.owner_pool())
        .await;
        assert!(
            refused.is_err(),
            "the shape check accepted {bad:?}, so a digest column can hold something no \
             lookup will ever match"
        );
    }

    // The control, and the rollout value.
    for allowed in [OTHER_DIGEST, ""] {
        sqlx::query(
            "UPDATE agent_vault_approvals /* query-audit-allow: owner constraint probe */ \
             SET action_digest = $1 WHERE id = $2",
        )
        .bind(allowed)
        .bind(id.to_string())
        .execute(db.owner_pool())
        .await
        .expect("a well-shaped digest and the rollout default are both accepted");
    }
}

/// The queue's bound is a bound (issue #132).
///
/// A separate test from the exclusions above because it needs a queue with MORE in it than the
/// limit: bounding a one-row queue at one passes against a `LIMIT` that was never written,
/// which is the shape of a cap test that proves nothing.
#[tokio::test]
async fn the_queue_returns_no_more_than_the_limit_and_keeps_the_oldest() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let (agent, org) = seed_agent_in_org(&db, &env, scope).await;
    let now = now_micros(&env);
    let control = db.control_store().scoped(scope);

    let live = AgentVaultApprovalId::generate(&env, &scope);
    raise(&db, &env, &control, &agent, live, TEST_DIGEST, now)
        .await
        .expect("raise the older request");

    let second_live = AgentVaultApprovalId::generate(&env, &scope);
    control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .request(
            &env,
            NewVaultApproval {
                id: &second_live,
                agent_id: &agent,
                provider: "github",
                requested_details: &requested_details(),
                action_digest: TEST_DIGEST,
                expires_at_unix_micros: now + 60_000_000,
            },
        )
        .await
        .expect("raise a second live request");
    assert_eq!(
        db.store()
            .scoped(scope)
            .agent_vault_approvals()
            .pending_for_organization(&org, now + 30_000_000, 50)
            .await
            .expect("list")
            .len(),
        2,
        "the control: unbounded, this organization has two waiting"
    );

    let bounded = db
        .store()
        .scoped(scope)
        .agent_vault_approvals()
        .pending_for_organization(&org, now + 30_000_000, 1)
        .await
        .expect("list the queue");
    assert_eq!(bounded.len(), 1, "the limit bounds the answer");
    assert_eq!(
        bounded[0].id, live,
        "and it keeps the OLDEST, because an approver works a queue from the front"
    );
}

/// Replacing an expired access token does NOT turn the approval gate off (issue #132).
///
/// The operator's commonest write on this route is "the downstream token expired, here is a
/// new one": provider, access token, scopes. Under replace-semantics that silently made a
/// sensitive connection ordinary, and the flag was write-only, so nothing showed them. The
/// write now reports what the row ENDED UP being rather than what was sent.
#[tokio::test]
async fn a_re_store_that_omits_the_flag_keeps_a_sensitive_connection_sensitive() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let acting = || {
        db.control_store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
    };

    let id = AgentVaultConnectionId::generate(&env, &scope);
    let sensitive = acting()
        .agent_vault()
        .store_connection(
            &env,
            NewVaultConnection {
                id: &id,
                agent_id: &agent,
                provider: "google",
                access_token: DOWNSTREAM_ACCESS,
                refresh_token: Some(DOWNSTREAM_REFRESH),
                granted_scopes: &["mail.read".to_owned()],
                expires_at_unix_micros: None,
                requires_approval: Some(true),
                refresh: None,
            },
            now_micros(&env),
        )
        .await
        .expect("store a sensitive connection");
    assert!(
        sensitive.requires_approval,
        "the control: it was stored sensitive"
    );

    // The ordinary repair: a fresh access token, nothing said about sensitivity.
    let replacement = AgentVaultConnectionId::generate(&env, &scope);
    let after = acting()
        .agent_vault()
        .store_connection(
            &env,
            NewVaultConnection {
                id: &replacement,
                agent_id: &agent,
                provider: "google",
                access_token: "ya29.A-REPLACEMENT-ACCESS-TOKEN",
                refresh_token: None,
                granted_scopes: &["mail.read".to_owned()],
                expires_at_unix_micros: None,
                requires_approval: None,
                refresh: None,
            },
            now_micros(&env),
        )
        .await
        .expect("re-store");
    assert_eq!(
        after.id, id,
        "the row keeps the id it was created with, so the caller's fresh id addresses nothing"
    );
    assert!(
        after.requires_approval,
        "omitting the flag left the gate ON, and the write says so"
    );
    assert!(
        db.store()
            .scoped(scope)
            .agent_vault()
            .connection(&agent, "google")
            .await
            .expect("read")
            .expect("exists")
            .requires_approval,
        "and the row itself agrees"
    );

    // And `false` still means false: a preserving default that could not be overridden would
    // make a sensitive connection permanent, which is the opposite failure.
    let ordinary = acting()
        .agent_vault()
        .store_connection(
            &env,
            NewVaultConnection {
                id: &AgentVaultConnectionId::generate(&env, &scope),
                agent_id: &agent,
                provider: "google",
                access_token: DOWNSTREAM_ACCESS,
                refresh_token: None,
                granted_scopes: &["mail.read".to_owned()],
                expires_at_unix_micros: None,
                requires_approval: Some(false),
                refresh: None,
            },
            now_micros(&env),
        )
        .await
        .expect("re-store as ordinary");
    assert!(
        !ordinary.requires_approval,
        "an explicit false still turns the gate off"
    );
}

/// A refreshed credential is written by the DATA plane, which holds UPDATE and not INSERT.
///
/// The claim the fix rests on, and nothing checked it: the first version re-stored through
/// `management()` on the data-plane pool, which is the same low-privilege pool, so the upsert
/// was refused by Postgres at the moment a refresh succeeded -- the worst possible time,
/// because the provider had already rotated the token.
#[tokio::test]
async fn the_data_plane_can_write_a_refreshed_credential_and_cannot_insert_a_new_one() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let id = store_connection(&db, &env, scope, &agent, "google").await;

    // The UPDATE, as the data plane. This is the write the token door performs.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault()
        .refresh_stored_credential(
            &env,
            ironauth_store::RefreshedCredentialWrite {
                id: &id,
                agent_id: &agent,
                provider: "google",
                access_token: "ya29.A-FRESH-ACCESS-TOKEN",
                refresh_token: Some("1//A-ROTATED-REFRESH-TOKEN"),
                expires_at_unix_micros: None,
            },
            now_micros(&env),
        )
        .await
        .expect("the data plane may replace a refreshed credential");

    // `connection_with_refresh`, not `connection`. The plain reader deliberately does NOT
    // open the refresh token -- its own doc says so -- so it answers `None` for that field
    // whatever the row holds, and the assertion below was unsatisfiable against it. It read
    // as a grant or an encryption failure; it was the wrong reader, and it shipped red.
    let after = db
        .store()
        .scoped(scope)
        .agent_vault()
        .connection_with_refresh(&agent, "google")
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(after.access_token, "ya29.A-FRESH-ACCESS-TOKEN");
    assert_eq!(
        after.refresh_token.as_deref(),
        Some("1//A-ROTATED-REFRESH-TOKEN"),
        "the rotated refresh token replaced the stored one"
    );
    // And the PLAIN reader still hides it, so the line above is reading the with-refresh
    // variant on purpose rather than by accident.
    let hidden = db
        .store()
        .scoped(scope)
        .agent_vault()
        .connection(&agent, "google")
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(
        hidden.refresh_token, None,
        "the plain reader must not open the refresh token"
    );

    // And the INSERT it does not hold. Without this the assertion above would be satisfied by
    // a data plane that could do anything, and the plane separation would be untested.
    let mut tx = db.app_pool().begin().await.expect("app transaction");
    for (key, value) in [
        ("ironauth.tenant_id", scope.tenant().to_string()),
        ("ironauth.environment_id", scope.environment().to_string()),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(key)
            .bind(&value)
            .execute(&mut *tx)
            .await
            .expect("bind the scope");
    }
    let refused = sqlx::query(
        "INSERT INTO agent_vault_connections \
         (id, tenant_id, environment_id, agent_id, provider, access_token_sealed, \
          access_token_dek_version, granted_scopes, state) \
         VALUES ($1, $2, $3, $4, 'github', '\\x00'::bytea, 1, ARRAY[]::text[], 'active')",
    )
    .bind(AgentVaultConnectionId::generate(&env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(agent.to_string())
    .execute(&mut *tx)
    .await;
    assert!(
        refused.is_err(),
        "the data plane must not be able to create a connection"
    );
}

/// The data plane may SPEND an approval and may do nothing else to one (issue #132).
///
/// Found by review before it ran anywhere: spending happens at the TOKEN DOOR, which runs on
/// the data-plane role, and 0179 deliberately withheld UPDATE from that role. So the consume
/// would have been refused by Postgres at the last step of every approved sensitive exchange,
/// AFTER the human said yes. The grant that fixes it is exactly what 0179 withheld, so it is
/// paired with a policy admitting one transition, and this test is what proves the pairing is
/// not just the grant.
#[tokio::test]
async fn the_data_plane_may_spend_an_approval_and_may_not_grant_itself_one() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let agent = seed_agent(&db, &env, scope).await;
    let now = now_micros(&env);
    let control = db.control_store().scoped(scope);

    // An approval a human APPROVED, narrowed. Narrowed on purpose: consuming a row that
    // carries `approved_details` is what the details-only-when-approved CHECK refused, so a
    // test that approved without narrowing would pass against the unrelaxed constraint.
    let id = AgentVaultApprovalId::generate(&env, &scope);
    raise(&db, &env, &control, &agent, id, TEST_DIGEST, now)
        .await
        .expect("raise");
    control
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .decide(
            &env,
            &id,
            true,
            Some(&requested_details()),
            "operator",
            now + 1,
        )
        .await
        .expect("approve it, narrowed");

    // THE DATA PLANE spends it. This is the write the token door performs.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .agent_vault_approvals()
        .consume(&env, &id, now + 2)
        .await
        .expect("the data plane may spend an approval a human granted");

    let spent = db
        .store()
        .scoped(scope)
        .agent_vault_approvals()
        .get(&id)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(spent.state, "consumed");
    assert!(
        !spent.authorizes(now + 3),
        "and a spent approval authorizes nothing further"
    );
    assert!(
        spent.approved_details.is_some(),
        "while keeping what the human agreed to, which is the evidence"
    );

    // Spending it AGAIN finds nothing to spend, so two concurrent exchanges cannot both issue.
    assert!(
        matches!(
            db.store()
                .scoped(scope)
                .acting(db.test_actor(&env), CorrelationId::generate(&env))
                .agent_vault_approvals()
                .consume(&env, &id, now + 4)
                .await,
            Err(ironauth_store::StoreError::NotFound)
        ),
        "an approval is spent once"
    );

    // AND THE TRANSITION IT MAY NOT MAKE. Without this the grant above would have handed the
    // data plane back exactly what 0179 withheld: the ability to approve its own action.
    let pending = AgentVaultApprovalId::generate(&env, &scope);
    raise(&db, &env, &control, &agent, pending, OTHER_DIGEST, now)
        .await
        .expect("raise a second, undecided");

    let mut tx = db.app_pool().begin().await.expect("app transaction");
    for (key, value) in [
        ("ironauth.tenant_id", scope.tenant().to_string()),
        ("ironauth.environment_id", scope.environment().to_string()),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(key)
            .bind(&value)
            .execute(&mut *tx)
            .await
            .expect("bind the scope");
    }
    let self_approved = sqlx::query(
        "UPDATE agent_vault_approvals \
         SET state = 'approved', decided_at = now(), decided_by = 'self' WHERE id = $1",
    )
    .bind(pending.to_string())
    .execute(&mut *tx)
    .await;
    assert!(
        self_approved.is_err() || self_approved.expect("checked").rows_affected() == 0,
        "the data plane must not be able to approve a pending action"
    );

    // Nor un-spend one, which would make a single decision reusable.
    let reopened = sqlx::query("UPDATE agent_vault_approvals SET state = 'approved' WHERE id = $1")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await;
    assert!(
        reopened.is_err() || reopened.expect("checked").rows_affected() == 0,
        "the data plane must not be able to re-open a spent approval"
    );
}
