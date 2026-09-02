// SPDX-License-Identifier: MIT OR Apache-2.0

//! Agent principals at the token doors (issue #130), over a real database
//! (`DATABASE_URL`).
//!
//! Covers the acceptance criteria the control plane could not: a token issued to an agent
//! carries the agent principal identity alongside the human and organization it acts for;
//! per-tool scope enforcement refuses a request outside the DECLARED set with an audited
//! denial; and a suspended or revoked agent obtains no token at all while staying listable.
//!
//! Adversarial: the refusal is measured on the AUDIT ROW as well as the status, because a
//! control that refuses without leaving evidence cannot be shown to have refused; a client
//! with no agent behind it is unaffected, so the gate cannot have been implemented by
//! breaking ordinary machine issuance; and the denial names EVERY undeclared tool rather
//! than the first.

mod common;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Harness, form, json, verify_clock};
use ironauth_jose::verify;
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::{AgentPrincipalId, ClientId};

/// A standard-padded Basic credential of `client_id:client_secret`.
fn basic_header(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// The `grant_type=client_credentials` form body (plus an optional `scope`).
fn cc_form(scope: Option<&str>) -> String {
    match scope {
        Some(scope) => form(&[("grant_type", "client_credentials"), ("scope", scope)]),
        None => form(&[("grant_type", "client_credentials")]),
    }
}

/// Seed an organization, a user, and an agent bound to `client`, returning the agent id.
///
/// Seeded through the STORE rather than the management plane: this suite is about what the
/// token doors do with an agent that exists, and routing every fixture through a second
/// plane would make a management-side failure look like an issuance one.
/// What `seed_agent` created, so an assertion can name the EXACT ids rather than a shape.
struct SeededAgent {
    id: AgentPrincipalId,
    linked_user: String,
    organization: String,
}

async fn seed_agent(harness: &Harness, client: &ClientId, tool_scopes: &[&str]) -> SeededAgent {
    // Through the SHARED fixture. This file had its own copy of the same two INSERTs, and two
    // copies of a fixture drift: the newer one was written for a different suite and threw away
    // the linked user and organization this one asserts on.
    let (id, linked_user, organization) = harness.seed_agent_returning(client, tool_scopes).await;
    SeededAgent {
        id,
        linked_user,
        organization,
    }
}

/// Move a seeded agent to `state`, through the SHARED harness helper.
///
/// A thin wrapper rather than a second copy. This file had its own `set_state` doing a raw
/// `UPDATE agents SET state = $1`, and the harness had an identical one: two copies of the same
/// false "as the control plane would" comment, one file apart. The cascade test below was red
/// against both. One implementation now, in `common/mod.rs`, which is where the reasoning lives.
async fn set_state(harness: &Harness, id: &AgentPrincipalId, state: &str) {
    harness.set_agent_state(id, state).await;
}

/// Every audit action recorded in the harness scope, with its detail.
async fn audit_rows(harness: &Harness) -> Vec<(String, Option<String>)> {
    harness
        .store()
        .scoped(harness.scope())
        .audit()
        .list()
        .await
        .expect("read the audit trail")
        .into_iter()
        .map(|row| (row.action, row.detail))
        .collect()
}

/// AC3: a token issued to an agent carries the agent principal identity, and the human and
/// organization it acts for, so a downstream system can attribute the action to all three.
#[tokio::test]
async fn a_token_for_an_agent_carries_the_agent_its_user_and_its_organization() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let seeded = seed_agent(&harness, &client, &["deploy", "rollback"]).await;

    let (status, _headers, body) = harness
        .token_with_auth(
            &cc_form(Some("deploy")),
            Some(&basic_header(&client_id, &secret)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "agent issuance: {body}");

    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let verified = verify(
        &access,
        &harness.access_token_policy(&client_id),
        &verify_clock(),
    )
    .expect("at+jwt verifies");
    let claims = verified.claims();
    assert_eq!(
        claims.get("agent_id").and_then(serde_json::Value::as_str),
        Some(seeded.id.to_string().as_str()),
        "the token names the agent principal"
    );
    // The EXACT ids, not their prefixes. A prefix assertion passes for any user and any
    // organization in the scope, which is precisely the confusion this attribution exists to
    // rule out: a token naming the wrong human still starts with `usr_`.
    assert_eq!(
        claims
            .get("agent_linked_user")
            .and_then(serde_json::Value::as_str),
        Some(seeded.linked_user.as_str()),
        "the token names the human this agent acts for"
    );
    assert_eq!(
        claims
            .get("agent_organization")
            .and_then(serde_json::Value::as_str),
        Some(seeded.organization.as_str()),
        "and the organization it acts inside"
    );

    // AC2: the issuance is on the trail, in its own stream-separated action.
    let rows = audit_rows(&harness).await;
    assert!(
        rows.iter()
            .any(|(action, detail)| action == "agent_token.issue"
                && detail.as_deref() == Some("granted=deploy")),
        "the issuance is audited with what was granted: {rows:?}"
    );
}

/// AC3: a request naming a tool the agent never declared is refused, and the refusal is
/// AUDITED. The audit assertion is the point: a control that refuses without leaving
/// evidence cannot be shown to have refused.
#[tokio::test]
async fn a_tool_outside_the_declared_set_is_refused_with_an_audited_denial() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    seed_agent(&harness, &client, &["deploy"]).await;

    // Two undeclared tools, so the denial is measured for naming EVERY one rather than the
    // first: a caller told one at a time is sent round the loop once per tool.
    let (status, _headers, body) = harness
        .token_with_auth(
            &cc_form(Some("deploy delete_everything drop_database")),
            Some(&basic_header(&client_id, &secret)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "refusal: {body}");
    assert_eq!(json(&body)["error"], "invalid_scope");

    let rows = audit_rows(&harness).await;
    assert!(
        rows.iter()
            .any(|(action, detail)| action == "agent_token.deny"
                && detail.as_deref() == Some("reason=undeclared:delete_everything,drop_database")),
        "the denial names every undeclared tool: {rows:?}"
    );
    assert!(
        !rows.iter().any(|(action, _)| action == "agent_token.issue"),
        "and nothing was issued: {rows:?}"
    );
}

/// AC5: a suspended agent obtains no token, and the refusal says which state refused it.
#[tokio::test]
async fn a_suspended_agent_obtains_no_token() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let seeded = seed_agent(&harness, &client, &["deploy"]).await;

    set_state(&harness, &seeded.id, "suspended").await;

    let (status, _headers, body) = harness
        .token_with_auth(
            &cc_form(Some("deploy")),
            Some(&basic_header(&client_id, &secret)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "suspended: {body}");
    assert_eq!(json(&body)["error"], "unauthorized_client");

    let rows = audit_rows(&harness).await;
    assert!(
        rows.iter()
            .any(|(action, detail)| action == "agent_token.deny"
                && detail.as_deref() == Some("reason=suspended")),
        "the denial names the state that refused: {rows:?}"
    );
}

/// AC1: revocation blocks new issuance. The state is terminal, so this is the one that has
/// to hold even after the agent is left alone.
#[tokio::test]
async fn a_revoked_agent_obtains_no_token() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let seeded = seed_agent(&harness, &client, &["deploy"]).await;

    set_state(&harness, &seeded.id, "revoked").await;

    let (status, _headers, body) = harness
        .token_with_auth(
            &cc_form(Some("deploy")),
            Some(&basic_header(&client_id, &secret)),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "revoked: {body}");
    assert_eq!(json(&body)["error"], "unauthorized_client");
}

/// The CONTROL: a client with no agent behind it is untouched. Without this, the three
/// refusals above would also pass if the gate had simply broken machine issuance outright.
#[tokio::test]
async fn a_client_with_no_agent_still_issues_exactly_as_before() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();

    let (status, _headers, body) = harness
        .token_with_auth(
            &cc_form(Some("anything at all")),
            Some(&basic_header(&client_id, &secret)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "ordinary machine issuance: {body}");

    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let verified = verify(
        &access,
        &harness.access_token_policy(&client_id),
        &verify_clock(),
    )
    .expect("at+jwt verifies");
    assert!(
        verified.claims().get("agent_id").is_none(),
        "and carries no agent identity"
    );

    let rows = audit_rows(&harness).await;
    assert!(
        !rows
            .iter()
            .any(|(action, _)| action.starts_with("agent_token.")),
        "and writes no agent audit row: {rows:?}"
    );
}

/// The revocation SLO is DOCUMENTED, and the document agrees with the code (issue #130,
/// criterion 1).
///
/// The criterion says outstanding tokens die "within the documented SLO", and there was no
/// document: no `docs/agents.md`, and `grep -i slo docs/` matched nothing but the words "slow"
/// and "slot". A window nobody wrote down is not one an operator can hold anybody to.
///
/// This pins the SENTENCE and the NUMBER separately, the same way
/// `session_tokenizer.rs` pins its own window, because a table of numbers does not state the
/// window as a function of the configured TTL and a sentence alone does not say what the
/// default is. The number is read from the CONFIG DEFAULT rather than typed here twice, so a
/// change to the default fails this test rather than quietly making the doc wrong.
///
/// Needs no database: it reads a committed file and a config default.
#[test]
fn the_revocation_window_is_documented_and_matches_the_configured_default() {
    const DOC: &str = include_str!("../../../docs/agents.md");

    assert!(
        DOC.contains(
            "**The revocation window is exactly `oidc.access_token_ttl_secs`, and only for a \
             resource\n> server that does not introspect.**"
        ),
        "the doc must state the window as a function of the configured TTL, not as a bare number"
    );

    let default_ttl = ironauth_config::Config::default()
        .oidc
        .access_token_ttl_secs;
    assert!(
        DOC.contains(&format!(
            "| Default `access_token_ttl_secs` | {default_ttl} |"
        )),
        "the doc's table must carry the CONFIGURED default ({default_ttl}), or it teaches a \
         number the deployment does not use"
    );
    assert!(
        DOC.contains(&format!(
            "| Worst-case window, non-introspecting resource server | {default_ttl} |"
        )),
        "and the window row must equal it, since the window IS the token lifetime"
    );
    assert!(
        DOC.contains("| Worst-case window, introspecting resource server | 0 |"),
        "the introspecting case is zero, which is the half revoking the grants delivers"
    );

    // THE PROSE, not just the table. A review proved this gap by rewriting the sentence to say
    // "a NINETY-minute worst case" and watching the test stay green: the number was derived
    // and the sentence beside it was hand-written, which is the drift a table-only assertion
    // cannot see. The prose now states the SAME derived number.
    assert!(
        DOC.contains(&format!(
            "`access_token_ttl_secs: {default_ttl}` that is a {default_ttl}-second worst case"
        )),
        "the sentence beside the table must state the same number the table does, in the \
         same units, or a reader is taught one window and shown another"
    );

    // The two halves of what revocation does, both stated. Without the second sentence the doc
    // describes the behaviour this PR fixed rather than the behaviour it now has.
    assert!(
        DOC.contains("New issuance stops immediately."),
        "the doc states the immediate half"
    );
    assert!(
        DOC.contains("The grants behind its outstanding tokens are revoked."),
        "and the half that kills what was already issued"
    );
    // And that suspension is deliberately NOT that, or an operator reads the section above and
    // assumes a pause also kills outstanding tokens.
    assert!(
        DOC.contains("**Suspension is not revocation.**"),
        "the doc distinguishes suspension from revocation"
    );
}

/// REVOKING AN AGENT KILLS ITS OUTSTANDING TOKENS, and only its own (issue #130, criterion 1).
///
/// Two properties in one test, because they fail in opposite directions and a test for either
/// alone passes on the other's bug:
///
///   - WITHOUT the cascade, setting the state blocks the next issuance and leaves every token
///     the agent already holds working until it expires. That is the half the criterion asks
///     for and the half a state check does not deliver.
///   - With a cascade scoped only to the CLIENT, revoking the agent revokes every live grant
///     on that client. `agents_client_unique` guarantees no second AGENT shares the client; it
///     says nothing about who holds GRANTS on it, and nothing stops an operator binding an
///     agent to a client that also serves interactive logins. So a human's grant is seeded on
///     the same client, and it must survive.
///
/// The subject is what separates them: a machine grant's subject is the client's
/// service-account principal, a person's is their user id.
#[tokio::test]
async fn revoking_an_agent_revokes_its_grants_and_leaves_the_clients_human_grants_alone() {
    let h = Harness::start().await;
    let (client, secret) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    let client_id = client.to_string();
    let seeded = seed_agent(&h, &client, &["deploy"]).await;

    // A token for the agent, which opens a machine grant subject to the service account.
    let (status, _headers, body) = h
        .token_with_auth(
            &cc_form(Some("deploy")),
            Some(&basic_header(&client_id, &secret)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "agent issuance: {body}");

    // A HUMAN's grant on the SAME client, seeded as the owner: this is the row the
    // client-scoped cascade would have taken with it.
    let human = h.seed_unique_user().await;
    sqlx::query(
        "INSERT INTO grants /* query-audit-allow: owner test seed */ \
         (id, tenant_id, environment_id, client_id, subject, created_at) \
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind(format!("gnt_human_{}", h.scope().environment()))
    .bind(h.scope().tenant().to_string())
    .bind(h.scope().environment().to_string())
    .bind(&client_id)
    .bind(&human)
    .execute(h.db().owner_pool())
    .await
    .expect("seed a human grant on the same client");

    let live_machine_grants = |label: &'static str| {
        let pool = h.db().owner_pool().clone();
        let tenant = h.scope().tenant().to_string();
        let environment = h.scope().environment().to_string();
        let client_id = client_id.clone();
        async move {
            let (count,): (i64,) = sqlx::query_as(
                "SELECT count(*) FROM grants /* query-audit-allow: owner test read */ \
                 WHERE tenant_id = $1 AND environment_id = $2 AND client_id = $3 \
                   AND revoked_at IS NULL \
                   AND subject IN (SELECT id FROM service_accounts \
                                   WHERE tenant_id = $1 AND environment_id = $2 \
                                     AND client_id = $3)",
            )
            .bind(&tenant)
            .bind(&environment)
            .bind(&client_id)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|error| panic!("{label}: count machine grants: {error}"));
            count
        }
    };

    assert!(
        live_machine_grants("before").await >= 1,
        "the issuance opened a machine grant, which is what revocation has to reach"
    );

    set_state(&h, &seeded.id, "revoked").await;

    assert_eq!(
        live_machine_grants("after").await,
        0,
        "revoking the agent must revoke the grants behind its outstanding tokens; setting the \
         state alone only blocks the NEXT issuance"
    );

    let (human_live,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM grants /* query-audit-allow: owner test read */ \
         WHERE tenant_id = $1 AND environment_id = $2 AND subject = $3 \
           AND revoked_at IS NULL",
    )
    .bind(h.scope().tenant().to_string())
    .bind(h.scope().environment().to_string())
    .bind(&human)
    .fetch_one(h.db().owner_pool())
    .await
    .expect("count human grants");
    assert_eq!(
        human_live, 1,
        "and it must NOT touch a person's grant on the same client: revoking an agent is not \
         revoking the client"
    );
}
