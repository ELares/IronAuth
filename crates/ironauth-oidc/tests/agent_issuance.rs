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
use ironauth_store::{AgentPrincipalId, ClientId, OrganizationId};

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
    let env = harness.env();
    let scope = harness.scope();
    // The organization row directly: `organizations()` is a CONTROL-plane repository and
    // this suite drives the data plane. The agent's foreign key needs the row to exist, not
    // the management route that usually creates it.
    let organization = OrganizationId::generate(env, &scope);
    sqlx::query(
        "INSERT INTO organizations /* query-audit-allow: owner test seed */ \
         (id, tenant_id, environment_id, display_name) VALUES ($1, $2, $3, 'agent org')",
    )
    .bind(organization.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(harness.db().owner_pool())
    .await
    .expect("seed organization");
    let user = harness.seed_unique_user().await;
    let linked_user = ironauth_store::UserId::parse_in_scope(&user, &scope).expect("user id");

    // The agent row directly, for the same reason the organization is: registering an agent
    // is a CONTROL-plane write and the data-plane role this suite runs as holds only SELECT
    // on `agents`. That split is the design, not an obstacle -- the token doors must be able
    // to READ an agent and must not be able to create one -- so the fixture writes as the
    // owner rather than the suite asking for a privilege the gate should never have.
    let id = AgentPrincipalId::generate(env, &scope);
    let tools: Vec<String> = tool_scopes.iter().map(|t| (*t).to_owned()).collect();
    sqlx::query(
        "INSERT INTO agents /* query-audit-allow: owner test seed */ \
         (id, tenant_id, environment_id, organization_id, linked_user_id, display_name, \
          state, tool_scopes, client_id) \
         VALUES ($1, $2, $3, $4, $5, 'deploy bot', 'active', $6, $7)",
    )
    .bind(id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(organization.to_string())
    .bind(linked_user.to_string())
    .bind(&tools)
    .bind(client.to_string())
    .execute(harness.db().owner_pool())
    .await
    .expect("seed agent");
    SeededAgent {
        id,
        linked_user: linked_user.to_string(),
        organization: organization.to_string(),
    }
}

/// Move a seeded agent to `state`, as the control plane would.
async fn set_state(harness: &Harness, id: &AgentPrincipalId, state: &str) {
    sqlx::query(
        "UPDATE agents /* query-audit-allow: owner test seed */ SET state = $1 WHERE id = $2",
    )
    .bind(state)
    .bind(id.to_string())
    .execute(harness.db().owner_pool())
    .await
    .expect("set agent state");
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
