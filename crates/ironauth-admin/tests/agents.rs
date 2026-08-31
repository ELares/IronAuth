// SPDX-License-Identifier: MIT OR Apache-2.0

//! Agent principals over a real database (issue #130).
//!
//! An agent is a first-class principal: it acts FOR a person, INSIDE an organization, with a
//! DECLARED tool set. These tests drive the operator surface criteria 1, 4 and 5 ask for --
//! register, list, inspect linkage and scopes, suspend, revoke -- entirely over HTTP.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::{EnvironmentId, Scope, TenantId};
use serde_json::Value;

/// The scope a `(tenant, environment)` pair names.
fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// Every audit action recorded in this scope.
async fn audit_actions(h: &Harness, tenant: &str, environment: &str) -> Vec<String> {
    h.store()
        .scoped(scope_of(tenant, environment))
        .audit()
        .list()
        .await
        .expect("read the audit trail")
        .into_iter()
        .map(|row| row.action)
        .collect()
}

/// Create a tenant with an environment.
async fn tenant_env(h: &Harness) -> (String, String) {
    h.create_tenant("acme", "k-tenant").await
}

/// Create an organization and return its id.
async fn create_org(h: &Harness, tenant: &str, environment: &str, key: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": "Globex" }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// Create an active user and return its id.
async fn create_user(
    h: &Harness,
    tenant: &str,
    environment: &str,
    ident: &str,
    key: &str,
) -> String {
    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let body = serde_json::json!({ "identifier": ident }).to_string();
    let (status, _, response) = h.post(&users, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create user: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// Register an agent and return the parsed response.
async fn register(
    h: &Harness,
    agents: &str,
    user: &str,
    tools: &[&str],
    key: &str,
) -> (StatusCode, Value) {
    let body = serde_json::json!({
        "linked_user_id": user,
        "display_name": "deploy bot",
        "tool_scopes": tools,
    })
    .to_string();
    let (status, _, response) = h.post(agents, key, &body).await;
    let value = if response.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Value::String(response))
    };
    (status, value)
}

#[tokio::test]
async fn an_agent_registers_lists_with_its_linkage_and_scopes_and_revokes() {
    // CRITERION 1 END TO END: an org admin lists the agents acting for their organization,
    // inspects linkage and scopes, and revokes one.
    let h = Harness::start(260).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let user = create_user(&h, &tenant, &environment, "ada@example.test", "k-user").await;
    let agents =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/agents");

    let (status, created) = register(&h, &agents, &user, &["deploy", "read_logs"], "k-agent").await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let agent_id = created["id"].as_str().expect("an agent id").to_owned();
    assert_eq!(created["state"], "active", "{created}");

    // THE LIST CARRIES THE LINKAGE AND THE SCOPES. Criterion 1 asks the admin to inspect
    // both, and a list that returned only ids would make that a second round trip per agent
    // -- or, more likely, a surface nobody uses.
    let (status, _, response) = h.get(&agents).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let list: Value = serde_json::from_str(&response).expect("json");
    let item = &list["items"][0];
    assert_eq!(item["id"].as_str(), Some(agent_id.as_str()), "{response}");
    assert_eq!(
        item["linked_user_id"].as_str(),
        Some(user.as_str()),
        "{response}"
    );
    assert_eq!(
        item["organization_id"].as_str(),
        Some(org.as_str()),
        "{response}"
    );
    assert_eq!(
        item["tool_scopes"],
        serde_json::json!(["deploy", "read_logs"]),
        "the declared tool set is what bounds this agent, so the operator must see it: {response}"
    );

    // REVOKE.
    let state_path = format!("{agents}/{agent_id}/state");
    let (status, _, response) = h
        .put(
            &state_path,
            &serde_json::json!({ "state": "revoked" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["state"],
        "revoked",
        "{response}"
    );

    // AND REVOCATION IS TERMINAL. A control an incident responder reaches for is not one
    // that can be quietly undone.
    let (status, _, response) = h
        .put(
            &state_path,
            &serde_json::json!({ "state": "active" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a revoked agent was returned to active: {response}"
    );
}

#[tokio::test]
async fn a_suspended_agent_stays_listable_and_auditable() {
    // CRITERION 5. A soft delete would have answered the operator's question ("what can act
    // here?") and destroyed the investigator's ("what WAS acting here, and who turned it
    // off?"). The state is a column, not a filter.
    let h = Harness::start(261).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let user = create_user(&h, &tenant, &environment, "ada@example.test", "k-user").await;
    let agents =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/agents");
    let (_status, created) = register(&h, &agents, &user, &["deploy"], "k-agent").await;
    let agent_id = created["id"].as_str().expect("an agent id").to_owned();

    let (status, _, response) = h
        .put(
            &format!("{agents}/{agent_id}/state"),
            &serde_json::json!({ "state": "suspended" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");

    let (status, _, response) = h.get(&agents).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let list: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        list["items"].as_array().map(Vec::len),
        Some(1),
        "{response}"
    );
    assert_eq!(
        list["items"][0]["state"], "suspended",
        "a suspended agent must stay listable, and say so: {response}"
    );

    // AUDITABLE: the state change is on the trail under its own verb, because finding a
    // suspension under a generic update means reading every update to know one happened.
    let rows = audit_actions(&h, &tenant, &environment).await;
    assert!(
        rows.iter().any(|action| action == "agent.state.set"),
        "the suspension must be audited under its own verb: {rows:?}"
    );
    assert!(
        rows.iter().any(|action| action == "agent.register"),
        "and so must the registration: {rows:?}"
    );
}

#[tokio::test]
async fn an_agent_of_another_organization_is_unreachable_through_this_path() {
    // CRITERION 4's boundary. The nesting is the control: an agent presented under the wrong
    // organization's path must be the uniform not-found, or the path is decoration.
    let h = Harness::start(262).await;
    let (tenant, environment) = tenant_env(&h).await;
    let mine = create_org(&h, &tenant, &environment, "k-org-a").await;
    let theirs = create_org(&h, &tenant, &environment, "k-org-b").await;
    let user = create_user(&h, &tenant, &environment, "ada@example.test", "k-user").await;

    let their_agents =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{theirs}/agents");
    let (_status, created) = register(&h, &their_agents, &user, &["deploy"], "k-agent").await;
    let agent_id = created["id"].as_str().expect("an agent id").to_owned();

    // Not listed under mine.
    let my_agents =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{mine}/agents");
    let (status, _, response) = h.get(&my_agents).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let list: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        list["items"].as_array().map(Vec::len),
        Some(0),
        "another organization's agent was listed under mine: {response}"
    );

    // AND NOT REVOCABLE through mine, which is the half that matters: a listing leak is a
    // disclosure, a revocation leak is a denial of service against another org.
    let (status, _, response) = h
        .put(
            &format!("{my_agents}/{agent_id}/state"),
            &serde_json::json!({ "state": "revoked" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another organization's agent was revocable through my path: {response}"
    );

    // And it is still active where it belongs.
    let (status, _, response) = h.get(&their_agents).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["items"][0]["state"],
        "active",
        "the refusal must not have taken effect anyway: {response}"
    );
}

#[tokio::test]
async fn an_agent_with_no_declared_tools_is_refused() {
    // An agent that declared nothing can do nothing, and registering it silently produces a
    // principal whose every request is denied with no hint why. Almost always a caller that
    // forgot the field.
    let h = Harness::start(263).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let user = create_user(&h, &tenant, &environment, "ada@example.test", "k-user").await;
    let agents =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/agents");

    let (status, response) = register(&h, &agents, &user, &[], "k-agent").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");

    // And a blank one, which passes a length check and declares nothing.
    let (status, response) = register(&h, &agents, &user, &["   "], "k-agent-blank").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
}

#[tokio::test]
async fn registering_an_agent_for_an_absent_user_is_the_uniform_not_found() {
    // An agent linked to nobody is the unattributable principal this issue exists to prevent,
    // so the linkage is checked before anything is written.
    //
    // The id sent here is WELL FORMED and IN SCOPE, for a user that existed and no longer
    // does. That is the only input that reaches the existence read: a syntactically invalid
    // id is refused by `parse_in_scope` one line earlier, so a test using one passes with the
    // existence check deleted and measures nothing.
    let h = Harness::start(264).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let user = create_user(&h, &tenant, &environment, "gone@example.test", "k-user").await;
    let (status, _, response) = h
        .delete(&format!(
            "/v1/tenants/{tenant}/environments/{environment}/users/{user}"
        ))
        .await;
    assert!(
        status.is_success(),
        "the linked user must be gone before the check is measured: {response}"
    );

    let agents =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/agents");
    let (status, response) = register(&h, &agents, &user, &["deploy"], "k-agent").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a well-formed id for a user that is gone: {response}"
    );

    // And the malformed-id path stays covered, so removing the parse would also be caught.
    let (status, response) = register(&h, &agents, "usr_absent", &["deploy"], "k-agent-2").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a malformed id: {response}");
}
