// SPDX-License-Identifier: MIT OR Apache-2.0

//! Organization membership and lifecycle over HTTP (issue #94), driven through the
//! management router against a real database.
//!
//! Pins: a user is added to an organization, listed, and removed (soft delete, so a
//! repeat remove is the uniform 404); a duplicate add is a 409; disabling an
//! organization flips its `active` flag while it stays readable, and re-enabling
//! restores it; and creating an organization invitation validates the org-context
//! (a cross-scope, unknown, or disabled org is rejected before the invitation is
//! provisioned).

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

/// Create a tenant with an environment and return the organizations base path.
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

#[tokio::test]
async fn membership_add_list_and_remove_round_trip() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let user = create_user(&h, &tenant, &environment, "member@x.test", "k-user").await;
    let base =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/memberships");

    // Add the user.
    let body = serde_json::json!({ "user_id": user }).to_string();
    let (status, _, response) = h.post(&base, "k-add", &body).await;
    assert_eq!(status, StatusCode::CREATED, "add member: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(value["organization_id"], org);
    assert_eq!(value["user_id"], user);
    assert_eq!(value["state"], "active");
    let membership = value["id"].as_str().expect("id").to_owned();
    assert!(membership.starts_with("omb_"), "membership id is typed");

    // List the org's one member.
    let (status, _, response) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "list members: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(value["items"].as_array().expect("items").len(), 1);

    // Remove the member: 204, then it reads as absent (the list is empty).
    let (status, _, _) = h.delete(&format!("{base}/{membership}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, _, response) = h.get(&base).await;
    let value: Value = serde_json::from_str(&response).expect("json");
    assert!(value["items"].as_array().expect("items").is_empty());

    // A repeat remove of the already-removed membership is the uniform 404.
    let (status, _, _) = h.delete(&format!("{base}/{membership}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn duplicate_add_is_a_conflict() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let user = create_user(&h, &tenant, &environment, "dup@x.test", "k-user").await;
    let base =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/memberships");

    let body = serde_json::json!({ "user_id": user }).to_string();
    let (status, _, _) = h.post(&base, "k-add-1", &body).await;
    assert_eq!(status, StatusCode::CREATED);
    // A distinct second add (different Idempotency-Key) of the same user is a 409.
    let (status, _, response) = h.post(&base, "k-add-2", &body).await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate add: {response}");
}

#[tokio::test]
async fn add_to_an_unknown_user_is_not_found() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let base =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/memberships");

    // A well-formed but never-created user id (in this scope) is the uniform not-found.
    let absent = fresh_in_scope_user(&tenant, &environment);
    let body = serde_json::json!({ "user_id": absent }).to_string();
    let (status, _, _) = h.post(&base, "k-add", &body).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn organization_disable_and_enable_toggle_the_active_flag() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let org_path = format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}");

    // A fresh organization is active.
    let (_, _, response) = h.get(&org_path).await;
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["active"],
        true
    );

    // Disable it: still readable, but active is now false.
    let (status, _, response) = h
        .post(&format!("{org_path}/disable"), "k-disable", "")
        .await;
    assert_eq!(status, StatusCode::OK, "disable: {response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["active"],
        false
    );
    let (status, _, response) = h.get(&org_path).await;
    assert_eq!(status, StatusCode::OK, "a disabled org is still readable");
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["active"],
        false
    );

    // Re-enable it.
    let (status, _, response) = h.post(&format!("{org_path}/enable"), "k-enable", "").await;
    assert_eq!(status, StatusCode::OK, "enable: {response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["active"],
        true
    );
}

#[tokio::test]
async fn org_invitation_create_validates_the_org_context() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let invitations = format!("/v1/tenants/{tenant}/environments/{environment}/invitations");

    // A valid, active org: the org invitation is created.
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let body = serde_json::json!({
        "identifier": "invitee@x.test",
        "credential_type": "password",
        "org_context": org,
    })
    .to_string();
    let (status, _, response) = h.post(&invitations, "k-inv-ok", &body).await;
    assert_eq!(status, StatusCode::CREATED, "valid org_context: {response}");

    // A malformed org_context is a 400.
    let body = serde_json::json!({
        "identifier": "bad@x.test",
        "org_context": "org_not-a-real-id",
    })
    .to_string();
    let (status, _, _) = h.post(&invitations, "k-inv-bad", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "malformed org_context");

    // An unknown (well-formed, in-scope) org_context is a 400.
    let unknown = fresh_in_scope_org(&tenant, &environment);
    let body = serde_json::json!({
        "identifier": "unknown@x.test",
        "org_context": unknown,
    })
    .to_string();
    let (status, _, _) = h.post(&invitations, "k-inv-unknown", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown org_context");

    // A DISABLED org_context is a 409 (the org exists but is disabled).
    let disabled = create_org(&h, &tenant, &environment, "k-org2").await;
    let org_path =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{disabled}");
    let (status, _, _) = h
        .post(&format!("{org_path}/disable"), "k-disable", "")
        .await;
    assert_eq!(status, StatusCode::OK);
    let body = serde_json::json!({
        "identifier": "disabled@x.test",
        "org_context": disabled,
    })
    .to_string();
    let (status, _, _) = h.post(&invitations, "k-inv-disabled", &body).await;
    assert_eq!(status, StatusCode::CONFLICT, "disabled org_context");
}

/// The `(tenant, environment)` scope parsed from two id path segments.
fn scope_of(tenant: &str, environment: &str) -> ironauth_store::Scope {
    use ironauth_store::{EnvironmentId, Scope, TenantId};
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// A well-formed organization id in the given scope that was never created (for the
/// unknown-org-context probe).
fn fresh_in_scope_org(tenant: &str, environment: &str) -> String {
    ironauth_store::OrganizationId::generate(
        &ironauth_env::Env::system(),
        &scope_of(tenant, environment),
    )
    .to_string()
}

/// A well-formed user id in the given scope that was never created.
fn fresh_in_scope_user(tenant: &str, environment: &str) -> String {
    ironauth_store::UserId::generate(&ironauth_env::Env::system(), &scope_of(tenant, environment))
        .to_string()
}
