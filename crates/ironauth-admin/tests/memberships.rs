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
async fn remove_then_readd_revives_the_membership() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let user = create_user(&h, &tenant, &environment, "revive@x.test", "k-user").await;
    let base =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/memberships");
    let body = serde_json::json!({ "user_id": user }).to_string();

    // Add, then remove.
    let (status, _, response) = h.post(&base, "k-add-1", &body).await;
    assert_eq!(status, StatusCode::CREATED, "first add: {response}");
    let membership = serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let (status, _, _) = h.delete(&format!("{base}/{membership}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Re-add the SAME user: this REVIVES the removed membership, a 201 (not a 409),
    // and the org roster has one live member again.
    let (status, _, response) = h.post(&base, "k-add-2", &body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "re-add revives, not 409: {response}"
    );
    let (_, _, response) = h.get(&base).await;
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(value["items"].as_array().expect("items").len(), 1);
}

/// Issue #395: a re-add REVIVES the removed row, which keeps its ORIGINAL id, so the
/// 201 must report THAT id and not the one the handler minted for the insert it did
/// not perform. A minted id is a phantom: it is never persisted, so every endpoint
/// keyed on an `omb_` id answers the uniform 404 for it and a caller who follows the
/// create response is stuck.
///
/// Issue #435 is the same defect in `metadata` and `created_at_unix_ms`, the two other
/// fields a revive can make disagree with the request. All six are therefore asserted
/// against the ROW here (the roster entry), never against the request that produced
/// it, so an assertion can only pass when the response really does describe what was
/// persisted. The first add deliberately carries metadata the re-add omits, and the
/// revive keeps the original `created_at`, so a response rendered from REQUEST state
/// disagrees with the roster in exactly those two.
#[tokio::test]
async fn readd_reports_the_revived_membership_row_which_resolves() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let user = create_user(&h, &tenant, &environment, "phantom@x.test", "k-user").await;
    let base =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/memberships");
    // The first add SETS metadata; the re-add OMITS it, so the revived row keeps the
    // metadata the first add stored (the UPDATE coalesces a NULL bind).
    let first = serde_json::json!({ "user_id": user, "metadata": { "a": 1 } }).to_string();
    let readd = serde_json::json!({ "user_id": user }).to_string();

    // Add, keep the id the create reported, then remove.
    let (status, _, response) = h.post(&base, "k-add-1", &first).await;
    assert_eq!(status, StatusCode::CREATED, "first add: {response}");
    let original = serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let (status, _, _) = h.delete(&format!("{base}/{original}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Re-add: the SAME row comes back, so the reported id must be the SAME id.
    let (status, _, created) = h.post(&base, "k-add-2", &readd).await;
    assert_eq!(status, StatusCode::CREATED, "re-add: {created}");
    let value: Value = serde_json::from_str(&created).expect("json");
    let readded = value["id"].as_str().expect("id").to_owned();
    assert_eq!(
        readded, original,
        "the re-add must report the REVIVED row's id, not a freshly minted one: {created}"
    );

    // The reported id RESOLVES: an endpoint keyed on an `omb_` id answers 200 for it,
    // rather than the 404 a phantom id gets everywhere.
    let (status, _, response) = h.get(&format!("{base}/{readded}/effective-roles")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the reported id must resolve: {response}"
    );

    // And the 201 describes THE ROW, field for field (issue #435). The org's single
    // live member read back from the database must be the very object the create
    // returned: same id, organization, user, state, metadata and creation time. Every
    // one of those is compared against the PERSISTED value, so a field rendered from
    // request state instead (the omitted metadata, or the re-add's clock rather than
    // the row's original `created_at`) fails here.
    let (status, _, response) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "list members: {response}");
    let list: Value = serde_json::from_str(&response).expect("json");
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "one live member: {response}");
    // Field by field FIRST, so a failure names the field it was, and then as whole
    // objects, so a field added to the view later is covered without anyone
    // remembering to add a line for it here.
    assert_eq!(
        items[0]["id"], value["id"],
        "the roster names the reported id"
    );
    assert_eq!(items[0]["organization_id"], value["organization_id"]);
    assert_eq!(items[0]["user_id"], value["user_id"]);
    assert_eq!(items[0]["state"], value["state"]);
    assert_eq!(
        items[0]["metadata"], value["metadata"],
        "the revived row KEPT the first add's metadata; the 201 must report that"
    );
    assert_eq!(
        items[0]["created_at_unix_ms"], value["created_at_unix_ms"],
        "the revived row kept its ORIGINAL creation time; the 201 must report that"
    );
    assert_eq!(
        items[0], value,
        "the 201 must describe the persisted row, field for field"
    );

    // The STORED idempotent response is not a phantom either: replaying the re-add
    // (same Idempotency-Key) serves back the very same bytes, so every field above
    // holds for the replay too, forever.
    let (status, _, replay) = h.post(&base, "k-add-2", &readd).await;
    assert_eq!(status, StatusCode::CREATED, "replayed re-add: {replay}");
    assert_eq!(
        replay, created,
        "the replay must serve the original response byte for byte"
    );
}

/// The FRESH-insert half of the same contract. The revive path is where a response
/// built from request state goes wrong, so it is the path the fix is argued from, but
/// the stored Idempotency-Key body is now produced by a renderer the store invokes
/// rather than by the handler, and that renderer runs on BOTH arms. A first create
/// therefore has to keep replaying its own bytes, and describe its own row, exactly
/// as before.
#[tokio::test]
async fn a_first_create_replays_its_own_response_and_describes_its_row() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let user = create_user(&h, &tenant, &environment, "fresh@x.test", "k-user").await;
    let base =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/memberships");
    let body = serde_json::json!({ "user_id": user, "metadata": { "seat": "b" } }).to_string();

    let (status, _, created) = h.post(&base, "k-add", &body).await;
    assert_eq!(status, StatusCode::CREATED, "first add: {created}");
    let value: Value = serde_json::from_str(&created).expect("json");

    // The 201 describes the row that was inserted, read back from the database.
    let (status, _, response) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "list members: {response}");
    let list: Value = serde_json::from_str(&response).expect("json");
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "one live member: {response}");
    assert_eq!(
        items[0], value,
        "the 201 of a FRESH insert must describe the persisted row too"
    );

    // Replaying the same Idempotency-Key serves the stored bytes back unchanged.
    let (status, _, replay) = h.post(&base, "k-add", &body).await;
    assert_eq!(status, StatusCode::CREATED, "replayed first add: {replay}");
    assert_eq!(
        replay, created,
        "the replay must serve the original response byte for byte"
    );
}

#[tokio::test]
async fn delete_via_the_wrong_organization_path_is_not_found_and_does_not_remove() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org_a = create_org(&h, &tenant, &environment, "k-org-a").await;
    let org_b = create_org(&h, &tenant, &environment, "k-org-b").await;
    let user = create_user(&h, &tenant, &environment, "nested@x.test", "k-user").await;

    // Add the user to org A.
    let base_a = format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org_a}/memberships"
    );
    let body = serde_json::json!({ "user_id": user }).to_string();
    let (status, _, response) = h.post(&base_a, "k-add", &body).await;
    assert_eq!(status, StatusCode::CREATED);
    let membership = serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // Deleting org A's membership via org B's path is the uniform 404 (the nested
    // resource does not belong to org B), and does NOT remove it.
    let base_b = format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org_b}/memberships"
    );
    let (status, _, _) = h.delete(&format!("{base_b}/{membership}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "wrong-org delete is 404");

    // The membership is untouched: org A still lists its one live member.
    let (_, _, response) = h.get(&base_a).await;
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        value["items"].as_array().expect("items").len(),
        1,
        "the wrong-org delete must not have removed org A's membership"
    );
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

#[tokio::test]
async fn a_retried_org_toggle_replays_the_original_response() {
    // The organization toggles are naturally idempotent, so this is not a data-safety
    // fix: it is what makes a retry after a network timeout return the ORIGINAL response
    // rather than re-deriving one, which is the convention the other admin state
    // mutations already follow.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let org = create_org(&h, &tenant, &environment, "k-org").await;
    let org_path = format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}");
    let disable = format!("{org_path}/disable");

    let (status, _, first) = h.post(&disable, "retry-key", "").await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let first_view: Value = serde_json::from_str(&first).expect("json");
    assert_eq!(first_view["active"], false);

    // The retry under the same key returns the stored bytes.
    let (status, _, replayed) = h.post(&disable, "retry-key", "").await;
    assert_eq!(status, StatusCode::OK, "{replayed}");
    assert_eq!(
        serde_json::from_str::<Value>(&replayed).expect("json"),
        first_view,
        "a retry under the same key replays the original response verbatim"
    );

    // THE CONTROL, and it is the sharp one: move the live state on, then retry the ORIGINAL
    // key again. A stored response must still describe what THAT request did, so it reports
    // `active: false` while the organization is now active. Anything re-derived at replay
    // time would report the current state and this would fail.
    let (status, _, enabled) = h.post(&format!("{org_path}/enable"), "k-enable", "").await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    assert_eq!(
        serde_json::from_str::<Value>(&enabled).expect("json")["active"],
        true
    );
    let (status, _, replayed_again) = h.post(&disable, "retry-key", "").await;
    assert_eq!(status, StatusCode::OK, "{replayed_again}");
    assert_eq!(
        serde_json::from_str::<Value>(&replayed_again).expect("json")["active"],
        false,
        "the replay describes the request it stored, not the organization's state now"
    );
    let (_, _, live) = h.get(&org_path).await;
    assert_eq!(
        serde_json::from_str::<Value>(&live).expect("json")["active"],
        true,
        "and the live organization is genuinely still enabled, so the two really differ"
    );
}

#[tokio::test]
async fn step_up_policies_round_trip_through_the_management_surface() {
    // Issue #262: management parity for the `ironauth step-up-policy` CLI. The store
    // repos and the CLI already existed, so the interesting part is the PLANE: the CLI
    // writes as the data-plane role, which 0047 granted, and this surface runs as the
    // control-plane role, which it did not. Without migration 0110 every write here is a
    // 500 and every read an empty list, which is the dead-surface shape #441 described.
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/step-up-policies");

    let (status, _, body) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        serde_json::from_str::<Value>(&body).expect("json")["items"]
            .as_array()
            .expect("items")
            .is_empty(),
        "a fresh environment has no policies: {body}"
    );

    let set = serde_json::json!({
        "scope_token": "payments:write",
        "min_acr": "aal2",
        "max_auth_age_secs": 300
    })
    .to_string();
    let (status, _, body) = h.post(&base, "k-set", &set).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, _, body) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = serde_json::from_str::<Value>(&body).expect("json");
    let items = items["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "the policy is listed: {body}");
    assert_eq!(items[0]["scope_token"], "payments:write");
    assert_eq!(items[0]["min_acr"], "aal2");
    assert_eq!(items[0]["max_auth_age_secs"], 300);

    // The set is an UPSERT, so a second set REPLACES rather than duplicating. That branch
    // is the one needing the column-scoped UPDATE grant, so it is exercised explicitly.
    let raise =
        serde_json::json!({ "scope_token": "payments:write", "min_acr": "aal3" }).to_string();
    let (status, _, body) = h.post(&base, "k-raise", &raise).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, _, body) = h.get(&base).await;
    let items = serde_json::from_str::<Value>(&body).expect("json");
    let items = items["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "replaced, not duplicated: {body}");
    assert_eq!(items[0]["min_acr"], "aal3");

    // A retry under the SAME key replays rather than re-executing.
    let (status, _, body) = h.post(&base, "k-raise", &raise).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    // ... and the same key against a DIFFERENT request is the fingerprint conflict.
    let (status, _, body) = h
        .post(
            &base,
            "k-raise",
            &serde_json::json!({ "scope_token": "other:scope", "min_acr": "aal2" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    let (status, _, body) = h.delete(&format!("{base}/payments:write")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, _, body) = h.get(&base).await;
    assert!(
        serde_json::from_str::<Value>(&body).expect("json")["items"]
            .as_array()
            .expect("items")
            .is_empty(),
        "the policy is gone: {body}"
    );

    // Removing an absent policy is a no-op success, matching the CLI and the store.
    let (status, _, body) = h.delete(&format!("{base}/payments:write")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}
