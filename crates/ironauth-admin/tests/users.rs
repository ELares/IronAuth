// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admin user management over HTTP (issue #52): the Keycloak/FusionAuth paper-cut
//! checklist and the differentiating lifecycle half, driven through the management
//! router against a real database.
//!
//! Pins: the paper-cut checklist (a caller-supplied id on create with its 409
//! collision, PATCH, accurate list pagination on every list endpoint), the lifecycle
//! state transitions (valid applied, invalid refused), external-id link/unlink and
//! per-scope uniqueness, and the uniform cross-tenant not-found the IDOR harness
//! expects on every new endpoint.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, OPERATOR_TOKEN, bearer};
use serde_json::Value;

/// A tenant with an environment, and the users collection path under it.
async fn tenant_env(h: &Harness) -> (String, String, String) {
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let users = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    (tenant, environment, users)
}

/// A PATCH with the operator token and a JSON body.
async fn patch(h: &Harness, path: &str, body: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("PATCH")
        .uri(path)
        .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .expect("request builds");
    let (status, _, response) = h.send(request).await;
    (status, response)
}

/// A PUT with the operator token and a JSON body.
async fn put(h: &Harness, path: &str, body: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("PUT")
        .uri(path)
        .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .expect("request builds");
    let (status, _, response) = h.send(request).await;
    (status, response)
}

#[tokio::test]
async fn create_read_update_delete_and_the_supplied_id_paper_cut() {
    let h = Harness::start(50).await;
    let (_t, _e, users) = tenant_env(&h).await;

    // Create with a body carrying an external id and claims.
    let body = serde_json::json!({
        "identifier": "ada@example.test",
        "external_id": "crm-1",
        "claims": { "email": "ada@example.test", "name": "Ada" }
    })
    .to_string();
    let (status, _, response) = h.post(&users, "k-create", &body).await;
    assert_eq!(status, StatusCode::CREATED, "create: {response}");
    let created: Value = serde_json::from_str(&response).expect("json");
    let user_id = created["id"].as_str().expect("id").to_owned();
    assert_eq!(created["state"], "active");
    assert_eq!(created["external_id"], "crm-1");
    assert!(
        created.get("password_hash").is_none(),
        "the password hash is never returned"
    );

    let one = format!("{users}/{user_id}");

    // Read it back.
    let (status, _, response) = h.get(&one).await;
    assert_eq!(status, StatusCode::OK, "get: {response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).unwrap()["identifier"],
        "ada@example.test"
    );

    // PATCH the profile (a partial update of the claims).
    let (status, response) = patch(&h, &one, r#"{"claims":{"name":"Ada L"}}"#).await;
    assert_eq!(status, StatusCode::OK, "patch: {response}");

    // A caller-supplied id is honored on create; a re-use is a 409.
    let supplied = common::Harness::fresh_user_id(
        // Reconstruct the scope from the created user's own id path is unnecessary;
        // mint a fresh id in the same scope by parsing the created id's scope.
        parse_scope(&user_id),
    )
    .to_string();
    let supplied_body =
        serde_json::json!({ "id": supplied, "identifier": "grace@example.test" }).to_string();
    let (status, _, response) = h.post(&users, "k-supplied", &supplied_body).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "supplied-id create: {response}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&response).unwrap()["id"],
        supplied
    );
    // Re-create with the same id: a conflict.
    let (status, _, _) = h.post(&users, "k-supplied-2", &supplied_body).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a re-used supplied id is a 409"
    );

    // Delete the first user; it then reads as not-found, and a repeat delete is 404.
    let (status, _, _) = h.delete(&one).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete is 204");
    let (status, _, _) = h.get(&one).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a deleted user reads as not-found"
    );
    let (status, _, _) = h.delete(&one).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a repeat delete is the uniform not-found"
    );
}

/// Parse the `(tenant, environment)` scope embedded in a `usr_` id string.
fn parse_scope(user_id: &str) -> ironauth_store::Scope {
    // The id embeds its scope in the clear; parse_declared_scope recovers it.
    ironauth_store::UserId::parse_declared_scope(user_id)
        .expect("valid user id")
        .scope()
}

#[tokio::test]
async fn list_paginates_accurately_and_filters() {
    let h = Harness::start(2).await;
    let (_t, _e, users) = tenant_env(&h).await;

    for (i, ident) in ["a@x.test", "b@x.test", "c@x.test"].iter().enumerate() {
        let body = serde_json::json!({ "identifier": ident }).to_string();
        let (status, _, response) = h.post(&users, &format!("k-{i}"), &body).await;
        assert_eq!(status, StatusCode::CREATED, "{response}");
    }

    // First page (size 2) plus a cursor walk returns every user, once.
    let (status, _, response) = h.get(&users).await;
    assert_eq!(status, StatusCode::OK);
    let page1: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(
        page1["items"].as_array().unwrap().len(),
        2,
        "page size honored"
    );
    let cursor = page1["next_cursor"]
        .as_str()
        .expect("a further page exists");
    let (status, _, response) = h.get(&format!("{users}?cursor={cursor}")).await;
    assert_eq!(status, StatusCode::OK);
    let page2: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(
        page2["items"].as_array().unwrap().len(),
        1,
        "the last user is on page two"
    );
    assert!(page2.get("next_cursor").is_none() || page2["next_cursor"].is_null());

    // A filter narrows the list.
    let (status, _, response) = h.get(&format!("{users}?identifier=b@x.test")).await;
    assert_eq!(status, StatusCode::OK);
    let filtered: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(filtered["items"].as_array().unwrap().len(), 1);
    assert_eq!(filtered["items"][0]["identifier"], "b@x.test");
}

#[tokio::test]
async fn lifecycle_transitions_are_validated_and_audited() {
    let h = Harness::start(50).await;
    let (_t, _e, users) = tenant_env(&h).await;
    let body = serde_json::json!({ "identifier": "u@x.test" }).to_string();
    let (_s, _, response) = h.post(&users, "k-c", &body).await;
    let user_id = serde_json::from_str::<Value>(&response).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let state_path = format!("{users}/{user_id}/state");

    // A valid transition (active -> blocked) applies.
    let (status, _, response) = h
        .post(&state_path, "k-block", r#"{"state":"blocked"}"#)
        .await;
    assert_eq!(status, StatusCode::OK, "block: {response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).unwrap()["state"],
        "blocked"
    );

    // An invalid transition (blocked -> pending_verification) is a 409.
    let (status, _, _) = h
        .post(&state_path, "k-bad", r#"{"state":"pending_verification"}"#)
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an invalid transition is refused"
    );

    // scheduled_offboarding without a timestamp is a 400.
    let (status, _, _) = h
        .post(
            &state_path,
            "k-sched",
            r#"{"state":"scheduled_offboarding"}"#,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "scheduled_offboarding needs a timestamp"
    );

    // The audit log recorded the applied transition with actor attribution.
    let audits = h
        .control_store()
        .scoped(parse_scope(&user_id))
        .audit()
        .list()
        .await
        .expect("audit list");
    assert!(
        audits.iter().any(|row| row.action == "user.state_change"),
        "the applied transition is in the audit log"
    );
}

#[tokio::test]
async fn external_id_link_unlink_and_per_scope_uniqueness() {
    let h = Harness::start(50).await;
    let (_t, _e, users) = tenant_env(&h).await;

    let (_s, _, r1) = h.post(&users, "k1", r#"{"identifier":"one@x.test"}"#).await;
    let u1 = serde_json::from_str::<Value>(&r1).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_s, _, r2) = h.post(&users, "k2", r#"{"identifier":"two@x.test"}"#).await;
    let u2 = serde_json::from_str::<Value>(&r2).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Link an external id to u1.
    let link1 = format!("{users}/{u1}/external-id");
    let (status, response) = put(&h, &link1, r#"{"external_id":"shared"}"#).await;
    assert_eq!(status, StatusCode::OK, "link: {response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).unwrap()["external_id"],
        "shared"
    );

    // u2 cannot claim the same external id: a 409.
    let link2 = format!("{users}/{u2}/external-id");
    let (status, _) = put(&h, &link2, r#"{"external_id":"shared"}"#).await;
    assert_eq!(status, StatusCode::CONFLICT, "a second claim is refused");

    // The list filters by the linked external id.
    let (status, _, response) = h.get(&format!("{users}?external_id=shared")).await;
    assert_eq!(status, StatusCode::OK);
    let filtered: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(filtered["items"].as_array().unwrap().len(), 1);
    assert_eq!(filtered["items"][0]["id"], u1);

    // Unlink frees it for u2.
    let request = Request::builder()
        .method("DELETE")
        .uri(&link1)
        .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = h.send(request).await;
    assert_eq!(status, StatusCode::OK, "unlink is 200");
    let (status, _) = put(&h, &link2, r#"{"external_id":"shared"}"#).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the freed external id can be re-claimed"
    );
}

#[tokio::test]
async fn cross_tenant_access_is_the_uniform_not_found() {
    let h = Harness::start(50).await;

    // Create a user in tenant A.
    let (ta, ea) = h.create_tenant("tenant-a", "ka").await;
    let users_a = format!("/v1/tenants/{ta}/environments/{ea}/users");
    let (_s, _, response) = h
        .post(&users_a, "k-a", r#"{"identifier":"a@x.test"}"#)
        .await;
    let victim_id = serde_json::from_str::<Value>(&response).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // A second, unrelated tenant B.
    let (tb, eb) = h.create_tenant("tenant-b", "kb").await;

    // Reaching A's user through B's environment path is the uniform not-found on
    // every surface (the user id parses under B's scope as absent).
    let via_b = format!("/v1/tenants/{tb}/environments/{eb}/users/{victim_id}");
    let (status, _, _) = h.get(&via_b).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-tenant get is not-found"
    );
    let (status, _, _) = h.delete(&via_b).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-tenant delete is not-found"
    );
    let (status, _, _) = h
        .post(&format!("{via_b}/state"), "k-x", r#"{"state":"blocked"}"#)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-tenant state change is not-found"
    );
    let (status, _) = put(
        &h,
        &format!("{via_b}/external-id"),
        r#"{"external_id":"x"}"#,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-tenant external-id link is not-found"
    );

    // The same probe against A's own environment resolves (control), so the 404 is a
    // scope boundary, not a broken route.
    let via_a = format!("/v1/tenants/{ta}/environments/{ea}/users/{victim_id}");
    let (status, _, _) = h.get(&via_a).await;
    assert_eq!(status, StatusCode::OK, "the user resolves in its own scope");
}
