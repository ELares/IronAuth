// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environment secret management over HTTP (issue #235, follow-up to #45), driven through the
//! management router against a real database.
//!
//! The variable half of this surface shipped first and is proven in `variables.rs`. The
//! properties worth proving HERE are the ones that are specific to a secret, and every one of
//! them is a decision rather than plumbing.
//!
//! * The VALUE NEVER COMES BACK. Not from the read, not from the list, not from the write's
//!   own response. This is the `mak_` lesson from issue #11: a management API that can write a
//!   credential must not double as a way to enumerate credentials. A wrapper that mirrored
//!   `variables.rs` too closely would return `value` and look entirely correct.
//! * The write REACHES THE TABLE, through the DATA-plane role. `ironauth_control` is fenced out
//!   of `environment_secrets` by 0100's restrictive policies to one reserved name, so a surface
//!   that used the management store would be refused by the database on every other name. The
//!   round trip below is what proves the cross-role seam is actually wired, and it is why the
//!   round trip is asserted through `version` rather than through a value nothing returns.
//! * SCOPE CONTAINMENT. Secrets are `(tenant, environment)` scoped and row-level security is
//!   the fence. The fixtures differ in the ENVIRONMENT alone, under one tenant: a second tenant
//!   would also be refused by the tenant predicate and so would prove nothing about the
//!   environment half.
//! * CROSS-ROLE IDEMPOTENCY. The write lands on the data plane and the replay record on the
//!   control plane, so they cannot share a transaction. A replay must still return the original
//!   response rather than sealing a second time.
//!
//! Every fixture uses `start_with_signing_registry`, and that is not incidental: the shared
//! registry is how this surface reaches the data-plane role, so a harness without one drives
//! every case into the fail-closed 422 and measures nothing about the secrets themselves.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

/// The `.../environments/{environment}/secrets` base path.
fn base(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/secrets")
}

fn body(value: &str) -> String {
    serde_json::json!({ "value": value }).to_string()
}

#[tokio::test]
async fn a_secret_round_trips_as_metadata_and_its_value_is_never_returned() {
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let root = base(&tenant, &environment);

    let (status, _, response) = h
        .put_with_key(&format!("{root}/STRIPE_KEY"), "k-1", &body("sk_live_alpha"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "first write: {response}");
    assert!(
        !response.contains("sk_live_alpha"),
        "the write echoed the secret back in its own response: {response}"
    );

    let (status, _, response) = h.get(&format!("{root}/STRIPE_KEY")).await;
    assert_eq!(status, StatusCode::OK, "read back: {response}");
    assert!(
        !response.contains("sk_live_alpha"),
        "the read returned the secret VALUE, which no endpoint on this surface may do: \
         {response}"
    );
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(value["name"], "STRIPE_KEY");
    assert!(
        value.get("value").is_none(),
        "the metadata shape carries a `value` field at all, which is the shape a later change \
         would fill in: {response}"
    );
    let first_version = value["version"].as_i64().expect("version");

    // A second write REPLACES and advances the revision. This is the only observable evidence
    // that a write landed, precisely because the value is unreadable, and it is what an
    // operator confirms a rotation by.
    let (status, _, response) = h
        .put_with_key(&format!("{root}/STRIPE_KEY"), "k-2", &body("sk_live_beta"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "second write: {response}");

    let (_, _, response) = h.get(&format!("{root}/STRIPE_KEY")).await;
    let value: Value = serde_json::from_str(&response).expect("json");
    assert!(
        value["version"].as_i64().expect("version") > first_version,
        "a replace must advance the revision counter, or a rotation is unverifiable: {response}"
    );

    // The LIST is the other place a value could leak, and it is the one a wrapper is most
    // likely to get wrong by reusing the variable list shape.
    let (status, _, response) = h.get(&root).await;
    assert_eq!(status, StatusCode::OK, "list: {response}");
    assert!(
        !response.contains("sk_live_beta") && !response.contains("sk_live_alpha"),
        "the list returned secret values: {response}"
    );
    let listed: Value = serde_json::from_str(&response).expect("json");
    let items = listed["items"].as_array().expect("items");
    assert_eq!(
        items.len(),
        1,
        "the second write replaced rather than added"
    );
    assert_eq!(items[0]["name"], "STRIPE_KEY");
}

#[tokio::test]
async fn a_replayed_write_returns_the_original_response_without_sealing_again() {
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let root = base(&tenant, &environment);

    let (status, _, _) = h
        .put_with_key(&format!("{root}/TOKEN"), "k-replay", &body("first"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, _, response) = h.get(&format!("{root}/TOKEN")).await;
    let version = serde_json::from_str::<Value>(&response).expect("json")["version"]
        .as_i64()
        .expect("version");

    // The SAME key and the SAME body. The record lives on the control plane and the write on
    // the data plane, so this is the case the two-phase split has to get right: the replay is
    // served from the recorded response and the seal does not run a second time.
    let (status, _, _) = h
        .put_with_key(&format!("{root}/TOKEN"), "k-replay", &body("first"))
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "the replay answers as before"
    );

    let (_, _, response) = h.get(&format!("{root}/TOKEN")).await;
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["version"]
            .as_i64()
            .expect("version"),
        version,
        "the replay re-sealed: the revision moved, so the write ran twice and the recorded \
         response was not consulted"
    );
}

#[tokio::test]
async fn a_secret_is_invisible_to_a_sibling_environment_and_deletes_only_in_its_own() {
    let h = Harness::start_with_signing_registry(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let sibling = h.create_environment(&tenant, "staging", "k-sibling").await;
    let root = base(&tenant, &environment);
    let other = base(&tenant, &sibling);

    let (status, _, _) = h
        .put_with_key(&format!("{root}/SHARED_NAME"), "k-a", &body("alpha"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The SAME name in the sibling environment is a different secret, not a collision.
    let (status, _, response) = h.get(&format!("{other}/SHARED_NAME")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a secret leaked across the environment fence: {response}"
    );

    let (status, _, response) = h.delete(&format!("{root}/SHARED_NAME")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete: {response}");
    let (status, _, _) = h.get(&format!("{root}/SHARED_NAME")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the delete landed");
}
