// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admin user invitations over HTTP (issue #60), driven through the management
//! router against a real database.
//!
//! Pins: create provisions a pending-verification user and returns the one-time
//! token exactly ONCE; a read (get/list) and an idempotent replay NEVER return the
//! token (only its digest is ever stored); revoke makes a pending invitation
//! unacceptable and is idempotent; resend rotates the token and returns a fresh one;
//! and a cross-scope invitation probe is the uniform not-found (the anti-oracle).

mod common;

use common::Harness;
use serde_json::Value;

/// A tenant with an environment, and the invitations collection path under it.
async fn tenant_env(h: &Harness) -> (String, String, String) {
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let invitations = format!("/v1/tenants/{tenant}/environments/{environment}/invitations");
    (tenant, environment, invitations)
}

#[tokio::test]
async fn create_returns_the_one_time_token_and_reads_omit_it() {
    let h = Harness::start(50).await;
    let (_t, _e, invitations) = tenant_env(&h).await;

    let body = serde_json::json!({
        "identifier": "ada@example.test",
        "credential_type": "password",
    })
    .to_string();
    let (status, _, response) = h.post(&invitations, "inv-key-1", &body).await;
    assert_eq!(status, reqwest_status_created(), "create: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    let invitation = &value["invitation"];
    assert_eq!(invitation["target_identifier"], "ada@example.test");
    assert_eq!(invitation["state"], "pending");
    assert_eq!(invitation["credential_type"], "password");
    let id = invitation["id"].as_str().expect("invitation id").to_owned();
    // The one-time token is present at creation.
    let token = value["token"].as_str().expect("token present at create");
    assert!(token.starts_with("ira_inv_"), "token wire form: {token}");

    // A GET of the invitation NEVER returns the token (only the digest is stored).
    let (get_status, _, get_body) = h.get(&format!("{invitations}/{id}")).await;
    assert_eq!(get_status, reqwest_status_ok(), "get: {get_body}");
    let got: Value = serde_json::from_str(&get_body).expect("json");
    assert!(
        got.get("token").is_none(),
        "a read must not carry the token"
    );
    assert_eq!(got["id"], id);

    // The LIST also omits the token.
    let (list_status, _, list_body) = h.get(&invitations).await;
    assert_eq!(list_status, reqwest_status_ok(), "list: {list_body}");
    let list: Value = serde_json::from_str(&list_body).expect("json");
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "one invitation listed");
    assert!(
        items[0].get("token").is_none(),
        "list must not carry tokens"
    );
}

#[tokio::test]
async fn an_idempotent_replay_returns_the_invitation_without_the_token() {
    let h = Harness::start(50).await;
    let (_t, _e, invitations) = tenant_env(&h).await;

    let body = serde_json::json!({ "identifier": "grace@example.test" }).to_string();
    let (status, _, first) = h.post(&invitations, "inv-key-2", &body).await;
    assert_eq!(status, reqwest_status_created(), "first create: {first}");
    let first_value: Value = serde_json::from_str(&first).expect("json");
    assert!(
        first_value["token"].as_str().is_some(),
        "the token is revealed on the original creation"
    );

    // Replaying the SAME POST with the SAME key returns the stored response, which is
    // the invitation WITHOUT the one-time token (the token is shown only once).
    let (replay_status, _, replay) = h.post(&invitations, "inv-key-2", &body).await;
    assert_eq!(replay_status, reqwest_status_created(), "replay: {replay}");
    let replay_value: Value = serde_json::from_str(&replay).expect("json");
    assert!(
        replay_value.get("token").is_none() || replay_value["token"].is_null(),
        "an idempotent replay must not re-reveal the one-time token: {replay}"
    );
    assert_eq!(
        replay_value["invitation"]["id"], first_value["invitation"]["id"],
        "the replay returns the same invitation"
    );
}

#[tokio::test]
async fn revoke_makes_a_pending_invitation_unacceptable_and_is_idempotent() {
    let h = Harness::start(50).await;
    let (_t, _e, invitations) = tenant_env(&h).await;

    let body = serde_json::json!({ "identifier": "revoke@example.test" }).to_string();
    let (_s, _, created) = h.post(&invitations, "inv-key-3", &body).await;
    let id = serde_json::from_str::<Value>(&created).expect("json")["invitation"]["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // Revoke the pending invitation.
    let (status, _, response) = h
        .post(&format!("{invitations}/{id}/revoke"), "rev-key-1", "")
        .await;
    assert_eq!(status, reqwest_status_ok(), "revoke: {response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["state"],
        "revoked"
    );

    // The read reflects the revoked state.
    let (_s, _, got) = h.get(&format!("{invitations}/{id}")).await;
    assert_eq!(
        serde_json::from_str::<Value>(&got).expect("json")["state"],
        "revoked"
    );

    // A replay with the SAME key returns the stored response.
    let (replay_status, _, _) = h
        .post(&format!("{invitations}/{id}/revoke"), "rev-key-1", "")
        .await;
    assert_eq!(replay_status, reqwest_status_ok(), "revoke replay");

    // A fresh revoke of the now-revoked invitation matches no pending row: 404.
    let (again_status, _, again) = h
        .post(&format!("{invitations}/{id}/revoke"), "rev-key-2", "")
        .await;
    assert_eq!(
        again_status,
        reqwest_status_not_found(),
        "re-revoking a revoked invitation is a not-found: {again}"
    );
}

#[tokio::test]
async fn resend_rotates_the_token_and_returns_a_fresh_one() {
    let h = Harness::start(50).await;
    let (_t, _e, invitations) = tenant_env(&h).await;

    let body = serde_json::json!({ "identifier": "resend@example.test" }).to_string();
    let (_s, _, created) = h.post(&invitations, "inv-key-4", &body).await;
    let created_value: Value = serde_json::from_str(&created).expect("json");
    let id = created_value["invitation"]["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let first_token = created_value["token"].as_str().expect("token").to_owned();

    let (status, _, response) = h
        .post(&format!("{invitations}/{id}/resend"), "resend-key-1", "")
        .await;
    assert_eq!(status, reqwest_status_ok(), "resend: {response}");
    let resend_value: Value = serde_json::from_str(&response).expect("json");
    let fresh_token = resend_value["token"].as_str().expect("fresh token");
    assert!(fresh_token.starts_with("ira_inv_"));
    assert_ne!(
        fresh_token, first_token,
        "resend issues a DIFFERENT token, invalidating the prior one"
    );
    assert_eq!(resend_value["invitation"]["state"], "pending");
}

#[tokio::test]
async fn a_cross_scope_invitation_probe_is_the_uniform_not_found() {
    let h = Harness::start(50).await;
    let (tenant_a, env_a) = h.create_tenant("Acme", "k-a").await;
    let (tenant_b, env_b) = h.create_tenant("Beta", "k-b").await;
    let inv_a = format!("/v1/tenants/{tenant_a}/environments/{env_a}/invitations");

    let body = serde_json::json!({ "identifier": "a-person@example.test" }).to_string();
    let (_s, _, created) = h.post(&inv_a, "inv-key-5", &body).await;
    let id_a = serde_json::from_str::<Value>(&created).expect("json")["invitation"]["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // A's invitation id fetched under B's scope is the uniform not-found: a token or
    // id minted in one tenant never resolves in another.
    let (status_cross, _, cross) = h
        .get(&format!(
            "/v1/tenants/{tenant_b}/environments/{env_b}/invitations/{id_a}"
        ))
        .await;
    assert_eq!(
        status_cross,
        reqwest_status_not_found(),
        "cross probe: {cross}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&cross).expect("json")["error"],
        "not_found",
        "the cross-scope probe is the uniform not-found (the anti-oracle)"
    );

    // The invitation is still visible in its OWN scope (the isolation is directional,
    // not a global disappearance).
    let (status_own, _, own) = h.get(&format!("{inv_a}/{id_a}")).await;
    assert_eq!(status_own, reqwest_status_ok(), "own-scope get: {own}");
}

// Small status-code helpers so the test reads at a glance (the harness returns
// `axum::http::StatusCode`).
fn reqwest_status_created() -> axum::http::StatusCode {
    axum::http::StatusCode::CREATED
}
fn reqwest_status_ok() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}
fn reqwest_status_not_found() -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_FOUND
}
