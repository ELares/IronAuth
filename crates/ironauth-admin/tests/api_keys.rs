// SPDX-License-Identifier: MIT OR Apache-2.0

//! The API key management surface (issue #99, criterion 6).
//!
//! The store layer is covered in `ironauth-store`; what is worth driving here is what the HTTP
//! layer adds and could get wrong: that a listing never carries a verifier, that a revoked key
//! is still listed, and that the endpoint is scoped and authorized like its neighbours.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::api_key::{ApiKeyKindTag, mint_api_key};
use ironauth_store::{
    ActorRef, ApiKeyOwner, CorrelationId, EnvironmentId, NewApiKey, OrganizationId, Scope,
    ServiceId, TenantId,
};
use serde_json::Value;

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Create an organization through the management API and return its id.
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

/// Issue a key owned by `org` through the store, returning its plaintext and handle.
async fn issue_org_key(
    h: &Harness,
    tenant: &str,
    environment: &str,
    org: &str,
    label: &str,
) -> (String, String) {
    let env = Env::system();
    let scope = scope_of(tenant, environment);
    let org_id = OrganizationId::parse_in_scope(org, &scope).expect("org id");
    let minted = mint_api_key(&env, &scope, ApiKeyKindTag::ApiKey);
    h.db()
        .control_store()
        .scoped(scope)
        .acting(
            ActorRef::service(ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .api_keys()
        .create(
            &env,
            NewApiKey {
                id: &minted.id,
                key_digest: &minted.digest,
                owner: &ApiKeyOwner::Organization(org_id),
                display_name: label,
                expires_at_unix_micros: None,
            },
            now_micros(&env),
            None,
        )
        .await
        .expect("create the key");
    (minted.plaintext, minted.id.to_string())
}

/// The listing carries the handle and NEVER the key or its digest.
///
/// The types make this true (`ApiKeyRecord` has no digest field), so the test is a guard on the
/// types staying that way. A management surface returning verifiers hands a
/// credential-equivalent to everyone allowed to LOOK, which is a strictly larger set than
/// those allowed to USE.
#[tokio::test]
async fn the_listing_carries_no_key_material() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let (plaintext, handle) = issue_org_key(&h, &tenant, &environment, &org, "ci deploy").await;

    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/api-keys");
    let (status, _, body) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "list: {body}");

    assert!(body.contains(&handle), "the non-secret handle is listed");
    assert!(
        !body.contains(&plaintext),
        "the listing returned the KEY: {body}"
    );
    let (_, secret) = plaintext.split_once('~').expect("delimiter");
    assert!(
        !body.contains(secret),
        "the listing returned the key's secret: {body}"
    );
    let digest = ironauth_store::api_key::api_key_digest(&plaintext);
    assert!(
        !body.contains(&digest),
        "the listing returned the digest, which verifies as well as the key does: {body}"
    );
}

/// A revoked key is still listed, carrying its revocation time.
///
/// Same reason migration 0123 retains the row: a rotation's point is that the old key is
/// visible beside the new one, and an operator investigating a leak must be able to tell
/// "revoked at 14:02" from "no such key".
#[tokio::test]
async fn a_revoked_key_is_still_listed_with_its_revocation_time() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k2").await;
    let (_, live) = issue_org_key(&h, &tenant, &environment, &org, "live").await;
    let (_, dead) = issue_org_key(&h, &tenant, &environment, &org, "dead").await;

    let env = Env::system();
    let scope = scope_of(&tenant, &environment);
    h.db()
        .control_store()
        .scoped(scope)
        .acting(
            ActorRef::service(ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .api_keys()
        .revoke(
            &env,
            &ironauth_store::ApiKeyId::parse_in_scope(&dead, &scope).expect("key id"),
            now_micros(&env),
        )
        .await
        .expect("revoke");

    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/api-keys");
    let (status, _, body) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "list: {body}");
    let items = serde_json::from_str::<Value>(&body).expect("json")["items"]
        .as_array()
        .expect("items")
        .clone();
    assert_eq!(items.len(), 2, "both keys are listed: {body}");

    let revoked = items
        .iter()
        .find(|item| item["id"] == dead.as_str())
        .expect("the revoked key is listed");
    assert!(
        revoked["revoked_at_unix_ms"].is_i64(),
        "the revoked key must carry its revocation time: {revoked}"
    );
    let still_live = items
        .iter()
        .find(|item| item["id"] == live.as_str())
        .expect("the live key is listed");
    assert!(
        still_live.get("revoked_at_unix_ms").is_none(),
        "a live key must carry no revocation time: {still_live}"
    );
}

/// Another organization's keys never appear.
#[tokio::test]
async fn one_organizations_listing_never_shows_anothers_keys() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let mine = create_org(&h, &tenant, &environment, "k3").await;
    let theirs = create_org(&h, &tenant, &environment, "k4").await;
    let (_, ours) = issue_org_key(&h, &tenant, &environment, &mine, "ours").await;
    let (_, foreign) = issue_org_key(&h, &tenant, &environment, &theirs, "theirs").await;

    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{mine}/api-keys");
    let (status, _, body) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "list: {body}");
    assert!(body.contains(&ours));
    assert!(
        !body.contains(&foreign),
        "another organization's key leaked into this listing: {body}"
    );
}

/// A credential that is not this deployment's management key is refused, before any listing.
///
/// `h.get` carries the harness's valid management credential; `get_as` carries whatever it is
/// given. A bad bearer must be 401 rather than an empty list, or the endpoint becomes an
/// organization-existence oracle for anyone who can reach it.
#[tokio::test]
async fn a_bad_credential_is_refused_rather_than_shown_an_empty_list() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k5").await;
    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/api-keys");
    let (status, _, body) = h.get_as(&path, "not-a-real-management-key").await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a bad credential must be 401, not an empty listing: {body}"
    );
}

/// Creating returns the key EXACTLY once, and a replay returns the record without it.
///
/// The replay half is the one that matters. `idempotency_keys.response_body` is plaintext
/// retained 24 hours, so storing the created body verbatim would put a live credential there,
/// which is the recoverable copy migration 0123 exists to prevent. The stored body elides the
/// key and replays as 200, following `keys.rs`.
#[tokio::test]
async fn creating_returns_the_key_once_and_a_replay_never_repeats_it() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "ck1").await;
    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/api-keys");
    let request = serde_json::json!({ "display_name": "ci deploy" }).to_string();

    let (status, _, body) = h.post(&path, "create-key-1", &request).await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    let created: Value = serde_json::from_str(&body).expect("json");
    let key = created["key"]
        .as_str()
        .expect("the key is returned once")
        .to_owned();
    assert!(key.starts_with("ira_ak_"), "an API key prefix: {key}");
    assert_eq!(created["key_already_issued"], false);

    // The SAME idempotency key: a replay, carrying no key material and no second credential.
    let (status, _, replay_body) = h.post(&path, "create-key-1", &request).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "replay is 200, not 201: {replay_body}"
    );
    let replay: Value = serde_json::from_str(&replay_body).expect("json");
    assert_eq!(replay["key_already_issued"], true);
    assert!(
        replay.get("key").is_none(),
        "the replay returned the key again: {replay_body}"
    );
    assert_eq!(replay["id"], created["id"], "the replay names the same key");

    // Exactly one key exists, and the listing still never carries the material.
    let (status, _, listed) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "list: {listed}");
    let items = serde_json::from_str::<Value>(&listed).expect("json")["items"]
        .as_array()
        .expect("items")
        .len();
    assert_eq!(items, 1, "the retry minted a second credential: {listed}");
    assert!(
        !listed.contains(&key),
        "the listing carries the key: {listed}"
    );
}

/// The created key actually WORKS: it verifies through the data plane's own path.
///
/// Without this the endpoint could return a well-formed string that authenticates nothing,
/// and every other assertion here would still pass.
#[tokio::test]
async fn the_created_key_verifies_through_the_data_plane() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "ck2").await;
    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/api-keys");
    let (status, _, body) = h
        .post(
            &path,
            "create-key-2",
            &serde_json::json!({ "display_name": "verifies" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    let key = serde_json::from_str::<Value>(&body).expect("json")["key"]
        .as_str()
        .expect("key")
        .to_owned();

    let env = Env::system();
    let resolved = h
        .db()
        .store()
        .scoped(scope_of(&tenant, &environment))
        .api_keys()
        .verify(&key, now_micros(&env))
        .await
        .expect("verify");
    let resolved = resolved.expect("the created key must verify");
    assert_eq!(
        resolved.owner,
        ApiKeyOwner::Organization(
            OrganizationId::parse_in_scope(&org, &scope_of(&tenant, &environment)).expect("org")
        )
    );
}

/// Revoking kills the key immediately and leaves it listed with its revocation time.
#[tokio::test]
async fn revoking_kills_the_key_and_leaves_it_visible() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "rv1").await;
    let base =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/api-keys");
    let (status, _, body) = h
        .post(
            &base,
            "rv-1",
            &serde_json::json!({ "display_name": "doomed" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    let created: Value = serde_json::from_str(&body).expect("json");
    let id = created["id"].as_str().expect("id").to_owned();
    let key = created["key"].as_str().expect("key").to_owned();

    let env = Env::system();
    let scope = scope_of(&tenant, &environment);
    assert!(
        h.db()
            .store()
            .scoped(scope)
            .api_keys()
            .verify(&key, now_micros(&env))
            .await
            .expect("verify")
            .is_some(),
        "the key works before revocation"
    );

    let (status, _, body) = h.delete(&format!("{base}/{id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "revoke: {body}");
    assert!(
        h.db()
            .store()
            .scoped(scope)
            .api_keys()
            .verify(&key, now_micros(&env))
            .await
            .expect("verify")
            .is_none(),
        "the key must stop verifying on the very next request"
    );

    let (_, _, listed) = h.get(&base).await;
    let items = serde_json::from_str::<Value>(&listed).expect("json")["items"].clone();
    let entry = items
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == id.as_str())
        .expect("the revoked key is still listed");
    assert!(
        entry["revoked_at_unix_ms"].is_i64(),
        "a revoked key stays listed with its revocation time: {entry}"
    );
}

/// One organization cannot revoke another's key, even by guessing the handle.
///
/// `revoke` is scoped to the ENVIRONMENT, so without the ownership check the URL's
/// organization would be decorative and a delegated admin confined to org A could kill org B's
/// credentials. The refusal is the uniform not-found, so it is not an existence oracle either.
#[tokio::test]
async fn one_organization_cannot_revoke_anothers_key() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let mine = create_org(&h, &tenant, &environment, "rv2").await;
    let theirs = create_org(&h, &tenant, &environment, "rv3").await;
    let (_, victim) = issue_org_key(&h, &tenant, &environment, &theirs, "victim").await;

    let (status, _, body) = h
        .delete(&format!(
            "/v1/tenants/{tenant}/environments/{environment}/organizations/{mine}/api-keys/{victim}"
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "one organization revoked another's key: {body}"
    );

    let (_, _, listed) = h
        .get(&format!(
            "/v1/tenants/{tenant}/environments/{environment}/organizations/{theirs}/api-keys"
        ))
        .await;
    let entry = serde_json::from_str::<Value>(&listed).expect("json")["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == victim.as_str())
        .expect("the victim key still exists")
        .clone();
    assert!(
        entry.get("revoked_at_unix_ms").is_none(),
        "the refused revoke revoked it anyway: {entry}"
    );
}

/// Rotation is ONE request: the old key dies and the new one works, and a retry does neither
/// again.
///
/// The single-request property is the whole reason `rotate` is a store operation rather than
/// two calls. Exposed as create-then-revoke, a client that crashed between them would leave
/// the old key live beside the new one, which is the failure a rotation performed to contain
/// a leak exists to prevent.
#[tokio::test]
async fn rotation_is_one_request_and_a_retry_issues_nothing_further() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "ro1").await;
    let base =
        format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/api-keys");
    let (status, _, body) = h
        .post(
            &base,
            "ro-1",
            &serde_json::json!({ "display_name": "ci deploy" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    let first: Value = serde_json::from_str(&body).expect("json");
    let old_id = first["id"].as_str().expect("id").to_owned();
    let old_key = first["key"].as_str().expect("key").to_owned();

    let (status, _, body) = h.post(&format!("{base}/{old_id}/rotate"), "ro-2", "").await;
    assert_eq!(status, StatusCode::CREATED, "rotate: {body}");
    let rotated: Value = serde_json::from_str(&body).expect("json");
    let new_key = rotated["key"].as_str().expect("key").to_owned();
    assert_ne!(new_key, old_key, "rotation must issue different material");
    assert_eq!(
        rotated["display_name"], "ci deploy",
        "the replacement inherits the label, so a rotation does not silently rename the \
         integration an operator is watching"
    );

    let env = Env::system();
    let scope = scope_of(&tenant, &environment);
    let repo = h.db().store();
    assert!(
        repo.scoped(scope)
            .api_keys()
            .verify(&old_key, now_micros(&env))
            .await
            .expect("verify")
            .is_none(),
        "the OLD key must be dead, or a rotation to contain a leak left it working"
    );
    assert!(
        repo.scoped(scope)
            .api_keys()
            .verify(&new_key, now_micros(&env))
            .await
            .expect("verify")
            .is_some(),
        "the NEW key must work, or a routine rotation locked the caller out"
    );

    // The retry: same idempotency key, no key material, and no third credential.
    let (status, _, replay) = h.post(&format!("{base}/{old_id}/rotate"), "ro-2", "").await;
    assert_eq!(status, StatusCode::OK, "replay is 200: {replay}");
    let replay_value: Value = serde_json::from_str(&replay).expect("json");
    assert_eq!(replay_value["key_already_issued"], true);
    assert!(
        replay_value.get("key").is_none(),
        "the replay repeated the key: {replay}"
    );

    let (_, _, listed) = h.get(&base).await;
    let items = serde_json::from_str::<Value>(&listed).expect("json")["items"]
        .as_array()
        .expect("items")
        .len();
    assert_eq!(
        items, 2,
        "one original plus one replacement, not three: {listed}"
    );
}
