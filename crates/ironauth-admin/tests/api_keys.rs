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
