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

/// Mint a service-account principal for a fresh client, and answer its id.
async fn seed_service_account(h: &Harness, scope: Scope, label: &str) -> String {
    let env = Env::system();
    let actor = ActorRef::service(ServiceId::generate(&env));
    let client = h
        .db()
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(&env))
        .clients()
        .create(&env, label)
        .await
        .expect("create the client");
    h.db()
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(&env))
        .service_accounts()
        .ensure(&env, &client)
        .await
        .expect("mint the principal")
        .to_string()
}

/// A key created for a service account verifies AS that service account.
///
/// The route hardcodes the owner, and an owner written as `Organization` would still mint a
/// working key: it would authenticate, and it would carry the wrong principal's authority. The
/// only way to see the difference is to verify the key and read back who it resolved to.
#[tokio::test]
async fn a_service_accounts_key_verifies_as_that_service_account() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "sk-tenant").await;
    let scope = scope_of(&tenant, &environment);
    let principal = seed_service_account(&h, scope, "a machine client").await;
    let base = format!(
        "/v1/tenants/{tenant}/environments/{environment}/service-accounts/{principal}/api-keys"
    );

    let (status, _, body) = h
        .post(
            &base,
            "sk-create",
            &serde_json::json!({ "display_name": "ci runner" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    let key = serde_json::from_str::<Value>(&body).expect("json")["key"]
        .as_str()
        .expect("the 201 carries the key exactly once")
        .to_owned();

    let env = Env::system();
    let resolved = h
        .db()
        .store()
        .scoped(scope)
        .api_keys()
        .verify(&key, now_micros(&env))
        .await
        .expect("verify")
        .expect("the created key must verify");
    assert_eq!(
        resolved.owner,
        ApiKeyOwner::ServiceAccount(
            ironauth_store::ServiceAccountId::parse_in_scope(&principal, &scope)
                .expect("principal id")
        ),
        "the key authenticates as the wrong principal"
    );
}

/// One service account's key is invisible and untouchable from another's path.
///
/// The store addresses a key by its handle alone and is environment scoped, so nothing below
/// the handler distinguishes these two principals. Without the ownership check the path
/// segment would be decorative: naming any handle under any principal would work.
#[tokio::test]
async fn one_service_account_cannot_see_or_kill_anothers_key() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "sk2-tenant").await;
    let scope = scope_of(&tenant, &environment);
    let mine = seed_service_account(&h, scope, "my machine").await;
    let theirs = seed_service_account(&h, scope, "their machine").await;
    let root = format!("/v1/tenants/{tenant}/environments/{environment}/service-accounts");

    let (status, _, body) = h
        .post(
            &format!("{root}/{theirs}/api-keys"),
            "sk2-create",
            &serde_json::json!({ "display_name": "theirs" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    let their_key = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let (status, _, body) = h.get(&format!("{root}/{mine}/api-keys")).await;
    assert_eq!(status, StatusCode::OK, "list: {body}");
    let items = serde_json::from_str::<Value>(&body).expect("json")["items"]
        .as_array()
        .expect("items")
        .len();
    assert_eq!(items, 0, "another principal's key appeared in my listing");

    let (status, _, body) = h
        .delete(&format!("{root}/{mine}/api-keys/{their_key}"))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "one service account revoked another's key: {body}"
    );

    let (status, _, body) = h
        .post(
            &format!("{root}/{mine}/api-keys/{their_key}/rotate"),
            "sk2-rotate",
            "",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "one service account rotated another's key: {body}"
    );

    // And the key it could not reach is still live for its real owner, so the refusals above
    // were refusals rather than a slower way of destroying it.
    let (status, _, body) = h.get(&format!("{root}/{theirs}/api-keys")).await;
    assert_eq!(status, StatusCode::OK, "list: {body}");
    let theirs_view = serde_json::from_str::<Value>(&body).expect("json");
    assert_eq!(theirs_view["items"].as_array().expect("items").len(), 1);
    assert!(
        theirs_view["items"][0]["revoked_at_unix_ms"].is_null(),
        "the key the other principal could not reach was revoked anyway: {theirs_view}"
    );
}

/// A well-formed principal id that names nothing is the uniform not-found.
///
/// Both halves matter and they fail differently. Without the existence check the LISTING would
/// answer 200 with an empty array, which tells a caller "this principal exists and holds no
/// keys" about a principal that does not exist; and the CREATE would reach the insert and come
/// back as the foreign key's 500, which is an internal error for what is a caller mistake.
#[tokio::test]
async fn a_service_account_that_does_not_exist_is_the_uniform_not_found() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "sk3-tenant").await;
    let scope = scope_of(&tenant, &environment);
    // Well formed and in this scope, so nothing before the existence check refuses it.
    let absent = ironauth_store::ServiceAccountId::generate(&Env::system(), &scope);
    let base = format!(
        "/v1/tenants/{tenant}/environments/{environment}/service-accounts/{absent}/api-keys"
    );

    let (status, _, body) = h.get(&base).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "listing an absent principal answered something other than not-found: {body}"
    );

    let (status, _, body) = h
        .post(
            &base,
            "sk3-create",
            &serde_json::json!({ "display_name": "orphan" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "minting a key for an absent principal answered something other than not-found: {body}"
    );
}

/// Seed a user and answer its id.
async fn seed_user(h: &Harness, tenant: &str, environment: &str, handle: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let body = serde_json::json!({ "identifier": handle }).to_string();
    let (status, _, response) = h.post(&base, handle, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create user: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// A personal access token carries the PUBLISHED `ira_pat_` prefix, not the API-key one.
///
/// This is the assertion the whole surface turns on, and no status code can make it. Minting
/// `ApiKeyKindTag::ApiKey` for a user produces a token that authenticates perfectly, resolves
/// to the right owner, and passes every other test here. It differs only in its prefix, and
/// `docs/design/TOKEN-FORMATS.md` publishes that prefix for operators to register with a secret
/// scanner. Get it wrong and the scanner goes blind to the credential most likely to end up in
/// a developer's dotfile.
///
/// Asserted against the constants rather than against literals, so it links to the same pair
/// `the_published_scanner_regex_matches_every_generated_key_kind` checks the document against.
/// The two together are what make the published regex true of what the product issues.
#[tokio::test]
async fn a_personal_access_token_carries_the_published_pat_prefix() {
    use ironauth_store::api_key::{API_KEY_PREFIX, PERSONAL_ACCESS_TOKEN_PREFIX};

    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "pat-tenant").await;
    let user = seed_user(&h, &tenant, &environment, "pat-user@example.test").await;
    let base = format!(
        "/v1/tenants/{tenant}/environments/{environment}/users/{user}/personal-access-tokens"
    );

    let (status, _, body) = h
        .post(
            &base,
            "pat-create",
            &serde_json::json!({ "display_name": "laptop" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    let token = serde_json::from_str::<Value>(&body).expect("json")["key"]
        .as_str()
        .expect("the 201 carries the token exactly once")
        .to_owned();

    assert!(
        token.starts_with(PERSONAL_ACCESS_TOKEN_PREFIX),
        "a personal access token was minted without the published PAT prefix, so the scanner \
         regex operators register would not match it: {token}"
    );
    assert!(
        !token.starts_with(API_KEY_PREFIX),
        "the token carries the API-key prefix, which is the exact confusion the two prefixes \
         exist to prevent: {token}"
    );

    // And it is a real credential, not merely a well-shaped string.
    let env = Env::system();
    let scope = scope_of(&tenant, &environment);
    let resolved = h
        .db()
        .store()
        .scoped(scope)
        .api_keys()
        .verify(&token, now_micros(&env))
        .await
        .expect("verify")
        .expect("the created token must verify");
    assert_eq!(
        resolved.owner,
        ApiKeyOwner::User(ironauth_store::UserId::parse_in_scope(&user, &scope).expect("user id")),
        "the token authenticates as the wrong principal"
    );
}

/// One user's personal access token is invisible and untouchable from another's path.
#[tokio::test]
async fn one_user_cannot_see_or_kill_anothers_personal_access_token() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "pat2-tenant").await;
    let mine = seed_user(&h, &tenant, &environment, "mine@example.test").await;
    let theirs = seed_user(&h, &tenant, &environment, "theirs@example.test").await;
    let root = format!("/v1/tenants/{tenant}/environments/{environment}/users");

    let (status, _, body) = h
        .post(
            &format!("{root}/{theirs}/personal-access-tokens"),
            "pat2-create",
            &serde_json::json!({ "display_name": "theirs" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    let their_token = serde_json::from_str::<Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let (status, _, body) = h
        .get(&format!("{root}/{mine}/personal-access-tokens"))
        .await;
    assert_eq!(status, StatusCode::OK, "list: {body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json")["items"]
            .as_array()
            .expect("items")
            .len(),
        0,
        "another user's token appeared in my listing"
    );

    let (status, _, body) = h
        .delete(&format!(
            "{root}/{mine}/personal-access-tokens/{their_token}"
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "one user revoked another's personal access token: {body}"
    );

    // The token they could not reach is still live for its owner, so that was a refusal and
    // not a slower way of destroying it.
    let (status, _, body) = h
        .get(&format!("{root}/{theirs}/personal-access-tokens"))
        .await;
    assert_eq!(status, StatusCode::OK, "list: {body}");
    let view = serde_json::from_str::<Value>(&body).expect("json");
    assert_eq!(view["items"].as_array().expect("items").len(), 1);
    assert!(
        view["items"][0]["revoked_at_unix_ms"].is_null(),
        "the token the other user could not reach was revoked anyway: {view}"
    );
}

/// A well-formed user id that names nobody is the uniform not-found.
///
/// The same pair of failures the service-account surface has, and worth asserting separately
/// on each because each surface resolves its owner its own way. Without the check the LISTING
/// answers 200 with an empty array, telling a caller "this user exists and holds no tokens"
/// about a user who does not exist; and the CREATE reaches the insert and comes back as the
/// foreign key's 500, an internal error for what is a caller mistake.
#[tokio::test]
async fn a_user_who_does_not_exist_is_the_uniform_not_found_for_tokens() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "pat3-tenant").await;
    let scope = scope_of(&tenant, &environment);
    // Well formed and in this scope, so nothing before the existence check refuses it.
    let absent = ironauth_store::UserId::generate(&Env::system(), &scope);
    let base = format!(
        "/v1/tenants/{tenant}/environments/{environment}/users/{absent}/personal-access-tokens"
    );

    let (status, _, body) = h.get(&base).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "listing an absent user's tokens answered something other than not-found: {body}"
    );

    let (status, _, body) = h
        .post(
            &base,
            "pat3-create",
            &serde_json::json!({ "display_name": "orphan" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "minting a token for an absent user answered something other than not-found: {body}"
    );
}

/// Everything queued for the webhook fan-out in this scope.
async fn queued_events(h: &Harness, scope: ironauth_store::Scope) -> Vec<Value> {
    use std::time::Duration;

    h.db()
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &Env::system(),
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim webhook events")
        .into_iter()
        .map(|message| message.payload)
        .collect()
}

/// Revoking an ORGANIZATION api key announces it, over the real management route.
///
/// `revoke_with_event` shipped with #875 and the organization-scoped handler never called it,
/// so an operator revoking an organization credential produced an audit row and NO event
/// while the personal-access-token path produced both. The store method was already covered;
/// what was missing was the handler passing an event to it, which is why this test drives the
/// HTTP route rather than the repository.
///
/// The SAME `api_key.revoked` type the personal path emits: an organization key and a
/// personal one are the same credential kind under different owners, and a second type for
/// the owner would make every consumer subscribe twice to learn one fact.
#[tokio::test]
async fn revoking_an_organization_api_key_announces_it() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k-evt").await;
    let (_, key_id) = issue_org_key(&h, &tenant, &environment, &org, "to be revoked").await;
    let scope = scope_of(&tenant, &environment);
    let management = h.create_key(&tenant, &environment, "ci", "k-mgmt").await;

    // Everything the fixture's own provisioning enqueued, discarded, so the count below
    // measures the revoke and nothing else.
    let _ = queued_events(&h, scope).await;

    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/api-keys/{key_id}"
    );
    let (status, _, body) = h.delete_as(&path, &management).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "revoke: {body}");

    let events = queued_events(&h, scope).await;
    assert_eq!(events.len(), 1, "the revocation enqueues exactly one event");
    assert_eq!(events[0]["type"], "api_key.revoked");
    assert_eq!(events[0]["payload"]["api_key_id"], key_id);
    ironauth_store::event_catalog::validate_event(&events[0])
        .expect("the envelope validates against the registry the fan-out enforces");
}
