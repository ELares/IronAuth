// SPDX-License-Identifier: MIT OR Apache-2.0

//! WASM token hook management over HTTP (issue #114, criterion 5).
//!
//! # Why this file exists
//!
//! Review found that nothing observed the deploy PERSISTING anything: the unit tests exercise
//! `validate_component` below HTTP, and the sweeps only ask whether the environment is fenced,
//! so deleting the store write from the handler left the whole suite green. A management
//! surface whose write nothing checks is the same defect this surface was built to close --
//! `token_hooks` having no production writer -- moved one level up.
//!
//! So these drive the real router, and then read the real table.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::{EnvironmentId, Scope, TenantId};
use sqlx::Row as _;

/// The eight-byte preamble of a WebAssembly component: `\0asm` then the layer word.
const COMPONENT: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

/// What `token_hooks.component_bounded` permits, and what the handler's own constant says.
const MAX_COMPONENT_BYTES: usize = 8 * 1024 * 1024;

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn hook_path(tenant: &str, environment: &str, client: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/applications/{client}/token-hook")
}

/// The stored component's length and payload version, read from the table itself.
async fn stored(
    harness: &Harness,
    tenant: &str,
    environment: &str,
    client: &str,
) -> Option<(i32, i32)> {
    sqlx::query(
        "SELECT octet_length(component) AS n, payload_version FROM token_hooks \
         WHERE tenant_id = $1 AND environment_id = $2 AND client_id = $3",
    )
    .bind(tenant)
    .bind(environment)
    .bind(client)
    .fetch_optional(harness.db().owner_pool())
    .await
    .expect("read token_hooks")
    .map(|row| (row.get("n"), row.get("payload_version")))
}

/// The deploy WRITES, the read reports what was written, and the delete REMOVES.
///
/// Every assertion here reads the table or the handler's own response rather than trusting a
/// status code: deleting the store write from the handler must fail this, which is precisely
/// what it did not do before this file existed.
#[tokio::test]
async fn deploy_read_delete_lifecycle_actually_persists() {
    let harness = Harness::start(215).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = hook_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put_bytes(&format!("{path}?payload_version=1"), COMPONENT)
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");

    // THE TABLE, not the response. A handler that returned its own view without writing would
    // satisfy the status and the body and fail here.
    assert_eq!(
        stored(&harness, &tenant, &env, &client).await,
        Some((i32::try_from(COMPONENT.len()).expect("fits"), 1)),
        "the deploy must store the component it was given"
    );

    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "get: {body}");
    assert!(
        body.contains("\"component_bytes\":8") && body.contains("\"payload_version\":1"),
        "the read reports the stored length and version: {body}"
    );

    let (status, _, _) = harness.delete(&path).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete");
    assert_eq!(
        stored(&harness, &tenant, &env, &client).await,
        None,
        "the delete must remove the row, not just answer 204"
    );
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the hook is gone");
}

/// A REDEPLOY replaces in place rather than accumulating rows.
#[tokio::test]
async fn a_redeploy_replaces_the_component() {
    let harness = Harness::start(216).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = format!("{}?payload_version=1", hook_path(&tenant, &env, &client));

    let (status, _, _) = harness.put_bytes(&path, COMPONENT).await;
    assert_eq!(status, StatusCode::OK);

    let mut longer = COMPONENT.to_vec();
    longer.extend_from_slice(b"more of a component");
    let (status, _, body) = harness.put_bytes(&path, &longer).await;
    assert_eq!(status, StatusCode::OK, "redeploy: {body}");

    assert_eq!(
        stored(&harness, &tenant, &env, &client).await,
        Some((i32::try_from(longer.len()).expect("fits"), 1)),
        "one row per client, replaced in place"
    );
}

/// A component AT the documented bound is stored, which is what crosses the handler's constant
/// with the table's CHECK.
///
/// The unit test beside `MAX_COMPONENT_BYTES` reads that constant and never reads the
/// migration, so it would pass with both numbers wrong in the same direction. This one puts
/// exactly that many bytes through the real handler into the real table: if the two disagree,
/// the insert fails.
///
/// It also proves the route's body limit was lifted. axum's default is 2 MiB, so without the
/// `DefaultBodyLimit` layer this is a framework 413 long before the handler or the database
/// sees it.
#[tokio::test]
async fn a_component_at_the_documented_bound_is_stored() {
    let harness = Harness::start(217).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = format!("{}?payload_version=1", hook_path(&tenant, &env, &client));

    let mut at_bound = COMPONENT.to_vec();
    at_bound.resize(MAX_COMPONENT_BYTES, 0);
    let (status, _, body) = harness.put_bytes(&path, &at_bound).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the handler's bound and the table's CHECK must admit the same size: {body}"
    );
    assert_eq!(
        stored(&harness, &tenant, &env, &client).await,
        Some((i32::try_from(MAX_COMPONENT_BYTES).expect("fits"), 1))
    );

    let mut over = at_bound;
    over.push(0);
    let (status, _, body) = harness.put_bytes(&path, &over).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "one byte over is this API's 400, not a framework 413: {body}"
    );
    assert!(
        body.contains("component_too_large"),
        "named refusal: {body}"
    );
}

/// A core MODULE is refused over HTTP, with the named reason, and nothing is stored.
#[tokio::test]
async fn a_core_module_is_refused_over_http_and_stores_nothing() {
    let harness = Harness::start(218).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = format!("{}?payload_version=1", hook_path(&tenant, &env, &client));

    let module: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let (status, _, body) = harness.put_bytes(&path, module).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "core module: {body}");
    assert!(
        body.contains("core_module_not_component"),
        "the refusal names WHICH mistake it is, so an operator checks their build command \
         rather than their bytes: {body}"
    );
    assert_eq!(stored(&harness, &tenant, &env, &client).await, None);
}

/// An unknown payload version is refused with this API's error shape, not the framework's.
///
/// Both spellings: a value this build cannot honour, and a value that is not a number at all.
/// The second is why the query parameter is a `String` -- typed `u32` it would be an axum
/// extractor rejection, which is plain text, carries no `ErrorBody`, and happens before the
/// permission check.
#[tokio::test]
async fn a_bad_payload_version_is_this_apis_refusal() {
    let harness = Harness::start(219).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    for version in ["99", "banana"] {
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version={version}"), COMPONENT)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "version {version}: {body}");
        assert!(
            body.contains("unknown_payload_version"),
            "version {version} must be this API's named refusal: {body}"
        );
        assert_eq!(stored(&harness, &tenant, &env, &client).await, None);
    }
}
