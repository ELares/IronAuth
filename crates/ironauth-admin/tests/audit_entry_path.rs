// SPDX-License-Identifier: MIT OR Apache-2.0

//! The entry path a caller declares reaches the audit row (issue #123 criterion 5).
//!
//! > Every admin MCP mutation appears in the audit stream attributed to the machine identity
//! > with the MCP entry path marked.
//!
//! Two halves, and both are asserted here because either alone is satisfied by a broken build:
//! a header that is recorded but not readable proves nothing, and a column that is always NULL
//! passes any test that only checks the absence case.

mod common;

use axum::http::StatusCode;
use common::Harness;
use sqlx::Row as _;

/// The `entry_path` values recorded for `action` in this scope, oldest first.
///
/// Read straight from the table rather than through an export, so this measures what was
/// STORED. An export could render a value the column does not hold, and the column is what a
/// SIEM query groups by.
async fn entry_paths(
    harness: &Harness,
    tenant: &str,
    environment: &str,
    action: &str,
) -> Vec<Option<String>> {
    sqlx::query(
        "SELECT entry_path FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = $3 \
         ORDER BY occurred_at, id",
    )
    .bind(tenant)
    .bind(environment)
    .bind(action)
    .fetch_all(harness.db().owner_pool())
    .await
    .expect("read the audit rows")
    .iter()
    .map(|row| row.get::<Option<String>, _>("entry_path"))
    .collect()
}

async fn create_user(
    harness: &Harness,
    tenant: &str,
    environment: &str,
    key: &str,
    entry: Option<&str>,
) -> StatusCode {
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let body = serde_json::json!({ "identifier": format!("{key}@example.test"), "password": "a-long-enough-password" })
        .to_string();
    let extra: Vec<(&str, &str)> = match entry {
        Some(value) => vec![("x-ironauth-entry-path", value)],
        None => Vec::new(),
    };
    let (status, _, response) = harness
        .post_with_headers("POST", &path, key, &body, &extra)
        .await;
    assert!(
        status == StatusCode::CREATED,
        "create user ({entry:?}): {status} {response}"
    );
    status
}

#[tokio::test]
async fn a_declared_entry_path_is_recorded_and_a_direct_call_records_none() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("acme", "entry-path-tenant").await;

    // DIRECT FIRST, so the NULL below is a measurement rather than the state of an empty table.
    create_user(&harness, &tenant, &environment, "direct-1", None).await;
    create_user(&harness, &tenant, &environment, "mcp-1", Some("mcp")).await;
    // An UNRECOGNISED value records nothing rather than refusing the call: the header is a
    // provenance hint and not a control, so a client sending a value this version does not know
    // must not lose the ability to manage its own tenant.
    create_user(
        &harness,
        &tenant,
        &environment,
        "unknown-1",
        Some("carrier-pigeon"),
    )
    .await;

    let recorded = entry_paths(&harness, &tenant, &environment, "user.create").await;
    assert_eq!(
        recorded,
        vec![None, Some("mcp".to_owned()), None],
        "the declared path is recorded, a direct call records none, and an unknown value records none"
    );
}
