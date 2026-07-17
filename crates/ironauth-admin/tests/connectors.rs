// SPDX-License-Identifier: MIT OR Apache-2.0

//! Management-API integration tests for the declarative federation connectors
//! (issue #75, PR A): the immutable-slug guard on update (MEDIUM-1) and the honest
//! `enabled` toggle (LOW-4).

mod common;

use axum::http::StatusCode;
use common::Harness;

/// A minimal, valid connector body for `slug` with a LITERAL upstream client secret
/// (resolved and sealed at rest, never returned by a read). `enabled` is omitted, so
/// it defaults to `true` on create.
fn connector_body(slug: &str, display: &str) -> String {
    serde_json::json!({
        "connector_id": slug,
        "display_name": display,
        "protocol": "oidc",
        "endpoints": { "issuer": "https://issuer.example.com" },
        "scopes": ["openid", "email"],
        "client_id": "ironauth-at-acme",
        "client_secret": "upstream-secret-value"
    })
    .to_string()
}

/// Create a tenant + environment and a connector; return `(tenant, env, connector_id)`.
async fn seed_connector(harness: &Harness) -> (String, String, String) {
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/connectors");
    let (status, _, body) = harness
        .post(
            &path,
            "create-connector-key",
            &connector_body("acme-oidc", "Acme OIDC"),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create connector: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(view["connector_slug"], "acme-oidc");
    assert_eq!(view["enabled"], true, "a new connector defaults to enabled");
    let id = view["id"].as_str().expect("id").to_owned();
    (tenant, environment, id)
}

#[tokio::test]
async fn update_rejects_a_slug_change_and_mutates_nothing() {
    let harness = Harness::start(50).await;
    let (tenant, environment, id) = seed_connector(&harness).await;
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/connectors/{id}");

    // A PUT whose connector_id differs from the stored slug is REJECTED (409) and
    // nothing is mutated: the slug is the immutable natural key.
    let changed = connector_body("acme-oidc-renamed", "Acme OIDC");
    let (status, _, body) = harness.put(&path, &changed).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "slug change must be a 409: {body}"
    );
    assert!(
        !body.contains("upstream-secret-value"),
        "the error must not leak the secret"
    );

    // The connector is untouched: the stored slug and the definition's connector_id
    // both still read the original value.
    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(view["connector_slug"], "acme-oidc");
    assert_eq!(view["definition"]["connector_id"], "acme-oidc");
    assert_eq!(view["definition"]["display_name"], "Acme OIDC");
}

#[tokio::test]
async fn update_preserving_the_slug_succeeds_and_the_enabled_toggle_round_trips() {
    let harness = Harness::start(50).await;
    let (tenant, environment, id) = seed_connector(&harness).await;
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/connectors/{id}");

    // A PUT that preserves the slug and disables the connector succeeds, and the
    // enabled=false round-trips in the view (the toggle is now a real operation).
    let mut body: serde_json::Value =
        serde_json::from_str(&connector_body("acme-oidc", "Acme Renamed")).expect("json");
    body["enabled"] = serde_json::Value::Bool(false);
    let (status, _, response) = harness.put(&path, &body.to_string()).await;
    assert_eq!(status, StatusCode::OK, "preserving-slug update: {response}");
    let view: serde_json::Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["connector_slug"], "acme-oidc");
    assert_eq!(view["definition"]["display_name"], "Acme Renamed");
    assert_eq!(view["enabled"], false, "the connector is now disabled");

    // A re-read confirms the disabled state persisted.
    let (status, _, response) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let view: serde_json::Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["enabled"], false);

    // Re-enabling round-trips the other way.
    let (status, _, response) = harness
        .put(&path, &connector_body("acme-oidc", "Acme Renamed"))
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let view: serde_json::Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["enabled"], true, "the toggle re-enables");
}
