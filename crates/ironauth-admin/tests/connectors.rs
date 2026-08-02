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

/// A connector body whose claim mapping targets `traits`.
fn connector_body_mapping(slug: &str, traits: &serde_json::Value) -> String {
    serde_json::json!({
        "connector_id": slug,
        "display_name": "Mapped",
        "protocol": "oidc",
        "endpoints": { "issuer": "https://issuer.example.com" },
        "scopes": ["openid", "email"],
        "client_id": "ironauth-at-acme",
        "client_secret": "upstream-secret-value",
        "claim_mapping": { "traits": traits }
    })
    .to_string()
}

/// Register and activate a trait schema with an ADMIN-ONLY `risk_score`, through the
/// management surface.
async fn seed_admin_only_schema(harness: &Harness, tenant: &str, environment: &str) {
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/trait-schemas");
    let schema = serde_json::json!({
        "schema": {
            "type": "object",
            "properties": {
                "email": {"type": "string"},
                "risk_score": {"type": "integer", "x-ironauth": {"visibility": "admin"}}
            }
        }
    })
    .to_string();
    let (status, _, created) = harness.post(&path, "schema-create", &schema).await;
    assert_eq!(status, StatusCode::OK, "create schema: {created}");
    let (status, _, activated) = harness
        .post(&format!("{path}/1/activate"), "schema-activate", "")
        .await;
    assert_eq!(status, StatusCode::OK, "activate schema: {activated}");
}

/// A claim mapping that targets an ADMIN-ONLY trait is refused at CONFIG time, on BOTH the
/// create and the update, and stores nothing.
///
/// The connector claim mapping is the other configuration surface that can name a trait, and
/// it had no admin-only gate at ALL:
/// `grep -rn "is_admin_only|admin_only|visibility" crates/ironauth-connector/src/
/// crates/ironauth-admin/src/connectors.rs` returned nothing. MEASURED, an upstream IdP
/// whose mapping named an admin-only trait wrote it onto a local identity on first login.
///
/// The refusal belongs HERE and not only at login: the store's self-service class refuses the
/// write, but a login-time refusal breaks the END USER for a fault only the operator can fix.
/// This is the same posture `validate_signup_form` already takes on the signup-form surface.
#[tokio::test]
async fn a_claim_mapping_targeting_an_admin_only_trait_is_refused_at_config_time() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    seed_admin_only_schema(&harness, &tenant, &environment).await;
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/connectors");

    // A mapping on a USER-visible trait is accepted, so the gate refuses the field and not
    // the feature.
    let ok = connector_body_mapping(
        "acme-ok",
        &serde_json::json!({"email": {"source": ["email"]}}),
    );
    let (status, _, body) = harness.post(&path, "ok-key", &ok).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a mapping on a user-visible trait is accepted: {body}"
    );

    // A mapping that TARGETS the admin-only trait is a 400 naming the offending location in
    // the DEFINITION, and nothing is stored.
    let hostile = connector_body_mapping(
        "acme-hostile",
        &serde_json::json!({
            "email": {"source": ["email"]},
            "risk_score": {"source": ["risk_score"], "required": false}
        }),
    );
    let (status, _, body) = harness.post(&path, "hostile-key", &hostile).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an admin-only mapping target is refused at config time: {body}"
    );
    assert!(
        body.contains("/claim_mapping/traits/risk_score"),
        "the refusal names the offending location in the definition the operator edits: \
         {body}"
    );
    assert!(
        !body.contains("upstream-secret-value"),
        "the refusal must not leak the secret: {body}"
    );
    let (status, _, list) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert!(
        !list.contains("acme-hostile"),
        "the refused create stored nothing: {list}"
    );

    // The UPDATE carries the SAME gate. Without this half, an operator could create a clean
    // connector and then edit an admin-only target into it, and the gate would read as
    // enforced while the update walked around it.
    let view: serde_json::Value = serde_json::from_str(&{
        let (_, _, one) = harness.get(&path).await;
        one
    })
    .expect("json");
    let id = view["items"][0]["id"].as_str().expect("id").to_owned();
    let edit = connector_body_mapping(
        "acme-ok",
        &serde_json::json!({
            "email": {"source": ["email"]},
            "risk_score": {"source": ["risk_score"], "required": false}
        }),
    );
    let (status, _, body) = harness.put(&format!("{path}/{id}"), &edit).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the update carries the same config-time gate: {body}"
    );
    let (status, _, after) = harness.get(&format!("{path}/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert!(
        !after.contains("risk_score"),
        "the refused update mutated nothing: {after}"
    );
}
