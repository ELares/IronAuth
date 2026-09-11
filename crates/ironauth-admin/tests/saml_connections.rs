// SPDX-License-Identifier: MIT OR Apache-2.0

//! Creating an organization's SAML upstream (issue #140 criterion 1).
//!
//! The store layer is covered in `ironauth-store`. What is worth driving here is what the HTTP
//! layer adds and could get wrong: that the two values a provider's console asks for are
//! DERIVED from this deployment and this connection rather than taken from the caller, and
//! that a base URL carrying a path is refused before it can produce an ACS URL nothing serves.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

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

fn create_body(base_url: &str) -> String {
    serde_json::json!({
        "display_name": "Okta Production",
        "idp_entity_id": "http://www.okta.com/exk1fake",
        "idp_sso_url": "https://acme.okta.com/app/fake/sso/saml",
        "public_base_url": base_url,
    })
    .to_string()
}

#[tokio::test]
async fn the_created_connection_names_this_deployment_and_this_connection() {
    // THE WHOLE POINT OF THE ENDPOINT. `saml_acs` verifies an assertion's `Recipient` against
    // the STORED `acs_url`, and the route is mounted at
    // `/t/{tenant}/e/{environment}/saml/acs/{connection}`. A stored URL whose path is anything
    // else describes a connection that can never complete a sign-in: the provider posts where
    // it was told and nothing answers. Nothing enforced that before, because nothing wrote the
    // column.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "ak-org").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/saml-connections"
    );

    let (status, _, body) = h
        .post(&path, "ak-saml", &create_body("https://auth.example"))
        .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    let view: Value = serde_json::from_str(&body).expect("json");
    let id = view["id"].as_str().expect("an id");

    assert_eq!(
        view["acs_url"].as_str(),
        Some(format!("https://auth.example/t/{tenant}/e/{environment}/saml/acs/{id}").as_str()),
        "the ACS URL must be the route this deployment serves for this connection: {body}"
    );
    assert_eq!(
        view["sp_entity_id"].as_str(),
        Some(
            format!("https://auth.example/t/{tenant}/e/{environment}/saml/metadata/{id}").as_str()
        ),
        "the SP entity id must be this connection's own metadata document: {body}"
    );
    assert_eq!(view["organization_id"].as_str(), Some(org.as_str()));
}

#[tokio::test]
async fn a_base_url_carrying_a_path_is_refused() {
    // A PATH IN THE BASE SILENTLY MOVES THE ACS. `https://auth.example/sso` would store an ACS
    // URL at `/sso/t/.../saml/acs/...`, which nothing serves, and the failure arrives as a
    // provider posting into a 404 long after the call returned 201. Refusing is the only
    // answer that reaches the operator while they can still fix it.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "ak-org").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/saml-connections"
    );

    // EVERY SHAPE THAT MOVES THE DERIVED ACS, not just the one with a slash. The first
    // version refused `/` alone, so a query, a fragment, userinfo and whitespace all passed
    // -- and each of them swallows the path this deployment serves into something else.
    for bad in [
        "https://auth.example/sso",
        "auth.example",
        "ftp://auth.example",
        "https://",
        "https://auth.example?x=1",
        "https://auth.example#frag",
        "https://user:pw@auth.example",
        "https://auth exam.ple",
        "https://auth.example:notaport",
        "https://-auth.example",
    ] {
        let (status, _, body) = h.post(&path, &format!("ak-{bad}"), &create_body(bad)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{bad} was accepted as a public base URL: {body}"
        );
    }

    // THE CONTROLS: well-formed origins still work, so the refusals above are the validation
    // and not an endpoint that refuses everything. A port is legal and so is a trailing slash.
    // A DISTINCT ENTITY ID PER CONTROL: the store allows one live connection per identity
    // provider entity id in a scope, so reusing one would make the second control a 409 and
    // the test would read as a validation failure.
    for (key, good) in [
        ("ak-good", "https://auth.example/"),
        ("ak-port", "https://auth.example:8443"),
        ("ak-http", "http://localhost:3000"),
    ] {
        let body = serde_json::json!({
            "display_name": "Okta Production",
            "idp_entity_id": format!("http://www.okta.com/exk-{key}"),
            "idp_sso_url": "https://acme.okta.com/app/fake/sso/saml",
            "public_base_url": good,
        })
        .to_string();
        let (status, _, body) = h.post(&path, key, &body).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{good} is a legal origin and must be accepted: {body}"
        );
    }
}

#[tokio::test]
async fn an_over_long_field_is_refused_rather_than_answered_with_a_server_error() {
    // Migration 0196 bounds every one of these columns. Without the same bound here the
    // caller's input reaches the CHECK, the store returns a database error, and the handler
    // maps it to a 500 -- so a client mistake looks like a server fault and names no field.
    // The base URL matters twice over: it is a prefix of two DERIVED values that carry their
    // own CHECKs, so an unbounded base violates a constraint on a column the caller never
    // mentioned.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "ak-org").await;
    let path = format!(
        "/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/saml-connections"
    );

    let long = "a".repeat(4096);
    for (field, body) in [
        (
            "display_name",
            serde_json::json!({
                "display_name": long,
                "idp_entity_id": "http://www.okta.com/exk",
                "idp_sso_url": "https://idp.example/sso",
                "public_base_url": "https://auth.example",
            }),
        ),
        (
            "public_base_url",
            serde_json::json!({
                "display_name": "Okta",
                "idp_entity_id": "http://www.okta.com/exk",
                "idp_sso_url": "https://idp.example/sso",
                "public_base_url": format!("https://{long}.example"),
            }),
        ),
    ] {
        let (status, _, response) = h
            .post(&path, &format!("ak-long-{field}"), &body.to_string())
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an over-long {field} must be a 400 naming it, not a 500: {response}"
        );
    }
}
