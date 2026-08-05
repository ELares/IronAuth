// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two security postures the data plane enforced and nothing could set (issues #27, #78).
//!
//! Both were dormant in the same way: a column read by the OIDC data plane, a store setter
//! that writes it, and no production caller. The PAR flag was worse than uncalled, it was
//! UNWRITABLE: no role held UPDATE on `clients.require_pushed_authorization_requests`, so
//! the setter would have been refused by the database had anything called it. Only tests
//! running through the superuser pool ever exercised it, which is exactly why nothing
//! surfaced the gap.
//!
//! What is asserted here is that the value is READ BACK from storage, not echoed: a handler
//! that returned its own request body would satisfy a weaker test and change nothing about
//! what `authorize.rs` reads.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{ActorRef, CorrelationId, EnvironmentId, Scope, ServiceId, TenantId};
use serde_json::Value;

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// Mint a client through the data-plane store, which is the only thing that can.
async fn create_client(h: &Harness, tenant: &str, environment: &str) -> String {
    let env = Env::system();
    h.store()
        .scoped(scope_of(tenant, environment))
        .acting(
            ActorRef::service(ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .clients()
        .create(&env, "acme worker")
        .await
        .expect("create client")
        .to_string()
}

#[tokio::test]
async fn the_par_requirement_round_trips_and_is_read_back_from_the_client_row() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let client = create_client(&h, &tenant, &environment).await;
    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/clients/{client}/par-requirement");

    let (status, _, response) = h
        .put(&path, &serde_json::json!({ "required": true }).to_string())
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        view["client_id"],
        Value::String(client.clone()),
        "{response}"
    );
    assert_eq!(
        view["require_pushed_authorization_requests"],
        Value::Bool(true),
        "{response}"
    );

    // THE STORE HALF, read through the data plane exactly as `authorize.rs` does. The
    // response above could have been rendered from the request; this cannot.
    let stored = h
        .store()
        .scoped(scope_of(&tenant, &environment))
        .clients()
        .get(
            &ironauth_store::ClientId::parse_in_scope(&client, &scope_of(&tenant, &environment))
                .expect("client id"),
        )
        .await
        .expect("read the client");
    assert!(
        stored.require_pushed_authorization_requests,
        "the flag the authorize path gates on is actually set"
    );

    // And it turns back off, so this is a switch rather than a one-way door.
    let (status, _, response) = h
        .put(&path, &serde_json::json!({ "required": false }).to_string())
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let stored = h
        .store()
        .scoped(scope_of(&tenant, &environment))
        .clients()
        .get(
            &ironauth_store::ClientId::parse_in_scope(&client, &scope_of(&tenant, &environment))
                .expect("client id"),
        )
        .await
        .expect("read the client");
    assert!(!stored.require_pushed_authorization_requests, "cleared");
}

#[tokio::test]
async fn the_auto_link_posture_sets_clears_and_refuses_a_token_outside_the_closed_set() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/auto-link-posture");

    for posture in ["off", "verified_to_verified"] {
        let (status, _, response) = h
            .put(
                &path,
                &serde_json::json!({ "posture": posture }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{posture}: {response}");
        assert_eq!(
            serde_json::from_str::<Value>(&response).expect("json")["posture"],
            Value::String(posture.to_owned()),
            "{response}"
        );
    }

    // An explicit null CLEARS the override so the environment inherits the deployment
    // default, which is a different state from either token and has to be reachable.
    let (status, _, response) = h
        .put(&path, &serde_json::json!({ "posture": null }).to_string())
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["posture"],
        Value::Null,
        "{response}"
    );

    // A token outside the closed set is a precise 400 rather than the database CHECK
    // surfacing as a 500, which is the shape this codebase keeps removing.
    let (status, _, response) = h
        .put(
            &path,
            &serde_json::json!({ "posture": "always" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(
        response.contains("verified_to_verified"),
        "the refusal names the accepted set: {response}"
    );
}
