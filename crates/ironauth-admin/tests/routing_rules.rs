// SPDX-License-Identifier: MIT OR Apache-2.0

//! The routing-rule management surface (issue #96).
//!
//! Migration 0059 shipped the table, the store shipped create and list, and the data
//! plane has routed on them since. None of it was reachable over HTTP: the committed
//! contract published zero paths containing `routing-rules`. An operator could not create
//! a rule, could not see one, and above all could not learn the DNS token to publish.
//!
//! These drive the surface end to end, and the assertions are chosen so that a surface
//! which merely RESPONDS would fail them: what matters is that a domain rule arrives
//! carrying the state and the token, because without those the operator has nothing to
//! act on and the rule can never leave `pending`.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{
    ActorRef, ConnectorCapabilities, ConnectorId, CorrelationId, EnvironmentId, NewConnector,
    NewOrgConnection, OrgConnectionId, OrganizationId, Scope, ServiceId, TenantId,
};
use serde_json::Value;

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn field(body: &str, key: &str) -> Value {
    serde_json::from_str::<Value>(body).expect("json")[key].clone()
}

/// Seed an organization and a connector, bind them, and return the `ocn_` id: the thing a
/// routing rule must point at.
async fn seed_connection(h: &Harness, tenant: &str, environment: &str) -> String {
    let env = Env::system();
    let scope = scope_of(tenant, environment);
    let actor = || ActorRef::service(ServiceId::generate(&env));

    let org = OrganizationId::generate(&env, &scope);
    h.db()
        .control_store()
        .management()
        .acting(actor(), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org, 1_000_000, "Acme Corp", None)
        .await
        .expect("create organization");

    let connector = ConnectorId::generate(&env, &scope);
    h.db().control_store()
        .scoped(scope)
        .acting(actor(), CorrelationId::generate(&env))
        .connectors()
        .create(
            &env,
            &connector,
            1_000_000,
            NewConnector {
                slug: "acme-oidc",
                definition_json: r#"{"connector_id":"acme-oidc","display_name":"Acme","protocol":"oidc","endpoints":{"issuer":"https://issuer.example.com"},"scopes":["openid","email"],"client_id":"ironauth-at-acme"}"#,
                client_secret: b"upstream-secret",
                capabilities: ConnectorCapabilities {
                    refresh: false,
                    groups: false,
                    logout_propagation: false,
                    email_verified_trust: "untrusted",
                },
                enabled: true,
            },
            None,
        )
        .await
        .expect("create connector");

    let binding = OrgConnectionId::generate(&env, &scope);
    h.db()
        .control_store()
        .scoped(scope)
        .acting(actor(), CorrelationId::generate(&env))
        .org_connections()
        .create(
            &env,
            &binding,
            1_000_000,
            NewOrgConnection {
                organization_id: &org,
                connector_id: &connector,
                overlay_min_acr: None,
                max_age_secs: None,
                overlay_min_class: None,
                capture_upstream_tokens: false,
                enabled: true,
            },
        )
        .await
        .expect("create org connection");
    binding.to_string()
}

/// A domain rule is created PENDING and arrives with the token to publish.
///
/// The token is the load-bearing part. Without it in the response the operator has
/// nothing to put in DNS, and a rule that cannot be verified routes nothing forever,
/// which is precisely the state the surface existed to rescue.
#[tokio::test]
async fn creating_a_domain_rule_returns_its_pending_state_and_the_token_to_publish() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let connection = seed_connection(&h, &tenant, &environment).await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/routing-rules");

    let (status, _, body) = h
        .post(
            &base,
            "k-rule",
            &serde_json::json!({
                "kind": "domain",
                "value": "acme.example",
                "org_connection_id": connection,
                "priority": 10,
            })
            .to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create the domain rule: {body}"
    );

    assert_eq!(
        field(&body, "domain_verification_state"),
        Value::String("pending".to_owned()),
        "a domain rule must start unverified: {body}"
    );
    let token = field(&body, "domain_verification_token");
    let token = token
        .as_str()
        .expect("a domain rule must carry the token the operator publishes");
    assert!(
        token.starts_with("ironauth-domain-verification="),
        "the token must be publishable as a TXT record value: {token}"
    );

    // And it is visible afterwards, because an operator who loses the create response
    // must still be able to find out what to publish.
    let (status, _, listed) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "list the rules: {listed}");
    assert!(
        listed.contains(token),
        "the token must remain readable from the list: {listed}"
    );
}

/// An app rule carries no verification ceremony, because it has no domain to prove.
#[tokio::test]
async fn an_app_rule_carries_no_verification_state_or_token() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let connection = seed_connection(&h, &tenant, &environment).await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/routing-rules");

    let (status, _, body) = h
        .post(
            &base,
            "k-app-rule",
            &serde_json::json!({
                "kind": "app",
                "value": "cli_whatever",
                "org_connection_id": connection,
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "create the app rule: {body}");
    assert_eq!(
        field(&body, "domain_verification_state"),
        Value::Null,
        "an app rule has no domain to verify: {body}"
    );
    assert_eq!(
        field(&body, "domain_verification_token"),
        Value::Null,
        "an app rule must not carry a token, which would imply a ceremony that does not \
         apply to it: {body}"
    );
}

/// An unknown selector kind is the caller's error, NAMED rather than defaulted.
///
/// Defaulting to one of the three would route logins somewhere the caller did not ask
/// for, which is the worst possible way to be forgiving.
#[tokio::test]
async fn an_unknown_selector_kind_is_refused_rather_than_defaulted() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let connection = seed_connection(&h, &tenant, &environment).await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/routing-rules");

    let (status, _, body) = h
        .post(
            &base,
            "k-bad-kind",
            &serde_json::json!({
                "kind": "subnet",
                "value": "10.0.0.0/8",
                "org_connection_id": connection,
            })
            .to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown selector kind must be refused: {body}"
    );

    let (_, _, listed) = h.get(&base).await;
    assert!(
        !listed.contains("10.0.0.0/8"),
        "the refused rule must not have been written: {listed}"
    );
}

/// The same domain cannot be claimed twice in one environment (criterion 4).
#[tokio::test]
async fn a_second_claim_on_the_same_domain_is_a_typed_conflict() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let connection = seed_connection(&h, &tenant, &environment).await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/routing-rules");
    let claim = serde_json::json!({
        "kind": "domain",
        "value": "contested.example",
        "org_connection_id": connection,
    })
    .to_string();

    let (status, _, body) = h.post(&base, "k-first", &claim).await;
    assert_eq!(status, StatusCode::CREATED, "the first claim: {body}");

    // A DIFFERENT idempotency key, so this is a genuine second claim rather than a
    // replay of the first, which would legitimately return the original response.
    let (status, _, body) = h.post(&base, "k-second", &claim).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a second claim on the same domain must be a typed conflict, not a 500 and not a \
         silent second route: {body}"
    );
}
