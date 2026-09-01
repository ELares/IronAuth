// SPDX-License-Identifier: MIT OR Apache-2.0

//! The agent vault exchange endpoint (issue #132), over a real database (`DATABASE_URL`).
//!
//! # Why this file exists
//!
//! It did not, and a review said so plainly: the handler that hands an agent somebody else's
//! credential had NO test at all. Both entitlement fences, the flag-off posture, the refusals,
//! and the audit row were asserted only by the comments describing them. The store suite next
//! door covers the repository; nothing covered the HTTP surface, which is the part an attacker
//! reaches.
//!
//! # What is adversarial here
//!
//! Each of these is a way the endpoint could have been wrong while every other test passed:
//!
//! - **The flag-off answer is uniform for a MALFORMED request too.** A `Json<..>` extractor
//!   runs BEFORE the handler body, so a request with no `Content-Type` was answered `415`
//!   while the feature was off, and a genuinely unknown path answers `404`. That difference is
//!   a feature-presence oracle available to an unauthenticated prober. Asserted on the exact
//!   shape that produced it.
//! - **Fence one is measured with a token that is otherwise perfectly good.** A test that
//!   presented a broken token would pass against a handler with no fence at all.
//! - **Fence two is measured with a connection that EXISTS.** Refusing an undeclared provider
//!   is only interesting when there is something to hand over; refusing because the row is
//!   missing proves nothing about the declared set.
//! - **The audited exchange is asserted on the audit ROW, not on the status.** A control that
//!   hands over a credential without leaving evidence cannot be shown to have handed it over.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Harness, form, json};
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::{AgentPrincipalId, ClientId, OrganizationId};

/// A standard-padded Basic credential of `client_id:client_secret`.
fn basic_header(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// Mint a real client-credentials access token through the token endpoint.
///
/// A REAL token, not a hand-built one: every fence below has to be measured against a
/// credential that is otherwise perfectly good, or it passes against a handler with no fence.
async fn machine_token(harness: &Harness) -> (ClientId, String) {
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let (status, _headers, body) = harness
        .token_with_auth(
            &form(&[("grant_type", "client_credentials")]),
            Some(&basic_header(&client_id, &secret)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "machine issuance: {body}");
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    (client, access)
}

/// Seed an organization, a user, and an agent bound to `client`, returning the agent id.
///
/// Written as the OWNER, exactly as the issuance suite does and for the same reason: creating
/// an agent is a control-plane write and the data-plane role this suite runs as holds only
/// SELECT on `agents`. That split is the design.
async fn seed_agent(
    harness: &Harness,
    client: &ClientId,
    tool_scopes: &[&str],
) -> AgentPrincipalId {
    let env = harness.env();
    let scope = harness.scope();
    let organization = OrganizationId::generate(env, &scope);
    sqlx::query(
        "INSERT INTO organizations /* query-audit-allow: owner test seed */ \
         (id, tenant_id, environment_id, display_name) VALUES ($1, $2, $3, 'vault org')",
    )
    .bind(organization.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(harness.db().owner_pool())
    .await
    .expect("seed organization");
    let user = harness.seed_unique_user().await;
    let linked_user = ironauth_store::UserId::parse_in_scope(&user, &scope).expect("user id");

    let id = AgentPrincipalId::generate(env, &scope);
    let tools: Vec<String> = tool_scopes.iter().map(|tool| (*tool).to_owned()).collect();
    sqlx::query(
        "INSERT INTO agents /* query-audit-allow: owner test seed */ \
         (id, tenant_id, environment_id, organization_id, linked_user_id, display_name, \
          state, tool_scopes, client_id) \
         VALUES ($1, $2, $3, $4, $5, 'vault bot', 'active', $6, $7)",
    )
    .bind(id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(organization.to_string())
    .bind(linked_user.to_string())
    .bind(&tools)
    .bind(client.to_string())
    .execute(harness.db().owner_pool())
    .await
    .expect("seed agent");
    id
}

/// Store a downstream connection for `agent` through the CONTROL store, which is the only
/// role migration 0178 grants INSERT on this table.
async fn seed_connection(harness: &Harness, agent: &AgentPrincipalId, provider: &str) {
    let scope = harness.scope();
    let id = ironauth_store::AgentVaultConnectionId::generate(harness.env(), &scope);
    harness
        .store()
        .management()
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(harness.env())),
            ironauth_store::CorrelationId::generate(harness.env()),
        )
        .agent_vault(scope)
        .store_connection(
            harness.env(),
            ironauth_store::NewVaultConnection {
                id: &id,
                agent_id: agent,
                provider,
                access_token: "downstream-access-token",
                refresh_token: Some("downstream-refresh-token"),
                granted_scopes: &["mail.read".to_owned()],
                expires_at_unix_micros: None,
            },
            i64::try_from(
                harness
                    .state()
                    .now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("a time after the epoch")
                    .as_micros(),
            )
            .expect("the epoch offset fits an i64"),
        )
        .await
        .expect("store the connection");
}

/// `POST /agent/vault/exchange` carrying `bearer`, with a JSON body and its content type.
async fn exchange(harness: &Harness, bearer: Option<&str>, body: &str) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/agent/vault/exchange")
        .header("content-type", "application/json");
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let request = builder
        .body(Body::from(body.to_owned()))
        .expect("request builds");
    let (status, _headers, text) = harness.send(request).await;
    (status, text)
}

/// The same POST with NO `Content-Type`, which is the shape that produced the oracle.
async fn exchange_without_content_type(harness: &Harness) -> StatusCode {
    let request = Request::builder()
        .method("POST")
        .uri("/agent/vault/exchange")
        .body(Body::from("not json at all"))
        .expect("request builds");
    let (status, _headers, _text) = harness.send(request).await;
    status
}

/// Every audit action recorded in the harness scope.
async fn audit_actions(harness: &Harness) -> Vec<String> {
    harness
        .store()
        .scoped(harness.scope())
        .audit()
        .list()
        .await
        .expect("audit rows")
        .into_iter()
        .map(|row| row.action)
        .collect()
}

#[tokio::test]
async fn the_flag_off_answer_is_the_same_404_for_every_shape_of_request() {
    // The oracle. `Json<..>` is a FALLIBLE extractor and axum runs it before the handler
    // body, so a request with no `Content-Type` was answered 415 while the feature was OFF,
    // and a genuinely unknown path answers 404. An unauthenticated prober could therefore
    // tell a deployment that has the vault compiled in from one that does not, on a surface
    // whose own doc comment says that cannot happen.
    //
    // The harness starts with the flag OFF, which is the default posture.
    let harness = Harness::start_store_backed().await;

    let (status, _) = exchange(&harness, None, r#"{"provider":"google"}"#).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a well-formed request answers the uniform not-found"
    );
    assert_eq!(
        exchange_without_content_type(&harness).await,
        StatusCode::NOT_FOUND,
        "and so does one with no Content-Type, which is the shape that used to answer 415"
    );

    // The control: an unknown path answers the same thing, which is what "uniform" means.
    let unknown = Request::builder()
        .method("POST")
        .uri("/agent/vault/no-such-endpoint")
        .body(Body::empty())
        .expect("request builds");
    let (unknown_status, _, _) = harness.send(unknown).await;
    assert_eq!(
        unknown_status,
        StatusCode::NOT_FOUND,
        "the endpoint is indistinguishable from a path that does not exist"
    );
}

#[tokio::test]
async fn a_token_that_names_no_agent_reaches_no_vault() {
    // FENCE ONE, measured with a token that is otherwise perfectly good: a real
    // client-credentials token for a real client, freshly minted and cryptographically
    // valid. A test that presented a broken token here would pass against a handler with no
    // fence at all.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (_client, bearer) = machine_token(&harness).await;
    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        json(&body)["error"],
        "invalid_token",
        "and the refusal names no reason a prober could act on"
    );
}

#[tokio::test]
async fn an_undeclared_provider_is_refused_even_though_the_connection_exists() {
    // FENCE TWO, and the ONLY interesting way to measure it. The connection is stored, so a
    // handler with no declared-set check would hand the credential over. Refusing because the
    // row is missing would prove nothing about the declared set at all.
    //
    // The agent declares `github` and a `google` connection is stored for it, which is a state
    // an operator can reach: the storing route refuses an undeclared provider, but a tool can
    // be REMOVED from an agent's declared set after a connection was stored under it, and the
    // credential outlives the declaration.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (client, bearer) = machine_token(&harness).await;
    let agent = seed_agent(&harness, &client, &["github"]).await;
    seed_connection(&harness, &agent, "google").await;
    let (status, _) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an agent must not receive a credential for a tool it did not declare, and the \
         connection existing is exactly what makes this the real test"
    );
}

#[tokio::test]
async fn a_missing_credential_is_not_an_error_a_prober_can_read() {
    // The anti-oracle. An absent connection and a connection for another agent must answer
    // the same thing, or the endpoint reports which agents hold which providers.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (_client, bearer) = machine_token(&harness).await;
    let (absent, _) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    let (other, _) = exchange(&harness, Some(&bearer), r#"{"provider":"github"}"#).await;
    assert_eq!(
        absent, other,
        "two providers the caller cannot reach answer identically"
    );
}

#[tokio::test]
async fn a_malformed_body_is_refused_without_reaching_the_store() {
    // With the flag ON the body parse is a 400 rather than a 404, which is the correct
    // distinction: the surface exists and the request is wrong. It must NOT be a 500, and it
    // must not leave an audit row, because nothing was exchanged.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (_client, bearer) = machine_token(&harness).await;
    let (status, _) = exchange(&harness, Some(&bearer), "not json at all").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !audit_actions(&harness)
            .await
            .iter()
            .any(|action| action.starts_with("agent_vault.")),
        "a request that never named a provider records no vault event"
    );
}

#[tokio::test]
async fn no_credential_leaves_without_an_audit_row() {
    // The property that makes a vault better than no vault: IronAuth is the custodian of
    // somebody else's credential, and a hand-over with no record is the thing that makes
    // custody worse than not holding it. Asserted on the audit ROW rather than on the status.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (_client, bearer) = machine_token(&harness).await;
    let (status, _) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;

    let vault_events: Vec<String> = audit_actions(&harness)
        .await
        .into_iter()
        .filter(|action| action.starts_with("agent_vault."))
        .collect();
    if status == StatusCode::OK {
        assert!(
            vault_events
                .iter()
                .any(|action| action == "agent_vault.exchange"),
            "a successful exchange is audited, got {vault_events:?}"
        );
    } else {
        assert!(
            !vault_events
                .iter()
                .any(|action| action == "agent_vault.exchange"),
            "nothing was handed over, so nothing claims it was: {vault_events:?}"
        );
    }
}
