// SPDX-License-Identifier: MIT OR Apache-2.0

//! The agent vault exchange endpoint (issue #132), over a real database (`DATABASE_URL`).
//!
//! # Why this file exists
//!
//! It did not, and a review said so plainly: the handler that hands an agent somebody else's
//! credential had NO test at all. All THREE entitlement fences, the flag-off posture, the
//! refusals, and the audit row were asserted only by the comments describing them. The store suite next
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

/// A confidential client and its secret, so a token can be minted from it LATER.
///
/// The two are separate on purpose. The agent claims a token carries are set at MINT time,
/// by the gate resolving an agent for the presenting client, so a token minted before the
/// agent row exists carries no `agent_id` at all. Every test that means to reach a fence
/// PAST fence one therefore has to seed the agent first and mint second, and an earlier
/// version of this file did it the other way round: three tests looked like they measured
/// fence two and the connection lookup, and every one of them was refused at fence one.
async fn machine_client(harness: &Harness) -> (ClientId, String) {
    harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await
}

/// Mint a real client-credentials access token for `client`.
///
/// A REAL token, not a hand-built one: every fence below has to be measured against a
/// credential that is otherwise perfectly good, or it passes against a handler with no fence.
async fn machine_token(
    harness: &Harness,
    client: &ClientId,
    secret: &str,
    scope: Option<&str>,
) -> String {
    let client_id = client.to_string();
    let body_form = match scope {
        Some(scope) => form(&[("grant_type", "client_credentials"), ("scope", scope)]),
        None => form(&[("grant_type", "client_credentials")]),
    };
    let (status, _headers, body) = harness
        .token_with_auth(&body_form, Some(&basic_header(&client_id, secret)))
        .await;
    assert_eq!(status, StatusCode::OK, "machine issuance: {body}");
    json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned()
}

/// The `agent_id` claim a token carries, or `None`.
///
/// Read from the token rather than assumed. A test that means to exercise a fence past fence
/// one asserts on this FIRST, so "the fixture reached the state it describes" is measured
/// rather than hoped for.
fn agent_claim(harness: &Harness, client: &ClientId, token: &str) -> Option<String> {
    let verified = ironauth_jose::verify(
        token,
        &harness.access_token_policy(&client.to_string()),
        &common::verify_clock(),
    )
    .expect("at+jwt verifies");
    verified
        .claims()
        .get("agent_id")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
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
        // The CONTROL store, and this line is the whole point: `harness.store()` is the
        // low-privilege application pool, and `.management()` wraps that SAME pool rather
        // than switching to another. Migration 0178 grants INSERT on this table to
        // `ironauth_control` alone, so seeding through the data plane is refused by Postgres
        // and the fixture panics before a request is ever sent. Every other `.management()`
        // call site in this tree goes through `db().control_store()` for exactly this reason.
        .db()
        .control_store()
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

    let (client, secret) = machine_client(&harness).await;
    let bearer = machine_token(&harness, &client, &secret, None).await;
    // The fixture reached the state this test describes: no agent is bound to this client, so
    // the token names none. Asserted rather than assumed, because it is the whole premise.
    assert_eq!(
        agent_claim(&harness, &client, &bearer),
        None,
        "an ordinary machine token names no agent"
    );

    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "RFC 6750 section 3.1 pairs invalid_token with 401"
    );
    assert_eq!(
        json(&body)["error"],
        "invalid_token",
        "and the refusal names no reason a prober could act on"
    );
}

/// Narrow an agent's declared tool set AFTER a token was minted against the old one.
///
/// The only way to isolate fence two. `gate_agent_issuance` refuses a token naming a tool the
/// agent has not declared, so a token that reaches the vault always names tools the agent
/// declared AT MINT TIME. Removing one afterwards is a state an operator reaches, and it is
/// the only state in which fence two decides anything fence three has not already decided.
async fn narrow_declared_tools(harness: &Harness, agent: &AgentPrincipalId, tools: &[&str]) {
    let owned: Vec<String> = tools.iter().map(|tool| (*tool).to_owned()).collect();
    sqlx::query(
        "UPDATE agents /* query-audit-allow: owner test seed */ SET tool_scopes = $1 \
         WHERE id = $2",
    )
    .bind(&owned)
    .bind(agent.to_string())
    .execute(harness.db().owner_pool())
    .await
    .expect("narrow the declared tools");
}

#[tokio::test]
async fn an_undeclared_provider_is_refused_even_though_the_connection_exists() {
    // FENCE TWO, ISOLATED. The connection is stored, so a handler with no declared-set check
    // would hand the credential over.
    //
    // The fixture matters more than the assertion here, and an earlier version got it wrong in
    // a way that made the test unable to tell fence two from fence three: it minted a token
    // scoped `github` and asked for `google`, so deleting EITHER fence left the other one
    // refusing and the test green. It proved only that at least one of the two existed.
    //
    // So: the agent declares `google`, the token is minted naming `google` (which is what puts
    // `google` in the token's granted scope, satisfying fence three), and only THEN is `google`
    // removed from the declared set. Fence three now passes and fence two is the only thing
    // left that can refuse.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google"]).await;
    seed_connection(&harness, &agent, "google").await;
    let bearer = machine_token(&harness, &client, &secret, Some("google")).await;
    assert_eq!(
        agent_claim(&harness, &client, &bearer).as_deref(),
        Some(agent.to_string().as_str()),
        "the token names the agent, so the request reaches the fences"
    );
    narrow_declared_tools(&harness, &agent, &["github"]).await;

    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an agent must not receive a credential for a tool it no longer declares: {body}"
    );
    assert_eq!(json(&body)["error"], "access_denied");
}

#[tokio::test]
async fn a_provider_outside_the_tokens_scope_is_refused_even_though_the_agent_declares_it() {
    // FENCE THREE, ISOLATED, and nothing tested it at all: a grep for its denial reason across
    // the whole repository returned one hit, the source line itself. It is the round-1 fix for
    // "a narrowed token opened the whole vault", and deleting the entire block left every test
    // in this file green.
    //
    // The mirror of the test above. The agent declares BOTH providers and holds a `google`
    // connection, so fence two passes; the token is minted naming only `github`, so `google` is
    // outside the granted scope and fence three is the only thing that can refuse.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google", "github"]).await;
    seed_connection(&harness, &agent, "google").await;
    let bearer = machine_token(&harness, &client, &secret, Some("github")).await;
    assert_eq!(
        agent_claim(&harness, &client, &bearer).as_deref(),
        Some(agent.to_string().as_str()),
        "the token names the agent, so the request reaches the fences"
    );

    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a token narrowed at issuance must not reach a provider outside its scope: {body}"
    );
    assert_eq!(json(&body)["error"], "access_denied");

    // The CONTROL: the same agent, the same connection, a token that DOES name `google`,
    // succeeds. Without it this test passes against a handler that refuses everything.
    let widened = machine_token(&harness, &client, &secret, Some("google")).await;
    let (ok_status, ok_body) = exchange(&harness, Some(&widened), r#"{"provider":"google"}"#).await;
    assert_eq!(
        ok_status,
        StatusCode::OK,
        "and the same request with the provider inside the token's scope succeeds: {ok_body}"
    );
}

#[tokio::test]
async fn a_missing_credential_answers_exactly_as_another_agents_does() {
    // THE ANTI-ORACLE, measured at the connection layer rather than upstream of it.
    //
    // An earlier version of this test used a token that named no agent, so both requests were
    // refused at fence one and the assertion compared two identical refusals produced before
    // any lookup ran. It would have passed against an endpoint that reported, in full detail,
    // which agents hold which providers.
    //
    // Two agents. The asking one DECLARES `google` and holds no connection; the other one
    // holds a `google` connection. If the two answers differ, the endpoint reports whether a
    // provider exists somewhere it cannot be reached from.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (asking_client, asking_secret) = machine_client(&harness).await;
    let asking_agent = seed_agent(&harness, &asking_client, &["google", "github"]).await;

    let (other_client, _other_secret) = machine_client(&harness).await;
    let other_agent = seed_agent(&harness, &other_client, &["google"]).await;
    seed_connection(&harness, &other_agent, "google").await;

    let bearer = machine_token(
        &harness,
        &asking_client,
        &asking_secret,
        Some("google github"),
    )
    .await;
    assert_eq!(
        agent_claim(&harness, &asking_client, &bearer).as_deref(),
        Some(asking_agent.to_string().as_str()),
        "the token names the asking agent, so both requests reach the connection lookup"
    );

    // `google` exists, for somebody else. `github` exists for nobody.
    let (someone_elses, _) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    let (nobodys, _) = exchange(&harness, Some(&bearer), r#"{"provider":"github"}"#).await;
    assert_eq!(
        someone_elses, nobodys,
        "a provider another agent holds and one nobody holds must answer identically, or the \
         endpoint discloses which agents hold which providers"
    );
    assert_ne!(
        someone_elses,
        StatusCode::OK,
        "and neither of them hands anything over"
    );
}

#[tokio::test]
async fn a_malformed_body_is_refused_without_reaching_the_store() {
    // With the flag ON the body parse is a 400 rather than a 404, which is the correct
    // distinction: the surface exists and the request is wrong. It must NOT be a 500, and it
    // must not leave an audit row, because nothing was exchanged.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (client, secret) = machine_client(&harness).await;
    let bearer = machine_token(&harness, &client, &secret, None).await;
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
async fn a_successful_exchange_hands_over_the_credential_and_audits_it() {
    // THE HAPPY PATH, which nothing exercised at all, and the property that makes a vault
    // better than no vault: IronAuth is the custodian of somebody else's credential, and a
    // hand-over with no record is what makes custody worse than not holding it.
    //
    // An earlier version of this test branched on the status it got, which meant it could not
    // fail: a 401 took the `else` arm and asserted that nothing had been handed over, which
    // was true because nothing had been attempted. The status is now asserted.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google"]).await;
    seed_connection(&harness, &agent, "google").await;
    // `scope=google` because the third fence requires the provider to be inside the TOKEN's
    // granted scope as well as inside the agent's declared set.
    let bearer = machine_token(&harness, &client, &secret, Some("google")).await;

    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(status, StatusCode::OK, "the exchange succeeds: {body}");
    let parsed = json(&body);
    assert_eq!(parsed["provider"], "google");
    assert_eq!(
        parsed["access_token"], "downstream-access-token",
        "the DOWNSTREAM credential is what comes back, not the IronAuth token"
    );
    assert!(
        parsed.get("refresh_token").is_none(),
        "and the refresh token, which the caller has no use for, never leaves"
    );

    assert!(
        audit_actions(&harness)
            .await
            .iter()
            .any(|action| action == "agent_vault.exchange"),
        "the hand-over is audited"
    );
}
