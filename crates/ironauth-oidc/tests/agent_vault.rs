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
use ironauth_fetch::{TestTlsIdentity, TestTlsTarget};
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
    seed_connection_requiring(harness, agent, provider, false).await;
}

/// The same, with the operator's SENSITIVITY decision spelled out.
async fn seed_connection_requiring(
    harness: &Harness,
    agent: &AgentPrincipalId,
    provider: &str,
    requires_approval: bool,
) {
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
                requires_approval: Some(requires_approval),
                refresh: None,
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

// ===========================================================================
// The approval gate (issue #132, criterion 4).
//
// Every test below exists because a review found the property it pins was false, and the
// fixtures are shaped by what those failures needed: a connection the OPERATOR marked
// sensitive (the agent used to decide that by naming a field), and an action digest that
// binds an approval to one request (an approval used to authorize every action at that
// provider until it expired).

/// Decide an approval as the control plane would, returning nothing.
async fn decide(harness: &Harness, approval: &str, approve: bool, details: Option<&str>) {
    let scope = harness.scope();
    let id = ironauth_store::AgentVaultApprovalId::parse_in_scope(approval, &scope)
        .expect("an approval id");
    let agreed: Option<serde_json::Value> =
        details.map(|raw| serde_json::from_str(raw).expect("the approver's details parse"));
    harness
        .db()
        .control_store()
        .management()
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(harness.env())),
            ironauth_store::CorrelationId::generate(harness.env()),
        )
        .agent_vault_approvals_acting(scope)
        .decide(
            harness.env(),
            &id,
            approve,
            agreed.as_ref(),
            "operator-under-test",
            now_micros(harness),
        )
        .await
        .expect("decide the approval");
}

/// The harness clock as epoch microseconds.
fn now_micros(harness: &Harness) -> i64 {
    i64::try_from(
        harness
            .state()
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a time after the epoch")
            .as_micros(),
    )
    .expect("the epoch offset fits an i64")
}

/// An agent, a sensitive connection, and a token that names it.
async fn sensitive_fixture(harness: &Harness) -> (ClientId, String, AgentPrincipalId) {
    let (client, secret) = machine_client(harness).await;
    let agent = seed_agent(harness, &client, &["google"]).await;
    seed_connection_requiring(harness, &agent, "google", true).await;
    let bearer = machine_token(harness, &client, &secret, Some("google")).await;
    assert_eq!(
        agent_claim(harness, &client, &bearer).as_deref(),
        Some(agent.to_string().as_str()),
        "the token names the agent, so the request reaches the gate"
    );
    (client, bearer, agent)
}

/// The action a sensitive exchange states, and a materially different one.
const ACTION_SMALL: &str =
    r#"{"provider":"google","authorization_details":[{"type":"payment","amount":1}]}"#;
const ACTION_LARGE: &str =
    r#"{"provider":"google","authorization_details":[{"type":"payment","amount":1000000}]}"#;

#[tokio::test]
async fn a_sensitive_exchange_raises_an_approval_and_issues_nothing() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    let (_client, bearer, _agent) = sensitive_fixture(&harness).await;

    let (status, body) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "it blocks rather than issues: {body}"
    );
    let parsed = json(&body);
    assert_eq!(parsed["status"], "approval_pending");
    assert!(
        parsed["approval_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("ava_")),
        "and hands back something to poll: {body}"
    );
    assert!(
        parsed.get("access_token").is_none(),
        "no credential leaves while a human has not decided"
    );

    // Asking again finds the SAME approval rather than raising a second one.
    let (again, again_body) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    assert_eq!(again, StatusCode::ACCEPTED);
    assert_eq!(
        json(&again_body)["approval_id"],
        parsed["approval_id"],
        "a second ask polls the first request rather than raising another"
    );
}

#[tokio::test]
async fn a_denied_agent_cannot_get_the_credential_by_dropping_the_field() {
    // THE BYPASS. The gate used to run when the REQUEST named `authorization_details`, so the
    // agent chose whether to enter it: a denied agent re-sent the same exchange without the
    // field and received the identical credential. "Denial issues no tokens" was true of the
    // gate's interior and false of the endpoint.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    let (_client, bearer, _agent) = sensitive_fixture(&harness).await;

    let (_, raised) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    let approval = json(&raised)["approval_id"]
        .as_str()
        .expect("an approval")
        .to_owned();
    decide(&harness, &approval, false, None).await;

    let (denied, _) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    assert_eq!(denied, StatusCode::FORBIDDEN, "the denial stands");

    // The bypass itself: same exchange, field omitted.
    let (bypass, bypass_body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_ne!(
        bypass,
        StatusCode::OK,
        "omitting authorization_details must not hand over the credential: {bypass_body}"
    );
    assert!(
        json(&bypass_body).get("access_token").is_none(),
        "and no token is in the body either: {bypass_body}"
    );
}

#[tokio::test]
async fn an_approval_authorizes_the_action_it_was_raised_for_and_no_other() {
    // Approve a payment of one; exchange for a payment of a million. The approval used to be
    // keyed on (agent, provider) alone, so the second request matched the first's approval and
    // was issued -- which made the approver's narrowing, in migration 0179's own word,
    // decorative.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    let (_client, bearer, _agent) = sensitive_fixture(&harness).await;

    let (_, raised) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    let approval = json(&raised)["approval_id"]
        .as_str()
        .expect("an approval")
        .to_owned();
    decide(&harness, &approval, true, None).await;

    // The approved action succeeds. This is the control: without it the assertion below passes
    // against a gate that refuses everything.
    let (approved, approved_body) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    assert_eq!(
        approved,
        StatusCode::OK,
        "the approved action is issued: {approved_body}"
    );
    assert_eq!(
        json(&approved_body)["access_token"],
        "downstream-access-token",
        "and it is the downstream credential"
    );

    // A DIFFERENT action is not covered by it.
    let (other, other_body) = exchange(&harness, Some(&bearer), ACTION_LARGE).await;
    assert_eq!(
        other,
        StatusCode::ACCEPTED,
        "a different action raises its OWN approval rather than riding the first: {other_body}"
    );
    assert_ne!(
        json(&other_body)["approval_id"].as_str(),
        Some(approval.as_str()),
        "and it is a different approval"
    );
}

/// The response reports what the APPROVER agreed to, not an echo of what was asked.
///
/// THE LIMIT OF THIS, stated because the test name used to over-claim it: what the approver
/// narrowed to is what the RESPONSE says. The `access_token` handed back is the downstream
/// credential exactly as the provider issued it, and nothing binds that credential to the
/// narrowed set -- the provider knows nothing about this approval. Constraining the token
/// itself would need a downstream that accepts RFC 9396 details on a token exchange, which is
/// graduation work and is recorded as such rather than implied by a test name.
#[tokio::test]
async fn an_approvers_narrowed_set_is_what_the_response_reports() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    let (_client, bearer, _agent) = sensitive_fixture(&harness).await;

    let (_, raised) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    let approval = json(&raised)["approval_id"]
        .as_str()
        .expect("an approval")
        .to_owned();
    decide(
        &harness,
        &approval,
        true,
        Some(r#"[{"type":"payment","amount":1,"currency":"GBP"}]"#),
    )
    .await;

    let (status, body) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        json(&body)["authorization_details"][0]["currency"],
        "GBP",
        "the response carries what the APPROVER agreed to, not an echo of the request: {body}"
    );
}

#[tokio::test]
async fn an_ordinary_connection_is_unaffected_by_the_gate() {
    // The control on the whole feature. `requires_approval` defaults false, so a connection an
    // operator did not mark sensitive behaves exactly as it did before the gate existed --
    // including when the agent names authorization details, which is now advisory rather than
    // the trigger.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google"]).await;
    seed_connection_requiring(&harness, &agent, "google", false).await;
    let bearer = machine_token(&harness, &client, &secret, Some("google")).await;

    let (status, body) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an ordinary connection issues without an approval: {body}"
    );
}

#[tokio::test]
async fn a_sensitive_connection_refuses_a_request_that_states_no_action() {
    // There is nothing for an approver to decide and nothing to bind an approval to, so this
    // is a bad request rather than a bypass or a blanket approval.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    let (_client, bearer, _agent) = sensitive_fixture(&harness).await;

    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(json(&body)["error"], "invalid_request");
}

// ===========================================================================
// The refresh (issue #132, criterion 3).
//
// The criterion is "stored-token refresh works and a failing connection isolates without
// affecting other connections". Both halves need a PROVIDER to answer, so these drive an
// in-process token endpoint through the federation fetcher's injected dialer, the same rig
// `federation.rs` uses. The alternative -- asserting on the store alone -- would have missed
// the blocker a review found: the refresh branch guarded on a field the ordinary read never
// populates, so the whole path was dead code and no store-level test could see it.

/// What the stub token endpoint answers.
#[derive(Clone, Copy)]
enum Downstream {
    /// A fresh access token and a rotated refresh token.
    Rotates,
    /// A fresh access token and NO refresh token, which a provider may legitimately do.
    KeepsTheRefreshToken,
    /// `invalid_grant`: the stored refresh token is spent or revoked.
    Refuses,
    /// A rate limit or a gateway fault: says nothing about the credential.
    Faults(u16),
    /// A fresh access token with NO `expires_in`, which RFC 6749 section 5.1 permits.
    NamesNoLifetime,
}

/// The DNS name the provider's certificate is minted for, and the host the stored token
/// endpoint names. Not the address dialed: the resolver answers a public address so
/// destination validation does real work, while the dialer lands the socket on the listener.
const PROVIDER_HOST: &str = "oauth2.example.test";

/// The token endpoint URL a refreshable connection stores.
///
/// `https`, and it has to be: migration 0181's `refresh_endpoint_https` CHECK refuses a
/// plaintext endpoint, so a fixture written against `http://` does not even get stored -- the
/// first draft of these tests seeded `http://` and every one of them would have aborted in
/// the fixture the moment a database was present, which is a suite that proves nothing while
/// reading as though it proves the criterion.
const PROVIDER_TOKEN_ENDPOINT: &str = "https://oauth2.example.test/token";

/// A TLS token endpoint on loopback, and the identity whose root the fetcher trusts.
struct Provider {
    identity: TestTlsIdentity,
    target: TestTlsTarget,
}

impl Provider {
    /// How many requests reached it.
    fn calls(&self) -> usize {
        self.target.received().len()
    }

    /// The body of the last request, as the provider saw it.
    fn last_body(&self) -> String {
        let received = self.target.received();
        let last = received.last().cloned().unwrap_or_default();
        let text = String::from_utf8_lossy(&last).to_string();
        text.split_once("\r\n\r\n")
            .map_or(String::new(), |(_, body)| body.to_owned())
    }
}

async fn provider(behaviour: Downstream) -> Provider {
    let identity = TestTlsIdentity::generate(PROVIDER_HOST);
    let (status, body) = match behaviour {
        Downstream::Rotates => (
            200,
            r#"{"access_token":"fresh-access-token","refresh_token":"rotated-refresh-token","expires_in":3600}"#,
        ),
        Downstream::KeepsTheRefreshToken => (
            200,
            r#"{"access_token":"fresh-access-token","expires_in":3600}"#,
        ),
        Downstream::Refuses => (400, r#"{"error":"invalid_grant"}"#),
        Downstream::Faults(code) => (code, r#"{"error":"temporarily_unavailable"}"#),
        Downstream::NamesNoLifetime => (200, r#"{"access_token":"fresh-access-token"}"#),
    };
    let target = TestTlsTarget::start(&identity, status, body.as_bytes().to_vec()).await;
    Provider { identity, target }
}

/// A harness whose federation fetcher TRUSTS the provider's throwaway root and lands its
/// socket on the provider's listener.
///
/// `Fetcher::from_parts` would be the shorter line and it cannot work here: its trust store is
/// empty by design, so no handshake completes, and `allow_plaintext_http` does not help
/// because the fetcher picks TLS from the URL scheme and the endpoint must be `https`.
fn with_provider(harness: &mut Harness, provider: &Provider) {
    with_provider_at(harness, provider, provider.target.addr);
}

/// The same, dialing an EXPLICIT address, so a test can point the fetcher at a port nothing is
/// listening on and produce a real transport failure rather than simulating one.
fn with_provider_at(harness: &mut Harness, provider: &Provider, addr: std::net::SocketAddr) {
    use ironauth_oidc::{FederationKeyResolver, FederationRuntime};
    let resolver = std::sync::Arc::new(ironauth_fetch::StaticResolver::new(vec![
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
    ]));
    let dialer = std::sync::Arc::new(ironauth_fetch::RecordingDialer::new(addr));
    let fetcher = std::sync::Arc::new(ironauth_fetch::Fetcher::from_parts_trusting(
        ironauth_fetch::FetchLimits::default(),
        resolver,
        dialer,
        &provider.identity.root_der,
    ));
    let keys = std::sync::Arc::new(FederationKeyResolver::new(
        std::sync::Arc::clone(&fetcher),
        std::time::Duration::from_secs(300),
    ));
    let runtime = std::sync::Arc::new(FederationRuntime::new(
        fetcher,
        keys,
        std::time::Duration::from_secs(300),
        std::time::Duration::from_secs(30),
    ));
    harness.install_federation(runtime);
}

/// Push an approval's deadline into the past, as the OWNER.
///
/// Directly, because there is no route that does it: a timeout is the absence of a decision,
/// so the only way to reach the timed-out state is for time to pass.
async fn expire_approval(harness: &Harness, approval: &str) {
    sqlx::query(
        "UPDATE agent_vault_approvals /* query-audit-allow: owner test write */ \
         SET expires_at = now() - interval '1 minute' WHERE id = $1",
    )
    .bind(approval)
    .execute(harness.db().owner_pool())
    .await
    .expect("age the approval");
}

/// The organization an agent belongs to, for the queue read.
async fn organization_of(harness: &Harness, agent: &AgentPrincipalId) -> OrganizationId {
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .agents()
        .get(agent)
        .await
        .expect("read the agent")
        .organization_id
}

/// Age a connection's stored credential to an hour ago, as the OWNER.
///
/// Through raw SQL rather than a re-store, because `store_connection` resets `state` to
/// `active` and clears `last_error`: re-storing to make a credential expire would also undo
/// whatever the test was about to observe.
async fn expire_connection(harness: &Harness, agent: &AgentPrincipalId, provider: &str) {
    let scope = harness.scope();
    sqlx::query(
        "UPDATE agent_vault_connections /* query-audit-allow: owner test write */ \
         SET expires_at = now() - interval '1 hour' \
         WHERE tenant_id = $1 AND environment_id = $2 AND agent_id = $3 AND provider = $4",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(agent.to_string())
    .bind(provider)
    .execute(harness.db().owner_pool())
    .await
    .expect("age the stored credential");
}

/// Seed a connection that CAN refresh, with an access token that expired an hour ago.
async fn seed_expired_refreshable(
    harness: &Harness,
    agent: &AgentPrincipalId,
    provider_name: &str,
) {
    let scope = harness.scope();
    let id = ironauth_store::AgentVaultConnectionId::generate(harness.env(), &scope);
    let now = now_micros(harness);
    harness
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
                provider: provider_name,
                access_token: "stale-access-token",
                refresh_token: Some("downstream-refresh-token"),
                granted_scopes: &["mail.read".to_owned()],
                expires_at_unix_micros: Some(now - 3_600_000_000),
                requires_approval: Some(false),
                refresh: Some(ironauth_store::VaultRefreshConfig {
                    token_endpoint: PROVIDER_TOKEN_ENDPOINT,
                    client_id: "downstream-client",
                    client_secret: "downstream-client-secret",
                }),
            },
            now,
        )
        .await
        .expect("store a refreshable connection");
}

#[tokio::test]
async fn an_expired_credential_is_refreshed_and_the_fresh_one_is_stored() {
    let downstream = provider(Downstream::Rotates).await;
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    with_provider(&mut harness, &downstream);

    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google"]).await;
    seed_expired_refreshable(&harness, &agent, "google").await;
    let bearer = machine_token(&harness, &client, &secret, Some("google")).await;

    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        json(&body)["access_token"],
        "fresh-access-token",
        "the expired credential was renewed rather than handed over stale: {body}"
    );
    assert_eq!(
        downstream.calls(),
        1,
        "exactly one call reached the provider"
    );
    let sent = downstream.last_body();
    assert!(
        sent.contains("grant_type=refresh_token")
            && sent.contains("refresh_token=downstream-refresh-token")
            && sent.contains("client_secret=downstream-client-secret"),
        "the refresh presented the stored token and the stored client credentials: {sent}"
    );

    // THE RE-STORE. A refresh that is not persisted renews on every single exchange, and the
    // first version could not persist: it wrote through the data plane, which migration 0178
    // grants no INSERT. A second exchange proves the fresh token came back from the DATABASE.
    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        json(&body)["access_token"],
        "fresh-access-token",
        "the second exchange serves the stored fresh token: {body}"
    );
    assert_eq!(
        downstream.calls(),
        1,
        "and it did NOT call the provider again, so the refresh was persisted"
    );
}

#[tokio::test]
async fn a_provider_that_omits_a_rotated_refresh_token_keeps_the_stored_one() {
    // A provider MAY answer without a refresh token, meaning "keep using the one you have".
    // Dropping it there would leave a connection that refreshes exactly once and then needs an
    // operator, which looks like a provider fault and is ours.
    let downstream = provider(Downstream::KeepsTheRefreshToken).await;
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    with_provider(&mut harness, &downstream);

    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google"]).await;
    seed_expired_refreshable(&harness, &agent, "google").await;
    let bearer = machine_token(&harness, &client, &secret, Some("google")).await;

    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let stored = harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .agent_vault()
        .connection(&agent, "google")
        .await
        .expect("read")
        .expect("the connection is still there");
    assert_eq!(
        stored.refresh_token.as_deref(),
        Some("downstream-refresh-token"),
        "the stored refresh token survived a response that did not rotate it"
    );
    assert!(
        stored.can_refresh,
        "and the connection can still refresh next time"
    );
}

#[tokio::test]
async fn a_failing_refresh_marks_its_own_connection_and_leaves_the_others_alone() {
    // The ISOLATION half of criterion 3, and the only shape that tests it: one agent, two
    // providers, one of them broken. A test with a single connection cannot distinguish
    // "marked the failing one" from "marked everything".
    let downstream = provider(Downstream::Refuses).await;
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    with_provider(&mut harness, &downstream);

    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google", "github"]).await;
    seed_expired_refreshable(&harness, &agent, "google").await;
    seed_connection(&harness, &agent, "github").await;

    let google = machine_token(&harness, &client, &secret, Some("google")).await;
    let (status, body) = exchange(&harness, Some(&google), r#"{"provider":"google"}"#).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a refresh the provider refused must not issue anything: {body}"
    );
    assert!(
        json(&body).get("access_token").is_none(),
        "and no token is in the body: {body}"
    );

    // The broken connection is MARKED, not deleted: an operator has to be able to see which
    // one is broken in order to re-establish it.
    let store = harness.db().control_store();
    let store = store.scoped(harness.scope());
    let broken = store
        .agent_vault()
        .connection(&agent, "google")
        .await
        .expect("read")
        .expect("the connection is still there, marked rather than deleted");
    assert_eq!(
        broken.state, "failed",
        "the failing connection is visibly failed rather than silently gone"
    );

    // And the agent's OTHER provider is untouched, which is what isolation means.
    let github = machine_token(&harness, &client, &secret, Some("github")).await;
    let (status, body) = exchange(&harness, Some(&github), r#"{"provider":"github"}"#).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "one dead downstream must not take the agent's other connections with it: {body}"
    );
    assert_eq!(json(&body)["access_token"], "downstream-access-token");
}

#[tokio::test]
async fn an_expired_connection_that_cannot_refresh_says_so_distinctly() {
    // Null refresh configuration is a FACT about the connection, not missing data: a credential
    // from a flow that returned no refresh token has to be re-established. Reporting that as a
    // provider failure would send an operator to look at a provider that is fine.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();

    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google"]).await;
    let scope = harness.scope();
    let id = ironauth_store::AgentVaultConnectionId::generate(harness.env(), &scope);
    let now = now_micros(&harness);
    harness
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
                agent_id: &agent,
                provider: "google",
                access_token: "stale-access-token",
                refresh_token: None,
                granted_scopes: &["mail.read".to_owned()],
                expires_at_unix_micros: Some(now - 3_600_000_000),
                requires_approval: Some(false),
                refresh: None,
            },
            now,
        )
        .await
        .expect("store an unrefreshable connection");
    let bearer = machine_token(&harness, &client, &secret, Some("google")).await;

    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an expired credential must not be handed over: {body}"
    );
    assert_eq!(
        json(&body)["error"],
        "connection_expired",
        "the answer names the CONNECTION as the thing to act on: {body}"
    );
    assert!(
        body.contains("must be replaced"),
        "and says what to do about it: {body}"
    );
}

#[tokio::test]
async fn an_approval_authorizes_one_exchange_and_the_next_one_asks_again() {
    // ONE human decision, ONE exchange. An approved row used to authorize every exchange of
    // that action for the full hour, so a single "yes" to a payment of one let the agent take
    // the credential as often as it liked. The approver decided an ACTION, not a window.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    let (_client, bearer, _agent) = sensitive_fixture(&harness).await;

    let (_, raised) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    let approval = json(&raised)["approval_id"]
        .as_str()
        .expect("an approval")
        .to_owned();
    decide(&harness, &approval, true, None).await;

    let (first, first_body) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    assert_eq!(
        first,
        StatusCode::OK,
        "the approved exchange is issued: {first_body}"
    );

    // The SECOND exchange of the same action does not ride the spent approval. It is not a
    // refusal either: the agent may legitimately need the action again, and a human answers
    // again.
    let (second, second_body) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    assert_eq!(
        second,
        StatusCode::ACCEPTED,
        "a second exchange raises a NEW request rather than reusing the spent one: {second_body}"
    );
    assert_ne!(
        json(&second_body)["approval_id"].as_str(),
        Some(approval.as_str()),
        "and it is a different approval"
    );
    assert!(
        json(&second_body).get("access_token").is_none(),
        "nothing is issued while the new one is pending: {second_body}"
    );
}

#[tokio::test]
async fn an_agent_cannot_flood_the_approvers_queue() {
    // The queue is a HUMAN surface and the listing is bounded, so without a per-agent cap an
    // agent raises 250 junk requests and hides the one it wants unseen behind a page with no
    // page two. The action digest is agent-chosen JSON, so distinct requests are cheap.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    let (_client, bearer, _agent) = sensitive_fixture(&harness).await;

    // Eight distinct actions are accepted: the bound is above what a working agent does.
    for n in 0..8 {
        let body = format!(
            r#"{{"provider":"google","authorization_details":[{{"type":"payment","amount":{n}}}]}}"#
        );
        let (status, response) = exchange(&harness, Some(&bearer), &body).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "action {n} should still be acceptable: {response}"
        );
    }

    // The ninth is refused, and refused DISTINCTLY: an operator reading this in a log has to
    // be able to tell a flood from a denial.
    let (status, body) = exchange(
        &harness,
        Some(&bearer),
        r#"{"provider":"google","authorization_details":[{"type":"payment","amount":999}]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(json(&body)["error"], "too_many_pending_approvals");

    // And the cap does not block an action that already HAS a pending row: polling must keep
    // working, or an agent that filled its own quota could never learn its answers.
    let (poll, poll_body) = exchange(
        &harness,
        Some(&bearer),
        r#"{"provider":"google","authorization_details":[{"type":"payment","amount":0}]}"#,
    )
    .await;
    assert_eq!(
        poll,
        StatusCode::ACCEPTED,
        "an already-raised action still polls: {poll_body}"
    );
    assert_eq!(json(&poll_body)["status"], "approval_pending");
}

#[tokio::test]
async fn a_denied_agent_does_not_make_ironauth_spend_the_refresh_token() {
    // ORDERING as a control. The refresh ran before the approval gate, so a denied agent
    // re-sending its exchange still made IronAuth present the OPERATOR's refresh token at the
    // provider -- and with a rotating provider, rotate it. No token reached the agent, and a
    // principal a human explicitly denied was still driving a token grant at the third party.
    let downstream = provider(Downstream::Rotates).await;
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    with_provider(&mut harness, &downstream);

    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google"]).await;
    // Sensitive AND expired: both halves are needed for the ordering to matter.
    let scope = harness.scope();
    let id = ironauth_store::AgentVaultConnectionId::generate(harness.env(), &scope);
    let now = now_micros(&harness);
    harness
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
                agent_id: &agent,
                provider: "google",
                access_token: "stale-access-token",
                refresh_token: Some("downstream-refresh-token"),
                granted_scopes: &["mail.read".to_owned()],
                expires_at_unix_micros: Some(now - 3_600_000_000),
                requires_approval: Some(true),
                refresh: Some(ironauth_store::VaultRefreshConfig {
                    token_endpoint: PROVIDER_TOKEN_ENDPOINT,
                    client_id: "downstream-client",
                    client_secret: "downstream-client-secret",
                }),
            },
            now,
        )
        .await
        .expect("store a sensitive, expired, refreshable connection");
    let bearer = machine_token(&harness, &client, &secret, Some("google")).await;

    let (_, raised) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    let approval = json(&raised)["approval_id"]
        .as_str()
        .expect("an approval")
        .to_owned();
    assert_eq!(
        downstream.calls(),
        0,
        "raising an approval must not touch the provider"
    );
    decide(&harness, &approval, false, None).await;

    let (status, body) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        downstream.calls(),
        0,
        "a denied action must not spend the operator's refresh token at the provider"
    );
}

#[tokio::test]
async fn a_provider_that_cannot_be_reached_leaves_the_connection_usable() {
    // A TRANSPORT failure says nothing about the credential. Marking on it meant a five-second
    // blip during one request permanently disabled the connection: a failed connection is
    // refused BEFORE the refresh block, so it never retried, and the only repair is an
    // operator re-supplying an access token from a consent flow they no longer have.
    let downstream = provider(Downstream::Rotates).await;
    let addr = downstream.target.addr;
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    with_provider(&mut harness, &downstream);

    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google"]).await;
    seed_expired_refreshable(&harness, &agent, "google").await;
    let bearer = machine_token(&harness, &client, &secret, Some("google")).await;

    // The control first: it works while the provider answers, so the assertion below cannot
    // pass because the fixture was broken all along.
    let (ok, ok_body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(ok, StatusCode::OK, "the control: {ok_body}");

    // Now age the credential again and point the dialer at a port nothing is listening on.
    expire_connection(&harness, &agent, "google").await;
    let dead = std::net::SocketAddr::new(addr.ip(), 1);
    with_provider_at(&mut harness, &downstream, dead);

    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an unreachable provider is a retry, not a repair: {body}"
    );
    assert_eq!(json(&body)["error"], "provider_unreachable");

    let still = harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .agent_vault()
        .connection(&agent, "google")
        .await
        .expect("read")
        .expect("the connection is still there");
    assert_eq!(
        still.state, "active",
        "a network blip must not take the connection out of service"
    );
}

#[tokio::test]
async fn an_action_nobody_answered_can_be_asked_again_after_it_times_out() {
    // THE DEADLOCK. The pending-uniqueness index is partial on `state = 'pending'` and carries
    // no deadline term, and nothing anywhere wrote `expired`, so a request nobody answered kept
    // its action's one slot for ever: the next attempt inserted, lost to the index, re-read the
    // winner and was handed a 202 whose deadline was already in the past -- permanently. The
    // approver could not clear it either, because the queue excludes expired rows and `decide`
    // refuses them.
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    let (_client, bearer, agent) = sensitive_fixture(&harness).await;

    let (_, raised) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    let first = json(&raised)["approval_id"]
        .as_str()
        .expect("an approval")
        .to_owned();

    // Nobody answers, and its deadline passes.
    expire_approval(&harness, &first).await;

    let (status, body) = exchange(&harness, Some(&bearer), ACTION_SMALL).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let second = json(&body)["approval_id"]
        .as_str()
        .expect("an approval")
        .to_owned();
    assert_ne!(
        second, first,
        "a timed-out request must be replaceable, not permanent"
    );
    assert!(
        json(&body)["expires_at"].as_i64().expect("a deadline")
            > i64::try_from(
                harness
                    .state()
                    .now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("after the epoch")
                    .as_secs()
            )
            .expect("fits"),
        "and the new request's deadline is in the FUTURE: the defect handed back a live-looking \
         202 whose deadline had already passed: {body}"
    );

    // The retired row left `pending`, so it no longer occupies the action's slot, and the new
    // one is what an approver sees.
    let queue = harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .agent_vault_approvals()
        .pending_for_organization(
            &organization_of(&harness, &agent).await,
            now_micros(&harness),
            50,
        )
        .await
        .expect("list the queue")
        .into_iter()
        .map(|approval| approval.id.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        queue,
        vec![second],
        "the approver sees the live request and not the retired one"
    );
}

#[tokio::test]
async fn a_provider_that_rate_limits_or_faults_leaves_the_connection_usable() {
    // 429 and 5xx are not statements about the credential. Marking on them was the same defect
    // the transport split fixed, one layer higher: a single 502 during a provider's deploy took
    // the connection permanently out of service, because a failed connection is refused before
    // the refresh block ever runs again.
    for status in [429_u16, 502] {
        let downstream = provider(Downstream::Faults(status)).await;
        let mut harness = Harness::start_store_backed().await;
        harness.enable_agent_vault();
        with_provider(&mut harness, &downstream);

        let (client, secret) = machine_client(&harness).await;
        let agent = seed_agent(&harness, &client, &["google"]).await;
        seed_expired_refreshable(&harness, &agent, "google").await;
        let bearer = machine_token(&harness, &client, &secret, Some("google")).await;

        let (answer, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
        assert_eq!(
            answer,
            StatusCode::SERVICE_UNAVAILABLE,
            "a {status} is a retry, not a repair: {body}"
        );
        let still = harness
            .db()
            .control_store()
            .scoped(harness.scope())
            .agent_vault()
            .connection(&agent, "google")
            .await
            .expect("read")
            .expect("exists");
        assert_eq!(
            still.state, "active",
            "a {status} must not take the connection out of service"
        );
    }

    // THE CONTROL, so the two above are not passing because nothing ever marks: a 400 is the
    // provider reading the refresh token and refusing to spend it, and that DOES mark.
    let refusing = provider(Downstream::Refuses).await;
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    with_provider(&mut harness, &refusing);
    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google"]).await;
    seed_expired_refreshable(&harness, &agent, "google").await;
    let bearer = machine_token(&harness, &client, &secret, Some("google")).await;
    let (answer, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(answer, StatusCode::CONFLICT, "a 400 marks: {body}");
    assert_eq!(
        harness
            .db()
            .control_store()
            .scoped(harness.scope())
            .agent_vault()
            .connection(&agent, "google")
            .await
            .expect("read")
            .expect("exists")
            .state,
        "failed"
    );
}

#[tokio::test]
async fn a_refreshed_credential_whose_provider_named_no_lifetime_still_expires() {
    // `NULL` expiry means "does not expire", so writing the provider's silence straight through
    // made a refreshed connection immortal HERE and therefore never refreshed again: the agent
    // would learn the credential was dead from the provider rather than from IronAuth, which is
    // the failure the refresh exists to prevent.
    let downstream = provider(Downstream::NamesNoLifetime).await;
    let mut harness = Harness::start_store_backed().await;
    harness.enable_agent_vault();
    with_provider(&mut harness, &downstream);

    let (client, secret) = machine_client(&harness).await;
    let agent = seed_agent(&harness, &client, &["google"]).await;
    seed_expired_refreshable(&harness, &agent, "google").await;
    let bearer = machine_token(&harness, &client, &secret, Some("google")).await;

    let (status, body) = exchange(&harness, Some(&bearer), r#"{"provider":"google"}"#).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let stored = harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .agent_vault()
        .connection(&agent, "google")
        .await
        .expect("read")
        .expect("exists");
    assert!(
        stored.expires_at_unix_micros.is_some(),
        "a credential with no stated lifetime still gets one, or it is never refreshed again"
    );
}
