// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8707 Resource Indicators (issue #28), end to end over a real database
//! (`DATABASE_URL`).
//!
//! Covers the acceptance criteria: URI validation (absolute, no fragment), the
//! per-client allowlist rejected with `invalid_target`, multi-resource authorization
//! narrowed to a subset at the token endpoint (a single-audience string and a
//! multi-audience array), refresh-time downscoping (and the rejection of an
//! expansion), cross-resource replay blocked by audience enforcement, and opaque
//! tokens whose recorded audiences are reported through introspection.

mod common;

use std::fmt::Write as _;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
    verify_clock,
};
use ironauth_jose::verify;
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::{
    ActorRef, ClientId, CorrelationId, NewResourceServer, ResourceServerId, ServiceId, TokenFormat,
};
use serde_json::{Value, json};

/// The resource-server audiences the tests target.
const RS_A: &str = "https://api.example/a";
const RS_B: &str = "https://api.example/b";
const RS_C: &str = "https://api.example/c";

/// Register a resource server in the harness scope with the given token format.
async fn register_rs(harness: &Harness, audience: &str, format: TokenFormat) {
    let env = harness.env();
    let id = ResourceServerId::generate(env, &harness.scope());
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .resource_servers()
        .register(
            env,
            NewResourceServer {
                id: &id,
                audience,
                token_format: format,
                access_token_ttl_secs: None,
            },
        )
        .await
        .expect("register resource server");
}

/// Set a client's RFC 8707 resource-indicator policy in the harness scope.
async fn set_policy(
    harness: &Harness,
    client_id: &ClientId,
    allowed: Option<Vec<String>>,
    require: bool,
) {
    let env = harness.env();
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .clients()
        .set_resource_indicator_policy(env, client_id, allowed.as_deref(), require)
        .await
        .expect("set resource-indicator policy");
}

/// Build the authorize query for the PUBLIC (PKCE) harness client with the given
/// resource indicators (each appended as a repeated `resource` parameter).
fn authorize_query(client: &str, resources: &[&str]) -> String {
    let mut query = format!(
        "response_type=code&client_id={client}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI)
    );
    for resource in resources {
        write!(query, "&resource={}", enc(resource)).expect("write to String");
    }
    query
}

/// Authorize a fresh consenting subject for the PUBLIC harness client, returning the
/// redirect response.
async fn authorize_public(
    harness: &Harness,
    resources: &[&str],
) -> (StatusCode, HeaderMap, String) {
    let client = harness.client_id().to_string();
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client).await;
    let cookie = harness.session_cookie(&subject).await;
    harness
        .authorize_with_cookie(&authorize_query(&client, resources), &cookie)
        .await
}

/// The token-endpoint form for a PKCE public-client code exchange with the given
/// resource indicators.
fn token_form(code: &str, client: &str, resources: &[&str]) -> String {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client),
        ("code_verifier", PKCE_VERIFIER),
    ];
    for resource in resources {
        pairs.push(("resource", *resource));
    }
    form(&pairs)
}

/// The refresh-grant form for a public client with the given resource indicators.
fn refresh_form(refresh: &str, client: &str, resources: &[&str]) -> String {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("client_id", client),
    ];
    for resource in resources {
        pairs.push(("resource", *resource));
    }
    form(&pairs)
}

/// HTTP Basic authorization header for a confidential client.
fn basic(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// `POST /introspect` with a Basic `Authorization` header, returning the parsed body.
async fn introspect(harness: &Harness, token: &str, authorization: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, authorization)
        .body(Body::from(form(&[("token", token)])))
        .expect("request builds");
    let (status, _, body) = harness.send(request).await;
    let value = if body.is_empty() {
        Value::Null
    } else {
        json(&body)
    };
    (status, value)
}

/// The `aud` claim of a verified at+jwt, as a list of member strings (a single-string
/// `aud` is a one-element list; a JSON-array `aud` is its members).
fn aud_members(claims: &Value) -> Vec<String> {
    match claims {
        Value::String(single) => vec![single.clone()],
        Value::Array(members) => members
            .iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// AC: a multi-resource authorization, then single- and multi-resource token
/// requests, yield correctly narrowed audiences (a single string, then an array).
#[tokio::test]
async fn multi_resource_authorization_is_narrowed_at_the_token_endpoint() {
    let harness = Harness::start().await;
    register_rs(&harness, RS_A, TokenFormat::AtJwt).await;
    register_rs(&harness, RS_B, TokenFormat::AtJwt).await;
    let client = harness.client_id().to_string();

    // Approve BOTH resources at authorization; redeem for a SINGLE one.
    let (status, headers, body) = authorize_public(&harness, &[RS_A, RS_B]).await;
    assert_eq!(status, StatusCode::FOUND, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code");
    let (status, _, body) = harness.token(&token_form(&code, &client, &[RS_A])).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let verified = verify(&access, &harness.policy(RS_A), &verify_clock()).expect("verifies for A");
    // A single resource yields a single-STRING aud (byte-identical to the pre-#28
    // wire form), and client_id stays the OAuth client.
    let aud = verified.claims().get("aud").expect("aud");
    assert!(aud.is_string(), "single resource is a string aud: {aud}");
    assert_eq!(aud_members(aud), vec![RS_A.to_owned()]);
    assert_eq!(
        verified.claims().get("client_id").and_then(Value::as_str),
        Some(client.as_str()),
        "client_id stays the OAuth client, not the resource"
    );

    // A fresh code redeemed for BOTH resources yields a JSON-ARRAY aud.
    let (_, headers, _) = authorize_public(&harness, &[RS_A, RS_B]).await;
    let code = location_param(&headers, "code").expect("code");
    let (status, _, body) = harness
        .token(&token_form(&code, &client, &[RS_A, RS_B]))
        .await;
    assert_eq!(status, StatusCode::OK, "token multi: {body}");
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    // Verifies against EITHER member (array membership), and the aud is an array.
    let verified = verify(&access, &harness.policy(RS_A), &verify_clock()).expect("A member");
    verify(&access, &harness.policy(RS_B), &verify_clock()).expect("B member");
    let aud = verified.claims().get("aud").expect("aud");
    assert!(aud.is_array(), "two resources is an array aud: {aud}");
    let members = aud_members(aud);
    assert!(
        members.contains(&RS_A.to_owned()) && members.contains(&RS_B.to_owned()),
        "both requested audiences present: {aud}"
    );
}

/// AC: cross-resource replay is rejected. A token minted for resource A fails
/// audience validation at resource B (and at the bare client-id audience).
#[tokio::test]
async fn cross_resource_replay_is_rejected_by_audience_enforcement() {
    let harness = Harness::start().await;
    register_rs(&harness, RS_A, TokenFormat::AtJwt).await;
    register_rs(&harness, RS_B, TokenFormat::AtJwt).await;
    let client = harness.client_id().to_string();

    let (_, headers, _) = authorize_public(&harness, &[RS_A, RS_B]).await;
    let code = location_param(&headers, "code").expect("code");
    let (status, _, body) = harness.token(&token_form(&code, &client, &[RS_A])).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    // The token minted for A is valid AT A.
    verify(&access, &harness.policy(RS_A), &verify_clock()).expect("valid at A");
    // The SAME token FAILS audience validation at B (confused-deputy / replay defense).
    assert!(
        verify(&access, &harness.policy(RS_B), &verify_clock()).is_err(),
        "a token minted for resource A must not be accepted at resource B"
    );
    // It is also not a client-audience (UserInfo) token: it is resource-scoped.
    assert!(
        verify(&access, &harness.policy(&client), &verify_clock()).is_err(),
        "a resource-scoped token is not valid at the client audience"
    );
}

/// AC: a resource outside the client's allowlist fails with `invalid_target`, while
/// an allowlisted resource succeeds.
#[tokio::test]
async fn a_resource_outside_the_client_allowlist_is_invalid_target() {
    let harness = Harness::start().await;
    register_rs(&harness, RS_A, TokenFormat::AtJwt).await;
    register_rs(&harness, RS_B, TokenFormat::AtJwt).await;
    let client_id = *harness.client_id();
    // Restrict the client to A only (B is registered but not allowlisted).
    set_policy(&harness, &client_id, Some(vec![RS_A.to_owned()]), false).await;

    let (status, headers, body) = authorize_public(&harness, &[RS_B]).await;
    assert_eq!(status, StatusCode::FOUND, "authorize: {body}");
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_target"),
        "a disallowed resource is invalid_target"
    );

    // The allowlisted resource succeeds (a code is issued).
    let (status, headers, _) = authorize_public(&harness, &[RS_A]).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location_param(&headers, "code").is_some(),
        "an allowlisted resource is accepted"
    );
}

/// AC (URI validation): a non-absolute resource, or one carrying a fragment, is
/// `invalid_target` at BOTH the authorization and the token endpoints.
#[tokio::test]
async fn a_malformed_or_fragment_resource_is_invalid_target() {
    let harness = Harness::start().await;
    register_rs(&harness, RS_A, TokenFormat::AtJwt).await;
    let client = harness.client_id().to_string();

    // Authorization endpoint: a relative reference (no scheme).
    let (status, headers, _) = authorize_public(&harness, &["not-a-uri"]).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_target")
    );
    // Authorization endpoint: a fragment component is forbidden (RFC 8707 section 2).
    let (_, headers, _) = authorize_public(&harness, &["https://api.example/a#frag"]).await;
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_target")
    );

    // Token endpoint: approve A, then present a fragment resource.
    let (_, headers, _) = authorize_public(&harness, &[RS_A]).await;
    let code = location_param(&headers, "code").expect("code");
    let (status, _, body) = harness
        .token(&token_form(&code, &client, &["https://api.example/a#frag"]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "token: {body}");
    assert_eq!(json(&body)["error"], "invalid_target");
}

/// An unregistered (unknown) resource is `invalid_target` (never a silent fallback).
#[tokio::test]
async fn an_unregistered_resource_is_invalid_target() {
    let harness = Harness::start().await;
    // RS_A is deliberately NOT registered.
    let (status, headers, _) = authorize_public(&harness, &[RS_A]).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_target")
    );
}

/// AC: refresh-time downscoping to a subset works; an attempt to add a new resource
/// on refresh is rejected with `invalid_target`.
#[tokio::test]
async fn refresh_downscopes_to_a_subset_but_expansion_is_rejected() {
    let harness = Harness::start().await;
    register_rs(&harness, RS_A, TokenFormat::AtJwt).await;
    register_rs(&harness, RS_B, TokenFormat::AtJwt).await;
    // RS_C is registered but NOT approved at authorization, so it is an expansion.
    register_rs(&harness, RS_C, TokenFormat::AtJwt).await;
    let client = harness.client_id().to_string();

    // Approve A and B (with a scope so a refresh token is issued).
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client).await;
    let cookie = harness.session_cookie(&subject).await;
    let mut query = authorize_query(&client, &[RS_A, RS_B]);
    query.push_str("&scope=openid");
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::FOUND, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code");
    let (status, _, body) = harness
        .token(&token_form(&code, &client, &[RS_A, RS_B]))
        .await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    let refresh = json(&body)["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned();

    // Downscope the refresh to A only: succeeds, and the token is scoped to A alone.
    let (status, _, body) = harness
        .token(&refresh_form(&refresh, &client, &[RS_A]))
        .await;
    assert_eq!(status, StatusCode::OK, "refresh downscope: {body}");
    let refreshed = json(&body);
    let access = refreshed["access_token"].as_str().expect("access_token");
    verify(access, &harness.policy(RS_A), &verify_clock()).expect("scoped to A");
    assert!(
        verify(access, &harness.policy(RS_B), &verify_clock()).is_err(),
        "the refreshed token was downscoped away from B"
    );
    // A public client rotates on every refresh, so use the successor for the next call.
    let refresh_next = refreshed["refresh_token"]
        .as_str()
        .map_or_else(|| refresh.clone(), str::to_owned);

    // Attempt to EXPAND to C (registered, but never approved at authorization).
    let (status, _, body) = harness
        .token(&refresh_form(&refresh_next, &client, &[RS_C]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "refresh expansion: {body}");
    assert_eq!(
        json(&body)["error"],
        "invalid_target",
        "adding a new resource on refresh is rejected"
    );
}

/// AC: opaque tokens report their audiences accurately via introspection, both a
/// multi-resource array and a single-resource string.
#[tokio::test]
async fn opaque_token_audiences_are_reported_via_introspection() {
    let harness = Harness::start().await;
    register_rs(&harness, RS_A, TokenFormat::Opaque).await;
    register_rs(&harness, RS_B, TokenFormat::Opaque).await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let client = client_id.to_string();

    // Approve A and B (confidential client, no PKCE), then redeem for BOTH.
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client}&redirect_uri={}&resource={}&resource={}",
        enc(REDIRECT_URI),
        enc(RS_A),
        enc(RS_B)
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::FOUND, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code");
    let token_body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("resource", RS_A),
        ("resource", RS_B),
    ]);
    let (status, _, body) = harness.token_with_auth(&token_body, Some(&auth)).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    let opaque = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    assert!(opaque.starts_with("ira_at_"), "an opaque token was issued");

    // Introspection reports the FULL recorded audience array.
    let (status, doc) = introspect(&harness, &opaque, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["active"], json!(true), "active: {doc}");
    assert!(
        doc["aud"].is_array(),
        "multi-resource aud is an array: {doc}"
    );
    let members = aud_members(&doc["aud"]);
    assert!(
        members.contains(&RS_A.to_owned()) && members.contains(&RS_B.to_owned()),
        "both recorded audiences reported: {doc}"
    );

    // A single-resource opaque token reports its aud as a STRING.
    let single_query = format!(
        "response_type=code&client_id={client}&redirect_uri={}&resource={}",
        enc(REDIRECT_URI),
        enc(RS_A)
    );
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client).await;
    let cookie = harness.session_cookie(&subject).await;
    let (status, headers, body) = harness.authorize_with_cookie(&single_query, &cookie).await;
    assert_eq!(status, StatusCode::FOUND, "authorize single: {body}");
    let code = location_param(&headers, "code").expect("code");
    let token_body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("resource", RS_A),
    ]);
    let (status, _, body) = harness.token_with_auth(&token_body, Some(&auth)).await;
    assert_eq!(status, StatusCode::OK, "token single: {body}");
    let opaque = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let (status, doc) = introspect(&harness, &opaque, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["active"], json!(true), "active: {doc}");
    assert_eq!(
        doc["aud"],
        json!(RS_A),
        "a single-resource opaque token reports a string aud: {doc}"
    );
}

/// The per-client no-resource knob: a client whose policy REFUSES a no-resource
/// request must name a resource, while a resource-bearing request succeeds.
#[tokio::test]
async fn a_client_requiring_a_resource_refuses_a_no_resource_request() {
    let harness = Harness::start().await;
    register_rs(&harness, RS_A, TokenFormat::AtJwt).await;
    let client_id = *harness.client_id();
    set_policy(&harness, &client_id, None, true).await;

    // No resource named: refused with invalid_target.
    let (status, headers, _) = authorize_public(&harness, &[]).await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        location_param(&headers, "error").as_deref(),
        Some("invalid_target"),
        "a strict client refuses a no-resource request"
    );

    // A resource named: accepted.
    let (status, headers, _) = authorize_public(&harness, &[RS_A]).await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(location_param(&headers, "code").is_some());
}

/// The additive no-resource default: with no resource and no strict policy, the
/// token's audience is the client id (the pre-#28 behavior, so `UserInfo` keeps
/// working).
#[tokio::test]
async fn no_resource_yields_the_client_audience_by_default() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;
    let (status, _, body) = harness.token(&token_form(&code, &client, &[])).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let verified =
        verify(&access, &harness.policy(&client), &verify_clock()).expect("client audience");
    assert_eq!(
        verified.claims().get("aud").and_then(Value::as_str),
        Some(client.as_str()),
        "no resource keeps the client-id audience"
    );
}
