// SPDX-License-Identifier: MIT OR Apache-2.0

//! Token revocation (RFC 7009) and introspection (RFC 7662) end to end, against a
//! real Postgres (issue #22).
//!
//! Covers the acceptance criteria: access and refresh tokens are revocable and then
//! introspect as `active:false`; revoking a refresh token cascades to its derived
//! access tokens; an unknown, malformed, or foreign-client revocation is a uniform
//! `200` with no existence oracle; unauthenticated introspection is `401` and leaks
//! nothing; a wrong `token_type_hint` still revokes; a cross-tenant token is inactive
//! and not revocable; discovery advertises both endpoints and their auth methods on
//! both well-known forms; and the internal revocation event is published on every
//! successful revocation with a stable schema.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{Harness, REDIRECT_URI, enc, form, json, location_param, send_through};
use ironauth_config::{OidcConfig, TokenFormat as ConfigTokenFormat};
use ironauth_oidc::{
    ClientAuthMethod, IntrospectionClaims, IntrospectionSerializer, RevocationEvent,
    RevocationEventSink, RevokedTokenType, SerializedIntrospection, oidc_router,
};
use ironauth_store::ClientId;
use serde_json::Value;

/// The `Authorization: Basic` header value for `client_secret_basic`.
fn basic(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// Decode a JWS payload segment's claims (unverified: for reading a claim in a test).
fn payload_claims(token: &str) -> serde_json::Map<String, Value> {
    let segment = token.split('.').nth(1).expect("payload segment");
    let bytes = URL_SAFE_NO_PAD.decode(segment).expect("base64url payload");
    serde_json::from_slice(&bytes).expect("claims json")
}

/// Drive authorize + token for a CONFIDENTIAL client (Basic auth), returning the full
/// token response (`access_token`, `id_token`, `refresh_token`, `scope`). The client
/// is confidential, so no PKCE is required in the harness.
async fn issue_confidential(
    harness: &Harness,
    client_id: &ClientId,
    secret: &str,
    scope: &str,
) -> Value {
    let cid = client_id.to_string();
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &cid).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={cid}&redirect_uri={}&scope={}",
        enc(REDIRECT_URI),
        enc(scope),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "authorize should redirect: {body}"
    );
    let code = location_param(&headers, "code").expect("code in redirect");
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
    ]);
    let (status, _, body) = harness
        .token_with_auth(&exchange, Some(&basic(&cid, secret)))
        .await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    json(&body)
}

/// `POST` a form body to `path` with an optional `Authorization` header.
async fn post_form(
    harness: &Harness,
    path: &str,
    body: &str,
    authorization: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    harness
        .send(
            builder
                .body(Body::from(body.to_owned()))
                .expect("request builds"),
        )
        .await
}

/// `POST /revoke` a token authenticated by a confidential client, with an optional
/// `token_type_hint`. Returns the status and body.
async fn revoke(
    harness: &Harness,
    token: &str,
    authorization: &str,
    hint: Option<&str>,
) -> (StatusCode, String) {
    let mut pairs = vec![("token", token)];
    if let Some(hint) = hint {
        pairs.push(("token_type_hint", hint));
    }
    let (status, _, body) = post_form(harness, "/revoke", &form(&pairs), Some(authorization)).await;
    (status, body)
}

/// `POST /introspect` a token authenticated by a confidential client, returning the
/// parsed JSON response.
async fn introspect(harness: &Harness, token: &str, authorization: &str) -> (StatusCode, Value) {
    let (status, _, body) = post_form(
        harness,
        "/introspect",
        &form(&[("token", token)]),
        Some(authorization),
    )
    .await;
    let value = if body.is_empty() {
        Value::Null
    } else {
        json(&body)
    };
    (status, value)
}

#[tokio::test]
async fn access_token_is_revocable_and_then_introspects_inactive() {
    // AC #1: an access token introspects active, is revocable, and subsequently
    // introspects as active:false. (Structurally covers the client_credentials access
    // token of issue #23: the revoke/introspect path is token-type-agnostic, so an
    // at+jwt today exercises the same code a client_credentials token will.)
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid profile").await;
    let access = tokens["access_token"].as_str().expect("access_token");
    let id_sub = payload_claims(tokens["id_token"].as_str().expect("id_token"))["sub"]
        .as_str()
        .expect("id sub")
        .to_owned();

    // Introspect active: the standard claim set is present and sub matches the ID token.
    let (status, doc) = introspect(&harness, access, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        doc["active"],
        Value::Bool(true),
        "active before revoke: {doc}"
    );
    assert_eq!(doc["token_type"], "Bearer");
    assert_eq!(doc["client_id"], client_id.to_string());
    assert_eq!(doc["scope"], "openid profile");
    assert_eq!(
        doc["sub"].as_str(),
        Some(id_sub.as_str()),
        "sub matches ID token"
    );
    assert!(doc["exp"].is_number() && doc["iat"].is_number());
    assert_eq!(doc["aud"], client_id.to_string());

    // Revoke: 200 with an empty body (RFC 7009 section 2.2).
    let (status, body) = revoke(&harness, access, &auth, None).await;
    assert_eq!(status, StatusCode::OK, "revoke: {body}");
    assert!(
        body.is_empty(),
        "revoke response has an empty body: {body:?}"
    );

    // Introspect again: now not-active, and exactly {"active":false} (no metadata leak).
    let (status, doc) = introspect(&harness, access, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        doc,
        json(r#"{"active":false}"#),
        "inactive after revoke: {doc}"
    );

    // Exactly one token.revoke audit row was written for the revocation.
    assert_eq!(
        harness.count_audit_action("token.revoke").await,
        1,
        "one token.revoke audit row"
    );
}

#[tokio::test]
async fn revoking_a_refresh_token_cascades_to_the_derived_access_token() {
    // AC #3: revoking a refresh token cascades: the access token derived from the same
    // grant introspects as active:false immediately.
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid").await;
    let access = tokens["access_token"].as_str().expect("access_token");
    let refresh = tokens["refresh_token"].as_str().expect("refresh_token");

    // Both are active before the revoke.
    assert_eq!(
        introspect(&harness, access, &auth).await.1["active"],
        Value::Bool(true)
    );
    assert_eq!(
        introspect(&harness, refresh, &auth).await.1["active"],
        Value::Bool(true)
    );

    // Revoke the REFRESH token.
    let (status, _) = revoke(&harness, refresh, &auth, None).await;
    assert_eq!(status, StatusCode::OK);

    // The cascade: the refresh token AND the access token derived from the same grant
    // are both inactive now.
    assert_eq!(
        introspect(&harness, refresh, &auth).await.1,
        json(r#"{"active":false}"#),
        "revoked refresh token is inactive"
    );
    assert_eq!(
        introspect(&harness, access, &auth).await.1,
        json(r#"{"active":false}"#),
        "the DERIVED access token cascaded to inactive"
    );
    // The refresh revoke audits through refresh_family.revoke (family spine + grant).
    assert_eq!(
        harness.count_audit_action("refresh_family.revoke").await,
        1,
        "one refresh_family.revoke audit row"
    );
}

#[tokio::test]
async fn opaque_access_token_is_revocable_and_introspectable() {
    // AC #1 for the opaque access-token format: introspect active, revoke, introspect
    // inactive. Opaque tokens have no offline validation, so introspection is the
    // internal store resolve exposed over the wire.
    let harness = Harness::start_with(OidcConfig {
        require_pkce_for_confidential_clients: false,
        default_access_token_format: ConfigTokenFormat::Opaque,
        ..OidcConfig::default()
    })
    .await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid profile").await;
    let access = tokens["access_token"].as_str().expect("access_token");
    assert!(
        access.starts_with("ira_at_"),
        "opaque access token: {access}"
    );

    let (status, doc) = introspect(&harness, access, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["active"], Value::Bool(true), "opaque active: {doc}");
    assert_eq!(doc["token_type"], "Bearer");
    assert_eq!(doc["client_id"], client_id.to_string());
    assert_eq!(doc["scope"], "openid profile");
    assert!(doc["sub"].as_str().is_some_and(|s| s.starts_with("usr_")));

    let (status, _) = revoke(&harness, access, &auth, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        introspect(&harness, access, &auth).await.1,
        json(r#"{"active":false}"#),
        "opaque access token inactive after revoke"
    );
}

#[tokio::test]
async fn unknown_malformed_and_foreign_revocations_are_an_indistinguishable_200() {
    // AC #2: revoking an unknown, a malformed, or a foreign-client token returns 200
    // with no distinguishable response, and (foreign) has NO effect on the token.
    let harness = Harness::start().await;
    let (client_a, secret_a) = harness
        .create_confidential_client_named(ClientAuthMethod::Basic, "client A")
        .await;
    let (client_b, secret_b) = harness
        .create_confidential_client_named(ClientAuthMethod::Basic, "client B")
        .await;
    let auth_a = basic(&client_a.to_string(), &secret_a);
    let auth_b = basic(&client_b.to_string(), &secret_b);

    let tokens = issue_confidential(&harness, &client_a, &secret_a, "openid").await;
    let access_a = tokens["access_token"].as_str().expect("access_token");

    // Client B (authenticated) revokes: an unknown opaque token, a malformed token,
    // and client A's token (foreign). All are a uniform 200 with an empty body.
    let unknown = revoke(&harness, "ira_at_bogus~nope", &auth_b, None).await;
    let malformed = revoke(&harness, "not-a-real-token", &auth_b, None).await;
    let foreign = revoke(&harness, access_a, &auth_b, None).await;
    assert_eq!(unknown, (StatusCode::OK, String::new()));
    assert_eq!(malformed, (StatusCode::OK, String::new()));
    assert_eq!(foreign, (StatusCode::OK, String::new()));
    assert_eq!(unknown, foreign, "unknown and foreign are byte-identical");

    // The foreign revoke had NO effect: client A's token is still active.
    assert_eq!(
        introspect(&harness, access_a, &auth_a).await.1["active"],
        Value::Bool(true),
        "a foreign-client revoke does not touch the token"
    );
    // No revocation ever committed (no audit rows), so no oracle side channel either.
    assert_eq!(harness.count_audit_action("token.revoke").await, 0);
    assert_eq!(harness.count_audit_action("refresh_family.revoke").await, 0);
}

#[tokio::test]
async fn unauthenticated_or_badly_authenticated_introspection_is_401_and_leaks_nothing() {
    // AC #4: introspection REQUIRES client authentication; an unauthenticated or
    // badly-authenticated call is 401 and reveals nothing about the token (RFC 7662
    // section 4).
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid").await;
    let access = tokens["access_token"].as_str().expect("access_token");

    // No client credentials at all: 401, and the body reveals nothing about the token.
    let (status, _, body) =
        post_form(&harness, "/introspect", &form(&[("token", access)]), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no client auth: {body}");
    assert!(
        !body.contains("\"active\""),
        "no token state leaked: {body}"
    );

    // A WRONG client secret: also 401, and byte-identical (no missing-vs-bad oracle).
    let wrong = basic(&client_id.to_string(), "not-the-secret");
    let (status_wrong, _, body_wrong) = post_form(
        &harness,
        "/introspect",
        &form(&[("token", access)]),
        Some(&wrong),
    )
    .await;
    assert_eq!(
        status_wrong,
        StatusCode::UNAUTHORIZED,
        "bad secret: {body_wrong}"
    );
    assert_eq!(
        body_wrong, body,
        "missing and bad auth are indistinguishable"
    );

    // With VALID auth the SAME token is active, proving the 401 was about auth, not
    // the token.
    assert_eq!(
        introspect(&harness, access, &auth).await.1["active"],
        Value::Bool(true)
    );
}

#[tokio::test]
async fn a_wrong_token_type_hint_still_revokes() {
    // The token_type_hint is a non-authoritative optimization (RFC 7009): a refresh
    // hint on an access token must still revoke it (the lookup falls back across
    // types, which the shape classification does by construction).
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid").await;
    let access = tokens["access_token"].as_str().expect("access_token");

    let (status, _) = revoke(&harness, access, &auth, Some("refresh_token")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        introspect(&harness, access, &auth).await.1,
        json(r#"{"active":false}"#),
        "a wrong hint still revoked the access token"
    );
}

#[tokio::test]
async fn a_public_client_revokes_its_own_token_without_a_secret() {
    // RFC 7009 does not require a secret for a public client: it authenticates by
    // presenting its client_id (method none) and revokes its own token.
    let harness = Harness::start().await;
    // The harness client is PUBLIC; a public client always requires PKCE, so issue
    // with the PKCE flow and redeem opaquely through the token endpoint.
    let public_id = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&public_id).await;
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &public_id),
        ("code_verifier", common::PKCE_VERIFIER),
    ]);
    let (status, _, body) = harness.token(&exchange).await;
    assert_eq!(status, StatusCode::OK, "token: {body}");
    let access = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    // Revoke with client_id in the form body (no Authorization header, method none).
    let (status, _, revoke_body) = post_form(
        &harness,
        "/revoke",
        &form(&[("token", &access), ("client_id", &public_id)]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "public revoke: {revoke_body}");

    // Confirm the public revoke actually took effect. `/introspect` requires a
    // CONFIDENTIAL client (a `client_id` is not secret), so the resource-server model
    // is exercised through a confidential client in the SAME scope reading the public
    // client's now-revoked token: it reads `active:false`.
    let (confidential, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let confidential_auth = basic(&confidential.to_string(), &secret);
    assert_eq!(
        introspect(&harness, &access, &confidential_auth).await.1,
        json(r#"{"active":false}"#),
        "the public client's token is inactive after its own revoke"
    );
    // Exactly one revocation committed (the public revoke), so it was not a silent
    // no-op despite carrying no secret.
    assert_eq!(harness.count_audit_action("token.revoke").await, 1);
}

#[tokio::test]
async fn a_cross_tenant_token_is_inactive_and_not_revocable() {
    // Cross-tenant isolation: a client authenticated in a FOREIGN tenant can neither
    // introspect (reads active:false) nor revoke a token issued in another tenant. The
    // token is resolved ONLY within the authenticated client's own scope, so its
    // embedded scope never matches and nothing leaks across the tenant boundary.
    let harness = Harness::start().await;
    let (owner, owner_secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let owner_auth = basic(&owner.to_string(), &owner_secret);
    let tokens = issue_confidential(&harness, &owner, &owner_secret, "openid").await;
    let access = tokens["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    // A confidential client in a SEPARATE tenant (its own scope).
    let foreign_scope = harness.provision_foreign_scope().await;
    let (foreign, foreign_secret) = harness
        .create_confidential_client_in(foreign_scope, ClientAuthMethod::Basic, "foreign")
        .await;
    let foreign_auth = basic(&foreign.to_string(), &foreign_secret);

    // The foreign client introspects the other tenant's token: active:false (no leak).
    let (status, doc) = introspect(&harness, &access, &foreign_auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        doc,
        json(r#"{"active":false}"#),
        "cross-tenant introspection is inactive"
    );

    // The foreign client tries to revoke it: 200 no-op, and the token stays active for
    // its real owner (the cross-tenant revoke had no effect).
    let (status, _) = revoke(&harness, &access, &foreign_auth, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        introspect(&harness, &access, &owner_auth).await.1["active"],
        Value::Bool(true),
        "a cross-tenant revoke does not touch the token"
    );
    // No revocation committed in the foreign scope.
    assert_eq!(harness.count_audit_action("token.revoke").await, 0);
}

#[tokio::test]
async fn discovery_advertises_both_endpoints_and_their_auth_methods_on_both_forms() {
    // AC #5: both endpoints and their auth-method arrays appear in generated discovery
    // on both well-known forms (the appended OIDC form and the host-inserted RFC 8414
    // form), identically.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let base = "https://issuer.test";
    // The two endpoints DIFFER by exactly `none`: `/revoke` accepts a public client
    // (RFC 7009), so it advertises the full method set; `/introspect` requires a
    // confidential client (RFC 7662 section 2.1, since a `client_id` is not secret), so
    // its advertised set excludes `none`.
    let revocation_methods =
        json(r#"["client_secret_basic","client_secret_post","private_key_jwt","none"]"#);
    let introspection_methods =
        json(r#"["client_secret_basic","client_secret_post","private_key_jwt"]"#);

    for uri in [
        format!(
            "/t/{}/e/{}/.well-known/openid-configuration",
            scope.tenant(),
            scope.environment()
        ),
        format!(
            "/.well-known/oauth-authorization-server/t/{}/e/{}",
            scope.tenant(),
            scope.environment()
        ),
    ] {
        let request = Request::builder()
            .method("GET")
            .uri(&uri)
            .body(Body::empty())
            .expect("request builds");
        let (status, _, body) = harness.send(request).await;
        assert_eq!(status, StatusCode::OK, "discovery {uri}: {body}");
        let doc = json(&body);
        assert_eq!(
            doc["revocation_endpoint"],
            format!("{base}/revoke"),
            "{uri}"
        );
        assert_eq!(
            doc["introspection_endpoint"],
            format!("{base}/introspect"),
            "{uri}"
        );
        assert_eq!(
            doc["revocation_endpoint_auth_methods_supported"], revocation_methods,
            "{uri}"
        );
        assert_eq!(
            doc["introspection_endpoint_auth_methods_supported"], introspection_methods,
            "introspection excludes none: {uri}"
        );
        // RFC 8414 section 2: the signing-alg arrays accompany private_key_jwt.
        assert!(
            doc["revocation_endpoint_auth_signing_alg_values_supported"].is_array(),
            "{uri}"
        );
        assert!(
            doc["introspection_endpoint_auth_signing_alg_values_supported"].is_array(),
            "{uri}"
        );
    }
}

/// A recording revocation sink, to assert the endpoint publishes on every revocation.
#[derive(Default)]
struct RecordingSink {
    events: Mutex<Vec<RevocationEvent>>,
}

impl RevocationEventSink for RecordingSink {
    fn publish(&self, event: &RevocationEvent) {
        self.events.lock().expect("lock").push(event.clone());
    }
}

#[tokio::test]
async fn every_successful_revocation_publishes_an_internal_event() {
    // AC #6: the internal revocation-event seam receives a typed event for every
    // successful revocation, with the stable schema (an access-token revoke carries
    // the grant; a refresh-token revoke additionally carries the family).
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid").await;
    let access = tokens["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let refresh = tokens["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned();

    // Rebuild the router over the SAME state with a recording sink installed (exactly
    // how the M4 external fan-out will wire a real sink).
    let sink = Arc::new(RecordingSink::default());
    let router = oidc_router(harness.state().clone().with_revocation_sink(sink.clone()));

    // Revoke the access token, then the refresh token, through the sink-wired router.
    for token in [&access, &refresh] {
        let request = Request::builder()
            .method("POST")
            .uri("/revoke")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::AUTHORIZATION, &auth)
            .body(Body::from(form(&[("token", token)])))
            .expect("request builds");
        let (status, _, body) = send_through(router.clone(), request).await;
        assert_eq!(status, StatusCode::OK, "revoke through sink router: {body}");
    }

    let events = sink.events.lock().expect("lock").clone();
    assert_eq!(
        events.len(),
        2,
        "one event per successful revocation: {events:?}"
    );
    // The access-token event: the grant chain, no family.
    assert_eq!(events[0].token_type, RevokedTokenType::AccessToken);
    assert_eq!(events[0].client_id, client_id.to_string());
    assert!(
        events[0].grant_id.starts_with("grt_"),
        "grant id: {}",
        events[0].grant_id
    );
    assert!(
        events[0].family_id.is_none(),
        "access-token event carries no family"
    );
    // The refresh-token event: the grant chain AND the family spine.
    assert_eq!(events[1].token_type, RevokedTokenType::RefreshToken);
    assert!(
        events[1]
            .family_id
            .as_deref()
            .is_some_and(|f| f.starts_with("rff_")),
        "refresh-token event carries the family: {:?}",
        events[1].family_id
    );
    // The event serializes to the stable, shape-locked schema.
    assert_eq!(
        serde_json::to_value(&events[0]).expect("serialize")["token_type"],
        "access_token"
    );
}

/// Build a `POST /revoke` request for `token` with an `Authorization` header, to send
/// through a sink-wired router.
fn revoke_request(token: &str, authorization: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/revoke")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, authorization)
        .body(Body::from(form(&[("token", token)])))
        .expect("request builds")
}

#[tokio::test]
async fn a_public_none_client_cannot_introspect() {
    // FIX 1 (issue #22 hardening): RFC 7662 section 2.1 REQUIRES a confidential client.
    // A `client_id` is NOT a secret (it appears in front-channel authorize URLs), so a
    // public `none` client presenting only its id must NOT be able to introspect a
    // token: it gets the SAME uniform 401 a missing/bad credential returns, leaking no
    // metadata. A confidential client CAN still introspect the same token (the
    // resource-server model is intact).
    let harness = Harness::start().await;
    let (owner, owner_secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let owner_auth = basic(&owner.to_string(), &owner_secret);
    let tokens = issue_confidential(&harness, &owner, &owner_secret, "openid profile").await;
    let access = tokens["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    // The public harness client (method none) presents ONLY its client_id in the body:
    // a uniform 401 that leaks nothing about the token.
    let public_id = harness.client_id().to_string();
    let (status, _, body) = post_form(
        &harness,
        "/introspect",
        &form(&[("token", &access), ("client_id", &public_id)]),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a public none client is rejected: {body}"
    );
    assert!(
        !body.contains("\"active\""),
        "no token state leaked to the none client: {body}"
    );
    assert!(
        !body.contains(&owner.to_string()) && !body.contains("openid profile"),
        "no token metadata leaked to the none client: {body}"
    );

    // A confidential client in the SAME scope still introspects the same token: the
    // resource-server model is unchanged, only `none` is now barred.
    assert_eq!(
        introspect(&harness, &access, &owner_auth).await.1["active"],
        Value::Bool(true),
        "a confidential client can still introspect"
    );
}

#[tokio::test]
async fn an_access_token_introspects_active_then_inactive_after_its_ttl() {
    // FIX 2a (issue #22 test rigor): advancing-clock expiry, so a regression dropping
    // the `exp > now` clause would not ship green. An at+jwt access token introspects
    // active:true; after the ManualClock advances well past its TTL, the signature's
    // exp check fails and it introspects active:false.
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid").await;
    let access = tokens["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    assert_eq!(
        introspect(&harness, &access, &auth).await.1["active"],
        Value::Bool(true),
        "active before the TTL passes"
    );

    // Advance the clock a full day, well past the default 300s access-token TTL and any
    // verification skew: the token's exp is now in the past, so it reads active:false.
    harness.clock().advance(Duration::from_secs(86_400));
    assert_eq!(
        introspect(&harness, &access, &auth).await.1,
        json(r#"{"active":false}"#),
        "inactive after the TTL passes (exp is enforced end to end)"
    );
}

#[tokio::test]
async fn a_refresh_token_introspects_active_then_inactive_after_its_idle_lifetime() {
    // FIX 2b (issue #22 test rigor): a refresh token introspects active:true; after the
    // ManualClock advances past its idle lifetime, it introspects active:false (the
    // store resolve compares the idle expiry against the clock seam).
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid").await;
    let refresh = tokens["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned();

    assert_eq!(
        introspect(&harness, &refresh, &auth).await.1["active"],
        Value::Bool(true),
        "active before the idle lifetime passes"
    );

    // Advance past the default refresh idle TTL (1_209_600s = 14 days).
    harness.clock().advance(Duration::from_secs(1_209_600 + 60));
    assert_eq!(
        introspect(&harness, &refresh, &auth).await.1,
        json(r#"{"active":false}"#),
        "inactive after the idle lifetime passes"
    );
}

#[tokio::test]
async fn revoking_the_access_token_cascades_to_the_refresh_token() {
    // FIX 3 (issue #22 test rigor): the OTHER cascade direction. Revoking the ACCESS
    // token revokes the whole grant chain, so the REFRESH token from the same grant
    // introspects active:false. This pins the deliberate least-astonishment choice that
    // revoking any token in a grant revokes the chain.
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid").await;
    let access = tokens["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    let refresh = tokens["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned();

    assert_eq!(
        introspect(&harness, &refresh, &auth).await.1["active"],
        Value::Bool(true),
        "the refresh token is active before the revoke"
    );

    // Revoke the ACCESS token.
    let (status, _) = revoke(&harness, &access, &auth, None).await;
    assert_eq!(status, StatusCode::OK);

    // The refresh token derived from the SAME grant cascaded to inactive.
    assert_eq!(
        introspect(&harness, &refresh, &auth).await.1,
        json(r#"{"active":false}"#),
        "revoking the access token revoked the whole grant chain, including the refresh token"
    );
}

#[tokio::test]
async fn a_foreign_or_double_revocation_is_exactly_once_on_the_sink_and_audit() {
    // FIX 4 (issue #22 test rigor): exactly-once on a real state flip (`if flipped`). A
    // foreign-client revoke and a double revoke both flip NO state, so they publish NO
    // event on the sink and write NO (second) audit row.
    let harness = Harness::start().await;
    let (owner, owner_secret) = harness
        .create_confidential_client_named(ClientAuthMethod::Basic, "owner")
        .await;
    let (other, other_secret) = harness
        .create_confidential_client_named(ClientAuthMethod::Basic, "other")
        .await;
    let owner_auth = basic(&owner.to_string(), &owner_secret);
    let other_auth = basic(&other.to_string(), &other_secret);
    let tokens = issue_confidential(&harness, &owner, &owner_secret, "openid").await;
    let access = tokens["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    // A recording sink over the SAME state, exactly how the M4 fan-out will wire one.
    let sink = Arc::new(RecordingSink::default());
    let router = oidc_router(harness.state().clone().with_revocation_sink(sink.clone()));
    let event_count = || sink.events.lock().expect("lock").len();

    // A FOREIGN-client revoke flips nothing: 200, no event, no audit row.
    let (status, _, _) = send_through(router.clone(), revoke_request(&access, &other_auth)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_count(), 0, "a foreign revoke publishes no event");
    assert_eq!(
        harness.count_audit_action("token.revoke").await,
        0,
        "a foreign revoke writes no audit row"
    );

    // The owner's FIRST revoke flips state: exactly one event, one audit row.
    let (status, _, _) = send_through(router.clone(), revoke_request(&access, &owner_auth)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_count(), 1, "one event on the real state flip");
    assert_eq!(harness.count_audit_action("token.revoke").await, 1);

    // A DOUBLE revoke (already revoked) flips nothing: NO second event, NO second row.
    let (status, _, _) = send_through(router.clone(), revoke_request(&access, &owner_auth)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event_count(), 1, "no second event on the double revoke");
    assert_eq!(
        harness.count_audit_action("token.revoke").await,
        1,
        "no second audit row on the double revoke"
    );
}

#[tokio::test]
async fn an_active_refresh_token_introspection_body_has_the_full_shape() {
    // FIX 5 (issue #22 test rigor): the FULL active-refresh introspection body, not
    // just active==true. A refresh token carries scope/sub/client_id/exp/iat and, per
    // the serializer's refresh mapping, OMITS token_type and aud (a refresh token has
    // no RFC 6749 5.1 token type and no audience), never emitted as null.
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid profile").await;
    let refresh = tokens["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned();
    let id_sub = payload_claims(tokens["id_token"].as_str().expect("id_token"))["sub"]
        .as_str()
        .expect("id sub")
        .to_owned();

    let (status, doc) = introspect(&harness, &refresh, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["active"], Value::Bool(true), "active: {doc}");
    assert_eq!(doc["scope"], "openid profile");
    assert_eq!(doc["client_id"], client_id.to_string());
    assert_eq!(
        doc["sub"].as_str(),
        Some(id_sub.as_str()),
        "sub matches the ID token"
    );
    assert!(doc["exp"].is_number(), "exp present: {doc}");
    assert!(doc["iat"].is_number(), "iat present: {doc}");
    // The refresh mapping OMITS token_type and aud entirely (never emitted as null).
    assert!(
        doc.get("token_type").is_none(),
        "a refresh token has no token_type: {doc}"
    );
    assert!(
        doc.get("aud").is_none(),
        "a refresh token has no aud: {doc}"
    );
}

#[tokio::test]
async fn a_multi_audience_at_jwt_introspects_active() {
    // FIX 6 (issue #22, forward-looking for #28 resource indicators): RFC 7519 permits
    // `aud` to be a JSON array. IronAuth mints only single-string `aud` today, so this
    // SYNTHESIZES a multi-aud at+jwt: it takes a real minted token's claims (its `jti`
    // keys a live store row) and RE-SIGNS them with the SAME signing key and `jti` but
    // an `aud` ARRAY, then introspects it. It reads active:true, proving `resolve_jwt`
    // accepts an array `aud` and verifies against a member (it would read active:false
    // if `aud` were peeked only as a string).
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid").await;
    let access = tokens["access_token"].as_str().expect("access_token");

    // Re-sign the real token's claims with a multi-audience `aud` array: the client_id
    // it already targets PLUS a second resource (as #28 resource indicators will mint).
    let mut claims = payload_claims(access);
    claims.insert(
        "aud".to_owned(),
        Value::Array(vec![
            Value::String(client_id.to_string()),
            Value::String("https://api.example/resource".to_owned()),
        ]),
    );
    let multi_aud = harness.sign_at_jwt(&Value::Object(claims)).await;

    let (status, doc) = introspect(&harness, &multi_aud, &auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        doc["active"],
        Value::Bool(true),
        "a multi-aud at+jwt with a live store row introspects active: {doc}"
    );
    // The reported `aud` is the token's FIRST audience (its client_id), per the
    // serializer's single-string aud mapping.
    assert_eq!(
        doc["aud"],
        client_id.to_string(),
        "first aud reported: {doc}"
    );
}

/// A custom introspection serializer that emits a sentinel body under a distinctive
/// content type, to prove the endpoint dispatches through the installed serializer.
struct SentinelSerializer;

impl IntrospectionSerializer for SentinelSerializer {
    fn serialize(&self, claims: &IntrospectionClaims) -> SerializedIntrospection {
        SerializedIntrospection {
            content_type: "application/sentinel+json",
            body: format!(r#"{{"sentinel":true,"active":{}}}"#, claims.active),
        }
    }
}

#[tokio::test]
async fn a_swapped_introspection_serializer_is_honored() {
    // FIX 7 (issue #22 test rigor): the RFC 9701 serializer seam is real. Installing a
    // custom serializer via `with_introspection_serializer` changes the endpoint's wire
    // output (content type and body), proving the endpoint dispatches through the
    // state's serializer, mirroring the revocation-sink swap test.
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client_id.to_string(), &secret);
    let tokens = issue_confidential(&harness, &client_id, &secret, "openid").await;
    let access = tokens["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    // Rebuild the router over the same state with the custom serializer installed.
    let router = oidc_router(
        harness
            .state()
            .clone()
            .with_introspection_serializer(Arc::new(SentinelSerializer)),
    );
    let request = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, &auth)
        .body(Body::from(form(&[("token", &access)])))
        .expect("request builds");
    let (status, headers, body) = send_through(router, request).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "introspect through custom serializer"
    );
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/sentinel+json"),
        "the custom serializer's content type is served"
    );
    let doc = json(&body);
    assert_eq!(
        doc["sentinel"],
        Value::Bool(true),
        "the custom serializer's body is served: {body}"
    );
    assert_eq!(
        doc["active"],
        Value::Bool(true),
        "the active token flows through the custom serializer: {body}"
    );
}
