// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `client_credentials` grant with service-account principals (RFC 6749 4.4,
//! RFC 9068, issue #23), over a real database (`DATABASE_URL`).
//!
//! Covers the acceptance criteria: an audience-restricted at+jwt carrying the
//! client's configured custom claims (AC1); a STABLE service-account `sub` distinct
//! from `client_id` and consistent across issuances (AC2); no refresh token (AC3);
//! the token is issued in the #22-consumable formats with grant linkage, so it is
//! revocable/introspectable by construction (AC4); and a failed client
//! authentication is `invalid_client` with the correct status and headers (AC6).
//! Adversarial: a custom claim cannot override a protected claim, `sub != client_id`,
//! no refresh token leaks, a public client is refused, and the principal is
//! scope-bound.

mod common;

use axum::http::{StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Harness, form, json, verify_clock};
use ironauth_config::{ClientCredentialsAudience, OidcConfig, TokenFormat as ConfigTokenFormat};
use ironauth_jose::verify;
use ironauth_oidc::{ClientAuthMethod, OPAQUE_ACCESS_TOKEN_PREFIX};
use ironauth_store::{ActorRef, CorrelationId, IssuedTokenId, ServiceAccountId, ServiceId};

/// A standard-padded Basic credential of `client_id:client_secret`.
fn basic_header(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// The `grant_type=client_credentials` form body (plus optional `scope`).
fn cc_form(scope: Option<&str>) -> String {
    match scope {
        Some(scope) => form(&[("grant_type", "client_credentials"), ("scope", scope)]),
        None => form(&[("grant_type", "client_credentials")]),
    }
}

/// Set a client's static custom-claims configuration through the store (the
/// declarative per-client config an admin surface will expose in a later milestone).
async fn set_custom_claims(
    harness: &Harness,
    client: &ironauth_store::ClientId,
    claims_json: &str,
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
        .set_custom_token_claims(env, client, Some(claims_json))
        .await
        .expect("set custom claims");
}

/// The decoded, verified claims of an at+jwt access token from a client-credentials
/// exchange, verified against the environment key and the given audience, as a JSON
/// object (so members are read with `claims["name"]`).
fn verified_claims(harness: &Harness, token: &str, audience: &str) -> serde_json::Value {
    let verified =
        verify(token, &harness.policy(audience), &verify_clock()).expect("at+jwt verifies");
    serde_json::Value::Object(verified.claims().raw().clone())
}

/// AC1 + AC2 (partial) + AC4 (structural): a confidential client obtains an
/// audience-restricted at+jwt whose `sub` is the service-account principal (distinct
/// from `client_id`) and which carries the client's configured custom claims; the
/// token is recorded against a grant, so #22 can introspect and revoke it.
#[tokio::test]
async fn client_credentials_issues_an_audience_restricted_at_jwt_with_custom_claims() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    set_custom_claims(
        &harness,
        &client,
        r#"{"department":"payments","tier":"gold"}"#,
    )
    .await;

    let (status, _headers, body) = harness
        .token_with_auth(&cc_form(None), Some(&basic_header(&client_id, &secret)))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "client_credentials exchange: {body}"
    );
    let value = json(&body);
    assert_eq!(value["token_type"], "Bearer");
    let access_token = value["access_token"].as_str().expect("access_token");

    // AC1: an at+jwt (RFC 9068), audience-restricted to the client id (the default
    // audience), carrying the configured custom claims.
    let claims = verified_claims(&harness, access_token, &client_id);
    assert_eq!(claims["iss"], harness.issuer().to_owned());
    assert_eq!(
        claims["aud"], client_id,
        "audience-restricted to the client"
    );
    assert_eq!(
        claims["client_id"], client_id,
        "client_id is the OAuth client"
    );
    assert_eq!(claims["department"], "payments", "custom claim is embedded");
    assert_eq!(claims["tier"], "gold", "custom claim is embedded");

    // AC2: sub is the stable service-account principal, DISTINCT from client_id.
    let sub = claims["sub"].as_str().expect("sub");
    assert!(
        sub.starts_with("sva_"),
        "sub is a service-account principal: {sub}"
    );
    assert_ne!(sub, client_id, "sub is DISTINCT from client_id (RFC 9068)");

    // A machine token carries NO authentication context: no acr, no auth_time (there
    // was no user authentication event to derive them from).
    assert!(claims.get("acr").is_none(), "no acr on a machine token");
    assert!(
        claims.get("auth_time").is_none(),
        "no auth_time on a machine token"
    );

    // AC4 (structural): the token is recorded against a grant, so the #22
    // introspection resolve returns it as active and a grant revoke would flip it.
    let jti = IssuedTokenId::parse_in_scope(claims["jti"].as_str().expect("jti"), &harness.scope())
        .expect("jti parses in scope");
    let resolved = harness
        .store()
        .scoped(harness.scope())
        .authorization()
        .resolve_access_token(&jti)
        .await
        .expect("resolve")
        .expect("the at+jwt is recorded against a grant");
    assert_eq!(resolved.subject, sub, "the grant carries the machine sub");
    assert_eq!(resolved.client_id, client_id);
    assert!(
        resolved.active,
        "the token's grant is live (revocable via #22)"
    );
}

/// AC2: the service-account `sub` is STABLE across issuances (the principal is minted
/// once, read back every time) and always distinct from `client_id`.
#[tokio::test]
async fn sub_is_stable_across_issuances() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Post)
        .await;
    let client_id = client.to_string();

    let post_body = form(&[
        ("grant_type", "client_credentials"),
        ("client_id", &client_id),
        ("client_secret", &secret),
    ]);
    let mut subs = Vec::new();
    for _ in 0..3 {
        let (status, _headers, body) = harness.token(&post_body).await;
        assert_eq!(status, StatusCode::OK, "exchange: {body}");
        let claims = verified_claims(
            &harness,
            json(&body)["access_token"].as_str().unwrap(),
            &client_id,
        );
        subs.push(claims["sub"].as_str().expect("sub").to_owned());
    }
    assert_eq!(subs[0], subs[1], "sub is stable across issuances");
    assert_eq!(subs[1], subs[2], "sub is stable across issuances");
    assert_ne!(subs[0], client_id, "sub is distinct from client_id");

    // The principal read back through the store matches the token's sub.
    let principal = harness
        .store()
        .scoped(harness.scope())
        .service_accounts()
        .principal_for(&client)
        .await
        .expect("read")
        .expect("a principal was minted");
    assert_eq!(principal.to_string(), subs[0]);
}

/// AC3: NO refresh token is returned for the client-credentials grant (RFC 6749
/// 4.4.3), and no ID token either (there is no user).
#[tokio::test]
async fn no_refresh_token_or_id_token_is_returned() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();

    let (status, _headers, body) = harness
        .token_with_auth(
            &cc_form(Some("read write")),
            Some(&basic_header(&client_id, &secret)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");
    let value = json(&body);
    assert!(
        value.get("refresh_token").is_none(),
        "RFC 6749 4.4.3: no refresh token on client_credentials"
    );
    assert!(value.get("id_token").is_none(), "no id_token (no user)");
    // The granted scope is echoed.
    assert_eq!(value["scope"], "read write");

    // DB-negative (RFC 6749 4.4.3): the guarantee holds at the DATABASE, not only in
    // the response body. A client-credentials issuance opens NO refresh family and
    // mints NO refresh token, so both rotation tables are empty for this scope.
    let (families, tokens) = harness.count_refresh_rows().await;
    assert_eq!(
        families, 0,
        "no refresh_families row for a client_credentials grant"
    );
    assert_eq!(
        tokens, 0,
        "no refresh_tokens row for a client_credentials grant"
    );
}

/// Adversarial: a custom claim can NEVER set a reserved claim name, proven against the
/// REAL mint (a signed, verified token). The hostile stored config names the protocol
/// claims (`sub`/`iss`/`aud`/`client_id`/`scope`/`exp`) AND the authentication-context
/// and binding claims (`acr`/`amr`/`auth_time`/`nonce`/`cnf`) a machine token must
/// never carry: the protocol claims keep their real values and the auth-context/binding
/// claims never appear, so a per-client config cannot forge an authentication context
/// or a self-asserted confirmation key.
#[tokio::test]
async fn a_custom_claim_cannot_override_a_protected_claim() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    // A hostile custom-claims config written straight into the store, naming the
    // protocol claims plus the authentication-context and binding claims a machine
    // token must never assert, plus a benign one.
    set_custom_claims(
        &harness,
        &client,
        r#"{"sub":"attacker","iss":"https://evil.test","aud":"https://evil.test/api","client_id":"cli_attacker","scope":"admin","exp":9999999999,"acr":"urn:evil:acr:high","amr":["mfa"],"auth_time":123,"nonce":"evil-nonce","cnf":{"jkt":"evil-thumbprint"},"role":"reader"}"#,
    )
    .await;

    let (status, _headers, body) = harness
        .token_with_auth(&cc_form(None), Some(&basic_header(&client_id, &secret)))
        .await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");
    let claims = verified_claims(
        &harness,
        json(&body)["access_token"].as_str().unwrap(),
        &client_id,
    );

    // Every protected claim keeps its real value; only the benign non-protected claim
    // is embedded.
    assert!(
        claims["sub"].as_str().unwrap().starts_with("sva_"),
        "sub is the real principal"
    );
    assert_ne!(claims["sub"], "attacker");
    assert_eq!(claims["iss"], harness.issuer().to_owned());
    assert_eq!(claims["aud"], client_id);
    assert_eq!(claims["client_id"], client_id);
    assert!(
        claims.get("scope").is_none(),
        "the hostile scope claim is dropped"
    );
    assert_ne!(
        claims["exp"].as_i64().unwrap(),
        9_999_999_999,
        "the real exp is not overridden"
    );
    // The authentication-context and binding claims a machine token never carries stay
    // absent: a custom claim cannot inject a human auth context (acr/amr/auth_time/
    // nonce) or a self-asserted confirmation key (cnf) into the minted token.
    for forbidden in ["acr", "amr", "auth_time", "nonce", "cnf"] {
        assert!(
            claims.get(forbidden).is_none(),
            "{forbidden} must never be injected by a custom claim on a machine token"
        );
    }
    assert_eq!(
        claims["role"], "reader",
        "the benign non-protected claim lands"
    );
}

/// AC6: a failed client authentication is `invalid_client` with the correct status
/// and headers (401, plus `WWW-Authenticate: Basic` for a Basic attempt).
#[tokio::test]
async fn failed_client_authentication_is_invalid_client_with_headers() {
    let harness = Harness::start().await;
    let (client, _secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();

    let (status, headers, body) = harness
        .token_with_auth(
            &cc_form(None),
            Some(&basic_header(&client_id, "the-wrong-secret")),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong secret: {body}");
    assert_eq!(json(&body)["error"], "invalid_client");
    assert_eq!(
        headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"ironauth\", charset=\"UTF-8\""),
        "a failed Basic attempt carries the RFC 6749 5.2 challenge"
    );
}

/// Adversarial (RFC 6749 4.4): a PUBLIC client (auth method `none`) cannot use the
/// client-credentials grant, because it authenticates with nothing.
#[tokio::test]
async fn a_public_client_cannot_use_the_grant() {
    let harness = Harness::start().await;
    // The default harness client is PUBLIC (method none).
    let public = harness.client_id().to_string();

    let (status, _headers, body) = harness
        .token(&form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &public),
        ]))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "public client: {body}");
    assert_eq!(json(&body)["error"], "invalid_client");
}

/// Errors: an out-of-policy scope (a machine principal may not request `openid` or
/// `offline_access`) is `invalid_scope`.
#[tokio::test]
async fn an_out_of_policy_scope_is_invalid_scope() {
    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();

    for bad in [
        "openid",
        "read openid",
        "offline_access",
        "read offline_access write",
    ] {
        let (status, _headers, body) = harness
            .token_with_auth(
                &cc_form(Some(bad)),
                Some(&basic_header(&client_id, &secret)),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "scope {bad:?}: {body}");
        assert_eq!(json(&body)["error"], "invalid_scope", "scope {bad:?}");
    }
}

/// The default audience is configurable per environment: with `issuer`, the token's
/// `aud` is the per-environment issuer rather than the client id.
#[tokio::test]
async fn the_default_audience_is_configurable() {
    let config = OidcConfig {
        client_credentials_default_audience: ClientCredentialsAudience::Issuer,
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();

    let (status, _headers, body) = harness
        .token_with_auth(&cc_form(None), Some(&basic_header(&client_id, &secret)))
        .await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");
    let issuer = harness.issuer().to_owned();
    let claims = verified_claims(
        &harness,
        json(&body)["access_token"].as_str().unwrap(),
        &issuer,
    );
    assert_eq!(claims["aud"], issuer, "aud is the per-environment issuer");
    assert_eq!(claims["client_id"], client_id, "client_id stays the client");
}

/// AC4 (opaque): with the environment default flipped to opaque, the
/// client-credentials token is an `ira_at_` reference token that resolves through
/// the internal store lookup (the #22 introspection path) to the machine principal.
#[tokio::test]
async fn opaque_client_credentials_token_is_introspectable() {
    let config = OidcConfig {
        default_access_token_format: ConfigTokenFormat::Opaque,
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    let scope = harness.scope();
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();

    let (status, _headers, body) = harness
        .token_with_auth(
            &cc_form(Some("read")),
            Some(&basic_header(&client_id, &secret)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");
    let access_token = json(&body)["access_token"].as_str().unwrap().to_owned();
    assert!(
        access_token.starts_with(OPAQUE_ACCESS_TOKEN_PREFIX),
        "opaque token prefix"
    );
    assert_eq!(access_token.matches('.').count(), 0, "not a JWS");

    // The internal resolve (the #22 introspection path) returns the machine
    // principal, the client, the configured audience, and the granted scope.
    let active = harness
        .store()
        .scoped(scope)
        .authorization()
        .resolve_opaque_access_token(&access_token, 0)
        .await
        .expect("resolve")
        .expect("active");
    assert!(
        active.subject.starts_with("sva_"),
        "sub is the machine principal"
    );
    assert_eq!(active.client_id, client_id);
    assert_eq!(
        active.audience, client_id,
        "the default audience is the client"
    );
    assert_eq!(active.scope.as_deref(), Some("read"));
}

/// Adversarial: two clients in the same environment get DISTINCT service-account
/// principals, and a principal id is scope-bound (it embeds its (tenant, environment)
/// and does not parse under another scope), so a principal cannot cross a tenant.
#[tokio::test]
async fn service_account_principals_are_distinct_and_scope_bound() {
    let harness = Harness::start().await;
    let (client_a, secret_a) = harness
        .create_confidential_client_named(ClientAuthMethod::Basic, "client a")
        .await;
    let (client_b, secret_b) = harness
        .create_confidential_client_named(ClientAuthMethod::Basic, "client b")
        .await;

    let sub_a = issue_and_read_sub(&harness, &client_a.to_string(), &secret_a).await;
    let sub_b = issue_and_read_sub(&harness, &client_b.to_string(), &secret_b).await;
    assert_ne!(sub_a, sub_b, "distinct clients get distinct principals");

    // The principal id embeds its scope: it parses under the home scope, and a
    // different scope sees a uniform not-found (it cannot be read cross-tenant).
    assert!(
        ServiceAccountId::parse_in_scope(&sub_a, &harness.scope()).is_ok(),
        "the principal parses in its home scope"
    );
    let foreign = harness.second_scope().await;
    assert!(
        ServiceAccountId::parse_in_scope(&sub_a, &foreign).is_err(),
        "the principal is not parseable under another scope (scope-bound)"
    );
}

/// Issue a client-credentials token for `client_id` and return the token's `sub`.
async fn issue_and_read_sub(harness: &Harness, client_id: &str, secret: &str) -> String {
    let (status, _headers, body) = harness
        .token_with_auth(&cc_form(None), Some(&basic_header(client_id, secret)))
        .await;
    assert_eq!(status, StatusCode::OK, "exchange: {body}");
    let claims = verified_claims(
        harness,
        json(&body)["access_token"].as_str().unwrap(),
        client_id,
    );
    claims["sub"].as_str().expect("sub").to_owned()
}
