// SPDX-License-Identifier: MIT OR Apache-2.0

//! First-party social-provider federation tests (issue #74), on a REAL database against a
//! MOCK upstream driven through the ironauth-fetch test-harness injected dialer.
//!
//! Every provider is provisioned purely as STORED connector DATA (the preset's quirks,
//! capabilities, claim mapping, and client-auth kind), with endpoints pointed at the mock so
//! the login rides the plaintext loopback. The suite proves the acceptance-critical crux:
//!
//! - Google, Apple, Microsoft (OIDC) and GitHub (OAuth 2.0) each complete an end-to-end login
//!   with JIT provisioning, with accurate capability entries;
//! - Apple's first-authorization name/email are PERSISTED, and a returning login that OMITS
//!   them SUCCEEDS with the stored profile (the crux), while a Hide My Email relay address is
//!   flagged verified-but-unroutable and is never a routing target;
//! - Apple authenticates the token exchange with a generated ES256 signed-JWT client secret;
//! - GitHub resolves a VERIFIED PRIMARY email from the email endpoint when the profile omits it;
//! - provisioning and login emit audit events.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use common::Harness;
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use ironauth_oidc::{
    FederationKeyResolver, FederationRuntime, federated_external_id, oidc_router, routable_email,
};
use ironauth_store::{ConnectorCapabilities, ConnectorId, CorrelationId, NewConnector, UserId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

const MOCK_ISSUER: &str = "http://upstream.example";
const PUBLIC_IP: [u8; 4] = [93, 184, 216, 34];

/// An EC P-256 PKCS#8 v1 DER key (base64), for the Apple signed-JWT client secret.
const APPLE_KEY_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNuwcPLgOT+sjCMxXd/uhTe18xl4oeOGys2HpTnjjcq6hRANCAASS1c57Xfh8eGjBTbVtg8Ge1yy7M4CKVUDLw8TgwnmvhhzI5cP2PHCwZpZfsZSSZudLLYaigmRbzdVXR7QHzhxe";

/// A mock upstream serving BOTH the OIDC surface (discovery, JWKS, token with an `id_token`)
/// and the OAuth 2.0/GitHub surface (an access-token endpoint, a profile endpoint, an email
/// endpoint), dispatched by request path. Each per-request body is a test-settable slot.
struct Mock {
    addr: SocketAddr,
    key: SigningKey,
    oidc_token: Arc<Mutex<String>>,
    gh_profile: Arc<Mutex<String>>,
    gh_emails: Arc<Mutex<String>>,
}

async fn start_mock() -> Mock {
    let key = SigningKey::ed25519_from_seed(Some("up-kid".to_owned()), &[7_u8; 32]).expect("key");
    let jwks = JwkSet::from_signing_keys([&key])
        .expect("jwk set")
        .to_json()
        .expect("jwks json");
    let discovery = format!(
        r#"{{"issuer":"{MOCK_ISSUER}","authorization_endpoint":"{MOCK_ISSUER}/authorize","token_endpoint":"{MOCK_ISSUER}/token","jwks_uri":"{MOCK_ISSUER}/jwks","id_token_signing_alg_values_supported":["EdDSA"],"code_challenge_methods_supported":["S256"]}}"#
    );
    let oidc_token = Arc::new(Mutex::new(String::from("{}")));
    let gh_profile = Arc::new(Mutex::new(String::from("{}")));
    let gh_emails = Arc::new(Mutex::new(String::from("[]")));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (t, p, e) = (
        Arc::clone(&oidc_token),
        Arc::clone(&gh_profile),
        Arc::clone(&gh_emails),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let (discovery, jwks) = (discovery.clone(), jwks.clone());
            let (t, p, e) = (Arc::clone(&t), Arc::clone(&p), Arc::clone(&e));
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let first = request.lines().next().unwrap_or("");
                let body = if first.contains("openid-configuration") {
                    discovery
                } else if first.contains("/jwks") {
                    jwks
                } else if first.contains("/token") {
                    t.lock().expect("token lock").clone()
                } else if first.contains("/access_token") {
                    String::from(r#"{"access_token":"gh-access-token","token_type":"bearer"}"#)
                } else if first.contains("/user/emails") {
                    e.lock().expect("emails lock").clone()
                } else if first.contains("/user") {
                    p.lock().expect("profile lock").clone()
                } else {
                    String::from("{}")
                };
                let response = format!(
                    "HTTP/1.1 200 S\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    Mock {
        addr,
        key,
        oidc_token,
        gh_profile,
        gh_emails,
    }
}

fn build_runtime(addr: SocketAddr) -> Arc<FederationRuntime> {
    let resolver = Arc::new(StaticResolver::new(vec![IpAddr::from(PUBLIC_IP)]));
    let dialer = Arc::new(RecordingDialer::new(addr));
    let fetcher = Arc::new(Fetcher::from_parts(
        FetchLimits::default(),
        resolver,
        dialer,
    ));
    let keys = Arc::new(FederationKeyResolver::new_allow_http(
        Arc::clone(&fetcher),
        Duration::from_secs(300),
    ));
    Arc::new(FederationRuntime::new_allow_http(
        fetcher,
        keys,
        Duration::from_secs(300),
        Duration::from_secs(30),
    ))
}

fn router(harness: &Harness, runtime: Arc<FederationRuntime>) -> Router {
    oidc_router(harness.state().clone().with_federation(runtime))
}

/// The trait schema every provider maps into: email, name, login, and the Apple relay flag.
async fn seed_trait_schema(harness: &Harness) {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "email": {"type": "string", "minLength": 3},
            "name": {"type": "string"},
            "login": {"type": "string"},
            "email_relay": {"type": "boolean"}
        },
        "additionalProperties": false
    })
    .to_string();
    let env = harness.env().clone();
    let scope = harness.scope();
    let (_, version) = harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .trait_schemas()
        .create_version(&env, &schema, 1_000_000)
        .await
        .expect("create schema version");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .trait_schemas()
        .activate_version(&env, version)
        .await
        .expect("activate schema version");
}

/// Seed a connector at `slug` from a DATA-ONLY `definition_json` and `capabilities`, with the
/// given raw `client_secret` bytes (a shared secret, or an EC key for Apple's signed JWT).
async fn seed(
    harness: &Harness,
    slug: &str,
    definition_json: &str,
    capabilities: ConnectorCapabilities<'_>,
    client_secret: &[u8],
) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = ConnectorId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .connectors()
        .create(
            &env,
            &id,
            1_000_000,
            NewConnector {
                slug,
                definition_json,
                client_secret,
                capabilities,
                enabled: true,
            },
            None,
        )
        .await
        .expect("seed connector");
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

async fn drive_authorize(harness: &Harness, r: Router, slug: &str) -> String {
    let scope = harness.scope();
    let return_to = format!("/authorize?client_id={}", harness.client_id());
    let uri = format!(
        "/t/{}/e/{}/federation/{slug}/authorize?return_to={}",
        scope.tenant(),
        scope.environment(),
        encode(&return_to),
    );
    let response = r
        .oneshot(
            Request::builder()
                .uri(&uri)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("authorize");
    assert_eq!(response.status(), StatusCode::SEE_OTHER, "authorize 303s");
    response
        .headers()
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("str")
        .to_owned()
}

fn param(location: &str, name: &str) -> Option<String> {
    let query = location.split_once('?')?.1;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == name {
                return Some(v.to_owned());
            }
        }
    }
    None
}

async fn drive_callback(harness: &Harness, r: Router, slug: &str, state: &str) -> StatusCode {
    let scope = harness.scope();
    let uri = format!(
        "/t/{}/e/{}/federation/{slug}/callback?state={state}&code=up-code",
        scope.tenant(),
        scope.environment(),
    );
    r.oneshot(
        Request::builder()
            .uri(&uri)
            .body(Body::empty())
            .expect("req"),
    )
    .await
    .expect("callback")
    .status()
}

fn id_token(
    key: &SigningKey,
    nonce: &str,
    aud: &str,
    sub: &str,
    extra: serde_json::Value,
) -> String {
    let mut claims = serde_json::json!({
        "iss": MOCK_ISSUER,
        "sub": sub,
        "aud": aud,
        "exp": 4_102_444_800_i64,
        "iat": 0,
        "nonce": nonce,
    });
    if let (serde_json::Value::Object(c), serde_json::Value::Object(o)) = (&mut claims, extra) {
        for (k, v) in o {
            c.insert(k, v);
        }
    }
    let payload = serde_json::to_vec(&claims).expect("payload");
    sign_jws(key, &payload, &EmissionOptions::new().with_typ("JWT")).expect("sign")
}

fn token_body(id_token: &str) -> String {
    format!(r#"{{"access_token":"up-at","token_type":"Bearer","id_token":"{id_token}"}}"#)
}

async fn provisioned(harness: &Harness, external_id: &str) -> Option<UserId> {
    harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_external_id(external_id)
        .await
        .expect("by_external_id")
        .map(|record| record.id)
}

async fn traits_of(harness: &Harness, id: &UserId) -> serde_json::Value {
    harness
        .store()
        .scoped(harness.scope())
        .users()
        .traits(id)
        .await
        .expect("traits")
        .map_or(serde_json::Value::Null, |(_, value)| value)
}

/// Count audit rows in scope with `action`.
async fn audit_count(harness: &Harness, action: &str) -> usize {
    harness
        .store()
        .scoped(harness.scope())
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .filter(|record| record.action == action)
        .count()
}

/// A standard OIDC discovery-form connector definition (Google/Microsoft) with the mock issuer.
fn oidc_definition(slug: &str, client_id: &str) -> String {
    serde_json::json!({
        "connector_id": slug,
        "display_name": slug,
        "protocol": "oidc",
        "endpoints": {"issuer": MOCK_ISSUER},
        "scopes": ["openid", "email", "profile"],
        "client_id": client_id,
        "claim_mapping": {"traits": {
            "email": {"source": ["email"], "required": true},
            "name": {"source": ["name"], "required": false}
        }}
    })
    .to_string()
}

fn caps(refresh: bool, groups: bool, trust: &str) -> ConnectorCapabilities<'_> {
    ConnectorCapabilities {
        refresh,
        groups,
        logout_propagation: false,
        email_verified_trust: trust,
    }
}

#[tokio::test]
async fn google_completes_an_end_to_end_login_with_jit_and_accurate_capabilities() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    let mock = start_mock().await;
    let client_id = "google-client";
    seed(
        &harness,
        "google",
        &oidc_definition("google", client_id),
        caps(true, false, "trusted"),
        b"google-secret",
    )
    .await;

    let location = drive_authorize(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "google",
    )
    .await;
    assert!(location.starts_with(&format!("{MOCK_ISSUER}/authorize")));
    let nonce = param(&location, "nonce").expect("nonce");
    let state = param(&location, "state").expect("state");
    *mock.oidc_token.lock().unwrap() = token_body(&id_token(
        &mock.key,
        &nonce,
        client_id,
        "google-sub-1",
        serde_json::json!({"email": "user@gmail.test", "name": "G User"}),
    ));

    let status = drive_callback(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "google",
        &state,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "login completes");

    let id = provisioned(
        &harness,
        &federated_external_id(MOCK_ISSUER, "google-sub-1"),
    )
    .await
    .expect("google user provisioned");
    let traits = traits_of(&harness, &id).await;
    assert_eq!(
        traits.get("email").and_then(|v| v.as_str()),
        Some("user@gmail.test")
    );
    // Capability entries are stored accurately and queryable.
    let record = harness
        .store()
        .scoped(harness.scope())
        .connectors()
        .by_slug("google")
        .await
        .expect("by_slug")
        .expect("connector");
    assert!(record.capabilities.refresh);
    assert_eq!(record.capabilities.email_verified_trust, "trusted");
    // Provisioning and login emit audit events.
    assert!(
        audit_count(&harness, "user.create").await >= 1,
        "JIT provisioning audited"
    );
    assert!(
        audit_count(&harness, "session.create").await >= 1,
        "login session audited"
    );
}

#[tokio::test]
async fn microsoft_completes_login_with_groups_capability() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    let mock = start_mock().await;
    let client_id = "ms-client";
    seed(
        &harness,
        "microsoft",
        &oidc_definition("microsoft", client_id),
        caps(true, true, "trusted"),
        b"ms-secret",
    )
    .await;

    let location = drive_authorize(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "microsoft",
    )
    .await;
    let nonce = param(&location, "nonce").expect("nonce");
    let state = param(&location, "state").expect("state");
    *mock.oidc_token.lock().unwrap() = token_body(&id_token(
        &mock.key,
        &nonce,
        client_id,
        "ms-sub-1",
        serde_json::json!({"email": "user@contoso.test", "name": "M User"}),
    ));

    let status = drive_callback(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "microsoft",
        &state,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        provisioned(&harness, &federated_external_id(MOCK_ISSUER, "ms-sub-1"))
            .await
            .is_some()
    );
    let record = harness
        .store()
        .scoped(harness.scope())
        .connectors()
        .by_slug("microsoft")
        .await
        .expect("by_slug")
        .expect("connector");
    assert!(record.capabilities.groups, "Microsoft delivers groups");
}

/// An Apple connector definition: the signed-JWT client secret, the first-auth-only profile
/// quirk, and the Hide My Email relay domain, all expressed as DATA.
fn apple_definition(client_id: &str) -> String {
    serde_json::json!({
        "connector_id": "apple",
        "display_name": "Apple",
        "protocol": "oidc",
        "endpoints": {"issuer": MOCK_ISSUER},
        "scopes": ["openid", "email", "name"],
        "client_id": client_id,
        "client_auth": {"kind": "signed_jwt", "team_id": "TEAMID1234", "key_id": "KEYID5678", "audience": "https://appleid.apple.com"},
        "claim_mapping": {"traits": {
            "email": {"source": ["email"], "required": true},
            "name": {"source": ["name"], "required": false},
            "email_relay": {"source": ["email_relay"], "required": false}
        }},
        "quirks": {"profile_delivered_first_auth_only": true, "relay_email_domain": "privaterelay.appleid.com", "sticky_scopes": true}
    })
    .to_string()
}

#[tokio::test]
async fn apple_persists_the_first_auth_profile_and_a_returning_login_without_email_succeeds() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    let mock = start_mock().await;
    let client_id = "com.example.app";
    let apple_key = base64::engine::general_purpose::STANDARD
        .decode(APPLE_KEY_B64)
        .expect("apple key");
    seed(
        &harness,
        "apple",
        &apple_definition(client_id),
        caps(false, false, "trusted"),
        &apple_key,
    )
    .await;

    // First authorization: Apple delivers name and email. The signed-JWT client secret is
    // generated inside the callback (proving ES256 assertion generation end to end).
    let loc1 = drive_authorize(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "apple",
    )
    .await;
    let nonce1 = param(&loc1, "nonce").expect("nonce");
    let state1 = param(&loc1, "state").expect("state");
    *mock.oidc_token.lock().unwrap() = token_body(&id_token(
        &mock.key,
        &nonce1,
        client_id,
        "apple-sub-1",
        serde_json::json!({"email": "real@example.test", "name": "Apple User"}),
    ));
    let status1 = drive_callback(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "apple",
        &state1,
    )
    .await;
    assert_eq!(
        status1,
        StatusCode::SEE_OTHER,
        "first Apple login completes"
    );
    let id = provisioned(&harness, &federated_external_id(MOCK_ISSUER, "apple-sub-1"))
        .await
        .expect("apple user provisioned");
    let traits = traits_of(&harness, &id).await;
    assert_eq!(
        traits.get("email").and_then(|v| v.as_str()),
        Some("real@example.test"),
        "first-auth email persisted"
    );
    assert_eq!(
        traits.get("name").and_then(|v| v.as_str()),
        Some("Apple User")
    );

    // A RETURNING login: Apple omits name and email entirely. The stored profile is reused, so
    // the login SUCCEEDS (the crux) instead of failing the required-email check.
    let loc2 = drive_authorize(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "apple",
    )
    .await;
    let nonce2 = param(&loc2, "nonce").expect("nonce");
    let state2 = param(&loc2, "state").expect("state");
    *mock.oidc_token.lock().unwrap() = token_body(&id_token(
        &mock.key,
        &nonce2,
        client_id,
        "apple-sub-1",
        serde_json::json!({}),
    ));
    let status2 = drive_callback(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "apple",
        &state2,
    )
    .await;
    assert_eq!(
        status2,
        StatusCode::SEE_OTHER,
        "returning Apple login without email SUCCEEDS"
    );
    let same = provisioned(&harness, &federated_external_id(MOCK_ISSUER, "apple-sub-1"))
        .await
        .expect("same apple user");
    assert_eq!(same, id, "the returning login maps to the same identity");
    let traits2 = traits_of(&harness, &same).await;
    assert_eq!(
        traits2.get("email").and_then(|v| v.as_str()),
        Some("real@example.test"),
        "the returning login retains the stored email"
    );
}

#[tokio::test]
async fn apple_hide_my_email_relay_is_flagged_verified_but_unroutable() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    let mock = start_mock().await;
    let client_id = "com.example.app";
    let apple_key = base64::engine::general_purpose::STANDARD
        .decode(APPLE_KEY_B64)
        .expect("apple key");
    seed(
        &harness,
        "apple",
        &apple_definition(client_id),
        caps(false, false, "trusted"),
        &apple_key,
    )
    .await;

    let loc = drive_authorize(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "apple",
    )
    .await;
    let nonce = param(&loc, "nonce").expect("nonce");
    let state = param(&loc, "state").expect("state");
    let relay = "abc123def@privaterelay.appleid.com";
    *mock.oidc_token.lock().unwrap() = token_body(&id_token(
        &mock.key,
        &nonce,
        client_id,
        "apple-relay-1",
        serde_json::json!({"email": relay, "name": "Relay User"}),
    ));
    let status = drive_callback(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "apple",
        &state,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let id = provisioned(
        &harness,
        &federated_external_id(MOCK_ISSUER, "apple-relay-1"),
    )
    .await
    .expect("relay user provisioned");
    let traits = traits_of(&harness, &id).await;
    // The relay address is stored and flagged verified-but-unroutable.
    assert_eq!(traits.get("email").and_then(|v| v.as_str()), Some(relay));
    assert_eq!(
        traits
            .get("email_relay")
            .and_then(serde_json::Value::as_bool),
        Some(true),
        "the relay address is flagged"
    );
    // The relay address is NEVER selected as an operational mail routing target.
    assert_eq!(
        routable_email(relay, true),
        None,
        "a relay address is unroutable"
    );
}

/// A GitHub OAuth 2.0 connector definition (non-OIDC): explicit endpoints, no ID token, with the
/// email endpoint that resolves the primary verified email. Endpoints point at the mock.
fn github_definition(client_id: &str) -> String {
    serde_json::json!({
        "connector_id": "github",
        "display_name": "GitHub",
        "protocol": "oauth2",
        "endpoints": {
            "authorization_endpoint": format!("{MOCK_ISSUER}/login/oauth/authorize"),
            "token_endpoint": format!("{MOCK_ISSUER}/login/oauth/access_token"),
            "profile_endpoint": format!("{MOCK_ISSUER}/user"),
            "email_endpoint": format!("{MOCK_ISSUER}/user/emails"),
            "identity_issuer": MOCK_ISSUER
        },
        "scopes": ["read:user", "user:email"],
        "client_id": client_id,
        "claim_mapping": {"traits": {
            "email": {"source": ["email"], "required": true},
            "name": {"source": ["name"], "required": false},
            "login": {"source": ["login"], "required": false}
        }}
    })
    .to_string()
}

#[tokio::test]
async fn github_resolves_the_verified_primary_email_via_the_email_endpoint() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    let mock = start_mock().await;
    let client_id = "github-client";
    seed(
        &harness,
        "github",
        &github_definition(client_id),
        caps(false, false, "untrusted"),
        b"github-secret",
    )
    .await;
    // The profile OMITS a usable email (null); the email endpoint carries the primary verified one.
    *mock.gh_profile.lock().unwrap() =
        String::from(r#"{"id":42424242,"login":"octocat","name":"The Octocat","email":null}"#);
    *mock.gh_emails.lock().unwrap() = String::from(
        r#"[{"email":"unverified@example.test","primary":false,"verified":false},{"email":"octo@github.test","primary":true,"verified":true}]"#,
    );

    let location = drive_authorize(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "github",
    )
    .await;
    assert!(location.starts_with(&format!("{MOCK_ISSUER}/login/oauth/authorize")));
    assert!(param(&location, "nonce").is_none(), "OAuth2 sends no nonce");
    let state = param(&location, "state").expect("state");

    let status = drive_callback(
        &harness,
        router(&harness, build_runtime(mock.addr)),
        "github",
        &state,
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "github login completes");

    // The identity keys on the STABLE numeric id (namespaced), never the login or email.
    let id = provisioned(&harness, &federated_external_id(MOCK_ISSUER, "42424242"))
        .await
        .expect("github user provisioned by numeric id");
    let traits = traits_of(&harness, &id).await;
    assert_eq!(
        traits.get("email").and_then(|v| v.as_str()),
        Some("octo@github.test"),
        "the verified primary email was resolved from the email endpoint"
    );
    assert_eq!(
        traits.get("login").and_then(|v| v.as_str()),
        Some("octocat")
    );
    assert!(
        audit_count(&harness, "user.create").await >= 1,
        "github JIT provisioning audited"
    );
}
