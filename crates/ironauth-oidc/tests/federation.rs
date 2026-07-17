// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end and adversarial federation login tests (issue #75, PR B), on a REAL
//! database against a MOCK upstream OIDC provider driven through the ironauth-fetch
//! test-harness injected dialer (like the client-assertion / ACME tests).
//!
//! The whole point of the declarative connector is ZERO code change to add a provider:
//! every test here provisions the upstream purely as a STORED connector definition, never
//! a code path. The suite proves the wired flow the security review needs:
//!
//! - a full federated login through a data-only connector provisions a local identity and
//!   establishes a session whose token carries the HONEST federated `acr`/`amr`;
//! - a private-range issuer/`jwks_uri` is BLOCKED on the wire, so the login fails and NO
//!   user is provisioned;
//! - every malicious upstream ID token (`alg:none`, algorithm confusion, wrong `kid`,
//!   forged issuer, wrong audience, expired, `nonce` mismatch) is rejected with NO user
//!   provisioned;
//! - a replayed / forged / absent callback `state` fails (single-use CSRF).

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use ironauth_oidc::{
    FederationKeyResolver, FederationRuntime, federated_amr_from_auth_methods,
    federated_external_id, oidc_router,
};
use ironauth_store::{
    ConnectorCapabilities, ConnectorId, CorrelationId, NewConnector, Scope, SessionId, UserId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

const UPSTREAM_ISSUER: &str = "http://upstream.example";
const UPSTREAM_CLIENT_ID: &str = "ironauth-at-upstream";
const CONNECTOR_SLUG: &str = "acme";

/// A mock upstream OIDC provider: its address, its signing key, the `id_token` JSON its token
/// endpoint currently returns (settable per test after the nonce is known), and the HTTP STATUS
/// its token endpoint currently returns (settable so a test can drive a per-request `400` or a
/// real `5xx` outage, issue #76).
struct Upstream {
    addr: SocketAddr,
    key: SigningKey,
    token_response: Arc<Mutex<String>>,
    token_status: Arc<Mutex<u16>>,
}

/// Start the mock upstream. It dispatches by request path: discovery (always `200`), JWKS
/// (always `200`), and a token endpoint whose body AND status are the shared, test-settable
/// `token_response` / `token_status` (the status defaults to `200`).
async fn start_upstream() -> Upstream {
    let key = SigningKey::ed25519_from_seed(Some("up-kid".to_owned()), &[7_u8; 32]).expect("key");
    let jwks = JwkSet::from_signing_keys([&key])
        .expect("jwk set")
        .to_json()
        .expect("jwks json");
    let discovery = format!(
        r#"{{"issuer":"{UPSTREAM_ISSUER}","authorization_endpoint":"{UPSTREAM_ISSUER}/authorize","token_endpoint":"{UPSTREAM_ISSUER}/token","jwks_uri":"{UPSTREAM_ISSUER}/jwks","id_token_signing_alg_values_supported":["EdDSA"],"code_challenge_methods_supported":["S256"]}}"#
    );
    let token_response = Arc::new(Mutex::new(String::from("{}")));
    let token_status = Arc::new(Mutex::new(200_u16));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let token_for_server = Arc::clone(&token_response);
    let status_for_server = Arc::clone(&token_status);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let discovery = discovery.clone();
            let jwks = jwks.clone();
            let token = Arc::clone(&token_for_server);
            let status = Arc::clone(&status_for_server);
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let first = request.lines().next().unwrap_or("");
                let (code, body) = if first.contains("openid-configuration") {
                    (200_u16, discovery)
                } else if first.contains("/jwks") {
                    (200, jwks)
                } else if first.contains("/token") {
                    (
                        *status.lock().expect("status lock"),
                        token.lock().expect("token lock").clone(),
                    )
                } else {
                    (200, String::from("{}"))
                };
                let response = format!(
                    "HTTP/1.1 {code} S\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    Upstream {
        addr,
        key,
        token_response,
        token_status,
    }
}

/// Build a federation runtime pointing at `addr` through the injected dialer, with every
/// host resolving to `resolver_ips` (a public IP for the happy path; a private IP to prove
/// the SSRF block).
fn build_runtime(addr: SocketAddr, resolver_ips: Vec<IpAddr>) -> Arc<FederationRuntime> {
    let resolver = Arc::new(StaticResolver::new(resolver_ips));
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
        // A short probe window keeps the health-backoff timings readable under the harness clock.
        Duration::from_secs(30),
    ))
}

/// Store an issuer-form connector pointing at the mock upstream (a DATA-ONLY definition, no
/// code path). Created on the CONTROL plane, which provisions the scope's envelope keys.
async fn seed_connector(harness: &Harness) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = ConnectorId::generate(&env, &scope);
    let definition = format!(
        r#"{{"connector_id":"{CONNECTOR_SLUG}","display_name":"Acme","protocol":"oidc","endpoints":{{"issuer":"{UPSTREAM_ISSUER}"}},"scopes":["openid","email"],"client_id":"{UPSTREAM_CLIENT_ID}"}}"#
    );
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
                slug: CONNECTOR_SLUG,
                definition_json: &definition,
                client_secret: b"upstream-client-secret",
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
        .expect("seed connector");
}

/// The federation-enabled router: the harness `OidcState` with the runtime installed.
fn federation_router(harness: &Harness, runtime: Arc<FederationRuntime>) -> Router {
    oidc_router(harness.state().clone().with_federation(runtime))
}

/// Minimal percent-encoding for the `return_to` value (so its own `?`/`=`/`&` do not break
/// the outer query), matching the server's decoder.
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

/// Drive the federated authorize leg and return the upstream redirect `Location`.
async fn drive_authorize(harness: &Harness, router: Router) -> String {
    let scope = harness.scope();
    let return_to = format!("/authorize?client_id={}", harness.client_id());
    let uri = format!(
        "/t/{}/e/{}/federation/{CONNECTOR_SLUG}/authorize?return_to={}",
        scope.tenant(),
        scope.environment(),
        encode(&return_to),
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("authorize");
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the authorize leg 302s to the upstream"
    );
    response
        .headers()
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("location str")
        .to_owned()
}

/// Extract a query parameter from an upstream redirect URL.
fn param(location: &str, name: &str) -> String {
    let query = location.split_once('?').expect("query").1;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == name {
                return v.to_owned();
            }
        }
    }
    panic!("missing param {name} in {location}");
}

/// Mint an upstream `id_token` with the given claim overrides, signed with the upstream key.
fn id_token(key: &SigningKey, base: serde_json::Value, overrides: serde_json::Value) -> String {
    let mut claims = base;
    if let (serde_json::Value::Object(c), serde_json::Value::Object(o)) = (&mut claims, overrides) {
        for (k, v) in o {
            c.insert(k, v);
        }
    }
    let payload = serde_json::to_vec(&claims).expect("payload");
    sign_jws(key, &payload, &EmissionOptions::new().with_typ("JWT")).expect("sign")
}

/// The base `id_token` claims for a valid upstream token bound to `nonce`.
fn base_claims(nonce: &str, sub: &str) -> serde_json::Value {
    serde_json::json!({
        "iss": UPSTREAM_ISSUER,
        "sub": sub,
        "aud": UPSTREAM_CLIENT_ID,
        "exp": 4_102_444_800_i64, // year 2100 (harness clock is at the epoch)
        "iat": 0,
        "nonce": nonce,
    })
}

/// A token-endpoint response wrapping an `id_token`.
fn token_response(id_token: &str) -> String {
    format!(r#"{{"access_token":"upstream-at","token_type":"Bearer","id_token":"{id_token}"}}"#)
}

/// Drive the callback with a `state` and `code`, returning the response.
async fn drive_callback(
    harness: &Harness,
    router: Router,
    state: &str,
) -> axum::response::Response {
    let scope = harness.scope();
    let uri = format!(
        "/t/{}/e/{}/federation/{CONNECTOR_SLUG}/callback?state={state}&code=upstream-code",
        scope.tenant(),
        scope.environment(),
    );
    router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("callback")
}

/// Whether a user with `external_id` (the upstream sub) is provisioned in scope.
async fn user_provisioned(harness: &Harness, external_id: &str) -> bool {
    harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_external_id(external_id)
        .await
        .expect("by_external_id")
        .is_some()
}

/// The provisioned user id for `external_id`, or `None` when no such federated user
/// exists in scope.
async fn provisioned_user_id(harness: &Harness, external_id: &str) -> Option<UserId> {
    harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_external_id(external_id)
        .await
        .expect("by_external_id")
        .map(|record| record.id)
}

/// Register and activate a trait schema in the harness scope (issue #75, PR C): the
/// active schema the callback type-checks the mapped traits against. Registered on
/// the control plane, which provisions the scope's envelope keys.
async fn seed_trait_schema(harness: &Harness, schema_json: &str) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let (_, version) = harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .trait_schemas()
        .create_version(&env, schema_json, 1_000_000)
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

/// Seed an issuer-form connector at `slug` carrying an explicit `definition_json` (so a
/// test can install a claim mapping), pointing at the mock upstream. A DATA-ONLY
/// definition, created on the control plane.
async fn seed_connector_json(harness: &Harness, slug: &str, definition_json: &str) {
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
                client_secret: b"upstream-client-secret",
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
        .expect("seed connector");
}

/// The trait schema the claim-mapping tests type-check against: `email` (a string of at
/// least 3 chars) and `name` (a string), with NO additional properties (so a mapping
/// targeting an undeclared trait is a Config fault).
fn mapping_trait_schema() -> String {
    serde_json::json!({
        "type": "object",
        "properties": {
            "email": {"type": "string", "minLength": 3},
            "name": {"type": "string"}
        },
        "additionalProperties": false
    })
    .to_string()
}

/// An issuer-form connector definition mapping the upstream `email` (required) and
/// `name` (optional) claims to IronAuth traits: a DATA-ONLY connector added with ZERO
/// code change.
fn mapped_connector_definition(slug: &str) -> String {
    format!(
        r#"{{"connector_id":"{slug}","display_name":"Mapped","protocol":"oidc","endpoints":{{"issuer":"{UPSTREAM_ISSUER}"}},"scopes":["openid","email"],"client_id":"{UPSTREAM_CLIENT_ID}","claim_mapping":{{"traits":{{"email":{{"source":["email"]}},"name":{{"source":["name"],"required":false}}}}}}}}"#
    )
}

/// Drive a full federated login for `slug` with an `id_token` built from `overrides`
/// merged onto the base claims (bound to the login's nonce and `sub`), returning the
/// callback response.
async fn login_with_overrides(
    harness: &Harness,
    runtime: &Arc<FederationRuntime>,
    upstream: &Upstream,
    slug: &str,
    sub: &str,
    overrides: serde_json::Value,
) -> axum::response::Response {
    let location = authorize_for(
        harness,
        federation_router(harness, Arc::clone(runtime)),
        slug,
    )
    .await;
    let location = location
        .headers()
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("location str")
        .to_owned();
    let state = param(&location, "state");
    let nonce = param(&location, "nonce");
    let token = id_token(&upstream.key, base_claims(&nonce, sub), overrides);
    *upstream.token_response.lock().unwrap() = token_response(&token);
    callback_for(
        harness,
        federation_router(harness, Arc::clone(runtime)),
        slug,
        &state,
    )
    .await
}

#[tokio::test]
async fn a_data_only_connector_provisions_mapped_traits_end_to_end_with_zero_code_change() {
    // The PR C acceptance crux: a connector's declarative claim mapping maps upstream
    // claims (email, name) to IronAuth traits, and the provisioned user CARRIES them,
    // added purely as a stored definition (zero code change).
    let harness = Harness::start().await;
    seed_trait_schema(&harness, &mapping_trait_schema()).await;
    seed_connector_json(
        &harness,
        CONNECTOR_SLUG,
        &mapped_connector_definition(CONNECTOR_SLUG),
    )
    .await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    let response = login_with_overrides(
        &harness,
        &runtime,
        &upstream,
        CONNECTOR_SLUG,
        "mapped-sub-1",
        serde_json::json!({ "email": "user@upstream.example", "name": "Ada Lovelace" }),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the mapped login resumes the local authorize"
    );

    let external_id = federated_external_id(UPSTREAM_ISSUER, "mapped-sub-1");
    let user_id = provisioned_user_id(&harness, &external_id)
        .await
        .expect("the federated user is provisioned");
    let (version, traits) = harness
        .store()
        .scoped(harness.scope())
        .users()
        .traits(&user_id)
        .await
        .expect("traits read")
        .expect("the provisioned user carries mapped traits");
    assert_eq!(version, 1, "the traits record the active schema version");
    assert_eq!(
        traits.get("email"),
        Some(&serde_json::json!("user@upstream.example"))
    );
    assert_eq!(traits.get("name"), Some(&serde_json::json!("Ada Lovelace")));
}

#[tokio::test]
async fn a_mapped_email_from_a_nested_path_is_nfkc_normalized_when_provisioned() {
    // INFO fix: the email trait is NFKC-normalized regardless of the claim PATH it maps from.
    // Here `email` maps from a NESTED path (`emails.0`) and the upstream value carries a
    // fullwidth commercial-at (U+FF20); the provisioned trait must be the ordinary ASCII form,
    // proving the resolved email is canonicalized in the evaluator (not only the top-level claim).
    let harness = Harness::start().await;
    seed_trait_schema(&harness, &mapping_trait_schema()).await;
    let slug = "nested-email";
    let definition = format!(
        r#"{{"connector_id":"{slug}","display_name":"Nested","protocol":"oidc","endpoints":{{"issuer":"{UPSTREAM_ISSUER}"}},"scopes":["openid","email"],"client_id":"{UPSTREAM_CLIENT_ID}","claim_mapping":{{"traits":{{"email":{{"source":["emails.0"]}}}}}}}}"#
    );
    seed_connector_json(&harness, slug, &definition).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    let response = login_with_overrides(
        &harness,
        &runtime,
        &upstream,
        slug,
        "nested-email-sub",
        serde_json::json!({ "emails": ["user\u{FF20}x.example"] }),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the nested-path mapped login resumes the local authorize"
    );

    let external_id = federated_external_id(UPSTREAM_ISSUER, "nested-email-sub");
    let user_id = provisioned_user_id(&harness, &external_id)
        .await
        .expect("the federated user is provisioned");
    let (_, traits) = harness
        .store()
        .scoped(harness.scope())
        .users()
        .traits(&user_id)
        .await
        .expect("traits read")
        .expect("the provisioned user carries mapped traits");
    assert_eq!(
        traits.get("email"),
        Some(&serde_json::json!("user@x.example")),
        "the nested-path email is NFKC-normalized before it is provisioned"
    );
}

#[tokio::test]
async fn a_missing_required_claim_fails_closed_and_provisions_no_user_upstream_protocol() {
    // FAIL-CLOSED (UpstreamProtocol class): the mapping requires `email` but the upstream
    // OMITS it, so the evaluator returns an UpstreamClaim error and the login aborts BEFORE
    // any user row is written (the "never a partially provisioned user" criterion).
    let harness = Harness::start().await;
    seed_trait_schema(&harness, &mapping_trait_schema()).await;
    seed_connector_json(
        &harness,
        CONNECTOR_SLUG,
        &mapped_connector_definition(CONNECTOR_SLUG),
    )
    .await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    // The upstream token carries no `email` (only the optional `name`).
    let response = login_with_overrides(
        &harness,
        &runtime,
        &upstream,
        CONNECTOR_SLUG,
        "no-email-sub",
        serde_json::json!({ "name": "No Email" }),
    )
    .await;
    assert_ne!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a missing required claim must not complete the login"
    );
    assert!(session_id_from_cookies(&response, &harness.scope()).is_none());
    assert!(
        provisioned_user_id(
            &harness,
            &federated_external_id(UPSTREAM_ISSUER, "no-email-sub")
        )
        .await
        .is_none(),
        "NO user is provisioned when a required claim is absent (fail-closed)"
    );
}

#[tokio::test]
async fn a_type_mismatch_fails_closed_and_provisions_no_user_config() {
    // FAIL-CLOSED (Config class): the upstream sends `email` as a NUMBER, a well-formed value
    // that fails the trait schema's type check. That is a mapping-definition fault (Config),
    // distinct from the missing-claim UpstreamProtocol case, and it likewise provisions NO user.
    let harness = Harness::start().await;
    seed_trait_schema(&harness, &mapping_trait_schema()).await;
    seed_connector_json(
        &harness,
        CONNECTOR_SLUG,
        &mapped_connector_definition(CONNECTOR_SLUG),
    )
    .await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    let response = login_with_overrides(
        &harness,
        &runtime,
        &upstream,
        CONNECTOR_SLUG,
        "num-email-sub",
        serde_json::json!({ "email": 42 }),
    )
    .await;
    assert_ne!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a trait type mismatch must not complete the login"
    );
    assert!(session_id_from_cookies(&response, &harness.scope()).is_none());
    assert!(
        provisioned_user_id(
            &harness,
            &federated_external_id(UPSTREAM_ISSUER, "num-email-sub")
        )
        .await
        .is_none(),
        "NO user is provisioned when a mapped trait fails the type check (fail-closed)"
    );
}

#[tokio::test]
async fn a_returning_login_refreshes_the_mapped_traits() {
    // The documented returning-login policy: a re-login re-applies the mapping so upstream
    // trait drift is reflected, still on the ONE issuer-namespaced identity (no second user).
    let harness = Harness::start().await;
    seed_trait_schema(&harness, &mapping_trait_schema()).await;
    seed_connector_json(
        &harness,
        CONNECTOR_SLUG,
        &mapped_connector_definition(CONNECTOR_SLUG),
    )
    .await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    let first = login_with_overrides(
        &harness,
        &runtime,
        &upstream,
        CONNECTOR_SLUG,
        "returning-sub",
        serde_json::json!({ "email": "old@upstream.example", "name": "Old Name" }),
    )
    .await;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    let external_id = federated_external_id(UPSTREAM_ISSUER, "returning-sub");
    let user_id = provisioned_user_id(&harness, &external_id)
        .await
        .expect("first login");

    // Second login: the upstream now asserts a different name; the traits refresh in place.
    let second = login_with_overrides(
        &harness,
        &runtime,
        &upstream,
        CONNECTOR_SLUG,
        "returning-sub",
        serde_json::json!({ "email": "new@upstream.example", "name": "New Name" }),
    )
    .await;
    assert_eq!(second.status(), StatusCode::SEE_OTHER);
    let user_id_again = provisioned_user_id(&harness, &external_id)
        .await
        .expect("returning login");
    assert_eq!(
        user_id, user_id_again,
        "a returning login reuses the one identity"
    );
    let (_, traits) = harness
        .store()
        .scoped(harness.scope())
        .users()
        .traits(&user_id)
        .await
        .expect("traits read")
        .expect("traits present");
    assert_eq!(
        traits.get("email"),
        Some(&serde_json::json!("new@upstream.example"))
    );
    assert_eq!(traits.get("name"), Some(&serde_json::json!("New Name")));
}

/// The session id from a `Set-Cookie` response, or `None` when no session cookie is set.
fn session_id_from_cookies(
    response: &axum::response::Response,
    scope: &Scope,
) -> Option<SessionId> {
    for value in response.headers().get_all(header::SET_COOKIE) {
        let value = value.to_str().ok()?;
        if let Some(rest) = value.strip_prefix("__Host-ironauth_session=") {
            let id = rest.split(';').next()?;
            return SessionId::parse_in_scope(id, scope).ok();
        }
    }
    None
}

#[tokio::test]
async fn a_full_federated_login_provisions_a_user_and_an_honest_session_with_zero_code_change() {
    let harness = Harness::start().await;
    seed_connector(&harness).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    // Authorize: 302 to the upstream, carrying an unguessable state and nonce.
    let location =
        drive_authorize(&harness, federation_router(&harness, Arc::clone(&runtime))).await;
    assert!(
        location.starts_with(&format!("{UPSTREAM_ISSUER}/authorize?")),
        "{location}"
    );
    assert!(
        location.contains("code_challenge="),
        "PKCE S256 is sent (upstream advertises it)"
    );
    let state = param(&location, "state");
    let nonce = param(&location, "nonce");

    // The upstream issues an ID token bound to that nonce; the callback validates it.
    let token = id_token(
        &upstream.key,
        base_claims(&nonce, "upstream-sub-1"),
        serde_json::json!({ "amr": ["hwk", "mfa"], "acr": "aal2", "auth_time": 1_699_999_000 }),
    );
    *upstream.token_response.lock().unwrap() = token_response(&token);

    let response = drive_callback(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        &state,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "callback resumes the local authorize"
    );
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("/authorize?client_id={}", harness.client_id()),
    );

    // A local identity was provisioned from the VERIFIED upstream sub, keyed on the
    // issuer-namespaced external id (issue #75, HIGH-1), not the bare sub.
    assert!(
        user_provisioned(
            &harness,
            &federated_external_id(UPSTREAM_ISSUER, "upstream-sub-1")
        )
        .await,
        "the federated user is provisioned"
    );
    assert!(
        !user_provisioned(&harness, "upstream-sub-1").await,
        "the local identity is keyed on issuer+sub, never the bare sub"
    );

    // The established session carries the HONEST federated auth event: the federated method
    // (which mints the federated-context acr) plus the upstream amr passthrough (which mints
    // the local token's amr verbatim, per the tokens.rs mint test), never a fabricated local
    // factor.
    let session_id = session_id_from_cookies(&response, &harness.scope()).expect("session cookie");
    let record = harness
        .store()
        .scoped(harness.scope())
        .sessions()
        .get(&session_id, 1, i64::MAX / 2)
        .await
        .expect("session get")
        .expect("session exists");
    assert!(
        record.auth_methods.starts_with("federated"),
        "{}",
        record.auth_methods
    );
    assert_eq!(
        federated_amr_from_auth_methods(&record.auth_methods),
        vec!["hwk".to_owned(), "mfa".to_owned()],
        "the session carries the upstream amr passthrough for the minted token"
    );

    // Single-use CSRF: replaying the SAME state fails (the correlation row is consumed).
    let replay = drive_callback(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        &state,
    )
    .await;
    assert_ne!(
        replay.status(),
        StatusCode::SEE_OTHER,
        "a replayed state must not resume"
    );
    assert!(
        session_id_from_cookies(&replay, &harness.scope()).is_none(),
        "a replay sets no session"
    );
}

#[tokio::test]
async fn a_forged_or_absent_callback_state_fails_single_use_csrf() {
    let harness = Harness::start().await;
    seed_connector(&harness).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    // A forged state (never issued) matches no consumable correlation row.
    let response = drive_callback(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        "forged-state",
    )
    .await;
    assert_ne!(response.status(), StatusCode::SEE_OTHER);
    assert!(session_id_from_cookies(&response, &harness.scope()).is_none());
    assert!(
        !user_provisioned(&harness, "upstream-sub-1").await,
        "no user for a forged callback"
    );
}

#[tokio::test]
async fn a_private_range_upstream_is_blocked_and_provisions_no_user() {
    // The connector's issuer host resolves to the cloud-metadata address: the discovery fetch
    // is Blocked on the wire, so the login fails and no user is provisioned (the SSRF crux).
    let harness = Harness::start().await;
    seed_connector(&harness).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([169, 254, 169, 254])]);

    let scope = harness.scope();
    let return_to = format!("/authorize?client_id={}", harness.client_id());
    let uri = format!(
        "/t/{}/e/{}/federation/{CONNECTOR_SLUG}/authorize?return_to={}",
        scope.tenant(),
        scope.environment(),
        encode(&return_to),
    );
    let response = federation_router(&harness, runtime)
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
        .await
        .expect("authorize");
    // A blocked discovery fetch fails the login without redirecting to any upstream.
    assert_ne!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a private-range issuer is not redirected to"
    );
    assert!(
        !user_provisioned(&harness, "upstream-sub-1").await,
        "no user for a blocked upstream"
    );
}

/// Each malicious upstream ID token must be rejected with NO user provisioned.
#[tokio::test]
async fn malicious_upstream_id_tokens_are_rejected_and_provision_no_user() {
    let harness = Harness::start().await;
    seed_connector(&harness).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);
    let other_key =
        SigningKey::ed25519_from_seed(Some("up-kid".to_owned()), &[42_u8; 32]).expect("forger");

    // Each case gets a fresh authorize (fresh state/nonce), then a malicious token.
    for (label, sub) in [
        ("alg_none", "sub-none"),
        ("forged_iss", "sub-iss"),
        ("wrong_aud", "sub-aud"),
        ("expired", "sub-exp"),
        ("forged_sig", "sub-sig"),
        ("nonce_mismatch", "sub-nonce"),
    ] {
        let location =
            drive_authorize(&harness, federation_router(&harness, Arc::clone(&runtime))).await;
        let state = param(&location, "state");
        let nonce = param(&location, "nonce");
        let token = match label {
            "alg_none" => {
                // A hand-crafted unsecured token (alg:none, empty signature).
                use base64::Engine as _;
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
                let body =
                    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&base_claims(&nonce, sub)).unwrap());
                format!("{head}.{body}.")
            }
            "forged_iss" => id_token(
                &upstream.key,
                base_claims(&nonce, sub),
                serde_json::json!({ "iss": "http://evil.example" }),
            ),
            "wrong_aud" => id_token(
                &upstream.key,
                base_claims(&nonce, sub),
                serde_json::json!({ "aud": "some-other-client" }),
            ),
            "expired" => id_token(
                &upstream.key,
                base_claims(&nonce, sub),
                // The harness clock sits at the Unix epoch, so an expired token needs an exp
                // before it (past the skew window).
                serde_json::json!({ "exp": -1000_i64 }),
            ),
            "forged_sig" => {
                // Signed with a different key that reuses the trusted kid.
                id_token(&other_key, base_claims(&nonce, sub), serde_json::json!({}))
            }
            "nonce_mismatch" => id_token(
                &upstream.key,
                base_claims("attacker-nonce", sub),
                serde_json::json!({}),
            ),
            _ => unreachable!(),
        };
        *upstream.token_response.lock().unwrap() = token_response(&token);

        let response = drive_callback(
            &harness,
            federation_router(&harness, Arc::clone(&runtime)),
            &state,
        )
        .await;
        assert_ne!(
            response.status(),
            StatusCode::SEE_OTHER,
            "{label}: a malicious upstream token must not establish a session"
        );
        assert!(
            session_id_from_cookies(&response, &harness.scope()).is_none(),
            "{label}: no session cookie on a rejected token"
        );
        assert!(
            !user_provisioned(&harness, sub).await,
            "{label}: NO user is provisioned from an unverified upstream token"
        );
    }
}

// ---- Cross-connector external-id isolation (issue #75, HIGH-1) ----

const ISSUER_A: &str = "http://issuer-a.example";
const ISSUER_B: &str = "http://issuer-b.example";
const SLUG_A: &str = "conn-a";
const SLUG_B: &str = "conn-b";

/// A mock upstream that serves discovery keyed on the request `Host`, so several connectors
/// with DIFFERENT configured issuers drive their whole flow through the one injected dialer:
/// the served document's `issuer` is derived from the `Host`, so each connector's mix-up
/// check passes. One shared signing key; a settable token response (sequenced per login).
async fn start_host_routed_upstream() -> (SocketAddr, SigningKey, Arc<Mutex<String>>) {
    let key = SigningKey::ed25519_from_seed(Some("up-kid".to_owned()), &[7_u8; 32]).expect("key");
    let jwks = JwkSet::from_signing_keys([&key])
        .expect("jwk set")
        .to_json()
        .expect("jwks json");
    let token_response = Arc::new(Mutex::new(String::from("{}")));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let token_for_server = Arc::clone(&token_response);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let jwks = jwks.clone();
            let token = Arc::clone(&token_for_server);
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let first = request.lines().next().unwrap_or("").to_owned();
                // The Host header names the connector's issuer host (port stripped).
                let host = request
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("host:"))
                    .and_then(|line| line.split_once(':').map(|(_, value)| value.trim()))
                    .map(|value| value.split(':').next().unwrap_or(value).to_owned())
                    .unwrap_or_default();
                let body = if first.contains("openid-configuration") {
                    let issuer = format!("http://{host}");
                    format!(
                        r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"{issuer}/jwks","id_token_signing_alg_values_supported":["EdDSA"],"code_challenge_methods_supported":["S256"]}}"#
                    )
                } else if first.contains("/jwks") {
                    jwks
                } else if first.contains("/token") {
                    token.lock().expect("token lock").clone()
                } else {
                    String::from("{}")
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    (addr, key, token_response)
}

/// Seed an issuer-form connector with an explicit `slug`, `issuer`, and `client_id`, returning
/// its id. A DATA-ONLY definition, created on the control plane (which provisions the envelope
/// keys). `enabled` is set from the argument so the enabled-recheck test can seed a live one.
async fn seed_named_connector(
    harness: &Harness,
    slug: &str,
    issuer: &str,
    client_id: &str,
    enabled: bool,
) -> ConnectorId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = ConnectorId::generate(&env, &scope);
    let definition = format!(
        r#"{{"connector_id":"{slug}","display_name":"C","protocol":"oidc","endpoints":{{"issuer":"{issuer}"}},"scopes":["openid","email"],"client_id":"{client_id}"}}"#
    );
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
                definition_json: &definition,
                client_secret: b"upstream-client-secret",
                capabilities: ConnectorCapabilities {
                    refresh: false,
                    groups: false,
                    logout_propagation: false,
                    email_verified_trust: "untrusted",
                },
                enabled,
            },
            None,
        )
        .await
        .expect("seed connector");
    id
}

/// Drive the federated authorize leg for `slug` and return the response (whatever its status).
async fn authorize_for(harness: &Harness, router: Router, slug: &str) -> axum::response::Response {
    let scope = harness.scope();
    let return_to = format!("/authorize?client_id={}", harness.client_id());
    let uri = format!(
        "/t/{}/e/{}/federation/{slug}/authorize?return_to={}",
        scope.tenant(),
        scope.environment(),
        encode(&return_to),
    );
    router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("authorize")
}

/// Drive the callback for `slug` with a `state`, returning the response.
async fn callback_for(
    harness: &Harness,
    router: Router,
    slug: &str,
    state: &str,
) -> axum::response::Response {
    let scope = harness.scope();
    let uri = format!(
        "/t/{}/e/{}/federation/{slug}/callback?state={state}&code=upstream-code",
        scope.tenant(),
        scope.environment(),
    );
    router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("callback")
}

/// Mint a valid upstream `id_token` for `issuer` / `client_id` / `nonce` / `sub`.
fn mint(key: &SigningKey, issuer: &str, client_id: &str, nonce: &str, sub: &str) -> String {
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": sub,
        "aud": client_id,
        "exp": 4_102_444_800_i64,
        "iat": 0,
        "nonce": nonce,
    });
    let payload = serde_json::to_vec(&claims).expect("payload");
    sign_jws(key, &payload, &EmissionOptions::new().with_typ("JWT")).expect("sign")
}

/// The user id the session cookie of a successful callback resolves to.
async fn session_subject(harness: &Harness, response: &axum::response::Response) -> String {
    let session_id = session_id_from_cookies(response, &harness.scope()).expect("session cookie");
    harness
        .store()
        .scoped(harness.scope())
        .sessions()
        .get(&session_id, 1, i64::MAX / 2)
        .await
        .expect("session get")
        .expect("session exists")
        .subject
}

/// Run one full federated login for `slug` (its `issuer` and upstream `sub`, audienced to the
/// shared `UPSTREAM_CLIENT_ID`), returning the local user id the established session belongs
/// to. Sequences the shared token response.
async fn login_subject(
    harness: &Harness,
    runtime: &Arc<FederationRuntime>,
    token_slot: &Arc<Mutex<String>>,
    key: &SigningKey,
    slug: &str,
    issuer: &str,
    sub: &str,
) -> String {
    let response = authorize_for(
        harness,
        federation_router(harness, Arc::clone(runtime)),
        slug,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "authorize for {slug}"
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("location str")
        .to_owned();
    let state = param(&location, "state");
    let nonce = param(&location, "nonce");
    *token_slot.lock().unwrap() =
        token_response(&mint(key, issuer, UPSTREAM_CLIENT_ID, &nonce, sub));
    let response = callback_for(
        harness,
        federation_router(harness, Arc::clone(runtime)),
        slug,
        &state,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "callback for {slug}"
    );
    session_subject(harness, &response).await
}

#[tokio::test]
async fn two_connectors_with_distinct_issuers_and_the_same_sub_resolve_to_two_users() {
    // The account-takeover the namespacing fixes: two connectors pointing at DIFFERENT
    // upstream IdPs that both assert sub=1001 must map to TWO DISTINCT local users, so an
    // attacker who controls a second connector's IdP and picks a victim's sub does NOT bind
    // to the victim's account.
    let harness = Harness::start().await;
    seed_named_connector(&harness, SLUG_A, ISSUER_A, UPSTREAM_CLIENT_ID, true).await;
    seed_named_connector(&harness, SLUG_B, ISSUER_B, UPSTREAM_CLIENT_ID, true).await;
    let (addr, key, token_slot) = start_host_routed_upstream().await;
    let runtime = build_runtime(addr, vec![IpAddr::from([93, 184, 216, 34])]);

    let subject_a = login_subject(
        &harness,
        &runtime,
        &token_slot,
        &key,
        SLUG_A,
        ISSUER_A,
        "1001",
    )
    .await;
    let subject_b = login_subject(
        &harness,
        &runtime,
        &token_slot,
        &key,
        SLUG_B,
        ISSUER_B,
        "1001",
    )
    .await;

    assert_ne!(
        subject_a, subject_b,
        "the SAME sub from DIFFERENT issuers must not collide onto one local user (no takeover)"
    );
    // Both issuer-namespaced identities exist and are distinct.
    assert!(user_provisioned(&harness, &federated_external_id(ISSUER_A, "1001")).await);
    assert!(user_provisioned(&harness, &federated_external_id(ISSUER_B, "1001")).await);
    // The bare sub is NOT the key any longer (the old, vulnerable lookup finds nothing).
    assert!(
        !user_provisioned(&harness, "1001").await,
        "the local identity is keyed on issuer+sub, never the bare sub"
    );
}

#[tokio::test]
async fn two_connectors_to_the_same_issuer_with_the_same_sub_share_one_user() {
    // The identity-sharing half: two DIFFERENT connectors to the SAME issuer asserting the
    // same sub are the same upstream identity, so they resolve to ONE local user.
    let harness = Harness::start().await;
    seed_named_connector(&harness, SLUG_A, ISSUER_A, UPSTREAM_CLIENT_ID, true).await;
    seed_named_connector(&harness, SLUG_B, ISSUER_A, UPSTREAM_CLIENT_ID, true).await;
    let (addr, key, token_slot) = start_host_routed_upstream().await;
    let runtime = build_runtime(addr, vec![IpAddr::from([93, 184, 216, 34])]);

    let subject_a = login_subject(
        &harness,
        &runtime,
        &token_slot,
        &key,
        SLUG_A,
        ISSUER_A,
        "2002",
    )
    .await;
    let subject_b = login_subject(
        &harness,
        &runtime,
        &token_slot,
        &key,
        SLUG_B,
        ISSUER_A,
        "2002",
    )
    .await;

    assert_eq!(
        subject_a, subject_b,
        "the same issuer + same sub is one upstream identity, so it shares one local user"
    );
}

#[tokio::test]
async fn an_upstream_token_with_nbf_in_the_future_is_rejected() {
    // Defence in depth for the nbf enforcement the JOSE core owns: a not-yet-valid token
    // (nbf far in the future of the harness clock at the epoch) provisions no user.
    let harness = Harness::start().await;
    seed_connector(&harness).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    let location =
        drive_authorize(&harness, federation_router(&harness, Arc::clone(&runtime))).await;
    let state = param(&location, "state");
    let nonce = param(&location, "nonce");
    let token = id_token(
        &upstream.key,
        base_claims(&nonce, "sub-nbf"),
        serde_json::json!({ "nbf": 4_100_000_000_i64 }),
    );
    *upstream.token_response.lock().unwrap() = token_response(&token);

    let response = drive_callback(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        &state,
    )
    .await;
    assert_ne!(
        response.status(),
        StatusCode::SEE_OTHER,
        "an nbf-in-future token is rejected"
    );
    assert!(session_id_from_cookies(&response, &harness.scope()).is_none());
    assert!(
        !user_provisioned(&harness, &federated_external_id(UPSTREAM_ISSUER, "sub-nbf")).await,
        "no user from a not-yet-valid token"
    );
}

// ---- Issue #76: failure isolation, health, and parameter passthrough ----

const UNAVAILABLE_STATUS: StatusCode = StatusCode::SERVICE_UNAVAILABLE;

/// The `created_at`/`updated_at` micros every seeded connector is created with (the third
/// argument to `connectors().create`). It is the connector-definition FINGERPRINT the health
/// record and the health read key on (issue #76), so a health snapshot in these tests reads under
/// it.
const SEED_FINGERPRINT: i64 = 1_000_000;

/// Seed a connector from a full definition JSON string, returning its id.
async fn seed_definition(harness: &Harness, slug: &str, definition_json: &str) -> ConnectorId {
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
                client_secret: b"upstream-client-secret",
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
        .expect("seed connector");
    id
}

/// Drive the federated authorize leg for `slug` with an explicit `return_to`, returning
/// the response (whatever its status).
async fn authorize_with_return_to(
    harness: &Harness,
    router: Router,
    slug: &str,
    return_to: &str,
) -> axum::response::Response {
    let scope = harness.scope();
    let uri = format!(
        "/t/{}/e/{}/federation/{slug}/authorize?return_to={}",
        scope.tenant(),
        scope.environment(),
        encode(return_to),
    );
    router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("authorize")
}

/// The upstream redirect Location of a successful authorize leg.
fn location_of(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("location str")
        .to_owned()
}

#[tokio::test]
async fn a_broken_connector_is_typed_unavailable_and_never_affects_a_healthy_sibling() {
    // The failure-isolation crux (issue #76): with one connector whose upstream is broken and
    // one healthy connector, the healthy connector keeps serving logins and the broken one
    // returns a TYPED connector-unavailable error -- one dead upstream never takes down a sibling.
    let harness = Harness::start().await;
    // GOOD points at the real mock issuer; BROKEN points at a DIFFERENT issuer, so the mock's
    // discovery document (issuer = UPSTREAM_ISSUER) fails BROKEN's mix-up check (an upstream
    // protocol fault) while GOOD resolves cleanly. Both share the one runtime and dialer.
    seed_named_connector(&harness, "good", UPSTREAM_ISSUER, UPSTREAM_CLIENT_ID, true).await;
    let broken_id =
        seed_named_connector(&harness, "broken", "http://broken.example", "cid", true).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    // The healthy sibling serves a login (302 to the upstream).
    let good = authorize_for(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        "good",
    )
    .await;
    assert_eq!(
        good.status(),
        StatusCode::SEE_OTHER,
        "the healthy connector serves logins"
    );

    // The broken connector returns a TYPED connector-unavailable error, not a 302 and not a crash.
    let broken = authorize_for(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        "broken",
    )
    .await;
    assert_eq!(
        broken.status(),
        UNAVAILABLE_STATUS,
        "the broken connector returns a typed connector-unavailable error"
    );

    // The healthy sibling STILL serves after the broken connector failed (no process impact).
    let good_again = authorize_for(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        "good",
    )
    .await;
    assert_eq!(
        good_again.status(),
        StatusCode::SEE_OTHER,
        "the sibling is unaffected"
    );

    // Per-connector health flipped for exactly the broken connector; the sibling is healthy.
    let now = harness.env().clock().now_utc();
    let broken_health = runtime
        .health()
        .snapshot(now, &broken_id.to_string(), SEED_FINGERPRINT)
        .expect("broken health recorded");
    assert_eq!(broken_health.last_error_kind, Some("upstream_protocol"));
    assert!(broken_health.error_total >= 1);
}

#[tokio::test]
async fn a_dead_upstream_is_typed_unavailable_and_backoff_prevents_rehammering() {
    // A connector pointed at a DEAD upstream (its issuer resolves to a blocked private address)
    // returns a typed connector-unavailable error and flips to the unavailable state with a
    // backoff. A SECOND immediate authorize is denied by the backoff WITHOUT re-attempting the
    // upstream (do not hammer a dead upstream), so no second failure is recorded.
    let harness = Harness::start().await;
    let id = seed_named_connector(
        &harness,
        CONNECTOR_SLUG,
        UPSTREAM_ISSUER,
        UPSTREAM_CLIENT_ID,
        true,
    )
    .await;
    let upstream = start_upstream().await;
    // The metadata address is blocked on the wire, so discovery fails as UpstreamUnavailable.
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([169, 254, 169, 254])]);

    let first = drive_authorize_expect_unavailable(&harness, Arc::clone(&runtime)).await;
    assert_eq!(
        first.status(),
        UNAVAILABLE_STATUS,
        "a dead upstream is typed unavailable"
    );
    let now = harness.env().clock().now_utc();
    let health = runtime
        .health()
        .snapshot(now, &id.to_string(), SEED_FINGERPRINT)
        .expect("health recorded");
    assert_eq!(health.state.as_str(), "unavailable");
    assert_eq!(health.error_total, 1);
    assert!(
        health.next_retry_at.is_some(),
        "a backoff retry instant is armed"
    );

    // A second authorize at the same clock instant is denied by the backoff: the upstream is
    // NOT re-attempted, so the failure count does not grow.
    let second = drive_authorize_expect_unavailable(&harness, Arc::clone(&runtime)).await;
    assert_eq!(second.status(), UNAVAILABLE_STATUS);
    let health = runtime
        .health()
        .snapshot(now, &id.to_string(), SEED_FINGERPRINT)
        .expect("health present");
    assert_eq!(
        health.error_total, 1,
        "the backoff prevented a second upstream attempt (no re-hammering)"
    );
}

/// Drive the standard authorize leg and return the response (used where a non-302 is expected).
async fn drive_authorize_expect_unavailable(
    harness: &Harness,
    runtime: Arc<FederationRuntime>,
) -> axum::response::Response {
    let scope = harness.scope();
    let return_to = format!("/authorize?client_id={}", harness.client_id());
    let uri = format!(
        "/t/{}/e/{}/federation/{CONNECTOR_SLUG}/authorize?return_to={}",
        scope.tenant(),
        scope.environment(),
        encode(&return_to),
    );
    federation_router(harness, runtime)
        .oneshot(
            Request::builder()
                .uri(&uri)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("authorize")
}

#[tokio::test]
async fn a_per_request_upstream_4xx_does_not_trip_the_connector_into_backoff() {
    // HIGH-1 (issue #76): a token endpoint 400 (RFC 6749 5.2 invalid_grant for a bad, expired, or
    // replayed authorization code) is a PER-REQUEST condition, not a connector outage. Both
    // /federation routes are PUBLIC, so mapping it to the connector backoff would be an
    // unauthenticated connector-wide DoS: one garbage /callback would 503 the NEXT /authorize for
    // every user. The 4xx-vs-5xx class split maps it to UpstreamProtocol, which feeds the error
    // rate WITHOUT changing admission, so one bad code can never blacklist the connector.
    let harness = Harness::start().await;
    let id = seed_named_connector(
        &harness,
        CONNECTOR_SLUG,
        UPSTREAM_ISSUER,
        UPSTREAM_CLIENT_ID,
        true,
    )
    .await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    // Begin a login (discovery resolves and caches), then submit a GARBAGE code at the callback:
    // the upstream token endpoint answers 400 invalid_grant (the attacker / back-button / expired
    // code path).
    let location =
        drive_authorize(&harness, federation_router(&harness, Arc::clone(&runtime))).await;
    let state = param(&location, "state");
    *upstream.token_status.lock().unwrap() = 400;
    *upstream.token_response.lock().unwrap() = r#"{"error":"invalid_grant"}"#.to_owned();
    let response = drive_callback(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        &state,
    )
    .await;
    // The login FAILS (no session, no user), but not by tripping the connector down.
    assert_ne!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a bad code fails the login"
    );
    assert!(session_id_from_cookies(&response, &harness.scope()).is_none());
    assert!(
        !user_provisioned(&harness, &federated_external_id(UPSTREAM_ISSUER, "any")).await,
        "no user is provisioned from a rejected code"
    );

    // The health record shows a PER-REQUEST protocol fault: NO backoff armed, admission unchanged,
    // but the error-rate counter still increments (health visibility).
    let now = harness.env().clock().now_utc();
    let health = runtime
        .health()
        .snapshot(now, &id.to_string(), SEED_FINGERPRINT)
        .expect("health recorded");
    assert_ne!(
        health.state.as_str(),
        "unavailable",
        "a per-request 4xx must not flip the connector unavailable"
    );
    assert!(
        health.next_retry_at.is_none(),
        "a per-request 4xx must not arm the connector backoff"
    );
    assert_eq!(health.last_error_kind, Some("upstream_protocol"));
    assert!(
        health.error_total >= 1,
        "the error-rate counter still increments without flipping admission"
    );

    // The attack's payoff would be denying the NEXT authorize. It is still Allowed (302): a single
    // bad token never blacklists the connector.
    let again = authorize_for(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        CONNECTOR_SLUG,
    )
    .await;
    assert_eq!(
        again.status(),
        StatusCode::SEE_OTHER,
        "a subsequent authorize for another user still Allows (no connector-wide DoS)"
    );
}

#[tokio::test]
async fn a_real_upstream_5xx_outage_arms_the_connector_backoff() {
    // The other half of the HIGH-1 class split (issue #76): a token endpoint 5xx is a REAL outage,
    // so it MUST map to UpstreamUnavailable and arm the backoff -- the exact opposite of the 4xx
    // case -- so a subsequent authorize is DENIED within the window (do not hammer a dead upstream).
    let harness = Harness::start().await;
    let id = seed_named_connector(
        &harness,
        CONNECTOR_SLUG,
        UPSTREAM_ISSUER,
        UPSTREAM_CLIENT_ID,
        true,
    )
    .await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    let location =
        drive_authorize(&harness, federation_router(&harness, Arc::clone(&runtime))).await;
    let state = param(&location, "state");
    // The token endpoint is genuinely down (503), a real outage.
    *upstream.token_status.lock().unwrap() = 503;
    let response = drive_callback(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        &state,
    )
    .await;
    assert_ne!(response.status(), StatusCode::SEE_OTHER, "the login fails");

    let now = harness.env().clock().now_utc();
    let health = runtime
        .health()
        .snapshot(now, &id.to_string(), SEED_FINGERPRINT)
        .expect("health recorded");
    assert_eq!(
        health.state.as_str(),
        "unavailable",
        "a 5xx is a real outage that flips the connector unavailable"
    );
    assert_eq!(health.last_error_kind, Some("upstream_unavailable"));
    assert!(
        health.next_retry_at.is_some(),
        "a real outage arms the connector backoff"
    );

    // A subsequent authorize is DENIED inside the backoff window (the correct outage behaviour).
    let again = authorize_for(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        CONNECTOR_SLUG,
    )
    .await;
    assert_eq!(
        again.status(),
        UNAVAILABLE_STATUS,
        "a real outage backs the connector off (a subsequent authorize is denied)"
    );
}

#[tokio::test]
async fn a_cached_discovery_with_a_dead_token_endpoint_stays_unavailable_and_grows_backoff() {
    // MEDIUM (issue #76): when discovery is CACHED but the token endpoint / JWKS / validation is
    // down, the authorize leg only resolves cached discovery -- which is NOT a login success. It
    // must therefore NOT record_success, or it would flap the health gauge to healthy between a
    // failed callback and the next authorize AND pin the backoff at its base window (never growing).
    // With the fix the connector STAYS unavailable across repeated logins and the backoff GROWS.
    let harness = Harness::start().await;
    let id = seed_named_connector(
        &harness,
        CONNECTOR_SLUG,
        UPSTREAM_ISSUER,
        UPSTREAM_CLIENT_ID,
        true,
    )
    .await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);
    // The token endpoint is dead for the whole test; discovery and JWKS stay reachable, so
    // discovery caches on the first authorize and every later authorize is a pure cache hit.
    *upstream.token_status.lock().unwrap() = 503;

    // Cycle 1: authorize (fetches + caches discovery) then a failing callback (token 503).
    let location =
        drive_authorize(&harness, federation_router(&harness, Arc::clone(&runtime))).await;
    let state = param(&location, "state");
    drive_callback(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        &state,
    )
    .await;
    let now = harness.env().clock().now_utc();
    let after_one = runtime
        .health()
        .snapshot(now, &id.to_string(), SEED_FINGERPRINT)
        .expect("health recorded");
    assert_eq!(after_one.state.as_str(), "unavailable");
    assert_eq!(after_one.consecutive_failures, 1);

    // Advance past the base backoff window (30s) so the next authorize is admitted as a probe.
    harness.clock().advance(Duration::from_secs(31));

    // Cycle 2: the authorize leg resolves discovery from the CACHE. The health must STILL read
    // unavailable right after it (the bug would have flapped it to healthy here).
    let location =
        drive_authorize(&harness, federation_router(&harness, Arc::clone(&runtime))).await;
    let state = param(&location, "state");
    let after_authorize = runtime
        .health()
        .snapshot(
            harness.env().clock().now_utc(),
            &id.to_string(),
            SEED_FINGERPRINT,
        )
        .expect("health present");
    assert_eq!(
        after_authorize.state.as_str(),
        "unavailable",
        "the authorize leg must not flap a cached-discovery connector to healthy"
    );
    assert_eq!(
        after_authorize.consecutive_failures, 1,
        "the authorize leg must not clear the consecutive-failure count"
    );
    drive_callback(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        &state,
    )
    .await;
    let after_two = runtime
        .health()
        .snapshot(
            harness.env().clock().now_utc(),
            &id.to_string(),
            SEED_FINGERPRINT,
        )
        .expect("health present");
    assert_eq!(after_two.state.as_str(), "unavailable");
    assert_eq!(
        after_two.consecutive_failures, 2,
        "the backoff GROWS: a second failed login escalates the consecutive-failure count"
    );

    // Advance past the now-doubled window (60s) and run a third cycle: the count keeps growing,
    // proving the backoff is not pinned at the base window.
    harness.clock().advance(Duration::from_secs(61));
    let location =
        drive_authorize(&harness, federation_router(&harness, Arc::clone(&runtime))).await;
    let state = param(&location, "state");
    drive_callback(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        &state,
    )
    .await;
    let after_three = runtime
        .health()
        .snapshot(
            harness.env().clock().now_utc(),
            &id.to_string(),
            SEED_FINGERPRINT,
        )
        .expect("health present");
    assert_eq!(
        after_three.consecutive_failures, 3,
        "consecutive failures keep escalating (the backoff window keeps growing, never pinned)"
    );
}

#[tokio::test]
async fn passthrough_forwards_the_three_allowlisted_params_verbatim_and_never_others() {
    // The passthrough contract (issue #76): prompt, login_hint, ui_locales supplied downstream
    // are observed VERBATIM (bounded + encoded) in the upstream authorize request; a param
    // OUTSIDE the allowlist (redirect_uri, foo) is NEVER forwarded (the negative test).
    let harness = Harness::start().await;
    seed_named_connector(
        &harness,
        CONNECTOR_SLUG,
        UPSTREAM_ISSUER,
        UPSTREAM_CLIENT_ID,
        true,
    )
    .await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    // The downstream authorization request carries the three allowlisted params (percent-encoded
    // in the return_to, printable-ASCII per the resume validator) plus non-allowlisted params.
    let return_to = format!(
        "/authorize?client_id={}&prompt=login%20consent&login_hint=ada%40example.test&\
         ui_locales=fr-CA%20en&redirect_uri=https%3A%2F%2Fattacker.example&foo=bar",
        harness.client_id()
    );
    let response = authorize_with_return_to(
        &harness,
        federation_router(&harness, runtime),
        CONNECTOR_SLUG,
        &return_to,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = location_of(&response);

    // The three allowlisted params ride the UPSTREAM query, re-encoded verbatim.
    assert_eq!(param(&location, "prompt"), "login%20consent");
    assert_eq!(param(&location, "login_hint"), "ada%40example.test");
    assert_eq!(param(&location, "ui_locales"), "fr-CA%20en");
    // Nothing outside the allowlist is forwarded, even a sensitive downstream redirect_uri.
    assert!(!location.contains("foo="), "{location}");
    assert!(
        !location.contains("attacker.example"),
        "a non-allowlisted downstream param must never reach the upstream: {location}"
    );
}

#[tokio::test]
async fn per_connector_passthrough_disable_flags_are_honored() {
    // A connector can disable any of the three; a disabled param is not forwarded even when the
    // downstream request supplies it. Here login_hint (the privacy-sensitive one) is disabled.
    let harness = Harness::start().await;
    let definition = format!(
        r#"{{"connector_id":"{CONNECTOR_SLUG}","display_name":"Acme","protocol":"oidc","endpoints":{{"issuer":"{UPSTREAM_ISSUER}"}},"scopes":["openid","email"],"client_id":"{UPSTREAM_CLIENT_ID}","passthrough":{{"login_hint":false,"prompt":true,"ui_locales":true}}}}"#
    );
    seed_definition(&harness, CONNECTOR_SLUG, &definition).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    let return_to = format!(
        "/authorize?client_id={}&prompt=login&login_hint=ada%40example.test&ui_locales=fr",
        harness.client_id()
    );
    let response = authorize_with_return_to(
        &harness,
        federation_router(&harness, runtime),
        CONNECTOR_SLUG,
        &return_to,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = location_of(&response);
    assert_eq!(param(&location, "prompt"), "login");
    assert_eq!(param(&location, "ui_locales"), "fr");
    assert!(
        !location.contains("login_hint="),
        "a per-connector-disabled login_hint is not forwarded: {location}"
    );
}

#[tokio::test]
async fn per_connector_health_metrics_are_exported_with_the_connector_label() {
    // The connector-labeled health metrics reflect an induced upstream outage (issue #76): the
    // error series is present with the connector label and the error kind.
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("no recorder installed yet in this test binary");
    ironauth_oidc::describe_connector_health_metrics();

    let harness = Harness::start().await;
    let id = seed_named_connector(
        &harness,
        CONNECTOR_SLUG,
        UPSTREAM_ISSUER,
        UPSTREAM_CLIENT_ID,
        true,
    )
    .await;
    let upstream = start_upstream().await;
    // A blocked upstream induces an UpstreamUnavailable failure that records the metric.
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([169, 254, 169, 254])]);
    let response = drive_authorize_expect_unavailable(&harness, runtime).await;
    assert_eq!(response.status(), UNAVAILABLE_STATUS);

    let rendered = handle.render();
    assert!(
        rendered.contains("ironauth_connector_upstream_error_total"),
        "the connector error series is exported: {rendered}"
    );
    assert!(
        rendered.contains(&format!("connector=\"{id}\"")),
        "the series carries the connector label: {rendered}"
    );
    assert!(
        rendered.contains("kind=\"upstream_unavailable\""),
        "the series carries the error kind label: {rendered}"
    );
}

#[tokio::test]
async fn an_explicit_endpoint_connector_is_rejected_cleanly_at_the_authorize_leg() {
    // An explicit-endpoint connector cannot bind an iss yet (PR B), so it must fail CLEANLY
    // and EARLY at the authorize leg (a 400), not 302 to the upstream and then 500 the
    // callback after the user has authenticated.
    let harness = Harness::start().await;
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = ConnectorId::generate(&env, &scope);
    let definition = r#"{"connector_id":"expl","display_name":"E","protocol":"oidc","endpoints":{"authorization_endpoint":"https://x.example/a","token_endpoint":"https://x.example/t","jwks_uri":"https://x.example/j"},"scopes":["openid"],"client_id":"cid"}"#;
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
                slug: "expl",
                definition_json: definition,
                client_secret: b"secret",
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
        .expect("seed explicit connector");
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    let response = authorize_for(&harness, federation_router(&harness, runtime), "expl").await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "explicit-endpoint federation fails cleanly at authorize, before any redirect or state"
    );
}

#[tokio::test]
async fn a_connector_disabled_between_authorize_and_callback_fails_closed_at_the_callback() {
    // INFO-2: the callback re-checks `enabled`, so a connector disabled mid-flow completes
    // no login even with an otherwise-valid upstream token.
    let harness = Harness::start().await;
    let id = seed_named_connector(
        &harness,
        CONNECTOR_SLUG,
        UPSTREAM_ISSUER,
        UPSTREAM_CLIENT_ID,
        true,
    )
    .await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr, vec![IpAddr::from([93, 184, 216, 34])]);

    let location =
        drive_authorize(&harness, federation_router(&harness, Arc::clone(&runtime))).await;
    let state = param(&location, "state");
    let nonce = param(&location, "nonce");
    let token = id_token(
        &upstream.key,
        base_claims(&nonce, "sub-disabled"),
        serde_json::json!({}),
    );
    *upstream.token_response.lock().unwrap() = token_response(&token);

    // Disable the connector AFTER the authorize leg, BEFORE the callback.
    let env = harness.env().clone();
    let scope = harness.scope();
    let record = harness
        .db()
        .control_store()
        .scoped(scope)
        .connectors()
        .get(&id)
        .await
        .expect("get connector");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .connectors()
        .update(
            &env,
            &id,
            NewConnector {
                slug: &record.slug,
                definition_json: &record.definition_json,
                client_secret: b"upstream-client-secret",
                capabilities: ConnectorCapabilities {
                    refresh: record.capabilities.refresh,
                    groups: record.capabilities.groups,
                    logout_propagation: record.capabilities.logout_propagation,
                    email_verified_trust: &record.capabilities.email_verified_trust,
                },
                enabled: false,
            },
        )
        .await
        .expect("disable connector");

    let response = drive_callback(
        &harness,
        federation_router(&harness, Arc::clone(&runtime)),
        &state,
    )
    .await;
    assert_ne!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a connector disabled mid-flow must not complete the login"
    );
    assert!(session_id_from_cookies(&response, &harness.scope()).is_none());
    assert!(
        !user_provisioned(
            &harness,
            &federated_external_id(UPSTREAM_ISSUER, "sub-disabled")
        )
        .await,
        "no user is provisioned once the connector is disabled"
    );
}
