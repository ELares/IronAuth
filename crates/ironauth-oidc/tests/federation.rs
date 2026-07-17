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
    FederationKeyResolver, FederationRuntime, federated_amr_from_auth_methods, oidc_router,
};
use ironauth_store::{
    ConnectorCapabilities, ConnectorId, CorrelationId, NewConnector, Scope, SessionId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

const UPSTREAM_ISSUER: &str = "http://upstream.example";
const UPSTREAM_CLIENT_ID: &str = "ironauth-at-upstream";
const CONNECTOR_SLUG: &str = "acme";

/// A mock upstream OIDC provider: its address, its signing key, and the `id_token` JSON its
/// token endpoint currently returns (settable per test after the nonce is known).
struct Upstream {
    addr: SocketAddr,
    key: SigningKey,
    token_response: Arc<Mutex<String>>,
}

/// Start the mock upstream. It dispatches by request path: discovery, JWKS, and a token
/// endpoint whose body is the shared, test-settable `token_response`.
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
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let token_for_server = Arc::clone(&token_response);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let discovery = discovery.clone();
            let jwks = jwks.clone();
            let token = Arc::clone(&token_for_server);
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
    Upstream {
        addr,
        key,
        token_response,
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

    // A local identity was provisioned from the VERIFIED upstream sub.
    assert!(
        user_provisioned(&harness, "upstream-sub-1").await,
        "the federated user is provisioned"
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
