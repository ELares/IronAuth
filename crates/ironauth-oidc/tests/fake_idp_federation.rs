// SPDX-License-Identifier: MIT OR Apache-2.0

//! The emulator's fake upstream IdP completes a real OIDC federation login, offline
//! (issue #121, criterion 4).
//!
//! # Why this is not a duplicate of the federation suite
//!
//! `tests/federation.rs` already drives a full federated login, but against an upstream
//! hand-rolled inside that file: a server that returns whatever the test set on it. It proves
//! IronAuth's side of the protocol. It says nothing about the provider `ironauth dev` actually
//! ships, which is what criterion 4 is about, and the two had in fact diverged: the shipped
//! provider echoed no `nonce` and stamped every token with `iat = 0`, so a login through it
//! could not have succeeded. A double asserted against a second double is a test of the second
//! double.
//!
//! # The test is the browser as well as the server
//!
//! A federation login has three participants and the test plays two of them. IronAuth's
//! outbound legs (discovery, JWKS, the token exchange) reach the provider through the
//! `ironauth-fetch` injected dialer, as everywhere else in this suite. The `/authorize` leg is
//! not an outbound fetch at all: it is a redirect the USER AGENT follows. So the test connects
//! to the provider directly for that hop, exactly as a browser would, and carries the code it
//! is handed back to IronAuth's callback. Skipping that hop by calling `authorize_redirect` in
//! process would have left the one leg the relying party never makes untested.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_jose::SigningKey;
use ironauth_oidc::{
    FederationKeyResolver, FederationRuntime, fake_idp, federated_external_id, oidc_router,
};
use ironauth_store::{
    ConnectorCapabilities, ConnectorId, CorrelationId, NewConnector, Scope, SessionId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

/// The issuer the provider serves under. It never resolves: the dialer sends every connection
/// to the in-process listener, and the resolver answers with a public address so the SSRF
/// policy admits it (a loopback answer is denied, which is the policy working).
const UPSTREAM_ISSUER: &str = "http://fake-upstream.example";
const CONNECTOR_SLUG: &str = "dev-upstream";

/// The instant the whole test runs at. The harness clock sits at the epoch, so the provider is
/// stamped with the same value; a provider reading the real wall clock would issue tokens whose
/// `iat` is 56 years ahead of the relying party validating them.
const NOW_SECS: i64 = 0;

/// Serve `fake_idp` on a loopback listener. Every request is answered by `fake_idp::respond`,
/// so this harness contributes no protocol behaviour of its own: it is a socket and a clock.
async fn start_fake_idp() -> SocketAddr {
    let key = Arc::new(
        SigningKey::ed25519_from_seed(Some("dev-upstream".to_owned()), &[9_u8; 32])
            .expect("upstream signing key"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let key = Arc::clone(&key);
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                let target = request
                    .lines()
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_owned();
                let body = request.split_once("\r\n\r\n").map_or("", |(_, body)| body);
                let response =
                    fake_idp::respond(&target, body, &key, UPSTREAM_ISSUER, NOW_SECS);
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    addr
}

/// A federation runtime whose every outbound fetch lands on `addr`, with hostnames resolving
/// to a public address so the SSRF policy admits them.
fn build_runtime(addr: SocketAddr) -> Arc<FederationRuntime> {
    let resolver = Arc::new(StaticResolver::new(vec![IpAddr::from([93, 184, 216, 34])]));
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

/// Store the connector the emulator seeds: issuer-form, pointed at the fake provider, with the
/// `client_id` the provider issues its tokens' audience for.
async fn seed_connector(harness: &Harness) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let id = ConnectorId::generate(&env, &scope);
    let client_id = fake_idp::FAKE_CLIENT_ID;
    let definition = format!(
        r#"{{"connector_id":"{CONNECTOR_SLUG}","display_name":"Dev upstream","protocol":"oidc","endpoints":{{"issuer":"{UPSTREAM_ISSUER}"}},"scopes":["openid","email"],"client_id":"{client_id}"}}"#
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
                client_secret: b"dev-upstream-secret",
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

fn federation_router(harness: &Harness, runtime: Arc<FederationRuntime>) -> Router {
    oidc_router(harness.state().clone().with_federation(runtime))
}

/// Percent-encode a `return_to` so its own separators do not break the outer query.
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

fn param(location: &str, name: &str) -> String {
    let query = location.split_once('?').expect("a query").1;
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == name {
                return value.to_owned();
            }
        }
    }
    panic!("missing {name} in {location}");
}

/// The user agent's hop: GET the provider's authorize endpoint over a real socket and return
/// the `Location` it redirects the browser back to.
async fn follow_to_the_provider(addr: SocketAddr, location: &str) -> String {
    let target = location
        .strip_prefix(UPSTREAM_ISSUER)
        .expect("the redirect points at the provider");
    let mut socket = tokio::net::TcpStream::connect(addr).await.expect("connect");
    socket
        .write_all(
            format!("GET {target} HTTP/1.1\r\nHost: fake-upstream.example\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("write");
    let mut response = String::new();
    socket
        .read_to_string(&mut response)
        .await
        .expect("read the provider response");
    assert!(
        response.starts_with("HTTP/1.1 302"),
        "the provider redirects the browser back: {response}"
    );
    response
        .lines()
        .find_map(|line| {
            line.strip_prefix("Location: ")
                .or_else(|| line.strip_prefix("location: "))
        })
        .expect("a Location header")
        .trim()
        .to_owned()
}

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

#[tokio::test]
async fn the_emulators_fake_upstream_completes_a_federation_login_offline() {
    let harness = Harness::start().await;
    seed_connector(&harness).await;
    let addr = start_fake_idp().await;
    let runtime = build_runtime(addr);

    // Nobody is federated yet. Without this the two assertions at the end could both hold in a
    // database that was already carrying the user, and the login would prove nothing.
    let external_id = federated_external_id(UPSTREAM_ISSUER, fake_idp::FAKE_SUBJECT);
    assert!(
        !user_provisioned(&harness, &external_id).await,
        "the federated user must not exist before the login"
    );

    // Leg 1: IronAuth resolves the provider's discovery document and redirects the browser.
    let return_to = format!("/authorize?client_id={}", harness.client_id());
    let uri = format!(
        "/t/{}/e/{}/federation/{CONNECTOR_SLUG}/authorize?return_to={}",
        harness.scope().tenant(),
        harness.scope().environment(),
        encode(&return_to),
    );
    let response = federation_router(&harness, Arc::clone(&runtime))
        .oneshot(Request::builder().uri(&uri).body(Body::empty()).expect("req"))
        .await
        .expect("authorize");
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the authorize leg redirects to the provider, which means its discovery document \
         parsed and its endpoints resolved"
    );
    let to_provider = response
        .headers()
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("location str")
        .to_owned();
    assert!(
        to_provider.starts_with(&format!("{UPSTREAM_ISSUER}/authorize?")),
        "{to_provider}"
    );
    let bound_nonce = param(&to_provider, "nonce");

    // Leg 2: the browser hop. The provider authenticates its fixed identity and hands back a
    // code carrying the nonce it was asked to bind.
    let back_to_ironauth = follow_to_the_provider(addr, &to_provider).await;
    let code = param(&back_to_ironauth, "code");
    let state = param(&back_to_ironauth, "state");
    assert_eq!(
        fake_idp::nonce_from_code(&code).as_deref(),
        Some(bound_nonce.as_str()),
        "the code must carry the nonce IronAuth bound, or the ID token cannot echo it"
    );

    // Leg 3: the callback redeems the code with the provider and completes the login.
    let callback = format!(
        "/t/{}/e/{}/federation/{CONNECTOR_SLUG}/callback?state={state}&code={code}",
        harness.scope().tenant(),
        harness.scope().environment(),
    );
    let response = federation_router(&harness, Arc::clone(&runtime))
        .oneshot(
            Request::builder()
                .uri(&callback)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("callback");
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the callback resumes the local authorize, which it only reaches by accepting the \
         provider's ID token: signature, issuer, audience, expiry and the bound nonce"
    );
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .expect("location")
            .to_str()
            .expect("str"),
        return_to,
        "the login resumes the pending local authorization request"
    );

    // The login is complete in the two senses that matter: an identity exists, and a session
    // was established for it. A redirect alone would be satisfied by a callback that resumed
    // without authenticating anyone.
    assert!(
        user_provisioned(&harness, &external_id).await,
        "the login provisions a local identity from the provider's verified subject"
    );
    let session_id = session_id_from_cookies(&response, &harness.scope())
        .expect("the completed login sets a session cookie");
    let record = harness
        .store()
        .scoped(harness.scope())
        .sessions()
        .get(&session_id, 1, i64::MAX / 2)
        .await
        .expect("session get")
        .expect("the session exists");
    assert!(
        record.auth_methods.starts_with("federated"),
        "the session records the honest federated method, not a fabricated local factor: {}",
        record.auth_methods
    );
}
