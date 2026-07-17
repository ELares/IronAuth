// SPDX-License-Identifier: MIT OR Apache-2.0

//! Enterprise inbound routing and JIT provisioning, end to end (issue #77, PR 1), on a
//! REAL database against a MOCK upstream OIDC provider driven through the ironauth-fetch
//! injected dialer (like the federation suite).
//!
//! Proves the wired acceptance flow:
//!
//! - a login whose email DOMAIN maps to an org connection is routed to that org's
//!   connector and JIT-provisioned on first login, stamped with the org;
//! - a subsequent login updates the identity in place with NO duplicate user (the same
//!   verified `(issuer, sub)` key);
//! - per-app and per-user rules OVERRIDE a domain rule per the documented precedence;
//! - a no-match identifier falls through to the ordinary LOCAL login (fail-safe to
//!   local);
//! - the CALLBACK re-derives the organization from the CONSUMED correlation row, never
//!   from anything the browser sent.

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
use ironauth_oidc::{FederationKeyResolver, FederationRuntime, federated_external_id, oidc_router};
use ironauth_store::{
    ConnectorCapabilities, ConnectorId, CorrelationId, NewConnector, NewOrgConnection,
    NewRoutingRule, OrgConnectionId, OrganizationId, RoutingRuleId, RoutingSelector, Scope,
    SessionId,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

const UPSTREAM_ISSUER: &str = "http://upstream.example";
const UPSTREAM_CLIENT_ID: &str = "ironauth-at-upstream";
const ROUTED_DOMAIN: &str = "acme.example";

/// A mock upstream OIDC provider whose token endpoint returns a test-settable `id_token`.
struct Upstream {
    addr: SocketAddr,
    key: SigningKey,
    token_response: Arc<Mutex<String>>,
}

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

/// The federation-enabled router over the harness state with `runtime` installed.
fn router(harness: &Harness, runtime: &Arc<FederationRuntime>) -> Router {
    oidc_router(harness.state().clone().with_federation(Arc::clone(runtime)))
}

/// Seed a connector at `slug` pointing at the mock upstream, an organization, and a
/// binding between them; return the binding id.
async fn seed_binding(harness: &Harness, slug: &str) -> OrgConnectionId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let control = harness.db().control_store();

    let org_id = OrganizationId::generate(&env, &scope);
    control
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org_id, 1_000_000, "Acme Corp", None)
        .await
        .expect("create organization");

    let connector_id = ConnectorId::generate(&env, &scope);
    let definition = format!(
        r#"{{"connector_id":"{slug}","display_name":"Acme","protocol":"oidc","endpoints":{{"issuer":"{UPSTREAM_ISSUER}"}},"scopes":["openid","email"],"client_id":"{UPSTREAM_CLIENT_ID}"}}"#
    );
    control
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .connectors()
        .create(
            &env,
            &connector_id,
            1_000_000,
            NewConnector {
                slug,
                definition_json: &definition,
                client_secret: b"upstream-secret",
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
        .expect("create connector");

    let ocn_id = OrgConnectionId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .org_connections()
        .create(
            &env,
            &ocn_id,
            1_000_000,
            NewOrgConnection {
                organization_id: &org_id,
                connector_id: &connector_id,
                capture_upstream_tokens: false,
                enabled: true,
            },
        )
        .await
        .expect("create org connection");
    ocn_id
}

/// Seed a routing rule mapping `selector` to `ocn_id`.
async fn seed_rule(harness: &Harness, selector: RoutingSelector<'_>, ocn_id: &OrgConnectionId) {
    let env = harness.env().clone();
    let scope = harness.scope();
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .routing_rules()
        .create(
            &env,
            &RoutingRuleId::generate(&env, &scope),
            1_000_000,
            NewRoutingRule {
                selector,
                org_connection_id: ocn_id,
                priority: 0,
                enabled: true,
            },
        )
        .await
        .expect("create routing rule");
}

/// A URL-encoded `POST /login` form body for `identifier` returning to a local authorize.
fn login_form(harness: &Harness, identifier: &str) -> String {
    let return_to = format!("/authorize?client_id={}", harness.client_id());
    format!(
        "identifier={}&password=irrelevant&return_to={}",
        encode(identifier),
        encode(&return_to)
    )
}

/// Minimal percent-encoding matching the server decoder.
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

/// Drive `POST /login` with `identifier` and return the response.
async fn post_login(
    router: Router,
    harness: &Harness,
    identifier: &str,
) -> axum::response::Response {
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(login_form(harness, identifier)))
                .expect("request"),
        )
        .await
        .expect("login")
}

fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .expect("location")
        .to_str()
        .expect("location str")
        .to_owned()
}

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

async fn get(router: Router, uri: &str) -> axum::response::Response {
    router
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("get")
}

fn id_token(key: &SigningKey, nonce: &str, sub: &str) -> String {
    let claims = serde_json::json!({
        "iss": UPSTREAM_ISSUER,
        "sub": sub,
        "aud": UPSTREAM_CLIENT_ID,
        "exp": 4_102_444_800_i64,
        "iat": 0,
        "nonce": nonce,
    });
    let payload = serde_json::to_vec(&claims).expect("payload");
    sign_jws(key, &payload, &EmissionOptions::new().with_typ("JWT")).expect("sign")
}

fn token_response(id_token: &str) -> String {
    format!(r#"{{"access_token":"upstream-at","token_type":"Bearer","id_token":"{id_token}"}}"#)
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

/// Drive the full routed login (POST /login -> federated authorize -> callback) for
/// `identifier` and upstream `sub`, returning the final callback response.
async fn routed_login(
    harness: &Harness,
    runtime: &Arc<FederationRuntime>,
    upstream: &Upstream,
    identifier: &str,
    sub: &str,
) -> axum::response::Response {
    // 1. POST /login: a routed identifier redirects to the federated authorize leg.
    let login = post_login(router(harness, runtime), harness, identifier).await;
    assert_eq!(
        login.status(),
        StatusCode::SEE_OTHER,
        "a routed login redirects to federation"
    );
    let authorize_uri = location(&login);
    assert!(
        authorize_uri.contains("/federation/") && authorize_uri.contains("org_connection="),
        "the redirect carries the routed org connection: {authorize_uri}"
    );

    // 2. GET the federated authorize leg: 302 to the upstream with state + nonce.
    let authorize = get(router(harness, runtime), &authorize_uri).await;
    assert_eq!(
        authorize.status(),
        StatusCode::SEE_OTHER,
        "the authorize leg redirects to the upstream"
    );
    let upstream_redirect = location(&authorize);
    let state = param(&upstream_redirect, "state");
    let nonce = param(&upstream_redirect, "nonce");

    // 3. The upstream issues an id_token bound to that nonce; drive the callback.
    *upstream.token_response.lock().unwrap() =
        token_response(&id_token(&upstream.key, &nonce, sub));
    let scope = harness.scope();
    let callback_uri = format!(
        "/t/{}/e/{}/federation/{}/callback?state={state}&code=upstream-code",
        scope.tenant(),
        scope.environment(),
        // The connector slug is the segment before /callback in the authorize URI.
        authorize_uri
            .split("/federation/")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .expect("slug"),
    );
    get(router(harness, runtime), &callback_uri).await
}

#[tokio::test]
async fn a_domain_routed_first_login_jit_provisions_and_stamps_the_org() {
    let harness = Harness::start().await;
    let ocn_id = seed_binding(&harness, "acme").await;
    seed_rule(&harness, RoutingSelector::Domain(ROUTED_DOMAIN), &ocn_id).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr);

    let response = routed_login(
        &harness,
        &runtime,
        &upstream,
        "alice@acme.example",
        "acme-sub-1",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the routed federated login completes and resumes the local authorize"
    );
    assert!(session_id_from_cookies(&response, &harness.scope()).is_some());

    // The federated user is provisioned, keyed on the verified issuer-namespaced id, and
    // STAMPED with the routed organization.
    let external_id = federated_external_id(UPSTREAM_ISSUER, "acme-sub-1");
    let user = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_external_id(&external_id)
        .await
        .expect("by_external_id")
        .expect("the federated user is provisioned");
    let stamped = harness
        .store()
        .scoped(harness.scope())
        .users()
        .org_connection(&user.id)
        .await
        .expect("org_connection read")
        .expect("the user is stamped with the org connection");
    assert_eq!(stamped.to_string(), ocn_id.to_string());
}

#[tokio::test]
async fn a_subsequent_routed_login_updates_the_same_user_with_no_duplicate() {
    let harness = Harness::start().await;
    let ocn_id = seed_binding(&harness, "acme").await;
    seed_rule(&harness, RoutingSelector::Domain(ROUTED_DOMAIN), &ocn_id).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr);

    let first = routed_login(
        &harness,
        &runtime,
        &upstream,
        "bob@acme.example",
        "acme-sub-2",
    )
    .await;
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    let external_id = federated_external_id(UPSTREAM_ISSUER, "acme-sub-2");
    let first_user = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_external_id(&external_id)
        .await
        .expect("by_external_id")
        .expect("first login provisions")
        .id;

    let second = routed_login(
        &harness,
        &runtime,
        &upstream,
        "bob@acme.example",
        "acme-sub-2",
    )
    .await;
    assert_eq!(second.status(), StatusCode::SEE_OTHER);
    let second_user = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_external_id(&external_id)
        .await
        .expect("by_external_id")
        .expect("second login resolves")
        .id;
    assert_eq!(
        first_user, second_user,
        "a subsequent login reuses the one (issuer, sub) identity (no duplicate)"
    );
    // Still stamped with the org after the update-in-place.
    assert_eq!(
        harness
            .store()
            .scoped(harness.scope())
            .users()
            .org_connection(&second_user)
            .await
            .expect("org_connection")
            .expect("still stamped")
            .to_string(),
        ocn_id.to_string()
    );
}

#[tokio::test]
async fn per_app_and_per_user_rules_override_a_domain_rule() {
    let harness = Harness::start().await;
    // A domain binding on connector "acme", plus a distinct binding on connector
    // "override" that the app and user rules point at.
    let domain_ocn = seed_binding(&harness, "acme").await;
    seed_rule(
        &harness,
        RoutingSelector::Domain(ROUTED_DOMAIN),
        &domain_ocn,
    )
    .await;

    // A second binding (fresh org + connector "override") for the more-specific rules.
    let override_ocn = {
        let env = harness.env().clone();
        let scope = harness.scope();
        let control = harness.db().control_store();
        let org = OrganizationId::generate(&env, &scope);
        control
            .management()
            .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
            .organizations(scope)
            .create(&env, &org, 1_000_000, "Override Corp", None)
            .await
            .expect("org");
        let connector = ConnectorId::generate(&env, &scope);
        let definition = format!(
            r#"{{"connector_id":"override","display_name":"O","protocol":"oidc","endpoints":{{"issuer":"{UPSTREAM_ISSUER}"}},"scopes":["openid"],"client_id":"{UPSTREAM_CLIENT_ID}"}}"#
        );
        control
            .scoped(scope)
            .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
            .connectors()
            .create(
                &env,
                &connector,
                1_000_000,
                NewConnector {
                    slug: "override",
                    definition_json: &definition,
                    client_secret: b"s",
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
            .expect("connector");
        let ocn = OrgConnectionId::generate(&env, &scope);
        control
            .scoped(scope)
            .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
            .org_connections()
            .create(
                &env,
                &ocn,
                1_000_000,
                NewOrgConnection {
                    organization_id: &org,
                    connector_id: &connector,
                    capture_upstream_tokens: false,
                    enabled: true,
                },
            )
            .await
            .expect("binding");
        ocn
    };

    let runtime = build_runtime(([127, 0, 0, 1], 1).into());

    // Per-app override: an app rule for the harness client wins over the domain rule.
    seed_rule(
        &harness,
        RoutingSelector::App(&harness.client_id().to_string()),
        &override_ocn,
    )
    .await;
    let app_routed = post_login(router(&harness, &runtime), &harness, "carol@acme.example").await;
    assert_eq!(app_routed.status(), StatusCode::SEE_OTHER);
    assert!(
        location(&app_routed).contains("/federation/override/authorize"),
        "the app rule overrides the domain rule: {}",
        location(&app_routed)
    );
    assert!(
        location(&app_routed).contains(&format!("org_connection={override_ocn}")),
        "the routed org connection is the app rule's: {}",
        location(&app_routed)
    );

    // Per-user override: a user rule for a specific handle wins over both.
    seed_rule(
        &harness,
        RoutingSelector::User("dan@acme.example"),
        &override_ocn,
    )
    .await;
    let user_routed = post_login(router(&harness, &runtime), &harness, "dan@acme.example").await;
    assert_eq!(user_routed.status(), StatusCode::SEE_OTHER);
    assert!(
        location(&user_routed).contains("/federation/override/authorize"),
        "the user rule overrides the app and domain rules: {}",
        location(&user_routed)
    );
}

#[tokio::test]
async fn a_no_match_identifier_falls_through_to_local_login() {
    let harness = Harness::start().await;
    let ocn_id = seed_binding(&harness, "acme").await;
    seed_rule(&harness, RoutingSelector::Domain(ROUTED_DOMAIN), &ocn_id).await;
    let runtime = build_runtime(([127, 0, 0, 1], 1).into());

    // An email at an UNROUTED domain is not redirected to federation; it falls through to
    // the ordinary local login (which, for an unknown account + wrong password, re-renders
    // the failed-login page rather than a federation redirect).
    let response = post_login(
        router(&harness, &runtime),
        &harness,
        "stranger@other.example",
    )
    .await;
    let is_federation_redirect = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|location| location.contains("/federation/"));
    assert!(
        !is_federation_redirect,
        "an unrouted identifier must not be redirected to federation"
    );
}
