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
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
    verify_clock,
};
use ironauth_env::Clock;
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, TotpParams, code_at, sign_jws, verify};
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
/// binding between them (with NO broker overlay); return the binding id.
async fn seed_binding(harness: &Harness, slug: &str) -> OrgConnectionId {
    seed_binding_with_overlay(harness, slug, None, None, None).await
}

/// Like [`seed_binding`] but stamps the broker overlay policy columns (issue #77 PR 2) on
/// the binding, so a test can exercise the overlay the callback and the authorization gate
/// enforce.
async fn seed_binding_with_overlay(
    harness: &Harness,
    slug: &str,
    overlay_min_acr: Option<&str>,
    max_age_secs: Option<i32>,
    overlay_min_class: Option<&str>,
) -> OrgConnectionId {
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
                overlay_min_acr,
                max_age_secs,
                overlay_min_class,
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
        authorize_uri.contains("/federation/") && authorize_uri.contains("routing="),
        "the redirect carries the server-authenticated routing token: {authorize_uri}"
    );

    // 2-3. Follow the authorize leg to the upstream and drive the callback.
    complete_federation(harness, runtime, upstream, &authorize_uri, sub).await
}

/// Follow a federated `authorize_uri` (302 to the upstream), have the mock upstream issue
/// an `id_token` bound to the nonce, and drive the callback, returning its response.
async fn complete_federation(
    harness: &Harness,
    runtime: &Arc<FederationRuntime>,
    upstream: &Upstream,
    authorize_uri: &str,
    sub: &str,
) -> axum::response::Response {
    let authorize = get(router(harness, runtime), authorize_uri).await;
    assert_eq!(
        authorize.status(),
        StatusCode::SEE_OTHER,
        "the authorize leg redirects to the upstream"
    );
    let upstream_redirect = location(&authorize);
    let state = param(&upstream_redirect, "state");
    let nonce = param(&upstream_redirect, "nonce");

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

/// Build a federated authorize URI for connector `slug`, carrying the local `return_to`
/// and, when `routing` is `Some`, that routing token as the `routing` query param.
fn authorize_uri(harness: &Harness, slug: &str, routing: Option<&str>) -> String {
    let scope = harness.scope();
    let return_to = format!("/authorize?client_id={}", harness.client_id());
    let mut uri = format!(
        "/t/{}/e/{}/federation/{}/authorize?return_to={}",
        scope.tenant(),
        scope.environment(),
        slug,
        encode(&return_to),
    );
    if let Some(token) = routing {
        use std::fmt::Write as _;
        let _ = write!(uri, "&routing={}", encode(token));
    }
    uri
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
#[allow(clippy::too_many_lines)]
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
                    overlay_min_acr: None,
                    max_age_secs: None,
                    overlay_min_class: None,
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
    // The routed org connection now travels as an OPAQUE server-authenticated token (its
    // id is no longer a browser-visible plaintext param); the end-to-end stamp test proves
    // the correct org is bound. Here we assert the token is present on the winning route.
    assert!(
        location(&app_routed).contains("routing="),
        "the app-rule route carries a routing token: {}",
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

/// Seed an org, a connector at `slug` (pointing at the mock upstream), and a binding
/// between them; return the connector id and the binding id.
async fn seed_connector_and_binding(
    harness: &Harness,
    slug: &str,
) -> (ConnectorId, OrgConnectionId) {
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
                overlay_min_acr: None,
                max_age_secs: None,
                overlay_min_class: None,
                capture_upstream_tokens: false,
                enabled: true,
            },
        )
        .await
        .expect("create org connection");
    (connector_id, ocn_id)
}

/// Seed a fresh org and a SECOND binding on the EXISTING `connector_id` (two orgs
/// legitimately sharing one connector), returning the new binding id.
async fn seed_extra_binding(harness: &Harness, connector_id: &ConnectorId) -> OrgConnectionId {
    let env = harness.env().clone();
    let scope = harness.scope();
    let control = harness.db().control_store();

    let org_id = OrganizationId::generate(&env, &scope);
    control
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .organizations(scope)
        .create(&env, &org_id, 1_000_000, "Rival Corp", None)
        .await
        .expect("create organization");

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
                connector_id,
                overlay_min_acr: None,
                max_age_secs: None,
                overlay_min_class: None,
                capture_upstream_tokens: false,
                enabled: true,
            },
        )
        .await
        .expect("create second org connection");
    ocn_id
}

/// Flip the first character of a routing token's MAC part to a different base64url char,
/// so the recomputed MAC no longer matches (the `.`-separated layout is
/// `b64(ocn).b64(expiry).b64(mac)`).
fn flip_mac(token: &str) -> String {
    let (rest, mac) = token.rsplit_once('.').expect("mac part");
    let first = mac.chars().next().expect("non-empty mac");
    let replacement = if first == 'A' { 'B' } else { 'A' };
    let flipped: String = std::iter::once(replacement)
        .chain(mac.chars().skip(1))
        .collect();
    format!("{rest}.{flipped}")
}

/// Replace the org-connection part (part 0) of a routing token with `new_ocn_b64`, keeping
/// the original expiry and MAC (the swap the fix must reject).
fn replace_ocn_part(token: &str, new_ocn_b64: &str) -> String {
    let (_old_ocn, rest) = token.split_once('.').expect("ocn part");
    format!("{new_ocn_b64}.{rest}")
}

#[tokio::test]
async fn a_browser_tampered_routing_token_fails_closed_with_no_org_stamped() {
    let harness = Harness::start().await;
    let scope = harness.scope();
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr);

    // Two org connections legitimately SHARE connector "acme" ((orgA, acme) and (orgB, acme)
    // coexist under the (tenant, env, org, connector) unique index), plus a second connector
    // "other" pointing at the same upstream. This is the exact shape the swap and
    // cross-connector attacks target.
    let (acme_connector, ocn_a) = seed_connector_and_binding(&harness, "acme").await;
    let ocn_b = seed_extra_binding(&harness, &acme_connector).await;
    let _other = seed_connector_and_binding(&harness, "other").await;

    // A valid routing token for ocn_a under connector "acme", minted through the STORE the
    // way the login surface does. The harness clock is frozen at the epoch, so the authorize
    // leg reads now = 0 micros; a future expiry keeps the token live.
    let expiry = 1_000_000_000_i64;
    let valid = harness
        .store()
        .scoped(scope)
        .org_connections()
        .mint_routing_token(&ocn_a.to_string(), "acme", expiry)
        .expect("mint valid token");

    // Control: the untampered token is accepted, so the authorize leg redirects upstream.
    let ok = get(
        router(&harness, &runtime),
        &authorize_uri(&harness, "acme", Some(&valid)),
    )
    .await;
    assert_eq!(
        ok.status(),
        StatusCode::SEE_OTHER,
        "a valid routing token routes to the upstream"
    );

    // (a) A flipped MAC byte fails closed with the uniform not-found.
    let flipped = flip_mac(&valid);
    assert_eq!(
        get(
            router(&harness, &runtime),
            &authorize_uri(&harness, "acme", Some(&flipped)),
        )
        .await
        .status(),
        StatusCode::NOT_FOUND,
        "a tampered MAC fails closed"
    );

    // (b) Swapping the org-connection part to a SIBLING under the SAME connector fails
    // closed: the MAC covers ocn_a, not ocn_b, so the browser cannot downgrade the org.
    let sibling_ocn_part = harness
        .store()
        .scoped(scope)
        .org_connections()
        .mint_routing_token(&ocn_b.to_string(), "acme", expiry)
        .expect("mint sibling token")
        .split('.')
        .next()
        .expect("ocn part")
        .to_owned();
    let swapped = replace_ocn_part(&valid, &sibling_ocn_part);
    assert_eq!(
        get(
            router(&harness, &runtime),
            &authorize_uri(&harness, "acme", Some(&swapped)),
        )
        .await
        .status(),
        StatusCode::NOT_FOUND,
        "a browser-swapped org connection under the same connector fails closed"
    );

    // (c) A token minted for connector "acme" presented at connector "other" fails closed:
    // the connector slug is bound into the MAC, so cross-connector replay is rejected.
    assert_eq!(
        get(
            router(&harness, &runtime),
            &authorize_uri(&harness, "other", Some(&valid)),
        )
        .await
        .status(),
        StatusCode::NOT_FOUND,
        "a token replayed on another connector fails closed"
    );

    // (d) An expired token (expiry at the epoch, which the authorize clock reads as now)
    // fails closed.
    let expired = harness
        .store()
        .scoped(scope)
        .org_connections()
        .mint_routing_token(&ocn_a.to_string(), "acme", 0)
        .expect("mint expired token");
    assert_eq!(
        get(
            router(&harness, &runtime),
            &authorize_uri(&harness, "acme", Some(&expired)),
        )
        .await
        .status(),
        StatusCode::NOT_FOUND,
        "an expired token fails closed"
    );

    // No org was stamped by any failed authorize: JIT provisioning happens only at a
    // COMPLETED callback, and every tampered token stopped at the authorize leg. The
    // end-to-end happy-path tests prove a VALID token stamps the correct org.
}

#[tokio::test]
async fn a_direct_federated_login_without_a_routing_token_stamps_no_org() {
    let harness = Harness::start().await;
    let _seeded = seed_connector_and_binding(&harness, "acme").await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr);

    // Hit the federated authorize leg DIRECTLY with NO routing token (a non-routed
    // "log in with Acme" style federated login): the safe default is no org binding.
    let uri = authorize_uri(&harness, "acme", None);
    let response = complete_federation(&harness, &runtime, &upstream, &uri, "direct-sub-1").await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "a direct federated login completes and resumes the local authorize"
    );

    let external_id = federated_external_id(UPSTREAM_ISSUER, "direct-sub-1");
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
        .expect("org_connection read");
    assert!(
        stamped.is_none(),
        "a direct federated login with no routing token carries no org binding"
    );
}

// ---- Broker overlay (issue #77 PR 2) ----
//
// These drive the broker overlay end to end on a REAL database: an org connection whose
// overlay layers an MFA policy on top of a PERMISSIVE upstream forces a real local second
// factor, and the resulting token's `amr`/`acr` reflect it HONESTLY (only because the
// ceremony actually ran). A NULL overlay resumes exactly as a plain federated login, and
// the overlay is enforced at the authorization gate even when the callback redirect is
// skipped (non-bypassable).

/// The current epoch seconds from the harness clock (for a fresh TOTP code).
fn now_secs(harness: &Harness) -> u64 {
    harness
        .clock()
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs()
}

/// The `__Host-ironauth_session=<value>` cookie pair from a response's `Set-Cookie`s.
fn session_cookie_from_headers(headers: &axum::http::HeaderMap) -> String {
    for value in headers.get_all(header::SET_COOKIE) {
        if let Ok(text) = value.to_str() {
            if text.starts_with("__Host-ironauth_session=") {
                return text
                    .split(';')
                    .next()
                    .expect("cookie value")
                    .trim()
                    .to_owned();
            }
        }
    }
    panic!("no session cookie in the response");
}

/// A FULL downstream authorization request to resume after the federated login (an openid
/// code flow with PKCE), so the resumed request issues a real code we can exchange.
fn full_authorize_return_to(harness: &Harness) -> String {
    format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256&nonce=n-broker",
        harness.client_id(),
        enc(REDIRECT_URI),
    )
}

/// The PKCE token-exchange form for the harness public client's code.
fn token_form_pkce(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

/// Drive `POST /login` for `identifier` with an explicit full `return_to`, returning the
/// response (a routed identifier redirects to the federated authorize leg).
async fn post_login_return_to(
    router: Router,
    identifier: &str,
    return_to: &str,
) -> axum::response::Response {
    let body = format!(
        "identifier={}&password=irrelevant&return_to={}",
        encode(identifier),
        encode(return_to)
    );
    router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("login")
}

/// An upstream `id_token` bound to `nonce` for `sub`, optionally asserting an `auth_time`.
fn id_token_at(key: &SigningKey, nonce: &str, sub: &str, auth_time: Option<i64>) -> String {
    let mut claims = serde_json::json!({
        "iss": UPSTREAM_ISSUER,
        "sub": sub,
        "aud": UPSTREAM_CLIENT_ID,
        "exp": 4_102_444_800_i64,
        "iat": 0,
        "nonce": nonce,
    });
    if let Some(auth_time) = auth_time {
        claims["auth_time"] = serde_json::json!(auth_time);
    }
    let payload = serde_json::to_vec(&claims).expect("payload");
    sign_jws(key, &payload, &EmissionOptions::new().with_typ("JWT")).expect("sign")
}

/// Follow a federated `authorize_uri` to the upstream, mint an `id_token` (optionally with
/// an `auth_time`), and drive the callback, returning its response.
async fn complete_federation_at(
    harness: &Harness,
    runtime: &Arc<FederationRuntime>,
    upstream: &Upstream,
    authorize_uri: &str,
    sub: &str,
    auth_time: Option<i64>,
) -> axum::response::Response {
    let authorize = get(router(harness, runtime), authorize_uri).await;
    assert_eq!(authorize.status(), StatusCode::SEE_OTHER);
    let upstream_redirect = location(&authorize);
    let state = param(&upstream_redirect, "state");
    let nonce = param(&upstream_redirect, "nonce");
    *upstream.token_response.lock().unwrap() =
        token_response(&id_token_at(&upstream.key, &nonce, sub, auth_time));
    let scope = harness.scope();
    let callback_uri = format!(
        "/t/{}/e/{}/federation/{}/callback?state={state}&code=upstream-code",
        scope.tenant(),
        scope.environment(),
        authorize_uri
            .split("/federation/")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .expect("slug"),
    );
    get(router(harness, runtime), &callback_uri).await
}

/// Drive the full routed brokered login (POST /login -> federated authorize -> callback)
/// for `identifier`/`sub` resuming at `return_to`, returning the callback response.
async fn brokered_login(
    harness: &Harness,
    runtime: &Arc<FederationRuntime>,
    upstream: &Upstream,
    identifier: &str,
    sub: &str,
    return_to: &str,
    auth_time: Option<i64>,
) -> axum::response::Response {
    let login = post_login_return_to(router(harness, runtime), identifier, return_to).await;
    assert_eq!(
        login.status(),
        StatusCode::SEE_OTHER,
        "a routed login redirects to federation"
    );
    let authorize_uri = location(&login);
    complete_federation_at(harness, runtime, upstream, &authorize_uri, sub, auth_time).await
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_broker_mfa_overlay_forces_a_real_ceremony_and_the_token_amr_is_honest() {
    let harness = Harness::start().await;
    // The org keeps its (permissive) upstream, but the broker overlays an MFA requirement.
    let ocn_id = seed_binding_with_overlay(&harness, "acme", None, None, Some("mfa")).await;
    seed_rule(&harness, RoutingSelector::Domain(ROUTED_DOMAIN), &ocn_id).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr);
    let client = harness.client_id().to_string();
    let return_to = full_authorize_return_to(&harness);

    // The brokered federated login: the callback establishes the federated session but,
    // because the overlay requires MFA and the federated context is UNRANKED, routes
    // STRAIGHT to the second-factor ceremony rather than resuming.
    let callback = brokered_login(
        &harness,
        &runtime,
        &upstream,
        "alice@acme.example",
        "acme-sub-mfa",
        &return_to,
        None,
    )
    .await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let ceremony = location(&callback);
    assert!(
        ceremony.starts_with("/login/mfa"),
        "an mfa overlay on a permissive upstream forces a real ceremony, got {ceremony}"
    );
    let fed_cookie = session_cookie_from_headers(callback.headers());
    let mfa_return_to =
        location_param(callback.headers(), "return_to").expect("return_to on the ceremony");

    // The provisioned federated subject.
    let external_id = federated_external_id(UPSTREAM_ISSUER, "acme-sub-mfa");
    let subject = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_external_id(&external_id)
        .await
        .expect("by_external_id")
        .expect("provisioned")
        .id
        .to_string();
    // Consent up front, so the backstop and resume requests reach the step-up gate rather
    // than the (earlier) consent gate.
    harness.grant_consent(&subject, &client).await;

    // Non-bypassable: skipping the ceremony and hitting the resume /authorize directly with
    // the federated session STILL routes to the second factor (the authorization gate
    // enforces the same overlay), so a user cannot escape it at the federated acr.
    let (status, headers, _) = harness
        .get_with_cookie(&mfa_return_to, Some(&fed_cookie))
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let backstop = common::location(&headers).expect("a Location on the backstop redirect");
    assert!(
        backstop.starts_with("/login/mfa"),
        "the overlay is enforced at the authorization gate, not only the callback redirect: \
         {backstop}"
    );

    // Complete a REAL second factor: enroll TOTP and prove a live code at the ceremony.
    harness.seed_active_totp(&subject).await;
    harness.clock().advance(Duration::from_secs(60));
    let code = code_at(
        &[0x0A; 20],
        TotpParams::authenticator_default(),
        now_secs(&harness),
    );
    let mfa_form = form(&[("code", &code), ("return_to", &mfa_return_to)]);
    let (status, headers, _) = harness
        .post_form("/login/mfa", &mfa_form, Some(&fed_cookie))
        .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the ceremony upgrades the session"
    );
    let upgraded = session_cookie_from_headers(&headers);

    // Resume the pending request: the session now satisfies the overlay, so a code issues.
    let (status, headers, _) = harness
        .get_with_cookie(&mfa_return_to, Some(&upgraded))
        .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the resumed request issues a code"
    );
    let auth_code = location_param(&headers, "code").expect("a code after the ceremony");

    // The token's amr HONESTLY reflects the overlay factor: it carries `mfa`/`otp` ONLY
    // because a real ceremony ran (a pure federated login would carry neither), and the acr
    // is the multi-factor acr, never a fabricated one.
    let (status, _, body) = harness.token(&token_form_pkce(&auth_code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let id_token = json(&body)["id_token"]
        .as_str()
        .expect("id_token")
        .to_owned();
    let policy = harness.policy(&client);
    let verified = verify(&id_token, &policy, &verify_clock()).expect("id token verifies");
    let claims = serde_json::Value::Object(verified.claims().raw().clone());
    assert_eq!(
        claims["acr"], "urn:ironauth:acr:mfa",
        "the overlay-stepped-up token carries the honest multi-factor acr"
    );
    let amr: Vec<&str> = claims["amr"]
        .as_array()
        .expect("amr array")
        .iter()
        .map(|value| value.as_str().expect("amr token"))
        .collect();
    assert!(
        amr.contains(&"mfa") && amr.contains(&"otp"),
        "amr reflects the real second factor, got {amr:?}"
    );
    assert!(
        !amr.contains(&"pwd"),
        "the federated login ran no password; amr must not fabricate one, got {amr:?}"
    );
}

#[tokio::test]
async fn a_no_overlay_federated_login_resumes_unchanged_at_the_federated_acr() {
    let harness = Harness::start().await;
    // A binding with NULL overlay columns: no broker overlay is configured.
    let ocn_id = seed_binding(&harness, "acme").await;
    seed_rule(&harness, RoutingSelector::Domain(ROUTED_DOMAIN), &ocn_id).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr);
    let client = harness.client_id().to_string();
    let return_to = full_authorize_return_to(&harness);

    let callback = brokered_login(
        &harness,
        &runtime,
        &upstream,
        "bob@acme.example",
        "acme-sub-plain",
        &return_to,
        None,
    )
    .await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    // No overlay: the callback resumes DIRECTLY to the pending request (never the ceremony).
    let resumed = location(&callback);
    assert!(
        !resumed.starts_with("/login/mfa"),
        "a no-overlay federated login must not force a ceremony, got {resumed}"
    );
    assert!(
        resumed.starts_with("/authorize"),
        "a no-overlay federated login resumes the pending request, got {resumed}"
    );
    let fed_cookie = session_cookie_from_headers(callback.headers());

    // The resumed request issues a code directly, and its token carries the UNRANKED
    // federated acr with NO fabricated second factor (the honesty contrast).
    let subject = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_external_id(&federated_external_id(UPSTREAM_ISSUER, "acme-sub-plain"))
        .await
        .expect("by_external_id")
        .expect("provisioned")
        .id
        .to_string();
    harness.grant_consent(&subject, &client).await;
    let (status, headers, _) = harness.get_with_cookie(&resumed, Some(&fed_cookie)).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the resumed request issues a code"
    );
    let auth_code = location_param(&headers, "code").expect("a code without any ceremony");
    let (status, _, body) = harness.token(&token_form_pkce(&auth_code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let id_token = json(&body)["id_token"]
        .as_str()
        .expect("id_token")
        .to_owned();
    let policy = harness.policy(&client);
    let verified = verify(&id_token, &policy, &verify_clock()).expect("id token verifies");
    let claims = serde_json::Value::Object(verified.claims().raw().clone());
    assert_eq!(
        claims["acr"], "urn:ironauth:acr:federated",
        "a plain federated login carries the federated context acr"
    );
    let amr = claims["amr"].as_array().cloned().unwrap_or_default();
    let amr: Vec<&str> = amr.iter().filter_map(|value| value.as_str()).collect();
    assert!(
        !amr.contains(&"mfa"),
        "no ceremony ran, so amr must not contain a second factor, got {amr:?}"
    );
}

#[tokio::test]
async fn a_max_age_overlay_forces_reauth_when_the_federated_auth_time_is_stale() {
    let harness = Harness::start().await;
    // A pure max-age overlay (no acr floor): a stale upstream auth_time must force re-auth.
    let ocn_id = seed_binding_with_overlay(&harness, "acme", None, Some(1), None).await;
    seed_rule(&harness, RoutingSelector::Domain(ROUTED_DOMAIN), &ocn_id).await;
    let upstream = start_upstream().await;
    let runtime = build_runtime(upstream.addr);
    let return_to = full_authorize_return_to(&harness);

    // The harness clock is frozen at the epoch; advance it so the callback instant is well
    // past the (epoch) upstream auth_time and the one-second overlay window has lapsed.
    harness.clock().advance(Duration::from_secs(3_600));

    // The upstream asserts an auth_time (epoch) far older than the one-second overlay window.
    let callback = brokered_login(
        &harness,
        &runtime,
        &upstream,
        "carol@acme.example",
        "acme-sub-age",
        &return_to,
        Some(0),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let ceremony = location(&callback);
    assert!(
        ceremony.starts_with("/login/mfa"),
        "a stale federated auth_time under a max-age overlay forces re-auth, got {ceremony}"
    );
}

// ---- Broker overlay over an OAuth 2.0 (GitHub) backed org connection (issue #77 PR 2) ----
//
// The routing machinery and the shared finalize path are protocol-agnostic: an org connection
// whose connector is a plain OAuth 2.0 (GitHub) connector carries the SAME server-authenticated
// org binding on the consumed correlation row as an OIDC connector, so a broker overlay layered
// on top of a PERMISSIVE upstream like GitHub is enforced IDENTICALLY (a real local ceremony at
// the callback and the same non-bypassable authorization-gate backstop). This is exactly the
// feature's use case: brokering MFA over a permissive social upstream.

/// A mock GitHub OAuth 2.0 upstream: an access-token endpoint plus FIXED profile and email
/// endpoints (no ID token). The identity keys on the stable numeric id; the primary verified
/// email is the routed-domain address so the JIT-provisioned user matches the login identifier.
struct GithubUpstream {
    addr: SocketAddr,
}

async fn start_github_upstream() -> GithubUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let first = request.lines().next().unwrap_or("");
                // `/user/emails` must be matched BEFORE `/user` (it contains it).
                let body = if first.contains("/access_token") {
                    String::from(r#"{"access_token":"gh-broker-at","token_type":"bearer"}"#)
                } else if first.contains("/user/emails") {
                    String::from(
                        r#"[{"email":"alice@acme.example","primary":true,"verified":true}]"#,
                    )
                } else if first.contains("/user") {
                    String::from(
                        r#"{"id":77770001,"login":"brokeroct","name":"Broker Octocat","email":null}"#,
                    )
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
    GithubUpstream { addr }
}

/// The federated external id the mock GitHub identity provisions under (the stable numeric id
/// namespaced by the connector's `identity_issuer`, which is `UPSTREAM_ISSUER` here).
fn github_external_id() -> String {
    federated_external_id(UPSTREAM_ISSUER, "77770001")
}

/// Seed an org, a GitHub OAuth 2.0 (non-OIDC) connector at `slug` pointing at the mock, and a
/// binding between them stamping the broker overlay `overlay_min_class` (issue #77 PR 2);
/// return the binding id.
async fn seed_github_binding_with_overlay(
    harness: &Harness,
    slug: &str,
    overlay_min_class: Option<&str>,
) -> OrgConnectionId {
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
    let definition = serde_json::json!({
        "connector_id": slug,
        "display_name": "Acme GitHub",
        "protocol": "oauth2",
        "endpoints": {
            "authorization_endpoint": format!("{UPSTREAM_ISSUER}/login/oauth/authorize"),
            "token_endpoint": format!("{UPSTREAM_ISSUER}/login/oauth/access_token"),
            "profile_endpoint": format!("{UPSTREAM_ISSUER}/user"),
            "email_endpoint": format!("{UPSTREAM_ISSUER}/user/emails"),
            "identity_issuer": UPSTREAM_ISSUER
        },
        "scopes": ["read:user", "user:email"],
        "client_id": UPSTREAM_CLIENT_ID
    })
    .to_string();
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
                client_secret: b"github-secret",
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
                overlay_min_acr: None,
                max_age_secs: None,
                overlay_min_class,
                capture_upstream_tokens: false,
                enabled: true,
            },
        )
        .await
        .expect("create org connection");
    ocn_id
}

/// Follow a federated OAuth 2.0 `authorize_uri` (302 to the upstream, NO nonce) and drive the
/// callback, returning its response. The mock GitHub upstream serves a fixed identity.
async fn complete_github_federation(
    harness: &Harness,
    runtime: &Arc<FederationRuntime>,
    authorize_uri: &str,
) -> axum::response::Response {
    let authorize = get(router(harness, runtime), authorize_uri).await;
    assert_eq!(authorize.status(), StatusCode::SEE_OTHER);
    let upstream_redirect = location(&authorize);
    assert!(
        upstream_redirect.starts_with(&format!("{UPSTREAM_ISSUER}/login/oauth/authorize")),
        "the OAuth 2.0 authorize leg redirects to the upstream: {upstream_redirect}"
    );
    let state = param(&upstream_redirect, "state");
    let scope = harness.scope();
    let callback_uri = format!(
        "/t/{}/e/{}/federation/{}/callback?state={state}&code=gh-code",
        scope.tenant(),
        scope.environment(),
        authorize_uri
            .split("/federation/")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .expect("slug"),
    );
    get(router(harness, runtime), &callback_uri).await
}

/// Drive the full routed brokered GitHub (OAuth 2.0) login (POST /login -> federated authorize
/// -> callback) for `identifier` resuming at `return_to`, returning the callback response.
async fn brokered_github_login(
    harness: &Harness,
    runtime: &Arc<FederationRuntime>,
    identifier: &str,
    return_to: &str,
) -> axum::response::Response {
    let login = post_login_return_to(router(harness, runtime), identifier, return_to).await;
    assert_eq!(
        login.status(),
        StatusCode::SEE_OTHER,
        "a routed login redirects to federation"
    );
    let authorize_uri = location(&login);
    complete_github_federation(harness, runtime, &authorize_uri).await
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_broker_mfa_overlay_over_an_oauth2_connector_forces_a_real_ceremony_and_stamps_the_org() {
    let harness = Harness::start().await;
    // The org fronts a PERMISSIVE GitHub (OAuth 2.0) upstream, but the broker overlays MFA.
    let ocn_id = seed_github_binding_with_overlay(&harness, "acme-gh", Some("mfa")).await;
    seed_rule(&harness, RoutingSelector::Domain(ROUTED_DOMAIN), &ocn_id).await;
    let upstream = start_github_upstream().await;
    let runtime = build_runtime(upstream.addr);
    let client = harness.client_id().to_string();
    let return_to = full_authorize_return_to(&harness);

    // The brokered GitHub login: the callback establishes the federated session but, because
    // the overlay requires MFA and the federated context is UNRANKED, routes STRAIGHT to the
    // second-factor ceremony rather than resuming (identical to the OIDC flagship).
    let callback =
        brokered_github_login(&harness, &runtime, "alice@acme.example", &return_to).await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let ceremony = location(&callback);
    assert!(
        ceremony.starts_with("/login/mfa"),
        "an mfa overlay on a permissive OAuth 2.0 upstream forces a real ceremony, got {ceremony}"
    );
    let fed_cookie = session_cookie_from_headers(callback.headers());
    let mfa_return_to =
        location_param(callback.headers(), "return_to").expect("return_to on the ceremony");

    // The federated user is provisioned (keyed on the stable numeric id) and STAMPED with the
    // routed org connection, exactly like the OIDC path.
    let subject_id = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_external_id(&github_external_id())
        .await
        .expect("by_external_id")
        .expect("the GitHub federated user is provisioned")
        .id;
    let stamped = harness
        .store()
        .scoped(harness.scope())
        .users()
        .org_connection(&subject_id)
        .await
        .expect("org_connection read")
        .expect("the OAuth 2.0 federated user is stamped with the org connection");
    assert_eq!(
        stamped.to_string(),
        ocn_id.to_string(),
        "the OAuth 2.0 path stamps the same server-authenticated org binding as OIDC"
    );
    let subject = subject_id.to_string();
    harness.grant_consent(&subject, &client).await;

    // Non-bypassable backstop: skip the callback ceremony and hit the resume /authorize DIRECTLY
    // with the federated session; the authorization gate enforces the SAME overlay, so it still
    // routes to the second factor. A user cannot escape it at the federated acr.
    let (status, headers, _) = harness
        .get_with_cookie(&mfa_return_to, Some(&fed_cookie))
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let backstop = common::location(&headers).expect("a Location on the backstop redirect");
    assert!(
        backstop.starts_with("/login/mfa"),
        "the overlay is enforced at the authorization gate for an OAuth 2.0 connection too: \
         {backstop}"
    );

    // Complete a REAL second factor and prove the resumed token's amr is HONEST.
    harness.seed_active_totp(&subject).await;
    harness.clock().advance(Duration::from_secs(60));
    let code = code_at(
        &[0x0A; 20],
        TotpParams::authenticator_default(),
        now_secs(&harness),
    );
    let mfa_form = form(&[("code", &code), ("return_to", &mfa_return_to)]);
    let (status, headers, _) = harness
        .post_form("/login/mfa", &mfa_form, Some(&fed_cookie))
        .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the ceremony upgrades the session"
    );
    let upgraded = session_cookie_from_headers(&headers);

    let (status, headers, _) = harness
        .get_with_cookie(&mfa_return_to, Some(&upgraded))
        .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the resumed request issues a code"
    );
    let auth_code = location_param(&headers, "code").expect("a code after the ceremony");

    let (status, _, body) = harness.token(&token_form_pkce(&auth_code, &client)).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let id_token = json(&body)["id_token"]
        .as_str()
        .expect("id_token")
        .to_owned();
    let policy = harness.policy(&client);
    let verified = verify(&id_token, &policy, &verify_clock()).expect("id token verifies");
    let claims = serde_json::Value::Object(verified.claims().raw().clone());
    assert_eq!(
        claims["acr"], "urn:ironauth:acr:mfa",
        "the overlay-stepped-up token carries the honest multi-factor acr"
    );
    let amr: Vec<&str> = claims["amr"]
        .as_array()
        .expect("amr array")
        .iter()
        .map(|value| value.as_str().expect("amr token"))
        .collect();
    assert!(
        amr.contains(&"mfa") && amr.contains(&"otp"),
        "amr reflects the real second factor, got {amr:?}"
    );
    assert!(
        !amr.contains(&"pwd"),
        "the GitHub federated login ran no password; amr must not fabricate one, got {amr:?}"
    );
}

#[tokio::test]
async fn a_no_overlay_oauth2_federated_login_resumes_unchanged() {
    let harness = Harness::start().await;
    // A GitHub (OAuth 2.0) binding with NULL overlay columns: no policy is layered on, so the
    // login must resume exactly as a plain federated login (no regression to issue #74).
    let ocn_id = seed_github_binding_with_overlay(&harness, "acme-gh", None).await;
    seed_rule(&harness, RoutingSelector::Domain(ROUTED_DOMAIN), &ocn_id).await;
    let upstream = start_github_upstream().await;
    let runtime = build_runtime(upstream.addr);
    let return_to = full_authorize_return_to(&harness);

    let callback =
        brokered_github_login(&harness, &runtime, "alice@acme.example", &return_to).await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let resumed = location(&callback);
    assert!(
        !resumed.starts_with("/login/mfa"),
        "a no-overlay OAuth 2.0 federated login must not force a ceremony, got {resumed}"
    );
    assert!(
        resumed.starts_with("/authorize"),
        "a no-overlay OAuth 2.0 federated login resumes the pending request, got {resumed}"
    );
    // Still provisioned and stamped with the org (the stamp is independent of the overlay).
    let subject_id = harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_external_id(&github_external_id())
        .await
        .expect("by_external_id")
        .expect("the GitHub federated user is provisioned")
        .id;
    assert_eq!(
        harness
            .store()
            .scoped(harness.scope())
            .users()
            .org_connection(&subject_id)
            .await
            .expect("org_connection read")
            .expect("stamped")
            .to_string(),
        ocn_id.to_string()
    );
}
