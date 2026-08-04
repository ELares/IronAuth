// SPDX-License-Identifier: MIT OR Apache-2.0

//! The PERMANENT guarded-account-linking adversarial suite (issue #78, PR 2), on a REAL
//! database against a MOCK upstream driven through the ironauth-fetch test-harness.
//!
//! Account linking is where federation CVEs live. This suite encodes the CVE class as
//! executable attacks that must FAIL, so a regression cannot ship silently:
//!
//!   (a) unverified pre-registration then victim social login (Better-Auth CVE / nOAuth
//!       shape): an attacker who pre-registers an UNVERIFIED local account with the victim's
//!       email never links into or gains access to that account when the victim social-logs
//!       in, even under the opt-in verified-to-verified posture (`local_verified` is false);
//!   (b) a forged / upstream-manipulated `email_verified` from an UNTRUSTED connector never
//!       auto-links (the nOAuth class);
//!   (c) an untrusted-IdP auto-link attempt is blocked regardless of the other inputs;
//!   (d) no self-service path sets a LOCAL identity's verified flag: a manual link never
//!       promotes the local verified state;
//!   (e) unlinking the last usable authentication method is refused with a typed error
//!       (the Zitadel anti-bricking guard), and the concurrency case cannot brick.
//!
//! Positive controls prove the block tests are meaningful: an all-green login DOES auto-link
//! (and only then), the per-environment posture override IS consulted, and every link and
//! unlink emits BOTH an audit event AND a notification to every verified channel.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{FAR_FUTURE_MICROS, Harness};
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use ironauth_oidc::{
    FederationKeyResolver, FederationRuntime, VerificationPurpose, VerificationSender,
    federated_external_id, oidc_router,
};
use ironauth_store::{
    AccountLinkId, AccountLinkMethod, AccountLinkRecord, ConnectorCapabilities, ConnectorId,
    CorrelationId, FederationLoginStateId, IdentifierType, NewAccountLink, NewConnector,
    NewFederationLoginState, NewUserIdentifier, PasswordRemovalOutcome, UniquenessMode,
    UnlinkOutcome, UserId,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tower::ServiceExt;

const MOCK_ISSUER: &str = "http://upstream.example";
const PUBLIC_IP: [u8; 4] = [93, 184, 216, 34];
const CLIENT_ID: &str = "ironauth-at-upstream";
const SLUG: &str = "google";

// ===========================================================================
// The mock upstream and federation runtime (mirrors the social_providers harness).
// ===========================================================================

struct Mock {
    addr: SocketAddr,
    key: SigningKey,
    oidc_token: Arc<Mutex<String>>,
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
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let token = Arc::clone(&oidc_token);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let (discovery, jwks, token) = (discovery.clone(), jwks.clone(), Arc::clone(&token));
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

// ===========================================================================
// A recording verification sender: captures every AccountLinked / AccountUnlinked alert.
// ===========================================================================

#[derive(Debug, Default)]
struct RecordingSender {
    linked: Mutex<Vec<String>>,
    unlinked: Mutex<Vec<String>>,
}

impl RecordingSender {
    fn linked(&self) -> Vec<String> {
        let mut out = self.linked.lock().expect("lock").clone();
        out.sort();
        out
    }

    fn unlinked(&self) -> Vec<String> {
        let mut out = self.unlinked.lock().expect("lock").clone();
        out.sort();
        out
    }
}

impl VerificationSender for RecordingSender {
    fn send(&self, _scope: ironauth_store::Scope, purpose: VerificationPurpose, recipient: &str) {
        match purpose {
            VerificationPurpose::AccountLinked => {
                self.linked.lock().expect("lock").push(recipient.to_owned());
            }
            VerificationPurpose::AccountUnlinked => {
                self.unlinked
                    .lock()
                    .expect("lock")
                    .push(recipient.to_owned());
            }
            _ => {}
        }
    }
}

// ===========================================================================
// Seeding + driving helpers.
// ===========================================================================

async fn seed_trait_schema(harness: &Harness) {
    let schema = json!({
        "type": "object",
        "properties": {
            "email": {"type": "string", "minLength": 3},
            "name": {"type": "string"},
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

/// Seed an OIDC discovery connector at `SLUG` with the given `email_verified` trust.
async fn seed_connector(harness: &Harness, trust: &str) {
    // The capability matrix rides the definition_json exactly as production stores it (the
    // callback reads its email_verified trust from `definition.capabilities`), and is mirrored
    // into the separate capability columns below.
    let definition = json!({
        "connector_id": SLUG,
        "display_name": SLUG,
        "protocol": "oidc",
        "endpoints": {"issuer": MOCK_ISSUER},
        "scopes": ["openid", "email", "profile"],
        "client_id": CLIENT_ID,
        "capabilities": {"email_verified_trust": trust},
        "claim_mapping": {"traits": {
            "email": {"source": ["email"], "required": true},
            "name": {"source": ["name"], "required": false}
        }}
    })
    .to_string();
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
                slug: SLUG,
                definition_json: &definition,
                client_secret: b"secret",
                capabilities: ConnectorCapabilities {
                    refresh: false,
                    groups: false,
                    logout_propagation: false,
                    email_verified_trust: trust,
                },
                enabled: true,
            },
            None,
        )
        .await
        .expect("seed connector");
}

/// Seed a TRUSTED Apple-style OIDC connector (mirroring the shipped `apple_definition`) that
/// names the Hide My Email relay domain as a quirk (issue #74), so the callback runs the SAME
/// relay classification the real Apple connector does. It is mounted at the test `SLUG` route
/// so every shared login/callback helper applies unchanged; only the relay quirk and the
/// `email_relay` trait mapping differ from `seed_connector`.
async fn seed_relay_connector(harness: &Harness) {
    let definition = json!({
        "connector_id": SLUG,
        "display_name": "apple",
        "protocol": "oidc",
        "endpoints": {"issuer": MOCK_ISSUER},
        "scopes": ["openid", "email", "name"],
        "client_id": CLIENT_ID,
        "capabilities": {"email_verified_trust": "trusted"},
        "claim_mapping": {"traits": {
            "email": {"source": ["email"], "required": true},
            "name": {"source": ["name"], "required": false},
            "email_relay": {"source": ["email_relay"], "required": false}
        }},
        "quirks": {"relay_email_domain": "privaterelay.appleid.com"}
    })
    .to_string();
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
                slug: SLUG,
                definition_json: &definition,
                client_secret: b"secret",
                capabilities: ConnectorCapabilities {
                    refresh: false,
                    groups: false,
                    logout_propagation: false,
                    email_verified_trust: "trusted",
                },
                enabled: true,
            },
            None,
        )
        .await
        .expect("seed relay connector");
}

async fn connector_id(harness: &Harness) -> String {
    harness
        .store()
        .scoped(harness.scope())
        .connectors()
        .by_slug(SLUG)
        .await
        .expect("by_slug")
        .expect("connector")
        .id
        .to_string()
}

/// Set (or clear) the PER-ENVIRONMENT auto-link posture override through the control plane.
async fn set_env_posture(harness: &Harness, posture: Option<&str>) {
    let env = harness.env().clone();
    let scope = harness.scope();
    let env_id = scope.environment();
    harness
        .db()
        .control_store()
        .management()
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .environments(scope.tenant())
        .set_auto_link_posture(&env, &env_id, posture)
        .await
        .expect("set posture");
}

fn subject_id(harness: &Harness, subject: &str) -> UserId {
    harness
        .store()
        .scoped(harness.scope())
        .users()
        .parse_id(subject)
        .expect("parse subject")
}

/// Add an Email identifier to a local user with the given `verified` flag.
async fn add_email(harness: &Harness, subject: &UserId, raw: &str, verified: bool) {
    let env = harness.env().clone();
    harness
        .store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .user_identifiers()
        .add(
            &env,
            NewUserIdentifier {
                id: &ironauth_store::UserIdentifierId::generate(&env, &harness.scope()),
                user_id: subject,
                identifier_type: IdentifierType::Email,
                raw,
                verified,
                mode: UniquenessMode::EnvironmentWide,
                org: None,
            },
            None,
        )
        .await
        .expect("add email identifier");
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

fn id_token(key: &SigningKey, nonce: &str, sub: &str, extra: Value) -> String {
    let mut claims = json!({
        "iss": MOCK_ISSUER,
        "sub": sub,
        "aud": CLIENT_ID,
        "exp": 4_102_444_800_i64,
        "iat": 0,
        "nonce": nonce,
    });
    if let (Value::Object(c), Value::Object(o)) = (&mut claims, extra) {
        for (k, v) in o {
            c.insert(k, v);
        }
    }
    let payload = serde_json::to_vec(&claims).expect("payload");
    sign_jws(key, &payload, &EmissionOptions::new().with_typ("JWT")).expect("sign") // invariant-allow: typ-via-declaration -- a simulated UPSTREAM issuer's ID token; its media type is that peer's, not an IronAuth profile
}

fn token_body(id_token: &str) -> String {
    format!(r#"{{"access_token":"up-at","token_type":"Bearer","id_token":"{id_token}"}}"#)
}

async fn drive_authorize(harness: &Harness, runtime: Arc<FederationRuntime>) -> String {
    let scope = harness.scope();
    let return_to = format!("/authorize?client_id={}", harness.client_id());
    let uri = format!(
        "/t/{}/e/{}/federation/{SLUG}/authorize?return_to={}",
        scope.tenant(),
        scope.environment(),
        encode(&return_to),
    );
    let response = router(harness, runtime)
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

async fn drive_callback(
    harness: &Harness,
    runtime: Arc<FederationRuntime>,
    state: &str,
) -> StatusCode {
    let scope = harness.scope();
    let uri = format!(
        "/t/{}/e/{}/federation/{SLUG}/callback?state={state}&code=up-code",
        scope.tenant(),
        scope.environment(),
    );
    router(harness, runtime)
        .oneshot(
            Request::builder()
                .uri(&uri)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("callback")
        .status()
}

/// Drive a full federated login (authorize then callback) emitting the given id-token
/// claims, returning the callback status.
async fn login(harness: &Harness, mock: &Mock, sub: &str, claims: Value) -> StatusCode {
    let location = drive_authorize(harness, build_runtime(mock.addr)).await;
    let nonce = param(&location, "nonce").expect("nonce");
    let state = param(&location, "state").expect("state");
    *mock.oidc_token.lock().expect("lock") = token_body(&id_token(&mock.key, &nonce, sub, claims));
    drive_callback(harness, build_runtime(mock.addr), &state).await
}

async fn links_for(harness: &Harness, user: &UserId) -> Vec<AccountLinkRecord> {
    harness
        .store()
        .scoped(harness.scope())
        .account_links()
        .list_for_user(user)
        .await
        .expect("list links")
}

async fn provisioned(harness: &Harness, sub: &str) -> Option<UserId> {
    harness
        .store()
        .scoped(harness.scope())
        .users()
        .by_external_id(&federated_external_id(MOCK_ISSUER, sub))
        .await
        .expect("by_external_id")
        .map(|record| record.id)
}

async fn email_verified(harness: &Harness, subject: &UserId, raw: &str) -> Option<bool> {
    harness
        .store()
        .scoped(harness.scope())
        .user_identifiers()
        .list_for_user(subject)
        .await
        .expect("list identifiers")
        .into_iter()
        .find(|record| record.raw == raw)
        .map(|record| record.verified)
}

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

// ===========================================================================
// Positive controls: auto-link works ONLY all-green, and the per-env posture is consulted.
// ===========================================================================

#[tokio::test]
async fn all_green_auto_links_a_verified_local_account_and_never_promotes_verified() {
    let mut harness = Harness::start().await;
    let sender = Arc::new(RecordingSender::default());
    harness.install_verification_sender(sender.clone());
    seed_trait_schema(&harness).await;
    seed_connector(&harness, "trusted").await;
    // The per-environment override opts THIS environment into verified-to-verified linking.
    set_env_posture(&harness, Some("verified_to_verified")).await;

    // A verified local account whose email the federated identity will match.
    let subject = subject_id(&harness, &harness.seed_user("owner-acct", "pw").await);
    add_email(&harness, &subject, "owner@example.test", true).await;

    let mock = start_mock().await;
    let status = login(
        &harness,
        &mock,
        "fed-sub-1",
        json!({"email": "owner@example.test", "email_verified": true, "name": "Owner"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the all-green login auto-links and signs in"
    );

    // A single auto_verified link binds the federated identity to the EXISTING local user.
    let links = links_for(&harness, &subject).await;
    assert_eq!(links.len(), 1, "exactly one link");
    assert_eq!(links[0].link_method, AccountLinkMethod::AutoVerified);
    assert_eq!(links[0].user_id, subject.to_string());
    // No SEPARATE federated account was provisioned (the identity resolves to the local user).
    assert!(
        provisioned(&harness, "fed-sub-1").await.is_none(),
        "auto-link must NOT provision a separate federated account"
    );
    // The link NEVER promotes the local identity's verified flag (it was already true; the
    // point is the link touches account_links only, never user_identifiers.verified).
    assert_eq!(
        email_verified(&harness, &subject, "owner@example.test").await,
        Some(true)
    );
    // Both the audit event AND the notification fired.
    assert_eq!(audit_count(&harness, "account.identity.link").await, 1);
    assert_eq!(sender.linked(), vec!["owner@example.test".to_owned()]);

    // A RETURNING login of the same federated identity resolves to the SAME local user and
    // never creates a second link or a separate account.
    let again = login(
        &harness,
        &mock,
        "fed-sub-1",
        json!({"email": "owner@example.test", "email_verified": true, "name": "Owner"}),
    )
    .await;
    assert_eq!(again, StatusCode::SEE_OTHER);
    assert_eq!(
        links_for(&harness, &subject).await.len(),
        1,
        "no second link on return"
    );
    assert!(provisioned(&harness, "fed-sub-1").await.is_none());
}

#[tokio::test]
async fn default_posture_off_provisions_a_separate_account_never_a_silent_merge() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    seed_connector(&harness, "trusted").await;
    // NO per-environment override: the environment inherits the deployment default (Off).

    let subject = subject_id(&harness, &harness.seed_user("owner-acct", "pw").await);
    add_email(&harness, &subject, "owner@example.test", true).await;

    let mock = start_mock().await;
    let status = login(
        &harness,
        &mock,
        "fed-sub-1",
        json!({"email": "owner@example.test", "email_verified": true, "name": "Owner"}),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    // Under the conservative default posture a federated login provisions its OWN separate
    // account and NEVER links into the pre-existing local account.
    assert!(
        links_for(&harness, &subject).await.is_empty(),
        "no link under posture Off"
    );
    assert!(
        provisioned(&harness, "fed-sub-1").await.is_some(),
        "posture Off provisions a separate federated account"
    );
}

// ===========================================================================
// Scenario (a): unverified pre-registration then victim social login.
// ===========================================================================

#[tokio::test]
async fn scenario_a_unverified_pre_registration_then_victim_social_login_never_links() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    seed_connector(&harness, "trusted").await;
    // Even the MOST permissive posture must not save the attacker: local_verified is false.
    set_env_posture(&harness, Some("verified_to_verified")).await;

    // The attacker pre-registers an UNVERIFIED local account with the victim's email.
    let attacker = subject_id(&harness, &harness.seed_user("attacker-acct", "pw").await);
    add_email(&harness, &attacker, "victim@example.test", false).await;

    // The victim social-logs-in with the same email, even asserting email_verified on a
    // TRUSTED connector.
    let mock = start_mock().await;
    let status = login(
        &harness,
        &mock,
        "victim-sub",
        json!({"email": "victim@example.test", "email_verified": true, "name": "Victim"}),
    )
    .await;

    // The login is NOT auto-linked into the attacker's pre-registered account: the
    // unverified-local cell is the manual interstitial (no session, no link, no provision).
    assert_eq!(
        status,
        StatusCode::OK,
        "the interstitial is shown, never a silent merge"
    );
    assert!(
        links_for(&harness, &attacker).await.is_empty(),
        "the victim identity must NOT link into the attacker's pre-registered account"
    );
    assert!(
        provisioned(&harness, "victim-sub").await.is_none(),
        "the interstitial provisions no account"
    );
    // The attacker's pre-registered email is still unverified: nothing about the victim login
    // touched it.
    assert_eq!(
        email_verified(&harness, &attacker, "victim@example.test").await,
        Some(false)
    );
}

// ===========================================================================
// Scenario (b) + (c): forged / untrusted email_verified never auto-links.
// ===========================================================================

#[tokio::test]
async fn scenario_b_forged_email_verified_from_untrusted_connector_never_auto_links() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    // The connector's capability matrix marks email_verified UNTRUSTED (the default).
    seed_connector(&harness, "untrusted").await;
    set_env_posture(&harness, Some("verified_to_verified")).await;

    // A genuinely VERIFIED local account.
    let owner = subject_id(&harness, &harness.seed_user("owner-acct", "pw").await);
    add_email(&harness, &owner, "owner@example.test", true).await;

    // The upstream FORGES email_verified = true, but the connector is untrusted (nOAuth).
    let mock = start_mock().await;
    let status = login(
        &harness,
        &mock,
        "attacker-sub",
        json!({"email": "owner@example.test", "email_verified": true, "name": "Owner"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an untrusted connector never auto-links"
    );
    assert!(
        links_for(&harness, &owner).await.is_empty(),
        "a forged email_verified from an untrusted connector must NOT auto-link"
    );
    assert!(provisioned(&harness, "attacker-sub").await.is_none());
}

#[tokio::test]
async fn scenario_c_trusted_connector_but_upstream_omits_email_verified_never_auto_links() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    seed_connector(&harness, "trusted").await;
    set_env_posture(&harness, Some("verified_to_verified")).await;

    let owner = subject_id(&harness, &harness.seed_user("owner-acct", "pw").await);
    add_email(&harness, &owner, "owner@example.test", true).await;

    // Trusted connector, verified local, but the upstream OMITS email_verified (U = false):
    // the missing-upstream-claim cell is the interstitial, never an auto-link.
    let mock = start_mock().await;
    let status = login(
        &harness,
        &mock,
        "attacker-sub",
        json!({"email": "owner@example.test", "name": "Owner"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a missing upstream email_verified never auto-links"
    );
    assert!(links_for(&harness, &owner).await.is_empty());
    assert!(provisioned(&harness, "attacker-sub").await.is_none());
}

// ===========================================================================
// Relay class (issue #78 dependency note + plan section 8): an Apple Hide My Email
// relay login NEVER auto-links across accounts, even all-green.
// ===========================================================================

#[tokio::test]
async fn relay_apple_hide_my_email_login_never_auto_links_into_a_victim() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    // A TRUSTED Apple-style connector with the Hide My Email relay quirk configured.
    seed_relay_connector(&harness).await;
    // The MOST permissive posture: only the relay-address non-match stops a merge.
    set_env_posture(&harness, Some("verified_to_verified")).await;

    // A genuine VERIFIED local victim whose real email an attacker would love to merge into.
    let victim = subject_id(&harness, &harness.seed_user("victim-acct", "pw").await);
    add_email(&harness, &victim, "victim@example.test", true).await;

    // An Apple login whose ONLY asserted email is a per-app Hide My Email relay alias, even
    // asserting email_verified on the trusted connector under the opt-in posture.
    let mock = start_mock().await;
    let relay = "abc123def@privaterelay.appleid.com";
    let status = login(
        &harness,
        &mock,
        "apple-relay-sub",
        json!({"email": relay, "email_verified": true, "name": "Relay User"}),
    )
    .await;

    // A relay alias matches NO verified local identifier (resolve_local_email_match yields no
    // verified user), so the all-green tuple is never formed: the login provisions its OWN
    // separate federated account and NEVER auto-links into the victim (never a silent merge).
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the relay login provisions a separate account and signs in as it"
    );
    assert!(
        links_for(&harness, &victim).await.is_empty(),
        "a relay login must NOT create a link binding the relay identity to the victim"
    );
    let separate = provisioned(&harness, "apple-relay-sub")
        .await
        .expect("the relay login provisions a SEPARATE federated account, never a merge");
    assert_ne!(
        separate, victim,
        "the separately provisioned account is NOT the victim (no silent re-home)"
    );
    // The separate federated account carries no account_links row into any local user, and the
    // session runs as that separate subject, never as the victim.
    assert!(
        links_for(&harness, &separate).await.is_empty(),
        "a separately provisioned relay account holds no link into a local user"
    );
}

// ===========================================================================
// Scenario (d): a manual link NEVER promotes the local verified flag.
// ===========================================================================

#[tokio::test]
async fn scenario_d_manual_link_never_promotes_the_local_verified_flag() {
    let mut harness = Harness::start().await;
    let sender = Arc::new(RecordingSender::default());
    harness.install_verification_sender(sender.clone());
    seed_trait_schema(&harness).await;
    seed_connector(&harness, "trusted").await;
    let connector = connector_id(&harness).await;

    // The account owner has a verified email (the notification channel). The manual link
    // binds a DIFFERENT federated address.
    let owner = subject_id(&harness, &harness.seed_user("owner-acct", "pw").await);
    add_email(&harness, &owner, "owner@example.test", true).await;

    // Seed a manual-link correlation row (as the fresh-re-auth-gated start leg would) that
    // targets the owner, then drive the callback with a matching nonce.
    let state = "link-state-d";
    let nonce = "link-nonce-d";
    let fls_id = FederationLoginStateId::generate(harness.env(), &harness.scope());
    let owner_str = owner.to_string();
    harness
        .store()
        .scoped(harness.scope())
        .federation_login_states()
        .create(
            harness.env(),
            &fls_id,
            NewFederationLoginState {
                state,
                nonce,
                code_verifier: b"",
                connector_id: &connector,
                return_to: "/authorize?client_id=x",
                org_connection_id: None,
                link_target_user_id: Some(&owner_str),
                expires_at_unix_micros: FAR_FUTURE_MICROS,
            },
        )
        .await
        .expect("seed link state");

    let mock = start_mock().await;
    *mock.oidc_token.lock().expect("lock") = token_body(&id_token(
        &mock.key,
        nonce,
        "fed-sub-d",
        json!({"email": "federated@other.test", "email_verified": true, "name": "Fed"}),
    ));
    let status = drive_callback(&harness, build_runtime(mock.addr), state).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the manual link completes and signs in"
    );

    // A manual link was created binding the federated identity to the owner.
    let links = links_for(&harness, &owner).await;
    assert_eq!(links.len(), 1, "one manual link");
    assert_eq!(links[0].link_method, AccountLinkMethod::Manual);

    // The link NEVER created or promoted a local verified identifier for the federated
    // address: the owner still has ONLY their original verified email.
    assert_eq!(
        email_verified(&harness, &owner, "federated@other.test").await,
        None,
        "linking must not add the federated address as a local verified identifier"
    );
    assert_eq!(
        email_verified(&harness, &owner, "owner@example.test").await,
        Some(true)
    );

    // Both the audit event AND the notification fired.
    assert_eq!(audit_count(&harness, "account.identity.link").await, 1);
    assert_eq!(sender.linked(), vec!["owner@example.test".to_owned()]);
}

// ===========================================================================
// Scenario (e): unlinking the last usable method is blocked with a typed error.
// ===========================================================================

async fn create_link(
    harness: &Harness,
    user: &UserId,
    connector: &str,
    external_id: &str,
) -> AccountLinkId {
    let env = harness.env().clone();
    let id = AccountLinkId::generate(&env, &harness.scope());
    harness
        .store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .account_links()
        .create(
            &env,
            &id,
            NewAccountLink {
                user_id: user,
                connector_id: connector,
                external_id,
                email_verified: true,
                link_method: AccountLinkMethod::AutoVerified,
            },
        )
        .await
        .expect("create link");
    id
}

#[tokio::test]
async fn scenario_e_unlinking_the_last_usable_method_is_blocked_and_both_orderings_hold() {
    let harness = Harness::start().await;
    let owner = subject_id(&harness, &harness.seed_user("owner-acct", "pw").await);
    let link = create_link(&harness, &owner, "cnr_test", "fed:1").await;

    let unlink = || async {
        harness
            .store()
            .scoped(harness.scope())
            .acting(
                harness.db().test_actor(harness.env()),
                CorrelationId::generate(harness.env()),
            )
            .account_links()
            .unlink(harness.env(), &owner, &link, "detail")
            .await
            .expect("unlink")
    };

    // Ordering 1: the account still has its password, so the link is NOT the last method and
    // unlinking a DIFFERENT surviving link would be allowed. Here the password survives, so
    // removing the password first is allowed (the link survives as a method).
    let removed = harness
        .store()
        .scoped(harness.scope())
        .acting(
            harness.db().test_actor(harness.env()),
            CorrelationId::generate(harness.env()),
        )
        .users()
        .remove_password(harness.env(), &owner, None, "detail")
        .await
        .expect("remove password");
    assert!(
        matches!(removed, PasswordRemovalOutcome::Removed(_)),
        "removing the password is allowed while the link survives as a method"
    );

    // Ordering 2: now the link is the SOLE surviving usable method. Unlinking it is REFUSED
    // with the typed anti-bricking outcome, and nothing is deleted.
    assert_eq!(unlink().await, UnlinkOutcome::BlockedLastMethod);
    assert_eq!(
        links_for(&harness, &owner).await.len(),
        1,
        "a blocked unlink deletes nothing"
    );

    // A second account keeps a usable method (a passkeyless password account with an extra
    // link): unlinking one of two links is allowed.
    let other = subject_id(&harness, &harness.seed_user("other-acct", "pw").await);
    let l1 = create_link(&harness, &other, "cnr_test", "fed:2").await;
    let _l2 = create_link(&harness, &other, "cnr_test", "fed:3").await;
    let removed_one = harness
        .store()
        .scoped(harness.scope())
        .acting(
            harness.db().test_actor(harness.env()),
            CorrelationId::generate(harness.env()),
        )
        .account_links()
        .unlink(harness.env(), &other, &l1, "detail")
        .await
        .expect("unlink one of many");
    assert_eq!(
        removed_one,
        UnlinkOutcome::Removed,
        "one of several methods can be unlinked"
    );
}

// ===========================================================================
// The self-service endpoints: fresh re-auth gate + unlink audit/notification.
// ===========================================================================

async fn post_account(
    app: Router,
    harness: &Harness,
    path: &str,
    cookie: Option<&str>,
    body: &Value,
) -> StatusCode {
    let scope = harness.scope();
    let uri = format!(
        "/t/{}/e/{}/account/{path}",
        scope.tenant(),
        scope.environment()
    );
    let mut builder = Request::builder()
        .method("POST")
        .uri(&uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    app.oneshot(builder.body(Body::from(body.to_string())).expect("req"))
        .await
        .expect("post")
        .status()
}

#[tokio::test]
async fn start_link_requires_a_fresh_reauth_of_the_target_account() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    seed_connector(&harness, "trusted").await;
    let mock = start_mock().await;

    let subject = harness.seed_user("owner-acct", "pw").await;

    // No session at all: unauthenticated.
    let status = post_account(
        router(&harness, build_runtime(mock.addr)),
        &harness,
        "linked-identities/start",
        None,
        &json!({"connector": SLUG}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no session is rejected");

    // A FRESH session (auth_time == now under the frozen clock) passes the gate and mints an
    // upstream authorize leg.
    let (_id, fresh) = harness.session_with_id(&subject, "pwd", 0).await;
    let status = post_account(
        router(&harness, build_runtime(mock.addr)),
        &harness,
        "linked-identities/start",
        Some(&fresh),
        &json!({"connector": SLUG}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a fresh re-auth is accepted and starts the link"
    );

    // Advance the clock past the link freshness window: the SAME session is now stale and is
    // refused. An active-but-stale session is never sufficient (the security crux).
    harness.clock().advance(Duration::from_secs(3600));
    let status = post_account(
        router(&harness, build_runtime(mock.addr)),
        &harness,
        "linked-identities/start",
        Some(&fresh),
        &json!({"connector": SLUG}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an active but STALE session must be refused (never just an active session)"
    );
}

#[tokio::test]
async fn remove_linked_identity_audits_and_notifies_and_the_last_method_guard_blocks() {
    let mut harness = Harness::start().await;
    let sender = Arc::new(RecordingSender::default());
    harness.install_verification_sender(sender.clone());

    // An account with a password AND a link (so the link is not the sole method), plus a
    // verified email for the notification channel.
    let subject = subject_id(&harness, &harness.seed_user("owner-acct", "pw").await);
    add_email(&harness, &subject, "owner@example.test", true).await;
    let link = create_link(&harness, &subject, "cnr_test", "fed:1").await;
    let (_id, cookie) = harness
        .session_with_id(&subject.to_string(), "pwd", 0)
        .await;

    let status = post_account(
        oidc_router(harness.state().clone()),
        &harness,
        "linked-identities/remove",
        Some(&cookie),
        &json!({"link_id": link.to_string()}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a fresh-re-auth-gated unlink succeeds"
    );
    assert!(
        links_for(&harness, &subject).await.is_empty(),
        "the link is removed"
    );
    // Both the audit event AND the notification fired.
    assert_eq!(audit_count(&harness, "account.identity.unlink").await, 1);
    assert_eq!(sender.unlinked(), vec!["owner@example.test".to_owned()]);

    // A sole-link account: the unlink endpoint returns the typed 409, nothing is deleted.
    let solo = subject_id(&harness, &harness.seed_user("solo-acct", "pw").await);
    let solo_link = create_link(&harness, &solo, "cnr_test", "fed:solo").await;
    // Remove the password so the link is the only usable method.
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            harness.db().test_actor(harness.env()),
            CorrelationId::generate(harness.env()),
        )
        .users()
        .remove_password(harness.env(), &solo, None, "detail")
        .await
        .expect("remove password");
    let (_sid, solo_cookie) = harness.session_with_id(&solo.to_string(), "pwd", 0).await;
    let status = post_account(
        oidc_router(harness.state().clone()),
        &harness,
        "linked-identities/remove",
        Some(&solo_cookie),
        &json!({"link_id": solo_link.to_string()}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "unlinking the last method is a typed 409"
    );
    assert_eq!(
        links_for(&harness, &solo).await.len(),
        1,
        "nothing was deleted"
    );
}

// ===========================================================================
// The legacy-handle fallback (epic #514): a user who predates `user_identifiers`.
// ===========================================================================

#[tokio::test]
async fn a_user_with_only_a_legacy_handle_is_found_and_reaches_the_interstitial_never_a_link() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    seed_connector(&harness, "trusted").await;
    set_env_posture(&harness, Some("verified_to_verified")).await;

    // A PRE-EXISTING user: their login handle lives in `users.identifier` and there is NO
    // `user_identifiers` row, which is every user who predates that surface. Note the
    // deliberate absence of an `add_email` call, which is the whole fixture.
    let legacy = subject_id(
        &harness,
        &harness.seed_user("legacy@example.test", "pw").await,
    );

    // The same person social-logs-in, on a TRUSTED connector asserting email_verified. Every
    // cell of the decision tuple is green EXCEPT the local verified state, which the legacy
    // handle cannot supply because no column records it.
    let mock = start_mock().await;
    let status = login(
        &harness,
        &mock,
        "legacy-sub",
        json!({"email": "legacy@example.test", "email_verified": true, "name": "Legacy"}),
    )
    .await;

    // Found, so the interstitial asks the human to prove they own both sides. Before the
    // fallback this answered "no local account" and PROVISIONED a duplicate, which is the
    // defect: a returning user quietly acquired a second account.
    assert_eq!(
        status,
        StatusCode::OK,
        "a legacy local match must reach the interstitial rather than provisioning a second \
         account for someone who already has one"
    );
    assert!(
        provisioned(&harness, "legacy-sub").await.is_none(),
        "the interstitial provisions nothing: a duplicate account is the defect this closes"
    );
    // And it must NEVER auto-link. The fallback contributes existence only, so the one arm
    // that auto-links is structurally unreachable through it: `users.identifier` has no
    // per-handle verified state, and asserting one would be inventing a verification.
    assert!(
        links_for(&harness, &legacy).await.is_empty(),
        "a legacy handle must never be treated as a VERIFIED local account"
    );
}

#[tokio::test]
async fn the_legacy_fallback_does_not_change_the_default_posture() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    seed_connector(&harness, "trusted").await;
    // Posture OFF is the conservative default, and the decision table's `(Off, ..)` arm
    // ignores the local match entirely. A deployment that has not opted in must therefore
    // see NO behaviour change from the fallback, which is what makes this safe to land
    // ahead of any backfill.
    set_env_posture(&harness, None).await;

    let legacy = subject_id(
        &harness,
        &harness.seed_user("legacy@example.test", "pw").await,
    );

    let mock = start_mock().await;
    let status = login(
        &harness,
        &mock,
        "legacy-sub",
        json!({"email": "legacy@example.test", "email_verified": true, "name": "Legacy"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "posture off completes the login"
    );
    assert!(
        provisioned(&harness, "legacy-sub").await.is_some(),
        "under posture off a federated identity still provisions its own separate account, \
         exactly as before the fallback existed"
    );
    assert!(
        links_for(&harness, &legacy).await.is_empty(),
        "and it is still not linked into the local account"
    );
}

#[tokio::test]
async fn a_flexible_identifier_still_wins_and_can_still_auto_link() {
    let harness = Harness::start().await;
    seed_trait_schema(&harness).await;
    seed_connector(&harness, "trusted").await;
    set_env_posture(&harness, Some("verified_to_verified")).await;

    // This user has BOTH a legacy handle and a VERIFIED flexible identifier. The flexible
    // table is authoritative and is consulted first, so the auto-link path is unchanged: the
    // fallback must not shadow a verified match and turn an auto-link into an interstitial.
    let user = subject_id(
        &harness,
        &harness.seed_user("both@example.test", "pw").await,
    );
    add_email(&harness, &user, "both@example.test", true).await;

    let mock = start_mock().await;
    let status = login(
        &harness,
        &mock,
        "both-sub",
        json!({"email": "both@example.test", "email_verified": true, "name": "Both"}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the auto-link establishes a session"
    );
    assert_eq!(
        links_for(&harness, &user).await.len(),
        1,
        "a VERIFIED flexible identifier still auto-links; the legacy fallback must not \
         shadow it into the interstitial"
    );
}
