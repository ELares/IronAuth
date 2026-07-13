// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared harness for the OIDC provider integration tests.
//!
//! Brings up a real database (via the ironauth-store test harness), seeds a
//! `(tenant, environment)` scope with one OAuth client, provisions an Ed25519
//! signing key for the environment, builds the OIDC router over a data-plane
//! store, and drives requests through it. Not every helper is used by every test
//! binary, so dead code is allowed here.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use ironauth_config::OidcConfig;
use ironauth_env::{Env, ManualClock};
use ironauth_jose::{
    EnvironmentKeyStore, JwsAlgorithm, SigningKey, TrustedKey, VerificationPolicy,
};
use ironauth_oidc::{OidcState, oidc_router};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ClientId, CorrelationId, Scope, Store};
use tower::ServiceExt;

/// The RFC 7636 Appendix B PKCE verifier and its S256 challenge.
pub const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// The S256 challenge for [`PKCE_VERIFIER`].
pub const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// A syntactically valid redirect URI the tests bind codes to.
pub const REDIRECT_URI: &str = "https://client.test/cb";
/// The issuer base the harness configures.
pub const ISSUER_BASE: &str = "https://issuer.test";

/// A running OIDC provider over a fresh database.
pub struct Harness {
    // Held so the database and its pools outlive the router.
    db: TestDatabase,
    env: Env,
    clock: Arc<ManualClock>,
    scope: Scope,
    client_id: ClientId,
    verifying_key: TrustedKey,
    issuer: String,
    router: Router,
}

impl Harness {
    /// Start a fresh database, seed a scope and a client, provision a signing
    /// key, and build the OIDC router. Uses a deterministic clock frozen at the
    /// Unix epoch so token lifetimes and code expiry are driven explicitly.
    pub async fn start() -> Self {
        Self::start_with(OidcConfig::default()).await
    }

    /// Like [`Harness::start`] but with explicit OIDC settings (for the expiry
    /// test, which wants a short code lifetime).
    pub async fn start_with(config: OidcConfig) -> Self {
        let db = TestDatabase::start().await;
        let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0D1C_5EED);
        let scope = db.seed_scope(&env).await;

        // One OAuth client in scope (the authorization endpoint validates it).
        let client_id = db
            .store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
            .create(&env, "oidc test client")
            .await
            .expect("create client");

        // One Ed25519 signing key for the environment.
        let signing_key =
            SigningKey::generate_ed25519(Some("k1".to_owned()), env.entropy()).expect("gen key");
        let verifying_key = signing_key.verifying_key().expect("verifying key");
        let mut keys = EnvironmentKeyStore::new();
        keys.insert(scope.environment(), signing_key);

        let state = OidcState::new(db.store().clone(), env.clone(), keys, &config, ISSUER_BASE);
        let issuer = state.issuer_for(&scope);
        let router = oidc_router(state);

        Self {
            db,
            env,
            clock,
            scope,
            client_id,
            verifying_key,
            issuer,
            router,
        }
    }

    /// The data-plane store behind the router, for verifying audit rows and token
    /// status.
    #[must_use]
    pub fn store(&self) -> &Store {
        self.db.store()
    }

    /// The seeded scope.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The seeded client identifier (its string is the `client_id`).
    #[must_use]
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// The environment seam (for minting cross-scope test data).
    #[must_use]
    pub fn env(&self) -> &Env {
        &self.env
    }

    /// Seed a second environment of the SAME tenant and return a scope over it,
    /// for cross-environment isolation tests.
    pub async fn second_scope(&self) -> Scope {
        let environment = self
            .db
            .seed_environment(&self.env, self.scope.tenant())
            .await;
        Scope::new(self.scope.tenant(), environment)
    }

    /// The manual clock handle, for advancing time in the expiry test.
    #[must_use]
    pub fn clock(&self) -> &Arc<ManualClock> {
        &self.clock
    }

    /// The per-environment issuer the tokens carry.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// A clone of the router (concurrent race test clones it per task).
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// A verification policy that trusts the environment's public key and expects
    /// the harness issuer and the given audience.
    #[must_use]
    pub fn policy(&self, audience: &str) -> VerificationPolicy {
        VerificationPolicy::new(
            vec![JwsAlgorithm::EdDsa],
            vec![self.verifying_key.clone()],
            self.issuer.clone(),
            audience.to_owned(),
        )
        .expect("policy builds")
    }

    /// Drive one request through the router.
    pub async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
        send_through(self.router.clone(), request).await
    }

    /// `GET /authorize` with a pre-built query string (already encoded).
    pub async fn authorize(&self, query: &str) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("GET")
            .uri(format!("/authorize?{query}"))
            .body(Body::empty())
            .expect("request builds");
        self.send(request).await
    }

    /// `POST /token` with a pre-built form body (already encoded).
    pub async fn token(&self, form: &str) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form.to_owned()))
            .expect("request builds");
        self.send(request).await
    }
}

/// A clock at the token's issuance time (the frozen epoch), for verification.
#[must_use]
pub fn verify_clock() -> ManualClock {
    ManualClock::new(SystemTime::UNIX_EPOCH)
}

/// Drive one request through a router, returning status, headers, and body.
pub async fn send_through(
    router: Router,
    request: Request<Body>,
) -> (StatusCode, HeaderMap, String) {
    let response = router.oneshot(request).await.expect("router is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Percent-encode a query/form value (unreserved characters pass through).
#[must_use]
pub fn enc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
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

/// Build an `x-www-form-urlencoded` string from key/value pairs (values encoded).
#[must_use]
pub fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Read a query parameter from a `Location` header value (percent-decoding it).
#[must_use]
pub fn location_param(headers: &HeaderMap, name: &str) -> Option<String> {
    let location = headers.get(header::LOCATION)?.to_str().ok()?;
    let query = location.split_once('?').map_or("", |(_, q)| q);
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == name {
                return Some(percent_decode(value));
            }
        }
    }
    None
}

/// Minimal percent-decoding for reading redirect query values back.
#[must_use]
pub fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the JSON body of a token response and return `(field lookups)`.
#[must_use]
pub fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).expect("response body is JSON")
}
