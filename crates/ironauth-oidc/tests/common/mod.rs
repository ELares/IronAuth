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
use ironauth_oidc::{ClientAuthMethod, OidcState, SESSION_COOKIE, oidc_router};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ClientId, CorrelationId, Scope, SessionId, Store};
use tower::ServiceExt;

/// The RFC 7636 Appendix B PKCE verifier and its S256 challenge.
pub const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// The S256 challenge for [`PKCE_VERIFIER`].
pub const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// A syntactically valid redirect URI the tests bind codes to.
pub const REDIRECT_URI: &str = "https://client.test/cb";
/// The issuer base the harness configures.
pub const ISSUER_BASE: &str = "https://issuer.test";
/// A far-future expiry (year 2100) in epoch microseconds, so a seeded session
/// survives the clock advances the expiry and reuse tests perform.
pub const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;
/// The password the seeded harness users are created with.
pub const SEED_PASSWORD: &str = "correct horse battery staple";

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
    ///
    /// The default harness relaxes the confidential-client PKCE policy
    /// (`require_pkce_for_confidential_clients = false`, issue #13) so the
    /// client-authentication and interop tests can drive a confidential client
    /// through the token exchange WITHOUT PKCE (they exercise client auth, not
    /// PKCE). A PUBLIC client still always requires PKCE, so the public-client
    /// flows include a `code_challenge`. Tests that want the production default
    /// (PKCE required for confidential clients too) build the config explicitly and
    /// call [`Harness::start_with`].
    pub async fn start() -> Self {
        Self::start_with(OidcConfig {
            require_pkce_for_confidential_clients: false,
            ..OidcConfig::default()
        })
        .await
    }

    /// Like [`Harness::start`] but with explicit OIDC settings (for the expiry
    /// test, which wants a short code lifetime).
    pub async fn start_with(config: OidcConfig) -> Self {
        let db = TestDatabase::start().await;
        let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0D1C_5EED);
        let scope = db.seed_scope(&env).await;

        // One OAuth client in scope (the authorization endpoint validates it),
        // with the harness redirect URI registered so the exact-string redirect
        // match (issue #13) accepts it.
        let client_id = db
            .store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
            .create(&env, "oidc test client")
            .await
            .expect("create client");
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
            .register_redirect_uris(&env, &client_id, &[REDIRECT_URI])
            .await
            .expect("register redirect uri");

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
        self.token_with_auth(form, None).await
    }

    /// `POST /token` with an optional `Authorization` header (for
    /// `client_secret_basic`).
    pub async fn token_with_auth(
        &self,
        form: &str,
        authorization: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(value) = authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        let request = builder
            .body(Body::from(form.to_owned()))
            .expect("request builds");
        self.send(request).await
    }

    /// `GET /authorize` with a session cookie, so a request from an authenticated,
    /// consenting subject proceeds straight to issuing the code.
    pub async fn authorize_with_cookie(
        &self,
        query: &str,
        cookie: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("GET")
            .uri(format!("/authorize?{query}"))
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("request builds");
        self.send(request).await
    }

    /// `GET` any path with a session cookie (used to follow the interaction
    /// redirects in the end-to-end test).
    pub async fn get_with_cookie(
        &self,
        path: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut builder = Request::builder().method("GET").uri(path);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        self.send(builder.body(Body::empty()).expect("request builds"))
            .await
    }

    /// `POST` a form to `path` with an optional session cookie (used to submit the
    /// login, registration, and consent forms in the end-to-end test).
    pub async fn post_form(
        &self,
        path: &str,
        form: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        self.send(
            builder
                .body(Body::from(form.to_owned()))
                .expect("request builds"),
        )
        .await
    }

    /// A throwaway acting context for direct store seeding.
    fn seeding_actor(&self) -> (ironauth_store::ActorRef, CorrelationId) {
        (
            self.db.test_actor(&self.env),
            CorrelationId::generate(&self.env),
        )
    }

    /// Register a bootstrap user in the harness scope and return its subject (the
    /// `usr_` id string).
    pub async fn seed_user(&self, identifier: &str, password: &str) -> String {
        let hash = ironauth_oidc::hash_password(&self.env, password).expect("hash password");
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .users()
            .register(&self.env, identifier, &hash)
            .await
            .expect("register user")
            .to_string()
    }

    /// Seed a fresh user with a unique identifier (drawn from the deterministic
    /// entropy stream, which advances per call) and return its subject.
    pub async fn seed_unique_user(&self) -> String {
        use std::fmt::Write as _;
        let mut suffix = [0_u8; 8];
        self.env.entropy().fill_bytes(&mut suffix);
        let id = suffix.iter().fold(String::new(), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        });
        self.seed_user(&format!("user-{id}@example.test"), SEED_PASSWORD)
            .await
    }

    /// Record `subject`'s consent to `client_id` in the harness scope.
    pub async fn grant_consent(&self, subject: &str, client_id: &str) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .consents()
            .grant(&self.env, subject, client_id, None)
            .await
            .expect("grant consent");
    }

    /// Create a session for `subject` (a bootstrap `pwd` authentication event at
    /// the epoch) and return the `Cookie` header value. The session is far-future
    /// so it survives the clock advances in the expiry and reuse tests.
    pub async fn session_cookie(&self, subject: &str) -> String {
        self.session_cookie_at(subject, "pwd", 0).await
    }

    /// Like [`Harness::session_cookie`] but with an explicit `auth_methods` and
    /// recorded `auth_time` (epoch microseconds), so the ID-token claim tests can
    /// pin the authentication event a token derives its `auth_time`/`amr`/`acr`
    /// from.
    pub async fn session_cookie_at(
        &self,
        subject: &str,
        auth_methods: &str,
        auth_time_micros: i64,
    ) -> String {
        let session_id = SessionId::generate(&self.env, &self.scope);
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .sessions()
            .create(
                &self.env,
                &session_id,
                subject,
                auth_methods,
                auth_time_micros,
                FAR_FUTURE_MICROS,
            )
            .await
            .expect("create session");
        format!("{SESSION_COOKIE}={session_id}")
    }

    /// A ready authenticated `Cookie` value for the harness client: seeds a fresh
    /// user, records consent to the harness client, and returns the cookie. Each
    /// call is independent (a distinct user), so it can be used per code issuance.
    pub async fn authenticated_cookie(&self) -> String {
        self.authenticated_cookie_for(&self.client_id.to_string())
            .await
    }

    /// A ready authenticated `Cookie` value for an arbitrary `client_id`: seeds a
    /// fresh user, records consent to that client, and returns the cookie. Used by
    /// the ID-token claim tests that drive a purpose-built client (for example one
    /// that registered `require_auth_time`).
    pub async fn authenticated_cookie_for(&self, client_id: &str) -> String {
        let subject = self.seed_unique_user().await;
        self.grant_consent(&subject, client_id).await;
        self.session_cookie(&subject).await
    }

    /// Create a PUBLIC client that registered `require_auth_time` (issue #14), so
    /// its ID tokens carry `auth_time` even without a `max_age` request. Returns
    /// its id.
    pub async fn create_client_requiring_auth_time(&self) -> ClientId {
        let (actor, corr) = self.seeding_actor();
        let id = self
            .store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .create_requiring_auth_time(&self.env, "require-auth-time client")
            .await
            .expect("create require_auth_time client");
        self.register_default_redirect(&id).await;
        id
    }

    /// Create a PUBLIC client (`token_endpoint_auth_method` = none) and register
    /// `redirect_uris` for it, returning its id. Used by the redirect-matching and
    /// native-app tests to register loopback and private-use-scheme redirects.
    pub async fn create_public_client_with_redirects(
        &self,
        display_name: &str,
        redirect_uris: &[&str],
    ) -> ClientId {
        let (actor, corr) = self.seeding_actor();
        let id = self
            .store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .create(&self.env, display_name)
            .await
            .expect("create public client");
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .register_redirect_uris(&self.env, &id, redirect_uris)
            .await
            .expect("register redirect uris");
        id
    }

    /// Register the harness redirect URI for `client_id`, so the authorization
    /// endpoint's exact-string redirect match (issue #13) accepts it.
    pub async fn register_default_redirect(&self, client_id: &ClientId) {
        let (actor, corr) = self.seeding_actor();
        self.store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .register_redirect_uris(&self.env, client_id, &[REDIRECT_URI])
            .await
            .expect("register redirect uri");
    }

    /// Issue an `authorization_code` bound to `client_id` for a fresh consenting
    /// subject (no PKCE, so the exchange only has to satisfy client
    /// authentication and the `redirect_uri` binding), returning the raw code.
    /// Used by the interop test to drive a mainstream OAuth client through the
    /// token exchange.
    pub async fn issue_authenticated_code(&self, client_id: &str) -> String {
        let subject = self.seed_unique_user().await;
        self.grant_consent(&subject, client_id).await;
        let cookie = self.session_cookie(&subject).await;
        let query = format!(
            "response_type=code&client_id={client_id}&redirect_uri={}",
            enc(REDIRECT_URI)
        );
        let (status, headers, body) = self.authorize_with_cookie(&query, &cookie).await;
        assert_eq!(status, StatusCode::FOUND, "authorize: {body}");
        location_param(&headers, "code").expect("code in redirect")
    }

    /// Create a CONFIDENTIAL client registered for `method`, returning its id and
    /// the plaintext secret (shown once).
    pub async fn create_confidential_client(&self, method: ClientAuthMethod) -> (ClientId, String) {
        self.create_confidential_client_named(method, "confidential client")
            .await
    }

    /// Like [`Harness::create_confidential_client`] but with an explicit display
    /// name (used to prove the consent screen escapes a hostile client name).
    pub async fn create_confidential_client_named(
        &self,
        method: ClientAuthMethod,
        display_name: &str,
    ) -> (ClientId, String) {
        let secret = ironauth_oidc::generate_secret(&self.env);
        let secret_hash = ironauth_oidc::hash_secret(&secret);
        let (actor, corr) = self.seeding_actor();
        let id = self
            .store()
            .scoped(self.scope)
            .acting(actor, corr)
            .clients()
            .create_confidential(&self.env, display_name, method.as_str(), &secret_hash)
            .await
            .expect("create confidential client");
        self.register_default_redirect(&id).await;
        (id, secret)
    }

    /// Issue an `authorization_code` bound to `client_id` WITH PKCE (the RFC 7636
    /// Appendix B S256 challenge), for a fresh consenting subject, returning the
    /// raw code. Used where the target client requires PKCE (a public client always
    /// does): the caller redeems it with [`PKCE_VERIFIER`], or exercises a failure
    /// that trips before the PKCE check.
    pub async fn issue_authenticated_code_pkce(&self, client_id: &str) -> String {
        let subject = self.seed_unique_user().await;
        self.grant_consent(&subject, client_id).await;
        let cookie = self.session_cookie(&subject).await;
        let query = format!(
            "response_type=code&client_id={client_id}&redirect_uri={}&\
             code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
            enc(REDIRECT_URI)
        );
        let (status, headers, body) = self.authorize_with_cookie(&query, &cookie).await;
        assert_eq!(status, StatusCode::FOUND, "authorize: {body}");
        location_param(&headers, "code").expect("code in redirect")
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

/// The `Location` header value (a path or URL), if present.
#[must_use]
pub fn location(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::LOCATION)?
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// The `name=value` pair from a `Set-Cookie` header (dropping the attributes),
/// ready to be echoed back as a `Cookie` header value.
#[must_use]
pub fn set_cookie_pair(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::SET_COOKIE)?.to_str().ok()?;
    Some(value.split(';').next()?.trim().to_owned())
}

/// Extract the value of a form input by `name` from a rendered HTML page. Used by
/// the end-to-end test to genuinely round-trip the hidden `return_to` field
/// through the login/registration/consent forms rather than shortcutting it.
#[must_use]
pub fn form_field(html: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{name}\"");
    let start = html.find(&needle)?;
    let value_marker = "value=\"";
    let after = &html[start..];
    let value_start = after.find(value_marker)? + value_marker.len();
    let value = &after[value_start..];
    let end = value.find('"')?;
    Some(html_unescape(&value[..end]))
}

/// Reverse the small set of HTML entities the page escaper emits, so a value read
/// back out of a rendered form matches what was put in.
#[must_use]
pub fn html_unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&amp;", "&")
}
