// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared harness for the management-API integration tests.
//!
//! Brings up a real database (via the ironauth-store test harness), builds the
//! management router over a control-plane store, and drives requests through it.
//! Not every helper is used by every test binary, so dead code is allowed here.
#![allow(dead_code)]

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use ironauth_admin::{AdminState, management_router};
use ironauth_config::{AdminConfig, Secret, SecretString};
use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    AuthorizationCodeId, ClientId, CorrelationId, GrantId, IssueCode, NewDynamicClient,
    NewRefreshFamily, NewSession, RefreshFamilyId, RefreshTokenId, Scope, SessionId, Store, UserId,
    refresh_token_digest,
};
use tower::ServiceExt;

/// The bootstrap operator token the harness configures.
pub const OPERATOR_TOKEN: &str = "test-bootstrap-operator-token";

/// A far-future expiry (year 2100) in epoch microseconds: a seeded session or family
/// whose lifetime can never elapse during a test, so a resource that stops resolving
/// can only have been revoked.
pub const FAR_FUTURE_MICROS: i64 = 4_102_444_800_000_000;

/// A running management API over a fresh database.
pub struct Harness {
    // Held so the database and its pools outlive the router.
    db: TestDatabase,
    router: Router,
    // The (tenant, environment) the OUTBOUND verification endpoint was configured for
    // (issue #58), when built through `start_with_outbound_verification`. The endpoint
    // is bound to exactly this scope; a request to any other scope is a uniform 404.
    outbound_scope: Option<Scope>,
}

impl Harness {
    /// Start a fresh database and build the management router.
    ///
    /// `default_page_size` sets the page size used when a request omits `limit`.
    pub async fn start(default_page_size: u32) -> Self {
        Self::start_with_regions(default_page_size, Vec::new()).await
    }

    /// Start a fresh database and router with a configured data-residency region set
    /// (issue #46), for the tenant-lifecycle residency tests. An empty set (the
    /// default via [`Harness::start`]) leaves residency pinning unavailable.
    pub async fn start_with_regions(default_page_size: u32, allowed_regions: Vec<String>) -> Self {
        let db = TestDatabase::start().await;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size,
            allowed_regions,
            ..AdminConfig::default()
        };
        let state = AdminState::new(db.control_store().clone(), Env::system(), &config)
            .expect("admin state builds");
        let router = management_router(state);
        Self {
            db,
            router,
            outbound_scope: None,
        }
    }

    /// Start a fresh database and router with the experimental signup fraud-review-queue
    /// surface ARMED (issue #82, PR 2), so the review-queue endpoints answer instead of 404.
    /// `armed = false` leaves the feature off (its default), so a test can assert the
    /// endpoints 404 with the flag off.
    pub async fn start_with_signup_quarantine(default_page_size: u32, armed: bool) -> Self {
        let db = TestDatabase::start().await;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size,
            ..AdminConfig::default()
        };
        let state = AdminState::new(db.control_store().clone(), Env::system(), &config)
            .expect("admin state builds")
            .with_signup_quarantine_enabled(armed);
        let router = management_router(state);
        Self {
            db,
            router,
            outbound_scope: None,
        }
    }

    /// Start a fresh database and router with the experimental advanced-recovery-modes surface
    /// ARMED (issue #82, PR 3), so the recovery-approval review-queue endpoints answer instead
    /// of 404. `armed = false` leaves the feature off (its default), so a test can assert the
    /// endpoints 404 with the flag off.
    pub async fn start_with_advanced_recovery(default_page_size: u32, armed: bool) -> Self {
        let db = TestDatabase::start().await;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size,
            ..AdminConfig::default()
        };
        let state = AdminState::new(db.control_store().clone(), Env::system(), &config)
            .expect("admin state builds")
            .with_advanced_recovery_enabled(armed);
        let router = management_router(state);
        Self {
            db,
            router,
            outbound_scope: None,
        }
    }

    /// Start a fresh database and router with admin SUDO MODE enabled (issue #73) and a
    /// DETERMINISTIC clock, so a test can drive the freshness lifecycle by advancing the
    /// returned [`ironauth_env::ManualClock`]. `window_secs` is the re-authentication
    /// freshness window. The router's `AdminState` is built over the returned manual
    /// clock, so both an elevation's recorded instant and the guard's `now` move only
    /// when the test advances it. Setup helpers that go through non-environment-scoped
    /// operator-plane routes (create tenant / environment) are ungated, so they still
    /// work; the environment-scoped mutation guard is what the test exercises.
    pub async fn start_with_sudo(
        window_secs: u64,
    ) -> (Self, std::sync::Arc<ironauth_env::ManualClock>) {
        let db = TestDatabase::start().await;
        // A fixed, non-zero epoch start so recorded instants are plausible timestamps.
        let start = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let (env, clock) = Env::deterministic(start, 73);
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size: 50,
            sudo_mode_enabled: true,
            sudo_mode_window_secs: window_secs,
            ..AdminConfig::default()
        };
        let state =
            AdminState::new(db.control_store().clone(), env, &config).expect("admin state builds");
        let router = management_router(state);
        (
            Self {
                db,
                router,
                outbound_scope: None,
            },
            clock,
        )
    }

    /// Start a fresh database and router with the OUTBOUND lazy-migration
    /// credential-verification endpoint enabled, its shared token set, and BOUND to a
    /// freshly seeded `(tenant, environment)` scope (issue #58). `token` is the bearer
    /// a successor system presents; `None` leaves the endpoint enabled but
    /// unauthorized (fail-closed testing). The endpoint is authorized for exactly the
    /// returned [`Harness::outbound_scope`]; a request to any other scope is a uniform
    /// 404. Callers seed users into `outbound_scope`.
    pub async fn start_with_outbound_verification(token: Option<&str>) -> Self {
        let db = TestDatabase::start().await;
        // Seed the authorized scope BEFORE building the state, so the outbound
        // verification can be pinned to it (the endpoint is scope-bound, not global).
        let scope = db.seed_scope(&Env::system()).await;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size: 50,
            outbound_verification_enabled: true,
            outbound_verification_token: token
                .map(|value| Secret::Literal(SecretString::new(value))),
            outbound_verification_tenant: Some(scope.tenant().to_string()),
            outbound_verification_environment: Some(scope.environment().to_string()),
            ..AdminConfig::default()
        };
        let state = AdminState::new(db.control_store().clone(), Env::system(), &config)
            .expect("admin state builds");
        let router = management_router(state);
        Self {
            db,
            router,
            outbound_scope: Some(scope),
        }
    }

    /// Start a fresh database and router with a federation runtime installed (issue #76),
    /// so the per-connector health-diagnostics read reports the SAME in-memory health the
    /// caller records into `runtime.health()`.
    pub async fn start_with_federation(
        default_page_size: u32,
        runtime: std::sync::Arc<ironauth_oidc::FederationRuntime>,
    ) -> Self {
        let db = TestDatabase::start().await;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size,
            ..AdminConfig::default()
        };
        let state = AdminState::new(db.control_store().clone(), Env::system(), &config)
            .expect("admin state builds")
            .with_federation(runtime);
        let router = management_router(state);
        Self {
            db,
            router,
            outbound_scope: None,
        }
    }

    /// The `(tenant, environment)` the OUTBOUND verification endpoint was configured
    /// for (issue #58). Panics if the harness was not built through
    /// [`Harness::start_with_outbound_verification`].
    #[must_use]
    pub fn outbound_scope(&self) -> Scope {
        self.outbound_scope
            .expect("harness built with outbound verification")
    }

    /// The control-plane store behind the router, for verifying audit rows.
    #[must_use]
    pub fn control_store(&self) -> &Store {
        self.db.control_store()
    }

    /// The data-plane store behind the router, for seeding data-plane rows.
    #[must_use]
    pub fn store(&self) -> &Store {
        self.db.store()
    }

    /// The underlying test database, for a full superuser store snapshot (the flow inspector
    /// zero side effect proof snapshots every table's row count before and after a dry run).
    #[must_use]
    pub fn db(&self) -> &TestDatabase {
        &self.db
    }

    /// A stable test audit actor, for seeding rows through an acting repository.
    #[must_use]
    pub fn test_actor(&self, env: &Env) -> ironauth_store::ActorRef {
        self.db.test_actor(env)
    }

    /// A fresh data-plane scope (tenant + environment), for seeding a data-plane row
    /// (a DCR client) the management plane then reads or verifies.
    pub async fn seed_scope(&self) -> Scope {
        self.db.seed_scope(&Env::system()).await
    }

    /// Seed a QUARANTINED dynamically-registered client in `scope` via the app-role
    /// store and return its id (issue #31). The management plane cannot itself register
    /// a client (the control role holds no INSERT on `clients`), so a verify/get test
    /// seeds one through the app role exactly as the OIDC data plane would, then drives
    /// the management verify/get against it.
    pub async fn seed_quarantined_dcr_client(&self, scope: Scope) -> ClientId {
        let env = Env::system();
        let redirects = vec!["https://rp.example/cb".to_owned()];
        let token_hash = "0".repeat(64);
        self.db
            .store()
            .scoped(scope)
            .acting(self.db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
            .register_dynamic(
                &env,
                NewDynamicClient {
                    display_name: "seeded dcr client",
                    auth_method: "none",
                    secret_hash: None,
                    redirect_uris: &redirects,
                    application_type: "web",
                    id_token_signed_response_alg: "EdDSA",
                    jwks: None,
                    jwks_uri: None,
                    token_endpoint_auth_signing_alg: None,
                    registration_access_token_hash: &token_hash,
                    registration_uri_base: "https://issuer.test/connect/register",
                    quarantined: true,
                    dcr_policy_chain: None,
                },
                None,
            )
            .await
            .expect("seed dcr client")
            .id
    }

    /// Seed a LIVE session in `scope` for `subject` through the app-role store, exactly
    /// as an interactive login would (issue #32), and return its id. The management
    /// plane can read and revoke a session but never create one (the control role holds
    /// no INSERT on `sessions`), so the fleet-ops tests seed through the data plane.
    ///
    /// The lifetime runs to the year 2100, so a session that stops resolving in a test
    /// can only have been REVOKED, never merely expired.
    pub async fn seed_session(&self, scope: Scope, subject: &str) -> SessionId {
        let env = Env::system();
        let id = SessionId::generate(&env, &scope);
        self.db
            .store()
            .scoped(scope)
            .acting(self.db.test_actor(&env), CorrelationId::generate(&env))
            .sessions()
            .rotate(
                &env,
                &id,
                None,
                NewSession {
                    subject,
                    auth_methods: "pwd",
                    auth_time_micros: 0,
                    idle_expires_micros: FAR_FUTURE_MICROS,
                    absolute_expires_micros: FAR_FUTURE_MICROS,
                    user_agent: None,
                    peer_ip: None,
                },
            )
            .await
            .expect("seed session");
        id
    }

    /// Whether `session` still RESOLVES on the authentication read path (issue #32).
    /// This is the property a revoke must flip immediately.
    pub async fn session_resolves(&self, scope: Scope, session: &SessionId) -> bool {
        self.db
            .store()
            .scoped(scope)
            .sessions()
            .get(session, 0, 0)
            .await
            .expect("read session")
            .is_some()
    }

    /// Seed a refresh-token family bound to `session` (session bound or
    /// `offline_access`), through the app-role store, and return its id.
    pub async fn seed_refresh_family(
        &self,
        scope: Scope,
        subject: &str,
        client_id: &str,
        session: &SessionId,
        offline: bool,
    ) -> RefreshFamilyId {
        let env = Env::system();
        let code_id = AuthorizationCodeId::generate(&env, &scope);
        let grant_id = GrantId::generate(&env, &scope);
        let session_text = session.to_string();
        let client = ClientId::generate(&env, &scope);
        self.db
            .store()
            .scoped(scope)
            .acting(self.db.test_actor(&env), CorrelationId::generate(&env))
            .authorization()
            .issue(
                &env,
                IssueCode {
                    code_id: &code_id,
                    grant_id: &grant_id,
                    client_id: &client,
                    redirect_uri: "https://rp.example/cb",
                    browserless: false,
                    nonce: None,
                    code_challenge: None,
                    code_challenge_method: None,
                    subject,
                    oauth_scope: Some("openid"),
                    auth_methods: "pwd",
                    auth_time_micros: None,
                    session_ref: Some(&session_text),
                    consent_ref: None,
                    claims_request: None,
                    granted_resources: &[],
                    expires_at_micros: FAR_FUTURE_MICROS,
                    created_at_micros: 0,
                },
            )
            .await
            .expect("seed grant");

        let family_id = RefreshFamilyId::generate(&env, &scope);
        let jti = RefreshTokenId::generate(&env, &scope);
        let digest = refresh_token_digest(&format!("ira_rt_{jti}~seed"));
        self.db
            .store()
            .scoped(scope)
            .acting(self.db.test_actor(&env), CorrelationId::generate(&env))
            .refresh()
            .issue(
                &env,
                NewRefreshFamily {
                    family_id: &family_id,
                    token_jti: &jti,
                    token_digest: &digest,
                    grant_id: &grant_id,
                    subject,
                    client_id,
                    scope: Some("openid"),
                    auth_methods: "pwd",
                    auth_time_unix_micros: None,
                    offline,
                    created_at_unix_micros: 0,
                    idle_expires_at_unix_micros: FAR_FUTURE_MICROS,
                    absolute_expires_at_unix_micros: FAR_FUTURE_MICROS,
                },
            )
            .await
            .expect("seed refresh family");
        family_id
    }

    /// A freshly generated, in-scope user id (never inserted; `sessions.subject` is a
    /// text column, so no user row is needed to model a session's subject).
    #[must_use]
    pub fn fresh_user_id(scope: Scope) -> UserId {
        UserId::generate(&Env::system(), &scope)
    }

    /// A freshly generated, in-scope client id that is NOT inserted, for the
    /// anti-oracle not-found probes (it parses in scope but resolves to no client).
    #[must_use]
    pub fn fresh_client_id(scope: Scope) -> String {
        ClientId::generate(&Env::system(), &scope).to_string()
    }

    /// Drive one request through the router, returning status, headers, and body.
    pub async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router is infallible");
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

    /// An authenticated GET with the operator token.
    pub async fn get(&self, path: &str) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
            .body(Body::empty())
            .expect("request builds");
        self.send(request).await
    }

    /// An authenticated GET with an arbitrary bearer token (for wrong-scope tests).
    pub async fn get_as(&self, path: &str, token: &str) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header(header::AUTHORIZATION, bearer(token))
            .body(Body::empty())
            .expect("request builds");
        self.send(request).await
    }

    /// An authenticated operator POST with an Idempotency-Key and JSON body.
    pub async fn post(
        &self,
        path: &str,
        idempotency_key: &str,
        body: &str,
    ) -> (StatusCode, HeaderMap, String) {
        self.post_as(path, OPERATOR_TOKEN, idempotency_key, body)
            .await
    }

    /// A POST with an arbitrary bearer token.
    pub async fn post_as(
        &self,
        path: &str,
        token: &str,
        idempotency_key: &str,
        body: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::AUTHORIZATION, bearer(token))
            .header("idempotency-key", idempotency_key)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request builds");
        self.send(request).await
    }

    /// A POST carrying NO Authorization header, for the enablement-gate-before-bearer
    /// test (issue #58): a disabled endpoint must be a uniform 404 even to an
    /// unauthenticated probe, never a 401 that reveals the route exists.
    pub async fn post_unauthenticated(
        &self,
        path: &str,
        body: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request builds");
        self.send(request).await
    }

    /// An authenticated operator PUT with a JSON body (no Idempotency-Key: PUT is the
    /// idempotent replace).
    pub async fn put(&self, path: &str, body: &str) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("PUT")
            .uri(path)
            .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request builds");
        self.send(request).await
    }

    /// An authenticated operator DELETE.
    pub async fn delete(&self, path: &str) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("DELETE")
            .uri(path)
            .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
            .body(Body::empty())
            .expect("request builds");
        self.send(request).await
    }

    /// Create a tenant and return its `(tenant_id, environment_id)`.
    pub async fn create_tenant(&self, display_name: &str, key: &str) -> (String, String) {
        let body = serde_json::json!({ "display_name": display_name }).to_string();
        let (status, _, response) = self.post("/v1/tenants", key, &body).await;
        assert_eq!(status, StatusCode::CREATED, "create tenant: {response}");
        let value: serde_json::Value = serde_json::from_str(&response).expect("json");
        (
            value["tenant"]["id"]
                .as_str()
                .expect("tenant id")
                .to_owned(),
            value["environment"]["id"]
                .as_str()
                .expect("environment id")
                .to_owned(),
        )
    }

    /// Create an environment under a tenant and return its id.
    pub async fn create_environment(
        &self,
        tenant_id: &str,
        display_name: &str,
        key: &str,
    ) -> String {
        // The default helper creates a dev environment (the relaxed kind that
        // needs no custom domain), so the callers that only care about scoping
        // stay one line. Guardrail-specific tests use create_environment_typed.
        let path = format!("/v1/tenants/{tenant_id}/environments");
        let body = serde_json::json!({ "display_name": display_name, "kind": "dev" }).to_string();
        let (status, _, response) = self.post(&path, key, &body).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create environment: {response}"
        );
        let value: serde_json::Value = serde_json::from_str(&response).expect("json");
        value["id"].as_str().expect("environment id").to_owned()
    }

    /// Create an environment of an explicit kind (and optional custom domain),
    /// returning the raw `(status, response body)` so a guardrail test can assert
    /// on either a success or a structured guardrail failure (issue #42).
    pub async fn create_environment_typed(
        &self,
        tenant_id: &str,
        display_name: &str,
        kind: &str,
        custom_domain: Option<&str>,
        key: &str,
    ) -> (StatusCode, String) {
        let path = format!("/v1/tenants/{tenant_id}/environments");
        let mut body = serde_json::json!({ "display_name": display_name, "kind": kind });
        if let Some(domain) = custom_domain {
            body["custom_domain"] = serde_json::Value::String(domain.to_owned());
        }
        let (status, _, response) = self.post(&path, key, &body.to_string()).await;
        (status, response)
    }

    /// Mint a management key under an environment and return its secret token.
    pub async fn create_key(
        &self,
        tenant_id: &str,
        environment_id: &str,
        display_name: &str,
        key: &str,
    ) -> String {
        let path = format!("/v1/tenants/{tenant_id}/environments/{environment_id}/keys");
        let body = serde_json::json!({ "display_name": display_name }).to_string();
        let (status, _, response) = self.post(&path, key, &body).await;
        assert_eq!(status, StatusCode::CREATED, "create key: {response}");
        let value: serde_json::Value = serde_json::from_str(&response).expect("json");
        value["secret"].as_str().expect("secret").to_owned()
    }
}

/// A `Bearer <token>` header value.
#[must_use]
pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// Assert the rate-limit header contract is present on a response: the
/// structured RateLimit fields and the legacy X-RateLimit-* triplet.
pub fn assert_rate_limit_headers(headers: &HeaderMap) {
    for name in [
        "ratelimit",
        "ratelimit-policy",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    ] {
        assert!(
            headers.contains_key(name),
            "missing rate-limit header {name}"
        );
    }
}
