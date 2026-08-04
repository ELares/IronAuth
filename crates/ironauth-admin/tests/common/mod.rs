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
use ironauth_admin::{AdminState, DayOneSigningKeys, management_router};
use ironauth_config::{AdminConfig, IdentifiersConfig, Secret, SecretString};
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

    /// Start a fresh database and router over a CALLER-SUPPLIED environment seam, so a
    /// test can install its own clock or entropy double and drive what the handlers mint.
    ///
    /// The issue #247 atomicity test uses it to REPEAT a mint: an entropy source that can
    /// be rewound makes two different requests mint the same invitation handle, which is
    /// how a create's SECOND write is made to fail on real infrastructure without a
    /// production failure-injection knob in the admin crate.
    pub async fn start_with_env(default_page_size: u32, env: Env) -> Self {
        let db = TestDatabase::start().await;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size,
            ..AdminConfig::default()
        };
        let state =
            AdminState::new(db.control_store().clone(), env, &config).expect("admin state builds");
        let router = management_router(state);
        Self {
            db,
            router,
            outbound_scope: None,
        }
    }

    /// Start a fresh database and router with an explicit organization group nesting
    /// bound (issue #97), so a test can drive the depth refusal with a handful of
    /// groups instead of the shipped default's nine.
    ///
    /// This bounds tree DEPTH only. It caps nothing that is counted: the number of
    /// groups an organization may hold is uncapped by covenant, at every depth level.
    pub async fn start_with_group_depth(default_page_size: u32, max_group_depth: u32) -> Self {
        let db = TestDatabase::start().await;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size,
            ..AdminConfig::default()
        };
        let state = AdminState::new(db.control_store().clone(), Env::system(), &config)
            .expect("admin state builds")
            .with_max_group_depth(max_group_depth);
        let router = management_router(state);
        Self {
            db,
            router,
            outbound_scope: None,
        }
    }

    /// Start a fresh database and router with an explicit `[identifiers]` section
    /// (issue #54, epic #514), so a test can drive the identifier surface under a
    /// uniqueness mode other than the shipped environment-wide default.
    ///
    /// This constructor is what makes the config seam MEASURABLE rather than asserted.
    /// The section had no reader at all before the surface landed (issue #459), and the
    /// failure mode it guards against is precisely a handler that ignores the installed
    /// mode and passes a constant: such a handler passes every same-mode test and is
    /// caught only by a test that installs a DIFFERENT mode and observes the behaviour
    /// change.
    pub async fn start_with_identifiers(
        default_page_size: u32,
        identifiers: &IdentifiersConfig,
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
            .with_identifiers(identifiers);
        let router = management_router(state);
        Self {
            db,
            router,
            outbound_scope: None,
        }
    }

    /// Start a fresh database and router with an explicit `[token_claims]` budget
    /// (issue #98), so a test can drive the effective-roles view's budget verdict with
    /// a handful of permissions instead of the shipped default's 257.
    ///
    /// The budget bounds what one TOKEN CLAIM carries. It caps nothing that is stored,
    /// and no endpoint on this plane may refuse a write because of it, which is
    /// precisely what the tests using this constructor exist to prove.
    pub async fn start_with_token_claims(
        default_page_size: u32,
        token_claims: &ironauth_config::TokenClaimsConfig,
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
            .with_token_claims(token_claims);
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
    /// credential-verification endpoint ARMED in a freshly seeded
    /// `(tenant, environment)` scope (issue #58, re-homed by issue #250).
    ///
    /// There is no config knob any more: `token` is written into THAT ENVIRONMENT's
    /// own sealed secret through the real management endpoint, which is the only way
    /// the feature can be enabled at all. Every other scope in this database is
    /// therefore disabled, which is what makes the cross-environment test meaningful.
    /// Callers seed users into [`Harness::outbound_scope`].
    pub async fn start_with_outbound_verification(token: &str) -> Self {
        let db = TestDatabase::start().await;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size: 50,
            ..AdminConfig::default()
        };
        let state = AdminState::new(db.control_store().clone(), Env::system(), &config)
            .expect("admin state builds");
        let router = management_router(state);
        let harness = Self {
            db,
            router,
            outbound_scope: None,
        };
        let scope = harness.seed_scope().await;
        harness.arm_outbound_verification(scope, token).await;
        Self {
            outbound_scope: Some(scope),
            ..harness
        }
    }

    /// Arm outbound verification in `scope` with `token`, through the REAL management
    /// endpoint (issue #250), so the harness exercises the same seal an operator does
    /// rather than a second write path that could drift from it.
    ///
    /// # Panics
    ///
    /// Panics unless the write answers 200 with `enabled: true`.
    pub async fn arm_outbound_verification(&self, scope: Scope, token: &str) {
        let path = format!(
            "/v1/tenants/{}/environments/{}/migration/outbound-verification",
            scope.tenant(),
            scope.environment()
        );
        let body = serde_json::json!({ "token": token }).to_string();
        let (status, _headers, body) = self.put(&path, &body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "arming outbound verification must succeed: {body}"
        );
        let view: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(view["enabled"], true, "armed: {body}");
    }

    /// Start a fresh database and router with a store-backed data-plane issuer registry
    /// installed (issue #93), so the compatibility wizard can resolve an environment's
    /// signable set and write the per-client column through the data plane. The registry
    /// wraps the SAME data-plane store `store()` returns, so a scope this harness seeds
    /// keys into resolves through the wizard.
    pub async fn start_with_signing_registry(default_page_size: u32) -> Self {
        let db = TestDatabase::start().await;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size,
            ..AdminConfig::default()
        };
        let registry = std::sync::Arc::new(ironauth_oidc::IssuerRegistry::store_backed(
            "https://issuer.test",
            ironauth_oidc::JwksCacheWindow::clamped(300),
            db.store().clone(),
        ));
        let state = AdminState::new(db.control_store().clone(), Env::system(), &config)
            .expect("admin state builds")
            .with_signing_registry(registry);
        let router = management_router(state);
        Self {
            db,
            router,
            outbound_scope: None,
        }
    }

    /// Start a fresh database and router with EVERY optional management surface armed,
    /// bound to one freshly seeded `(tenant, environment)` returned as
    /// [`Harness::outbound_scope`].
    ///
    /// The whole-surface live sweep needs this. A surface that is off answers the uniform
    /// not-found BEFORE it resolves anything, so a sweep run against the default harness
    /// would report a clean 404 for every gated route and would be blind to whatever those
    /// routes do once they reach the database. Arming them all in one router is what makes
    /// the sweep's silence meaningful.
    ///
    /// Sudo mode is deliberately NOT armed: it gates every environment-scoped mutation on a
    /// fresh elevation, so arming it would turn the sweep into a 403 sweep. The elevation
    /// route is driven under [`Harness::start_with_sudo`] instead.
    ///
    /// The outbound verification endpoint is bound to an explicit `(tenant, environment)`
    /// at CONFIGURATION time, which it cannot be if the tenant does not exist yet, and the
    /// tenant cannot be seeded through the owner pool either: `TestDatabase::seed_scope`
    /// mints its own operator, and every management read is scoped to the BOOTSTRAP
    /// operator, so such a tenant is a uniform not-found to this plane (measured: the
    /// environment create answered 404). So the router is built TWICE over the one
    /// database, the tenant and environment are created through the first one exactly as an
    /// operator would, and the second is bound to what that produced.
    pub async fn start_fully_armed(default_page_size: u32, outbound_token: &str) -> Self {
        let db = TestDatabase::start().await;
        let bootstrap = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size,
            ..AdminConfig::default()
        };
        let opening_state = AdminState::new(db.control_store().clone(), Env::system(), &bootstrap)
            .expect("admin state builds");
        let opening = Self {
            db,
            router: management_router(opening_state),
            outbound_scope: None,
        };
        let (tenant, environment) = opening.create_tenant("armed", "armed-tenant").await;
        let scope = Scope::new(
            ironauth_store::TenantId::parse(&tenant).expect("tenant parses"),
            ironauth_store::EnvironmentId::parse(&environment).expect("environment parses"),
        );
        let db = opening.db;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size,
            ..AdminConfig::default()
        };
        let registry = std::sync::Arc::new(ironauth_oidc::IssuerRegistry::store_backed(
            "https://issuer.test",
            ironauth_oidc::JwksCacheWindow::clamped(300),
            db.store().clone(),
        ));
        let fetcher = std::sync::Arc::new(
            ironauth_fetch::Fetcher::new(ironauth_fetch::FetchLimits::default()).expect("fetcher"),
        );
        let keys = std::sync::Arc::new(ironauth_oidc::FederationKeyResolver::new(
            std::sync::Arc::clone(&fetcher),
            std::time::Duration::from_secs(300),
        ));
        let federation = std::sync::Arc::new(ironauth_oidc::FederationRuntime::new(
            fetcher,
            keys,
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(30),
        ));
        let state = AdminState::new(db.control_store().clone(), Env::system(), &config)
            .expect("admin state builds")
            .with_signing_registry(registry)
            .with_federation(federation)
            .with_signup_quarantine_enabled(true)
            .with_advanced_recovery_enabled(true);
        let router = management_router(state);
        let harness = Self {
            db,
            router,
            outbound_scope: None,
        };
        // Outbound verification is armed in THAT environment's own sealed secret
        // (issue #250), not in config, so the whole-surface sweeps drive the endpoint
        // through the same door an operator uses.
        harness
            .arm_outbound_verification(scope, outbound_token)
            .await;
        Self {
            outbound_scope: Some(scope),
            ..harness
        }
    }

    /// Provision the three day-one signing algorithms (`EdDSA`, `ES256`, `RS256`) into an
    /// existing `scope` through the data-plane store, so its issuer resolves as fully
    /// provisioned (every wizard recommendation is signable). Mirrors env-create's
    /// day-one provisioning; used after [`Harness::seed_scope`], which creates the
    /// environment row with no keys.
    pub async fn provision_all_algorithms(&self, scope: Scope) {
        let env = Env::system();
        let day_one =
            DayOneSigningKeys::generate(&env, &scope).expect("generate day-one signing keys");
        let actor = self.db.test_actor(&env);
        for key in day_one.as_new(1_000_000) {
            self.db
                .store()
                .scoped(scope)
                .acting(actor, CorrelationId::generate(&env))
                .signing_keys()
                .provision(&env, key)
                .await
                .expect("provision day-one signing key");
        }
    }

    /// Provision ONLY the day-one `EdDSA` signing key into `scope`, modeling a legacy
    /// environment that predates the multi-algorithm provisioning (issue #93): the wizard
    /// must reject pinning `ES256` or `RS256` there until it is backfilled.
    pub async fn provision_eddsa_only(&self, scope: Scope) {
        let env = Env::system();
        let day_one =
            DayOneSigningKeys::generate(&env, &scope).expect("generate day-one signing keys");
        let actor = self.db.test_actor(&env);
        for key in day_one.as_new(1_000_000) {
            if key.algorithm == "EdDSA" {
                self.db
                    .store()
                    .scoped(scope)
                    .acting(actor, CorrelationId::generate(&env))
                    .signing_keys()
                    .provision(&env, key)
                    .await
                    .expect("provision EdDSA signing key");
            }
        }
    }

    /// The stored `id_token_signed_response_alg` for a client in `scope`, read through
    /// the data-plane reader (the wizard's write through round-trips through this).
    pub async fn client_signing_alg(&self, scope: Scope, client: &ClientId) -> Option<String> {
        self.db
            .store()
            .scoped(scope)
            .clients()
            .id_token_signing_alg(client)
            .await
            .expect("read client signing alg")
    }

    /// An authenticated operator PUT carrying an Idempotency-Key and a JSON body.
    pub async fn put_with_key(
        &self,
        path: &str,
        idempotency_key: &str,
        body: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("PUT")
            .uri(path)
            .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
            .header("idempotency-key", idempotency_key)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request builds");
        self.send(request).await
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
                    org_id: None,
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
                    dpop_jkt: None,
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

    /// A PATCH with an arbitrary bearer token, for driving the environment-scoped
    /// MUTATION surface as a management key (the credential-scope tests).
    pub async fn patch_as(
        &self,
        path: &str,
        token: &str,
        body: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("PATCH")
            .uri(path)
            .header(header::AUTHORIZATION, bearer(token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request builds");
        self.send(request).await
    }

    /// A PUT with an arbitrary bearer token (no Idempotency-Key: PUT is the
    /// idempotent replace).
    pub async fn put_as(
        &self,
        path: &str,
        token: &str,
        body: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("PUT")
            .uri(path)
            .header(header::AUTHORIZATION, bearer(token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request builds");
        self.send(request).await
    }

    /// A DELETE with an arbitrary bearer token.
    pub async fn delete_as(&self, path: &str, token: &str) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("DELETE")
            .uri(path)
            .header(header::AUTHORIZATION, bearer(token))
            .body(Body::empty())
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

    /// An authenticated operator PUT with a RAW BYTE body, for the endpoints whose payload is
    /// not JSON (the brand asset uploads, whose bodies are sniffed rasters). A raster's magic
    /// bytes are not valid UTF-8, so they cannot ride [`Harness::put`]'s `&str`.
    pub async fn put_bytes(&self, path: &str, body: &[u8]) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("PUT")
            .uri(path)
            .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(body.to_vec()))
            .expect("request builds");
        self.send(request).await
    }

    /// An authenticated operator PATCH with a JSON body (no Idempotency-Key: a PATCH
    /// is a partial edit, not a create).
    pub async fn patch(&self, path: &str, body: &str) -> (StatusCode, HeaderMap, String) {
        let request = Request::builder()
            .method("PATCH")
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
