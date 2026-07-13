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
use ironauth_store::Store;
use ironauth_store::test_support::TestDatabase;
use tower::ServiceExt;

/// The bootstrap operator token the harness configures.
pub const OPERATOR_TOKEN: &str = "test-bootstrap-operator-token";

/// A running management API over a fresh database.
pub struct Harness {
    // Held so the database and its pools outlive the router.
    db: TestDatabase,
    router: Router,
}

impl Harness {
    /// Start a fresh database and build the management router.
    ///
    /// `default_page_size` sets the page size used when a request omits `limit`.
    pub async fn start(default_page_size: u32) -> Self {
        let db = TestDatabase::start().await;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size,
        };
        let state = AdminState::new(db.control_store().clone(), Env::system(), &config)
            .expect("admin state builds");
        let router = management_router(state);
        Self { db, router }
    }

    /// The control-plane store behind the router, for verifying audit rows.
    #[must_use]
    pub fn control_store(&self) -> &Store {
        self.db.control_store()
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
        let path = format!("/v1/tenants/{tenant_id}/environments");
        let body = serde_json::json!({ "display_name": display_name }).to_string();
        let (status, _, response) = self.post(&path, key, &body).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create environment: {response}"
        );
        let value: serde_json::Value = serde_json::from_str(&response).expect("json");
        value["id"].as_str().expect("environment id").to_owned()
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
