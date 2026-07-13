// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-issuer JWKS HTTP surface (issue #19).
//!
//! Database-free: builds an [`ironauth_oidc::IssuerRegistry`] directly over
//! in-memory key sets and drives the router. Covers acceptance criterion 2 (JWKS
//! responses carry explicit `Cache-Control` and `ETag`; a conditional request
//! returns `304`) and acceptance criterion 1 at the serving layer (two
//! environments have provably disjoint issuers and key sets). Discovery serving
//! moved to its own surface in issue #18 (see `tests/discovery.rs`); this binary
//! now exercises only the key set.

use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use ironauth_env::Env;
use ironauth_jose::{KeySet, SigningKey, SigningPolicy};
use ironauth_oidc::{
    IssuerEntry, IssuerRegistry, IssuerState, JwksCacheWindow, PairwiseSalt, issuer_router,
};
use ironauth_store::{EnvironmentId, Scope, TenantId};
use tower::ServiceExt;

const ISSUER_BASE: &str = "https://issuer.test";

/// A single-Ed25519-key environment registered in a fresh registry, returning the
/// registry, the scope, and the key's `kid`.
fn registry_with_one_environment(
    env: &Env,
    kid: &str,
    seed_byte: u8,
) -> (IssuerRegistry, Scope, String) {
    let scope = Scope::new(TenantId::generate(env), EnvironmentId::generate(env));
    let key = SigningKey::ed25519_from_seed(Some(kid.to_owned()), &[seed_byte; 32]).expect("key");
    let keyset = KeySet::bootstrap(key, SystemTime::UNIX_EPOCH);
    let mut registry = IssuerRegistry::new(ISSUER_BASE, JwksCacheWindow::clamped(600));
    registry.insert(
        scope.environment(),
        IssuerEntry::new(
            keyset,
            SigningPolicy::eddsa_default(),
            PairwiseSalt::new(vec![0_u8; 32]),
        ),
    );
    (registry, scope, kid.to_owned())
}

/// Drive one GET request through the router.
async fn get(
    router: &Router,
    uri: &str,
    if_none_match: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(etag) = if_none_match {
        builder = builder.header(header::IF_NONE_MATCH, etag);
    }
    let response = router
        .clone()
        .oneshot(builder.body(Body::empty()).expect("request builds"))
        .await
        .expect("router infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

#[tokio::test]
async fn jwks_response_carries_cache_control_and_etag_and_honors_if_none_match() {
    let env = Env::system();
    let (registry, scope, kid) = registry_with_one_environment(&env, "kid-1", 0x11);
    let router = issuer_router(IssuerState::new(Arc::new(registry), env));
    let jwks_uri = format!("/t/{}/e/{}/jwks.json", scope.tenant(), scope.environment());

    // 200 with explicit Cache-Control (in the 300..=900 range) and a strong ETag.
    let (status, headers, body) = get(&router, &jwks_uri, None).await;
    assert_eq!(status, StatusCode::OK);
    let cache_control = headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .expect("Cache-Control present");
    assert!(cache_control.contains("max-age=600"), "{cache_control}");
    let etag = headers
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .expect("ETag present")
        .to_owned();
    assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/jwk-set+json")
    );

    // The body is a JWK Set containing this environment's key.
    let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
    let kids: Vec<&str> = doc["keys"]
        .as_array()
        .expect("keys array")
        .iter()
        .filter_map(|k| k["kid"].as_str())
        .collect();
    assert_eq!(kids, vec![kid.as_str()]);

    // A conditional request with the matching ETag returns 304 with no body, and
    // still carries the caching validators.
    let (status, headers, body) = get(&router, &jwks_uri, Some(&etag)).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty(), "304 has no body: {body:?}");
    assert_eq!(
        headers.get(header::ETAG).and_then(|v| v.to_str().ok()),
        Some(etag.as_str())
    );
    assert!(headers.get(header::CACHE_CONTROL).is_some());

    // A non-matching If-None-Match is served fresh (200).
    let (status, _, _) = get(&router, &jwks_uri, Some("\"stale\"")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn an_unknown_or_malformed_issuer_is_a_uniform_not_found() {
    let env = Env::system();
    let (registry, scope, _) = registry_with_one_environment(&env, "kid-1", 0x11);
    let router = issuer_router(IssuerState::new(Arc::new(registry), env.clone()));

    // A well-formed but unregistered environment.
    let other_env = EnvironmentId::generate(&env);
    let unknown = format!("/t/{}/e/{}/jwks.json", scope.tenant(), other_env);
    assert_eq!(get(&router, &unknown, None).await.0, StatusCode::NOT_FOUND);

    // A malformed environment identifier fails identically.
    let malformed = format!("/t/{}/e/env_not-base64-!!/jwks.json", scope.tenant());
    assert_eq!(
        get(&router, &malformed, None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn two_environments_have_disjoint_issuers_and_key_sets() {
    let env = Env::system();

    // Two environments, each with its own key, in one registry.
    let scope_a = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
    let scope_b = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
    let mut registry = IssuerRegistry::new(ISSUER_BASE, JwksCacheWindow::clamped(600));
    for (scope, kid, seed) in [(&scope_a, "kid-a", 0xAA_u8), (&scope_b, "kid-b", 0xBB_u8)] {
        let key = SigningKey::ed25519_from_seed(Some(kid.to_owned()), &[seed; 32]).expect("key");
        registry.insert(
            scope.environment(),
            IssuerEntry::new(
                KeySet::bootstrap(key, SystemTime::UNIX_EPOCH),
                SigningPolicy::eddsa_default(),
                PairwiseSalt::new(vec![0_u8; 32]),
            ),
        );
    }
    let router = issuer_router(IssuerState::new(Arc::new(registry), env));

    let kids_a = jwks_kids_and_x(&router, &scope_a).await;
    let kids_b = jwks_kids_and_x(&router, &scope_b).await;

    // Disjoint kids and disjoint key material (the `x` coordinate).
    assert!(
        kids_a.0.is_disjoint(&kids_b.0),
        "kids overlap: {:?} vs {:?}",
        kids_a.0,
        kids_b.0
    );
    assert!(
        kids_a.1.is_disjoint(&kids_b.1),
        "key material overlaps across environments"
    );
}

/// The set of `kid`s and the set of `x` (public key) values from an environment's
/// published JWKS.
async fn jwks_kids_and_x(
    router: &Router,
    scope: &Scope,
) -> (
    std::collections::HashSet<String>,
    std::collections::HashSet<String>,
) {
    let uri = format!("/t/{}/e/{}/jwks.json", scope.tenant(), scope.environment());
    let (status, _, body) = get(router, &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
    let mut kids = std::collections::HashSet::new();
    let mut xs = std::collections::HashSet::new();
    for key in doc["keys"].as_array().expect("keys array") {
        if let Some(kid) = key["kid"].as_str() {
            kids.insert(kid.to_owned());
        }
        if let Some(x) = key["x"].as_str() {
            xs.insert(x.to_owned());
        }
    }
    (kids, xs)
}
