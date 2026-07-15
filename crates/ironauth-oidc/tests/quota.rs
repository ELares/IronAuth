// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tenant/environment quota enforcement on the REAL `/authorize` request path
//! (issue #50).
//!
//! These tests drive the live axum router, not the engine in isolation: they prove
//! that an over-quota scope is short-circuited with an RFC 6585 `429` carrying the
//! structured `RateLimit` headers and the machine-readable block signal; that a
//! scope under quota passes through the gate; that one tenant flooding its own
//! quota never throttles another tenant (fairness end to end); that the configured
//! tier actually governs the limit (change the tier, the behavior changes); and
//! that a concurrency storm on the live endpoint never admits more than the burst.
//!
//! The quota check runs right after the `client_id` declares its `(tenant,
//! environment)` scope and BEFORE the client store lookup, so a well-formed but
//! unregistered `client_id` is the cleanest probe: under quota it passes the gate
//! and the client lookup then renders a `400` page ("`client_id` unknown"); over
//! quota it never reaches the lookup and returns `429`. The distinction between
//! `400` (admitted by quota) and `429` (denied by quota) is exactly the signal
//! these tests assert.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, QuotaConfig, ScopeQuotaConfig};
use ironauth_env::Env;
use ironauth_quota::{BLOCK_SIGNAL_COOKIE, BLOCK_SIGNAL_HEADER};
use ironauth_store::{ClientId, EnvironmentId, Scope, TenantId};

/// A quota config that enforces ONLY the request-rate dimension, with an
/// environment burst of `env_burst` and no refill, under a tenant envelope large
/// enough that the environment bucket is the limiter. Every other dimension is
/// unlimited (burst 0), and the tenant request budget is generous, so a single
/// scope's request-rate limit is exactly `env_burst`.
fn request_quota(env_burst: u64) -> QuotaConfig {
    let unlimited_others = |requests_burst: u64| ScopeQuotaConfig {
        requests_per_second: 0, // no refill: deterministic burst budget.
        requests_burst,
        token_issuance_per_second: 0,
        token_issuance_burst: 0, // unlimited (not charged on this path).
        hook_seconds_per_second: 0,
        hook_seconds_burst: 0, // unlimited (not charged on this path).
    };
    QuotaConfig {
        tenant: unlimited_others(10_000),
        environment: unlimited_others(env_burst),
        usage_thresholds_percent: vec![100],
    }
}

/// The default OIDC config the quota tests use (relaxed confidential PKCE is
/// irrelevant here: no request reaches token exchange).
fn oidc_config() -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    }
}

/// A well-formed but unregistered `client_id` over a FRESH `(tenant, environment)`
/// scope. Its declared scope is what keys the quota buckets; because it is
/// unregistered, an admitted request renders a `400` page (client unknown), so the
/// status cleanly reports whether the quota gate admitted or denied the request.
fn fresh_client(env: &Env) -> String {
    let scope = Scope::new(TenantId::generate(env), EnvironmentId::generate(env));
    ClientId::generate(env, &scope).to_string()
}

/// `GET /authorize?client_id=...` on the live router.
async fn authorize(harness: &Harness, client_id: &str) -> (StatusCode, axum::http::HeaderMap) {
    let request = Request::builder()
        .method("GET")
        .uri(format!("/authorize?client_id={client_id}"))
        .body(Body::empty())
        .expect("request builds");
    let (status, headers, _body) = common::send_through(harness.router(), request).await;
    (status, headers)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn at_quota_returns_429_with_ratelimit_headers_and_block_signal() {
    let harness = Harness::start_with_quota(oidc_config(), request_quota(3)).await;
    let client_id = fresh_client(harness.env());

    // The first three fit the environment burst: admitted by quota, then a 400
    // because the client is unregistered (the gate let them through).
    for i in 0..3 {
        let (status, _headers) = authorize(&harness, &client_id).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "spend {i} must pass the quota gate (client unknown -> 400)"
        );
    }

    // The fourth is over quota: fail-closed with a 429 on the real endpoint.
    let (status, headers) = authorize(&harness, &client_id).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the over-quota request must be short-circuited with a 429"
    );
    // The structured and legacy rate-limit headers.
    assert_eq!(
        headers.get("ratelimit-policy").map(|v| v.to_str().unwrap()),
        Some("3;w=0"),
    );
    assert!(
        headers.contains_key("ratelimit"),
        "structured RateLimit header"
    );
    assert_eq!(
        headers
            .get("x-ratelimit-limit")
            .map(|v| v.to_str().unwrap()),
        Some("3"),
    );
    assert_eq!(
        headers
            .get("x-ratelimit-remaining")
            .map(|v| v.to_str().unwrap()),
        Some("0"),
    );
    assert!(
        headers.contains_key(header::RETRY_AFTER),
        "Retry-After present"
    );
    // The machine-readable block signal (header) plus the WAF cookie.
    assert_eq!(
        headers
            .get(BLOCK_SIGNAL_HEADER)
            .map(|v| v.to_str().unwrap()),
        Some("1"),
    );
    let cookie = headers
        .get(header::SET_COOKIE)
        .expect("block cookie")
        .to_str()
        .expect("ascii cookie");
    assert!(
        cookie.contains(BLOCK_SIGNAL_COOKIE),
        "the block-signal cookie is set for a cookie-gating WAF: {cookie}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flooding_tenant_does_not_throttle_a_quiet_tenant_end_to_end() {
    let harness = Harness::start_with_quota(oidc_config(), request_quota(3)).await;
    let noisy = fresh_client(harness.env());
    let quiet = fresh_client(harness.env());

    // Drain the noisy tenant's environment budget and push it over quota.
    for _ in 0..3 {
        assert_eq!(authorize(&harness, &noisy).await.0, StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        authorize(&harness, &noisy).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "the noisy tenant is throttled",
    );

    // The quiet tenant, a DIFFERENT tenant with a disjoint bucket, is untouched:
    // its full budget is available on the real path despite the noisy flood.
    for i in 0..3 {
        assert_eq!(
            authorize(&harness, &quiet).await.0,
            StatusCode::BAD_REQUEST,
            "quiet spend {i} must not be throttled by the noisy tenant",
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_configured_tier_governs_the_limit() {
    // A burst of 1 admits exactly one before the 429.
    let tight = Harness::start_with_quota(oidc_config(), request_quota(1)).await;
    let client = fresh_client(tight.env());
    assert_eq!(authorize(&tight, &client).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        authorize(&tight, &client).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "with a burst of 1 the second request is denied",
    );

    // Raising the configured tier to a burst of 5 admits five before the 429: the
    // config value, not a hard-coded constant, governs the behavior.
    let loose = Harness::start_with_quota(oidc_config(), request_quota(5)).await;
    let client = fresh_client(loose.env());
    for i in 0..5 {
        assert_eq!(
            authorize(&loose, &client).await.0,
            StatusCode::BAD_REQUEST,
            "spend {i} fits the raised burst of 5",
        );
    }
    assert_eq!(
        authorize(&loose, &client).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "the sixth request exceeds the raised burst of 5",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrency_storm_on_the_real_path_never_oversells_the_burst() {
    const BURST: u64 = 10;
    const RACERS: usize = 8;
    const PER_RACER: usize = 20;

    let harness = Harness::start_with_quota(oidc_config(), request_quota(BURST)).await;
    let client_id = fresh_client(harness.env());

    let admitted = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let denied = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut tasks = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let router = harness.router();
        let client_id = client_id.clone();
        let admitted = std::sync::Arc::clone(&admitted);
        let denied = std::sync::Arc::clone(&denied);
        tasks.push(tokio::spawn(async move {
            for _ in 0..PER_RACER {
                let request = Request::builder()
                    .method("GET")
                    .uri(format!("/authorize?client_id={client_id}"))
                    .body(Body::empty())
                    .expect("request builds");
                let (status, _headers, _body) = common::send_through(router.clone(), request).await;
                match status {
                    StatusCode::TOO_MANY_REQUESTS => {
                        denied.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    StatusCode::BAD_REQUEST => {
                        admitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    other => panic!("unexpected status {other} on the quota path"),
                }
            }
        }));
    }
    for task in tasks {
        task.await.expect("task joins");
    }

    // Exactly the burst is admitted, never more (the check-and-charge is atomic
    // under one mutex), and every other attempt is a clean 429.
    let total = (RACERS * PER_RACER) as u64;
    assert_eq!(
        admitted.load(std::sync::atomic::Ordering::SeqCst),
        BURST,
        "a concurrent storm must admit exactly the burst, never oversell",
    );
    assert_eq!(
        denied.load(std::sync::atomic::Ordering::SeqCst),
        total - BURST,
        "every request beyond the burst is a 429",
    );
}
