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
//! The quota is charged ONLY after the client store lookup confirms the client
//! exists in its declared `(tenant, environment)` scope, so a spend is only ever
//! drawn on a VERIFIED, real scope. A REGISTERED client is therefore the probe: the
//! bare `?client_id=` query (no `redirect_uri`) passes the client lookup, reaches
//! the quota gate, and then, when admitted, renders a `400` page ("`redirect_uri`
//! required"); when over quota it short-circuits to `429`. The distinction between
//! `400` (admitted by quota) and `429` (denied by quota) is exactly the signal
//! these tests assert.
//!
//! Two further tests prove the enforcement point is denial-of-service-safe: a flood of
//! well-formed but UNREGISTERED `client_id`s (each a distinct, attacker-chosen,
//! unauthenticated scope) allocates NO buckets (the spend is never reached), and a
//! spoofed victim-tenant scope cannot drain the victim's shared bucket. A final
//! test proves the idle-bucket reaper bounds memory under legitimate scope churn.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_config::{OidcConfig, QuotaConfig, ScopeQuotaConfig};
use ironauth_env::Env;
use ironauth_oidc::ClientAuthMethod;
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
        // The reaper is off for the enforcement regression tests: they never
        // advance the clock, so no bucket is idle, and this keeps the 429/fairness/
        // tier/concurrency assertions independent of eviction. The eviction test
        // below installs its own reaping config.
        idle_bucket_ttl_secs: 0,
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

/// A well-formed but UNREGISTERED `client_id` over a FRESH `(tenant, environment)`
/// scope. Any random bytes decode to a valid-looking scope, so this is exactly the
/// attacker probe: the client does not exist, so the store lookup returns
/// not-found and the request is rejected as a `400` page WITHOUT ever reaching the
/// quota spend. Used by the denial-of-service test to prove an unverified scope
/// allocates no bucket.
fn fresh_client(env: &Env) -> String {
    let scope = Scope::new(TenantId::generate(env), EnvironmentId::generate(env));
    ClientId::generate(env, &scope).to_string()
}

/// Register a real confidential client in a FRESH `(tenant, environment)` scope
/// (owned by a distinct tenant) and return its `client_id` string. Because the
/// client EXISTS, a request naming it is a VERIFIED scope: it passes the store
/// lookup and reaches the quota gate. The bare `?client_id=` query then renders a
/// `400` page (`redirect_uri` required) when admitted, so `400` vs `429` cleanly
/// reports the quota decision, exactly as the old unregistered probe did, but now
/// on the verified-scope path the fix enforces.
async fn registered_client(harness: &Harness) -> String {
    let scope = harness.provision_foreign_scope().await;
    registered_client_in(harness, scope).await
}

/// Register a real confidential client in an explicit `scope` and return its
/// `client_id` string, so a test can place a verified client in a chosen tenant.
async fn registered_client_in(harness: &Harness, scope: Scope) -> String {
    let (client_id, _secret) = harness
        .create_confidential_client_in(scope, ClientAuthMethod::Basic, "quota probe client")
        .await;
    client_id.to_string()
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
    let client_id = registered_client(&harness).await;

    // The first three fit the environment burst: admitted by quota, then a 400
    // because the bare query omits redirect_uri (the gate let them through).
    for i in 0..3 {
        let (status, _headers) = authorize(&harness, &client_id).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "spend {i} must pass the quota gate (redirect_uri required -> 400)"
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
    let noisy = registered_client(&harness).await;
    let quiet = registered_client(&harness).await;

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
    let client = registered_client(&tight).await;
    assert_eq!(authorize(&tight, &client).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        authorize(&tight, &client).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "with a burst of 1 the second request is denied",
    );

    // Raising the configured tier to a burst of 5 admits five before the 429: the
    // config value, not a hard-coded constant, governs the behavior.
    let loose = Harness::start_with_quota(oidc_config(), request_quota(5)).await;
    let client = registered_client(&loose).await;
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
    let client_id = registered_client(&harness).await;

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

/// A quota config whose TENANT request bucket is the limiter: a small tenant burst
/// under a large environment burst, no refill, so the SHARED per-tenant budget is
/// exactly `tenant_burst` and draining it throttles every environment under that
/// tenant (this is the shared bucket a cross-tenant attack would target). Every
/// other dimension is unlimited; the reaper is off.
fn tenant_limited_quota(tenant_burst: u64) -> QuotaConfig {
    let scope = |requests_burst: u64| ScopeQuotaConfig {
        requests_per_second: 0, // no refill: deterministic burst budget.
        requests_burst,
        token_issuance_per_second: 0,
        token_issuance_burst: 0,
        hook_seconds_per_second: 0,
        hook_seconds_burst: 0,
    };
    QuotaConfig {
        tenant: scope(tenant_burst),
        environment: scope(1_000),
        usage_thresholds_percent: vec![100],
        idle_bucket_ttl_secs: 0,
    }
}

// DEFECT 1 (HIGH): a flood of unauthenticated /authorize requests with random,
// nonexistent client_ids must NOT allocate quota buckets. The spend is charged only
// after the store confirms the client, so an unverified scope is rejected before it
// reaches a spend and allocates nothing. Against the pre-fix pre-verification spend
// this asserts the DoS: each distinct random scope allocated a tenant AND an
// environment bucket (2 per request) with no bound and no eviction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_of_unregistered_client_ids_allocates_no_buckets() {
    let harness = Harness::start_with_quota(oidc_config(), request_quota(1)).await;

    // A flood of well-formed but UNREGISTERED client_ids, each a DISTINCT random
    // (tenant, environment). Every one is rejected at the store lookup as a 400 and
    // never reaches the quota spend.
    for _ in 0..16 {
        let attacker = fresh_client(harness.env());
        assert_eq!(
            authorize(&harness, &attacker).await.0,
            StatusCode::BAD_REQUEST,
            "an unregistered client is rejected before any spend",
        );
    }

    assert_eq!(
        harness.quota_enforcer().bucket_count(),
        0,
        "an unbounded flood of unverified scopes must allocate zero buckets \
         (the pre-fix pre-verification spend would have allocated 32)",
    );
}

// DEFECT 2 (MEDIUM): an attacker who recovers a victim's tenant id (embedded in any
// of the victim's public client_ids) cannot drain the victim's SHARED per-tenant
// bucket by declaring that tenant with fabricated environments, because a spoofed,
// unregistered scope never reaches a spend. The victim's real traffic keeps its full
// tenant budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spoofed_victim_tenant_scope_cannot_drain_the_victims_bucket() {
    // The per-tenant bucket is the limiter (burst 3): if a spoofed request could
    // spend it, three of them would throttle the victim.
    let harness = Harness::start_with_quota(oidc_config(), tenant_limited_quota(3)).await;

    // The victim: a real, registered client in a fresh tenant.
    let victim_scope = harness.provision_foreign_scope().await;
    let victim_tenant = victim_scope.tenant();
    let victim = registered_client_in(&harness, victim_scope).await;

    // The attacker floods /authorize declaring the VICTIM'S tenant with fabricated
    // environments. Each spoofed client_id is well-formed but UNREGISTERED, so it is
    // rejected at the store lookup and never spends the victim's shared bucket.
    for _ in 0..10 {
        let spoofed_scope = Scope::new(victim_tenant, EnvironmentId::generate(harness.env()));
        let spoofed = ClientId::generate(harness.env(), &spoofed_scope).to_string();
        assert_eq!(
            authorize(&harness, &spoofed).await.0,
            StatusCode::BAD_REQUEST,
            "a spoofed victim-tenant client is unregistered -> 400, never a spend",
        );
    }
    assert_eq!(
        harness.quota_enforcer().bucket_count(),
        0,
        "a spoofed, unverified scope must not allocate (or draw on) any bucket",
    );

    // The victim's REAL traffic still has its FULL per-tenant budget: three requests
    // are admitted and only the victim's own fourth over-spend is throttled. Against
    // the pre-fix code the attacker's flood would have drained the burst-3 tenant
    // bucket and the victim's FIRST request would already 429.
    for i in 0..3 {
        assert_eq!(
            authorize(&harness, &victim).await.0,
            StatusCode::BAD_REQUEST,
            "victim spend {i} keeps its full tenant budget, undrained by the attacker",
        );
    }
    assert_eq!(
        authorize(&harness, &victim).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "the victim's own fourth request exhausts its tenant bucket",
    );
}

// Defense in depth: an idle bucket is reaped after the configured window, so even
// legitimate scope churn cannot grow memory without bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_bucket_is_reaped_after_the_configured_window() {
    // A one-minute idle window over the request-rate limiter.
    let mut quota = request_quota(5);
    quota.idle_bucket_ttl_secs = 60;
    let harness = Harness::start_with_quota(oidc_config(), quota).await;
    let client = registered_client(&harness).await;

    // One admitted request allocates the tenant and environment buckets.
    assert_eq!(
        authorize(&harness, &client).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        harness.quota_enforcer().bucket_count(),
        2,
        "a verified spend allocates the tenant and environment buckets",
    );

    // Advance past the idle window and reap: both idle buckets are evicted (driven by
    // the same deterministic clock), so the footprint is bounded under churn.
    harness.clock().advance(Duration::from_secs(61));
    let evicted = harness.quota_enforcer().reap_idle_buckets();
    assert_eq!(evicted, 2, "both idle buckets are reaped after the window");
    assert_eq!(
        harness.quota_enforcer().bucket_count(),
        0,
        "no bucket survives past the idle window",
    );
}
