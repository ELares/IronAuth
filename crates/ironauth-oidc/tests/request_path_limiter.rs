// SPDX-License-Identifier: MIT OR Apache-2.0

//! The REQUEST-PLANE layered limiter on the real request path (issue #150 criteria 1
//! and 3).
//!
//! Criterion 1 asks that the layers "enforce independently ... with the limiting layer
//! identified in headers and metrics", and criterion 3 that "correct structured RateLimit
//! and legacy X-RateLimit headers appear on throttled responses, and 429 carries
//! Retry-After". The forward-auth check already proves the machinery; these tests prove the
//! WIRING on the main OIDC path: a configured per-IP or per-tenant limit actually refuses
//! on `/authorize`, names the layer, and leaves the other budgets alone.
//!
//! The probe is the same as the quota tests: a registered client, a bare `?client_id=`
//! query. Admitted by the limiter, the request proceeds to the 400 page (`redirect_uri`
//! required); refused by it, the request short-circuits to 429 (or 403 for a
//! missing-identity refusal). The distinction between `400` and `429` is the signal.
//!
//! The peer address comes from the `x-ironauth-peer-ip` header the trusted-proxy
//! middleware stamps: the request path must not trust a client-supplied address, so these
//! tests send the header exactly as the middleware would, and one test asserts the
//! consequence of it being absent.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_config::{LimitConfig, OidcConfig, RateLimitConfig};
use ironauth_quota::layered::LIMITING_LAYER_HEADER;

fn oidc_config() -> OidcConfig {
    OidcConfig {
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    }
}

/// A per-IP budget of exactly `burst`, with a refill that never happens inside a test
/// unless the manual clock advances: deterministic burst math, and a REAL retry window,
/// which is what makes `Retry-After` mean something.
fn per_ip_burst(burst: f64) -> RateLimitConfig {
    RateLimitConfig {
        per_ip: Some(LimitConfig {
            per_second: 1.0,
            burst,
        }),
        per_tenant: None,
        per_environment: None,
        per_client: None,
        per_user: None,
    }
}

/// `GET /authorize?client_id=...` from `peer_ip` on the live router.
async fn authorize_from(
    harness: &Harness,
    client_id: &str,
    peer_ip: &str,
) -> (StatusCode, axum::http::HeaderMap) {
    let request = Request::builder()
        .method("GET")
        .uri(format!("/authorize?client_id={client_id}"))
        .header(ironauth_config::PEER_IP_HEADER, peer_ip)
        .body(Body::empty())
        .expect("request builds");
    let (status, headers, _body) = common::send_through(harness.router(), request).await;
    (status, headers)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_per_ip_burst_throttles_with_the_limiting_layer_named() {
    let harness = Harness::start_with_layered_limiter(oidc_config(), per_ip_burst(2.0)).await;
    let client_id = harness
        .create_confidential_client_in(
            harness.scope(),
            ironauth_oidc::ClientAuthMethod::Basic,
            "request-path limiter probe",
        )
        .await
        .0
        .to_string();

    // The first two from this address fit the burst: admitted by the limiter, then a 400
    // because the bare query omits redirect_uri.
    for i in 0..2 {
        let (status, _headers) = authorize_from(&harness, &client_id, "198.51.100.7").await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "spend {i} from 198.51.100.7 must pass the limiter"
        );
    }

    // The third is throttled: 429, the layer named, the structured and legacy headers, and
    // a Retry-After (criterion 3). The harness clock is frozen, so no refill has happened
    // and the burst math is exact.
    let (status, headers) = authorize_from(&harness, &client_id, "198.51.100.7").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the third must be refused"
    );
    assert_eq!(
        headers
            .get(LIMITING_LAYER_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("per_ip"),
        "the limiting layer is named in the response (criterion 1)"
    );
    assert!(headers.contains_key("ratelimit"), "structured header");
    assert!(headers.contains_key("x-ratelimit-limit"), "legacy header");
    assert!(
        headers.contains_key(header::RETRY_AFTER),
        "a throttle advertises when to retry (criterion 3)"
    );

    // THE OTHER ADDRESS IS UNAFFECTED: the per-IP bucket is per address, so this is the
    // control that proves the layer - not some wider budget - refused.
    let (status, _) = authorize_from(&harness, &client_id, "198.51.100.8").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a second address has its own budget"
    );

    // AND THE SAME ADDRESS RECOVERS ONCE THE CLOCK HAS: two seconds of frozen time
    // refills the bucket to full, so the budget the header advertised is the budget that
    // comes back.
    harness.clock().advance(Duration::from_secs(2));
    let (status, _) = authorize_from(&harness, &client_id, "198.51.100.7").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "after the advertised window the address admits again"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_per_tenant_burst_never_touches_another_tenant() {
    let harness = Harness::start_with_layered_limiter(
        oidc_config(),
        RateLimitConfig {
            per_ip: None,
            per_tenant: Some(LimitConfig {
                per_second: 0.0,
                burst: 2.0,
            }),
            per_environment: None,
            per_client: None,
            per_user: None,
        },
    )
    .await;
    let client_id = harness
        .create_confidential_client_in(
            harness.scope(),
            ironauth_oidc::ClientAuthMethod::Basic,
            "per-tenant probe",
        )
        .await
        .0
        .to_string();

    // Exhaust this tenant's request budget...
    for i in 0..2 {
        let (status, _) = authorize_from(&harness, &client_id, "198.51.100.7").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "tenant spend {i} passes");
    }
    let (status, headers) = authorize_from(&harness, &client_id, "198.51.100.9").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "tenant budget is gone"
    );
    assert_eq!(
        headers
            .get(LIMITING_LAYER_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("per_tenant"),
        "the layer that refused is the tenant layer, whatever address presented"
    );

    // ...and a SECOND tenant (a fresh scope under its own tenant) still admits: one
    // tenant's flood never consumes another's budget (criterion 2's direction).
    let second = harness.provision_foreign_scope().await;
    let second_client = harness
        .create_confidential_client_in(
            second,
            ironauth_oidc::ClientAuthMethod::Basic,
            "other tenant",
        )
        .await
        .0
        .to_string();
    let (status, _) = authorize_from(&harness, &second_client, "198.51.100.9").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "another tenant's budget is untouched"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_per_ip_limit_without_a_peer_address_is_a_403_not_a_throttle() {
    let harness = Harness::start_with_layered_limiter(oidc_config(), per_ip_burst(2.0)).await;
    let client_id = harness
        .create_confidential_client_in(
            harness.scope(),
            ironauth_oidc::ClientAuthMethod::Basic,
            "unidentified probe",
        )
        .await
        .0
        .to_string();

    // NO peer-address header: the request presents no key for the one configured layer.
    // That is a property of the request, not of its rate, so the answer is 403 - 429
    // would advertise a wait that can never produce an address.
    let request = Request::builder()
        .method("GET")
        .uri(format!("/authorize?client_id={client_id}"))
        .body(Body::empty())
        .expect("request builds");
    let (status, _, _) = common::send_through(harness.router(), request).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an unidentified request is refused, not throttled"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_per_client_burst_throttles_that_client_and_no_other() {
    let harness = Harness::start_with_layered_limiter(
        oidc_config(),
        RateLimitConfig {
            per_ip: None,
            per_tenant: None,
            per_environment: None,
            per_client: Some(LimitConfig {
                per_second: 0.0,
                burst: 2.0,
            }),
            per_user: None,
        },
    )
    .await;
    let client_a = harness
        .create_confidential_client_in(
            harness.scope(),
            ironauth_oidc::ClientAuthMethod::Basic,
            "per-client probe a",
        )
        .await
        .0
        .to_string();
    let client_b = harness
        .create_confidential_client_in(
            harness.scope(),
            ironauth_oidc::ClientAuthMethod::Basic,
            "per-client probe b",
        )
        .await
        .0
        .to_string();

    // Client A fits its burst twice, then is throttled WITH THE LAYER NAMED - even though
    // the peer address is the same as client B's later request.
    for i in 0..2 {
        let (status, _) = authorize_from(&harness, &client_a, "198.51.100.7").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "client A spend {i} passes");
    }
    let (status, headers) = authorize_from(&harness, &client_a, "198.51.100.7").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "client A is over budget"
    );
    assert_eq!(
        headers
            .get(LIMITING_LAYER_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("per_client"),
        "the layer that refused is the client layer, whatever address presented"
    );

    // CLIENT B, SAME ADDRESS, SAME TENANT: its own budget is untouched. This is the
    // control that proves the layer is per client and not per address or per tenant.
    let (status, _) = authorize_from(&harness, &client_b, "198.51.100.7").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "another client has its own budget"
    );
}

/// A per-user budget of exactly `burst`, with a refill that never happens inside a test
/// unless the manual clock advances: the layer that binds only where a VERIFIED subject
/// is resolved, which is the token endpoint's grants.
fn per_user_burst(burst: f64) -> RateLimitConfig {
    RateLimitConfig {
        per_ip: None,
        per_tenant: None,
        per_environment: None,
        per_client: None,
        per_user: Some(LimitConfig {
            per_second: 1.0,
            burst,
        }),
    }
}

/// The PKCE code-exchange form for the harness's default public client.
fn code_form_pkce(code: &str, client_id: &str) -> String {
    common::form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", common::REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", common::PKCE_VERIFIER),
    ])
}

/// The refresh-token grant form for a public client.
fn refresh_form(refresh_token: &str, client_id: &str) -> String {
    common::form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ])
}

/// A fresh refresh token for a FRESH user, through the real authorize and code paths.
async fn refresh_token_for(harness: &Harness, client_id: &str) -> String {
    let code = harness.issue_authenticated_code_pkce(client_id).await;
    let (status, _, body) = harness.token(&code_form_pkce(&code, client_id)).await;
    assert_eq!(status, StatusCode::OK, "code exchange: {body}");
    common::json(&body)["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_per_user_burst_throttles_that_subject_and_no_other() {
    let harness = Harness::start_with_layered_limiter(oidc_config(), per_user_burst(2.0)).await;
    let client_id = harness.client_id().to_string();

    // ALICE, whose budget of two is spent by: the code exchange (a subject-resolved
    // spend, one token) and her first refresh (the second). The NEXT refresh is
    // throttled, with the layer named - even though the token rotated in between, the
    // SUBJECT is what the bucket keys on.
    let mut token = refresh_token_for(&harness, &client_id).await; // spends 1
    let (status, _, body) = harness.token(&refresh_form(&token, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "first refresh: {body}");
    token = common::json(&body)["refresh_token"]
        .as_str()
        .expect("rotated")
        .to_owned(); // spends 2

    let (status, headers, _) = harness.token(&refresh_form(&token, &client_id)).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the third spend is refused"
    );
    assert_eq!(
        headers
            .get(LIMITING_LAYER_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("per_user"),
        "the layer that refused is the subject layer"
    );

    // THE THROTTLE DOES NOT CONSUME THE FAMILY: the same token refreshes again once the
    // advertised window has passed, which is the difference between a throttle and a
    // revocation.
    harness.clock().advance(Duration::from_secs(2));
    let (status, _, body) = harness.token(&refresh_form(&token, &client_id)).await;
    assert_eq!(status, StatusCode::OK, "recovery after the window: {body}");

    // BOB, A DIFFERENT SUBJECT: his own budget is untouched, even though he shares the
    // client, the address, the tenant and the environment with alice's requests.
    let bob = refresh_token_for(&harness, &client_id).await;
    let (status, _, _) = harness.token(&refresh_form(&bob, &client_id)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "another subject's budget is untouched"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_shipped_default_admits_every_request() {
    // No limits configured: the limiter is INSTALLED (one code path) but every layer is
    // unlimited, so every request proceeds exactly as it did before the limiter existed.
    let harness = Harness::start_with_layered_limiter(
        oidc_config(),
        RateLimitConfig {
            per_ip: None,
            per_tenant: None,
            per_environment: None,
            per_client: None,
            per_user: None,
        },
    )
    .await;
    let client_id = harness
        .create_confidential_client_in(
            harness.scope(),
            ironauth_oidc::ClientAuthMethod::Basic,
            "default probe",
        )
        .await
        .0
        .to_string();

    for _ in 0..5 {
        let (status, _) = authorize_from(&harness, &client_id, "198.51.100.7").await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an unlimited deployment is behaviorally unchanged"
        );
    }
}

/// The peer-address header the middleware stamps is the one thing the limiter can key:
/// pin that constant here so a rename breaks this file's contract loudly.
#[test]
fn the_peer_ip_header_is_the_documented_one() {
    assert_eq!(
        ironauth_config::PEER_IP_HEADER,
        "x-ironauth-peer-ip",
        "the tests send the header exactly as the middleware stamps it"
    );
}

/// CRITERION 2, INDUCED UNDER LOAD: one tenant driven to saturation does not reduce
/// another tenant's admitted throughput AT ALL - the bound is zero interference, not a
/// margin. Both tenants have the same per-tenant budget; a concurrent storm saturates one
/// while the other is measured.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_noisy_tenant_storm_never_reduces_a_quiet_tenant_s_throughput() {
    const BUDGET: u64 = 3;
    const RACERS: usize = 8;
    const PER_RACER: usize = 30;

    let harness = Harness::start_with_layered_limiter(
        oidc_config(),
        RateLimitConfig {
            per_ip: None,
            per_tenant: Some(LimitConfig {
                per_second: 0.0,
                burst: 3.0,
            }),
            per_environment: None,
            per_client: None,
            per_user: None,
        },
    )
    .await;
    let noisy = harness
        .create_confidential_client_in(
            harness.scope(),
            ironauth_oidc::ClientAuthMethod::Basic,
            "noisy tenant",
        )
        .await
        .0
        .to_string();
    let quiet_scope = harness.provision_foreign_scope().await;
    let quiet = harness
        .create_confidential_client_in(
            quiet_scope,
            ironauth_oidc::ClientAuthMethod::Basic,
            "quiet tenant",
        )
        .await
        .0
        .to_string();

    let noisy_admitted = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let quiet_admitted = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut tasks = Vec::with_capacity(RACERS * 2);
    for (client_id, counter, label) in [
        (&noisy, &noisy_admitted, "noisy"),
        (&quiet, &quiet_admitted, "quiet"),
    ] {
        for _ in 0..RACERS {
            let router = harness.router();
            let client_id = client_id.clone();
            let counter = std::sync::Arc::clone(counter);
            tasks.push(tokio::spawn(async move {
                for _ in 0..PER_RACER {
                    let request = Request::builder()
                        .method("GET")
                        .uri(format!("/authorize?client_id={client_id}"))
                        .body(Body::empty())
                        .expect("request builds");
                    let (status, _, _) = common::send_through(router.clone(), request).await;
                    match status {
                        StatusCode::BAD_REQUEST => {
                            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                        StatusCode::TOO_MANY_REQUESTS => {}
                        other => panic!("{label}: unexpected status {other}"),
                    }
                }
            }));
        }
    }
    for task in tasks {
        task.await.expect("task joins");
    }

    let noisy_total = noisy_admitted.load(std::sync::atomic::Ordering::SeqCst);
    let quiet_total = quiet_admitted.load(std::sync::atomic::Ordering::SeqCst);
    // The noisy tenant hit its budget (exactly: the per-tenant bucket is one atomic
    // check-and-charge in L1 mode).
    assert_eq!(
        noisy_total, BUDGET,
        "the noisy tenant saturated at its budget"
    );
    // THE FAIRNESS BOUND: the quiet tenant's admitted throughput is EXACTLY its own
    // budget, whatever the storm beside it did. Zero interference, not a margin.
    assert_eq!(
        quiet_total, BUDGET,
        "the quiet tenant's admitted throughput must equal its own budget under the \
         noisy tenant's storm"
    );
}
