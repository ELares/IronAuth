// SPDX-License-Identifier: MIT OR Apache-2.0

//! Management-API integration test for the per-connector health-diagnostics read
//! (issue #76): the mgmt read reflects an induced upstream outage recorded into the
//! SAME in-memory federation health registry the OIDC data plane records into.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use common::Harness;
use ironauth_connector::ConnectorError;
use ironauth_env::Env;
use ironauth_fetch::{FetchLimits, Fetcher};
use ironauth_oidc::{FederationKeyResolver, FederationRuntime};
use ironauth_store::{EnvironmentId, Scope, TenantId};

/// A minimal valid connector create body for `slug`.
fn connector_body(slug: &str) -> String {
    serde_json::json!({
        "connector_id": slug,
        "display_name": "Acme OIDC",
        "protocol": "oidc",
        "endpoints": { "issuer": "https://issuer.example.com" },
        "scopes": ["openid", "email"],
        "client_id": "ironauth-at-acme",
        "client_secret": "upstream-secret-value"
    })
    .to_string()
}

/// A real federation runtime (its fetcher is never used: the test only touches the
/// in-memory health registry, never the network).
fn runtime() -> Arc<FederationRuntime> {
    let fetcher = Arc::new(Fetcher::new(FetchLimits::default()).expect("fetcher"));
    let keys = Arc::new(FederationKeyResolver::new(
        Arc::clone(&fetcher),
        Duration::from_secs(300),
    ));
    Arc::new(FederationRuntime::new(
        fetcher,
        keys,
        Duration::from_secs(300),
        Duration::from_secs(30),
    ))
}

#[tokio::test]
async fn the_health_read_reflects_an_induced_outage_and_isolates_siblings() {
    let runtime = runtime();
    let harness = Harness::start_with_federation(50, Arc::clone(&runtime)).await;
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/connectors");

    // Seed two connectors: one whose upstream we will "kill", and a healthy sibling.
    let (status, _, body) = harness
        .post(&base, "create-broken", &connector_body("broken-oidc"))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let broken_id = serde_json::from_str::<serde_json::Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let (status, _, body) = harness
        .post(&base, "create-healthy", &connector_body("healthy-oidc"))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let healthy_id = serde_json::from_str::<serde_json::Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // Induce an upstream outage on the broken connector and a success on the sibling, recorded
    // (via the injected clock seam) into the SAME registry the admin plane reads. The record must
    // key on each connector's REAL definition fingerprint (its store-row updated_at micros), the
    // value the mgmt read now discounts a stale record against (issue #76), exactly as the OIDC
    // data plane records it.
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );
    let scoped = harness.control_store().scoped(scope);
    let connectors = scoped.connectors();
    let broken_fp = connectors
        .get(&connectors.parse_id(&broken_id).expect("parse broken id"))
        .await
        .expect("broken record")
        .updated_at_unix_micros;
    let healthy_fp = connectors
        .get(&connectors.parse_id(&healthy_id).expect("parse healthy id"))
        .await
        .expect("healthy record")
        .updated_at_unix_micros;
    let now = Env::system().clock().now_utc();
    runtime.health().record_failure(
        now,
        &broken_id,
        broken_fp,
        &ConnectorError::UpstreamUnavailable("dead upstream".to_owned()),
    );
    runtime
        .health()
        .record_success(now, &healthy_id, healthy_fp);

    // The mgmt read for the broken connector reports the typed unavailable state.
    let (status, _, body) = harness.get(&format!("{base}/{broken_id}/health")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(view["state"], "unavailable", "{body}");
    assert_eq!(view["last_error_kind"], "upstream_unavailable");
    assert_eq!(view["error_total"], 1);
    assert!(
        view["next_retry_at_unix_ms"].is_number(),
        "an unavailable connector carries a backoff retry instant: {body}"
    );

    // The healthy sibling's health is untouched by the broken connector's outage.
    let (status, _, body) = harness.get(&format!("{base}/{healthy_id}/health")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(view["state"], "healthy", "{body}");
    assert_eq!(view["success_total"], 1);
}

#[tokio::test]
async fn a_never_exercised_connector_reads_unknown_and_an_absent_id_is_not_found() {
    let harness = Harness::start_with_federation(50, runtime()).await;
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/connectors");
    let (status, _, body) = harness
        .post(&base, "create-connector", &connector_body("acme-oidc"))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = serde_json::from_str::<serde_json::Value>(&body).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // A connector that exists but has never been exercised reports the unknown state.
    let (status, _, body) = harness.get(&format!("{base}/{id}/health")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(view["state"], "unknown", "{body}");

    // An absent connector id is a uniform not-found (never an oracle).
    let (status, _, _) = harness
        .get(&format!("{base}/cnr_0000000000000000000000000000/health"))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Unauthenticated access is unauthorized.
    let (status, _, _) = harness
        .get_as(&format!("{base}/{id}/health"), "wrong-token")
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
