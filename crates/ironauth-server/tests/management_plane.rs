// SPDX-License-Identifier: MIT OR Apache-2.0

//! Management/public plane separation: health, readiness, and metrics live on
//! the management plane only and must 404 on the public plane.

mod common;

use axum::http::StatusCode;
use common::{get, server_from};

const DB_ON_TEST_NET: &str = "[database]\nurl = \"postgres://ironauth@192.0.2.1:5432/ironauth\"\n";

#[tokio::test]
async fn management_routes_absent_from_public_plane() {
    let server = server_from(DB_ON_TEST_NET);
    for path in ["/healthz", "/readyz", "/metrics"] {
        let (status, _, _) = get(server.app(), path).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} must not exist on the public plane"
        );
    }
}

#[tokio::test]
async fn public_routes_absent_from_management_plane() {
    let server = server_from(DB_ON_TEST_NET);
    for path in ["/", "/.well-known/security.txt"] {
        let (status, _, _) = get(server.management_app(), path).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{path} must not exist on the management plane"
        );
    }
}

#[tokio::test]
async fn healthz_is_always_ok() {
    let server = server_from(DB_ON_TEST_NET);
    let (status, _, body) = get(server.management_app(), "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok\n");
}

#[tokio::test]
async fn readyz_reports_503_when_database_unreachable() {
    // TEST-NET-1 (RFC 5737) address is not reachable, so readiness fails.
    let server = server_from(DB_ON_TEST_NET);
    let (status, _, body) = get(server.management_app(), "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("not ready"), "{body}");
}

#[tokio::test]
async fn metrics_serves_prometheus_exposition() {
    let server = server_from(DB_ON_TEST_NET);
    // Drive one request so at least one series exists.
    let _ = get(server.management_app(), "/healthz").await;
    let (status, headers, body) = get(server.management_app(), "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(content_type.contains("text/plain"), "{content_type}");
    assert!(body.contains("ironauth_up"), "{body}");
    assert!(body.contains("ironauth_http_requests_total"), "{body}");
    // Metric labels must be route templates, never raw paths.
    assert!(body.contains("route=\"/healthz\""), "{body}");
}

#[tokio::test]
async fn public_root_and_security_txt_serve() {
    let server = server_from(DB_ON_TEST_NET);
    let (status, _, body) = get(server.app(), "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("IronAuth"), "{body}");

    let (status, headers, body) = get(server.app(), "/.well-known/security.txt").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Contact:"), "{body}");
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(content_type.contains("text/plain"), "{content_type}");
}
