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

    // THE HISTOGRAM BUCKETS, as the EXPOSITION renders them.
    //
    // `DURATION_BUCKETS` was asserted only by construction: nothing read a `le=` boundary
    // back off the wire, so a future exporter bump that changed the default buckets or the
    // way a histogram renders would pass every gate in this repo. The bucket list is a
    // contract with whatever scrapes this endpoint, and a dashboard or an alert threshold
    // built on `le="0.25"` breaks silently if it moves.
    //
    // Every boundary, plus `+Inf`, `_sum` and `_count`, because a partial check would let a
    // truncated or re-scaled list through.
    for boundary in [
        "0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10",
        "+Inf",
    ] {
        assert!(
            body.contains(&format!(
                "ironauth_http_request_duration_seconds_bucket{{method=\"GET\",\
                 route=\"/healthz\",status=\"200\",le=\"{boundary}\"}}"
            )),
            "the exposition must carry the le=\"{boundary}\" bucket: {body}"
        );
    }
    for suffix in ["_sum", "_count"] {
        assert!(
            body.contains(&format!(
                "ironauth_http_request_duration_seconds{suffix}{{method=\"GET\",\
                 route=\"/healthz\",status=\"200\"}}"
            )),
            "the exposition must carry {suffix} with its full label set: {body}"
        );
    }

    // THE COUNT, because every assertion above is a PRESENCE check and a thirteenth boundary
    // would pass all of them. Measured: re-scaling or dropping a boundary fails above,
    // ADDING one did not until this line. Thirteen is the twelve configured boundaries plus
    // `+Inf`.
    let rendered = body
        .lines()
        .filter(|line| {
            line.starts_with(
                "ironauth_http_request_duration_seconds_bucket{method=\"GET\",route=\"/healthz\"",
            )
        })
        .count();
    assert_eq!(
        rendered, 13,
        "the healthz histogram must render exactly the twelve configured boundaries plus \
         +Inf, so an ADDED bucket is caught as well as a removed one: {body}"
    );

    // The label ORDER above is asserted deliberately, not incidentally. Prometheus attaches
    // no meaning to it, and it does not vary at runtime, so pinning it costs nothing today
    // and would cost one test edit on some future exporter that sorts labels. That is a
    // cheaper failure than a silently loosened assertion.
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

/// THE DEGRADED ARM, which is the one issue #149 criterion 6 is actually about.
///
/// "Health endpoints report the active degraded tier DISTINCTLY from healthy and from hard
/// down" is a claim about three outcomes, and two of them were covered: `healthz_is_always_ok`
/// and `readyz_reports_503_when_database_unreachable`. The middle one, the whole point of the
/// criterion, had no test at the HTTP layer at all. `readiness.rs` tests the probe's tier
/// CONSTRUCTION thoroughly; nothing asserted what an operator reading `/readyz` sees.
///
/// A degraded state needs a REACHABLE database and an unreachable optional component. The
/// database half is a bare TCP listener, which is sufficient because the probe connects and
/// speaks no protocol -- the same property that makes readiness a weak signal in production is
/// what makes this test cheap, and it is worth naming rather than relying on quietly.
#[tokio::test]
async fn readyz_reports_the_degraded_tier_distinctly() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port to listen on");
    let port = listener.local_addr().expect("a bound address").port();

    let server = server_from(&format!(
        "[database]\nurl = \"postgres://ironauth@127.0.0.1:{port}/ironauth\"\n\
         \n[outbox]\n# TEST-NET-1 (RFC 5737), which is not reachable.\n\
         ironbus_addr = \"192.0.2.1:4222\"\n"
    ));
    let (status, _, body) = get(server.management_app(), "/readyz").await;

    // 200, NOT 503. A degraded tier still serves every flow, so answering 503 would have a
    // Kubernetes readiness probe pull the pod out of its Service because an OPTIONAL component
    // is down, turning an accelerator outage into an availability outage.
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body, "degraded: backbone_absent\n",
        "the body is what carries the tier, as a stable token an operator and a dashboard can \
         both match on"
    );

    // DISTINCT FROM HEALTHY, which is the word the criterion uses. Asserted as a contrast
    // rather than by reading the degraded body alone: a handler that answered the same 200
    // "ready" for both would satisfy the status assertion above and defeat the criterion.
    assert_ne!(body, "ready\n");
}

/// The healthy arm, for the same reason: without it the contrast above has only one side.
#[tokio::test]
async fn readyz_reports_ready_when_nothing_is_degraded() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port to listen on");
    let port = listener.local_addr().expect("a bound address").port();

    let server = server_from(&format!(
        "[database]\nurl = \"postgres://ironauth@127.0.0.1:{port}/ironauth\"\n"
    ));
    let (status, _, body) = get(server.management_app(), "/readyz").await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, "ready\n");
}
