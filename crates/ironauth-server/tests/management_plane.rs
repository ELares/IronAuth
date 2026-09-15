// SPDX-License-Identifier: MIT OR Apache-2.0

//! Management/public plane separation: health, readiness, and metrics live on
//! the management plane only and must 404 on the public plane.

mod common;

use axum::http::StatusCode;
use common::{get, server_from};
use ironauth_server::DegradedTier;

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
/// "Health endpoints report the ACTIVE degraded tier distinctly from healthy and from hard
/// down" is a claim about three outcomes, and two were covered: `healthz_is_always_ok` and
/// `readyz_reports_503_when_database_unreachable`. The middle one, the whole point of the
/// criterion, had no test at the HTTP layer at all. `readiness.rs` tests the probe's tier
/// CONSTRUCTION across seventeen cases; nothing asserted what an operator reading `/readyz`
/// actually sees.
///
/// # Every tier, because the criterion says ACTIVE
///
/// The first version of this test drove only `BackboneAbsent`, and a review measured what
/// that leaves open: replacing `tier.token()` in the handler with the literal
/// `"backbone_absent"` passed all eight tests here AND all forty-two lib tests. A handler
/// that ignores the active tier and always prints one token would have shipped green, which
/// is precisely the property the criterion names.
///
/// The concrete harm is a misrouted page: a deployment with an IronCache configured and down
/// answers `degraded: backbone_absent`, and the on-call opens the message-broker runbook for
/// a cache outage.
///
/// So the table drives both variants and asserts it covers `DegradedTier::ALL`, which makes a
/// third variant added later an obvious omission rather than a silent one.
#[tokio::test]
async fn readyz_reports_each_degraded_tier_distinctly() {
    // The healthy body, OBSERVED rather than written down, so the contrast below is between
    // two things the handler actually produced.
    let (healthy_status, healthy_body) = readyz_for("").await;
    assert_eq!(healthy_status, StatusCode::OK);
    assert_eq!(healthy_body, "ready\n");

    let cases = [
        ("outbox", "ironbus_addr", "backbone_absent"),
        ("hot_state", "ironcache_addr", "accelerator_absent"),
    ];
    assert_eq!(
        cases.len(),
        DegradedTier::ALL.len(),
        "every tier must be driven through the HANDLER, not just constructed in the probe: \
         a tier with no case here is one the response body is never checked for"
    );

    for (section, key, token) in cases {
        // 127.0.0.1:1 rather than a TEST-NET-1 address: nothing can bind port 1 without root,
        // so the connect is an immediate ECONNREFUSED instead of burning the full probe
        // timeout, and the case stops depending on how the host network treats an unroutable
        // destination. A network whose egress proxy completes connects to anywhere would make
        // the TEST-NET version report Ready.
        let (status, body) = readyz_for(&format!("\n[{section}]\n{key} = \"127.0.0.1:1\"\n")).await;

        // 200, NOT 503. A degraded tier still serves every flow, so answering 503 would have a
        // Kubernetes readiness probe pull the pod out of its Service because an OPTIONAL
        // component is down, turning an accelerator outage into an availability outage.
        assert_eq!(status, StatusCode::OK, "{section}: {body}");
        assert_eq!(
            body,
            format!("degraded: {token}\n"),
            "{section}: the body must name WHICH tier is active"
        );
        assert_ne!(
            body, healthy_body,
            "{section}: degraded must be distinguishable from healthy, which is the word the \
             criterion uses"
        );
    }
}

/// `/readyz` against a reachable database and no optional components.
///
/// The database half is a bare `TcpListener` that never accepts, which is enough because the
/// probe connects and speaks no protocol. The same property that makes this cheap is what
/// makes readiness a weak signal in production, and a reader should meet both facts in one
/// place: a deployment with wrong credentials or an unmigrated schema also reports Ready.
async fn readyz_for(extra: &str) -> (StatusCode, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port to listen on");
    let port = listener.local_addr().expect("a bound address").port();
    let server = server_from(&format!(
        "[database]\nurl = \"postgres://ironauth@127.0.0.1:{port}/ironauth\"\n{extra}"
    ));
    let (status, _, body) = get(server.management_app(), "/readyz").await;
    // Held until here so the port cannot be reused between bind and probe.
    drop(listener);
    (status, body)
}
