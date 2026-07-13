// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adversarial trusted-proxy suite driven through the live router.
//!
//! These complement the pure unit tests in `proxy.rs`: they prove that under
//! the real middleware, forged forwarding headers cannot move the derived
//! scheme or the effective client IP, that the fail-closed path increments the
//! rejection counter, and that only the correct hop position is honored.

mod common;

use std::sync::{Mutex, PoisonError};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{CaptureWriter, get, send, server_from};
use ironauth_config::LogFormat;

const ZERO_TRUST: &str = "dev_mode = true\n\
    [server]\npublic_url = \"http://id.example.test\"\n\
    [database]\nurl = \"postgres://ironauth@192.0.2.1:5432/ironauth\"\n";

const ONE_TRUSTED_HOP: &str = "dev_mode = true\n\
    [server]\npublic_url = \"http://id.example.test\"\n\
    [proxy]\ntrusted_hops = 1\ntrust_forwarded = true\n\
    [database]\nurl = \"postgres://ironauth@192.0.2.1:5432/ironauth\"\n";

/// Serializes every test in this file that drives a request through the live
/// middleware, and pairs with each running under a real subscriber.
///
/// The `"request completed"` call site in [`ironauth_server::observe`] registers
/// its `tracing` callsite interest in a process-global cache the first time it
/// fires; every later hit short-circuits on that cached value. The first
/// registration resolves against whatever dispatcher is the current default on
/// the firing thread. If a test drives a request with *no* subscriber installed,
/// the call site registers against the no-op global dispatcher, which reports
/// `Interest::never()`, pinning the event as uninteresting for the rest of the
/// process, so the log-asserting siblings silently lose it. Run in parallel
/// (libtest's default) the tests raced to be that first registrant, which is why
/// the drop was intermittent rather than constant. Serializing them and running
/// every request under a live subscriber (below) guarantees the first
/// registration, and every one after it, resolves against a real capturing
/// dispatcher, so interest caches as enabled. Production installs a single
/// subscriber for the process lifetime and never hits this, so the coordination
/// lives only in the tests. `lock()` tolerates a poisoned guard so one failing
/// test cannot cascade into the rest.
static REQUEST_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Build a current-thread runtime and drive `body` to completion on this
/// thread, keeping request handling and its log events on the caller's thread.
fn block_on_current_thread<F: std::future::Future<Output = ()>>(body: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds")
        .block_on(body);
}

/// Run `body` under a fresh capturing subscriber installed on the current thread
/// and return everything it logged. Serialized against the other request-driving
/// tests via [`REQUEST_TEST_LOCK`].
fn with_captured_logs<F>(body: F) -> String
where
    F: std::future::Future<Output = ()>,
{
    let _guard = REQUEST_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let writer = CaptureWriter::new();
    let subscriber = ironauth_server::telemetry::build_subscriber(LogFormat::Json, writer.clone());
    tracing::subscriber::with_default(subscriber, || block_on_current_thread(body));
    writer.contents()
}

#[test]
fn zero_trust_ignores_forged_scheme_and_host_headers() {
    let logs = with_captured_logs(async {
        let server = server_from(ZERO_TRUST);
        // Config base URL is config-sourced regardless of headers.
        assert_eq!(server.base_url(), "http://id.example.test");
        let req = Request::builder()
            .uri("/")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "evil.example")
            .header("forwarded", "for=6.6.6.6;proto=https;host=evil.example")
            .body(Body::empty())
            .expect("request builds");
        let (status, _, _) = send(server.app(), req).await;
        assert_eq!(status, StatusCode::OK);
    });
    // The logged scheme is the config scheme, never the spoofed one.
    assert!(logs.contains("\"url.scheme\":\"http\""), "{logs}");
    assert!(
        !logs.contains("\"url.scheme\":\"https\""),
        "scheme must not follow X-Forwarded-Proto: {logs}"
    );
    // The client IP is the (unspecified) transport peer, not the forged one.
    assert!(!logs.contains("6.6.6.6"), "forged for= leaked: {logs}");
}

#[test]
fn one_trusted_hop_honors_only_the_correct_position() {
    // Exactly one forwarding entry: the single trusted proxy appended the real
    // client, which is honored.
    let honored = with_captured_logs(async {
        let server = server_from(ONE_TRUSTED_HOP);
        let req = Request::builder()
            .uri("/")
            .header("x-forwarded-for", "203.0.113.7")
            .body(Body::empty())
            .expect("request builds");
        let _ = send(server.app(), req).await;
    });
    assert!(
        honored.contains("\"client.ip\":\"203.0.113.7\""),
        "correct single hop must be honored: {honored}"
    );

    // A forged extra entry makes two, which does not match one trusted hop and
    // fails closed to the peer (0.0.0.0 in oneshot with no ConnectInfo).
    let failed = with_captured_logs(async {
        let server = server_from(ONE_TRUSTED_HOP);
        let req = Request::builder()
            .uri("/")
            .header("x-forwarded-for", "66.66.66.66, 203.0.113.7")
            .body(Body::empty())
            .expect("request builds");
        let _ = send(server.app(), req).await;
    });
    assert!(
        failed.contains("\"client.ip\":\"0.0.0.0\""),
        "spoofed extra hop must fail closed to the peer: {failed}"
    );
    assert!(
        !failed.contains("66.66.66.66"),
        "forged prefix must not be adopted: {failed}"
    );
}

#[test]
fn fail_closed_increments_the_rejection_counter() {
    let _guard = REQUEST_TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    // This test asserts on metrics, not logs, but it still drives a request
    // through the same middleware. Run it under a live subscriber (output
    // discarded) so the shared request-logging callsites are never registered
    // against the no-op dispatcher, which would poison the interest cache the
    // log-asserting siblings depend on. See [`REQUEST_TEST_LOCK`].
    let subscriber =
        ironauth_server::telemetry::build_subscriber(LogFormat::Json, CaptureWriter::new());
    tracing::subscriber::with_default(subscriber, || {
        block_on_current_thread(async {
            let server = server_from(ONE_TRUSTED_HOP);
            // Two entries against one trusted hop: ambiguous, fails closed.
            let req = Request::builder()
                .uri("/")
                .header("x-forwarded-for", "66.66.66.66, 203.0.113.7")
                .body(Body::empty())
                .expect("request builds");
            let (status, _, _) = send(server.app(), req).await;
            assert_eq!(status, StatusCode::OK);

            let (_, _, metrics) = get(server.management_app(), "/metrics").await;
            let value = counter_value(&metrics, "ironauth_proxy_forwarding_rejected_total");
            assert!(
                value >= 1.0,
                "fail-closed must increment the rejection counter, got {value}: {metrics}"
            );
        });
    });
}

/// Sum the values of every series whose name matches `metric` in Prometheus
/// exposition text.
fn counter_value(exposition: &str, metric: &str) -> f64 {
    exposition
        .lines()
        .filter(|line| line.starts_with(metric) && !line.starts_with('#'))
        .filter_map(|line| line.rsplit(' ').next())
        .filter_map(|value| value.parse::<f64>().ok())
        .sum()
}
