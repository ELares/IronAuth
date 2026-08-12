// SPDX-License-Identifier: MIT OR Apache-2.0

//! Log sink delivery against a REAL socket, through the REAL outbound path (issue #110).
//!
//! Every other sink test uses a recording double, which proves what the shipper decides but
//! not what the outbound stack does with it. These drive the real sinks through the real
//! SSRF-hardened fetcher at a real loopback listener.
//!
//! # What this can and cannot reach, stated
//!
//! An audit export must not travel in cleartext, so the sinks send `https` and the fetcher
//! refuses a plaintext target unless a request opts in, which the sinks deliberately do not.
//! The test fetcher's TLS config trusts an EMPTY root store, so no loopback server
//! certificate can validate. That combination means a successful HTTPS body delivery is NOT
//! reachable from a unit test on this runner, and it is not faked here.
//!
//! What IS reachable, and what these cover: the sink's behaviour when its configured
//! endpoint is refused by the outbound policy, and that the refusal an operator reads names
//! the actual cause. The issue's containerized-receiver lane remains the honest place for a
//! body-level end-to-end check, and it stays open on the issue rather than being claimed
//! here.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ironauth_admin::log_shipper::{DatadogSink, HttpLogSink, LogSink, SinkOutcome, SplunkHecSink};
use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_store::log_stream::{LogStreamRecord, SinkType, StreamHealth, StreamSource};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// A listener that accepts and says nothing, so a connection attempt is REAL.
async fn idle_listener() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind a loopback listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        // Hold the listener open for the life of the test; accept and drop.
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });
    addr
}

/// A fetcher whose policy runs for real but whose socket lands on `target`.
fn fetcher_to(target: SocketAddr) -> Arc<Fetcher> {
    Arc::new(Fetcher::from_parts(
        FetchLimits::default(),
        // A public address, so destination validation performs its real checks rather than
        // being handed a loopback it would refuse outright for a different reason.
        Arc::new(StaticResolver::new(vec![IpAddr::from(Ipv4Addr::new(
            93, 184, 216, 34,
        ))])),
        Arc::new(RecordingDialer::new(target)),
    ))
}

fn stream(sink_type: SinkType, endpoint: &str) -> LogStreamRecord {
    LogStreamRecord {
        id: "lgs_e2e".to_string(),
        description: String::new(),
        source: StreamSource::Both,
        sink_type,
        sink_config: json!({ "endpoint": endpoint, "bucket": "audit", "region": "us-east-1" }),
        credential_secret_name: None,
        event_type_filter: None,
        organization_id: None,
        active: true,
        cursor: None,
        health: StreamHealth::default(),
    }
}

fn events() -> Vec<Value> {
    vec![json!({"class_uid": 3004, "activity_name": "client.create", "uid": "aud_1"})]
}

/// A plaintext endpoint is refused, and the refusal says WHY.
///
/// This is a configuration mistake, not a network one. Before this test the operator got
/// "the sink could not be reached", which sends them to look at their network for a problem
/// that is in their config, and quietly implies the export might work once the network is
/// fixed. It never would: an audit export in cleartext is refused by design.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plaintext_endpoint_is_refused_with_a_reason_that_names_the_scheme() {
    let addr = idle_listener().await;
    for (sink_type, sink) in [
        (
            SinkType::Http,
            Arc::new(HttpLogSink::new(fetcher_to(addr))) as Arc<dyn LogSink>,
        ),
        (
            SinkType::Datadog,
            Arc::new(DatadogSink::new(fetcher_to(addr))),
        ),
        (
            SinkType::SplunkHec,
            Arc::new(SplunkHecSink::new(fetcher_to(addr))),
        ),
    ] {
        let endpoint = format!("http://collector.example.test:{}/ingest", addr.port());
        let outcome = sink
            .deliver(&stream(sink_type, &endpoint), Some("token"), &events())
            .await;
        match outcome {
            SinkOutcome::Rejected(reason) => {
                assert!(
                    reason.contains("https"),
                    "{} must name the scheme so the operator fixes the config rather than \
                     the network: {reason}",
                    sink_type.as_str()
                );
                assert!(
                    !reason.contains("could not be reached"),
                    "{} reported a configuration mistake as a connectivity one: {reason}",
                    sink_type.as_str()
                );
            }
            SinkOutcome::Accepted => panic!(
                "{} accepted a cleartext endpoint, which would export the audit trail in \
                 the clear",
                sink_type.as_str()
            ),
        }
    }
}

/// An https endpoint reaches the REAL transport and fails there, not in the policy.
///
/// The distinction matters: it proves the sinks are refused for the scheme above because of
/// the scheme, and not because every request from this harness is blocked before dialing.
/// Without this, the test above would pass for a fetcher that refuses everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_https_endpoint_gets_past_the_policy_and_fails_at_the_transport() {
    let addr = idle_listener().await;
    let sink = HttpLogSink::new(fetcher_to(addr));
    let endpoint = format!("https://collector.example.test:{}/ingest", addr.port());
    let outcome = sink
        .deliver(&stream(SinkType::Http, &endpoint), None, &events())
        .await;
    match outcome {
        SinkOutcome::Rejected(reason) => {
            assert!(
                !reason.contains("https"),
                "an https endpoint must not be refused for its scheme: {reason}"
            );
            // The TLS handshake fails against a bare TCP listener under an empty root
            // store, which is a TRANSPORT outcome. That is as far as this runner reaches.
            assert!(
                reason.contains("could not be reached") || reason.contains("timed out"),
                "the failure must come from the transport, which is what proves the \
                 request left the policy: {reason}"
            );
        }
        SinkOutcome::Accepted => {
            panic!("a bare TCP listener cannot complete a TLS handshake, so this cannot pass")
        }
    }
}
