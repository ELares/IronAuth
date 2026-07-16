// SPDX-License-Identifier: MIT OR Apache-2.0

//! The HIBP k-anonymity request shape, proven on the wire (issue #63).
//!
//! A real [`HibpRangeProvider`] is driven through the SSRF-hardened fetcher's injected
//! dialer against an in-process loopback server that CAPTURES the exact request bytes.
//! The assertions are the acceptance-critical k-anonymity guarantee: only the 5-char
//! SHA-1 prefix ever crosses the wire, the full password and full hash never do, and the
//! padded-response request header is set. The response is a padded range that the
//! provider parses to screen the password as breached.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_screening::{
    BreachRangeProvider, FailurePolicy, HibpRangeProvider, ScreenOutcome, Screener, digest_password,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A loopback HTTP/1.1 server that records the first request it receives and answers
/// every request with a fixed range `body`. Returns its bound address and the shared
/// capture buffer.
async fn start_range_server(body: String) -> (SocketAddr, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let captured = Arc::new(Mutex::new(String::new()));
    let captured_server = Arc::clone(&captured);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let body = body.clone();
            let captured = Arc::clone(&captured_server);
            tokio::spawn(async move {
                let mut buf = [0_u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                // Record only the first request.
                {
                    let mut slot = captured.lock().expect("capture lock");
                    if slot.is_empty() {
                        *slot = request;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    (addr, captured)
}

/// A padded HIBP range body for the "password" prefix (5BAA6): the real matching suffix
/// with a high count, plus a zero-count padding decoy that must be stripped.
fn padded_body_for_password() -> String {
    "1E4C9B93F3F0682250B6CF8331B7EE68FD8:33288079\r\n\
     0000000000000000000000000000000000A:0\r\n"
        .to_owned()
}

#[tokio::test]
async fn only_the_five_char_prefix_crosses_the_wire() {
    let (addr, captured) = start_range_server(padded_body_for_password()).await;

    // Resolve the (fake) HIBP host to a public address so the SSRF policy admits it, then
    // pin the dial to the loopback server; the request rides plaintext http via the
    // testing constructor.
    let resolver = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let dialer = Arc::new(RecordingDialer::new(addr));
    let fetcher = Arc::new(Fetcher::from_parts(
        FetchLimits::default(),
        resolver,
        dialer,
    ));
    let provider = HibpRangeProvider::new_allow_http(fetcher, "http://range.hibp-mirror.test");

    let screener = Screener::new(
        Arc::new(provider) as Arc<dyn BreachRangeProvider>,
        FailurePolicy::FailClosed,
    );
    // "password" is the canonical HIBP breach; the padded range makes it a match.
    assert_eq!(screener.screen("password").await, ScreenOutcome::Breached);

    let request = captured.lock().expect("capture lock").clone();
    assert!(!request.is_empty(), "the server captured a request");

    // The request line targets /range/5BAA6 and NOTHING more of the hash.
    assert!(
        request.contains("GET /range/5BAA6 "),
        "request must target the 5-char prefix range path, got:\n{request}"
    );
    // The padded-response header is set.
    assert!(
        request.to_ascii_lowercase().contains("add-padding: true"),
        "the Add-Padding header must be sent, got:\n{request}"
    );
    // The full SHA-1 (prefix + suffix) NEVER appears on the wire: neither the 35-char
    // suffix nor the joined 40-char hash, nor the plaintext password.
    let digest = digest_password("password");
    let suffix_is_present = request
        .to_ascii_uppercase()
        .contains("1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    assert!(
        !suffix_is_present,
        "the SHA-1 suffix must never be sent, got:\n{request}"
    );
    assert!(
        !request.to_ascii_uppercase().contains("5BAA61E4"),
        "the full SHA-1 hash must never be sent, got:\n{request}"
    );
    assert!(
        !request.contains("password"),
        "the plaintext password must never be sent, got:\n{request}"
    );
    // Sanity: the prefix we sent is the digest's prefix.
    assert_eq!(digest.prefix().as_str(), "5BAA6");
}

#[tokio::test]
async fn a_clean_password_is_not_flagged_by_the_padded_range() {
    // The same padded range does NOT contain a fresh password's suffix, so it is allowed.
    let (addr, _captured) = start_range_server(padded_body_for_password()).await;
    let resolver = Arc::new(StaticResolver::new(vec![IpAddr::from([8, 8, 8, 8])]));
    let dialer = Arc::new(RecordingDialer::new(addr));
    let fetcher = Arc::new(Fetcher::from_parts(
        FetchLimits::default(),
        resolver,
        dialer,
    ));
    let provider = HibpRangeProvider::new_allow_http(fetcher, "http://range.hibp-mirror.test");
    let screener = Screener::new(
        Arc::new(provider) as Arc<dyn BreachRangeProvider>,
        FailurePolicy::FailClosed,
    );
    // A password whose prefix will not be 5BAA6 (so the server returns its fixed body, but
    // the suffix will not match): treated as not breached.
    assert_eq!(
        screener.screen("an-unbreached-passphrase-2026").await,
        ScreenOutcome::NotBreached
    );
}
