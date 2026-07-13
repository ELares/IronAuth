// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adversarial destination controls, driven end to end through the connector.
//!
//! Every case proves the same two things: the fetch is refused with the uniform
//! [`FetchError::Blocked`], and the dialer is never invoked (the connection is
//! never attempted to a denied address). Both literal-IP URLs and hostnames that
//! RESOLVE to denied addresses are covered, across IPv4, IPv6, and the
//! IPv4-in-IPv6 forms including the cloud-metadata address.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ironauth_fetch::{
    FetchError, FetchLimits, FetchPurpose, FetchRequest, Fetcher, RecordingDialer, StaticResolver,
};

/// A dialer target that is never reached: these tests all block before dialing.
fn unused_target() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9))
}

/// Fetch `url` through a fetcher whose resolver returns `resolved` (empty for a
/// literal-IP URL, which skips resolution). Returns the result and the dialer so
/// the test can assert nothing was dialed.
async fn attempt(
    url: &str,
    answers: Vec<IpAddr>,
) -> (Result<(), FetchError>, Arc<RecordingDialer>) {
    let resolver = Arc::new(StaticResolver::new(answers));
    let dialer = Arc::new(RecordingDialer::new(unused_target()));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver, Arc::clone(&dialer));
    let request = FetchRequest::get(FetchPurpose::JwksUri, url).allow_plaintext_http();
    let result = fetcher.fetch(request).await.map(|_| ());
    (result, dialer)
}

/// The denied literal-IP targets, as URLs. Each must block before any dial.
const LITERAL_TARGETS: &[&str] = &[
    // IPv4 cloud metadata and private/loopback/special-use.
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://100.64.0.1/",
    "http://0.0.0.0/",
    "http://255.255.255.255/",
    "http://169.254.0.1/",
    // IPv6 loopback, link-local, unique-local, multicast.
    "http://[::1]/",
    "http://[fe80::1]/",
    "http://[fc00::1]/",
    "http://[fd00::1]/",
    "http://[ff02::1]/",
    // IPv4-mapped and IPv4-compatible IPv6 forms of denied addresses,
    // including the metadata address (the crux bypass).
    "http://[::ffff:169.254.169.254]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:10.0.0.1]/",
    "http://[::192.168.0.1]/",
];

#[tokio::test]
async fn literal_ip_targets_are_blocked_before_dialing() {
    for url in LITERAL_TARGETS {
        let (result, dialer) = attempt(url, Vec::new()).await;
        assert_eq!(result, Err(FetchError::Blocked), "{url} must be blocked");
        assert!(
            dialer.requested().is_empty(),
            "{url} must never be dialed, but dialer saw {:?}",
            dialer.requested()
        );
    }
}

/// The denied addresses to hand back from DNS for a benign-looking hostname.
const RESOLVED_TARGETS: &[&str] = &[
    "169.254.169.254",
    "127.0.0.1",
    "10.11.12.13",
    "172.31.255.255",
    "192.168.0.5",
    "100.127.0.1",
    "198.18.0.1",
    "::1",
    "fe80::5",
    "fc00::5",
    "ff02::5",
    "::ffff:169.254.169.254",
];

#[tokio::test]
async fn hostnames_resolving_to_denied_addresses_are_blocked() {
    for addr in RESOLVED_TARGETS {
        let ip: IpAddr = addr.parse().expect("test address");
        let resolver = Arc::new(StaticResolver::new(vec![ip]));
        let dialer = Arc::new(RecordingDialer::new(unused_target()));
        let fetcher = Fetcher::from_parts(
            FetchLimits::default(),
            Arc::clone(&resolver),
            Arc::clone(&dialer),
        );
        // A perfectly ordinary hostname; the danger is only in what it resolves
        // to, which is exactly the SSRF shape (attacker controls the name).
        let request = FetchRequest::get(FetchPurpose::JwksUri, "http://client.example/jwks.json")
            .allow_plaintext_http();
        let result = fetcher.fetch(request).await;
        assert_eq!(
            result.map(|_| ()),
            Err(FetchError::Blocked),
            "hostname resolving to {addr} must be blocked"
        );
        assert_eq!(resolver.calls(), 1, "the host is resolved exactly once");
        assert!(
            dialer.requested().is_empty(),
            "a host resolving to {addr} must never be dialed"
        );
    }
}

#[tokio::test]
async fn disallowed_scheme_is_refused_without_resolving() {
    let resolver = Arc::new(StaticResolver::new(vec![common::public_ip()]));
    let dialer = Arc::new(RecordingDialer::new(unused_target()));
    let fetcher = Fetcher::from_parts(
        FetchLimits::default(),
        Arc::clone(&resolver),
        Arc::clone(&dialer),
    );
    // Plaintext http without the opt-in is refused; and it is refused before any
    // resolution, so it leaks nothing either.
    let request = FetchRequest::get(FetchPurpose::Logo, "http://logo.example/a.png");
    let result = fetcher.fetch(request).await;
    assert_eq!(result.map(|_| ()), Err(FetchError::SchemeNotAllowed));
    assert_eq!(resolver.calls(), 0);
    assert!(dialer.requested().is_empty());
}

#[tokio::test]
async fn malformed_urls_are_invalid_requests() {
    let resolver = Arc::new(StaticResolver::new(Vec::new()));
    let dialer = Arc::new(RecordingDialer::new(unused_target()));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver, dialer);
    for url in [
        "ftp://example.com/",
        "not a url",
        "https://user:pw@example.com/",
    ] {
        let request = FetchRequest::get(FetchPurpose::ClientMetadata, url);
        let result = fetcher.fetch(request).await;
        assert!(
            matches!(result, Err(FetchError::InvalidRequest(_))),
            "{url} should be an invalid request, got {result:?}"
        );
    }
}
