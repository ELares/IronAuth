// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ACME directory client is confined to the SSRF-hardened fetch path (issue
//! #47).
//!
//! A custom domain's ACME CA URL is configuration and the validated domain is
//! tenant-controlled, so the ACME exchange is outbound and SSRF-adjacent. These
//! tests prove the directory fetch cannot be steered at internal infrastructure:
//! a directory URL that is (or resolves to) a loopback, private, or cloud-metadata
//! address is refused with the uniform [`AcmeError::Blocked`], and the dialer is
//! never invoked. Both a literal internal IP and a hostname that RESOLVES to an
//! internal address (the DNS-rebinding shape) are covered.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_oidc::{AcmeDirectoryClient, AcmeError};

/// A dialer target that must never be reached: every case blocks before dialing.
fn unused_target() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 9))
}

/// Build an ACME directory client whose fetcher resolves any hostname to
/// `answers` (empty for a literal-IP URL, which skips resolution), returning the
/// client and the recording dialer so a test can assert nothing was dialed.
fn client_resolving(answers: Vec<IpAddr>) -> (AcmeDirectoryClient, Arc<RecordingDialer>) {
    let resolver = Arc::new(StaticResolver::new(answers));
    let dialer = Arc::new(RecordingDialer::new(unused_target()));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver, Arc::clone(&dialer));
    // allow_http so the scheme opt-in is not what does the blocking; the SSRF
    // ADDRESS guard is what must refuse these, independent of the scheme.
    let client = AcmeDirectoryClient::new_allow_http(Arc::new(fetcher));
    (client, dialer)
}

#[tokio::test]
async fn a_literal_internal_ca_url_is_refused_before_dialing() {
    // Loopback, private, and the cloud-metadata address, all as literal-IP ACME
    // directory URLs: each must block with the uniform Blocked and never dial.
    for url in [
        "http://127.0.0.1/acme/directory",
        "http://10.0.0.1/directory",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/directory",
    ] {
        let (client, dialer) = client_resolving(Vec::new());
        let result = client.fetch_directory(url).await;
        assert_eq!(
            result,
            Err(AcmeError::Blocked),
            "{url} must be refused by the SSRF guard"
        );
        assert!(
            dialer.requested().is_empty(),
            "{url} must never be dialed, but the dialer saw {:?}",
            dialer.requested()
        );
    }
}

#[tokio::test]
async fn a_ca_hostname_resolving_to_loopback_is_refused() {
    // The DNS-rebinding shape: a public-looking CA hostname that resolves to a
    // loopback address. The guard acts on the RESOLVED address, so this is refused
    // exactly as a literal loopback is, and nothing is dialed.
    let (client, dialer) = client_resolving(vec![IpAddr::from([127, 0, 0, 1])]);
    let result = client
        .fetch_directory("https://ca.internal.example/acme/directory")
        .await;
    assert_eq!(result, Err(AcmeError::Blocked));
    assert!(
        dialer.requested().is_empty(),
        "a hostname resolving to loopback must never be dialed"
    );
}

#[tokio::test]
async fn the_metadata_address_mapped_into_ipv6_is_refused() {
    // The IPv4-in-IPv6 mapped form of the cloud-metadata address (a classic
    // bypass) is refused as a literal ACME directory URL.
    let (client, dialer) = client_resolving(Vec::new());
    let result = client
        .fetch_directory("http://[::ffff:169.254.169.254]/latest/meta-data/")
        .await;
    assert_eq!(result, Err(AcmeError::Blocked));
    assert!(dialer.requested().is_empty());
}
