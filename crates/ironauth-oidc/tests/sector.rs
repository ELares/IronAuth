// SPDX-License-Identifier: MIT OR Apache-2.0

//! `sector_identifier_uri` validation (issue #19), database-free.
//!
//! Acceptance criterion 6: validation rejects `http` URLs, rejects documents
//! missing any registered redirect URI, and blocks SSRF targets (link-local,
//! private ranges) through the hardened fetcher. The SSRF cases drive the fetcher
//! through an injected resolver so no real network is touched.

use std::sync::Arc;

use ironauth_fetch::{FetchError, FetchLimits, Fetcher, RecordingDialer, StaticResolver};
use ironauth_oidc::{
    SectorError, check_sector_document, sector_uri_required, validate_sector_identifier,
};

/// The client's registered redirect URIs.
fn redirects() -> Vec<String> {
    vec![
        "https://a.example.test/cb".to_owned(),
        "https://b.example.test/cb".to_owned(),
    ]
}

/// A fetcher whose resolver maps every host to `resolves_to`, with a dialer that
/// forwards nowhere useful (a blocked destination never dials).
fn fetcher_resolving_to(resolves_to: &str) -> Fetcher {
    let resolver = Arc::new(StaticResolver::new(vec![resolves_to.parse().expect("ip")]));
    let dialer = Arc::new(RecordingDialer::new("127.0.0.1:9".parse().expect("addr")));
    Fetcher::from_parts(FetchLimits::default(), resolver, dialer)
}

#[tokio::test]
async fn http_sector_uri_is_rejected_before_any_fetch() {
    // A public sentinel resolver would let a fetch succeed, but the https-only
    // check fires first, so the network is never reached.
    let fetcher = fetcher_resolving_to("93.184.216.34");
    let result = validate_sector_identifier(
        &fetcher,
        "http://sector.example.test/uris.json",
        &redirects(),
    )
    .await;
    assert!(matches!(result, Err(SectorError::NotHttps)), "{result:?}");
}

#[tokio::test]
async fn link_local_metadata_target_is_blocked() {
    // The AWS/GCP metadata address: the hardened fetcher blocks it at resolution.
    let fetcher = fetcher_resolving_to("169.254.169.254");
    let result = validate_sector_identifier(
        &fetcher,
        "https://sector.example.test/uris.json",
        &redirects(),
    )
    .await;
    assert!(
        matches!(result, Err(SectorError::Fetch(FetchError::Blocked))),
        "metadata target must be blocked: {result:?}"
    );
}

#[tokio::test]
async fn private_range_target_is_blocked() {
    let fetcher = fetcher_resolving_to("10.0.0.5");
    let result = validate_sector_identifier(
        &fetcher,
        "https://sector.example.test/uris.json",
        &redirects(),
    )
    .await;
    assert!(
        matches!(result, Err(SectorError::Fetch(FetchError::Blocked))),
        "private-range target must be blocked: {result:?}"
    );
}

#[test]
fn document_must_list_every_registered_redirect_uri() {
    let redirects = redirects();
    // Complete document: valid.
    let complete = br#"["https://a.example.test/cb","https://b.example.test/cb"]"#;
    assert!(check_sector_document(complete, &redirects).is_ok());

    // Missing one redirect uri: rejected.
    let missing = br#"["https://a.example.test/cb"]"#;
    assert!(matches!(
        check_sector_document(missing, &redirects),
        Err(SectorError::MissingRedirectUri)
    ));

    // Not a JSON array of strings: rejected.
    assert!(matches!(
        check_sector_document(b"{\"a\":1}", &redirects),
        Err(SectorError::MalformedDocument)
    ));
}

#[test]
fn sector_uri_is_required_only_when_redirect_hosts_differ() {
    assert!(!sector_uri_required(&[
        "https://app.example.test/cb".to_owned(),
        "https://app.example.test/cb2".to_owned(),
    ]));
    assert!(sector_uri_required(&redirects()));
}
