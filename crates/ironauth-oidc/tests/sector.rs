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
    SectorError, check_sector_document, resolve_pairwise_sector, sector_uri_required,
    validate_sector_identifier,
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

#[test]
fn ports_and_dns_case_do_not_split_a_sector_host() {
    assert!(
        !sector_uri_required(&[
            "https://APP.example.test/cb".to_owned(),
            "https://app.example.test:8443/other".to_owned(),
            "http://app.example.test:8080/local".to_owned(),
        ]),
        "Core 8.1 uses the host component, not the HTTP Host header"
    );
    assert!(sector_uri_required(&[
        "https://app.example.test:8443/cb".to_owned(),
        "https://other.example.test:8443/cb".to_owned(),
    ]));
}

#[tokio::test]
async fn inferred_sector_is_the_host_and_never_needs_network() {
    let fetcher = fetcher_resolving_to("169.254.169.254");
    let sector = resolve_pairwise_sector(
        &fetcher,
        None,
        &[
            "https://APP.example.test:8443/cb".to_owned(),
            "https://app.example.test:9443/other".to_owned(),
        ],
    )
    .await
    .unwrap();
    assert_eq!(sector, "app.example.test");
}

#[tokio::test]
async fn every_redirect_must_supply_the_same_host_for_inference() {
    let fetcher = fetcher_resolving_to("169.254.169.254");
    for uris in [
        vec![],
        vec!["com.example.app:/callback".to_owned()],
        vec![
            "https://a.example.test/cb".to_owned(),
            "com.example.app:/callback".to_owned(),
        ],
        redirects(),
    ] {
        assert!(sector_uri_required(&uris));
        assert!(matches!(
            resolve_pairwise_sector(&fetcher, None, &uris).await,
            Err(SectorError::SectorUriRequired)
        ));
    }
}

#[tokio::test]
async fn an_explicit_sector_is_validated_even_for_a_single_redirect_host() {
    let fetcher = fetcher_resolving_to("169.254.169.254");
    let redirects = vec!["https://app.example.test/cb".to_owned()];
    assert!(matches!(
        resolve_pairwise_sector(
            &fetcher,
            Some("http://sector.example.test/uris.json"),
            &redirects
        )
        .await,
        Err(SectorError::NotHttps)
    ));
    assert!(matches!(
        resolve_pairwise_sector(
            &fetcher,
            Some("https://sector.example.test/uris.json"),
            &redirects
        )
        .await,
        Err(SectorError::Fetch(FetchError::Blocked))
    ));
}

#[tokio::test]
async fn explicit_sector_uses_its_own_host_after_a_real_tls_document_check() {
    use ironauth_fetch::{TestTlsIdentity, TestTlsTarget};
    let identity = TestTlsIdentity::generate("sector.example.test");
    let target = TestTlsTarget::start(
        &identity,
        200,
        br#"["https://a.example.test/cb","https://b.example.test/cb"]"#.to_vec(),
    )
    .await;
    let fetcher = Fetcher::from_parts_trusting(
        FetchLimits::default(),
        Arc::new(StaticResolver::new(vec!["93.184.216.34".parse().unwrap()])),
        Arc::new(RecordingDialer::new(target.addr)),
        &identity.root_der,
    );
    assert_eq!(
        resolve_pairwise_sector(
            &fetcher,
            Some("https://sector.example.test:8443/uris.json"),
            &redirects()
        )
        .await
        .unwrap(),
        "sector.example.test"
    );
    let mut missing = redirects();
    missing.push("https://unlisted.example.test/cb".to_owned());
    assert!(matches!(
        resolve_pairwise_sector(
            &fetcher,
            Some("https://sector.example.test:8443/uris.json"),
            &missing
        )
        .await,
        Err(SectorError::MissingRedirectUri)
    ));
    assert_eq!(
        target.received().len(),
        2,
        "each registration validates the document"
    );
}

#[tokio::test]
async fn explicit_and_inferred_ipv6_hosts_have_identical_canonical_sectors() {
    use ironauth_fetch::{TestTlsIdentity, TestTlsTarget};
    let identity = TestTlsIdentity::generate("2001:4860::8888");
    let redirects = vec!["https://[2001:4860::8888]/cb".to_owned()];
    let target =
        TestTlsTarget::start(&identity, 200, serde_json::to_vec(&redirects).unwrap()).await;
    let fetcher = Fetcher::from_parts_trusting(
        FetchLimits::default(),
        Arc::new(StaticResolver::new(vec![
            "2001:4860::8888".parse().unwrap(),
        ])),
        Arc::new(RecordingDialer::new(target.addr)),
        &identity.root_der,
    );
    let inferred = resolve_pairwise_sector(&fetcher, None, &redirects)
        .await
        .unwrap();
    let explicit = resolve_pairwise_sector(
        &fetcher,
        Some("https://[2001:4860:0:0:0:0:0:8888]:8443/uris.json"),
        &redirects,
    )
    .await
    .unwrap();
    assert_eq!(explicit, inferred);
    assert_eq!(explicit, "[2001:4860::8888]");
    assert_eq!(target.received().len(), 1);
}
