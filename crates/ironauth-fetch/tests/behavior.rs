// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transport behavior against a raw in-process server: redirects surface as
//! errors and are never followed, oversized bodies abort at the size cap, slow
//! responses abort at the time cap, and requests carry no ambient authority.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::Behavior;
use ironauth_fetch::{
    FetchError, FetchLimits, FetchPurpose, FetchRequest, Fetcher, RecordingDialer, StaticResolver,
};

/// Build a fetcher whose resolver returns the public sentinel and whose dialer
/// forwards to `server_addr`, with the given caps. Returns the fetcher and the
/// dialer for pin assertions.
fn fetcher_for(
    server_addr: std::net::SocketAddr,
    limits: FetchLimits,
) -> (Fetcher, Arc<RecordingDialer>) {
    let resolver = Arc::new(StaticResolver::new(vec![common::public_ip()]));
    let dialer = Arc::new(RecordingDialer::new(server_addr));
    let fetcher = Fetcher::from_parts(limits, resolver, Arc::clone(&dialer));
    (fetcher, dialer)
}

#[tokio::test]
async fn successful_fetch_returns_status_and_body_pinned_to_the_public_ip() {
    let server = common::start(Behavior::Body(b"{\"keys\":[]}".to_vec())).await;
    let (fetcher, dialer) = fetcher_for(server.addr, FetchLimits::default());

    let request = FetchRequest::get(FetchPurpose::JwksUri, "http://issuer.example/jwks.json")
        .allow_plaintext_http();
    let response = fetcher.fetch(request).await.expect("fetch succeeds");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.body(), b"{\"keys\":[]}");
    // The socket was pinned to the validated public address, not the loopback
    // the bytes were physically forwarded to.
    assert_eq!(dialer.requested()[0].ip(), common::public_ip());
}

#[tokio::test]
async fn a_redirect_to_a_private_address_is_returned_as_an_error_not_followed() {
    // The origin answers 302 with a Location pointing at the metadata service.
    let server = common::start(Behavior::Redirect("http://169.254.169.254/".to_owned())).await;
    let (fetcher, dialer) = fetcher_for(server.addr, FetchLimits::default());

    let request = FetchRequest::get(FetchPurpose::SectorIdentifier, "http://issuer.example/s")
        .allow_plaintext_http();
    let result = fetcher.fetch(request).await;

    assert_eq!(
        result.map(|_| ()),
        Err(FetchError::RedirectNotFollowed { status: 302 })
    );
    // Exactly one dial (the public origin); the redirect target is never dialed.
    assert_eq!(dialer.requested().len(), 1);
    assert_eq!(dialer.requested()[0].ip(), common::public_ip());
}

#[tokio::test]
async fn an_oversized_body_aborts_at_the_size_cap() {
    // The origin promises 100 KB; the cap is 1 KiB.
    let server = common::start(Behavior::Sized(100_000)).await;
    let limits = FetchLimits {
        max_response_bytes: 1024,
        total_timeout: Duration::from_secs(10),
    };
    let (fetcher, _dialer) = fetcher_for(server.addr, limits);

    let request = FetchRequest::get(FetchPurpose::ClientMetadata, "http://issuer.example/big")
        .allow_plaintext_http();
    let result = fetcher.fetch(request).await;

    assert_eq!(
        result.map(|_| ()),
        Err(FetchError::ResponseTooLarge { limit: 1024 })
    );
}

#[tokio::test]
async fn a_hanging_response_aborts_at_the_time_cap() {
    let server = common::start(Behavior::Hang).await;
    let limits = FetchLimits {
        max_response_bytes: 1 << 20,
        total_timeout: Duration::from_millis(200),
    };
    let (fetcher, _dialer) = fetcher_for(server.addr, limits);

    let request = FetchRequest::get(FetchPurpose::WebhookDelivery, "http://issuer.example/slow")
        .allow_plaintext_http();
    // An outer guard fails the test fast (rather than hanging on the server's
    // 60-second sleep) if the fetcher's own deadline does not fire. Time is
    // measured only by tokio's timer, never a raw clock read.
    let outcome = tokio::time::timeout(Duration::from_secs(5), fetcher.fetch(request)).await;
    let result = outcome.expect("the fetcher's own deadline fires well within 5s");

    assert_eq!(result.map(|_| ()), Err(FetchError::Timeout));
}

#[tokio::test]
async fn requests_carry_no_cookies_credentials_or_proxy_headers() {
    let server = common::start(Behavior::Body(b"ok".to_vec())).await;
    let (fetcher, _dialer) = fetcher_for(server.addr, FetchLimits::default());

    // A single, explicitly set header. The fetcher never adds a cookie jar, a
    // default Authorization, or any proxy header; and it never consults
    // HTTP_PROXY/NO_PROXY (the socket goes straight to the pinned address).
    let request = FetchRequest::get(FetchPurpose::JwksUri, "http://issuer.example/jwks.json")
        .allow_plaintext_http()
        .header(
            http::header::ACCEPT,
            http::HeaderValue::from_static("application/json"),
        );
    let response = fetcher.fetch(request).await.expect("fetch succeeds");
    assert_eq!(response.body(), b"ok");

    let heads = server.requests();
    assert_eq!(heads.len(), 1);
    let head = heads[0].to_ascii_lowercase();
    // The caller's header and the true Host are present...
    assert!(head.contains("accept: application/json"), "head: {head}");
    assert!(head.contains("host: issuer.example"), "head: {head}");
    // ...and nothing ambient is.
    for forbidden in ["cookie:", "authorization:", "proxy-", "set-cookie:"] {
        assert!(
            !head.contains(forbidden),
            "request must not carry {forbidden}: {head}"
        );
    }
}

#[tokio::test]
async fn the_dispatcher_owns_framing_and_strips_caller_framing_headers() {
    let server = common::start(Behavior::Body(b"ok".to_vec())).await;
    let (fetcher, _dialer) = fetcher_for(server.addr, FetchLimits::default());

    // A POST with a real 5-byte body, but a caller who tries to set a bogus
    // Content-Length, a conflicting Transfer-Encoding, a hop-by-hop Connection,
    // and a Proxy-* header. The dispatcher must strip all of those and let hyper
    // derive the true framing; legitimate headers (Content-Type) pass through.
    let request = FetchRequest::new(
        FetchPurpose::WebhookDelivery,
        http::Method::POST,
        "http://hook.example/deliver",
    )
    .allow_plaintext_http()
    .body("hello")
    .header(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_static("999"),
    )
    .header(
        http::header::TRANSFER_ENCODING,
        http::HeaderValue::from_static("chunked"),
    )
    .header(
        http::header::CONNECTION,
        http::HeaderValue::from_static("keep-alive"),
    )
    .header(
        http::HeaderName::from_static("proxy-authorization"),
        http::HeaderValue::from_static("Basic c2VjcmV0"),
    )
    .header(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    let response = fetcher.fetch(request).await.expect("fetch succeeds");
    assert_eq!(response.status().as_u16(), 200);

    let heads = server.requests();
    assert_eq!(heads.len(), 1);
    let head = heads[0].to_ascii_lowercase();
    // hyper's framing matches the actual body length, and the bogus values are
    // nowhere on the wire.
    assert!(head.contains("content-length: 5"), "head: {head}");
    assert!(!head.contains("999"), "bogus content-length leaked: {head}");
    assert!(
        !head.contains("chunked"),
        "transfer-encoding leaked: {head}"
    );
    assert!(!head.contains("keep-alive"), "connection leaked: {head}");
    assert!(!head.contains("proxy-"), "proxy header leaked: {head}");
    // A legitimate caller header still passes through.
    assert!(
        head.contains("content-type: application/json"),
        "head: {head}"
    );
}

#[tokio::test]
async fn caps_have_safe_defaults_and_are_configurable() {
    let defaults = FetchLimits::default();
    assert_eq!(
        defaults.max_response_bytes,
        1 << 20,
        "1 MiB body cap default"
    );
    assert_eq!(defaults.total_timeout, Duration::from_secs(10));

    // Configurable per the tunability principle.
    let custom = FetchLimits {
        max_response_bytes: 4096,
        total_timeout: Duration::from_secs(2),
    };
    assert_eq!(custom.max_response_bytes, 4096);
    assert_eq!(custom.total_timeout, Duration::from_secs(2));
}
