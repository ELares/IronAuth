// SPDX-License-Identifier: MIT OR Apache-2.0

//! The DNS-rebinding crux: a record that flips between the validation lookup and
//! a (hypothetical) connect-time lookup must not be able to move the connection
//! to a private address.
//!
//! The connector resolves exactly once and pins the connection to a validated
//! address by value, so there is no connect-time lookup for a flipped record to
//! poison. The two tests here prove both halves of the defense: the pin means a
//! record that would return a private address on a second lookup is never
//! consulted a second time, and a single answer that already contains a private
//! address blocks the whole fetch.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use common::Behavior;
use ironauth_fetch::{
    FetchError, FetchLimits, FetchPurpose, FetchRequest, Fetcher, RecordingDialer,
    SequenceResolver, StaticResolver,
};

const METADATA: &str = "169.254.169.254";

#[tokio::test]
async fn pin_defeats_a_record_that_rebinds_to_a_private_address() {
    // The server the validated public address forwards to.
    let server = common::start(Behavior::Body(b"jwks".to_vec())).await;

    // The resolver would answer PUBLIC first (passes validation) and PRIVATE on
    // a second lookup. A naive client that re-resolves at connect time would
    // dial the metadata service; this one must not.
    let resolver = Arc::new(SequenceResolver::new(vec![
        vec![common::public_ip()],
        vec![METADATA.parse().expect("metadata ip")],
    ]));
    let dialer = Arc::new(RecordingDialer::new(server.addr));
    let fetcher = Fetcher::from_parts(
        FetchLimits::default(),
        Arc::clone(&resolver),
        Arc::clone(&dialer),
    );

    let request = FetchRequest::get(FetchPurpose::JwksUri, "http://rebind.example/jwks.json")
        .allow_plaintext_http();
    let response = fetcher.fetch(request).await.expect("public path succeeds");
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.body(), b"jwks");

    // The host was resolved exactly once: the flipped second answer was never
    // consulted, so the private address never had a chance to be reached.
    assert_eq!(resolver.calls(), 1, "resolved exactly once");

    // The connection was pinned to the validated PUBLIC address, never the
    // private one.
    let attempts = dialer.requested();
    assert_eq!(attempts.len(), 1, "exactly one dial");
    assert_eq!(
        attempts[0].ip(),
        common::public_ip(),
        "pinned to the public IP"
    );
    let private: IpAddr = METADATA.parse().unwrap();
    assert!(
        attempts
            .iter()
            .all(|addr: &SocketAddr| addr.ip() != private),
        "the private address is never dialed"
    );
}

#[tokio::test]
async fn a_single_answer_containing_a_private_address_blocks_the_whole_fetch() {
    // The multi-record rebinding variant: one answer holds both a public and a
    // private address. Validating EVERY address means the private one blocks the
    // whole fetch; the connection is never attempted.
    let server = common::start(Behavior::Body(b"never served".to_vec())).await;
    let resolver = Arc::new(StaticResolver::new(vec![
        common::public_ip(),
        METADATA.parse().expect("metadata ip"),
    ]));
    let dialer = Arc::new(RecordingDialer::new(server.addr));
    let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver, Arc::clone(&dialer));

    let request = FetchRequest::get(FetchPurpose::JwksUri, "http://multi.example/jwks.json")
        .allow_plaintext_http();
    let result = fetcher.fetch(request).await;
    assert_eq!(result.map(|_| ()), Err(FetchError::Blocked));
    assert!(
        dialer.requested().is_empty(),
        "a set containing a private address is never dialed"
    );
}
