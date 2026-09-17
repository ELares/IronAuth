// SPDX-License-Identifier: MIT OR Apache-2.0

//! With Postgres down, discovery and JWKS keep serving (issue #149, criterion 2).
//!
//! > With Postgres down, discovery, JWKS, and stateless access-token validation continue to
//! > serve, verified by the chaos suite.
//!
//! # Why the existing discovery tests do not answer this
//!
//! `tests/discovery.rs` is database-FREE by construction: it pre-populates an in-memory
//! registry and drives the router with no store at all. That shows discovery does not need a
//! database on a path where none exists. It cannot show what happens to a deployment whose
//! database WAS there and then went away, which is the tier this criterion is about, because
//! the registry in that deployment was loaded through a store and holds a handle to it.
//!
//! So this starts a store-backed harness, warms the surfaces a request would warm, and then
//! CLOSES THE POOL. Every later query fails the way a lost Postgres fails.
//!
//! # The control is the point
//!
//! A test that closes a pool and then asserts two endpoints still answer proves nothing unless
//! the pool really closed: a no-op `close` and a healthy database are indistinguishable from
//! the two assertions alone. So the SAME authorization is driven twice: once while the database
//! answers, where it must reach a code, and once after the close, where it must not. Without
//! that pair this test passes against a build where `close_pool_for_test` does nothing, which
//! is exactly the shape that makes a chaos suite decorative.
//!
//! IT TOOK THREE GOES TO GET THAT RIGHT, and the failures are worth recording because each one
//! looked like a working test. The first sent a bare
//! `/authorize?response_type=code&client_id=...` after the close and asserted it was not a
//! redirect -- but that request is a 400 on a HEALTHY database too, because it omits
//! `redirect_uri`, so it passed with the close neutered to a no-op. The second was the right
//! idea and never reached the file: `cargo fmt` had reflowed the block a scripted edit was
//! matching on, so the replacement silently did not apply and the old control stayed.
//!
//! The assertions it guards needed the same treatment. `warm_jwks.contains("keys")` is
//! satisfied by `{"keys":[]}`, so emptying the published key set left every row green -- the
//! before and the after agreed on nothing. The premise now requires a non-empty array.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{Harness, send_through};

/// `GET` a path on the harness router, returning the status and body.
async fn get(harness: &Harness, path: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("request builds");
    let (status, _headers, body) = send_through(harness.router(), request).await;
    (status, body)
}

/// One full authorization for the harness client, which cannot be answered without the store.
async fn authorize(harness: &Harness, cookie: &str) -> (StatusCode, String) {
    let client_id = harness.client_id().to_string();
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&scope={}",
        common::enc(common::REDIRECT_URI),
        common::enc("openid")
    );
    let (status, _headers, body) = harness.authorize_with_cookie(&query, cookie).await;
    (status, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_and_jwks_serve_after_the_database_goes_away() {
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let subject = harness.seed_unique_user().await;
    harness
        .grant_consent_scoped(&subject, &harness.client_id().to_string(), Some("openid"))
        .await;
    let cookie = harness.session_cookie(&subject).await;
    let discovery_path = format!(
        "/t/{}/e/{}/.well-known/openid-configuration",
        scope.tenant(),
        scope.environment()
    );
    let jwks_path = format!("/t/{}/e/{}/jwks.json", scope.tenant(), scope.environment());

    // WARMED FIRST, because that is what a running deployment has done. A node that has never
    // served either surface has nothing cached, and asserting about that node would be a
    // different claim -- a cold start against a dead database, which this criterion does not
    // make and which would fail.
    let (status, warm_discovery) = get(&harness, &discovery_path).await;
    assert_eq!(status, StatusCode::OK, "{warm_discovery}");
    let (status, warm_jwks) = get(&harness, &jwks_path).await;
    assert_eq!(status, StatusCode::OK, "{warm_jwks}");
    // NON-EMPTY, not merely present. `contains("keys")` is satisfied by `{"keys":[]}`, and a
    // mutation proved it: emptying the published set left every assertion in this test green,
    // because the before and after agreed on nothing.
    let published =
        serde_json::from_str::<serde_json::Value>(&warm_jwks).expect("the JWKS document is JSON");
    assert!(
        published["keys"]
            .as_array()
            .is_some_and(|keys| !keys.is_empty()),
        "the premise: this environment publishes at least one key, or the comparison below \
         compares two empty documents and holds whatever the outage does: {warm_jwks}"
    );

    // The live half of the control: the same request, before the close, DOES reach a code.
    let (status, body) = authorize(&harness, &cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "the premise: this authorization succeeds while the database answers: {body}"
    );

    harness.store().close_pool_for_test().await;

    // THE CONTROL, and the same request as the live half above.
    //
    // The first version sent one bare `/authorize?response_type=code&client_id` here and
    // asserted it was not a redirect. It passed with `close_pool_for_test` neutered to a no-op,
    // because that request is a 400 on a HEALTHY database too: it omits `redirect_uri`. A
    // control that fails for a reason unrelated to the thing under test measures nothing, and
    // reads as though it measured everything. Driving the request that SUCCEEDED above is what
    // makes the difference attributable to the close.
    let (status, body) = authorize(&harness, &cookie).await;
    assert_ne!(
        status,
        StatusCode::SEE_OTHER,
        "the control did not fail, so the database is still answering and this test measures \
         nothing: {status} {body}"
    );

    // AND THE TWO SURFACES THE CRITERION NAMES, unchanged.
    let (status, body) = get(&harness, &discovery_path).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "discovery must serve with the database gone: {body}"
    );
    assert_eq!(
        body, warm_discovery,
        "and serve the SAME document: a degraded tier that quietly drops advertised \
         capabilities is a different outage from the one this tier promises"
    );

    let (status, body) = get(&harness, &jwks_path).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "JWKS must serve with the database gone, or every stateless access-token validation \
         in the estate fails on its next key fetch: {body}"
    );
    assert_eq!(
        body, warm_jwks,
        "and publish the same keys: a JWKS that empties under a database outage revokes every \
         token in flight"
    );
}
