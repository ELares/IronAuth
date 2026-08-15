// SPDX-License-Identifier: MIT OR Apache-2.0

//! A URL `client_id` reaching the authorization endpoint (issue #128).
//!
//! The unit tests in `cimd.rs` prove the resolver's ordering against a fake source. This
//! file proves the COMPOSITION: that the scope-routed authorize endpoint actually reaches
//! that resolver, that the feature gate really gates it, and that a resolved CIMD client
//! carries the quarantine posture the issue specifies rather than a registered client's.
//!
//! What is deliberately NOT asserted here is a completed code flow. That needs a logged-in
//! session, and the interaction redirect is the observable that separates "the client
//! resolved" from "the client was refused", which is exactly the boundary these cases sit
//! on.

mod common;

use std::sync::Arc;
use std::sync::Mutex;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::Harness;
use ironauth_oidc::cimd::{CimdDocumentSource, CimdFetchFuture, CimdResponse};
use ironauth_store::Scope;

const CIMD_URL: &str = "https://app.example/client-metadata.json";

/// A source that serves one document and records every URL it was asked for, so a test can
/// assert a fetch did NOT happen.
struct Serving {
    body: Vec<u8>,
    calls: Mutex<Vec<String>>,
}

impl Serving {
    fn new(client_id: &str) -> Arc<Self> {
        let body = serde_json::to_vec(&serde_json::json!({
            "client_id": client_id,
            "client_name": "Metadata Document Client",
            "redirect_uris": ["https://app.example/cb"],
        }))
        .expect("document serializes");
        Arc::new(Self {
            body,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.calls.lock().expect("calls").len()
    }
}

impl CimdDocumentSource for Serving {
    fn get<'a>(&'a self, url: &'a str) -> CimdFetchFuture<'a> {
        self.calls.lock().expect("calls").push(url.to_owned());
        let response = CimdResponse {
            final_url: url.to_owned(),
            body: self.body.clone(),
            max_age: None,
        };
        Box::pin(async move { Ok(response) })
    }
}

fn scoped_authorize(scope: Scope, client_id: &str) -> String {
    let encoded: String = client_id
        .chars()
        .map(|c| match c {
            ':' => "%3A".to_owned(),
            '/' => "%2F".to_owned(),
            other => other.to_string(),
        })
        .collect();
    format!(
        "/t/{}/e/{}/authorize?response_type=code&client_id={encoded}\
         &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid&state=s\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
        scope.tenant(),
        scope.environment()
    )
}

async fn get(harness: &Harness, uri: String) -> (StatusCode, String) {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    let (status, _headers, body) = harness.send(request).await;
    (status, body)
}

#[tokio::test]
async fn a_url_client_id_is_an_unknown_client_while_the_feature_is_off() {
    // The default posture. Off by default is criterion 4, and this is what "off" has to
    // mean on the wire: not a different error, not a hint, just an unknown client.
    let harness = Harness::start_store_backed().await;

    let (status, body) = get(&harness, scoped_authorize(harness.scope(), CIMD_URL)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body.contains("malformed or unknown"),
        "expected the opaque unknown-client page, got: {body}"
    );
}

#[tokio::test]
async fn nothing_is_dereferenced_while_the_feature_is_off() {
    // Stronger than the error check above, and the one that matters: with the feature off
    // the server must not make the request AT ALL. An implementation that fetched first
    // and refused afterwards would pass the previous test and still hand an unregistered
    // party the use of the server's network position.
    let harness = Harness::start_store_backed().await;
    let source = Serving::new(CIMD_URL);
    // Deliberately NOT armed: the source is built but never installed.

    let _ = get(&harness, scoped_authorize(harness.scope(), CIMD_URL)).await;

    assert_eq!(
        source.calls(),
        0,
        "the feature is off, so no document may be fetched"
    );
}

#[tokio::test]
async fn an_installed_source_is_not_reachable_until_the_feature_is_armed() {
    // The acknowledgment gate, on its own. A mutation sweep found that the earlier
    // feature-off cases could not see it: with no source installed, a URL client_id is
    // refused for want of a source whether or not the flag is set, so forcing the flag on
    // left every test green. Installing the source and leaving the surface UNARMED is the
    // only state where the gate is the thing doing the refusing.
    //
    // What it protects is criterion 4: the draft is unstable, and an operator who has not
    // acknowledged the pinned revision must not have the server dereferencing
    // attacker-chosen URLs. Losing this check would make the acknowledgment decorative.
    let mut harness = Harness::start_store_backed().await;
    let source = Serving::new(CIMD_URL);
    harness.install_cimd_source_unarmed(Arc::clone(&source) as Arc<dyn CimdDocumentSource>);

    let (status, body) = get(&harness, scoped_authorize(harness.scope(), CIMD_URL)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("malformed or unknown"), "{body}");
    assert_eq!(
        source.calls(),
        0,
        "an unacknowledged deployment must not dereference, even with a source installed"
    );
}

#[tokio::test]
async fn an_armed_deployment_resolves_a_url_client_id_and_fetches_its_document() {
    let mut harness = Harness::start_store_backed().await;
    let source = Serving::new(CIMD_URL);
    harness.enable_cimd(
        Arc::clone(&source) as Arc<dyn CimdDocumentSource>,
        vec![],
        vec![],
    );

    let (status, body) = get(&harness, scoped_authorize(harness.scope(), CIMD_URL)).await;

    assert_eq!(
        source.calls(),
        1,
        "the document must be fetched exactly once"
    );
    assert!(
        !body.contains("malformed or unknown"),
        "the client resolved, so it must not render the unknown-client page: {body}"
    );
    assert_ne!(
        status,
        StatusCode::BAD_REQUEST,
        "a resolved CIMD client must get past the client check"
    );
}

#[tokio::test]
async fn a_deny_listed_domain_is_refused_without_the_server_making_a_request() {
    // The ordering property, asserted through the endpoint rather than only against the
    // resolver. A test that checked the error alone would pass just as happily if the
    // request went out first and the deny list were consulted afterwards.
    let mut harness = Harness::start_store_backed().await;
    let source = Serving::new(CIMD_URL);
    harness.enable_cimd(
        Arc::clone(&source) as Arc<dyn CimdDocumentSource>,
        vec![],
        vec!["app.example".to_owned()],
    );

    let (status, body) = get(&harness, scoped_authorize(harness.scope(), CIMD_URL)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("malformed or unknown"), "{body}");
    assert_eq!(
        source.calls(),
        0,
        "a deny-listed domain must not get the use of the server's network position"
    );
}

#[tokio::test]
async fn a_document_that_does_not_name_itself_is_refused() {
    // The document claims a different client_id than the URL it was served from. Without
    // this, one URL serves a document claiming another party's identity.
    let mut harness = Harness::start_store_backed().await;
    let source = Serving::new("https://other.example/client-metadata.json");
    harness.enable_cimd(
        Arc::clone(&source) as Arc<dyn CimdDocumentSource>,
        vec![],
        vec![],
    );

    let (status, body) = get(&harness, scoped_authorize(harness.scope(), CIMD_URL)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("malformed or unknown"), "{body}");
    assert_eq!(source.calls(), 1);
}

#[tokio::test]
async fn a_url_client_id_is_still_unknown_at_the_deployment_root() {
    // CIMD is reachable ONLY on the scope-routed mount, because a URL declares no
    // (tenant, environment) and the root has nowhere else to learn one. Arming the feature
    // must not quietly make the root accept URLs.
    let mut harness = Harness::start_store_backed().await;
    let source = Serving::new(CIMD_URL);
    harness.enable_cimd(
        Arc::clone(&source) as Arc<dyn CimdDocumentSource>,
        vec![],
        vec![],
    );

    let encoded = CIMD_URL.replace(':', "%3A").replace('/', "%2F");
    let (status, body) = get(
        &harness,
        format!(
            "/authorize?response_type=code&client_id={encoded}\
             &redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid&state=s"
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("malformed or unknown"), "{body}");
    assert_eq!(
        source.calls(),
        0,
        "the root mount must not dereference anything"
    );
}
