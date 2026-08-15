// SPDX-License-Identifier: MIT OR Apache-2.0

//! The scope-routed authorization endpoint (issue #128).
//!
//! `/t/{tenant}/e/{environment}/authorize` exists because a CIMD `client_id` is a URL and
//! declares no (tenant, environment), so the scope has to arrive somewhere the requester
//! cannot pick at will. That makes the path a security boundary rather than a routing
//! convenience, and what is asserted here is exactly that boundary:
//!
//! * the route behaves like the root route when the path names the client's own scope, so
//!   adding it changed nothing for existing clients;
//! * a client presented under a DIFFERENT scope's path is refused, because following the
//!   declared scope instead would make the path decoration and the route a cross-tenant
//!   read;
//! * the refusal is indistinguishable from an unknown client, so the route does not become
//!   an oracle for which tenants and environments exist.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::Harness;
use ironauth_store::Scope;

/// A minimal, well-formed authorization-code request for `client_id`.
fn query(client_id: &str) -> String {
    format!(
        "response_type=code&client_id={client_id}\
         &redirect_uri=https%3A%2F%2Fclient.test%2Fcb&scope=openid&state=s\
         &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
    )
}

fn scoped_path(scope: Scope, client_id: &str) -> String {
    format!(
        "/t/{}/e/{}/authorize?{}",
        scope.tenant(),
        scope.environment(),
        query(client_id)
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
async fn the_scoped_route_matches_the_root_route_for_a_client_in_its_own_scope() {
    // The additive claim. If this diverges, mounting the route changed behaviour for
    // clients that never asked for it.
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    let scope = harness.scope();

    let (root_status, root_body) = get(&harness, format!("/authorize?{}", query(&client_id))).await;
    let (scoped_status, scoped_body) = get(&harness, scoped_path(scope, &client_id)).await;

    assert_eq!(
        scoped_status, root_status,
        "the scoped route must not answer differently from the root route"
    );
    assert_eq!(scoped_body, root_body);
}

#[tokio::test]
async fn a_client_presented_under_another_environments_path_is_refused() {
    // The cross-scope case, within one tenant. The client_id is real and the path is
    // real; only the PAIRING is wrong, which is exactly the request an attacker sends.
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    let foreign = harness.second_scope().await;

    let (status, body) = get(&harness, scoped_path(foreign, &client_id)).await;

    assert_ne!(
        status,
        StatusCode::FOUND,
        "a mismatched scope must not reach the interaction redirect"
    );
    assert!(
        body.contains("malformed or unknown"),
        "expected the opaque unknown-client page, got: {body}"
    );
}

#[tokio::test]
async fn a_client_presented_under_another_tenants_path_is_refused() {
    // The same defect across a TENANT edge, which is the one that actually costs an
    // operator something.
    //
    // A mutation sweep is what pinned down what this case can and cannot claim. Weakening
    // the guard to compare only the ENVIRONMENT survives both this test and the one above,
    // and that is not a hole in the sweep: an `EnvironmentId` is a random 128-bit value, so
    // it already determines its tenant and the two comparisons cannot diverge. The case is
    // kept because it drives the edge an operator actually cares about, NOT because it
    // distinguishes a partial comparison from a total one. Nothing can, and a comment
    // claiming otherwise would be describing a test that does not exist.
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    let foreign = harness.provision_foreign_scope().await;
    assert_ne!(
        foreign.tenant(),
        harness.scope().tenant(),
        "the fixture must actually cross a tenant edge, or this test proves nothing"
    );

    let (status, body) = get(&harness, scoped_path(foreign, &client_id)).await;

    assert_ne!(status, StatusCode::FOUND);
    assert!(
        body.contains("malformed or unknown"),
        "expected the opaque unknown-client page, got: {body}"
    );
}

#[tokio::test]
async fn a_mismatched_scope_is_indistinguishable_from_an_unknown_client() {
    // If the two differed, the route would answer "this pairing is wrong" for a real
    // tenant and "no such client" otherwise, which enumerates the deployment.
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();
    let foreign = harness.second_scope().await;

    let (mismatch_status, mismatch_body) = get(&harness, scoped_path(foreign, &client_id)).await;
    let (unknown_status, unknown_body) = get(
        &harness,
        scoped_path(harness.scope(), "cli_definitely_not_real"),
    )
    .await;

    assert_eq!(mismatch_status, unknown_status);
    assert_eq!(
        mismatch_body, unknown_body,
        "a wrong pairing and an absent client must be one response"
    );
}

#[tokio::test]
async fn a_malformed_scope_in_the_path_is_refused_without_a_store_lookup() {
    let harness = Harness::start_store_backed().await;
    let client_id = harness.client_id().to_string();

    let (status, body) = get(
        &harness,
        format!(
            "/t/not-a-tenant/e/not-an-env/authorize?{}",
            query(&client_id)
        ),
    )
    .await;

    assert_ne!(status, StatusCode::FOUND);
    assert!(
        body.contains("malformed or unknown"),
        "expected the opaque page, got: {body}"
    );
}
