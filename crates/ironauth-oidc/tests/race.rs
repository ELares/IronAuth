// SPDX-License-Identifier: MIT OR Apache-2.0

//! The single-use concurrency race, against one shared Postgres.
//!
//! N concurrent `authorization_code` exchanges of the SAME code are fired at once
//! through routers sharing one store pool. The atomic consume (`UPDATE ... WHERE
//! consumed_at IS NULL RETURNING ...`) is the only serialization: exactly one
//! exchange sees the code unconsumed and returns 200, and the other N-1 see zero
//! rows and return `invalid_grant`. No in-memory marker is involved, so this is a
//! faithful stand-in for N stateless nodes racing on the same database.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, PKCE_VERIFIER, REDIRECT_URI, form, json, send_through};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_code_redeemed_concurrently_succeeds_exactly_once() {
    const RACERS: usize = 8;

    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // Issue one code.
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}",
        common::enc(REDIRECT_URI)
    );
    let (status, headers, body) = harness.authorize(&query).await;
    assert_eq!(status, StatusCode::FOUND, "authorize: {body}");
    let code = common::location_param(&headers, "code").expect("code");

    // The exchange body (identical for every racer).
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);

    // Fire RACERS concurrent exchanges at once. Each clones the router (sharing
    // the one store pool) and sends the same request.
    let mut tasks = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let router = harness.router();
        let exchange = exchange.clone();
        tasks.push(tokio::spawn(async move {
            let request = Request::builder()
                .method("POST")
                .uri("/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(exchange))
                .expect("request builds");
            send_through(router, request).await
        }));
    }

    let mut successes = 0_usize;
    let mut invalid_grants = 0_usize;
    for task in tasks {
        let (status, _headers, body) = task.await.expect("task joins");
        match status {
            StatusCode::OK => {
                successes += 1;
                // A success carries a real token pair.
                let value = json(&body);
                assert!(value["access_token"].is_string(), "success has a token");
                assert!(value["id_token"].is_string(), "success has an id token");
            }
            StatusCode::BAD_REQUEST => {
                invalid_grants += 1;
                assert_eq!(json(&body)["error"], "invalid_grant", "loser body: {body}");
            }
            other => panic!("unexpected status {other}: {body}"),
        }
    }

    assert_eq!(successes, 1, "exactly one concurrent exchange must succeed");
    assert_eq!(
        invalid_grants,
        RACERS - 1,
        "every other concurrent exchange must be invalid_grant"
    );
}
