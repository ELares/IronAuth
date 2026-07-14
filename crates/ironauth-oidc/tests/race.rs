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
use ironauth_jose::verify;
use ironauth_store::{IssuedTokenId, TokenStatus};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_code_redeemed_concurrently_succeeds_exactly_once() {
    const RACERS: usize = 8;

    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // Issue one code (as an authenticated, consenting subject). The public client
    // requires PKCE (issue #13), so bind the S256 challenge the exchange verifies.
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={}&code_challenge_method=S256",
        common::enc(REDIRECT_URI),
        common::PKCE_CHALLENGE,
    );
    let cookie = harness.authenticated_cookie().await;
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
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
    let mut winner_access = None;
    for task in tasks {
        let (status, _headers, body) = task.await.expect("task joins");
        match status {
            StatusCode::OK => {
                successes += 1;
                // A success carries a real token pair.
                let value = json(&body);
                assert!(value["access_token"].is_string(), "success has a token");
                assert!(value["id_token"].is_string(), "success has an id token");
                winner_access = Some(
                    value["access_token"]
                        .as_str()
                        .expect("access token string")
                        .to_owned(),
                );
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

    let winner = winner_access.expect("exactly one winner produced a token");
    assert_single_redeem_no_reuse(&harness, &client_id, &winner).await;
}

/// The losers all raced WITHIN the grace window (the manual clock is frozen at
/// issuance), so every one is a benign retry: exactly one redeem is audited, NO
/// reuse is audited, and the single winner's token is active. The concurrency
/// gate never mistakes a race for a reuse.
async fn assert_single_redeem_no_reuse(harness: &Harness, client_id: &str, winner_access: &str) {
    let audits = harness
        .store()
        .scoped(harness.scope())
        .audit()
        .list()
        .await
        .expect("audit list");
    assert_eq!(
        audits
            .iter()
            .filter(|r| r.action == "authorization_code.redeem")
            .count(),
        1,
        "exactly one redeem is audited across the whole race",
    );
    assert_eq!(
        audits
            .iter()
            .filter(|r| r.action == "authorization_code.reuse")
            .count(),
        0,
        "a concurrent within-grace race is never audited as a reuse",
    );

    let policy = harness.policy(client_id);
    let jti = verify(winner_access, &policy, &common::verify_clock())
        .expect("winner token verifies")
        .claims()
        .get("jti")
        .and_then(|v| v.as_str())
        .expect("jti claim")
        .to_owned();
    let jti_id = IssuedTokenId::parse_in_scope(&jti, &harness.scope()).expect("jti in scope");
    assert_eq!(
        harness
            .store()
            .scoped(harness.scope())
            .authorization()
            .token_status(&jti_id)
            .await
            .expect("token status"),
        TokenStatus::Active,
        "the winning exchange's token is active",
    );
}
