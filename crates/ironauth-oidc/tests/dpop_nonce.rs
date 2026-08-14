// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server-issued `DPoP` nonces at the token endpoint (RFC 9449 section 8, issue #124
//! acceptance criterion 1's challenge-retry item). Over a real database
//! (`DATABASE_URL`).
//!
//! # What a nonce buys
//!
//! Without one, a proof's freshness rests entirely on the client's own `iat` clock.
//! An attacker who obtains a proof has the whole freshness window to present it to a
//! server that has never seen it, and the `jti` replay cache cannot help, because to
//! THAT server it is not a replay. A server-issued nonce makes freshness the server's
//! own assertion instead: a proof minted before the challenge cannot echo a value the
//! server had not yet handed out.
//!
//! The policy is OFF by default, because enabling it costs every client a challenge
//! round trip and breaks any client that does not implement the retry. So the default
//! path is tested too: with the policy off, nothing here changes at all.

mod common;

use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, PKCE_VERIFIER, REDIRECT_URI, form, json, send_through};
use ironauth_config::OidcConfig;
use ironauth_jose::SigningKey;
use ironauth_jose::dpop_test_util::{sign_proof, sign_proof_with_nonce};

/// A harness whose token endpoint requires a server-issued nonce.
async fn nonce_harness() -> Harness {
    Harness::start_with(OidcConfig {
        require_dpop_nonce: true,
        require_pkce_for_confidential_clients: false,
        ..OidcConfig::default()
    })
    .await
}

fn proof_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("dpop-nonce".to_owned()), &[23_u8; 32]).expect("ed25519")
}

fn expected_htu() -> String {
    format!("{}/token", common::ISSUER_BASE)
}

fn now_secs(harness: &Harness) -> u64 {
    harness
        .state()
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `POST /token` redeeming `code` with a proof carrying `nonce` (or none), returning
/// the status, the `DPoP-Nonce` response header, and the body.
async fn redeem(
    harness: &Harness,
    code: &str,
    client_id: &str,
    nonce: Option<&str>,
    jti: &str,
) -> (StatusCode, Option<String>, String) {
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let proof = match nonce {
        Some(nonce) => sign_proof_with_nonce(
            &proof_key(),
            "POST",
            &expected_htu(),
            now_secs(harness),
            jti,
            nonce,
        ),
        None => sign_proof(
            &proof_key(),
            "POST",
            &expected_htu(),
            now_secs(harness),
            jti,
        ),
    };
    let request = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("DPoP", proof)
        .body(Body::from(body))
        .expect("request builds");
    let (status, headers, body) = send_through(harness.router(), request).await;
    let issued = headers
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    (status, issued, body)
}

/// THE flow: a first proof with no nonce is challenged, and the retry echoing the
/// issued nonce succeeds.
#[tokio::test]
async fn a_proof_without_a_nonce_is_challenged_and_the_retry_succeeds() {
    let harness = nonce_harness().await;
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;

    let (status, issued, body) = redeem(&harness, &code, &client, None, "jti-challenge").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "challenged: {body}");
    assert_eq!(json(&body)["error"], "use_dpop_nonce");
    let nonce = issued.expect("the challenge carries a DPoP-Nonce header");
    assert!(!nonce.is_empty(), "the challenge nonce is not empty");

    // The challenge did NOT burn the code: the retry redeems it. A challenge that
    // consumed the code would make the flow it is instructing the client to perform
    // impossible.
    let (status, _, body) = redeem(&harness, &code, &client, Some(&nonce), "jti-retry").await;
    assert_eq!(status, StatusCode::OK, "retry with the nonce: {body}");
    assert_eq!(json(&body)["token_type"], "DPoP");
}

/// A nonce this server never issued is refused, and answered with a fresh challenge
/// rather than a bare rejection, so a client that guessed can still recover.
#[tokio::test]
async fn a_nonce_the_server_never_issued_is_refused() {
    let harness = nonce_harness().await;
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;

    let (status, issued, body) = redeem(
        &harness,
        &code,
        &client,
        Some("a-nonce-this-server-never-minted"),
        "jti-forged",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "refused: {body}");
    assert_eq!(json(&body)["error"], "use_dpop_nonce");
    let fresh = issued.expect("a fresh nonce accompanies the refusal");

    // And the fresh one works, so the refusal was the forged value and nothing else.
    let (status, _, body) = redeem(&harness, &code, &client, Some(&fresh), "jti-recover").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the issued nonce is accepted: {body}"
    );
}

/// An absent nonce and an unrecognised one are answered IDENTICALLY (same status,
/// same error code), so the response is not an oracle for which nonces this instance
/// still holds.
#[tokio::test]
async fn absent_and_unrecognised_nonces_are_indistinguishable() {
    let harness = nonce_harness().await;
    let client = harness.client_id().to_string();
    let code_a = harness.issue_authenticated_code_pkce(&client).await;
    let code_b = harness.issue_authenticated_code_pkce(&client).await;

    let (status_absent, _, body_absent) = redeem(&harness, &code_a, &client, None, "jti-a").await;
    let (status_unknown, _, body_unknown) = redeem(
        &harness,
        &code_b,
        &client,
        Some("not-a-real-nonce"),
        "jti-b",
    )
    .await;

    assert_eq!(status_absent, status_unknown);
    assert_eq!(json(&body_absent)["error"], json(&body_unknown)["error"]);
    assert_eq!(
        json(&body_absent)["error_description"],
        json(&body_unknown)["error_description"]
    );
}

/// A nonce is NOT single use: RFC 9449 section 8 lets a client keep using one until
/// the server challenges again. Single-use would force a challenge before every
/// request, which is the behavior section 8 exists to avoid.
///
/// Proof replay is still refused, by the `jti` cache, which is the mechanism that
/// owns that job: the second redemption below carries a DIFFERENT `jti`.
#[tokio::test]
async fn one_nonce_serves_more_than_one_request() {
    let harness = nonce_harness().await;
    let client = harness.client_id().to_string();
    let first = harness.issue_authenticated_code_pkce(&client).await;

    let (_, issued, _) = redeem(&harness, &first, &client, None, "jti-get-nonce").await;
    let nonce = issued.expect("a challenge nonce");

    let (status, _, body) = redeem(&harness, &first, &client, Some(&nonce), "jti-use-1").await;
    assert_eq!(status, StatusCode::OK, "first use: {body}");

    let second = harness.issue_authenticated_code_pkce(&client).await;
    let (status, _, body) = redeem(&harness, &second, &client, Some(&nonce), "jti-use-2").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same nonce serves again: {body}"
    );
}

/// A nonce past its acceptance window is refused with a fresh challenge.
#[tokio::test]
async fn a_stale_nonce_is_challenged_again() {
    let harness = nonce_harness().await;
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;

    let (_, issued, _) = redeem(&harness, &code, &client, None, "jti-stale-get").await;
    let nonce = issued.expect("a challenge nonce");

    // Past the nonce TTL. The proof itself is re-signed at the advanced clock, so it
    // is FRESH: the only stale thing is the nonce, and the refusal is attributable to
    // it rather than to the proof's own iat window.
    harness.clock().advance(Duration::from_secs(600));

    let (status, issued_again, body) =
        redeem(&harness, &code, &client, Some(&nonce), "jti-stale-use").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "stale nonce refused: {body}"
    );
    assert_eq!(json(&body)["error"], "use_dpop_nonce");
    assert!(
        issued_again.is_some_and(|fresh| fresh != nonce),
        "the challenge carries a NEW nonce, not the stale one back"
    );
}

/// With the policy OFF (the shipped default) nothing changes: a proof with no nonce
/// is accepted and no challenge is ever issued.
///
/// The regression guard. Without it, challenging unconditionally would pass every
/// other test here while breaking every existing `DPoP` client on upgrade.
#[tokio::test]
async fn the_default_configuration_never_challenges() {
    assert!(
        !OidcConfig::default().require_dpop_nonce,
        "the shipped default must not require a nonce"
    );

    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;

    let (status, issued, body) = redeem(&harness, &code, &client, None, "jti-default").await;
    assert_eq!(status, StatusCode::OK, "unchanged by default: {body}");
    assert_eq!(json(&body)["token_type"], "DPoP");
    assert!(
        issued.is_none(),
        "no DPoP-Nonce header when the policy is off"
    );
}

/// With the policy off, a proof that volunteers a nonce is still accepted: the server
/// is not checking, so an unexpected value must be ignored rather than refused.
#[tokio::test]
async fn a_volunteered_nonce_is_ignored_when_the_policy_is_off() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;

    let (status, _, body) = redeem(
        &harness,
        &code,
        &client,
        Some("a-nonce-nobody-asked-for"),
        "jti-volunteered",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ignored, not refused: {body}");
}
