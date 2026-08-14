// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `DPoP`-by-default posture for PUBLIC clients (issue #124 acceptance criterion
//! 2, RFC 9449). Over a real database (`DATABASE_URL`).
//!
//! # The posture
//!
//! A public client is one that cannot keep a secret, so its tokens are the ones a
//! theft most directly monetizes and there is no client authentication standing
//! between an attacker and a refresh. Requiring a `DPoP` proof turns a stolen token
//! into one the thief cannot present. IronAuth makes that the DEFAULT, which is the
//! one step past every OSS peer this issue asks for, and bearer the exception.
//!
//! # Why the escape hatch exists, and why it is per client
//!
//! Some public clients cannot mint proofs: an embedded or TV runtime with no
//! `WebCrypto`, a vendor SDK the operator does not control, a native app shipped before
//! the operator adopted the posture. Without a way out, a deployment would have to
//! choose between abandoning the posture entirely and breaking those clients, and it
//! would choose the former. Per CLIENT rather than per deployment, because a
//! deployment-wide switch would have to be set for the weakest client and would then
//! silently relax every other client with it.
//!
//! # The fixture arrangement
//!
//! The shared harness RELAXES its seeded public client, because hundreds of suites
//! predate this posture and drive plain bearer exchanges to test something else. So
//! every strict client here is created explicitly, and the relaxed path is tested
//! against the seeded one. Both halves need covering: a posture that refused
//! everything would pass a strict-only suite.

mod common;

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, send_through};
use ironauth_jose::SigningKey;
use ironauth_jose::dpop_test_util::sign_proof;
use ironauth_store::ClientId;

fn proof_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("posture".to_owned()), &[41_u8; 32]).expect("ed25519")
}

fn token_htu() -> String {
    format!("{}/token", common::ISSUER_BASE)
}

fn now_secs(harness: &Harness) -> u64 {
    harness
        .state()
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A PUBLIC client under the strict posture: created fresh and left at the column
/// default, so nothing in the fixture relaxes it.
async fn strict_public_client(harness: &Harness) -> ClientId {
    harness
        .create_public_client_with_redirects("strict posture client", &[REDIRECT_URI])
        .await
}

/// Put `client` back under the strict posture. Every harness helper relaxes what it
/// creates (the convention this suite exists to work against), so a strict fixture has
/// to say so explicitly rather than rely on a default it does not control.
async fn make_strict(harness: &Harness, client: &ClientId) {
    harness.set_client_bearer_posture(client, false).await;
}

/// Drive authorize for `client_id` and return the code.
async fn code_for(harness: &Harness, client_id: &str) -> String {
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI)
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    common::location_param(&headers, "code").expect("code in redirect")
}

/// Redeem `code` for `client_id`, with or without a `DPoP` proof.
async fn redeem(
    harness: &Harness,
    code: &str,
    client_id: &str,
    with_proof: bool,
    jti: &str,
) -> (StatusCode, String) {
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let mut builder = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if with_proof {
        let proof = sign_proof(&proof_key(), "POST", &token_htu(), now_secs(harness), jti);
        builder = builder.header("DPoP", proof);
    }
    let (status, _, body) = send_through(
        harness.router(),
        builder.body(Body::from(body)).expect("request builds"),
    )
    .await;
    (status, body)
}

/// THE posture: a public client under the default gets NO bearer token.
#[tokio::test]
async fn a_strict_public_client_cannot_obtain_a_bearer_token() {
    let harness = Harness::start().await;
    let client = strict_public_client(&harness).await;
    make_strict(&harness, &client).await;
    let client = client.to_string();

    let code = code_for(&harness, &client).await;
    let (status, body) = redeem(&harness, &code, &client, false, "unused").await;
    assert_ne!(status, StatusCode::OK, "bearer must be refused: {body}");
    assert_eq!(json(&body)["error"], "invalid_dpop_proof");
}

/// The same client WITH a proof succeeds, so the refusal is the missing proof and not
/// something else about the fixture.
#[tokio::test]
async fn a_strict_public_client_succeeds_with_a_proof() {
    let harness = Harness::start().await;
    let client = strict_public_client(&harness).await;
    make_strict(&harness, &client).await;
    let client = client.to_string();

    let code = code_for(&harness, &client).await;
    let (status, body) = redeem(&harness, &code, &client, true, "jti-strict-ok").await;
    assert_eq!(status, StatusCode::OK, "a proof satisfies it: {body}");
    assert_eq!(json(&body)["token_type"], "DPoP");
}

/// The refusal does NOT burn the code: the client's retry with a proof still works.
///
/// Without this the posture would convert every un-upgraded client from "gets bearer
/// tokens" to "cannot authenticate at all even after fixing its code", because the
/// first attempt would consume the one-time code.
#[tokio::test]
async fn a_posture_refusal_leaves_the_code_live() {
    let harness = Harness::start().await;
    let client = strict_public_client(&harness).await;
    make_strict(&harness, &client).await;
    let client = client.to_string();

    let code = code_for(&harness, &client).await;
    let (status, _) = redeem(&harness, &code, &client, false, "unused").await;
    assert_ne!(status, StatusCode::OK);

    let (status, body) = redeem(&harness, &code, &client, true, "jti-retry").await;
    assert_eq!(status, StatusCode::OK, "the code survived: {body}");
}

/// A RELAXED public client keeps getting bearer tokens.
///
/// The escape hatch has to actually work, or the posture is not a default but a law,
/// and the deployments that cannot mint proofs would turn `DPoP` off wholesale.
#[tokio::test]
async fn a_relaxed_public_client_still_gets_bearer_tokens() {
    let harness = Harness::start().await;
    // The seeded client, which the harness relaxes.
    let client = harness.client_id().to_string();

    let code = code_for(&harness, &client).await;
    let (status, body) = redeem(&harness, &code, &client, false, "unused").await;
    assert_eq!(status, StatusCode::OK, "relaxed client: {body}");
    assert_eq!(json(&body)["token_type"], "Bearer");
}

/// A CONFIDENTIAL client is unaffected by the posture even at the strict default.
///
/// It authenticates on every token request, so the sender constraint a proof adds is
/// not the control protecting it. Requiring one would impose a round trip and a
/// key-management burden to defend something already defended.
#[tokio::test]
async fn a_confidential_client_is_unaffected_by_the_posture() {
    let harness = Harness::start().await;
    let (client_id, secret) = harness
        .create_confidential_client(ironauth_oidc::ClientAuthMethod::Basic)
        .await;
    // Explicitly strict, so this proves the posture SKIPS confidential clients rather
    // than that the fixture happened to be relaxed.
    make_strict(&harness, &client_id).await;
    let client = client_id.to_string();

    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client}&redirect_uri={}",
        enc(REDIRECT_URI)
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = common::location_param(&headers, "code").expect("code");

    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
    ]);
    let basic = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{client}:{secret}")
        )
    );
    let (status, _, body) = harness.token_with_auth(&exchange, Some(&basic)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a confidential client needs no proof: {body}"
    );
    assert_eq!(json(&body)["token_type"], "Bearer");
}

/// The posture holds on the REFRESH path too.
///
/// An unbound family reaches the permissive branch of the refresh `DPoP` check, so
/// without a posture gate there a public client could sidestep the rule entirely by
/// refreshing a family obtained before the posture was turned on: the exchange would
/// be constrained and every renewal after it would not.
#[tokio::test]
async fn the_posture_holds_on_the_refresh_path() {
    let harness = Harness::start().await;
    // Obtain an UNBOUND refresh token while the client is relaxed, exactly as a
    // deployment would have before turning the posture on.
    let client_id = strict_public_client(&harness).await;
    let client = client_id.to_string();
    let code = code_for(&harness, &client).await;
    let (status, body) = redeem(&harness, &code, &client, false, "unused").await;
    assert_eq!(status, StatusCode::OK, "relaxed exchange: {body}");
    let refresh = json(&body)["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_owned();

    // Now the operator turns the posture on for this client.
    make_strict(&harness, &client_id).await;

    let form_body = form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh),
        ("client_id", &client),
    ]);
    let (status, _, body) = harness.token(&form_body).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the grandfathered family must not renew as bearer: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_dpop_proof");
}
