// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9449 section 10 `dpop_jkt`: binding an authorization CODE to a `DPoP` key at
//! the authorization request, before the token request exists (issue #124 acceptance
//! criterion 3). Over a real database (`DATABASE_URL`).
//!
//! # Why the code and not just the token
//!
//! Binding at the token endpoint alone constrains what a code is exchanged FOR. It
//! does not constrain WHO may exchange it, so an attacker who intercepts the code (a
//! redirect leak, a malicious app that claimed the redirect URI, a shoulder-surfed
//! URL) can still redeem it under a proof key of their own and receive a perfectly
//! valid token bound to themselves. `dpop_jkt` closes that: the code names its key
//! before it is ever issued, and the token endpoint refuses both a proof for a
//! different key AND a redemption carrying no proof at all, so the binding cannot be
//! dropped rather than matched.
//!
//! Both delivery paths are covered, because they are separate code paths reaching the
//! same seam: the parameter inline on `/authorize`, and pushed through the
//! authenticated back channel with PAR (RFC 9126), which is what section 10
//! recommends since a front-channel query parameter is visible to the browser.

mod common;

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
    send_through,
};
use ironauth_jose::SigningKey;
use ironauth_jose::dpop_test_util::{jkt_of, sign_proof};

/// The key the client commits to on the authorization request.
fn committed_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("dpop-committed".to_owned()), &[11_u8; 32]).expect("ed25519")
}

/// A DIFFERENT key, standing in for an attacker who intercepted the code and holds a
/// proof key of their own.
fn other_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("dpop-other".to_owned()), &[12_u8; 32]).expect("ed25519")
}

/// The deployment-root `token_endpoint` a compliant client signs its `htu` over.
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

/// Drive `/authorize` for a fresh consenting subject with EXTRA query parameters
/// appended, returning the redirect status, the `code` when one was issued, and the
/// `error` when one was returned.
async fn authorize_with(harness: &Harness, client_id: &str, extra: &str) -> (StatusCode, String) {
    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, client_id).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256{extra}",
        enc(REDIRECT_URI)
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    let param = location_param(&headers, "code")
        .or_else(|| location_param(&headers, "error"))
        .unwrap_or(body);
    (status, param)
}

/// A code issued with `dpop_jkt` committing to [`committed_key`].
async fn bound_code(harness: &Harness, client_id: &str) -> String {
    let jkt = jkt_of(&committed_key());
    let (status, code) =
        authorize_with(harness, client_id, &format!("&dpop_jkt={}", enc(&jkt))).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {code}");
    code
}

/// `POST /token` redeeming `code`, with zero or one `DPoP` proof headers.
async fn redeem(
    harness: &Harness,
    code: &str,
    client_id: &str,
    proof_key: Option<&SigningKey>,
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
    if let Some(key) = proof_key {
        let proof = sign_proof(key, "POST", &expected_htu(), now_secs(harness), jti);
        builder = builder.header("DPoP", proof);
    }
    let (status, _, body) = send_through(
        harness.router(),
        builder.body(Body::from(body)).expect("request builds"),
    )
    .await;
    (status, body)
}

/// A code bound by `dpop_jkt` is redeemable by a proof for THAT key, and the issued
/// token is bound to it.
#[tokio::test]
async fn a_committed_key_redeems_its_own_code() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let code = bound_code(&harness, &client).await;

    let (status, body) = redeem(&harness, &code, &client, Some(&committed_key()), "jti-ok").await;
    assert_eq!(status, StatusCode::OK, "committed key redeems: {body}");
    let doc = json(&body);
    // RFC 9449 section 5: the exchange is sender-constrained, so it advertises DPoP.
    assert_eq!(doc["token_type"], "DPoP");
}

/// THE criterion: a token request proving a DIFFERENT key is rejected.
///
/// This is the interception case. Without `dpop_jkt` the attacker's proof would be
/// accepted and the token bound to the attacker's own key.
#[tokio::test]
async fn a_different_key_cannot_redeem_a_bound_code() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let code = bound_code(&harness, &client).await;

    let (status, body) = redeem(&harness, &code, &client, Some(&other_key()), "jti-other").await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a foreign key must not redeem: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_dpop_proof");

    // The refusal did not burn the code: the legitimate client still redeems it. A
    // binding that let an attacker destroy the code would trade theft for denial of
    // service rather than fixing anything.
    let (status, body) = redeem(
        &harness,
        &code,
        &client,
        Some(&committed_key()),
        "jti-after",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the code survives the refusal: {body}"
    );
}

/// A bound code presented with NO proof is refused, rather than falling back to an
/// unbound bearer exchange.
///
/// The companion to the wrong-key case, and the more important one: if the binding
/// could simply be omitted, every attacker would omit it.
#[tokio::test]
async fn a_bound_code_cannot_be_redeemed_without_a_proof() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let code = bound_code(&harness, &client).await;

    let (status, body) = redeem(&harness, &code, &client, None, "unused").await;
    assert_ne!(status, StatusCode::OK, "a bound code needs a proof: {body}");
    assert_eq!(json(&body)["error"], "invalid_dpop_proof");
}

/// The same binding delivered through PAR (RFC 9126), which is the delivery RFC 9449
/// section 10 recommends because a front-channel parameter is visible to the browser.
///
/// A separate code path from the inline case: the parameter is validated at the push,
/// stored, and replayed when the `request_uri` is consumed.
#[tokio::test]
async fn a_pushed_dpop_jkt_binds_the_code_just_as_an_inline_one_does() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let jkt = jkt_of(&committed_key());

    let push = form(&[
        ("response_type", "code"),
        ("client_id", &client),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge", PKCE_CHALLENGE),
        ("code_challenge_method", "S256"),
        ("dpop_jkt", &jkt),
    ]);
    let (status, _, body) = harness.par(&push, None).await;
    assert_eq!(status, StatusCode::CREATED, "push: {body}");
    let request_uri = json(&body)["request_uri"]
        .as_str()
        .expect("request_uri")
        .to_owned();

    let subject = harness.seed_unique_user().await;
    harness.grant_consent(&subject, &client).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!("client_id={client}&request_uri={}", enc(&request_uri));
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize via PAR: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");

    // The pushed binding is enforced: a foreign key is refused...
    let (status, body) = redeem(
        &harness,
        &code,
        &client,
        Some(&other_key()),
        "jti-par-other",
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a foreign key must not redeem: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_dpop_proof");

    // ...and the committed key succeeds, so the refusal is the binding and not some
    // other failure in the PAR path.
    let (status, body) = redeem(
        &harness,
        &code,
        &client,
        Some(&committed_key()),
        "jti-par-ok",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "committed key redeems: {body}");
    assert_eq!(json(&body)["token_type"], "DPoP");
}

/// A malformed `dpop_jkt` is `invalid_request` rather than a code bound to a value no
/// key can ever match, which would surface as a confusing proof mismatch at redemption.
#[tokio::test]
async fn a_malformed_dpop_jkt_is_refused_at_the_request() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    for malformed in [
        "too-short",
        // A padded base64 thumbprint: the right bytes, the wrong encoding.
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I=",
        // Base64 rather than base64url: `+` and `/` are not in the alphabet.
        "0ZcOCORZNYy+DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
        "a space in the middle of a value of the right length ",
    ] {
        let (_, param) =
            authorize_with(&harness, &client, &format!("&dpop_jkt={}", enc(malformed))).await;
        assert_eq!(
            param, "invalid_request",
            "{malformed:?} must be refused as invalid_request"
        );
    }
}

/// A well-formed thumbprint that is nobody's key is ACCEPTED at the request and fails
/// at redemption.
///
/// Deliberate: the value is a public commitment, so possession cannot be checked here,
/// and refusing well-formed values would mean guessing. Binding a code to a key the
/// client cannot prove is the client's own mistake, and it fails closed.
#[tokio::test]
async fn a_well_formed_thumbprint_for_no_key_binds_and_then_fails_closed() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let nobodys_key = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    assert_eq!(
        nobodys_key.len(),
        43,
        "the fixture is a real thumbprint shape"
    );

    let (status, code) = authorize_with(
        &harness,
        &client,
        &format!("&dpop_jkt={}", enc(nobodys_key)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "accepted at the request: {code}"
    );

    let (status, body) = redeem(
        &harness,
        &code,
        &client,
        Some(&committed_key()),
        "jti-nobody",
    )
    .await;
    assert_ne!(status, StatusCode::OK, "no key can prove it: {body}");
    assert_eq!(json(&body)["error"], "invalid_dpop_proof");
}

/// With NO `dpop_jkt` the flow is unchanged: the code is unbound, and the token
/// endpoint's opportunistic binding still applies.
///
/// The regression guard. Without it, binding every code unconditionally would pass
/// every other test here while breaking every ordinary browser client.
#[tokio::test]
async fn an_authorization_request_without_dpop_jkt_is_unchanged() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let (status, code) = authorize_with(&harness, &client, "").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {code}");

    // No proof at all: a plain bearer exchange, exactly as before.
    let (status, body) = redeem(&harness, &code, &client, None, "unused").await;
    assert_eq!(status, StatusCode::OK, "unbound exchange: {body}");
    assert_eq!(json(&body)["token_type"], "Bearer");

    // And an unbound code accepts ANY key opportunistically, which is the RFC 9449
    // section 5 behavior `dpop_jkt` narrows rather than replaces.
    let (status, code) = authorize_with(&harness, &client, "").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {code}");
    let (status, body) = redeem(&harness, &code, &client, Some(&other_key()), "jti-any").await;
    assert_eq!(status, StatusCode::OK, "opportunistic binding: {body}");
    assert_eq!(json(&body)["token_type"], "DPoP");
}
