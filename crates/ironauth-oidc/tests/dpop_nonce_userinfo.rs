// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server-issued `DPoP` nonces at the PROTECTED RESOURCE (`GET /userinfo`, RFC 9449
//! section 8, issue #124). Over a real database (`DATABASE_URL`).
//!
//! The companion to the token-endpoint half. The mechanism is shared (one nonce
//! store, one `DPoP-Nonce` header constant) but the wire shape is NOT: a token
//! endpoint challenges with a `400` and a JSON `use_dpop_nonce` body, while a
//! protected resource challenges with a `401` and a `DPoP`-scheme
//! `WWW-Authenticate` naming `use_dpop_nonce`. Both must work, and a client that
//! already holds a nonce from one must be able to spend it at the other, which is
//! what sharing the store buys.
//!
//! The policy is OFF by default, so the default path is pinned here too.

mod common;

use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, SEED_PASSWORD, enc, form, json,
    location_param,
};
use ironauth_config::OidcConfig;
use ironauth_jose::SigningKey;
use ironauth_jose::access_token_hash;
use ironauth_jose::dpop_test_util::{sign_proof, sign_proof_with_ath, sign_proof_with_ath_nonce};

const CLAIMS_JSON: &str = r#"{ "name": "Ada Lovelace", "email": "ada@example.test" }"#;

fn proof_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("dpop-nonce-rs".to_owned()), &[31_u8; 32]).expect("ed25519")
}

fn token_htu() -> String {
    format!("{}/token", common::ISSUER_BASE)
}

fn userinfo_htu() -> String {
    format!("{}/userinfo", common::ISSUER_BASE)
}

fn now_secs(harness: &Harness) -> u64 {
    harness
        .state()
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn unique_identifier(harness: &Harness) -> String {
    format!("nonce-rs-{}@example.test", harness.fresh_ed25519_seed()[0])
}

/// A harness whose deployment requires a server-issued nonce.
async fn nonce_harness() -> Harness {
    nonce_harness_with_token_ttl(OidcConfig::default().access_token_ttl_secs).await
}

/// The same, with an explicit access-token lifetime.
///
/// The shipped default is 300 seconds, which is EXACTLY the nonce TTL. Any test that
/// advances the clock past the nonce window therefore expires the access token at the
/// same instant, and `userinfo` answers `invalid_token` before it ever reaches the
/// nonce check: the assertion would pass or fail for the wrong reason. A staleness
/// test has to outlive its own credential to say anything about staleness.
async fn nonce_harness_with_token_ttl(access_token_ttl_secs: u64) -> Harness {
    Harness::start_with(OidcConfig {
        require_dpop_nonce: true,
        require_pkce_for_confidential_clients: false,
        access_token_ttl_secs,
        ..OidcConfig::default()
    })
    .await
}

/// Drive authorize plus a `DPoP`-bound code exchange, returning the bound token.
///
/// The exchange itself needs a nonce when the policy is on, so this performs the
/// token endpoint's own challenge-retry first. That is not incidental setup: it is
/// the reason the nonce STORE has to be shared between the two surfaces, and it
/// would fail outright if each kept its own.
async fn bound_access_token(harness: &Harness, requires_nonce: bool) -> (String, Option<String>) {
    let client = harness.client_id().to_string();
    let subject = harness
        .seed_user_with_claims(&unique_identifier(harness), SEED_PASSWORD, CLAIMS_JSON)
        .await;
    harness.grant_consent(&subject, &client).await;
    let cookie = harness.session_cookie(&subject).await;
    let query = format!(
        "response_type=code&client_id={client}&redirect_uri={}&scope={}&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        enc(REDIRECT_URI),
        enc("openid profile email"),
    );
    let (status, headers, body) = harness.authorize_with_cookie(&query, &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");

    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client),
        ("code_verifier", PKCE_VERIFIER),
    ]);

    let post = |proof: String, body: String| async move {
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("DPoP", proof)
            .body(Body::from(body))
            .expect("request builds");
        harness.send(request).await
    };

    let first = sign_proof(
        &proof_key(),
        "POST",
        &token_htu(),
        now_secs(harness),
        "jti-tok-1",
    );
    let (status, headers, body) = post(first, exchange.clone()).await;
    let (body, issued) = if requires_nonce {
        assert_eq!(status, StatusCode::BAD_REQUEST, "challenged: {body}");
        let nonce = issued_nonce(&headers).expect("token endpoint challenge carries a nonce");
        let retry = ironauth_jose::dpop_test_util::sign_proof_with_nonce(
            &proof_key(),
            "POST",
            &token_htu(),
            now_secs(harness),
            "jti-tok-2",
            &nonce,
        );
        let (status, _, body) = post(retry, exchange).await;
        assert_eq!(status, StatusCode::OK, "retry: {body}");
        (body, Some(nonce))
    } else {
        assert_eq!(status, StatusCode::OK, "exchange: {body}");
        (body, None)
    };
    let token = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();
    (token, issued)
}

/// `GET /userinfo` presenting `token` under the `DPoP` scheme with a proof that
/// optionally carries `nonce`.
async fn userinfo(
    harness: &Harness,
    token: &str,
    nonce: Option<&str>,
    jti: &str,
) -> (StatusCode, HeaderMap, String) {
    let ath = access_token_hash(token);
    let proof = match nonce {
        Some(nonce) => sign_proof_with_ath_nonce(
            &proof_key(),
            "GET",
            &userinfo_htu(),
            now_secs(harness),
            jti,
            &ath,
            nonce,
        ),
        None => sign_proof_with_ath(
            &proof_key(),
            "GET",
            &userinfo_htu(),
            now_secs(harness),
            jti,
            &ath,
        ),
    };
    let request = Request::builder()
        .method("GET")
        .uri("/userinfo")
        .header(header::AUTHORIZATION, format!("DPoP {token}"))
        .header("DPoP", proof)
        .body(Body::empty())
        .expect("request builds");
    harness.send(request).await
}

fn challenge(headers: &HeaderMap) -> String {
    headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn issued_nonce(headers: &HeaderMap) -> Option<String> {
    headers
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// THE flow at a protected resource: a proof with no nonce draws a `401` `DPoP`
/// challenge naming `use_dpop_nonce`, and the retry echoing the issued nonce is
/// served.
#[tokio::test]
async fn a_userinfo_proof_without_a_nonce_is_challenged_and_the_retry_succeeds() {
    let harness = nonce_harness().await;
    let (token, _) = bound_access_token(&harness, true).await;

    let (status, headers, body) = userinfo(&harness, &token, None, "jti-ui-1").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "challenged: {body}");
    let www = challenge(&headers);
    assert!(www.starts_with("DPoP "), "DPoP-scheme challenge: {www}");
    assert!(
        www.contains("error=\"use_dpop_nonce\""),
        "the challenge names use_dpop_nonce: {www}"
    );
    let nonce = issued_nonce(&headers).expect("the challenge carries a DPoP-Nonce header");

    let (status, _, body) = userinfo(&harness, &token, Some(&nonce), "jti-ui-2").await;
    assert_eq!(status, StatusCode::OK, "retry with the nonce: {body}");
    assert_eq!(json(&body)["name"], "Ada Lovelace", "claims released");
}

/// The two surfaces share ONE nonce store: a nonce issued by the token endpoint is
/// spendable at `userinfo` with no second challenge.
///
/// This is the property that makes the feature usable rather than merely correct. If
/// each surface kept its own store, a client would be challenged again at every
/// surface it touched, and the round trips would multiply.
#[tokio::test]
async fn a_nonce_from_the_token_endpoint_is_accepted_at_userinfo() {
    let harness = nonce_harness().await;
    // The nonce the TOKEN endpoint issued during this exchange's own challenge-retry.
    // Taken from the real flow rather than a synthetic probe: `resolve_dpop_binding`
    // runs deep in the authorization_code path (after the code resolves), so a request
    // carrying no code never reaches it and never draws a challenge at all.
    let (token, token_endpoint_nonce) = bound_access_token(&harness, true).await;
    let token_endpoint_nonce = token_endpoint_nonce.expect("the token endpoint issued one");

    // Spend it at userinfo, first try, no challenge.
    let (status, _, body) = userinfo(
        &harness,
        &token,
        Some(&token_endpoint_nonce),
        "jti-cross-surface",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a token-endpoint nonce is spendable here: {body}"
    );
}

/// A nonce this server never issued is refused with a fresh challenge, not served.
#[tokio::test]
async fn a_userinfo_nonce_the_server_never_issued_is_refused() {
    let harness = nonce_harness().await;
    let (token, _) = bound_access_token(&harness, true).await;

    let (status, headers, body) = userinfo(
        &harness,
        &token,
        Some("a-nonce-this-server-never-minted"),
        "jti-forged",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "refused: {body}");
    assert!(
        challenge(&headers).contains("error=\"use_dpop_nonce\""),
        "a fresh challenge, not a bare rejection"
    );
    let fresh = issued_nonce(&headers).expect("a fresh nonce accompanies the refusal");

    let (status, _, body) = userinfo(&harness, &token, Some(&fresh), "jti-recover").await;
    assert_eq!(status, StatusCode::OK, "the issued nonce works: {body}");
}

/// The nonce challenge stays DISTINCT from the uniform `invalid_token` rejection.
///
/// The distinction is the point: a client that cannot tell "retry with this nonce"
/// from "your proof is bad" cannot perform the retry. Both are `401`, so the error
/// code in the challenge is the only thing carrying it.
#[tokio::test]
async fn the_nonce_challenge_is_distinguishable_from_a_rejection() {
    let harness = nonce_harness().await;
    let (token, _) = bound_access_token(&harness, true).await;

    let (_, nonce_headers, _) = userinfo(&harness, &token, None, "jti-needs-nonce").await;
    let needs_nonce = challenge(&nonce_headers);

    // A genuinely bad presentation: a proof over the WRONG htu, which is a rejection
    // rather than a nonce problem. It must NOT read as use_dpop_nonce, or a client
    // would retry forever against a proof that can never be accepted.
    let ath = access_token_hash(&token);
    let wrong_htu = sign_proof_with_ath(
        &proof_key(),
        "GET",
        "https://elsewhere.test/userinfo",
        now_secs(&harness),
        "jti-wrong-htu",
        &ath,
    );
    let request = Request::builder()
        .method("GET")
        .uri("/userinfo")
        .header(header::AUTHORIZATION, format!("DPoP {token}"))
        .header("DPoP", wrong_htu)
        .body(Body::empty())
        .expect("request builds");
    let (status, headers, _) = harness.send(request).await;
    let rejected = challenge(&headers);

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        rejected.contains("error=\"invalid_token\""),
        "a bad proof is the uniform rejection: {rejected}"
    );
    assert!(
        !rejected.contains("use_dpop_nonce"),
        "a bad proof must not invite a pointless retry: {rejected}"
    );
    assert_ne!(needs_nonce, rejected, "the two challenges differ");
    assert!(
        issued_nonce(&headers).is_none(),
        "a rejection carries no nonce"
    );
}

/// A nonce past its acceptance window draws a NEW challenge.
#[tokio::test]
async fn a_stale_userinfo_nonce_is_challenged_again() {
    // An access token that OUTLIVES the nonce window. At the shipped 300s default the
    // two expire together, and userinfo would answer invalid_token before reaching the
    // nonce check, so the assertion below would hold for the wrong reason.
    let harness = nonce_harness_with_token_ttl(3_600).await;
    let (token, _) = bound_access_token(&harness, true).await;

    let (_, headers, _) = userinfo(&harness, &token, None, "jti-stale-get").await;
    let nonce = issued_nonce(&headers).expect("a challenge nonce");

    // Past the nonce TTL (300s) and well inside the access token's. The proof is
    // re-signed at the advanced clock, so it is FRESH: the only stale thing is the
    // nonce, and the refusal is attributable to it alone.
    harness.clock().advance(Duration::from_secs(400));

    let (status, headers, body) = userinfo(&harness, &token, Some(&nonce), "jti-stale-use").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "stale nonce: {body}");
    assert!(challenge(&headers).contains("error=\"use_dpop_nonce\""));
    assert!(
        issued_nonce(&headers).is_some_and(|fresh| fresh != nonce),
        "the challenge carries a NEW nonce, not the stale one back"
    );
}

/// With the policy OFF (the shipped default) `userinfo` never challenges, and a
/// nonce a client volunteers unasked is ignored rather than refused.
#[tokio::test]
async fn the_default_configuration_never_challenges_at_userinfo() {
    let harness = Harness::start().await;
    let (token, _) = bound_access_token(&harness, false).await;

    let (status, headers, body) = userinfo(&harness, &token, None, "jti-default").await;
    assert_eq!(status, StatusCode::OK, "unchanged by default: {body}");
    assert!(
        issued_nonce(&headers).is_none(),
        "no DPoP-Nonce header when the policy is off"
    );

    let (status, _, body) = userinfo(
        &harness,
        &token,
        Some("a-nonce-nobody-asked-for"),
        "jti-volunteered",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ignored, not refused: {body}");
}
