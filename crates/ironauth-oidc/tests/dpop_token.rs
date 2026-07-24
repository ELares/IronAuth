// SPDX-License-Identifier: MIT OR Apache-2.0

//! `DPoP` (RFC 9449) sender-constrained token binding at the token endpoint's
//! `authorization_code` grant (issue #368 PR2, ISSUANCE side), over a real database
//! (`DATABASE_URL`).
//!
//! Covers the issuance behaviors: a valid `DPoP` proof binds the at+jwt (`cnf.jkt`),
//! the opaque access token, and the refresh family to the proof key; NO proof leaves
//! a plain bearer token; a present-but-invalid proof (wrong `htu`, bad signature, a
//! future `iat`) is a uniform `invalid_dpop_proof` that never burns the code; a
//! replayed `jti` is refused; and more than one `DPoP` header is refused.

mod common;

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, PKCE_VERIFIER, REDIRECT_URI, form, json, send_through, verify_clock};
use ironauth_config::{OidcConfig, TokenFormat as ConfigTokenFormat};
use ironauth_jose::dpop_test_util::{jkt_of, sign_proof};
use ironauth_jose::{Confirmation, SigningKey, verify};

/// The token-endpoint form for a PKCE public-client code exchange.
fn token_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

/// A fixed Ed25519 client proof key (the client's ephemeral `DPoP` key).
fn proof_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("dpop-client".to_owned()), &[3_u8; 32]).expect("ed25519")
}

/// The normalized token-endpoint `htu` the server expects: the per-environment
/// issuer plus the fixed `/token` path (RFC 9449 4.3).
fn expected_htu(harness: &Harness) -> String {
    format!("{}/token", harness.issuer())
}

/// The whole-seconds `iat` the proof carries, read from the harness clock so the
/// proof is fresh at `state.now()`.
fn now_secs(harness: &Harness) -> u64 {
    harness
        .state()
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `POST /token` with the given form body and zero or more `DPoP` header values.
async fn token_with_dpop(
    harness: &Harness,
    form_body: &str,
    dpop_values: &[&str],
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for value in dpop_values {
        builder = builder.header("DPoP", *value);
    }
    let request = builder
        .body(Body::from(form_body.to_owned()))
        .expect("request builds");
    let (status, _headers, body) = send_through(harness.router(), request).await;
    (status, body)
}

/// Read the `dpop_jkt` recorded on the most recent refresh family for `client_id`
/// (owner pool), or [`None`] when the column is SQL NULL (an unbound family).
async fn refresh_family_jkt(harness: &Harness, client_id: &str) -> Option<String> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT dpop_jkt FROM refresh_families \
         WHERE client_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(client_id)
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("a refresh family row");
    row.get::<Option<String>, _>("dpop_jkt")
}

/// Read the `dpop_jkt` recorded on the most recent opaque access token for
/// `client_id` (owner pool).
async fn opaque_token_jkt(harness: &Harness, client_id: &str) -> Option<String> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT dpop_jkt FROM opaque_access_tokens \
         WHERE client_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(client_id)
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("an opaque access token row");
    row.get::<Option<String>, _>("dpop_jkt")
}

/// A valid `DPoP` proof at the token endpoint binds the at+jwt's `cnf.jkt` to the
/// proof key thumbprint AND records that same jkt on the refresh family, so both the
/// access token and the refresh family are sender-constrained.
#[tokio::test]
async fn valid_dpop_proof_binds_the_at_jwt_cnf_and_the_refresh_family() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let key = proof_key();
    let expected_jkt = jkt_of(&key);

    let code = harness.issue_authenticated_code_pkce(&client).await;
    let proof = sign_proof(
        &key,
        "POST",
        &expected_htu(&harness),
        now_secs(&harness),
        "jti-bind-1",
    );

    let (status, body) = token_with_dpop(&harness, &token_form(&code, &client), &[&proof]).await;
    assert_eq!(status, StatusCode::OK, "bound exchange: {body}");
    let value = json(&body);
    let access_token = value["access_token"].as_str().expect("access_token");

    // The at+jwt carries the cnf confirmation, read through the SAME path production
    // uses, and its jkt equals the RFC 7638 thumbprint of the proof key.
    let verified =
        verify(access_token, &harness.policy(&client), &verify_clock()).expect("at+jwt verifies");
    let confirmation = Confirmation::from_claims(verified.claims())
        .expect("cnf parses")
        .expect("the bound at+jwt carries a cnf claim");
    assert_eq!(
        confirmation,
        Confirmation::Jkt(expected_jkt.clone()),
        "cnf.jkt is the proof key thumbprint"
    );

    // The refresh family stores the same jkt, so PR3 can enforce a matching proof.
    assert_eq!(
        refresh_family_jkt(&harness, &client).await,
        Some(expected_jkt),
        "the refresh family is bound to the proof key"
    );
}

/// A valid `DPoP` proof binds an OPAQUE access token by recording the jkt on its
/// stored row (an opaque token carries no claims, so the binding lives on the row).
#[tokio::test]
async fn valid_dpop_proof_binds_the_opaque_access_token_row() {
    let config = OidcConfig {
        default_access_token_format: ConfigTokenFormat::Opaque,
        ..OidcConfig::default()
    };
    let harness = Harness::start_with(config).await;
    let client = harness.client_id().to_string();
    let key = proof_key();
    let expected_jkt = jkt_of(&key);

    let code = harness.issue_authenticated_code_pkce(&client).await;
    let proof = sign_proof(
        &key,
        "POST",
        &expected_htu(&harness),
        now_secs(&harness),
        "jti-opaque-1",
    );

    let (status, body) = token_with_dpop(&harness, &token_form(&code, &client), &[&proof]).await;
    assert_eq!(status, StatusCode::OK, "bound opaque exchange: {body}");
    assert_eq!(json(&body)["token_type"], "Bearer");

    assert_eq!(
        opaque_token_jkt(&harness, &client).await,
        Some(expected_jkt),
        "the opaque access token row is bound to the proof key"
    );
}

/// With NO `DPoP` header the exchange is unchanged: a plain bearer at+jwt with no
/// `cnf`, and the refresh family carries no jkt.
#[tokio::test]
async fn no_dpop_header_issues_a_plain_bearer_token() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;

    let (status, body) = token_with_dpop(&harness, &token_form(&code, &client), &[]).await;
    assert_eq!(status, StatusCode::OK, "bearer exchange: {body}");
    let access_token = json(&body)["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    let verified =
        verify(&access_token, &harness.policy(&client), &verify_clock()).expect("at+jwt verifies");
    assert!(
        Confirmation::from_claims(verified.claims())
            .expect("cnf parses")
            .is_none(),
        "a bearer at+jwt carries no cnf claim"
    );
    assert_eq!(
        refresh_family_jkt(&harness, &client).await,
        None,
        "an unbound refresh family carries no jkt"
    );
}

/// A present-but-invalid `DPoP` proof is a uniform `invalid_dpop_proof`, mints no
/// token, and does NOT burn the one-time code (a subsequent bearer exchange with the
/// SAME code still succeeds). Covers a wrong `htu`, a tampered signature, and a
/// future `iat` — every reason maps to the same response body (no oracle).
#[tokio::test]
async fn an_invalid_dpop_proof_is_rejected_and_does_not_burn_the_code() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let key = proof_key();
    let iat = now_secs(&harness);

    // A proof bound to the WRONG htu.
    let wrong_htu = sign_proof(
        &key,
        "POST",
        "https://attacker.test/token",
        iat,
        "jti-bad-htu",
    );
    // A structurally valid proof whose signature is then tampered (flip the last
    // signature byte's base64url character).
    let good = sign_proof(&key, "POST", &expected_htu(&harness), iat, "jti-bad-sig");
    let mut tampered = good.clone();
    tampered.pop();
    tampered.push(if good.ends_with('A') { 'B' } else { 'A' });
    // A proof whose iat is far in the future, beyond the skew allowance.
    let future_iat = sign_proof(
        &key,
        "POST",
        &expected_htu(&harness),
        iat + 3_600,
        "jti-future",
    );

    for proof in [&wrong_htu, &tampered, &future_iat] {
        let code = harness.issue_authenticated_code_pkce(&client).await;
        let (status, body) =
            token_with_dpop(&harness, &token_form(&code, &client), &[proof.as_str()]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "rejected: {body}");
        let value = json(&body);
        assert_eq!(
            value["error"], "invalid_dpop_proof",
            "the uniform DPoP error, no oracle"
        );
        assert!(
            value.get("access_token").is_none(),
            "no token is minted for a bad proof"
        );
        // The code was NOT consumed: a plain bearer exchange with the same code
        // still succeeds, proving the bad proof did not burn the one-time code.
        let (retry_status, retry_body) =
            token_with_dpop(&harness, &token_form(&code, &client), &[]).await;
        assert_eq!(
            retry_status,
            StatusCode::OK,
            "the code survives a bad proof: {retry_body}"
        );
    }
}

/// A replayed `DPoP` proof `jti` (the same key and jti presented twice inside the
/// freshness window, each on its own single-use code) is refused as
/// `invalid_dpop_proof`.
#[tokio::test]
async fn a_replayed_dpop_jti_is_rejected() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let key = proof_key();
    let htu = expected_htu(&harness);
    let iat = now_secs(&harness);

    // First presentation on its own code: accepted.
    let code1 = harness.issue_authenticated_code_pkce(&client).await;
    let proof1 = sign_proof(&key, "POST", &htu, iat, "jti-replay");
    let (status1, body1) =
        token_with_dpop(&harness, &token_form(&code1, &client), &[&proof1]).await;
    assert_eq!(status1, StatusCode::OK, "first proof accepted: {body1}");

    // Same key + same jti, a fresh code: refused as a replay.
    let code2 = harness.issue_authenticated_code_pkce(&client).await;
    let proof2 = sign_proof(&key, "POST", &htu, iat, "jti-replay");
    let (status2, body2) =
        token_with_dpop(&harness, &token_form(&code2, &client), &[&proof2]).await;
    assert_eq!(status2, StatusCode::BAD_REQUEST, "replay refused: {body2}");
    assert_eq!(json(&body2)["error"], "invalid_dpop_proof");
}

/// More than one `DPoP` header is refused (RFC 9449: exactly one) as
/// `invalid_dpop_proof`, and the code is not burned.
#[tokio::test]
async fn multiple_dpop_headers_are_rejected() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let key = proof_key();
    let htu = expected_htu(&harness);
    let iat = now_secs(&harness);
    let proof_a = sign_proof(&key, "POST", &htu, iat, "jti-multi-a");
    let proof_b = sign_proof(&key, "POST", &htu, iat, "jti-multi-b");

    let code = harness.issue_authenticated_code_pkce(&client).await;
    let (status, body) = token_with_dpop(
        &harness,
        &token_form(&code, &client),
        &[proof_a.as_str(), proof_b.as_str()],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "two headers refused: {body}"
    );
    assert_eq!(json(&body)["error"], "invalid_dpop_proof");

    // The code was not burned: a clean bearer exchange still succeeds.
    let (retry_status, retry_body) =
        token_with_dpop(&harness, &token_form(&code, &client), &[]).await;
    assert_eq!(
        retry_status,
        StatusCode::OK,
        "the code survives the multi-header rejection: {retry_body}"
    );
}
