// SPDX-License-Identifier: MIT OR Apache-2.0

//! `DPoP` (RFC 9449 section 5) sender-constrained refresh-grant enforcement (issue
//! #368 PR3, the REDEMPTION side), over a real database (`DATABASE_URL`).
//!
//! PR2 STORES a refresh family's `dpop_jkt` when a code exchange presents a valid
//! proof; PR3 ENFORCES it. A family issued DPoP-bound can ONLY be rotated by a
//! request carrying a valid proof whose key thumbprint EQUALS the family's bound
//! `jkt`. Covered here: a bound refresh with the right-key proof rotates, re-binds
//! the rotated access token (`cnf.jkt`), advertises `token_type: DPoP`, and stays
//! refreshable; a bound refresh with NO proof, a WRONG-key proof, a REPLAYED `jti`,
//! or a stale `htu` is a uniform `invalid_dpop_proof` that neither rotates NOR
//! revokes the family; and an UNBOUND family is unchanged bearer, ignoring any
//! presented proof (never retroactively bound).

mod common;

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, PKCE_VERIFIER, REDIRECT_URI, form, json, send_through, verify_clock};
use ironauth_jose::dpop_test_util::{jkt_of, sign_proof};
use ironauth_jose::{Confirmation, SigningKey, verify};

/// The token-endpoint form for a PKCE public-client code exchange.
fn code_form(code: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", client_id),
        ("code_verifier", PKCE_VERIFIER),
    ])
}

/// The refresh-token grant form for a public client (`client_id` in the body).
fn refresh_form(refresh_token: &str, client_id: &str) -> String {
    form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ])
}

/// The client's ephemeral `DPoP` key (a fixed Ed25519 seed for determinism).
fn proof_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("dpop-refresh".to_owned()), &[7_u8; 32]).expect("ed25519")
}

/// A DIFFERENT client key, to prove a valid proof for the WRONG key is refused.
fn other_key() -> SigningKey {
    SigningKey::ed25519_from_seed(Some("dpop-other".to_owned()), &[9_u8; 32]).expect("ed25519")
}

/// The token-endpoint `htu` a compliant client signs: the DEPLOYMENT-ROOT
/// `token_endpoint` (`{issuer_base}/token`), NOT the per-environment issuer path.
/// Derived from the advertised base so a stale per-environment `htu` (the bug PR2
/// fixed) could never make these pass.
fn expected_htu() -> String {
    format!("{}/token", common::ISSUER_BASE)
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

/// The `cnf` confirmation on an at+jwt access token, read through the SAME path
/// production uses, or [`None`] for a plain bearer token.
fn cnf_of(harness: &Harness, client: &str, access_token: &str) -> Option<Confirmation> {
    let verified =
        verify(access_token, &harness.policy(client), &verify_clock()).expect("at+jwt verifies");
    Confirmation::from_claims(verified.claims()).expect("cnf parses")
}

/// Drive a code exchange WITH a valid proof so the opened refresh family is
/// DPoP-bound (the PR2 issuance path), returning the bound refresh token.
async fn bound_refresh_token(harness: &Harness, key: &SigningKey, jti: &str) -> String {
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;
    let proof = sign_proof(key, "POST", &expected_htu(), now_secs(harness), jti);
    let (status, body) = token_with_dpop(harness, &code_form(&code, &client), &[&proof]).await;
    assert_eq!(status, StatusCode::OK, "bound code exchange: {body}");
    assert_eq!(
        json(&body)["token_type"],
        "DPoP",
        "the bound exchange is DPoP"
    );
    assert_eq!(
        refresh_family_jkt(harness, &client).await,
        Some(jkt_of(key)),
        "the code exchange opened a DPoP-bound family"
    );
    json(&body)["refresh_token"]
        .as_str()
        .expect("a bound refresh token is issued")
        .to_owned()
}

/// Drive a code exchange with NO proof so the opened family is an UNBOUND bearer
/// family, returning the bearer refresh token.
async fn bearer_refresh_token(harness: &Harness) -> String {
    let client = harness.client_id().to_string();
    let code = harness.issue_authenticated_code_pkce(&client).await;
    let (status, body) = token_with_dpop(harness, &code_form(&code, &client), &[]).await;
    assert_eq!(status, StatusCode::OK, "bearer code exchange: {body}");
    assert_eq!(json(&body)["token_type"], "Bearer");
    assert_eq!(
        refresh_family_jkt(harness, &client).await,
        None,
        "the code exchange opened an unbound family"
    );
    json(&body)["refresh_token"]
        .as_str()
        .expect("a bearer refresh token is issued")
        .to_owned()
}

/// A bound family + a valid proof for the SAME key rotates: the rotated access token
/// re-binds (`cnf.jkt` == the family jkt), the response advertises `token_type:
/// DPoP`, and the rotated refresh token is ITSELF still bound (a second refresh with
/// a fresh proof for the same key succeeds), so the binding survives every rotation.
#[tokio::test]
async fn a_bound_family_rotates_with_a_matching_proof_and_stays_bound() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let key = proof_key();
    let expected_jkt = jkt_of(&key);

    let r0 = bound_refresh_token(&harness, &key, "jti-rotate-code").await;

    // First refresh: a fresh proof for the same key.
    let proof1 = sign_proof(
        &key,
        "POST",
        &expected_htu(),
        now_secs(&harness),
        "jti-rotate-1",
    );
    let (status, body) = token_with_dpop(&harness, &refresh_form(&r0, &client), &[&proof1]).await;
    assert_eq!(status, StatusCode::OK, "bound refresh rotates: {body}");
    let value = json(&body);
    assert_eq!(
        value["token_type"], "DPoP",
        "a bound refresh advertises DPoP"
    );
    let access_token = value["access_token"].as_str().expect("access_token");
    assert_eq!(
        cnf_of(&harness, &client, access_token),
        Some(Confirmation::Jkt(expected_jkt.clone())),
        "the rotated access token re-binds to the family key"
    );
    let r1 = value["refresh_token"]
        .as_str()
        .expect("a public client rotates the refresh token")
        .to_owned();
    assert_ne!(r1, r0, "the refresh token rotated");
    assert_eq!(
        refresh_family_jkt(&harness, &client).await,
        Some(expected_jkt),
        "the family stays bound across the rotation"
    );

    // The rotated refresh token is still bound: a second refresh with a fresh proof
    // for the same key succeeds.
    let proof2 = sign_proof(
        &key,
        "POST",
        &expected_htu(),
        now_secs(&harness),
        "jti-rotate-2",
    );
    let (status2, body2) = token_with_dpop(&harness, &refresh_form(&r1, &client), &[&proof2]).await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "the rotated RT still refreshes: {body2}"
    );
    assert_eq!(json(&body2)["token_type"], "DPoP");
}

/// A bound family presented with NO `DPoP` header is refused as the uniform
/// `invalid_dpop_proof`, does NOT rotate, and is NOT revoked: a subsequent PROPER
/// refresh with a matching proof still works (a rejected refresh must not `DoS` the
/// legitimate holder).
#[tokio::test]
async fn a_bound_family_with_no_proof_is_refused_and_not_burned() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let key = proof_key();
    let r0 = bound_refresh_token(&harness, &key, "jti-noproof-code").await;

    // No DPoP header on a bound family: uniform error, no rotation.
    let (status, body) = token_with_dpop(&harness, &refresh_form(&r0, &client), &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no proof refused: {body}");
    assert_eq!(json(&body)["error"], "invalid_dpop_proof");
    assert!(
        json(&body).get("access_token").is_none(),
        "no token is minted for a bound family with no proof"
    );

    // The family was NOT burned: the SAME refresh token still refreshes with a proper
    // proof, proving the rejection revoked nothing.
    let proof = sign_proof(
        &key,
        "POST",
        &expected_htu(),
        now_secs(&harness),
        "jti-noproof-ok",
    );
    let (status2, body2) = token_with_dpop(&harness, &refresh_form(&r0, &client), &[&proof]).await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "the family survives the rejected refresh: {body2}"
    );
    assert_eq!(json(&body2)["token_type"], "DPoP");
}

/// A bound family presented with a VALID proof for a DIFFERENT key (a thumbprint
/// mismatch) is refused as `invalid_dpop_proof` and does not rotate: possession of
/// SOME key is not enough, only the family's bound key.
#[tokio::test]
async fn a_bound_family_with_a_wrong_key_proof_is_refused() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let key = proof_key();
    let wrong = other_key();
    assert_ne!(jkt_of(&key), jkt_of(&wrong), "the two keys differ");
    let r0 = bound_refresh_token(&harness, &key, "jti-wrongkey-code").await;

    // A structurally valid proof, but for the wrong key: refused.
    let proof = sign_proof(
        &wrong,
        "POST",
        &expected_htu(),
        now_secs(&harness),
        "jti-wrongkey",
    );
    let (status, body) = token_with_dpop(&harness, &refresh_form(&r0, &client), &[&proof]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "wrong key refused: {body}");
    assert_eq!(json(&body)["error"], "invalid_dpop_proof");

    // Still not burned: the right key still refreshes.
    let right = sign_proof(
        &key,
        "POST",
        &expected_htu(),
        now_secs(&harness),
        "jti-wrongkey-ok",
    );
    let (status2, body2) = token_with_dpop(&harness, &refresh_form(&r0, &client), &[&right]).await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "the right key still works: {body2}"
    );
}

/// A bound family presented with a REPLAYED `jti` (here the jti the opening code
/// exchange already recorded, reused inside the freshness window) is refused by the
/// replay cache as `invalid_dpop_proof`, and does not rotate.
#[tokio::test]
async fn a_bound_family_with_a_replayed_jti_is_refused() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let key = proof_key();
    // The opening exchange records this jti in the replay cache.
    let r0 = bound_refresh_token(&harness, &key, "jti-shared-replay").await;

    // Reusing the SAME jti at refresh is a replay: refused.
    let replay = sign_proof(
        &key,
        "POST",
        &expected_htu(),
        now_secs(&harness),
        "jti-shared-replay",
    );
    let (status, body) = token_with_dpop(&harness, &refresh_form(&r0, &client), &[&replay]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "replay refused: {body}");
    assert_eq!(json(&body)["error"], "invalid_dpop_proof");

    // Not burned: a fresh jti for the same key still refreshes.
    let fresh = sign_proof(
        &key,
        "POST",
        &expected_htu(),
        now_secs(&harness),
        "jti-shared-fresh",
    );
    let (status2, body2) = token_with_dpop(&harness, &refresh_form(&r0, &client), &[&fresh]).await;
    assert_eq!(status2, StatusCode::OK, "a fresh jti still works: {body2}");
}

/// A bound family presented with a proof bound to the WRONG `htu` is refused
/// (delegated to the proof-validation core): one stale/mismatched-proof case is
/// enough here, the core's full matrix is covered by the issuance tests.
#[tokio::test]
async fn a_bound_family_with_a_stale_htu_proof_is_refused() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let key = proof_key();
    let r0 = bound_refresh_token(&harness, &key, "jti-badhtu-code").await;

    let proof = sign_proof(
        &key,
        "POST",
        "https://attacker.test/token",
        now_secs(&harness),
        "jti-badhtu",
    );
    let (status, body) = token_with_dpop(&harness, &refresh_form(&r0, &client), &[&proof]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "wrong htu refused: {body}");
    assert_eq!(json(&body)["error"], "invalid_dpop_proof");
}

/// An UNBOUND (bearer) family is unchanged: it rotates as a plain bearer with no
/// proof, and a PRESENTED proof is IGNORED (never rotates to `DPoP`, never
/// retroactively binds a family whose earlier tokens were bearer).
#[tokio::test]
async fn an_unbound_family_stays_bearer_and_ignores_a_presented_proof() {
    let harness = Harness::start().await;
    let client = harness.client_id().to_string();
    let r0 = bearer_refresh_token(&harness).await;

    // No proof: a plain bearer rotation, no cnf.
    let (status, body) = token_with_dpop(&harness, &refresh_form(&r0, &client), &[]).await;
    assert_eq!(status, StatusCode::OK, "bearer refresh: {body}");
    let value = json(&body);
    assert_eq!(
        value["token_type"], "Bearer",
        "an unbound family stays bearer"
    );
    let access_token = value["access_token"].as_str().expect("access_token");
    assert!(
        cnf_of(&harness, &client, access_token).is_none(),
        "a bearer rotated access token carries no cnf"
    );
    let r1 = value["refresh_token"]
        .as_str()
        .expect("rotated bearer refresh token")
        .to_owned();

    // A presented proof on an unbound family is IGNORED: still bearer, still no cnf,
    // and the family is NOT retroactively bound.
    let proof = sign_proof(
        &proof_key(),
        "POST",
        &expected_htu(),
        now_secs(&harness),
        "jti-ignored",
    );
    let (status2, body2) = token_with_dpop(&harness, &refresh_form(&r1, &client), &[&proof]).await;
    assert_eq!(
        status2,
        StatusCode::OK,
        "the proof is ignored, not an error: {body2}"
    );
    let value2 = json(&body2);
    assert_eq!(
        value2["token_type"], "Bearer",
        "a presented proof never binds an unbound family"
    );
    assert!(
        cnf_of(
            &harness,
            &client,
            value2["access_token"].as_str().expect("access_token")
        )
        .is_none(),
        "still no cnf"
    );
    assert_eq!(
        refresh_family_jkt(&harness, &client).await,
        None,
        "the family was never retroactively bound"
    );
}
