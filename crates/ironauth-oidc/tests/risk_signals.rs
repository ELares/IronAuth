// SPDX-License-Identifier: MIT OR Apache-2.0

//! The third-party risk-signal ingestion endpoint end to end (issue #82, PR 1), against a
//! real Postgres and the real protocol router.
//!
//! These pin the acceptance-critical properties:
//!
//! - ingestion AUTHENTICATES a signed Security Event Token (a JWS) by its SIGNATURE against
//!   the source's REGISTERED public key through the hardened JOSE core: a valid SET from a
//!   registered source is ingested (202), and an unsigned / wrong-key / unknown-source /
//!   wrong-algorithm / expired SET is a uniform 400 that ingests NOTHING;
//! - a re-delivery of the same `(source, source_jti)` is an idempotent no-op (never a
//!   duplicate row);
//! - with the `risk-signals` experimental flag off the endpoint answers a uniform 404 and no
//!   signal is stored.

mod common;

use std::time::SystemTime;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::Harness;
use ironauth_config::RiskSignalSource;
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use serde_json::json;

const SOURCE_ISS: &str = "https://vendor.example";
const SOURCE_KID: &str = "vendor-key-1";
const RAW_SUBJECT: &str = "alice@example.com";

/// A deterministic Ed25519 source key with the given seed byte (so a test can mint a SECOND,
/// unrelated key to exercise the wrong-key rejection).
fn source_key(seed_byte: u8) -> SigningKey {
    SigningKey::ed25519_from_seed(Some(SOURCE_KID.to_owned()), &[seed_byte; 32])
        .expect("ed25519 key from seed")
}

/// The public JWKS JSON for a source key, as it is registered in the source config.
fn jwks_of(key: &SigningKey) -> String {
    JwkSet::from_signing_keys(std::iter::once(key))
        .expect("jwks from signing key")
        .to_json()
        .expect("jwks to json")
}

/// A source config registering `key`'s public JWKS under `SOURCE_ISS`, mapping a `deny`
/// verdict to a HIGH contribution, with the given algorithm allowlist.
fn source_config(key: &SigningKey, algorithms: &[&str]) -> RiskSignalSource {
    let mut source = RiskSignalSource {
        iss: SOURCE_ISS.to_owned(),
        jwks: jwks_of(key),
        algorithms: algorithms.iter().map(|a| (*a).to_owned()).collect(),
        ..RiskSignalSource::default()
    };
    source
        .verdict_map
        .insert("deny".to_owned(), "high".to_owned());
    source
}

fn epoch_secs(at: SystemTime) -> i64 {
    i64::try_from(
        at.duration_since(SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_secs(),
    )
    .expect("fits i64")
}

/// Sign a SET with `key`, filling in the standard and signal claims. `iss`/`aud`/`exp` are
/// overridable per test; the rest are a well-formed CAEP-aligned signal for `subject`.
fn signed_set(
    key: &SigningKey,
    iss: &str,
    aud: &str,
    now_secs: i64,
    exp_secs: i64,
    jti: &str,
) -> String {
    let claims = json!({
        "iss": iss,
        "aud": aud,
        "iat": now_secs,
        "exp": exp_secs,
        "jti": jti,
        "sub_id": { "format": "email", "subject": RAW_SUBJECT },
        "signal_type": "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
        "event_timestamp": now_secs,
        "payload": { "kind": "verdict", "verdict": "deny" }
    });
    let payload = serde_json::to_vec(&claims).expect("claims serialize");
    sign_jws(key, &payload, &EmissionOptions::new()).expect("sign the SET")
}

fn ingest_request(path_scope: &str, set: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/t/{path_scope}/risk/signals"))
        .header(header::CONTENT_TYPE, "application/secevent+jwt")
        .body(Body::from(set))
        .expect("request builds")
}

/// The `{tenant}/e/{environment}` path segment and the issuer (SET audience) for the
/// harness scope.
fn scope_path_and_audience(harness: &Harness) -> (String, String) {
    let scope = harness.scope();
    let path = format!("{}/e/{}", scope.tenant(), scope.environment());
    let audience = harness.state().issuer_for(&scope);
    (path, audience)
}

async fn stored_signal_count(harness: &Harness) -> i64 {
    let scope = harness.scope();
    sqlx::query_scalar(
        "SELECT count(*) FROM risk_signals WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(harness.db().owner_pool())
    .await
    .expect("count risk_signals")
}

#[tokio::test]
async fn a_valid_signed_set_from_a_registered_source_is_ingested() {
    let key = source_key(1);
    let mut harness = Harness::start_store_backed().await;
    harness.enable_risk_signals(vec![source_config(&key, &["EdDSA"])]);
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    let set = signed_set(&key, SOURCE_ISS, &audience, now, now + 3600, "jti-1");
    let (status, _headers, body) = harness.send(ingest_request(&path, set.clone())).await;
    assert_eq!(status, StatusCode::ACCEPTED, "valid SET ingested: {body}");
    assert_eq!(
        stored_signal_count(&harness).await,
        1,
        "one row was written"
    );

    // A re-delivery of the SAME source_jti is an idempotent no-op (still 202, no duplicate).
    let (status, _headers, _body) = harness.send(ingest_request(&path, set)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "re-delivery is accepted");
    assert_eq!(
        stored_signal_count(&harness).await,
        1,
        "a re-delivery of the same source_jti wrote no duplicate row"
    );
}

#[tokio::test]
async fn the_endpoint_404s_unless_the_experimental_flag_is_on() {
    // The DEFAULT store-backed harness has the risk-signals feature OFF.
    let key = source_key(1);
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let path = format!("{}/e/{}", scope.tenant(), scope.environment());
    let audience = harness.state().issuer_for(&scope);
    let now = epoch_secs(harness.state().now());
    let set = signed_set(&key, SOURCE_ISS, &audience, now, now + 3600, "jti-1");

    let (status, _headers, _body) = harness.send(ingest_request(&path, set)).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the ingestion endpoint 404s while the flag is off"
    );
    assert_eq!(
        stored_signal_count(&harness).await,
        0,
        "no signal path runs while the flag is off"
    );
}

#[tokio::test]
async fn every_unauthenticated_or_stale_set_is_rejected_and_ingests_nothing() {
    let key = source_key(1);
    let wrong_key = source_key(2);
    let mut harness = Harness::start_store_backed().await;
    // The source is registered for EdDSA only.
    harness.enable_risk_signals(vec![source_config(&key, &["EdDSA"])]);
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    // 1. An UNSIGNED token (an empty signature segment) is rejected.
    let unsigned = {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": SOURCE_ISS, "aud": audience, "iat": now, "exp": now + 3600,
                "jti": "jti-unsigned",
                "sub_id": {"format":"email","subject":RAW_SUBJECT},
                "signal_type":"x", "event_timestamp": now,
                "payload":{"kind":"verdict","verdict":"deny"}
            }))
            .unwrap(),
        );
        format!("{header}.{payload}.")
    };

    // 2. A SET signed by the WRONG key (a valid JWS, but not the registered key).
    let wrong_sig = signed_set(
        &wrong_key,
        SOURCE_ISS,
        &audience,
        now,
        now + 3600,
        "jti-wrong-key",
    );

    // 3. A SET from an UNKNOWN source (iss not in the config).
    let unknown = signed_set(
        &key,
        "https://unregistered.example",
        &audience,
        now,
        now + 3600,
        "jti-unknown",
    );

    // 4. An EXPIRED SET (exp in the past).
    let expired = signed_set(
        &key,
        SOURCE_ISS,
        &audience,
        now - 7200,
        now - 3600,
        "jti-expired",
    );

    // 5. A SET for the WRONG audience (another env's issuer).
    let wrong_aud = signed_set(
        &key,
        SOURCE_ISS,
        "https://issuer.test/t/other/e/other",
        now,
        now + 3600,
        "jti-wrong-aud",
    );

    for (label, set) in [
        ("unsigned", unsigned),
        ("wrong key", wrong_sig),
        ("unknown source", unknown),
        ("expired", expired),
        ("wrong audience", wrong_aud),
    ] {
        let (status, _headers, body) = harness.send(ingest_request(&path, set)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} SET must be rejected: {body}"
        );
    }

    // A SET signed with an algorithm OUTSIDE the source's allowlist is rejected: reconfigure
    // the same key under an ES256-only allowlist, then present the EdDSA-signed SET.
    harness.enable_risk_signals(vec![source_config(&key, &["ES256"])]);
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());
    let wrong_alg = signed_set(
        &key,
        SOURCE_ISS,
        &audience,
        now,
        now + 3600,
        "jti-wrong-alg",
    );
    let (status, _headers, body) = harness.send(ingest_request(&path, wrong_alg)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a SET whose alg is outside the source allowlist must be rejected: {body}"
    );

    // NOTHING was ingested across every rejected delivery.
    assert_eq!(
        stored_signal_count(&harness).await,
        0,
        "no rejected SET was ever ingested"
    );
}

#[tokio::test]
async fn a_disabled_source_is_rejected() {
    let key = source_key(1);
    let mut harness = Harness::start_store_backed().await;
    let mut source = source_config(&key, &["EdDSA"]);
    source.enabled = false;
    harness.enable_risk_signals(vec![source]);
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());
    let set = signed_set(&key, SOURCE_ISS, &audience, now, now + 3600, "jti-1");

    let (status, _headers, body) = harness.send(ingest_request(&path, set)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a SET from a disabled source is rejected: {body}"
    );
    assert_eq!(stored_signal_count(&harness).await, 0);
}

#[tokio::test]
async fn a_malformed_signal_claim_is_rejected() {
    let key = source_key(1);
    let mut harness = Harness::start_store_backed().await;
    harness.enable_risk_signals(vec![source_config(&key, &["EdDSA"])]);
    let (path, audience) = scope_path_and_audience(&harness);
    let now = epoch_secs(harness.state().now());

    // A verified SET whose sub_id.format is OUTSIDE the closed RFC 9493 set is rejected.
    let claims = json!({
        "iss": SOURCE_ISS, "aud": audience, "iat": now, "exp": now + 3600, "jti": "jti-bad-format",
        "sub_id": { "format": "not_a_format", "subject": RAW_SUBJECT },
        "signal_type": "x", "event_timestamp": now,
        "payload": { "kind": "verdict", "verdict": "deny" }
    });
    let bytes = serde_json::to_vec(&claims).unwrap();
    let set = sign_jws(&key, &bytes, &EmissionOptions::new()).unwrap();
    let (status, _headers, body) = harness.send(ingest_request(&path, set)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown subject format is rejected: {body}"
    );
    assert_eq!(stored_signal_count(&harness).await, 0);
}
