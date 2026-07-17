// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Apple "Sign in with Apple" signed-JWT client secret (issue #74), a DATA-driven
//! quirk handler.
//!
//! Apple does not authenticate the token exchange with a static shared secret. It
//! requires a per-request, short-lived ES256 JWT ASSERTION generated from the operator's
//! configured EC P-256 private key: header `{ alg: ES256, kid: <key id> }`, claims
//! `{ iss: <team id>, sub: <client id>, aud: https://appleid.apple.com, iat, exp }`. The
//! connector definition carries this as [`ironauth_connector::ClientAuth::SignedJwt`]; the
//! sealed `client_secret` holds the private key. This module generates the assertion.
//!
//! # The two hard constraints
//!
//! - **One JOSE path.** The assertion is signed through the single `ironauth-jose` ES256
//!   entry point ([`sign_jws`]); this module writes no crypto and pulls in no JWT crate.
//! - **The clock seam.** `iat`/`exp` come from the caller-supplied instant (the federation
//!   layer passes `env.clock()`); the wall clock is never read directly here, so assertion
//!   generation is deterministic under a manual clock. The assertion is short-lived
//!   (regenerated every exchange), and `exp` is bounded by [`ASSERTION_TTL`].

use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ironauth_connector::ConnectorError;
use ironauth_jose::{EmissionOptions, SigningKey, sign_jws};

/// The lifetime of a generated Apple client-secret assertion. Apple permits up to six
/// months, but the assertion is regenerated on every token exchange, so a short window is
/// used: it bounds the blast radius of a captured assertion with no availability cost.
const ASSERTION_TTL: Duration = Duration::from_secs(300);

/// The inputs for an Apple signed-JWT client secret, mirroring
/// [`ironauth_connector::ClientAuth::SignedJwt`] plus the connector's client id (the
/// assertion `sub`).
#[derive(Debug, Clone, Copy)]
pub struct SignedJwtInputs<'a> {
    /// The Apple team identifier (the assertion `iss`).
    pub team_id: &'a str,
    /// The Apple key identifier (the JWS `kid` header).
    pub key_id: &'a str,
    /// The assertion audience (Apple: `https://appleid.apple.com`).
    pub audience: &'a str,
    /// The connector's client id (the assertion `sub`).
    pub client_id: &'a str,
}

/// Generate a fresh Apple client-secret JWT assertion (issue #74).
///
/// `key_material` is the operator's EC P-256 private key, either a PKCS#8 PEM (the `.p8`
/// Apple issues) or raw PKCS#8 DER; `now` is the current instant from the clock seam. The
/// returned compact JWS is the value sent as the `client_secret` form parameter in the
/// token exchange.
///
/// # Errors
///
/// [`ConnectorError::Config`] if the key material cannot be decoded or loaded as an ES256
/// key, or if signing fails: a bad key is an operator misconfiguration (not an upstream
/// fault), so it fails cleanly at the connector level and provisions no identity. The
/// error message never carries key material.
pub fn generate_signed_jwt(
    key_material: &[u8],
    inputs: SignedJwtInputs<'_>,
    now: SystemTime,
) -> Result<String, ConnectorError> {
    let der = pkcs8_der(key_material);
    let key =
        SigningKey::ecdsa_p256_from_pkcs8(Some(inputs.key_id.to_owned()), &der).map_err(|_| {
            ConnectorError::Config(
                "the Apple signing key is not a valid EC P-256 PKCS#8 key".to_owned(),
            )
        })?;

    let iat = epoch_secs(now);
    let exp = iat.saturating_add(i64::try_from(ASSERTION_TTL.as_secs()).unwrap_or(300));
    let claims = serde_json::json!({
        "iss": inputs.team_id,
        "sub": inputs.client_id,
        "aud": inputs.audience,
        "iat": iat,
        "exp": exp,
    });
    let payload = serde_json::to_vec(&claims).map_err(|_| {
        ConnectorError::Config("the Apple assertion claims could not be serialized".to_owned())
    })?;
    sign_jws(&key, &payload, &EmissionOptions::new()).map_err(|_| {
        ConnectorError::Config("the Apple client-secret assertion could not be signed".to_owned())
    })
}

/// Decode `key_material` to PKCS#8 DER: if it is a PEM document (`-----BEGIN ... -----`),
/// strip the armor and standard-base64-decode the body; otherwise pass the bytes through
/// as DER. A PEM whose body does not decode falls through to the raw bytes, which the key
/// loader then rejects with a clean config error (never a panic).
fn pkcs8_der(key_material: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(key_material) else {
        return key_material.to_vec();
    };
    if !text.contains("-----BEGIN") {
        return key_material.to_vec();
    }
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .flat_map(|line| line.chars().filter(|c| !c.is_whitespace()))
        .collect();
    STANDARD
        .decode(body.as_bytes())
        .unwrap_or_else(|_| key_material.to_vec())
}

/// The epoch-seconds representation of `at`, saturating at the bounds (mirrors the token
/// mint path). A pre-epoch instant yields `0`.
fn epoch_secs(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use ironauth_jose::{JwsAlgorithm, TrustedKey, VerificationPolicy, verify};

    use super::*;

    // A deterministic ES256 PKCS#8 v1 DER key (base64) for the tests, generated once with
    // `openssl ecparam -name prime256v1 -genkey | openssl pkcs8 -topk8 -nocrypt` (the exact
    // byte form `ecdsa_p256_from_pkcs8` accepts).
    fn es256_pkcs8() -> Vec<u8> {
        STANDARD.decode(ES256_PKCS8_B64).expect("fixture decodes")
    }

    const ES256_PKCS8_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNuwcPLgOT+sjCMxXd/uhTe18xl4oeOGys2HpTnjjcq6hRANCAASS1c57Xfh8eGjBTbVtg8Ge1yy7M4CKVUDLw8TgwnmvhhzI5cP2PHCwZpZfsZSSZudLLYaigmRbzdVXR7QHzhxe";

    fn inputs<'a>() -> SignedJwtInputs<'a> {
        SignedJwtInputs {
            team_id: "TEAMID1234",
            key_id: "KEYID5678",
            audience: "https://appleid.apple.com",
            client_id: "com.example.service",
        }
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn a_generated_assertion_is_a_valid_es256_jwt_with_the_apple_claims() {
        let der = es256_pkcs8();
        let jwt = generate_signed_jwt(&der, inputs(), now()).expect("assertion generated");

        // The header carries alg ES256 and the Apple kid.
        let kid = ironauth_jose::compact_jws_kid(&jwt);
        assert_eq!(kid.as_deref(), Some("KEYID5678"));

        // The assertion verifies under the key's own public key (proving the ES256 signature),
        // with iss/sub/aud matching and a bounded exp.
        let signing =
            SigningKey::ecdsa_p256_from_pkcs8(Some("KEYID5678".to_owned()), &der).unwrap();
        let trusted: TrustedKey = signing.verifying_key().unwrap();
        let policy = VerificationPolicy::new(
            vec![JwsAlgorithm::Es256],
            vec![trusted],
            "TEAMID1234",
            "https://appleid.apple.com",
        )
        .expect("policy");
        let (env, _clock) = ironauth_env::Env::deterministic(now(), 1);
        let verified = verify(&jwt, &policy, env.clock()).expect("assertion verifies");
        let claims = verified.claims();
        assert_eq!(
            claims.get("aud").and_then(|v| v.as_str()),
            Some("https://appleid.apple.com")
        );
        let iat = claims
            .get("iat")
            .and_then(serde_json::Value::as_i64)
            .expect("iat");
        let exp = claims
            .get("exp")
            .and_then(serde_json::Value::as_i64)
            .expect("exp");
        assert_eq!(iat, 1_700_000_000);
        assert_eq!(exp, 1_700_000_000 + 300, "exp is iat + the short TTL");
    }

    #[test]
    fn a_pem_wrapped_key_is_accepted() {
        // The .p8 Apple issues is PKCS#8 PEM; wrapping the DER fixture in PEM armor must load.
        let der = es256_pkcs8();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n");
        let jwt = generate_signed_jwt(pem.as_bytes(), inputs(), now()).expect("pem key accepted");
        assert_eq!(jwt.matches('.').count(), 2, "a compact JWS has two dots");
    }

    #[test]
    fn a_bad_key_is_a_clean_config_error() {
        let err = generate_signed_jwt(b"not a key", inputs(), now()).expect_err("bad key rejected");
        assert!(matches!(err, ConnectorError::Config(_)), "{err:?}");
    }

    #[test]
    fn the_expiry_tracks_the_clock_seam() {
        // A different clock instant yields a different iat/exp: proof the clock seam drives it.
        let der = es256_pkcs8();
        let later = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let jwt = generate_signed_jwt(&der, inputs(), later).expect("assertion");
        let signing =
            SigningKey::ecdsa_p256_from_pkcs8(Some("KEYID5678".to_owned()), &der).unwrap();
        let policy = VerificationPolicy::new(
            vec![JwsAlgorithm::Es256],
            vec![signing.verifying_key().unwrap()],
            "TEAMID1234",
            "https://appleid.apple.com",
        )
        .unwrap();
        let (env, _clock) = ironauth_env::Env::deterministic(later, 1);
        let verified = verify(&jwt, &policy, env.clock()).expect("verifies at the later clock");
        assert_eq!(
            verified
                .claims()
                .get("iat")
                .and_then(serde_json::Value::as_i64),
            Some(1_800_000_000)
        );
    }
}
