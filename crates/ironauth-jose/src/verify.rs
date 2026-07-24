// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one verification entry point and its orchestration.
//!
//! [`verify`] is the single public path by which any IronAuth code turns a
//! token string into trusted claims. It runs the stages in a fixed order whose
//! sequence is itself the security property: cheap caps first, then structural
//! parsing, then the header trust guards, then key selection, then the one
//! signature check, and only then the claim enforcement (so no unverified
//! payload is ever trusted). Every rejection funnels through [`reject`] into the
//! uniform [`VerifyError`], while the precise [`RejectReason`] is retained for
//! server-side diagnostics.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_env::Clock;

use crate::claims::{self, VerifiedClaims};
use crate::crypto;
use crate::error::{RejectReason, VerifyError};
use crate::header::{self, ProtectedHeader};
use crate::policy::{JwsAlgorithm, TrustedKey, VerificationPolicy};

/// A token that passed every check, and the trusted values recovered from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedToken {
    algorithm: JwsAlgorithm,
    key_id: Option<String>,
    claims: VerifiedClaims,
}

impl VerifiedToken {
    /// The algorithm that verified the signature (from the policy allowlist).
    #[must_use]
    pub fn algorithm(&self) -> JwsAlgorithm {
        self.algorithm
    }

    /// The `kid` the token carried, if any. It only ever selected among trusted
    /// keys; it never introduced one.
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// The verified claims.
    #[must_use]
    pub fn claims(&self) -> &VerifiedClaims {
        &self.claims
    }
}

/// Verify a compact JWS/JWT string against `policy`, using `clock` for the time
/// of evaluation.
///
/// This is the ONLY way to verify a token in IronAuth. On success it returns the
/// [`VerifiedToken`] with its claims; on any failure it returns the uniform
/// [`VerifyError`] (whose [`VerifyError::reason`] carries the internal
/// diagnostic). Trust is taken entirely from `policy`: the algorithm comes from
/// the allowlist, the key from the trusted set, and the token's own `alg`/`kid`
/// are only matched against them, never followed outside them.
///
/// # Errors
///
/// Returns [`VerifyError`] for every rejection: an oversized or malformed token,
/// a header that steers trust (`alg: none`, an unsupported or non-allowlisted
/// algorithm, embedded key material, `crit`, compression, or encryption), a key
/// mismatch, an invalid signature, or a failed claim (`exp`/`nbf`/`iat` outside
/// skew, or a wrong `iss`/`aud`).
pub fn verify(
    token: &str,
    policy: &VerificationPolicy,
    clock: &dyn Clock,
) -> Result<VerifiedToken, VerifyError> {
    let caps = &policy.caps;

    // Stage 1: size cap, before any base64/JSON/crypto work.
    if token.len() > caps.max_token_bytes {
        return reject(RejectReason::TokenTooLarge);
    }

    // Stage 2: structural split. Exactly three segments; a 5-segment JWE is
    // rejected here, cheaply, before any field is decoded.
    let (header_b64, payload_b64, signature_b64) =
        split_segments(token).ok_or_else(|| VerifyError::new(RejectReason::MalformedStructure))?;

    // Bound each segment's decoded size before allocating a decode buffer.
    if header_b64.len() > max_b64_len(caps.max_header_bytes) {
        return reject(RejectReason::SegmentTooLarge);
    }
    if payload_b64.len() > max_b64_len(caps.max_payload_bytes) {
        return reject(RejectReason::SegmentTooLarge);
    }

    // Stage 3: decode + parse + guard the protected header.
    let header_bytes = decode_b64(header_b64)?;
    let header = header::parse(&header_bytes, caps).map_err(VerifyError::new)?;

    // Stage 4: the claimed algorithm must be in the caller's allowlist.
    if !policy.algorithms.contains(&header.alg) {
        return reject(RejectReason::AlgNotAllowed);
    }

    // Stage 5: select the trusted key(s) eligible for this token.
    let candidates = select_keys(policy, &header)?;

    // Stage 6: decode the signature.
    let signature = decode_b64(signature_b64)?;

    // Stage 7: the one signature check, against the signing input (the raw
    // header and payload segments joined by a dot, exactly as signed).
    let signing_input = signing_input_bytes(header_b64, payload_b64);
    let verified = candidates.iter().any(|key| {
        crypto::verify_signature(header.alg, &key.material, &signing_input, &signature).is_ok()
    });
    if !verified {
        return reject(RejectReason::SignatureInvalid);
    }

    // Stage 8: only now decode and enforce the claims, against the env clock.
    let payload_bytes = decode_b64(payload_b64)?;
    let now_secs = now_seconds(clock);
    let claims =
        claims::parse_and_enforce(&payload_bytes, policy, now_secs).map_err(VerifyError::new)?;

    Ok(VerifiedToken {
        algorithm: header.alg,
        key_id: header.kid,
        claims,
    })
}

/// Extract the `kid` from a compact JWS/JWT's protected header WITHOUT verifying
/// the token, for the narrow purpose of a JWKS-refetch HINT on upstream key
/// rotation (issue #75).
///
/// This reads NO trust from the token: the returned `kid` is a bare selector value.
/// A caller may only use it to decide whether an already-trusted key set answers to
/// this `kid` (and so whether to refetch a connector's JWKS); it can never introduce
/// a key or steer verification, which stays entirely inside [`verify`]. The read is
/// bounded (a header segment above `MAX_HINT_HEADER_B64` yields [`None`]) and never
/// touches key material. Returns [`None`] when the token is malformed, the header is
/// not a JSON object, or no string `kid` is present.
#[must_use]
pub fn compact_jws_kid(token: &str) -> Option<String> {
    // A generous cap for a HEADER segment: enough for any realistic `kid`, small
    // enough that a hostile token cannot force a large base64/JSON decode here.
    const MAX_HINT_HEADER_B64: usize = 8192;
    let header_b64 = token.split('.').next()?;
    if header_b64.is_empty() || header_b64.len() > MAX_HINT_HEADER_B64 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(header_b64.as_bytes()).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    match value.get("kid") {
        Some(serde_json::Value::String(kid)) => Some(kid.clone()),
        _ => None,
    }
}

/// Split into exactly three non-empty `.`-separated segments.
///
/// Returns `None` for any other shape (two segments, four, five as in a JWE, an
/// empty segment, or a trailing dot). An `alg: none` unsecured JWS has an empty
/// third segment and is rejected here as well as at the header stage.
pub(crate) fn split_segments(token: &str) -> Option<(&str, &str, &str)> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() {
        return None; // four or more segments (for example a JWE)
    }
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return None;
    }
    Some((header, payload, signature))
}

/// The maximum base64url length that decodes to at most `decoded_bytes` bytes,
/// plus a small slack. Unpadded base64url uses 4 characters per 3 bytes.
pub(crate) fn max_b64_len(decoded_bytes: usize) -> usize {
    decoded_bytes
        .saturating_mul(4)
        .saturating_div(3)
        .saturating_add(4)
}

fn decode_b64(segment: &str) -> Result<Vec<u8>, VerifyError> {
    URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|_| VerifyError::new(RejectReason::Base64Malformed))
}

fn signing_input_bytes(header_b64: &str, payload_b64: &str) -> Vec<u8> {
    let mut input = Vec::with_capacity(header_b64.len() + 1 + payload_b64.len());
    input.extend_from_slice(header_b64.as_bytes());
    input.push(b'.');
    input.extend_from_slice(payload_b64.as_bytes());
    input
}

/// Resolve the trusted keys eligible to verify this token.
///
/// A `kid` may only select among already-trusted keys: if the token names a
/// `kid` that matches no trusted key, the token is rejected (never a key
/// source). Among the selected keys, only those whose family matches the claimed
/// algorithm are eligible; if none match, the token is rejected for a key-type
/// mismatch (this is where `RS256`-against-EC style confusion dies).
fn select_keys<'p>(
    policy: &'p VerificationPolicy,
    header: &ProtectedHeader,
) -> Result<Vec<&'p TrustedKey>, VerifyError> {
    let family = header.alg.key_family();

    if let Some(kid) = &header.kid {
        let names_a_key = policy
            .keys
            .iter()
            .any(|key| key.kid.as_deref() == Some(kid.as_str()));
        if !names_a_key {
            return reject(RejectReason::UnknownKid);
        }
    }

    let candidates: Vec<&TrustedKey> = policy
        .keys
        .iter()
        .filter(|key| {
            let kid_matches = match &header.kid {
                Some(kid) => key.kid.as_deref() == Some(kid.as_str()),
                None => true,
            };
            kid_matches && key.material.family() == family
        })
        .collect();

    if candidates.is_empty() {
        return reject(RejectReason::KeyTypeMismatch);
    }
    Ok(candidates)
}

fn now_seconds(clock: &dyn Clock) -> i64 {
    let secs = clock
        .now_utc()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// Collapse a reason into the uniform error. Centralized so every rejection path
/// looks identical from the outside.
fn reject<T>(reason: RejectReason) -> Result<T, VerifyError> {
    Err(VerifyError::new(reason))
}

#[cfg(test)]
mod tests {
    use super::compact_jws_kid;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn token_with_header(header: &str) -> String {
        let head = URL_SAFE_NO_PAD.encode(header.as_bytes());
        format!("{head}.eyJ9.c2ln")
    }

    #[test]
    fn compact_jws_kid_reads_the_header_kid_without_verifying() {
        let token = token_with_header(r#"{"alg":"EdDSA","kid":"up-2"}"#);
        assert_eq!(compact_jws_kid(&token).as_deref(), Some("up-2"));
    }

    #[test]
    fn compact_jws_kid_is_none_when_absent_or_malformed() {
        assert_eq!(
            compact_jws_kid(&token_with_header(r#"{"alg":"EdDSA"}"#)),
            None
        );
        // A non-string kid is not a usable selector.
        assert_eq!(compact_jws_kid(&token_with_header(r#"{"kid":42}"#)), None);
        // Not base64, not JSON, and the empty string all yield None (never a panic).
        assert_eq!(compact_jws_kid("not-a-token"), None);
        assert_eq!(compact_jws_kid(""), None);
    }
}
