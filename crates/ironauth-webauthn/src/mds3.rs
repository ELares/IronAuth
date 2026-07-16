// SPDX-License-Identifier: MIT OR Apache-2.0

//! FIDO Metadata Service (MDS3) BLOB verification (issue #66 PR B).
//!
//! The MDS3 BLOB is a JWS (a JWT compact serialization) whose header carries an
//! `x5c` certificate chain and whose payload is the metadata: a sequence number
//! (`no`), a `nextUpdate` date, and per-authenticator `entries` each keyed by
//! AAGUID and carrying that model's `attestationRootCertificates`. Trust is
//! anchored OUT OF BAND on the compiled-in FIDO Alliance Root CA (never a value
//! taken from the blob): [`verify_blob`] parses the `x5c` chain, pins it to the
//! supplied root, checks each certificate's validity window at the caller's clock
//! instant, and only then verifies the JWS signature with the chain's leaf key
//! through the one ring-backed JOSE primitive. A blob whose chain does not
//! terminate at the pinned root, whose signature does not verify, or which is
//! stale is rejected; the caller caches only a verified payload.
//!
//! This module is PURE: it takes the blob bytes, the pinned root, and the clock
//! instant as arguments and returns a parsed payload. The fetch (through the
//! SSRF-hardened `ironauth-fetch` client), the clock read (`env.clock()`), and
//! the cache write live in the OIDC sync job, so this stays a side-effect free,
//! unit-testable verifier exactly like the ceremony core.

use serde_json::Value;

use crate::der::{self, tag};
use crate::x509::{self, Certificate, X509Error};

/// The default FIDO Alliance MDS3 BLOB endpoint. A deployment may override it
/// (mirroring `hibp_base_url`) through `webauthn.mds3_base_url`; the pinned root
/// is compiled in and never fetched.
pub const MDS3_BASE_URL: &str = "https://mds3.fidoalliance.org/";

/// Why an MDS3 BLOB was rejected. One opaque set; the sync job records the label
/// for diagnostics and never exposes an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mds3Error {
    /// The compact JWS was not three base64url segments.
    MalformedJws,
    /// The JWS header or the payload JSON could not be parsed.
    MalformedJson,
    /// The header carried no usable `x5c` chain.
    MissingChain,
    /// A certificate in the chain (or the pinned root) was malformed.
    MalformedCertificate,
    /// The `x5c` chain did not verify against the pinned FIDO root (untrusted,
    /// expired, name-broken, or bad signature).
    UntrustedChain,
    /// The JWS signature did not verify against the chain leaf key.
    BadSignature,
    /// The payload was missing a required field or held a malformed value.
    MalformedPayload,
}

impl From<X509Error> for Mds3Error {
    fn from(err: X509Error) -> Self {
        match err {
            X509Error::Malformed | X509Error::UnsupportedKey | X509Error::UnsupportedSignature => {
                Mds3Error::MalformedCertificate
            }
            _ => Mds3Error::UntrustedChain,
        }
    }
}

/// A verified MDS3 payload: the sequence number, the next-update instant, and the
/// per-AAGUID entries the registration path consults.
///
/// It is `serde`-serializable so the OIDC sync job can persist the VERIFIED
/// snapshot into the `mds3_blob_cache.payload_jsonb` column and the registration
/// path can read it back without re-verifying the whole blob per ceremony (the
/// signature chain was already checked when the snapshot was cached).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Mds3Payload {
    /// The monotonically increasing blob sequence number (`no`).
    pub no: i64,
    /// `nextUpdate` as a Unix timestamp (midnight UTC of the stated date).
    pub next_update: i64,
    /// One entry per known authenticator model.
    pub entries: Vec<Mds3Entry>,
}

/// One MDS3 entry: an authenticator model's AAGUID and its attestation root
/// certificates (raw DER), which a packed attestation statement must chain to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Mds3Entry {
    /// The 16-byte AAGUID.
    pub aaguid: [u8; 16],
    /// The model's attestation root certificates, raw DER.
    pub attestation_root_certs: Vec<Vec<u8>>,
}

impl Mds3Entry {
    /// The AAGUID's canonical hyphenated-hex string form.
    #[must_use]
    pub fn aaguid_hex(&self) -> String {
        aaguid_to_hex(&self.aaguid)
    }
}

/// Verify an MDS3 BLOB against the pinned FIDO root at `now_unix`, returning the
/// parsed payload on success.
///
/// # Errors
///
/// The specific [`Mds3Error`] for the first failing structural or trust check.
pub fn verify_blob(
    blob: &str,
    pinned_root_der: &[u8],
    now_unix: i64,
) -> Result<Mds3Payload, Mds3Error> {
    let mut parts = blob.split('.');
    let header_b64 = parts.next().ok_or(Mds3Error::MalformedJws)?;
    let payload_b64 = parts.next().ok_or(Mds3Error::MalformedJws)?;
    let sig_b64 = parts.next().ok_or(Mds3Error::MalformedJws)?;
    if parts.next().is_some() {
        return Err(Mds3Error::MalformedJws);
    }

    let header_bytes = b64url(header_b64).ok_or(Mds3Error::MalformedJws)?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| Mds3Error::MalformedJson)?;
    let x5c = header
        .get("x5c")
        .and_then(Value::as_array)
        .ok_or(Mds3Error::MissingChain)?;
    if x5c.is_empty() {
        return Err(Mds3Error::MissingChain);
    }
    let chain_ders: Vec<Vec<u8>> = x5c
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .and_then(b64_std)
                .ok_or(Mds3Error::MalformedCertificate)
        })
        .collect::<Result<_, _>>()?;
    let chain: Vec<Certificate<'_>> = chain_ders
        .iter()
        .map(|der_bytes| x509::parse_certificate(der_bytes))
        .collect::<Result<_, _>>()?;

    let pinned_root =
        x509::parse_certificate(pinned_root_der).map_err(|_| Mds3Error::MalformedCertificate)?;

    // Pin the x5c chain to the compiled-in root, at the clock instant. This rejects
    // a chain to a wrong root, an expired certificate, and a broken name chain.
    let leaf = x509::verify_chain(&chain, std::slice::from_ref(&pinned_root), now_unix)?;

    // Verify the JWS signature with the (now trusted) leaf key over the ASCII
    // signing input `header_b64 . payload_b64`. A JWS ES256 signature is fixed-width
    // r||s, so this uses the JWS primitive, not the DER one the cert chain used.
    let signature = b64url(sig_b64).ok_or(Mds3Error::MalformedJws)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    ironauth_jose::verify_jws_signature(&leaf.public_key, signing_input.as_bytes(), &signature)
        .map_err(|_| Mds3Error::BadSignature)?;

    let payload_bytes = b64url(payload_b64).ok_or(Mds3Error::MalformedJws)?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| Mds3Error::MalformedJson)?;
    parse_payload(&payload)
}

/// Parse the (already signature-verified) MDS3 payload JSON.
fn parse_payload(payload: &Value) -> Result<Mds3Payload, Mds3Error> {
    let no = payload
        .get("no")
        .and_then(Value::as_i64)
        .ok_or(Mds3Error::MalformedPayload)?;
    let next_update_str = payload
        .get("nextUpdate")
        .and_then(Value::as_str)
        .ok_or(Mds3Error::MalformedPayload)?;
    let next_update = parse_date(next_update_str).ok_or(Mds3Error::MalformedPayload)?;
    let entries_json = payload
        .get("entries")
        .and_then(Value::as_array)
        .ok_or(Mds3Error::MalformedPayload)?;

    let mut entries = Vec::new();
    for entry in entries_json {
        let Some(aaguid_str) = entry.get("aaguid").and_then(Value::as_str) else {
            // An entry without an AAGUID (a U2F/UAF entry keyed differently) is not
            // relevant to a passkey AAGUID lookup; skip it rather than fail the blob.
            continue;
        };
        let Some(aaguid) = parse_aaguid(aaguid_str) else {
            continue;
        };
        let roots = entry
            .get("metadataStatement")
            .and_then(|s| s.get("attestationRootCertificates"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| c.as_str().and_then(b64_std))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        entries.push(Mds3Entry {
            aaguid,
            attestation_root_certs: roots,
        });
    }

    Ok(Mds3Payload {
        no,
        next_update,
        entries,
    })
}

/// Parse an MDS3 `nextUpdate` date (`YYYY-MM-DD`) into a Unix timestamp at
/// midnight UTC, by reusing the DER `GeneralizedTime` parser.
fn parse_date(text: &str) -> Option<i64> {
    let mut it = text.split('-');
    let y = it.next()?;
    let m = it.next()?;
    let d = it.next()?;
    if it.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let generalized = format!("{y}{m}{d}000000Z");
    der::parse_time(tag::GENERALIZED_TIME, generalized.as_bytes()).ok()
}

/// Parse a hyphenated-hex AAGUID (`0132d110-bf4e-4208-a403-ab4f5f12efe5`) into 16
/// bytes.
fn parse_aaguid(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Format 16 AAGUID bytes as the canonical hyphenated-hex string.
fn aaguid_to_hex(aaguid: &[u8; 16]) -> String {
    use core::fmt::Write as _;
    let mut h = String::with_capacity(32);
    for byte in aaguid {
        let _ = write!(h, "{byte:02x}");
    }
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// base64url (no padding) decode.
fn b64url(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()
}

/// base64 (standard, padded) decode, as an `x5c` entry uses.
fn b64_std(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testpki::{CertSpec, b64_std as enc_b64_std, build_cert, build_jws};

    const ROOT_SEED: [u8; 32] = [1; 32];
    const INT_SEED: [u8; 32] = [2; 32];
    const LEAF_SEED: [u8; 32] = [3; 32];
    const MODEL_ROOT_SEED: [u8; 32] = [4; 32];
    const NOW: i64 = 1_700_000_000;
    const FAR_FUTURE: i64 = 4_102_444_800; // 2100-01-01.

    fn root(not_after: i64) -> Vec<u8> {
        build_cert(&CertSpec {
            subject_cn: "FIDO Test Root",
            issuer_cn: "FIDO Test Root",
            subject_seed: ROOT_SEED,
            issuer_seed: ROOT_SEED,
            not_before: 0,
            not_after,
            aaguid: None,
        })
    }

    fn intermediate(not_after: i64) -> Vec<u8> {
        build_cert(&CertSpec {
            subject_cn: "FIDO Test Intermediate",
            issuer_cn: "FIDO Test Root",
            subject_seed: INT_SEED,
            issuer_seed: ROOT_SEED,
            not_before: 0,
            not_after,
            aaguid: None,
        })
    }

    fn leaf(not_after: i64) -> Vec<u8> {
        build_cert(&CertSpec {
            subject_cn: "FIDO Test Signer",
            issuer_cn: "FIDO Test Intermediate",
            subject_seed: LEAF_SEED,
            issuer_seed: INT_SEED,
            not_before: 0,
            not_after,
            aaguid: None,
        })
    }

    fn payload_json() -> String {
        let model_root = build_cert(&CertSpec {
            subject_cn: "Model Attestation Root",
            issuer_cn: "Model Attestation Root",
            subject_seed: MODEL_ROOT_SEED,
            issuer_seed: MODEL_ROOT_SEED,
            not_before: 0,
            not_after: FAR_FUTURE,
            aaguid: None,
        });
        format!(
            "{{\"no\":42,\"nextUpdate\":\"2099-01-01\",\"entries\":[\
             {{\"aaguid\":\"01020304-0506-0708-090a-0b0c0d0e0f10\",\
             \"metadataStatement\":{{\"attestationRootCertificates\":[\"{}\"]}}}}]}}",
            enc_b64_std(&model_root)
        )
    }

    fn valid_blob(not_after: i64) -> String {
        build_jws(
            &[leaf(not_after), intermediate(not_after)],
            &payload_json(),
            &LEAF_SEED,
        )
    }

    #[test]
    fn a_valid_blob_verifies_and_parses_entries() {
        let payload = verify_blob(&valid_blob(FAR_FUTURE), &root(FAR_FUTURE), NOW).unwrap();
        assert_eq!(payload.no, 42);
        assert_eq!(payload.entries.len(), 1);
        assert_eq!(
            payload.entries[0].aaguid,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
        assert_eq!(payload.entries[0].attestation_root_certs.len(), 1);
        assert_eq!(
            payload.entries[0].aaguid_hex(),
            "01020304-0506-0708-090a-0b0c0d0e0f10"
        );
    }

    #[test]
    fn a_chain_to_the_wrong_root_is_rejected() {
        // Pin a DIFFERENT self-signed root: the x5c chain no longer terminates at it.
        let wrong_root = build_cert(&CertSpec {
            subject_cn: "Some Other Root",
            issuer_cn: "Some Other Root",
            subject_seed: [9; 32],
            issuer_seed: [9; 32],
            not_before: 0,
            not_after: FAR_FUTURE,
            aaguid: None,
        });
        assert_eq!(
            verify_blob(&valid_blob(FAR_FUTURE), &wrong_root, NOW),
            Err(Mds3Error::UntrustedChain)
        );
    }

    #[test]
    fn an_expired_certificate_is_rejected() {
        // The chain certificates expire before NOW.
        assert_eq!(
            verify_blob(&valid_blob(1_000), &root(1_000), NOW),
            Err(Mds3Error::UntrustedChain)
        );
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let blob = valid_blob(FAR_FUTURE);
        // Flip the last character of the signature segment.
        let mut chars: Vec<char> = blob.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(
            verify_blob(&tampered, &root(FAR_FUTURE), NOW),
            Err(Mds3Error::BadSignature)
        );
    }

    #[test]
    fn a_tampered_payload_is_rejected() {
        // Re-sign nothing: swap the payload segment for a different (valid-JSON) one,
        // keeping the header and signature. The signature no longer covers it.
        let blob = valid_blob(FAR_FUTURE);
        let mut parts: Vec<&str> = blob.split('.').collect();
        let forged_payload =
            b64url_encode(br#"{"no":9999,"nextUpdate":"2099-01-01","entries":[]}"#);
        parts[1] = &forged_payload;
        let tampered = parts.join(".");
        assert_eq!(
            verify_blob(&tampered, &root(FAR_FUTURE), NOW),
            Err(Mds3Error::BadSignature)
        );
    }

    fn b64url_encode(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
}
