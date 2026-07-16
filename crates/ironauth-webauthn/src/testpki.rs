// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test-only DER X.509 certificate and JWS builders (issue #66 PR B).
//!
//! A self-contained minimal DER ENCODER, the mirror of the [`crate::der`] reader,
//! used ONLY by unit tests to synthesise a fake FIDO PKI (a root, an intermediate,
//! and an AAGUID leaf) and a hand-built MDS3 BLOB JWS, so the chain verifier and
//! the packed-attestation path can be exercised end to end without a browser or a
//! captured production blob. Everything signs with Ed25519 through the jose
//! `test-util` helper (the one crate allowed to name `ring`), so this test code
//! never names `ring` either. It is compiled only under `cfg(test)`.

#![allow(clippy::missing_panics_doc, clippy::cast_possible_truncation)]

use ironauth_jose::webauthn::test_util;

use crate::der::tag;

/// Encode a DER length.
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        bytes.reverse();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend_from_slice(&bytes);
        out
    }
}

/// Encode a DER TLV.
pub fn tlv(tag_byte: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag_byte];
    out.extend_from_slice(&der_len(contents.len()));
    out.extend_from_slice(contents);
    out
}

/// Encode a `SEQUENCE` from already-encoded elements.
pub fn seq(elements: &[Vec<u8>]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &elements.concat())
}

/// Encode an `OBJECT IDENTIFIER` from dotted arcs.
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut stack = Vec::new();
        let mut v = arc;
        stack.push((v & 0x7F) as u8);
        v >>= 7;
        while v > 0 {
            stack.push(((v & 0x7F) as u8) | 0x80);
            v >>= 7;
        }
        stack.reverse();
        body.extend_from_slice(&stack);
    }
    tlv(tag::OID, &body)
}

/// Encode an `INTEGER` from a small unsigned value.
fn int(value: u64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    // Prepend a zero if the top bit is set (keep it positive).
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(tag::INTEGER, &bytes)
}

/// Encode a `BIT STRING` with zero unused bits.
fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![0x00];
    body.extend_from_slice(bytes);
    tlv(tag::BIT_STRING, &body)
}

/// Encode a `GeneralizedTime` from a Unix timestamp (UTC, second precision).
fn generalized_time(unix: i64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = unix_to_civil(unix);
    let text = format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z");
    tlv(tag::GENERALIZED_TIME, text.as_bytes())
}

/// The Ed25519 `AlgorithmIdentifier` (`SEQUENCE { OID 1.3.101.112 }`, no params).
fn ed25519_alg_id() -> Vec<u8> {
    seq(&[oid(&[1, 3, 101, 112])])
}

/// A `Name` with a single common-name RDN.
fn name_cn(cn: &str) -> Vec<u8> {
    let atv = seq(&[oid(&[2, 5, 4, 3]), tlv(tag::UTF8_STRING, cn.as_bytes())]);
    let rdn = tlv(tag::SET, &atv);
    seq(&[rdn])
}

/// An Ed25519 `SubjectPublicKeyInfo`.
fn ed25519_spki(public_key: &[u8]) -> Vec<u8> {
    seq(&[ed25519_alg_id(), bit_string(public_key)])
}

/// The FIDO AAGUID extension (`id-fido-gen-ce-aaguid`), non-critical.
fn aaguid_extension(aaguid: &[u8; 16]) -> Vec<u8> {
    // extnValue = OCTET STRING wrapping OCTET STRING(aaguid).
    let inner = tlv(tag::OCTET_STRING, aaguid);
    let ext_value = tlv(tag::OCTET_STRING, &inner);
    seq(&[oid(&[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4]), ext_value])
}

/// A test certificate specification.
pub struct CertSpec<'a> {
    /// The subject common name.
    pub subject_cn: &'a str,
    /// The issuer common name (equal to `subject_cn` for a self-signed root).
    pub issuer_cn: &'a str,
    /// The subject's Ed25519 seed (its public key is derived from it).
    pub subject_seed: [u8; 32],
    /// The issuer's Ed25519 seed (equal to `subject_seed` for a self-signed root).
    pub issuer_seed: [u8; 32],
    /// `notBefore` as a Unix timestamp.
    pub not_before: i64,
    /// `notAfter` as a Unix timestamp.
    pub not_after: i64,
    /// An optional FIDO AAGUID extension value.
    pub aaguid: Option<[u8; 16]>,
}

/// Build a signed DER certificate from a [`CertSpec`].
#[must_use]
pub fn build_cert(spec: &CertSpec<'_>) -> Vec<u8> {
    let subject_pub = test_util::ed25519_public_key_from_seed(&spec.subject_seed);
    let mut tbs_elements = vec![
        // [0] version = v3 (INTEGER 2).
        tlv(tag::CONTEXT_CONSTRUCTED, &int(2)),
        // serialNumber.
        int(1),
        // signature AlgorithmIdentifier (Ed25519).
        ed25519_alg_id(),
        // issuer.
        name_cn(spec.issuer_cn),
        // validity.
        seq(&[
            generalized_time(spec.not_before),
            generalized_time(spec.not_after),
        ]),
        // subject.
        name_cn(spec.subject_cn),
        // subjectPublicKeyInfo.
        ed25519_spki(&subject_pub),
    ];
    if let Some(aaguid) = spec.aaguid {
        // [3] EXPLICIT extensions.
        let extensions = seq(&[aaguid_extension(&aaguid)]);
        tbs_elements.push(tlv(tag::CONTEXT_CONSTRUCTED | 3, &extensions));
    }
    let tbs = seq(&tbs_elements);
    let signature = test_util::ed25519_sign(&spec.issuer_seed, &tbs);
    seq(&[tbs, ed25519_alg_id(), bit_string(&signature)])
}

/// base64url (no padding) encode.
pub fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// base64 (standard, padded) encode, as an MDS3 `x5c` entry uses.
pub fn b64_std(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Build a compact JWS (`header.payload.sig`) signed with Ed25519 over the given
/// `signing_seed`, embedding `x5c` (standard-base64 DER certs) in the header.
#[must_use]
pub fn build_jws(x5c_ders: &[Vec<u8>], payload_json: &str, signing_seed: &[u8; 32]) -> String {
    let x5c: Vec<String> = x5c_ders.iter().map(|d| b64_std(d)).collect();
    let x5c_field = x5c
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(",");
    let header = format!("{{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"x5c\":[{x5c_field}]}}");
    let header_b64 = b64url(header.as_bytes());
    let payload_b64 = b64url(payload_json.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = test_util::ed25519_sign(signing_seed, signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(&sig))
}

/// Convert a Unix timestamp to civil UTC components (inverse of the reader's
/// `civil_to_unix`), for the test time encoder.
fn unix_to_civil(unix: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, secs / 3_600, (secs % 3_600) / 60, secs % 60)
}
