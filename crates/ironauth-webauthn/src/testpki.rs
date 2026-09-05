// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test-only DER X.509 certificate and JWS builders (issue #66 PR B).
//!
//! THE ENCODER IS NO LONGER HERE. These primitives are now `ironauth_der::write`, because the
//! SP metadata document (issue #139) needs a certificate writer in production and two encoders
//! would be two answers to what a certificate says -- the same argument the reader half already
//! makes. What stays here is the FIDO-specific grammar: the AAGUID extension, the chain shape,
//! and the Ed25519 spelling.
//!
//! IT WAS NOT THE WORKSPACE'S ONLY DER WRITER, which an earlier version of this paragraph said.
//! Two more live in test files -- `ironauth-saml/tests/certificates.rs` and
//! `ironauth-oidc/tests/webauthn_attestation.rs` -- and each builds fixtures for a READER, which
//! is why they were left alone: a fixture that agrees with the production encoder by
//! construction cannot catch the encoder disagreeing with a real certificate. They are not
//! covered by the base-128 first-subidentifier fix in this change, and no OID they write reaches
//! the case it fixes.
//!
//! Used ONLY by unit tests to synthesise a fake FIDO PKI (a root, an intermediate,
//! and an AAGUID leaf) and a hand-built MDS3 BLOB JWS, so the chain verifier and
//! the packed-attestation path can be exercised end to end without a browser or a
//! captured production blob. Everything signs with Ed25519 through the jose
//! `test-util` helper (the one crate allowed to name `ring`), so this test code
//! never names `ring` either. It is compiled only under `cfg(test)`.

#![allow(clippy::missing_panics_doc, clippy::cast_possible_truncation)]

use ironauth_jose::webauthn::test_util;

use crate::der::tag;
use ironauth_der::write::name_common as name_cn;
use ironauth_der::write::{bit_string, generalized_time, oid, seq, tlv, uint as int};

/// The Ed25519 `AlgorithmIdentifier` (`SEQUENCE { OID 1.3.101.112 }`, no params).
fn ed25519_alg_id() -> Vec<u8> {
    seq(&[oid(&[1, 3, 101, 112])])
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

/// The `basicConstraints` extension (`id-ce-basicConstraints`, 2.5.29.19),
/// critical, asserting `cA` = TRUE with an optional `pathLenConstraint`.
fn basic_constraints_extension(path_len: Option<u64>) -> Vec<u8> {
    // SEQUENCE { cA BOOLEAN TRUE, pathLenConstraint INTEGER OPTIONAL }.
    let mut inner = vec![tlv(tag::BOOLEAN, &[0xFF])];
    if let Some(len) = path_len {
        inner.push(int(len));
    }
    let ext_value = tlv(tag::OCTET_STRING, &seq(&inner));
    seq(&[
        oid(&[2, 5, 29, 19]),
        tlv(tag::BOOLEAN, &[0xFF]), // critical
        ext_value,
    ])
}

/// The `keyUsage` extension (`id-ce-keyUsage`, 2.5.29.15), critical, with the
/// given bits (bit 0 is the most-significant bit of the first octet). Emitted
/// with zero unused bits over one or two octets.
fn key_usage_extension(bits: u16) -> Vec<u8> {
    let b0 = (bits >> 8) as u8;
    let b1 = (bits & 0xFF) as u8;
    let mut body = vec![0x00, b0];
    if b1 != 0 {
        body.push(b1);
    }
    let bit_string = tlv(tag::BIT_STRING, &body);
    let ext_value = tlv(tag::OCTET_STRING, &bit_string);
    seq(&[
        oid(&[2, 5, 29, 15]),
        tlv(tag::BOOLEAN, &[0xFF]), // critical
        ext_value,
    ])
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
    /// Emit a critical `basicConstraints` `CA:TRUE`. Set on a certificate that
    /// issues another certificate (a root or intermediate); left `false` on an
    /// end-entity leaf.
    pub is_ca: bool,
    /// An optional `pathLenConstraint` (only meaningful alongside `is_ca`).
    pub path_len: Option<u64>,
    /// An optional critical `keyUsage` extension (bits big-endian, bit 0 is the
    /// MSB of the first octet). `keyCertSign` is bit 5 (`0x0400`).
    pub key_usage: Option<u16>,
}

/// Build a signed DER certificate from a [`CertSpec`], appending extra
/// already-encoded `Extension` SEQUENCEs verbatim.
///
/// A separate entry point rather than a field on [`CertSpec`]: the struct is
/// built by exhaustive literal at 28 sites, so a new field would edit all of
/// them to express something only the extension tests need. Use [`extension`]
/// to build the elements.
#[must_use]
pub fn build_cert_with_extensions(spec: &CertSpec<'_>, extra: &[Vec<u8>]) -> Vec<u8> {
    build_cert_inner(spec, extra)
}

/// Encode one `Extension` SEQUENCE: an OID, the `critical` BOOLEAN when it is
/// TRUE, and the `extnValue` OCTET STRING wrapping `value`.
///
/// `critical_octet` is written into the BOOLEAN verbatim rather than as a
/// `bool`, so a test can emit the non-canonical encodings DER forbids.
#[must_use]
pub fn extension(arcs: &[u64], critical_octet: Option<u8>, value: &[u8]) -> Vec<u8> {
    let mut elements = vec![oid(arcs)];
    if let Some(octet) = critical_octet {
        elements.push(tlv(tag::BOOLEAN, &[octet]));
    }
    elements.push(tlv(tag::OCTET_STRING, value));
    seq(&elements)
}

/// A `basicConstraints` extnValue asserting `cA` with the given BOOLEAN octet,
/// so a test can present the non-canonical `TRUE` encodings DER forbids.
#[must_use]
pub fn basic_constraints_value(ca_octet: u8) -> Vec<u8> {
    seq(&[tlv(tag::BOOLEAN, &[ca_octet])])
}

/// Build a signed DER certificate from a [`CertSpec`].
#[must_use]
pub fn build_cert(spec: &CertSpec<'_>) -> Vec<u8> {
    build_cert_inner(spec, &[])
}

fn build_cert_inner(spec: &CertSpec<'_>, extra: &[Vec<u8>]) -> Vec<u8> {
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
    // [3] EXPLICIT extensions, emitted when any extension is present.
    let mut extensions: Vec<Vec<u8>> = Vec::new();
    if spec.is_ca || spec.path_len.is_some() {
        extensions.push(basic_constraints_extension(spec.path_len));
    }
    if let Some(bits) = spec.key_usage {
        extensions.push(key_usage_extension(bits));
    }
    if let Some(aaguid) = spec.aaguid {
        extensions.push(aaguid_extension(&aaguid));
    }
    extensions.extend_from_slice(extra);
    if !extensions.is_empty() {
        tbs_elements.push(tlv(tag::CONTEXT_CONSTRUCTED | 3, &seq(&extensions)));
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
