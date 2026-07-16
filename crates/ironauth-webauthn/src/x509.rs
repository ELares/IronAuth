// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal X.509 certificate parsing and chain verification (issue #66 PR B).
//!
//! This reads the fields a FIDO attestation / MDS3 chain check needs from a DER
//! certificate: the raw `tbsCertificate` bytes (the signed message), the
//! signature algorithm and value, the validity window, the issuer and subject
//! distinguished names (reduced to their common-name text, which is all a name
//! chain match needs here), the subject public key (as a [`WebauthnKey`]), and
//! the FIDO AAGUID extension when present. It performs no cryptography itself:
//! every signature check is delegated to the one ring-backed primitive in
//! `ironauth-jose`, exactly as the ceremony verifier is.
//!
//! # What "chain verification" means here
//!
//! [`verify_chain`] walks `leaf -> intermediates... -> a trusted anchor`,
//! checking at each hop that the child's issuer name matches the parent's subject
//! name, that the parent's key verifies the child's signature, and that BOTH
//! certificates are inside their validity window at the caller-supplied instant
//! (from the `ironauth-env` clock, never a local `SystemTime`). The anchor set is
//! pinned OUT OF BAND (the compiled-in FIDO root for the MDS3 BLOB, or the MDS3
//! metadata's `attestationRootCertificates` for a packed statement); an `x5c`
//! header can never introduce its own trust. Revocation (CRL/OCSP) is DEFERRED
//! for v1 (the design surfaces MDS3 `nextUpdate` staleness in admin health
//! instead); this is a name-and-signature path validation, not a full RFC 5280
//! policy engine, which the module docs make explicit so no caller over-trusts
//! it.

use ironauth_jose::WebauthnKey;

use crate::der::{self, Der, DerError, tag};

/// Why a certificate parse or chain check failed. One opaque set; the caller maps
/// it to a single non-enumerating outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509Error {
    /// The certificate DER was malformed.
    Malformed,
    /// The subject public key used an algorithm this verifier does not support.
    UnsupportedKey,
    /// The signature algorithm on a certificate is not supported.
    UnsupportedSignature,
    /// A certificate in the chain was outside its validity window at the instant.
    Expired,
    /// A child's issuer name did not match its parent's subject name.
    NameChainBroken,
    /// A certificate signature did not verify against its issuer's key.
    BadSignature,
    /// The chain did not terminate at any pinned trust anchor.
    UntrustedRoot,
    /// The chain was empty or exceeded the depth bound.
    BadChain,
}

impl From<DerError> for X509Error {
    fn from(_: DerError) -> Self {
        X509Error::Malformed
    }
}

// Signature-algorithm OIDs (as dotted arcs).
const OID_ED25519: &[u64] = &[1, 3, 101, 112];
const OID_ECDSA_SHA256: &[u64] = &[1, 2, 840, 10_045, 4, 3, 2];
const OID_RSA_SHA256: &[u64] = &[1, 2, 840, 113_549, 1, 1, 11];
// Subject-public-key-algorithm OIDs.
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10_045, 2, 1];
const OID_P256: &[u64] = &[1, 2, 840, 10_045, 3, 1, 7];
const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113_549, 1, 1, 1];
// The FIDO AAGUID certificate extension (id-fido-gen-ce-aaguid).
const OID_FIDO_AAGUID: &[u64] = &[1, 3, 6, 1, 4, 1, 45_724, 1, 1, 4];
// The common-name attribute type (id-at-commonName).
const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];

/// The maximum certificate-chain depth (leaf plus intermediates). A real FIDO
/// chain is two or three deep; a longer one is refused rather than walked.
const MAX_CHAIN_DEPTH: usize = 6;

/// A parsed certificate: the fields a chain check reads, borrowing from the input
/// DER (so the signed `tbs` bytes stay a slice of the original).
#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    /// The raw DER of the `tbsCertificate` element (the signed message).
    pub tbs: &'a [u8],
    /// The issuer common name (the name-chain parent key).
    pub issuer_cn: Option<String>,
    /// The subject common name.
    pub subject_cn: Option<String>,
    /// `notBefore`, as a Unix timestamp (seconds).
    pub not_before: i64,
    /// `notAfter`, as a Unix timestamp (seconds).
    pub not_after: i64,
    /// The subject public key.
    pub public_key: WebauthnKey,
    /// The signature algorithm OID arcs from the outer `signatureAlgorithm`.
    pub sig_alg: Vec<u64>,
    /// The signature value bytes (the BIT STRING contents, unused bits stripped).
    pub signature: Vec<u8>,
    /// The FIDO AAGUID from the id-fido-gen-ce-aaguid extension, if present.
    pub aaguid: Option<[u8; 16]>,
}

impl Certificate<'_> {
    /// Whether the certificate is within its validity window at `now_unix`.
    #[must_use]
    pub fn is_valid_at(&self, now_unix: i64) -> bool {
        now_unix >= self.not_before && now_unix <= self.not_after
    }
}

/// Parse a DER certificate.
///
/// # Errors
///
/// [`X509Error::Malformed`] on any structural problem, [`X509Error::UnsupportedKey`]
/// for a subject key algorithm this verifier does not implement.
pub fn parse_certificate(der_bytes: &[u8]) -> Result<Certificate<'_>, X509Error> {
    let mut top = Der::new(der_bytes);
    let mut cert = top.take_sequence()?;
    // tbsCertificate: capture its RAW bytes (header included) for signature checks.
    let (tbs_tag, tbs_full, tbs_contents) = cert.take_element()?;
    if tbs_tag != tag::SEQUENCE {
        return Err(X509Error::Malformed);
    }
    // signatureAlgorithm (the outer copy, whose value is authenticated by being a
    // duplicate of the inner one; we read the outer since the signature follows it).
    let mut sig_alg_seq = cert.take_sequence()?;
    let sig_alg = der::oid_arcs(sig_alg_seq.take_tag(tag::OID)?)?;
    // signatureValue BIT STRING.
    let signature = bit_string_bytes(cert.take_tag(tag::BIT_STRING)?)?;

    // Now walk the tbsCertificate contents.
    let mut tbs = Der::new(tbs_contents);
    // [0] version (optional, EXPLICIT). Skip it if present.
    if tbs.peek_tag() == Some(tag::CONTEXT_CONSTRUCTED) {
        tbs.take_tag(tag::CONTEXT_CONSTRUCTED)?;
    }
    // serialNumber INTEGER (skip).
    tbs.take_tag(tag::INTEGER)?;
    // signature AlgorithmIdentifier (inner; skip, we used the outer copy).
    tbs.take_tag(tag::SEQUENCE)?;
    // issuer Name.
    let issuer_cn = name_common_name(tbs.take_tag(tag::SEQUENCE)?)?;
    // validity SEQUENCE { notBefore, notAfter }.
    let (not_before, not_after) = parse_validity(tbs.take_tag(tag::SEQUENCE)?)?;
    // subject Name.
    let subject_cn = name_common_name(tbs.take_tag(tag::SEQUENCE)?)?;
    // subjectPublicKeyInfo.
    let public_key = parse_spki(tbs.take_tag(tag::SEQUENCE)?)?;

    // Optional [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions. We only want
    // the AAGUID extension inside [3].
    let mut aaguid = None;
    while let Some(next) = tbs.peek_tag() {
        let (context_tag, contents) = tbs.take_any()?;
        if context_tag == (tag::CONTEXT_CONSTRUCTED | 3) {
            aaguid = find_aaguid_extension(contents)?;
        }
        let _ = next;
    }

    Ok(Certificate {
        tbs: tbs_full,
        issuer_cn,
        subject_cn,
        not_before,
        not_after,
        public_key,
        sig_alg,
        signature,
        aaguid,
    })
}

/// Strip the leading "unused bits" count off a BIT STRING's contents.
fn bit_string_bytes(contents: &[u8]) -> Result<Vec<u8>, X509Error> {
    let (&unused, rest) = contents.split_first().ok_or(X509Error::Malformed)?;
    if unused != 0 {
        // Certificate signatures and SPKIs are always byte-aligned (0 unused bits).
        return Err(X509Error::Malformed);
    }
    Ok(rest.to_vec())
}

/// Parse `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`.
fn parse_validity(contents: &[u8]) -> Result<(i64, i64), X509Error> {
    let mut v = Der::new(contents);
    let (before_tag, before_bytes) = v.take_any()?;
    let not_before = der::parse_time(before_tag, before_bytes)?;
    let (after_tag, after_bytes) = v.take_any()?;
    let not_after = der::parse_time(after_tag, after_bytes)?;
    Ok((not_before, not_after))
}

/// Extract the FIRST common-name (`2.5.4.3`) attribute value from an X.509 `Name`
/// (`RDNSequence`). A chain match here only needs the CN text, so other RDN
/// attributes are skipped rather than modelled.
fn name_common_name(contents: &[u8]) -> Result<Option<String>, X509Error> {
    let mut rdns = Der::new(contents);
    while !rdns.is_empty() {
        // Each RDN is a SET OF AttributeTypeAndValue.
        let set = rdns.take_tag(tag::SET)?;
        let mut attrs = Der::new(set);
        while !attrs.is_empty() {
            let mut atv = Der::new(attrs.take_tag(tag::SEQUENCE)?);
            let oid = der::oid_arcs(atv.take_tag(tag::OID)?)?;
            let (value_tag, value) = atv.take_any()?;
            if oid == OID_COMMON_NAME {
                let text = decode_directory_string(value_tag, value)?;
                return Ok(Some(text));
            }
        }
    }
    Ok(None)
}

/// Decode a `DirectoryString` (the CN value) from its common string tags.
fn decode_directory_string(value_tag: u8, value: &[u8]) -> Result<String, X509Error> {
    match value_tag {
        tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING => core::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|_| X509Error::Malformed),
        _ => Err(X509Error::Malformed),
    }
}

/// Parse a `SubjectPublicKeyInfo` into a [`WebauthnKey`].
fn parse_spki(contents: &[u8]) -> Result<WebauthnKey, X509Error> {
    let mut spki = Der::new(contents);
    let mut alg = Der::new(spki.take_tag(tag::SEQUENCE)?);
    let alg_oid = der::oid_arcs(alg.take_tag(tag::OID)?)?;
    let key_bits = bit_string_bytes(spki.take_tag(tag::BIT_STRING)?)?;

    if alg_oid == OID_ED25519 {
        if key_bits.len() != 32 {
            return Err(X509Error::UnsupportedKey);
        }
        return Ok(WebauthnKey::Ed25519 {
            public_key: key_bits,
        });
    }
    if alg_oid == OID_EC_PUBLIC_KEY {
        // The curve is the second AlgorithmIdentifier parameter.
        let curve = der::oid_arcs(alg.take_tag(tag::OID)?)?;
        if curve != OID_P256 {
            return Err(X509Error::UnsupportedKey);
        }
        // Uncompressed point: 0x04 || x(32) || y(32).
        if key_bits.len() != 65 || key_bits[0] != 0x04 {
            return Err(X509Error::UnsupportedKey);
        }
        return Ok(WebauthnKey::Es256 {
            x: key_bits[1..33].to_vec(),
            y: key_bits[33..65].to_vec(),
        });
    }
    if alg_oid == OID_RSA_ENCRYPTION {
        // The key BIT STRING wraps a SEQUENCE { modulus INTEGER, exponent INTEGER }.
        let mut rsa = Der::new(&key_bits);
        let mut params = rsa.take_sequence()?;
        let n = strip_integer(params.take_tag(tag::INTEGER)?);
        let e = strip_integer(params.take_tag(tag::INTEGER)?);
        return Ok(WebauthnKey::Rs256 { n, e });
    }
    Err(X509Error::UnsupportedKey)
}

/// Strip a leading sign-padding zero byte from a DER INTEGER's big-endian bytes,
/// yielding the magnitude ring expects for an RSA modulus/exponent.
fn strip_integer(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

/// Search an X.509 `Extensions` (`SEQUENCE OF Extension`) for the FIDO AAGUID
/// extension and return its 16-byte value.
fn find_aaguid_extension(contents: &[u8]) -> Result<Option<[u8; 16]>, X509Error> {
    // [3] EXPLICIT wraps a single SEQUENCE OF Extension.
    let mut wrap = Der::new(contents);
    let mut exts = wrap.take_sequence()?;
    while !exts.is_empty() {
        let mut ext = Der::new(exts.take_tag(tag::SEQUENCE)?);
        let oid = der::oid_arcs(ext.take_tag(tag::OID)?)?;
        // Optional critical BOOLEAN, then the extnValue OCTET STRING.
        let (next_tag, next) = ext.take_any()?;
        let ext_value = if next_tag == tag::BOOLEAN {
            ext.take_tag(tag::OCTET_STRING)?
        } else if next_tag == tag::OCTET_STRING {
            next
        } else {
            return Err(X509Error::Malformed);
        };
        if oid == OID_FIDO_AAGUID {
            // The extnValue is an OCTET STRING wrapping an OCTET STRING of the 16-byte
            // AAGUID (id-fido-gen-ce-aaguid is a DER OCTET STRING).
            let mut inner = Der::new(ext_value);
            let raw = inner.take_tag(tag::OCTET_STRING)?;
            let bytes: [u8; 16] = raw.try_into().map_err(|_| X509Error::Malformed)?;
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

/// Verify a certificate signature: the parent's public key over the child's raw
/// `tbs`, dispatched by the child's signature algorithm.
fn verify_cert_signature(
    child: &Certificate<'_>,
    parent_key: &WebauthnKey,
) -> Result<(), X509Error> {
    // The child's declared signature algorithm must match the parent key family, so
    // an ECDSA signature can never be checked with an RSA key or vice versa.
    let ok_family = match (&child.sig_alg, parent_key) {
        (alg, WebauthnKey::Ed25519 { .. }) if alg.as_slice() == OID_ED25519 => true,
        (alg, WebauthnKey::Es256 { .. }) if alg.as_slice() == OID_ECDSA_SHA256 => true,
        (alg, WebauthnKey::Rs256 { .. }) if alg.as_slice() == OID_RSA_SHA256 => true,
        _ => false,
    };
    if !ok_family {
        return Err(X509Error::UnsupportedSignature);
    }
    // A certificate signature (ECDSA) is ASN.1-DER encoded, exactly like a WebAuthn
    // ceremony signature, so the DER-form ring primitive is the right one (NOT the
    // fixed-width JWS one).
    ironauth_jose::verify_webauthn_signature(parent_key, child.tbs, &child.signature)
        .map_err(|_| X509Error::BadSignature)
}

/// Verify a certificate chain `leaf -> intermediates -> a pinned anchor`.
///
/// `chain[0]` is the leaf; `chain[1..]` are intermediates in issuing order.
/// `anchors` is the pinned, out-of-band trust set (DER). At each hop the parent's
/// subject name must match the child's issuer name, the parent's key must verify
/// the child's signature, and both certificates must be valid at `now_unix`. The
/// chain must reach an anchor (matched by name AND by the anchor's key verifying
/// the last chain certificate's signature); a chain that runs out without hitting
/// an anchor is [`X509Error::UntrustedRoot`]. Returns the verified leaf on success.
///
/// # Errors
///
/// The specific [`X509Error`] for the first failing check.
pub fn verify_chain<'a>(
    chain: &[Certificate<'a>],
    anchors: &[Certificate<'_>],
    now_unix: i64,
) -> Result<Certificate<'a>, X509Error> {
    if chain.is_empty() || chain.len() > MAX_CHAIN_DEPTH {
        return Err(X509Error::BadChain);
    }
    // Every certificate in the presented chain must be temporally valid.
    for cert in chain {
        if !cert.is_valid_at(now_unix) {
            return Err(X509Error::Expired);
        }
    }
    // Walk child -> parent within the presented chain.
    for pair in chain.windows(2) {
        let child = &pair[0];
        let parent = &pair[1];
        names_link(child, parent)?;
        verify_cert_signature(child, &parent.public_key)?;
    }
    // The last presented certificate must be signed by a pinned anchor.
    let last = chain.last().ok_or(X509Error::BadChain)?;
    for anchor in anchors {
        if !anchor.is_valid_at(now_unix) {
            continue;
        }
        if names_link(last, anchor).is_ok()
            && verify_cert_signature(last, &anchor.public_key).is_ok()
        {
            return Ok(chain[0].clone());
        }
    }
    // A self-issued leaf that IS itself an anchor (issuer == subject, matches an
    // anchor's subject and key) also terminates: a single self-signed root pinned
    // directly. This covers a one-element chain whose sole cert is the anchor.
    for anchor in anchors {
        if anchor.is_valid_at(now_unix)
            && anchor.subject_cn == last.subject_cn
            && anchor.public_key == last.public_key
        {
            return Ok(chain[0].clone());
        }
    }
    Err(X509Error::UntrustedRoot)
}

/// A child's issuer name must equal the parent's subject name. Both must carry a
/// common name (an anonymous DN cannot anchor a chain match here).
fn names_link(child: &Certificate<'_>, parent: &Certificate<'_>) -> Result<(), X509Error> {
    match (&child.issuer_cn, &parent.subject_cn) {
        (Some(issuer), Some(subject)) if issuer == subject => Ok(()),
        _ => Err(X509Error::NameChainBroken),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testpki::{CertSpec, build_cert};

    const NOW: i64 = 1_700_000_000;
    const FAR: i64 = 4_102_444_800;

    fn cert(
        subject: &str,
        issuer: &str,
        ss: [u8; 32],
        is: [u8; 32],
        not_after: i64,
        aaguid: Option<[u8; 16]>,
    ) -> Vec<u8> {
        build_cert(&CertSpec {
            subject_cn: subject,
            issuer_cn: issuer,
            subject_seed: ss,
            issuer_seed: is,
            not_before: 0,
            not_after,
            aaguid,
        })
    }

    #[test]
    fn parses_fields_and_aaguid_extension() {
        let der = cert("Leaf", "Root", [3; 32], [1; 32], FAR, Some([7; 16]));
        let parsed = parse_certificate(&der).unwrap();
        assert_eq!(parsed.subject_cn.as_deref(), Some("Leaf"));
        assert_eq!(parsed.issuer_cn.as_deref(), Some("Root"));
        assert_eq!(parsed.aaguid, Some([7; 16]));
        assert!(parsed.is_valid_at(NOW));
        assert!(matches!(parsed.public_key, WebauthnKey::Ed25519 { .. }));
    }

    #[test]
    fn a_two_hop_chain_verifies_to_the_root() {
        let root_der = cert("Root", "Root", [1; 32], [1; 32], FAR, None);
        let int_der = cert("Int", "Root", [2; 32], [1; 32], FAR, None);
        let leaf_der = cert("Leaf", "Int", [3; 32], [2; 32], FAR, None);
        let root = parse_certificate(&root_der).unwrap();
        let int = parse_certificate(&int_der).unwrap();
        let leaf = parse_certificate(&leaf_der).unwrap();
        assert!(verify_chain(&[leaf, int], std::slice::from_ref(&root), NOW).is_ok());
    }

    #[test]
    fn a_chain_to_a_wrong_root_is_untrusted() {
        let int_der = cert("Int", "Root", [2; 32], [1; 32], FAR, None);
        let leaf_der = cert("Leaf", "Int", [3; 32], [2; 32], FAR, None);
        let wrong_root_der = cert("Other", "Other", [9; 32], [9; 32], FAR, None);
        let leaf = parse_certificate(&leaf_der).unwrap();
        let int = parse_certificate(&int_der).unwrap();
        let wrong = parse_certificate(&wrong_root_der).unwrap();
        assert_eq!(
            verify_chain(&[leaf, int], std::slice::from_ref(&wrong), NOW).err(),
            Some(X509Error::UntrustedRoot)
        );
    }

    #[test]
    fn an_expired_certificate_is_rejected() {
        let root_der = cert("Root", "Root", [1; 32], [1; 32], 1_000, None);
        let leaf_der = cert("Leaf", "Root", [3; 32], [1; 32], 1_000, None);
        let root = parse_certificate(&root_der).unwrap();
        let leaf = parse_certificate(&leaf_der).unwrap();
        assert_eq!(
            verify_chain(&[leaf], std::slice::from_ref(&root), NOW).err(),
            Some(X509Error::Expired)
        );
    }

    #[test]
    fn a_forged_signature_does_not_verify() {
        // A leaf that CLAIMS to be issued by Root but was actually signed by a
        // different (attacker) key must not verify against the real root.
        let root_der = cert("Root", "Root", [1; 32], [1; 32], FAR, None);
        let forged_leaf_der = cert("Leaf", "Root", [3; 32], [8; 32], FAR, None); // signed by [8], not root
        let root = parse_certificate(&root_der).unwrap();
        let leaf = parse_certificate(&forged_leaf_der).unwrap();
        assert!(verify_chain(&[leaf], std::slice::from_ref(&root), NOW).is_err());
    }
}
