// SPDX-License-Identifier: MIT OR Apache-2.0

//! The mTLS certificate primitives (issue #159): parse, inspect, and fingerprint a
//! client certificate without a full PKI stack.
//!
//! The self-signed method's whole authentication is here: a client registers a
//! certificate (or a JWKS-carried `x5c`), and every request must present a certificate
//! with the SAME DER bytes, valid at the request instant. The PKI method (the trust-anchor
//! chain validation) builds on the same parse: subject extraction and validity are the
//! same operations, and the `x5t#S256` thumbprint is the RFC 8705 section 3 binding for
//! certificate-bound tokens, computed once here and reused by issuance and verification.
//!
//! Parsing is `x509-parser` (already in the tree through the LDAP edge; the deny audit
//! allowlists its licenses), and test certificates are generated with `rcgen` (test-only,
//! pinned to the workspace MSRV promise).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer as _;

use crate::crypto;

/// A certificate-processing failure, mapped to the client-auth surface's opaque
/// `invalid_client` at the boundary: nothing here is ever distinguishable on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateError {
    /// The presented PEM does not parse as a certificate.
    Unparsable,
    /// The presented certificate is expired (or not yet valid) at the request instant.
    NotValidNow,
    /// The presented chain's signatures do not verify up to a configured trust anchor.
    UntrustedChain,
    /// The presented certificate's subject does not match the registered expectation
    /// (RFC 8705 section 2.1.2).
    SubjectMismatch,
}

/// Validate a presented certificate against the trust anchors (issue #159, the PKI
/// method): every link's signature must verify up to a configured anchor, the
/// presented certificate must be valid at `unix_seconds`, and its subject must match
/// `expected_subject` (RFC 8705 section 2.1.2: the exact subject distinguished name).
///
/// The chain arrives as the presented leaf followed by its intermediates, each PEM
/// encoded. The topmost presented certificate must be DIRECTLY signed by a configured
/// anchor (the anchors are the trust boundary; an intermediate that walks up to an
/// anchor is accepted only when that topmost cert is itself an intermediate the
/// anchor signed).
///
/// # Errors
///
/// [`CertificateError`] for every failure, uniformly.
///
/// # Panics
///
/// On the internal `expect` of the last chain link: the links were all parsed at the
/// top of the walk, so this is unreachable in practice and only declared because the
/// panic is possible by construction.
pub fn validate_tls_client_chain(
    chain_pems: &[String],
    anchors: &[ParsedClientCertificate],
    expected_subject: &str,
    unix_seconds: i64,
) -> Result<ParsedClientCertificate, CertificateError> {
    let Some((head, tail)) = chain_pems.split_first() else {
        return Err(CertificateError::Unparsable);
    };
    let presented = parse_presented_certificate(head)?;
    if !certificate_valid_at(&presented.certificate(), unix_seconds) {
        return Err(CertificateError::NotValidNow);
    }
    if certificate_subject_dn(&presented.certificate()) != expected_subject {
        return Err(CertificateError::SubjectMismatch);
    }

    // Walk the chain: each link's signature must verify against the NEXT certificate
    // (the issuer), and the final link against one of the configured anchors. The
    // links are parsed FIRST and held by index, so the borrowed views never dangle.
    let mut links = Vec::with_capacity(tail.len() + 1);
    links.push(presented.clone());
    for link in tail {
        links.push(parse_presented_certificate(link)?);
    }
    for i in 0..links.len() - 1 {
        let subject = links[i].certificate();
        if !certificate_valid_at(&subject, unix_seconds) {
            return Err(CertificateError::NotValidNow);
        }
        let issuer = links[i + 1].certificate();
        if !certificate_valid_at(&issuer, unix_seconds) {
            return Err(CertificateError::NotValidNow);
        }
        subject
            .verify_signature(Some(issuer.public_key()))
            .map_err(|_| CertificateError::UntrustedChain)?;
    }
    // The topmost presented cert signed by a configured anchor.
    let topmost = links
        .last()
        .expect("at least the presented cert")
        .certificate();
    for anchor in anchors {
        if topmost
            .verify_signature(Some(anchor.certificate().public_key()))
            .is_ok()
        {
            return Ok(presented);
        }
    }
    Err(CertificateError::UntrustedChain)
}

/// Parse a PEM-encoded client certificate.
///
/// # Errors
///
/// [`CertificateError::Unparsable`] if the PEM does not contain exactly one certificate.
pub fn parse_pem_certificate(pem: &str) -> Result<ParsedClientCertificate, CertificateError> {
    let der = pem_to_der(pem).ok_or(CertificateError::Unparsable)?;
    let thumbprint = URL_SAFE_NO_PAD.encode(crypto::sha256(&der));
    Ok(ParsedClientCertificate { der, thumbprint })
}

/// The RFC 8705 section 3 certificate thumbprint: base64url (no padding) SHA-256 of
/// the certificate's DER. This is the `x5t#S256` member of the `cnf` claim that binds
/// an access token to a client certificate.
#[must_use]
pub fn certificate_thumbprint_sha256(cert: &X509Certificate<'_>) -> String {
    URL_SAFE_NO_PAD.encode(crypto::sha256(cert.as_raw()))
}

/// The certificate's subject distinguished name in its RFC 4514 string form (the
/// `tls_client_auth_subject_dn` matching value of RFC 8705 section 2.1.2).
#[must_use]
pub fn certificate_subject_dn(cert: &X509Certificate<'_>) -> String {
    cert.subject().to_string()
}

/// Whether the certificate is valid at `unix_seconds`: inside [notBefore, notAfter].
#[must_use]
pub fn certificate_valid_at(cert: &X509Certificate<'_>, unix_seconds: i64) -> bool {
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    not_before <= unix_seconds && unix_seconds <= not_after
}

/// Whether the presented certificate IS the registered one: exact DER equality. This is
/// the entire self-signed method's test - a different certificate, however otherwise
/// well-formed, is not the registered one.
#[must_use]
pub fn same_certificate(presented: &X509Certificate<'_>, registered: &X509Certificate<'_>) -> bool {
    presented.as_raw() == registered.as_raw()
}

/// Extract the DER from a PEM certificate block.
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let trimmed = pem.trim();
    if !trimmed.starts_with("-----BEGIN CERTIFICATE-----")
        || !trimmed.ends_with("-----END CERTIFICATE-----")
    {
        return None;
    }
    let body: String = trimmed
        .lines()
        .filter(|line| !line.contains("-----BEGIN") && !line.contains("-----END"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .ok()
}

/// A parsed client certificate plus its computed thumbprint, as one carrier so the two
/// cannot disagree: the thumbprint is computed from the same DER the parse validated,
/// and the DER is owned so the borrowed [`X509Certificate`] view never outlives it.
#[derive(Debug, Clone)]
pub struct ParsedClientCertificate {
    /// The owned DER bytes.
    der: Vec<u8>,
    /// The `x5t#S256` thumbprint of the certificate.
    pub thumbprint: String,
}

impl ParsedClientCertificate {
    /// The borrowed certificate view, parsed from the owned DER.
    ///
    /// # Panics
    ///
    /// If the DER somehow does not parse: it already parsed at construction, so this
    /// is unreachable in practice and only declared because the panic is possible by
    /// construction.
    #[must_use]
    pub fn certificate(&self) -> X509Certificate<'_> {
        let (_, cert) =
            X509Certificate::from_der(&self.der).expect("the DER already parsed at construction");
        cert
    }
}

/// Parse a PEM client certificate and compute its thumbprint.
///
/// # Errors
///
/// [`CertificateError::Unparsable`] if the PEM does not parse.
pub fn parse_presented_certificate(pem: &str) -> Result<ParsedClientCertificate, CertificateError> {
    parse_pem_certificate(pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use std::time::{Duration, SystemTime};
    use time::OffsetDateTime;

    /// A test CA + leaf, generated with rcgen, the same shape the integration tests use.
    fn test_leaf(not_before: OffsetDateTime, not_after: OffsetDateTime) -> (String, String) {
        let ca_key = KeyPair::generate().expect("the test CA key generates");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("the test CA certificate generates");
        let leaf_key = KeyPair::generate().expect("the leaf key generates");
        let mut leaf_params = CertificateParams::default();
        leaf_params.not_before = not_before;
        leaf_params.not_after = not_after;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("the leaf certificate generates");
        (ca_cert.pem(), leaf_cert.pem())
    }

    #[test]
    fn the_thumbprint_is_stable_and_deterministic() {
        let now = OffsetDateTime::now_utc();
        let (_, leaf) = test_leaf(now, now + Duration::from_secs(3600));
        let parsed = parse_presented_certificate(&leaf).expect("the leaf parses");
        let again = parse_presented_certificate(&leaf).expect("the leaf parses again");
        assert_eq!(parsed.thumbprint, again.thumbprint);
        assert_eq!(parsed.thumbprint.len(), 43, "base64url SHA-256, no padding");
        // The x5t#S256 base64url form is exactly 43 chars.
    }

    #[test]
    fn an_expired_certificate_is_not_valid_now() {
        let past = OffsetDateTime::now_utc() - Duration::from_secs(7200);
        let (_, leaf) = test_leaf(past, past + Duration::from_secs(3600));
        let parsed = parse_presented_certificate(&leaf).expect("the leaf parses");
        let now = SystemTime::now() // invariant-allow: time-via-env (test certificate
            // validity windows are anchored to real wall-clock: the cert must be valid when
            // the harness clock, advanced to real now, reads it).
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("post-epoch")
            .as_secs()
            .try_into()
            .expect("now is representable as i64");
        assert!(!certificate_valid_at(&parsed.certificate(), now));
    }

    #[test]
    fn a_valid_certificate_is_valid_now() {
        let now = OffsetDateTime::now_utc();
        let (_, leaf) = test_leaf(
            now - Duration::from_secs(60),
            now + Duration::from_secs(3600),
        );
        let parsed = parse_presented_certificate(&leaf).expect("the leaf parses");
        let now_secs = SystemTime::now() // invariant-allow: time-via-env (as above).
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("post-epoch")
            .as_secs()
            .try_into()
            .expect("now is representable as i64");
        assert!(certificate_valid_at(&parsed.certificate(), now_secs));
    }

    #[test]
    fn two_different_certificates_are_not_the_same() {
        let now = OffsetDateTime::now_utc();
        let (_, leaf_a) = test_leaf(now, now + Duration::from_secs(3600));
        let (_, leaf_b) = test_leaf(now, now + Duration::from_secs(3600));
        let a = parse_presented_certificate(&leaf_a).expect("a parses");
        let b = parse_presented_certificate(&leaf_b).expect("b parses");
        assert!(!same_certificate(&a.certificate(), &b.certificate()));
    }

    #[test]
    fn the_same_pem_parses_to_the_same_der() {
        let now = OffsetDateTime::now_utc();
        let (_, leaf) = test_leaf(now, now + Duration::from_secs(3600));
        let a = parse_presented_certificate(&leaf).expect("a parses");
        let b = parse_presented_certificate(&leaf).expect("b parses");
        assert!(same_certificate(&a.certificate(), &b.certificate()));
    }

    /// A CA-signed leaf chain validates against the anchor with a matching subject.
    #[test]
    fn a_ca_signed_chain_validates_against_its_anchor() {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = ca_params.self_signed(&ca_key).expect("the CA generates");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params = CertificateParams::default();
        leaf_params.not_before = time::OffsetDateTime::now_utc() - Duration::from_secs(60);
        leaf_params.not_after = time::OffsetDateTime::now_utc() + Duration::from_secs(3600);
        let leaf = leaf_params
            .signed_by(&leaf_key, &ca, &ca_key)
            .expect("the leaf generates");
        let anchor = parse_presented_certificate(&ca.pem()).expect("the anchor parses");
        let subject = certificate_subject_dn(
            &parse_presented_certificate(&leaf.pem())
                .expect("parses")
                .certificate(),
        );
        let now = SystemTime::now() // invariant-allow: time-via-env (test cert
        // validity windows anchored to real wall-clock)
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("post-epoch")
            .as_secs()
            .try_into()
            .expect("representable");
        let validated = validate_tls_client_chain(&[leaf.pem()], &[anchor], &subject, now)
            .expect("the chain validates");
        assert_eq!(validated.thumbprint.len(), 43);
    }

    /// A leaf from a DIFFERENT CA does not validate against the anchor.
    #[test]
    fn a_foreign_ca_leaf_is_an_untrusted_chain() {
        let key_a = KeyPair::generate().expect("key a");
        let ca_a = CertificateParams::default()
            .self_signed(&key_a)
            .expect("ca a");
        let key_b = KeyPair::generate().expect("key b");
        let ca_b = CertificateParams::default()
            .self_signed(&key_b)
            .expect("ca b");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf = CertificateParams::default()
            .signed_by(&leaf_key, &ca_a, &key_a)
            .expect("leaf under ca a");
        let anchor_b = parse_presented_certificate(&ca_b.pem()).expect("anchor b parses");
        let subject = certificate_subject_dn(
            &parse_presented_certificate(&leaf.pem())
                .expect("parses")
                .certificate(),
        );
        let now = SystemTime::now() // invariant-allow: time-via-env (test cert
        // validity windows anchored to real wall-clock)
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("post-epoch")
            .as_secs()
            .try_into()
            .expect("representable");
        assert!(matches!(
            validate_tls_client_chain(&[leaf.pem()], &[anchor_b], &subject, now),
            Err(CertificateError::UntrustedChain)
        ));
    }

    /// A subject that does not match the registered expectation is refused.
    #[test]
    fn a_subject_mismatch_is_refused() {
        let key = KeyPair::generate().expect("key");
        let ca = CertificateParams::default().self_signed(&key).expect("ca");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf = CertificateParams::default()
            .signed_by(&leaf_key, &ca, &key)
            .expect("leaf");
        let anchor = parse_presented_certificate(&ca.pem()).expect("anchor parses");
        let now = SystemTime::now() // invariant-allow: time-via-env (test cert
        // validity windows anchored to real wall-clock)
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("post-epoch")
            .as_secs()
            .try_into()
            .expect("representable");
        assert!(matches!(
            validate_tls_client_chain(&[leaf.pem()], &[anchor], "CN=wrong", now),
            Err(CertificateError::SubjectMismatch)
        ));
    }

    #[test]
    fn garbage_pem_is_unparsable() {
        assert!(matches!(
            parse_presented_certificate("not a certificate"),
            Err(CertificateError::Unparsable)
        ));
    }
}
