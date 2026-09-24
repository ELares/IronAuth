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
/// the entire self-signed method's test — a different certificate, however otherwise
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

    #[test]
    fn garbage_pem_is_unparsable() {
        assert!(matches!(
            parse_presented_certificate("not a certificate"),
            Err(CertificateError::Unparsable)
        ));
    }
}
