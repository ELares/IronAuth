// SPDX-License-Identifier: MIT OR Apache-2.0

//! AWS Signature Version 4 signing, for the S3 log sink (issue #110).
//!
//! Only what an S3 `PutObject` needs: a canonical request over a single PUT with a payload
//! hash, the string to sign, the derived signing key, and the `Authorization` header.
//!
//! # What is verified here, and what is not
//!
//! The HMAC primitive is checked against RFC 4231's published vectors, and the canonical
//! request and string-to-sign are checked STRUCTURALLY: field order, the sorted and
//! semicolon-joined signed-header list, the trailing payload hash, the `aws4_request`
//! terminator.
//!
//! The end-to-end signature is NOT pinned against an AWS-published example. That is a real
//! gap and it is stated rather than papered over: a hardcoded digest recalled imprecisely
//! would be worse than none, because it would fail for a reason nobody could diagnose. The
//! honest verification is an integration test against a real S3-compatible endpoint, which
//! belongs with the sink's own conformance run rather than here.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

/// The `SigV4` algorithm identifier.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// SHA-256 of `payload`, lowercase hex.
#[must_use]
pub fn sha256_hex(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hex(&hasher.finalize())
}

/// HMAC-SHA256.
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// What a request must state about itself to be signed.
#[derive(Debug, Clone)]
pub struct CanonicalRequest<'a> {
    /// The HTTP method, uppercase.
    pub method: &'a str,
    /// The URI path, already encoded.
    pub path: &'a str,
    /// Headers to sign, as (lowercase name, trimmed value). Sorted here, not by the caller.
    pub headers: Vec<(String, String)>,
    /// Lowercase hex SHA-256 of the body.
    pub payload_hash: &'a str,
}

impl CanonicalRequest<'_> {
    /// The canonical request string.
    ///
    /// The header list is sorted HERE. Leaving it to the caller is the classic `SigV4`
    /// mistake: the signature is computed over one order and the receiver recomputes it
    /// over another, and the failure is a 403 that says nothing about ordering.
    #[must_use]
    pub fn render(&self) -> String {
        let mut headers = self.headers.clone();
        headers.sort_by(|left, right| left.0.cmp(&right.0));
        let mut canonical_headers = String::new();
        for (name, value) in &headers {
            use std::fmt::Write as _;
            let _ = writeln!(canonical_headers, "{name}:{value}");
        }
        let signed_headers = self.signed_headers();
        format!(
            "{}\n{}\n\n{}\n{}\n{}",
            self.method, self.path, canonical_headers, signed_headers, self.payload_hash
        )
    }

    /// The semicolon-joined, sorted, lowercase header names.
    #[must_use]
    pub fn signed_headers(&self) -> String {
        let mut names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        names.join(";")
    }
}

/// The credential scope: `<date>/<region>/<service>/aws4_request`.
#[must_use]
pub fn credential_scope(date: &str, region: &str, service: &str) -> String {
    format!("{date}/{region}/{service}/aws4_request")
}

/// The string to sign.
#[must_use]
pub fn string_to_sign(timestamp: &str, scope: &str, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{timestamp}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    )
}

/// The derived signing key: four chained HMACs from the secret.
///
/// Chained rather than concatenated, which is the other classic mistake. Each step keys the
/// next, so the key is bound to the date, the region and the service together; a key
/// derived for one region cannot sign for another.
#[must_use]
pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let initial = format!("AWS4{secret}");
    let date_key = hmac(initial.as_bytes(), date.as_bytes());
    let region_key = hmac(&date_key, region.as_bytes());
    let service_key = hmac(&region_key, service.as_bytes());
    hmac(&service_key, b"aws4_request")
}

/// The complete `Authorization` header value.
#[must_use]
pub fn authorization_header(
    access_key: &str,
    scope: &str,
    signed_headers: &str,
    signature: &str,
) -> String {
    format!(
        "{ALGORITHM} Credential={access_key}/{scope}, SignedHeaders={signed_headers}, \
         Signature={signature}"
    )
}

/// Sign `canonical` and return the lowercase hex signature.
#[must_use]
pub fn sign(secret: &str, date: &str, region: &str, service: &str, string_to_sign: &str) -> String {
    let key = signing_key(secret, date, region, service);
    hex(&hmac(&key, string_to_sign.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 1, so the HMAC underneath is a KNOWN-ANSWER check rather than
    /// this module agreeing with itself.
    #[test]
    fn hmac_sha256_matches_the_rfc_4231_vector() {
        let key = [0x0b_u8; 20];
        assert_eq!(
            hex(&hmac(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// The published SHA-256 of the empty string, which S3 sends for an empty payload.
    #[test]
    fn sha256_of_the_empty_payload_is_the_published_value() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_canonical_request_sorts_headers_and_lists_them_in_the_same_order() {
        let request = CanonicalRequest {
            method: "PUT",
            path: "/bucket/key",
            headers: vec![
                ("x-amz-date".to_string(), "20240101T000000Z".to_string()),
                ("host".to_string(), "s3.example".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ],
            payload_hash: "abc",
        };
        let rendered = request.render();
        assert_eq!(request.signed_headers(), "content-type;host;x-amz-date");
        let header_block = rendered
            .split('\n')
            .skip(3)
            .take(3)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            header_block,
            "content-type:application/json\nhost:s3.example\nx-amz-date:20240101T000000Z",
            "the canonical headers must be sorted, and in the SAME order as the signed \
             header list, or the receiver recomputes a different signature and answers a \
             403 that says nothing about ordering"
        );
        assert!(
            rendered.ends_with("\nabc"),
            "the payload hash terminates the canonical request: {rendered}"
        );
    }

    #[test]
    fn the_string_to_sign_carries_the_algorithm_scope_and_request_digest() {
        let scope = credential_scope("20240101", "us-east-1", "s3");
        assert_eq!(scope, "20240101/us-east-1/s3/aws4_request");
        let sts = string_to_sign("20240101T000000Z", &scope, "CANONICAL");
        let lines: Vec<&str> = sts.split('\n').collect();
        assert_eq!(lines[0], ALGORITHM);
        assert_eq!(lines[1], "20240101T000000Z");
        assert_eq!(lines[2], scope);
        assert_eq!(lines[3], sha256_hex(b"CANONICAL"));
    }

    /// The signing key is CHAINED, so it is bound to date, region and service together.
    ///
    /// A key derived for one region must not sign for another. Concatenating the parts
    /// instead of chaining them would lose that binding while still producing a
    /// plausible-looking key.
    #[test]
    fn the_signing_key_is_bound_to_its_date_region_and_service() {
        let base = signing_key("secret", "20240101", "us-east-1", "s3");
        assert_ne!(base, signing_key("secret", "20240102", "us-east-1", "s3"));
        assert_ne!(base, signing_key("secret", "20240101", "eu-west-1", "s3"));
        assert_ne!(base, signing_key("secret", "20240101", "us-east-1", "kms"));
        assert_ne!(base, signing_key("other", "20240101", "us-east-1", "s3"));
        assert_eq!(base.len(), 32, "the derived key is one HMAC-SHA256 wide");
    }

    #[test]
    fn the_authorization_header_names_the_credential_scope_and_signed_headers() {
        let header =
            authorization_header("AKIA", "20240101/us-east-1/s3/aws4_request", "host", "sig");
        assert!(header.starts_with(ALGORITHM));
        assert!(header.contains("Credential=AKIA/20240101/us-east-1/s3/aws4_request"));
        assert!(header.contains("SignedHeaders=host"));
        assert!(header.ends_with("Signature=sig"));
    }
}
