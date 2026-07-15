// SPDX-License-Identifier: MIT OR Apache-2.0

//! Value types for per-environment custom domains with built-in ACME (issue
//! #47, EXPLORATORY).
//!
//! These are the typed vocabulary the custom-domain repository (in the
//! repository module) reads and writes: the closed challenge-type and status
//! enums the schema CHECK constraints mirror, the persisted domain and challenge
//! records, and the registration input. The persistence, isolation, and audited
//! writes live on the repository; this module holds only the pure value types so
//! they can be exercised without a database.
//!
//! A custom domain is TENANT-CONTROLLED and UNTRUSTED input: the [`normalize_domain`]
//! and [`domain_is_registrable`] helpers reject anything that is not a plain
//! registrable hostname (an IP literal, an internal single-label name, a value
//! with a scheme, port, path, or whitespace) BEFORE it is ever registered, so a
//! custom domain can never be used to point serving or an ACME/CA request at
//! internal infrastructure. The outbound ACME/CA HTTP is separately confined to
//! the SSRF-hardened `ironauth-fetch` path.

use std::fmt;

use crate::id::{AcmeChallengeId, CustomDomainId};

/// The ACME challenge type used to prove control of a domain (RFC 8555 sections
/// 8.3 and 8.4). Selectable per domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeType {
    /// The HTTP-01 challenge: serve a key authorization at
    /// `/.well-known/acme-challenge/<token>` over HTTP (RFC 8555 8.3).
    Http01,
    /// The DNS-01 challenge: publish a key-authorization digest as a `_acme-challenge`
    /// TXT record (RFC 8555 8.4). The only type that can authorize a wildcard,
    /// though wildcards are out of scope for this exploratory slice.
    Dns01,
}

impl ChallengeType {
    /// The stable wire string the schema CHECK pins (`http-01` or `dns-01`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ChallengeType::Http01 => "http-01",
            ChallengeType::Dns01 => "dns-01",
        }
    }

    /// Parse a stored wire string back into the typed challenge type.
    ///
    /// # Errors
    ///
    /// [`CustomDomainError::Decode`] if the string is not one of the two wire
    /// tokens (a corrupt row, never a value the schema CHECK admits).
    pub fn parse(value: &str) -> Result<Self, CustomDomainError> {
        match value {
            "http-01" => Ok(ChallengeType::Http01),
            "dns-01" => Ok(ChallengeType::Dns01),
            _ => Err(CustomDomainError::Decode),
        }
    }
}

impl fmt::Display for ChallengeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The verification lifecycle of a registered custom domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationStatus {
    /// Registered but not yet proven: no challenge has succeeded, so the domain
    /// is never served.
    Pending,
    /// An ACME challenge succeeded and the CA confirmed control: the domain is
    /// eligible to be served. Exactly one tenant can hold a given domain verified
    /// platform-wide (a global partial unique index enforces it).
    Verified,
    /// A challenge could not be satisfied: the domain stays unserved and the
    /// failure surfaces to the operator.
    Failed,
}

impl VerificationStatus {
    /// The stable wire string the schema CHECK pins.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            VerificationStatus::Pending => "pending",
            VerificationStatus::Verified => "verified",
            VerificationStatus::Failed => "failed",
        }
    }

    /// Parse a stored wire string back into the typed status.
    ///
    /// # Errors
    ///
    /// [`CustomDomainError::Decode`] if the string is not a known status token.
    pub fn parse(value: &str) -> Result<Self, CustomDomainError> {
        match value {
            "pending" => Ok(VerificationStatus::Pending),
            "verified" => Ok(VerificationStatus::Verified),
            "failed" => Ok(VerificationStatus::Failed),
            _ => Err(CustomDomainError::Decode),
        }
    }
}

impl fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The lifecycle of a single ACME challenge attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeStatus {
    /// Issued and awaiting the CA's confirmation.
    Pending,
    /// The CA confirmed control of the domain through this challenge.
    Valid,
    /// The challenge failed (the CA could not confirm control).
    Invalid,
}

impl ChallengeStatus {
    /// The stable wire string the schema CHECK pins.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ChallengeStatus::Pending => "pending",
            ChallengeStatus::Valid => "valid",
            ChallengeStatus::Invalid => "invalid",
        }
    }

    /// Parse a stored wire string back into the typed status.
    ///
    /// # Errors
    ///
    /// [`CustomDomainError::Decode`] if the string is not a known status token.
    pub fn parse(value: &str) -> Result<Self, CustomDomainError> {
        match value {
            "pending" => Ok(ChallengeStatus::Pending),
            "valid" => Ok(ChallengeStatus::Valid),
            "invalid" => Ok(ChallengeStatus::Invalid),
            _ => Err(CustomDomainError::Decode),
        }
    }
}

impl fmt::Display for ChallengeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The terminal result of an ACME challenge attempt, as recorded by the
/// repository. Distinct from [`ChallengeStatus`] (which also has a non-terminal
/// `Pending`): recording a result only ever moves a challenge to a terminal
/// state and correspondingly verifies or fails its domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeOutcome {
    /// The CA confirmed control: the challenge is valid and its domain verifies.
    Valid,
    /// The CA could not confirm control: the challenge is invalid and its domain
    /// moves to failed (a surfaced failure, never a silent degrade).
    Invalid,
}

impl ChallengeOutcome {
    /// The challenge status this outcome records.
    #[must_use]
    pub fn challenge_status(self) -> ChallengeStatus {
        match self {
            ChallengeOutcome::Valid => ChallengeStatus::Valid,
            ChallengeOutcome::Invalid => ChallengeStatus::Invalid,
        }
    }

    /// The domain verification status this outcome drives.
    #[must_use]
    pub fn verification_status(self) -> VerificationStatus {
        match self {
            ChallengeOutcome::Valid => VerificationStatus::Verified,
            ChallengeOutcome::Invalid => VerificationStatus::Failed,
        }
    }
}

/// A validation or decode failure on the custom-domain value types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomDomainError {
    /// The submitted domain is not a plain registrable hostname (an IP literal, a
    /// single-label internal name, or a value carrying a scheme, port, path, or
    /// whitespace). Rejected before registration so a domain can never point at
    /// internal infrastructure.
    InvalidDomain,
    /// A stored wire token did not parse into its typed enum (a corrupt row).
    Decode,
}

impl fmt::Display for CustomDomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustomDomainError::InvalidDomain => {
                f.write_str("custom domain is not a registrable hostname")
            }
            CustomDomainError::Decode => f.write_str("custom-domain value failed to decode"),
        }
    }
}

impl std::error::Error for CustomDomainError {}

/// A persisted custom-domain record.
#[derive(Debug, Clone)]
pub struct CustomDomainRecord {
    /// The domain's scoped identifier.
    pub id: CustomDomainId,
    /// The normalized fully-qualified domain name.
    pub domain_name: String,
    /// The selected ACME challenge type.
    pub challenge_type: ChallengeType,
    /// The verification lifecycle state.
    pub verification_status: VerificationStatus,
    /// The handle to the sealed certificate bundle in `encrypted_secrets`, or
    /// `None` before a certificate is issued. The private key never appears here.
    pub cert_secret_id: Option<crate::id::EncryptedSecretId>,
    /// The issued certificate's not-after epoch-microseconds, or `None` before
    /// issuance. The renewal scheduler renews well before this.
    pub cert_not_after_micros: Option<i64>,
}

/// A persisted ACME challenge record.
#[derive(Debug, Clone)]
pub struct AcmeChallengeRecord {
    /// The challenge's scoped identifier.
    pub id: AcmeChallengeId,
    /// The domain this challenge proves control of.
    pub domain_id: CustomDomainId,
    /// The challenge type attempted.
    pub challenge_type: ChallengeType,
    /// The challenge token (a public value the tenant serves or publishes).
    pub token: String,
    /// The challenge lifecycle state.
    pub status: ChallengeStatus,
    /// How many verification attempts have been made.
    pub attempts: i32,
    /// The next-attempt epoch-microseconds, or `None` when no retry is scheduled.
    pub next_attempt_at_micros: Option<i64>,
}

/// Normalize a submitted domain to its canonical lowercase form, stripping a
/// single trailing dot (the DNS root label). Does NOT validate; call
/// [`domain_is_registrable`] on the result.
#[must_use]
pub fn normalize_domain(input: &str) -> String {
    let trimmed = input.trim();
    let without_root = trimmed.strip_suffix('.').unwrap_or(trimmed);
    without_root.to_ascii_lowercase()
}

/// Whether `domain` is a plain registrable hostname safe to register and later
/// drive an ACME/CA request from. This is a conservative allowlist: at least two
/// dot-separated labels (so an internal single-label name like `localhost` is
/// refused), every label a non-empty run of ASCII letters, digits, or hyphens
/// (never starting or ending with a hyphen), no scheme, port, path, userinfo, or
/// whitespace, and not an IPv4 literal. It is deliberately stricter than a full
/// RFC 1035 parse: the outbound SSRF guard in `ironauth-fetch` is the real
/// network-level defense; this keeps an obviously-unsafe or malformed value from
/// ever being registered.
#[must_use]
pub fn domain_is_registrable(domain: &str) -> bool {
    // Reject anything carrying a scheme, port, path, userinfo, or whitespace.
    if domain.is_empty()
        || domain.len() > 253
        || domain.contains(|c: char| {
            c.is_whitespace() || matches!(c, '/' | ':' | '@' | '?' | '#' | '\\' | '%')
        })
    {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    // At least two labels: a single-label name (localhost, an internal host) is
    // never a public registrable domain.
    if labels.len() < 2 {
        return false;
    }
    let all_labels_valid = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    if !all_labels_valid {
        return false;
    }
    // Reject an IPv4 literal (every label numeric): an IP is never a domain we
    // ACME-verify, and it is a classic SSRF target.
    let looks_like_ipv4 = labels.len() == 4
        && labels
            .iter()
            .all(|label| label.chars().all(|c| c.is_ascii_digit()));
    if looks_like_ipv4 {
        return false;
    }
    // The final label (the TLD) must be alphabetic (never all-numeric).
    labels
        .last()
        .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_alphabetic()))
}

#[cfg(test)]
mod tests {
    use super::{
        ChallengeStatus, ChallengeType, VerificationStatus, domain_is_registrable, normalize_domain,
    };

    #[test]
    fn wire_strings_round_trip() {
        for value in [ChallengeType::Http01, ChallengeType::Dns01] {
            assert_eq!(ChallengeType::parse(value.as_str()).unwrap(), value);
        }
        for value in [
            VerificationStatus::Pending,
            VerificationStatus::Verified,
            VerificationStatus::Failed,
        ] {
            assert_eq!(VerificationStatus::parse(value.as_str()).unwrap(), value);
        }
        for value in [
            ChallengeStatus::Pending,
            ChallengeStatus::Valid,
            ChallengeStatus::Invalid,
        ] {
            assert_eq!(ChallengeStatus::parse(value.as_str()).unwrap(), value);
        }
    }

    #[test]
    fn parse_rejects_unknown_tokens() {
        assert!(ChallengeType::parse("tls-alpn-01").is_err());
        assert!(VerificationStatus::parse("revoked").is_err());
        assert!(ChallengeStatus::parse("processing").is_err());
    }

    #[test]
    fn normalize_lowercases_and_strips_root_dot() {
        assert_eq!(
            normalize_domain("  Auth.Example.COM.  "),
            "auth.example.com"
        );
    }

    #[test]
    fn registrable_accepts_plain_hostnames() {
        for good in [
            "auth.example.com",
            "id.acme-corp.io",
            "a.b.c.example.org",
            "xn--nxasmq6b.example",
        ] {
            assert!(domain_is_registrable(good), "{good} should be registrable");
        }
    }

    #[test]
    fn registrable_refuses_internal_and_ssrf_shaped_values() {
        for bad in [
            "",
            "localhost",
            "internal",
            "127.0.0.1",
            "10.0.0.5",
            "169.254.169.254",
            "auth.example.com:8080",
            "http://auth.example.com",
            "auth.example.com/path",
            "user@auth.example.com",
            "auth example.com",
            "-lead.example.com",
            "trail-.example.com",
            "auth..example.com",
            "auth.example.123",
        ] {
            assert!(!domain_is_registrable(bad), "{bad} must be refused");
        }
    }
}
