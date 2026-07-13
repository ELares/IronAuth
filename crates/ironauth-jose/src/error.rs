// SPDX-License-Identifier: MIT OR Apache-2.0

//! The verification error surface.
//!
//! Two types, split by audience. [`VerifyError`] is what a caller sees: it is
//! deliberately uniform, so a rejected token cannot be used as an oracle to
//! learn WHICH check failed (an attacker probing alg, key, claim, or signature
//! handling gets the same answer every time). [`RejectReason`] is the rich,
//! bounded-cardinality diagnostic that travels to logs and metrics, consistent
//! with the log-scrubbing stance: it names the exact structural reason for a
//! reject so operators can alarm on, say, a spike of embedded-key injections,
//! without that detail ever reaching the wire. The reason is reachable only
//! through [`VerifyError::reason`], which the crate documents as internal-only.

use std::fmt;

/// The single, opaque error every verification failure collapses into.
///
/// `Display` renders one fixed string regardless of the underlying cause, so
/// the value carries no oracle. The structured cause is available to the
/// server for logging and metrics through [`VerifyError::reason`]; it must
/// never be forwarded to a client.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyError {
    reason: RejectReason,
}

impl VerifyError {
    /// Wrap an internal reason. Crate-private: only the verifier mints errors.
    pub(crate) fn new(reason: RejectReason) -> Self {
        Self { reason }
    }

    /// The structured, bounded-cardinality reason this token was rejected.
    ///
    /// For server-side diagnostics ONLY: logs, metrics, and traces. Never
    /// return it, its [`RejectReason::as_metric_label`], or any derivative to a
    /// client; doing so reintroduces the verification oracle this type exists to
    /// remove.
    #[must_use]
    pub fn reason(&self) -> RejectReason {
        self.reason
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Uniform on purpose: identical for every cause.
        f.write_str("token verification failed")
    }
}

impl fmt::Debug for VerifyError {
    // Debug is for logs, not the wire, so it may carry the reason.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyError")
            .field("reason", &self.reason)
            .finish()
    }
}

impl std::error::Error for VerifyError {}

/// The exact structural reason a token was rejected.
///
/// Bounded-cardinality by construction: every variant is a fixed shape with no
/// attacker-controlled payload, so it is safe as a metrics label
/// ([`RejectReason::as_metric_label`]) and a scrubbed log field. This is the
/// internal diagnostic behind the uniform [`VerifyError`]; it is never exposed
/// to a client.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum RejectReason {
    /// The raw token exceeded the configured byte-size cap. Checked first, before
    /// any base64, JSON, or crypto work.
    TokenTooLarge,
    /// The token was not exactly three `.`-separated segments. A five-segment
    /// JWE is rejected here, cheaply, before any header field is read.
    MalformedStructure,
    /// A segment's base64url length exceeded the cap derived from the decoded
    /// caps, so it is rejected before the allocation of a decode buffer.
    SegmentTooLarge,
    /// A segment was not valid unpadded base64url.
    Base64Malformed,
    /// The protected header was not a valid JSON object, or carried a duplicate
    /// member.
    HeaderMalformed,
    /// The `alg` header was `none` (in any case or whitespace variant), or was
    /// absent/empty. Always rejected, with no configuration to permit it.
    AlgNone,
    /// The `alg` header named an algorithm this core does not implement,
    /// including every HMAC algorithm (`HS256`/`HS384`/`HS512`), which are
    /// unsupported precisely to defeat the public-key-as-HMAC-secret confusion.
    UnsupportedAlg,
    /// The `alg` header named a supported algorithm that is not in the caller's
    /// allowlist for this verification.
    AlgNotAllowed,
    /// The protected header carried in-token key material (`jwk`, `jku`, `x5u`,
    /// or `x5c`). Trust never comes from the token, so its presence is a reject,
    /// not a silent ignore.
    EmbeddedKeyInjection,
    /// The protected header carried a `crit` member. The core understands no
    /// critical extensions in M1, so any well-formed `crit` is a reject.
    UnknownCrit,
    /// The `crit` header was malformed: not an array, empty, a non-string
    /// member, a duplicate member, or a member naming a standard header
    /// parameter.
    MalformedCrit,
    /// The header indicated JWE (`enc` present) or any encryption parameter. This
    /// core verifies JWS only.
    EncryptionPresent,
    /// The header indicated compression (`zip` present). Compression is rejected
    /// at the header stage, before anything can be inflated (decompression-bomb
    /// defense).
    CompressionPresent,
    /// The header indicated PBES2 key derivation (a `PBES2-*` alg, or a `p2c` or
    /// `p2s` parameter), or the `p2c` iteration count exceeded the cap. PBES2 is
    /// excluded; the count cap rejects a bomb-shaped input cheaply.
    Pbes2Present,
    /// The header carried a `kid` that names no trusted key. A `kid` may only
    /// select among already-trusted keys; it never introduces one.
    UnknownKid,
    /// The claimed algorithm's key type did not match any trusted key eligible
    /// for this verification (for example `RS256` presented against an EC key).
    KeyTypeMismatch,
    /// The signature did not verify against any eligible trusted key.
    SignatureInvalid,
    /// The claims segment was not a valid JSON object, or carried a duplicate
    /// member.
    ClaimsMalformed,
    /// A required claim was absent (for example `exp`, or `iss`/`aud` when the
    /// policy expects them).
    ClaimMissing,
    /// The `exp` claim is in the past beyond the allowed skew.
    Expired,
    /// The `nbf` claim is in the future beyond the allowed skew.
    NotYetValid,
    /// The `iat` claim is in the future beyond the allowed skew.
    IssuedInFuture,
    /// The `iss` claim did not exactly equal the expected issuer.
    IssuerMismatch,
    /// The `aud` claim did not exactly contain the expected audience.
    AudienceMismatch,
}

impl RejectReason {
    /// A stable, bounded-cardinality label for metrics.
    ///
    /// Safe as a metric dimension (a fixed, small set of values). It is a
    /// server-side diagnostic and must never be surfaced to a client.
    #[must_use]
    pub fn as_metric_label(self) -> &'static str {
        match self {
            RejectReason::TokenTooLarge => "token_too_large",
            RejectReason::MalformedStructure => "malformed_structure",
            RejectReason::SegmentTooLarge => "segment_too_large",
            RejectReason::Base64Malformed => "base64_malformed",
            RejectReason::HeaderMalformed => "header_malformed",
            RejectReason::AlgNone => "alg_none",
            RejectReason::UnsupportedAlg => "unsupported_alg",
            RejectReason::AlgNotAllowed => "alg_not_allowed",
            RejectReason::EmbeddedKeyInjection => "embedded_key_injection",
            RejectReason::UnknownCrit => "unknown_crit",
            RejectReason::MalformedCrit => "malformed_crit",
            RejectReason::EncryptionPresent => "encryption_present",
            RejectReason::CompressionPresent => "compression_present",
            RejectReason::Pbes2Present => "pbes2_present",
            RejectReason::UnknownKid => "unknown_kid",
            RejectReason::KeyTypeMismatch => "key_type_mismatch",
            RejectReason::SignatureInvalid => "signature_invalid",
            RejectReason::ClaimsMalformed => "claims_malformed",
            RejectReason::ClaimMissing => "claim_missing",
            RejectReason::Expired => "expired",
            RejectReason::NotYetValid => "not_yet_valid",
            RejectReason::IssuedInFuture => "issued_in_future",
            RejectReason::IssuerMismatch => "issuer_mismatch",
            RejectReason::AudienceMismatch => "audience_mismatch",
        }
    }
}
