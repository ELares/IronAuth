// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 6238 TOTP (time-based one-time password), the second-factor primitive
//! (issue #69).
//!
//! This module lives in `ironauth-jose` for the same structural reason as
//! [`crate::envelope`] and [`crate::webauthn`]: `scripts/jose-audit.sh` lets
//! exactly one crate name `ring::hmac`, and the TOTP code is a keyed HMAC over a
//! time-step counter plus RFC 4226 dynamic truncation. Building on the ring
//! primitive that already signs JOSE HMACs keeps the workspace free of a
//! high-level TOTP crate (which would add a new dependency and its advisory
//! surface) and free of a raw `hmac`/`sha1` edge.
//!
//! The primitive is deliberately pure: it takes the wall-clock time in seconds as
//! a parameter rather than reaching for a clock, so the caller supplies
//! `env.clock().now_utc()` (the determinism seam) and the algorithm stays trivially
//! testable against the RFC 6238 appendix test vectors.
//!
//! # No HOTP
//!
//! RFC 4226 (HOTP) is referenced only as the truncation algorithm TOTP is built
//! on. There is NO counter-based, resynchronization-prone HOTP surface: the only
//! counter this module ever forms is `unix_time / period`, computed internally.
//! There is no way to ask for a code at an arbitrary caller-supplied counter.
//!
//! # Constant time
//!
//! [`verify`] compares the presented code against every candidate in the drift
//! window with a constant-time byte comparison (a non-short-circuiting XOR-fold)
//! and never early exits on the first mismatch, so a network attacker learns
//! nothing about the code from the response latency.

use ring::hmac;

/// The hash the HMAC is keyed with. RFC 6238 defines SHA-1 (the authenticator-app
/// default and the only form Google Authenticator and its clones accept), plus
/// SHA-256 and SHA-512 for deployments that provision a compatible authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1. The RFC 6238 default and the universal authenticator-app form.
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl TotpAlgorithm {
    /// The stable wire token (the `algorithm` stored on a credential and the
    /// `algorithm=` parameter of the provisioning URI): `SHA1`, `SHA256`, `SHA512`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        }
    }

    /// Parse a stored/wire token back into an algorithm. Case-sensitive on the
    /// canonical upper-case form; an unknown token is [`None`].
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "SHA1" => Some(TotpAlgorithm::Sha1),
            "SHA256" => Some(TotpAlgorithm::Sha256),
            "SHA512" => Some(TotpAlgorithm::Sha512),
            _ => None,
        }
    }

    fn ring_algorithm(self) -> hmac::Algorithm {
        match self {
            TotpAlgorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            TotpAlgorithm::Sha256 => hmac::HMAC_SHA256,
            TotpAlgorithm::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

/// The per-credential TOTP parameters: the hash, the number of decimal digits, and
/// the time-step period. Constructed through [`TotpParams::new`] so a nonsensical
/// combination (zero digits, a 12-digit code, a zero period) can never form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpParams {
    algorithm: TotpAlgorithm,
    digits: u32,
    period_secs: u64,
}

/// The reason a [`TotpParams`] could not be built. Carries no secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TotpParamsError {
    /// `digits` was outside the accepted 6..=8 range (6 is the authenticator-app
    /// default; 8 is the widest an app renders).
    Digits,
    /// `period_secs` was outside the accepted 15..=60 range (30 is the default).
    Period,
}

impl TotpParams {
    /// The RFC 6238 authenticator-app default: HMAC-SHA1, 6 digits, a 30-second
    /// period.
    #[must_use]
    pub fn authenticator_default() -> Self {
        Self {
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period_secs: 30,
        }
    }

    /// Build parameters, rejecting an out-of-range digit count or period.
    ///
    /// # Errors
    ///
    /// [`TotpParamsError::Digits`] if `digits` is not in 6..=8;
    /// [`TotpParamsError::Period`] if `period_secs` is not in 15..=60.
    pub fn new(
        algorithm: TotpAlgorithm,
        digits: u32,
        period_secs: u64,
    ) -> Result<Self, TotpParamsError> {
        if !(6..=8).contains(&digits) {
            return Err(TotpParamsError::Digits);
        }
        if !(15..=60).contains(&period_secs) {
            return Err(TotpParamsError::Period);
        }
        Ok(Self {
            algorithm,
            digits,
            period_secs,
        })
    }

    /// The hash algorithm.
    #[must_use]
    pub fn algorithm(self) -> TotpAlgorithm {
        self.algorithm
    }

    /// The number of decimal digits in a code.
    #[must_use]
    pub fn digits(self) -> u32 {
        self.digits
    }

    /// The time-step period, in seconds.
    #[must_use]
    pub fn period_secs(self) -> u64 {
        self.period_secs
    }

    /// The time-step index (the internal HOTP counter) for a wall-clock instant.
    #[must_use]
    pub fn timestep(self, unix_time_secs: u64) -> u64 {
        unix_time_secs / self.period_secs
    }
}

/// The one code for an explicit time-step index. RFC 4226 dynamic truncation of
/// `HMAC(secret, timestep_be)`, reduced mod `10^digits` and zero-padded to `digits`.
#[must_use]
fn code_for_timestep(secret: &[u8], params: TotpParams, timestep: u64) -> String {
    let key = hmac::Key::new(params.algorithm.ring_algorithm(), secret);
    let mac = hmac::sign(&key, &timestep.to_be_bytes());
    let digest = mac.as_ref();
    // Dynamic truncation (RFC 4226 section 5.3): the low nibble of the last byte
    // selects a 4-byte window; the top bit is masked so the value is unsigned.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulo = 10_u32.pow(params.digits);
    let value = binary % modulo;
    // Zero-pad to exactly `digits` characters so the constant-time compare in
    // `verify` always runs over equal-length slices.
    format!("{value:0width$}", width = params.digits as usize)
}

/// The code for a wall-clock instant, for provisioning-time self-tests and the
/// RFC 6238 test vectors.
#[must_use]
pub fn code_at(secret: &[u8], params: TotpParams, unix_time_secs: u64) -> String {
    code_for_timestep(secret, params, params.timestep(unix_time_secs))
}

/// Verify a presented code against the drift window and, on a match, return the
/// ABSOLUTE time-step index that matched (never a relative offset), so the caller
/// can enforce single-use (reject a step less than or equal to the last consumed
/// one) and resync (persist the matched step's offset from "now").
///
/// `drift_steps` is the one-sided tolerance: the window is
/// `[now_step - drift_steps, now_step + drift_steps]`. Every candidate is checked
/// with a constant-time comparison and the loop never short-circuits, so the
/// response reveals nothing about which (if any) step matched. A presented code
/// whose length is not `digits` can never equal a generated code and is rejected
/// without a compare.
#[must_use]
pub fn verify(
    secret: &[u8],
    params: TotpParams,
    unix_time_secs: u64,
    drift_steps: u64,
    presented: &str,
) -> Option<u64> {
    // A code is exactly `digits` ASCII decimal characters. Reject anything else up
    // front: it can never match, and this keeps every constant-time compare over
    // equal-length slices.
    if presented.len() != params.digits as usize || !presented.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now_step = params.timestep(unix_time_secs);
    let mut matched: Option<u64> = None;
    // Walk the whole window without early exit so latency is independent of where
    // (or whether) a match sits.
    let low = now_step.saturating_sub(drift_steps);
    let high = now_step.saturating_add(drift_steps);
    for step in low..=high {
        let candidate = code_for_timestep(secret, params, step);
        if constant_time_eq(candidate.as_bytes(), presented.as_bytes()) {
            matched = Some(step);
        }
    }
    matched
}

/// A constant-time byte-slice equality test that never short-circuits, so the
/// comparison time does not depend on where the first differing byte sits. The
/// length check is fine to leak: a code is always exactly `digits` characters, so
/// every candidate and every accepted presented code have the same fixed length.
#[must_use]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The RFC 4648 upper-case Base32 alphabet (no padding), the encoding every
/// authenticator app expects for a manually keyed secret and the `secret=`
/// parameter of the provisioning URI.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32-encode a secret (RFC 4648, upper case, NO padding).
#[must_use]
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[index] as char);
    }
    out
}

/// Decode a Base32 secret (RFC 4648), tolerating lower case, ASCII whitespace, and
/// `=` padding (all ignored), so a user can paste a grouped, mixed-case secret.
///
/// # Errors
///
/// Returns [`Base32Error`] if a non-alphabet character is present.
pub fn base32_decode(text: &str) -> Result<Vec<u8>, Base32Error> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in text.chars() {
        if ch == '=' || ch.is_ascii_whitespace() {
            continue;
        }
        let upper = ch.to_ascii_uppercase();
        let Some(value) = BASE32_ALPHABET.iter().position(|&a| a as char == upper) else {
            return Err(Base32Error::Alphabet);
        };
        buffer = (buffer << 5) | u32::try_from(value).unwrap_or(0);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            #[allow(clippy::cast_possible_truncation)]
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

/// A Base32 decode failure. Carries no secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Base32Error {
    /// A character outside the RFC 4648 Base32 alphabet was present.
    Alphabet,
}

/// The secret grouped into space-separated blocks of four Base32 characters, the
/// manual-entry form shown to a user whose device cannot scan the QR code.
#[must_use]
pub fn grouped_secret(secret: &[u8]) -> String {
    let encoded = base32_encode(secret);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 4);
    for (index, ch) in encoded.chars().enumerate() {
        if index > 0 && index % 4 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

/// Build the `otpauth://totp/...` provisioning URI an authenticator app renders as
/// a QR code (the Key URI Format). `issuer` and `account_name` are percent-encoded
/// into the label and the `issuer=` parameter; the secret is Base32 (no padding).
#[must_use]
pub fn provisioning_uri(
    issuer: &str,
    account_name: &str,
    secret: &[u8],
    params: TotpParams,
) -> String {
    let label = format!(
        "{}:{}",
        percent_encode(issuer),
        percent_encode(account_name)
    );
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period={period}",
        secret = base32_encode(secret),
        issuer = percent_encode(issuer),
        algorithm = params.algorithm.as_str(),
        digits = params.digits,
        period = params.period_secs,
    )
}

/// Percent-encode a URI label/parameter component, escaping everything outside the
/// RFC 3986 unreserved set so an issuer or account name with a space, a colon, or a
/// slash cannot break the URI structure.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors. The seed is the ASCII string "12345678901234567890"
    // (and its repetition for SHA-256/SHA-512), and the vectors pin the 8-digit code
    // at a set of instants.
    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    fn params8(algorithm: TotpAlgorithm) -> TotpParams {
        TotpParams::new(algorithm, 8, 30).unwrap()
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        let p = params8(TotpAlgorithm::Sha1);
        assert_eq!(code_at(SEED_SHA1, p, 59), "94287082");
        assert_eq!(code_at(SEED_SHA1, p, 1_111_111_109), "07081804");
        assert_eq!(code_at(SEED_SHA1, p, 1_111_111_111), "14050471");
        assert_eq!(code_at(SEED_SHA1, p, 1_234_567_890), "89005924");
        assert_eq!(code_at(SEED_SHA1, p, 2_000_000_000), "69279037");
        assert_eq!(code_at(SEED_SHA1, p, 20_000_000_000), "65353130");
    }

    #[test]
    fn rfc6238_sha256_and_sha512_vectors() {
        let p256 = params8(TotpAlgorithm::Sha256);
        assert_eq!(code_at(SEED_SHA256, p256, 59), "46119246");
        assert_eq!(code_at(SEED_SHA256, p256, 1_234_567_890), "91819424");
        let p512 = params8(TotpAlgorithm::Sha512);
        assert_eq!(code_at(SEED_SHA512, p512, 59), "90693936");
        assert_eq!(code_at(SEED_SHA512, p512, 1_234_567_890), "93441116");
    }

    #[test]
    fn verify_matches_the_current_step_and_returns_it() {
        let p = TotpParams::authenticator_default();
        let now = 1_700_000_000;
        let code = code_at(SEED_SHA1, p, now);
        let step = p.timestep(now);
        assert_eq!(verify(SEED_SHA1, p, now, 1, &code), Some(step));
    }

    #[test]
    fn verify_accepts_one_step_of_drift_either_side() {
        let p = TotpParams::authenticator_default();
        let now = 1_700_000_000;
        let step = p.timestep(now);
        // A code from the previous and next steps verifies within a 1-step window
        // and reports that step (so the caller can persist the resync offset).
        let prev = code_for_timestep(SEED_SHA1, p, step - 1);
        let next = code_for_timestep(SEED_SHA1, p, step + 1);
        assert_eq!(verify(SEED_SHA1, p, now, 1, &prev), Some(step - 1));
        assert_eq!(verify(SEED_SHA1, p, now, 1, &next), Some(step + 1));
        // Two steps away is outside a 1-step window.
        let far = code_for_timestep(SEED_SHA1, p, step + 2);
        assert_eq!(verify(SEED_SHA1, p, now, 1, &far), None);
    }

    #[test]
    fn verify_rejects_malformed_and_wrong_codes() {
        let p = TotpParams::authenticator_default();
        let now = 1_700_000_000;
        assert_eq!(verify(SEED_SHA1, p, now, 1, "000000"), None);
        assert_eq!(verify(SEED_SHA1, p, now, 1, "12345"), None); // too short
        assert_eq!(verify(SEED_SHA1, p, now, 1, "1234567"), None); // too long
        assert_eq!(verify(SEED_SHA1, p, now, 1, "abcdef"), None); // non-digit
    }

    #[test]
    fn base32_round_trips_and_ignores_grouping_and_case() {
        let secret = b"a totp seed of some length!!";
        let encoded = base32_encode(secret);
        assert_eq!(base32_decode(&encoded).unwrap(), secret);
        let grouped = grouped_secret(secret);
        assert!(grouped.contains(' '));
        assert_eq!(base32_decode(&grouped).unwrap(), secret);
        assert_eq!(
            base32_decode(&grouped.to_lowercase()).unwrap(),
            secret,
            "manual entry is case-insensitive"
        );
    }

    #[test]
    fn base32_known_vector() {
        // RFC 4648: "foobar" -> MZXW6YTBOI (no padding).
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn provisioning_uri_is_well_formed_and_percent_encoded() {
        let p = TotpParams::authenticator_default();
        let uri = provisioning_uri("Iron Auth", "user@example.com", b"12345678901234567890", p);
        assert!(uri.starts_with("otpauth://totp/Iron%20Auth:user%40example.com?"));
        assert!(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
        assert!(uri.contains("issuer=Iron%20Auth"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn params_reject_out_of_range() {
        assert_eq!(
            TotpParams::new(TotpAlgorithm::Sha1, 5, 30),
            Err(TotpParamsError::Digits)
        );
        assert_eq!(
            TotpParams::new(TotpAlgorithm::Sha1, 9, 30),
            Err(TotpParamsError::Digits)
        );
        assert_eq!(
            TotpParams::new(TotpAlgorithm::Sha1, 6, 10),
            Err(TotpParamsError::Period)
        );
        assert_eq!(
            TotpParams::new(TotpAlgorithm::Sha1, 6, 61),
            Err(TotpParamsError::Period)
        );
    }

    #[test]
    fn algorithm_tokens_round_trip() {
        for algorithm in [
            TotpAlgorithm::Sha1,
            TotpAlgorithm::Sha256,
            TotpAlgorithm::Sha512,
        ] {
            assert_eq!(TotpAlgorithm::parse(algorithm.as_str()), Some(algorithm));
        }
        assert_eq!(TotpAlgorithm::parse("MD5"), None);
        assert_eq!(TotpAlgorithm::parse("sha1"), None);
    }
}
