// SPDX-License-Identifier: MIT OR Apache-2.0

//! The local SHA-1 digest of a password, split into the k-anonymity range key.
//!
//! The HIBP range protocol keys on the SHA-1 of the password. This module computes
//! that SHA-1 LOCALLY and splits the 40-character uppercase hex form into a 5-char
//! PREFIX (the only part any provider ever receives) and a 35-char SUFFIX (compared
//! only ever inside this process). Neither the password nor its full hash is exposed
//! by any type here: [`Sha1Prefix`] renders only the 5-char prefix, and the suffix is
//! compared in constant time and never rendered.

use sha1::{Digest, Sha1};

/// The uppercase hex alphabet HIBP keys on. HIBP compares case-insensitively, but we
/// emit uppercase so the request and the corpus lookup are byte-for-byte stable.
const HEX: [u8; 16] = *b"0123456789ABCDEF";

/// How many hex characters of the SHA-1 form the range PREFIX (the HIBP k-anonymity
/// convention: 5 characters, 20 bits).
const PREFIX_LEN: usize = 5;

/// How many hex characters of the SHA-1 form the range SUFFIX (the remaining 35 of
/// the 40-character hex hash).
const SUFFIX_LEN: usize = 40 - PREFIX_LEN;

/// The 5-character uppercase hex PREFIX of a password's SHA-1: the ONLY portion of
/// the hash that ever leaves the process (it is what a range provider is queried
/// with). It renders only those 5 characters and carries neither the password nor the
/// rest of the hash.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sha1Prefix([u8; PREFIX_LEN]);

impl Sha1Prefix {
    /// The 5-character uppercase hex prefix as a string slice. This is the value put
    /// on the wire to a range provider, and nothing else about the hash is.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // The bytes are drawn from the uppercase hex alphabet by construction, so they
        // are always valid ASCII/UTF-8.
        std::str::from_utf8(&self.0).unwrap_or("00000")
    }
}

impl std::fmt::Debug for Sha1Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The prefix is the k-anonymized, non-secret range key, so rendering it in a
        // debug log is safe (unlike the suffix, which we never render).
        write!(f, "Sha1Prefix({})", self.as_str())
    }
}

/// The 35-character uppercase hex SUFFIX of a password's SHA-1. It is compared ONLY
/// inside this process, in constant time, against the suffixes a provider returns; it
/// is never rendered (no `Debug`) and never leaves the process.
#[derive(Clone, Copy)]
pub struct Sha1Suffix([u8; SUFFIX_LEN]);

impl std::fmt::Debug for Sha1Suffix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the suffix bytes: a candidate suffix is the tail of a password's
        // hash. A redacted form lets containers derive Debug without exposing it.
        f.write_str("Sha1Suffix(<redacted>)")
    }
}

impl Sha1Suffix {
    /// Parse an uppercase (or lowercase) hex suffix line, as returned by a range
    /// provider. Returns [`None`] unless the input is exactly 35 hex characters, so a
    /// malformed line is dropped rather than partially matched.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let bytes = raw.as_bytes();
        if bytes.len() != SUFFIX_LEN {
            return None;
        }
        let mut out = [0_u8; SUFFIX_LEN];
        for (dst, &byte) in out.iter_mut().zip(bytes) {
            let upper = byte.to_ascii_uppercase();
            if !upper.is_ascii_hexdigit() {
                return None;
            }
            *dst = upper;
        }
        Some(Self(out))
    }

    /// Whether two suffixes are equal, compared in CONSTANT time over the fixed 35
    /// bytes (no early exit), so the time taken never reveals how far a candidate
    /// matched a returned suffix. A boolean is folded from an accumulated difference.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        let mut diff = 0_u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// A password's SHA-1, split into its range PREFIX and SUFFIX. Constructed only by
/// [`digest_password`]; it exposes the prefix (the wire value) and the suffix (the
/// in-process comparison value) but never the password or the joined hash.
#[derive(Clone, Copy)]
pub struct Sha1Digest {
    prefix: Sha1Prefix,
    suffix: Sha1Suffix,
}

impl Sha1Digest {
    /// The 5-character range prefix: the only part of the hash that is ever sent to a
    /// provider.
    #[must_use]
    pub fn prefix(&self) -> Sha1Prefix {
        self.prefix
    }

    /// The 35-character range suffix, compared in constant time against a provider's
    /// returned suffixes. Never leaves the process.
    #[must_use]
    pub fn suffix(&self) -> Sha1Suffix {
        self.suffix
    }
}

/// Compute the SHA-1 of `password` LOCALLY and split it into the k-anonymity range
/// key. This is the ONLY place a password's hash is derived, and the result exposes
/// only the 5-char prefix on the wire; the full hash never leaves the process.
///
/// The password is expected to be already NFKC-normalized by
/// [`crate::normalize`](crate::normalize_nfkc); screening and hashing must use the
/// same normalized form so the SHA-1 (and the Argon2id verifier) agree.
#[must_use]
pub fn digest_password(password: &str) -> Sha1Digest {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let bytes: [u8; 20] = hasher.finalize().into();

    let mut hex = [0_u8; 40];
    for (i, &byte) in bytes.iter().enumerate() {
        hex[i * 2] = HEX[usize::from(byte >> 4)];
        hex[i * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }

    let mut prefix = [0_u8; PREFIX_LEN];
    prefix.copy_from_slice(&hex[..PREFIX_LEN]);
    let mut suffix = [0_u8; SUFFIX_LEN];
    suffix.copy_from_slice(&hex[PREFIX_LEN..]);

    Sha1Digest {
        prefix: Sha1Prefix(prefix),
        suffix: Sha1Suffix(suffix),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_matches_the_known_hibp_vector_for_password() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 (the canonical
        // HIBP example). The prefix is the first 5 chars, the suffix the remaining 35.
        let digest = digest_password("password");
        assert_eq!(digest.prefix().as_str(), "5BAA6");
        let expected_suffix =
            Sha1Suffix::parse("1E4C9B93F3F0682250B6CF8331B7EE68FD8").expect("suffix");
        assert!(digest.suffix().ct_eq(&expected_suffix));
    }

    #[test]
    fn prefix_is_exactly_five_uppercase_hex_and_never_the_full_hash() {
        let digest = digest_password("correct horse battery staple");
        let prefix = digest.prefix();
        assert_eq!(prefix.as_str().len(), 5);
        assert!(
            prefix.as_str().bytes().all(|b| b.is_ascii_hexdigit()),
            "prefix must be hex only"
        );
        // The rendered prefix carries nothing but the 5 chars.
        assert_eq!(
            format!("{prefix:?}"),
            format!("Sha1Prefix({})", prefix.as_str())
        );
    }

    #[test]
    fn suffix_parse_rejects_wrong_length_and_non_hex() {
        assert!(Sha1Suffix::parse("").is_none());
        assert!(Sha1Suffix::parse("TOOSHORT").is_none());
        assert!(Sha1Suffix::parse("1E4C9B93F3F0682250B6CF8331B7EE68FD").is_none()); // 34
        assert!(Sha1Suffix::parse("ZE4C9B93F3F0682250B6CF8331B7EE68FD8").is_none()); // Z
    }

    #[test]
    fn suffix_ct_eq_is_case_insensitive_and_distinguishes() {
        let upper = Sha1Suffix::parse("1E4C9B93F3F0682250B6CF8331B7EE68FD8").expect("suffix");
        let lower = Sha1Suffix::parse("1e4c9b93f3f0682250b6cf8331b7ee68fd8").expect("suffix");
        assert!(
            upper.ct_eq(&lower),
            "parse uppercases, so case does not matter"
        );
        let other = Sha1Suffix::parse("00000000000000000000000000000000000").expect("zero suffix");
        assert!(!upper.ct_eq(&other));
    }
}
