// SPDX-License-Identifier: MIT OR Apache-2.0

//! Base64url decoding and encoding for ceremony fields, plus a constant-time
//! byte comparison for the challenge check.
//!
//! WebAuthn JSON uses base64url without padding, but real-world client glue
//! occasionally emits the standard alphabet or leaves padding on. The decoder
//! is deliberately tolerant of both alphabets and of optional padding so a
//! well-formed ceremony from any conformant client parses, while still rejecting
//! genuinely malformed input.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};

/// Decode a base64url (or, tolerantly, base64) field into bytes.
///
/// Padding is stripped first, then the URL-safe alphabet is tried and the
/// standard alphabet as a fallback, so a conformant WebAuthn field and a
/// standard-alphabet variant both decode. Returns `None` on genuinely malformed
/// input.
#[must_use]
pub fn b64_decode(input: &str) -> Option<Vec<u8>> {
    let trimmed = input.trim_end_matches('=');
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(trimmed) {
        return Some(bytes);
    }
    STANDARD_NO_PAD.decode(trimmed).ok()
}

/// Encode bytes as base64url without padding, the form the WebAuthn option
/// documents use for byte fields (challenge, credential ids, user handle).
#[must_use]
pub fn b64_encode(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

/// Compare two byte slices in constant time relative to their contents.
///
/// The length is compared first (its leak is only the length, which is fixed for
/// a challenge), then every byte is folded into an accumulator so the loop does
/// not short-circuit on the first difference. Used for the single-use challenge
/// echo so the check is not a timing oracle.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_urlsafe_no_pad() {
        assert_eq!(b64_decode("YWJj").unwrap(), b"abc");
    }

    #[test]
    fn tolerates_padding_and_standard_alphabet() {
        // "??" bytes 0x3f 0x3f encode to "Pz8" in both alphabets; a value that
        // differs across alphabets exercises the fallback.
        let bytes = [0xfb, 0xff, 0xfe];
        let url = URL_SAFE_NO_PAD.encode(bytes);
        assert_eq!(b64_decode(&url).unwrap(), bytes);
        let std_padded = base64::engine::general_purpose::STANDARD.encode(bytes);
        assert_eq!(b64_decode(&std_padded).unwrap(), bytes);
    }

    #[test]
    fn rejects_malformed() {
        assert!(b64_decode("!!!not base64!!!").is_none());
    }

    #[test]
    fn round_trips_encode_decode() {
        let bytes = [0_u8, 1, 2, 250, 251, 252, 253, 254, 255];
        assert_eq!(b64_decode(&b64_encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
