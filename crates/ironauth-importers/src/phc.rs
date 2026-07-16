// SPDX-License-Identifier: MIT OR Apache-2.0

//! Re-encode vendor-native hash operands into the canonical strings the #55
//! scheme layer verifies.
//!
//! The importers never hash a password and never invent a verifier; they take the
//! raw operands a vendor export carries (a base64 salt, a base64 derived key, an
//! iteration count) and rebuild the SAME string an in-tree hasher would have
//! produced, so [`ironauth_import::ForeignHash::parse`] recognizes it and a later
//! login verifies it. Every re-encoded string is a one-way verifier; there is no
//! function here that recovers a plaintext password.
//!
//! The one subtlety is base64 alphabets. A vendor export uses STANDARD base64
//! (alphabet `+/`, usually padded); the PHC string form the scheme layer parses
//! uses "B64" (the same `+/` alphabet WITHOUT padding). These helpers decode the
//! vendor form and re-encode the PHC form so the operand bytes are preserved
//! exactly.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;

/// The PBKDF2 pseudo-random function a foreign credential was derived under. Only
/// the two HMAC variants the scheme layer recognizes (`$pbkdf2-sha256$` /
/// `$pbkdf2-sha512$`) are representable; the legacy HMAC-SHA1 variant is not and is
/// reported as a gap by the caller rather than mis-encoded here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pbkdf2Prf {
    /// PBKDF2 over HMAC-SHA256.
    Sha256,
    /// PBKDF2 over HMAC-SHA512.
    Sha512,
}

impl Pbkdf2Prf {
    /// The PHC algorithm identifier for this variant.
    fn ident(self) -> &'static str {
        match self {
            Pbkdf2Prf::Sha256 => "pbkdf2-sha256",
            Pbkdf2Prf::Sha512 => "pbkdf2-sha512",
        }
    }
}

/// Build a canonical PBKDF2 PHC string from the raw salt and derived-key bytes.
///
/// The output is `$pbkdf2-sha256$i=<iterations>,l=<len>$<salt>$<derived>` with the
/// two operands in PHC B64. The `l=<len>` parameter is always emitted and set to
/// the exact derived-key length the export carried, so the scheme layer recomputes
/// PBKDF2 to that same length: the re-encoding is correct regardless of the source
/// implementation's derived-key size (Keycloak's varies by version), never assuming
/// the `RustCrypto` default of 32 bytes.
pub(crate) fn pbkdf2_phc(prf: Pbkdf2Prf, iterations: u32, salt: &[u8], derived: &[u8]) -> String {
    format!(
        "${}$i={iterations},l={}${}${}",
        prf.ident(),
        derived.len(),
        STANDARD_NO_PAD.encode(salt),
        STANDARD_NO_PAD.encode(derived),
    )
}

/// Decode a STANDARD base64 operand (alphabet `+/`), tolerating present or absent
/// `=` padding, into its raw bytes. Returns [`None`] for a value that is not valid
/// base64 (the caller reports it as a gap rather than mapping a corrupt credential).
pub(crate) fn decode_std_b64(value: &str) -> Option<Vec<u8>> {
    STANDARD_NO_PAD.decode(value.trim_end_matches('=')).ok()
}

/// Decode a passlib "adapted base64" (ab64) operand, the encoding `OpenLDAP` /
/// passlib `{PBKDF2-SHA256}` credentials use: STANDARD base64 with `+` rewritten to
/// `.` and no padding. The inverse rewrite recovers a normal STANDARD operand.
pub(crate) fn decode_ab64(value: &str) -> Option<Vec<u8>> {
    let standard: String = value
        .chars()
        .map(|c| if c == '.' { '+' } else { c })
        .collect();
    decode_std_b64(&standard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_phc_emits_len_and_iterations() {
        let phc = pbkdf2_phc(Pbkdf2Prf::Sha256, 27_500, b"sixteen-byte-salt", &[0_u8; 32]);
        assert!(phc.starts_with("$pbkdf2-sha256$i=27500,l=32$"), "{phc}");
        // The two base64 operands (salt, derived key) carry no `=` padding; the only
        // `=` characters are the PHC `key=value` parameter separators.
        let operands: Vec<&str> = phc.rsplit('$').take(2).collect();
        assert!(
            operands.iter().all(|seg| !seg.contains('=')),
            "PHC operands carry no padding: {phc}"
        );
    }

    #[test]
    fn base64_round_trips_across_alphabets() {
        // A value with bytes that encode to `+` and `/` in the standard alphabet,
        // proving the padding-tolerant decoders and the ab64 rewrite agree.
        let raw = [0xfb_u8, 0xff, 0xbf, 0x00, 0x10, 0x83];
        let std = base64::engine::general_purpose::STANDARD.encode(raw);
        assert_eq!(decode_std_b64(&std).unwrap(), raw);
        let ab64 = std.trim_end_matches('=').replace('+', ".");
        assert_eq!(decode_ab64(&ab64).unwrap(), raw);
    }

    #[test]
    fn malformed_base64_is_none_not_a_panic() {
        assert!(decode_std_b64("not valid base64 !!!").is_none());
        assert!(decode_ab64("@@@@").is_none());
    }
}
