// SPDX-License-Identifier: MIT OR Apache-2.0

//! XML Encryption data decryption, for SAML encrypted assertions (issue #138, criterion 5).
//!
//! # What lives here and what deliberately does not
//!
//! THE DATA KEY IS DECRYPTED SOMEWHERE ELSE. This module takes a symmetric key that a caller
//! already has, and decrypts the `CipherValue` under it. The RSA key-transport step -- unwrapping
//! that symmetric key with the service provider's private key -- is a seam the caller fills, and
//! that is a deliberate decision with two reasons.
//!
//! The first is architectural: a production service provider's decryption key belongs in an HSM
//! or a KMS, not in a parsing library, and a library that took the private key would make the
//! HSM deployment the awkward path.
//!
//! The second is specific and it is why the obvious implementation is wrong here. `ring` offers
//! no RSA decryption at all. The `rsa` crate does, and this workspace already depends on it --
//! but `deny.toml` ignores RUSTSEC-2023-0071 (the Marvin timing attack) on the written ground
//! that the crate is "used only for RS256 keygen + DER export ... NEVER DECRYPTS or signs, so
//! the Marvin decryption-timing path is unreachable". Calling `rsa`'s decrypt here would make
//! that sentence false and the advisory live, in exactly the operation the advisory is about.
//! An exemption whose justification has quietly stopped holding is worse than no exemption.
//!
//! # The algorithm allowlist, and the two attacks it is shaped by
//!
//! GCM ONLY. CBC modes are refused, and `ring` offers none, so the refusal is structural rather
//! than a rule somebody has to keep following. XML Encryption's CBC modes are broken: Jager and
//! Somorovsky (CCS 2011) recovered plaintext from a conforming implementation using the parser's
//! own error behaviour as an oracle, and the follow-up work broke the "backwards compatibility"
//! defences too. A verifier that accepts CBC inherits that whether or not it thinks it is
//! careful about error messages, because the oracle is in what the XML parser does with the
//! decrypted bytes.
//!
//! RSA-1.5 KEY TRANSPORT IS REFUSED by the same reasoning one layer up: Bleichenbacher (1998),
//! which needs no CVE. An earlier version of this note cited Keycloak CVE-2026-2092, which is a
//! DIFFERENT vulnerability -- encrypted-assertion injection when the enclosing Response is
//! unsigned, the class the decrypt-then-revalidate ordering closes. A reader checking whether
//! the RSA-1.5 refusal is justified followed the only citation offered and found something else. The refusal is enforced where the algorithm URI is read, so a
//! caller's unwrapper is never asked to perform it.
//!
//! # The order is decrypt, then RE-VALIDATE
//!
//! A decrypted assertion is attacker-supplied bytes that happen to have been encrypted. Being
//! encrypted says the sender knew a key; it does not say who signed what. So the plaintext goes
//! back through the parser and the verifier like any other document, and this module returns
//! BYTES rather than anything that looks verified.

use ring::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

/// The nonce length XML Encryption 1.1 uses for GCM, in bytes (96 bits).
///
/// Prepended to the ciphertext rather than carried in its own element, which is what section 5.2.4
/// of XML Encryption 1.1 prescribes for the GCM modes.
const IV_BYTES: usize = 12;

/// A data-encryption algorithm this crate will decrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlEncAlg {
    /// AES-128-GCM (`http://www.w3.org/2009/xmlenc11#aes128-gcm`).
    Aes128Gcm,
    /// AES-256-GCM (`http://www.w3.org/2009/xmlenc11#aes256-gcm`).
    Aes256Gcm,
}

impl XmlEncAlg {
    /// The key length this algorithm takes, in bytes.
    #[must_use]
    pub const fn key_bytes(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }
}

/// Why a decryption was refused.
///
/// # One variant per DECISION, not per place the decision was made
///
/// The same rule the signature verifier follows, for the same reason: a finer taxonomy is an
/// oracle. In particular there is no variant distinguishing "the tag did not authenticate" from
/// "the plaintext was not what we expected", because that distinction is precisely what a
/// padding-oracle attack reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlEncError {
    /// The key is not the length the algorithm takes.
    KeyLength,
    /// The ciphertext is too short to carry an IV and a tag, or is otherwise malformed.
    Malformed,
    /// Authentication failed: a wrong key, or a tampered ciphertext.
    Decrypt,
}

impl core::fmt::Display for XmlEncError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::KeyLength => "the data key is not the length the algorithm takes",
            Self::Malformed => "the ciphertext is malformed",
            Self::Decrypt => "the ciphertext did not authenticate",
        })
    }
}

impl core::error::Error for XmlEncError {}

/// Decrypt an XML Encryption `CipherValue` under a data key.
///
/// `cipher_value` is `iv || ciphertext || tag`, which is the layout XML Encryption 1.1 section
/// 5.2.4 prescribes for the GCM modes: the IV is prepended to the cipher data rather than carried
/// in its own element.
///
/// # No associated data, and that is what the specification says
///
/// XML Encryption binds nothing into the AEAD's associated data. That is a real weakness of the
/// format -- the algorithm URI, the key it was wrapped under and the element it sits in are all
/// unauthenticated -- and it is not this function's to fix: inventing an AAD would make every
/// conforming ciphertext fail to decrypt. What answers the weakness is the layer above, where the
/// decrypted assertion is REVALIDATED against a pinned signing key rather than trusted for having
/// decrypted.
///
/// # Errors
///
/// [`XmlEncError`]. No variant carries any part of the ciphertext or the key.
pub fn decrypt(
    algorithm: XmlEncAlg,
    key: &[u8],
    cipher_value: &[u8],
) -> Result<Vec<u8>, XmlEncError> {
    // NOT KILLABLE BY A TEST, AND KEPT ANYWAY. `UnboundKey::new` below refuses a key that is not
    // the algorithm's length, so removing this changes no outcome: a mutation sweep confirmed
    // the whole suite stays green without it. It is here so the refusal does not DEPEND on that
    // behaviour of `ring`, and so the error says "key length" rather than arriving as whatever
    // the backend decides. A reader should know it is defence in depth rather than the check.
    if key.len() != algorithm.key_bytes() {
        return Err(XmlEncError::KeyLength);
    }
    let aead = match algorithm {
        XmlEncAlg::Aes128Gcm => &AES_128_GCM,
        XmlEncAlg::Aes256Gcm => &AES_256_GCM,
    };
    // AT LEAST an IV and a tag, and the empty plaintext is legal: a zero-length assertion is
    // nonsense but it is the PARSER's job to say so, not this function's. An earlier draft
    // required one byte of ciphertext and would have refused a conforming document.
    if cipher_value.len() < IV_BYTES + aead.tag_len() {
        return Err(XmlEncError::Malformed);
    }
    let mut nonce = [0_u8; IV_BYTES];
    nonce.copy_from_slice(&cipher_value[..IV_BYTES]);
    let mut in_out = cipher_value[IV_BYTES..].to_vec();

    let unbound = UnboundKey::new(aead, key).map_err(|_| XmlEncError::KeyLength)?;
    let opened = LessSafeKey::new(unbound)
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| XmlEncError::Decrypt)?;
    Ok(opened.to_vec())
}

/// Test-only encryption, so a corpus can build a document a real identity provider would send.
///
/// # Why this exists at all
///
/// A decryption corpus built by hand-writing base64 tests nothing: every entry would be refused
/// for not decrypting, and the suite would pass against an implementation that refused
/// everything. Each case has to start from a ciphertext that really decrypts, which means the
/// tests need an encryptor.
///
/// Behind a feature, so the surface does not exist in a normal build. A verifier that can also
/// encrypt is a verifier a caller can misuse.
#[cfg(feature = "test-util")]
pub mod test_util {
    use ring::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

    use super::{IV_BYTES, XmlEncAlg};

    /// Encrypt `plaintext`, producing `iv || ciphertext || tag`.
    ///
    /// The IV is an ARGUMENT rather than drawn here, because a test that cannot fix the nonce
    /// cannot produce the same bytes twice, and a corpus entry that changes every run is not a
    /// regression test. Real encryption must never do this.
    ///
    /// # Panics
    ///
    /// If the key or the IV is the wrong length, which a test cannot proceed past.
    #[must_use]
    pub fn encrypt(
        algorithm: XmlEncAlg,
        key: &[u8],
        iv: &[u8; IV_BYTES],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let aead = match algorithm {
            XmlEncAlg::Aes128Gcm => &AES_128_GCM,
            XmlEncAlg::Aes256Gcm => &AES_256_GCM,
        };
        let unbound = UnboundKey::new(aead, key).expect("a key of the algorithm's length");
        let mut in_out = plaintext.to_vec();
        LessSafeKey::new(unbound)
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(*iv), Aad::empty(), &mut in_out)
            .expect("sealing does not fail for in-memory input");
        let mut out = Vec::with_capacity(IV_BYTES + in_out.len());
        out.extend_from_slice(iv);
        out.append(&mut in_out);
        out
    }
}

// BEHIND THE FEATURE AS WELL AS `test`, because the encryptor these tests need is. The gate runs
// `cargo test -p ironauth-jose --lib` with NO features, and a test module that reaches for
// `test_util` there does not compile -- which is a broken build for every consumer running the
// plain command, not merely a skipped test.
#[cfg(all(test, feature = "test-util"))]
mod tests {
    use super::test_util::encrypt;
    use super::{IV_BYTES, XmlEncAlg, XmlEncError, decrypt};

    /// A fixed IV, so a failure is the same failure twice.
    const IV: [u8; IV_BYTES] = [7; IV_BYTES];

    /// Every algorithm round-trips, including the EMPTY plaintext.
    ///
    /// # The boundary this module argues for and nothing measured
    ///
    /// `decrypt` requires at least `IV_BYTES + tag_len` and the comment beside it records that an
    /// earlier draft required one byte MORE, which would have refused a conforming empty
    /// plaintext. Nothing exercised that: this module had no test at all, and was reached only
    /// through a second crate's SAML corpus, which never sends an empty assertion.
    #[test]
    fn every_algorithm_round_trips_including_the_empty_plaintext() {
        for (algorithm, key) in [
            (XmlEncAlg::Aes128Gcm, vec![0x2a; 16]),
            (XmlEncAlg::Aes256Gcm, vec![0x2a; 32]),
        ] {
            for plaintext in [&b""[..], &b"a"[..], &b"the assertion"[..]] {
                let sealed = encrypt(algorithm, &key, &IV, plaintext);
                assert_eq!(
                    decrypt(algorithm, &key, &sealed).as_deref(),
                    Ok(plaintext),
                    "{algorithm:?} must round-trip {} bytes",
                    plaintext.len()
                );
            }
        }
    }

    /// The length bound is exact at BOTH edges.
    ///
    /// # Why one arm is not enough
    ///
    /// A mutation sweep showed the bound survives being loosened to `<=` (which refuses the
    /// conforming empty plaintext) AND being tightened by dropping the tag length (which lets a
    /// value shorter than a tag reach the AEAD). The one input that separates all three is the
    /// empty plaintext's sealed form -- exactly `IV_BYTES + tag_len` bytes -- so both edges are
    /// pinned here.
    #[test]
    fn the_length_bound_is_exact_at_both_edges() {
        for algorithm in [XmlEncAlg::Aes128Gcm, XmlEncAlg::Aes256Gcm] {
            let key = vec![0x2a; algorithm.key_bytes()];
            let sealed = encrypt(algorithm, &key, &IV, b"");
            let smallest = sealed.len();
            assert_eq!(smallest, IV_BYTES + 16, "an empty plaintext is IV plus tag");

            // EXACTLY the bound: accepted, and it really decrypts.
            assert_eq!(decrypt(algorithm, &key, &sealed), Ok(Vec::new()));
            // ONE SHORT: malformed, not a decrypt failure. The distinction matters because a
            // length is not a secret and a tag mismatch is.
            assert_eq!(
                decrypt(algorithm, &key, &sealed[..smallest - 1]),
                Err(XmlEncError::Malformed)
            );
            // AT THE BOUND BUT NOT AUTHENTIC: the length check must not be doing the
            // authentication's job. Zeroes are the right length and the wrong bytes.
            assert_eq!(
                decrypt(algorithm, &key, &vec![0_u8; smallest]),
                Err(XmlEncError::Decrypt)
            );
        }
    }

    /// A wrong key, a tampered ciphertext and a tampered tag are one answer.
    #[test]
    fn a_wrong_key_and_a_tampered_ciphertext_are_indistinguishable() {
        let algorithm = XmlEncAlg::Aes256Gcm;
        let key = vec![0x2a; 32];
        let sealed = encrypt(algorithm, &key, &IV, b"the assertion");

        let mut flipped_body = sealed.clone();
        flipped_body[IV_BYTES] ^= 0x01;
        let mut flipped_tag = sealed.clone();
        let last = flipped_tag.len() - 1;
        flipped_tag[last] ^= 0x01;

        for (what, key, value) in [
            ("a wrong key", vec![0x99; 32], sealed.clone()),
            ("a flipped ciphertext byte", key.clone(), flipped_body),
            ("a flipped tag byte", key.clone(), flipped_tag),
        ] {
            assert_eq!(
                decrypt(algorithm, &key, &value),
                Err(XmlEncError::Decrypt),
                "{what}"
            );
        }
        // CONTROL: the untouched value still opens, so the sameness above is not "everything
        // fails".
        assert_eq!(
            decrypt(algorithm, &key, &sealed).as_deref(),
            Ok(&b"the assertion"[..])
        );
    }

    /// A key of the wrong length is refused before any ciphertext is touched.
    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        let sealed = encrypt(XmlEncAlg::Aes256Gcm, &[0x2a; 32], &IV, b"x");
        for length in [0_usize, 15, 16, 31, 33, 64] {
            assert_eq!(
                decrypt(XmlEncAlg::Aes256Gcm, &vec![0x2a; length], &sealed),
                Err(XmlEncError::KeyLength),
                "{length} bytes is not an AES-256 key"
            );
        }
        // AND THE 128 VARIANT TAKES 16, not 32: the length is per algorithm, not a constant.
        assert_eq!(
            decrypt(XmlEncAlg::Aes128Gcm, &[0x2a; 32], &sealed),
            Err(XmlEncError::KeyLength)
        );
    }
}
