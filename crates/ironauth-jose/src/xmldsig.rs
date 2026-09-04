// SPDX-License-Identifier: MIT OR Apache-2.0

//! The XML Signature verification primitive, which lives here for the reason every other
//! signature primitive does.
//!
//! # Why this is not in `ironauth-saml`
//!
//! `scripts/jose-audit.sh` allows exactly one crate a direct dependency on the crypto backend,
//! and this is it. Its argument applies to SAML with no change: a second crate reaching for the
//! same primitives is a second verifier, and the guarantee that there is only one hardened
//! verification path is worth more than the convenience of putting the code beside its caller.
//!
//! So `ironauth-saml` owns the XML: what a `SignedInfo` is, which transforms are allowed, how a
//! subtree canonicalises, and every wrapping refusal. This owns the two lines where bytes meet a
//! key.
//!
//! # SHA-1 is absent and cannot be named
//!
//! There is no [`XmlSigAlg`] variant for it. `rsa-sha1` is still the default in a great deal of
//! deployed SAML and it is the algorithm the collision work retired; a verifier that took it
//! "for compatibility" would be the weakest link in every deployment that had one. The mapping
//! from a URI to this enum is total in one direction only: a URI this does not know is an error,
//! never a default.

use ring::digest;
use ring::signature::{self, RsaPublicKeyComponents, VerificationAlgorithm};

/// The signature algorithms IronAuth accepts in an XML signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlSigAlg {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaSha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaSha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaSha512,
    /// ECDSA on P-256 with SHA-256.
    EcdsaP256Sha256,
    /// ECDSA on P-384 with SHA-384.
    EcdsaP384Sha384,
}

/// The digest algorithms IronAuth accepts in a `Reference`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlDigestAlg {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// A public key a caller has pinned.
///
/// # Raw material, not DER
///
/// `ring` verifies against an uncompressed EC point or RSA components; it does not take a
/// `SubjectPublicKeyInfo`. Taking DER here would put an X.509 parser on the path of
/// attacker-adjacent bytes for no gain, since whoever pinned the key already opened the
/// certificate to decide it was the one to pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlSigKey {
    /// A P-256 public key as the uncompressed point `0x04 || x || y`.
    EcdsaP256(Vec<u8>),
    /// A P-384 public key as the uncompressed point `0x04 || x || y`.
    EcdsaP384(Vec<u8>),
    /// An RSA public key as big-endian modulus and exponent.
    Rsa {
        /// The modulus.
        modulus: Vec<u8>,
        /// The public exponent.
        exponent: Vec<u8>,
    },
}

/// Digest `bytes`.
#[must_use]
pub fn xml_digest(algorithm: XmlDigestAlg, bytes: &[u8]) -> Vec<u8> {
    let algorithm = match algorithm {
        XmlDigestAlg::Sha256 => &digest::SHA256,
        XmlDigestAlg::Sha384 => &digest::SHA384,
        XmlDigestAlg::Sha512 => &digest::SHA512,
    };
    digest::digest(algorithm, bytes).as_ref().to_vec()
}

/// Verify an XML signature value.
///
/// # The ECDSA encoding is FIXED, not DER, and that is not a detail
///
/// RFC 4051 section 2.3.6 defines the `SignatureValue` for the `#ecdsa-sha*` methods as the
/// fixed-width `r || s` concatenation, the same shape JWA uses -- NOT the ASN.1 DER that an
/// X.509 or a TLS signature carries. A verifier wired to the DER algorithm rejects every
/// conforming ECDSA signature, which is a bug that looks like "SAML ECDSA does not work" and
/// gets fixed by turning ECDSA off.
///
/// # Key and algorithm must agree
///
/// A key of the wrong kind for the named algorithm is `false`, never a fallthrough to another
/// key. A caller pinning both an RSA and an ECDSA key must not let a signature choose which one
/// it can beat.
#[must_use]
pub fn verify_xml_signature(
    algorithm: XmlSigAlg,
    key: &XmlSigKey,
    message: &[u8],
    signature: &[u8],
) -> bool {
    match (algorithm, key) {
        (XmlSigAlg::EcdsaP256Sha256, XmlSigKey::EcdsaP256(point)) => verify_raw(
            &signature::ECDSA_P256_SHA256_FIXED,
            point,
            message,
            signature,
        ),
        (XmlSigAlg::EcdsaP384Sha384, XmlSigKey::EcdsaP384(point)) => verify_raw(
            &signature::ECDSA_P384_SHA384_FIXED,
            point,
            message,
            signature,
        ),
        (
            XmlSigAlg::RsaSha256 | XmlSigAlg::RsaSha384 | XmlSigAlg::RsaSha512,
            XmlSigKey::Rsa { modulus, exponent },
        ) => {
            let parameters = match algorithm {
                XmlSigAlg::RsaSha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                XmlSigAlg::RsaSha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                _ => &signature::RSA_PKCS1_2048_8192_SHA512,
            };
            RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            }
            .verify(parameters, message, signature)
            .is_ok()
        }
        _ => false,
    }
}

/// Verify against a raw public key.
fn verify_raw(
    algorithm: &'static dyn VerificationAlgorithm,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    signature::UnparsedPublicKey::new(algorithm, key)
        .verify(message, signature)
        .is_ok()
}

/// Sign for a test, which is the only thing that signs XML in this tree.
///
/// Behind `test-util` for the reason the WebAuthn helper is: a downstream crate's integration
/// test needs to produce a genuinely valid signature to have anything worth refusing forgeries
/// against, and the signing key must not exist outside a test.
#[cfg(feature = "test-util")]
pub mod test_util {
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

    use crate::sign::{SecureRandom, secure_random};

    /// A P-256 key pair for signing test documents.
    pub struct XmlTestKey {
        pair: EcdsaKeyPair,
        rng: SecureRandom,
    }

    impl XmlTestKey {
        /// Generate one.
        ///
        /// # Panics
        ///
        /// If the platform has no usable entropy, which a test cannot proceed without.
        #[must_use]
        pub fn generate() -> Self {
            // THE CRATE'S ONE RNG TOUCH POINT, not a second import of it. `sign.rs` holds the
            // single sanctioned `entropy-via-env` exception in the workspace, with its argument,
            // and a helper that reached for the backend's RNG itself would be a second exception
            // with no argument -- which is what `invariant-lints.sh` is for.
            let rng = secure_random();
            let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("generate a P-256 key");
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &rng)
                    .expect("load the generated key");
            Self { pair, rng }
        }

        /// The uncompressed public point, which is what a caller pins.
        #[must_use]
        pub fn public_point(&self) -> Vec<u8> {
            self.pair.public_key().as_ref().to_vec()
        }

        /// Load a key from a fixed PKCS#8 document, so a caller can have the SAME key twice.
        ///
        /// # Why a fuzz target cannot use [`XmlTestKey::generate`]
        ///
        /// A fuzzer needs the accept path to EXIST: with no key that can authorise anything,
        /// `verify` is `Err` by construction and every assertion downstream of it is
        /// unfalsifiable. It also needs determinism, because a corpus entry that verifies in one
        /// process and not the next is a corpus entry that means nothing.
        ///
        /// `generate` gives neither. This takes the bytes, so the caller can embed one.
        ///
        /// # Errors
        ///
        /// If the document is not a P-256 PKCS#8 private key.
        pub fn from_pkcs8(document: &[u8]) -> Result<Self, &'static str> {
            let rng = secure_random();
            let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document, &rng)
                .map_err(|_| "not a P-256 PKCS#8 key")?;
            Ok(Self { pair, rng })
        }

        /// A PKCS#8 document for a freshly generated key, so a caller can embed one.
        ///
        /// # Panics
        ///
        /// If the platform has no usable entropy.
        #[must_use]
        pub fn generate_pkcs8() -> Vec<u8> {
            let rng = secure_random();
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("generate a P-256 key")
                .as_ref()
                .to_vec()
        }

        /// Sign `message`, producing the fixed-width `r || s` an XML signature carries.
        ///
        /// # Panics
        ///
        /// If signing fails, which a test cannot proceed past.
        #[must_use]
        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.pair
                .sign(&self.rng, message)
                .expect("sign")
                .as_ref()
                .to_vec()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::XmlTestKey;

        /// A generated PKCS#8 document loads back, and the loaded key signs.
        ///
        /// # Why a generator needs a caller
        ///
        /// `generate_pkcs8` exists so a fuzz target can EMBED a fixed key: a fuzzer needs the
        /// accept path to be reachable and deterministic, and `generate` gives neither. That
        /// makes it a producer whose only consumer is a human running it once, so nothing would
        /// notice if it stopped producing a loadable document -- if, for instance, the curve
        /// constant it hardcodes diverged from the one `from_pkcs8` parses with.
        ///
        /// A review found it with no callers at all, which is the layer-without-a-caller shape.
        /// This is the caller, and it pins the two together.
        #[test]
        fn a_generated_key_document_loads_and_signs() {
            let document = XmlTestKey::generate_pkcs8();
            let key = XmlTestKey::from_pkcs8(&document).expect("a generated document loads");
            let signature = key.sign(b"a message");
            // A P-256 fixed-width signature is r||s over a 32 byte field.
            assert_eq!(signature.len(), 64);
            // AND THE POINT IS A POINT. Uncompressed, so 0x04 and two 32 byte coordinates.
            let point = key.public_point();
            assert_eq!(point.len(), 65);
            assert_eq!(point[0], 0x04);
        }

        /// Bytes that are not a PKCS#8 key are refused rather than panicking.
        #[test]
        fn a_document_that_is_not_a_key_is_refused() {
            assert!(XmlTestKey::from_pkcs8(b"").is_err());
            assert!(XmlTestKey::from_pkcs8(b"not a key at all").is_err());
            // A VALID DER PREFIX with the wrong contents, so the refusal is not merely "too
            // short": this is the shape a truncated or corrupted key actually has.
            let mut truncated = XmlTestKey::generate_pkcs8();
            truncated.truncate(20);
            assert!(XmlTestKey::from_pkcs8(&truncated).is_err());
        }
    }
}
