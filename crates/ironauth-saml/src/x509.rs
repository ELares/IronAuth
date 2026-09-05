// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public key inside a certificate, and NOTHING else about the certificate.
//!
//! # Why this is a walk and not a parser
//!
//! An identity provider hands an operator a certificate, and this deployment needs the key
//! inside it so that key can be PINNED. That is the whole job. What it deliberately is not:
//!
//! - It does not verify a signature on the certificate. There is no chain here to verify
//!   against, because the trust decision is the pinning itself: an operator looked at a
//!   certificate their identity provider gave them and said "this one". A certificate that
//!   verifies against a public root is not more trustworthy for that purpose than one that
//!   does not, and treating it as though it were is how CVE-2026-9090 happens one layer up.
//! - It does not read the subject, the issuer, the extensions, the key usage or the basic
//!   constraints. Every one of those is a string an attacker chose, and none of them changes
//!   which key signed an assertion.
//! - It does not read `NotBefore` or `NotAfter`. Expiry belongs to the pinning record in the
//!   store, which is what an operator rotates, not to a field inside the thing being pinned:
//!   a certificate that says it is valid until 2099 is not a promise anybody has to keep.
//!
//! So what stays here is a DER walk to exactly one place -- `tbsCertificate.subjectPublicKeyInfo`
//! -- and out again. Everything the walk does not need, it steps over without interpreting.
//!
//! # And why it is in this crate rather than reaching for a library
//!
//! `ironauth-saml` exists because SAML XML is hostile input handled in exactly one place. A
//! certificate an operator pastes into an admin form is the same kind of input, arriving at the
//! same subsystem, and the alternative -- a general X.509 library -- brings a parser for every
//! field listed above as deliberately unread. A parser you do not need is attack surface you
//! cannot argue about, and this one is a hundred lines of tag-length-value with a hard bound on
//! every step.
//!
//! # This is the MANAGEMENT surface, never the assertion path
//!
//! [`crate::TrustAnchor`] is a RAW key -- an EC point or an RSA modulus and exponent -- and that
//! is deliberate: no X.509 parser sits between a signed assertion and the decision to trust it.
//! This module runs when an operator UPLOADS a certificate, converts it once, and the store
//! keeps the raw key. A response arriving at the ACS endpoint never reaches this code.

use ironauth_jose::xmldsig::XmlSigKey;

/// The largest certificate this will look at, in bytes.
///
/// A certificate is a few kilobytes. The bound is generous enough that no real one is refused
/// and small enough that a walk over it is bounded work, which is the same argument
/// [`crate::Limits`] makes about a SAML document.
pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;

/// The DER object identifiers this recognises, as encoded bytes rather than dotted strings.
///
/// COMPARED AS BYTES because that is what is in the document. Rendering an OID to a string to
/// compare it introduces a second representation and a formatter to disagree about, and an
/// encoder that emits a non-minimal length or a leading zero would produce a string that matches
/// while the bytes do not.
mod oid {
    /// `1.2.840.113549.1.1.1` rsaEncryption.
    pub const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// `1.2.840.10045.2.1` id-ecPublicKey.
    pub const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// `1.2.840.10045.3.1.7` prime256v1 (P-256).
    pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// `1.3.132.0.34` secp384r1 (P-384).
    pub const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
}

/// Why a certificate did not yield a key.
///
/// # No variant carries any part of the certificate
///
/// The same rule [`crate::VerifyError`] follows. An operator pasting the wrong blob into a form
/// gets told which step failed, not their bytes echoed back into a log an auditor reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509Error {
    /// Larger than [`MAX_CERTIFICATE_BYTES`], or empty.
    Size,
    /// Not DER: a tag, length or nesting this walk does not accept.
    ///
    /// Deliberately one variant for every structural fault. Distinguishing "bad length" from
    /// "wrong tag" tells an attacker probing the form how far their input travelled, and tells
    /// an operator nothing they can act on -- their fix is the same either way, which is to
    /// paste the certificate their identity provider actually gave them.
    Malformed,
    /// A key algorithm this deployment cannot verify with.
    ///
    /// Ed25519, DSA, P-521, an RSA-PSS-restricted key: real certificates, and no XML Signature
    /// algorithm this crate accepts uses them. Separate from [`Self::Malformed`] because the
    /// operator's fix is different and possible: their identity provider can issue a key this
    /// deployment supports.
    UnsupportedAlgorithm,
    /// An RSA key outside the size range the signature backend will verify with.
    ///
    /// `ring` verifies `RSA_PKCS1_2048_8192_SHA*`, so a 1024-bit key is refused HERE rather than
    /// pinned and then failing every assertion at verification time with an error about the
    /// signature. Refusing at upload is the only point where an operator can still do something
    /// about it.
    RsaKeySize,
}

impl core::fmt::Display for X509Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Size => "the certificate is empty or larger than this server will read",
            Self::Malformed => "the certificate is not DER this server can read",
            Self::UnsupportedAlgorithm => {
                "the certificate's key is not one this server can verify signatures with"
            }
            Self::RsaKeySize => "the certificate's RSA key is outside the supported size range",
        })
    }
}

impl core::error::Error for X509Error {}

/// The smallest and largest RSA modulus the signature backend will verify with, in BYTES.
///
/// `ring`'s `RSA_PKCS1_2048_8192_SHA{256,384,512}` accept 2048 through 8192 bits. Written as
/// bytes because that is the unit the modulus arrives in, and checked here so a key that would
/// fail every verification is refused at the one moment an operator is looking at it.
const RSA_MODULUS_BYTES: core::ops::RangeInclusive<usize> = 256..=1024;

/// The public key inside a DER-encoded X.509 certificate.
///
/// # Errors
///
/// [`X509Error`]. No variant carries any part of the input.
pub fn public_key(der: &[u8]) -> Result<XmlSigKey, X509Error> {
    if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES {
        return Err(X509Error::Size);
    }
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let mut certificate = Reader::new(der).sequence()?;
    // TBSCertificate ::= SEQUENCE {
    //   [0] version, serialNumber, signature, issuer, validity, subject,
    //   subjectPublicKeyInfo, ... }
    //
    // Everything before `subjectPublicKeyInfo` is stepped over WITHOUT being interpreted, which
    // is the point: the serial number, the issuer name and the validity dates are attacker-
    // chosen values this deployment has no use for.
    let mut tbs = certificate.sequence()?;
    tbs.skip_optional_context(0)?; // version, absent in a v1 certificate
    tbs.skip()?; // serialNumber
    tbs.skip()?; // signature (the algorithm the ISSUER used, not this key's)
    tbs.skip()?; // issuer
    tbs.skip()?; // validity
    tbs.skip()?; // subject
    subject_public_key_info(&mut tbs)
}

/// The public key inside a DER-encoded `SubjectPublicKeyInfo`.
///
/// Exposed beside [`public_key`] because a `KeyDescriptor` in SAML metadata may carry a bare
/// SPKI as well as a whole certificate, and both arrive at the same management surface.
///
/// # Errors
///
/// [`X509Error`], as [`public_key`].
pub fn public_key_from_spki(der: &[u8]) -> Result<XmlSigKey, X509Error> {
    if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES {
        return Err(X509Error::Size);
    }
    subject_public_key_info(&mut Reader::new(der))
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }`
fn subject_public_key_info(outer: &mut Reader<'_>) -> Result<XmlSigKey, X509Error> {
    let mut spki = outer.sequence()?;
    let mut algorithm = spki.sequence()?;
    let oid = algorithm.oid()?;
    let key = spki.bit_string()?;

    if oid == oid::RSA {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let mut rsa = Reader::new(key).sequence()?;
        let modulus = rsa.unsigned_integer()?;
        let exponent = rsa.unsigned_integer()?;
        rsa.end()?;
        if !RSA_MODULUS_BYTES.contains(&modulus.len()) {
            return Err(X509Error::RsaKeySize);
        }
        return Ok(XmlSigKey::Rsa {
            modulus: modulus.to_vec(),
            exponent: exponent.to_vec(),
        });
    }

    if oid == oid::EC {
        // The curve is a PARAMETER of the algorithm, not part of the key bytes, so a reader that
        // skipped it would have an EC point of some length and no idea which curve it is on --
        // and P-256 and P-384 points are different lengths, so it would be guessing from the
        // length. Read it.
        let curve = algorithm.oid()?;
        algorithm.end()?;
        // An uncompressed point is `0x04 || x || y`. A COMPRESSED point (`0x02`/`0x03`) is
        // refused rather than decompressed: decompression is a modular square root, which is
        // arithmetic this crate has no business doing, and no identity provider emits one.
        let expected = if curve == oid::P256 {
            65
        } else if curve == oid::P384 {
            97
        } else {
            return Err(X509Error::UnsupportedAlgorithm);
        };
        if key.len() != expected || key.first() != Some(&0x04) {
            return Err(X509Error::Malformed);
        }
        return Ok(if expected == 65 {
            XmlSigKey::EcdsaP256(key.to_vec())
        } else {
            XmlSigKey::EcdsaP384(key.to_vec())
        });
    }

    Err(X509Error::UnsupportedAlgorithm)
}

/// A cursor over DER, which reads tag-length-value and refuses everything else.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// The next element's tag and contents, advancing past both.
    fn element(&mut self) -> Result<(u8, &'a [u8]), X509Error> {
        let (&tag, rest) = self.bytes.split_first().ok_or(X509Error::Malformed)?;
        let (&first, rest) = rest.split_first().ok_or(X509Error::Malformed)?;
        let (length, rest) = if first < 0x80 {
            // The short form: the byte IS the length.
            (usize::from(first), rest)
        } else {
            // The long form: the low seven bits count the length's own bytes.
            //
            // `0x80` ITSELF IS THE INDEFINITE FORM, which BER allows and DER forbids -- and it
            // is the shape that makes a length "however much is left", so accepting it is
            // accepting a document whose structure depends on where the reader stops.
            let count = usize::from(first & 0x7f);
            if count == 0 || count > core::mem::size_of::<usize>() {
                return Err(X509Error::Malformed);
            }
            let (bytes, rest) = rest.split_at_checked(count).ok_or(X509Error::Malformed)?;
            // DER REQUIRES THE MINIMAL ENCODING. A leading zero byte means the same number
            // written longer, and two encoders that disagree about which is canonical is how one
            // reader sees a different document from another.
            if bytes[0] == 0 {
                return Err(X509Error::Malformed);
            }
            let mut length = 0_usize;
            for &byte in bytes {
                length = length
                    .checked_mul(256)
                    .and_then(|shifted| shifted.checked_add(usize::from(byte)))
                    .ok_or(X509Error::Malformed)?;
            }
            // And a length that fits the short form must USE the short form.
            if length < 0x80 {
                return Err(X509Error::Malformed);
            }
            (length, rest)
        };
        let (value, rest) = rest.split_at_checked(length).ok_or(X509Error::Malformed)?;
        self.bytes = rest;
        Ok((tag, value))
    }

    /// The contents of the next element, which must be a SEQUENCE.
    fn sequence(&mut self) -> Result<Reader<'a>, X509Error> {
        match self.element()? {
            (0x30, value) => Ok(Reader::new(value)),
            _ => Err(X509Error::Malformed),
        }
    }

    /// The contents of the next element, which must be an OBJECT IDENTIFIER.
    fn oid(&mut self) -> Result<&'a [u8], X509Error> {
        match self.element()? {
            (0x06, value) => Ok(value),
            _ => Err(X509Error::Malformed),
        }
    }

    /// The bits of the next element, which must be a BIT STRING with no unused bits.
    ///
    /// A key is a whole number of bytes, so a non-zero unused-bit count is either a different
    /// kind of object or an encoder inventing one, and either way the bytes after it are not the
    /// key this reader thinks they are.
    fn bit_string(&mut self) -> Result<&'a [u8], X509Error> {
        match self.element()? {
            (0x03, value) => match value.split_first() {
                Some((0, bits)) => Ok(bits),
                _ => Err(X509Error::Malformed),
            },
            _ => Err(X509Error::Malformed),
        }
    }

    /// The next element as a non-negative INTEGER, with DER's sign padding removed.
    ///
    /// DER integers are SIGNED two's complement, so a modulus whose top bit is set is written
    /// with a leading `0x00` to keep it positive. That byte is padding, not magnitude: leaving
    /// it in makes a 2048-bit modulus 257 bytes long and would fail a size check that is right.
    /// A genuinely NEGATIVE integer is refused -- there is no such thing as a negative modulus,
    /// and reading one as though the sign were decoration is how a length check gets fooled.
    fn unsigned_integer(&mut self) -> Result<&'a [u8], X509Error> {
        match self.element()? {
            (0x02, value) => match value.split_first() {
                // A leading zero is padding ONLY when the next byte needs it. `00 7f` is the
                // non-minimal encoding of 127 and DER forbids it.
                Some((0, rest)) if rest.first().is_some_and(|byte| byte & 0x80 != 0) => Ok(rest),
                Some((first, _)) if first & 0x80 == 0 && *first != 0 => Ok(value),
                // Zero itself is the single byte `00`, which no key ever is.
                _ => Err(X509Error::Malformed),
            },
            _ => Err(X509Error::Malformed),
        }
    }

    /// Step over the next element without interpreting it.
    fn skip(&mut self) -> Result<(), X509Error> {
        self.element().map(|_| ())
    }

    /// Step over a context-specific constructed element with this number, if it is next.
    ///
    /// The version in a `TBSCertificate` is `[0] EXPLICIT` and ABSENT in a v1 certificate, which
    /// is why this is optional: a reader that required it would refuse every v1 certificate, and
    /// one that unconditionally skipped a field would read the serial number as the version and
    /// then be one element out for the rest of the structure.
    fn skip_optional_context(&mut self, number: u8) -> Result<(), X509Error> {
        if self.bytes.first() == Some(&(0xa0 | number)) {
            self.skip()?;
        }
        Ok(())
    }

    /// That nothing follows.
    ///
    /// Called where the structure says a sequence is complete. Trailing bytes inside a length
    /// somebody chose are bytes a second reader might interpret, which is the same argument the
    /// XML side makes about anything after the element it verified.
    fn end(&self) -> Result<(), X509Error> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(X509Error::Malformed)
        }
    }
}
