// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public key and the validity dates inside a certificate, and nothing else about it.
//!
//! # What this reads, and what the store needs
//!
//! An identity provider hands an operator a certificate, and this deployment PINS the key inside
//! it. `saml_connection_certificates` (migration 0197) stores three things this module produces
//! and one it does not:
//!
//! - `public_key` (and `rsa_exponent`), which is what the ACS hands the verifier;
//! - `not_before` and `not_after`, both `NOT NULL`, read out of the certificate at upload --
//!   `not_after` is what #141's expiry alerting reads, so refusing to read them would leave two
//!   required columns with no producer;
//! - `certificate_der`, the bytes themselves, which the caller already has.
//!
//! NOTHING CALLS THIS YET. The management handler that accepts an upload is the next piece of
//! #139, and until it lands the paragraph above describes an intended wiring rather than a live
//! one. Said plainly because a module doc that describes a caller nobody wrote is how a layer
//! ends up shipped, tested, and never executed.
//!
//! # What it deliberately does NOT do
//!
//! - It does not verify a signature on the certificate. There is no chain to verify against,
//!   because the trust decision IS the pinning: an operator looked at a certificate their
//!   identity provider gave them and said "this one". A certificate that chains to a public root
//!   is not more trustworthy for that purpose, and treating it as though it were is how
//!   CVE-2026-9090 happens one layer up.
//! - It does not read the subject, the issuer, the extensions, the key usage or the basic
//!   constraints. Every one of those is a string an attacker chose, and none of them changes
//!   which key signed an assertion.
//! - It does not compare the validity dates TO A CLOCK. It reads them so the store can record
//!   them, and it refuses an interval that ends before it starts -- which is a statement about
//!   the certificate, not about the time. Whether a pinned certificate has EXPIRED is a question
//!   about the clock, which this crate deliberately does not have, the same reason
//!   [`crate::check`] takes `now` as an argument.
//!
//! # This is the MANAGEMENT surface, never the assertion path
//!
//! [`crate::TrustAnchor`] is a RAW key -- an EC point, or an RSA modulus and exponent. That is
//! deliberate, and the property [`crate::verify`] depends on -- that no X.509 parsing sits
//! between a signed assertion and the decision to trust it -- is unchanged by this module,
//! though the sentence has to be about the PATH rather than the crate now. It runs when an
//! operator UPLOADS a
//! certificate, converts it once, and the store keeps the raw key. A response arriving at the ACS
//! endpoint never reaches this code.
//!
//! # The reader is shared, the policy is not
//!
//! The TLV reading is [`ironauth_der`], which was `ironauth-webauthn`'s module until SAML needed
//! it too. Two readers of the same bytes is two answers, and the interesting inputs are exactly
//! the ones they disagree about -- so the SPLITTER is shared and each caller keeps its own
//! POLICY: which curves, which key sizes, what a caller gets back.
//!
//! WHAT IS NOT YET SHARED, SAID PLAINLY: `ironauth-webauthn::x509::parse_certificate` is a
//! SECOND certificate walk, and this is a third of the way to being a third. They differ today
//! in more than policy -- WebAuthn's reads the subject and issuer names, the extensions and the
//! AAGUID because attestation needs them; takes Ed25519, P-256 and RSA with NO size bound at
//! all; and verifies a chain, which this deliberately does not. So
//! "the reader is shared" is true of the TLV layer and NOT of the certificate grammar above it.
//! Merging the two is worth doing and is not this PR: WebAuthn's walk is on a verified
//! attestation path, and changing it needs its own review rather than riding along here.

use ironauth_der::{Der, DerError, oid_arcs, parse_time, tag};
use ironauth_jose::xmldsig::XmlSigKey;

/// The largest certificate this will read, in bytes.
///
/// MATCHED TO THE COLUMN THAT HAS TO HOLD IT. `saml_connection_certificates.certificate_der`
/// is `CHECK (octet_length(certificate_der) BETWEEN 1 AND 16384)`, so a bound larger than that
/// here would accept a certificate the very next statement refuses -- and the operator would be
/// told about a database constraint rather than about their certificate. A bound is only useful
/// where somebody can act on it.
pub const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;

/// The DER object identifiers this recognises, as ARCS rather than encoded bytes.
///
/// Arcs because that is what [`ironauth_der::oid_arcs`] answers, and because a dotted list is
/// checkable by eye against the specification that names it.
mod oid {
    /// `1.2.840.113549.1.1.1` rsaEncryption.
    pub const RSA: &[u64] = &[1, 2, 840, 113_549, 1, 1, 1];
    /// `1.2.840.10045.2.1` id-ecPublicKey.
    pub const EC: &[u64] = &[1, 2, 840, 10_045, 2, 1];
    /// `1.2.840.10045.3.1.7` prime256v1 (P-256).
    pub const P256: &[u64] = &[1, 2, 840, 10_045, 3, 1, 7];
    /// `1.3.132.0.34` secp384r1 (P-384).
    pub const P384: &[u64] = &[1, 3, 132, 0, 34];
}

/// Why a certificate did not yield a key.
///
/// # No variant carries any part of the certificate
///
/// The same rule [`crate::VerifyError`] follows. An operator pasting the wrong blob into a form
/// is told which STEP failed, not their bytes echoed back into a log an auditor reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509Error {
    /// Empty, or larger than [`MAX_CERTIFICATE_BYTES`].
    Size,
    /// Not DER this reader accepts: a tag, a length, a nesting, or content after an element
    /// whose length said it was complete.
    ///
    /// Deliberately ONE variant for every structural fault. Distinguishing "bad length" from
    /// "wrong tag" tells somebody probing the form how far their input travelled, and tells an
    /// operator nothing they can act on: their fix is the same either way, which is to paste the
    /// certificate their identity provider actually gave them.
    Malformed,
    /// A key algorithm this deployment cannot verify signatures with.
    ///
    /// Ed25519, DSA, P-521: real certificates, and no XML Signature algorithm this crate accepts
    /// uses them. SEPARATE FROM [`Self::Malformed`] because the operator's fix is different and
    /// possible -- their identity provider can issue a key this deployment supports, which is
    /// not something they can do about a corrupt file.
    UnsupportedAlgorithm,
    /// An RSA key the signature backend will not verify with.
    ///
    /// SIZE IS THE COMMON CASE AND NOT THE ONLY ONE. `ring` verifies
    /// `RSA_PKCS1_2048_8192_SHA*`, so a 1024-bit modulus lands here -- and so does an exponent
    /// outside `3..=2^33-1`, or an even one, which `ring` rejects as a KEY before it looks at
    /// any signature. All of them are refused HERE rather than pinned and then failing every
    /// assertion with an error about the SIGNATURE, which would send an operator to look at
    /// their identity provider's signing configuration rather than at what they uploaded.
    /// Upload is the only moment anybody can still act on it.
    RsaUnusableKey,
}

impl core::fmt::Display for X509Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Size => "the certificate is empty or larger than this server will read",
            Self::Malformed => "the certificate is not DER this server can read",
            Self::UnsupportedAlgorithm => {
                "the certificate's key is not one this server can verify signatures with"
            }
            Self::RsaUnusableKey => {
                "the certificate's RSA key is not one this server can verify signatures with: \
                 the modulus must be 2048 to 8192 bits and the exponent an odd number from 3 to \
                 2^33-1"
            }
        })
    }
}

impl core::error::Error for X509Error {}

impl From<DerError> for X509Error {
    /// Every DER fault is [`X509Error::Malformed`], for the reason that variant gives.
    fn from(_: DerError) -> Self {
        Self::Malformed
    }
}

/// What the store records about a pinned certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    /// The key itself, in the shape [`crate::TrustAnchor`] takes.
    pub key: XmlSigKey,
    /// `notBefore`, in epoch seconds.
    pub not_before_unix_secs: i64,
    /// `notAfter`, in epoch seconds. What #141's expiry alerting reads.
    pub not_after_unix_secs: i64,
}

/// The smallest and largest RSA MODULUS the signature backend will verify with, in BYTES.
///
/// `ring`'s `RSA_PKCS1_2048_8192_SHA{256,384,512}` accept 2048 through 8192 bits. Written in
/// bytes because that is the unit the modulus arrives in, and checked here so a key that would
/// fail every verification is refused at the one moment an operator is looking at it.
const RSA_MODULUS_BYTES: core::ops::RangeInclusive<usize> = 256..=1024;

/// The RSA PUBLIC EXPONENT range, as VALUES.
///
/// CHECKED FOR THE SAME REASON THE MODULUS IS, and an earlier version checked only the modulus --
/// so `RsaUnusableKey`'s promise ("refused here rather than failing every assertion later") held for
/// one of the two numbers a key is made of. `ring` bounds the exponent to 33 bits (it must be
/// odd, at least 3, and less than 2^33), so five bytes is the ceiling; every real key uses three
/// (65537). A zero-length exponent is refused too: `rsa_exponent` in the store is
/// `CHECK (octet_length(rsa_exponent) > 0)`, and a key with no exponent verifies nothing.
const RSA_EXPONENT: core::ops::RangeInclusive<u64> = 3..=((1 << 33) - 1);

/// The key and validity inside a DER-encoded X.509 certificate.
///
/// # Errors
///
/// [`X509Error`]. No variant carries any part of the input.
pub fn pinned(der: &[u8]) -> Result<Pinned, X509Error> {
    if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES {
        return Err(X509Error::Size);
    }
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let mut outer = Der::new(der);
    let mut certificate = outer.take_sequence()?;
    // NOTHING MAY FOLLOW THE CERTIFICATE. An operator who appends a rotation certificate to the
    // old one would otherwise silently pin the OLD key and then watch every assertion fail with
    // an error about a signature -- the exact misdirection `RsaUnusableKey` exists to prevent.
    end(&outer)?;

    // TBSCertificate ::= SEQUENCE {
    //   [0] EXPLICIT version DEFAULT v1, serialNumber, signature, issuer, validity, subject,
    //   subjectPublicKeyInfo, ... }
    //
    // Everything before `validity` is stepped over WITHOUT being interpreted, which is the
    // point: the serial number and the issuer name are attacker-chosen values this deployment
    // has no use for.
    let mut tbs = certificate.take_sequence()?;
    // `[0] version` is ABSENT in a v1 certificate. A reader that required it refuses every v1
    // certificate; one that skipped a field unconditionally would read the serial number as the
    // version and be one element out for everything after it.
    if tbs.peek_tag() == Some(tag::CONTEXT_CONSTRUCTED) {
        tbs.take_any()?;
    }
    tbs.take_tag(tag::INTEGER)?; // serialNumber
    tbs.take_sequence()?; // signature: the algorithm the ISSUER used, not this key's
    tbs.take_sequence()?; // issuer
    let validity = validity(tbs.take_sequence()?)?;
    tbs.take_sequence()?; // subject
    let key = subject_public_key_info(tbs.take_sequence()?)?;
    // NOT `end(&tbs)`: `[1] issuerUniqueID`, `[2] subjectUniqueID` and `[3] extensions` are legal
    // here and this module reads none of them, so requiring emptiness would refuse every real
    // certificate. That is the ONE place trailing content is expected, and saying so is what
    // stops the rule everywhere else from looking arbitrary.
    //
    // THE REST OF THE CERTIFICATE MUST STILL BE THERE, though nothing here reads it. An earlier
    // version stopped at the SPKI, so `SEQUENCE { tbsCertificate }` alone -- no signature
    // algorithm, no signature, a shape no encoder produces and nothing else accepts -- was read
    // as a certificate and its key pinned. Reading a value out of a document is a claim that the
    // document is one, and the cheapest way to mean it is to require the parts to exist.
    certificate.take_sequence()?; // signatureAlgorithm
    certificate.take_tag(tag::BIT_STRING)?; // signatureValue
    end(&certificate)?;

    Ok(Pinned {
        key,
        not_before_unix_secs: validity.0,
        not_after_unix_secs: validity.1,
    })
}

/// The key inside a DER-encoded `SubjectPublicKeyInfo`.
///
/// # Why this is public beside [`pinned`]
///
/// SAML metadata carries an identity provider's key inside `<ds:X509Certificate>`, which is a
/// whole certificate, so [`pinned`] is the ordinary path and the only one wired to the store
/// today.
///
/// THIS ONE HAS NO PRODUCTION CALLER YET, and that is worth stating rather than leaving to be
/// discovered. `<ds:KeyValue>` in a `KeyDescriptor` carries key material without a certificate,
/// and the metadata reader that will consume it is not written. It is public now because the
/// adversarial suite exercises the SPKI grammar directly -- every DER shape below the
/// certificate wrapper is reachable through it and through nothing else -- and because a
/// metadata reader that had only [`pinned`] would have to refuse a conformant document or invent
/// a certificate around the key. If the metadata work lands without needing it, it should go.
///
/// It answers no validity, because there is none in an SPKI: a caller pinning one supplies the
/// dates itself or has none to supply.
///
/// # Errors
///
/// [`X509Error`], as [`pinned`].
pub fn public_key_from_spki(der: &[u8]) -> Result<XmlSigKey, X509Error> {
    if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES {
        return Err(X509Error::Size);
    }
    let mut outer = Der::new(der);
    let spki = outer.take_sequence()?;
    end(&outer)?;
    subject_public_key_info(spki)
}

/// `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`, as epoch seconds.
fn validity(mut validity: Der<'_>) -> Result<(i64, i64), X509Error> {
    let (not_before_tag, not_before) = validity.take_any()?;
    let (not_after_tag, not_after) = validity.take_any()?;
    end(&validity)?;
    let not_before = parse_time(not_before_tag, not_before)?;
    let not_after = parse_time(not_after_tag, not_after)?;
    // AN INTERVAL THAT ENDS BEFORE IT STARTS IS NOT AN INTERVAL, and the store agrees:
    // 0197 carries `CHECK (not_before < not_after)`. Refusing here means an operator is told
    // about their certificate rather than about a constraint violation.
    if not_before >= not_after {
        return Err(X509Error::Malformed);
    }
    Ok((not_before, not_after))
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }`
fn subject_public_key_info(mut spki: Der<'_>) -> Result<XmlSigKey, X509Error> {
    let mut algorithm = spki.take_sequence()?;
    let oid = oid_arcs(algorithm.take_tag(tag::OID)?)?;
    let key = bit_string(spki.take_tag(tag::BIT_STRING)?)?;
    // A THIRD ELEMENT IN AN SPKI IS NOT AN SPKI. OpenSSL answers "unable to load Public Key" for
    // one, and an earlier version of this module pinned a key from it -- so this server would
    // have been the permissive reader of a blob no other tool calls a public key, which is the
    // two-readers-disagreeing hazard the whole crate exists to close.
    end(&spki)?;

    if oid == oid::RSA {
        // AlgorithmIdentifier for rsaEncryption carries `parameters NULL` and nothing else. An
        // earlier version never looked, so `{rsaEncryption, P-384 OID, NULL}` read as RSA.
        // TWO SHAPES ARE CONFORMING AND BOTH ARE ACCEPTED: the explicit `NULL` RFC 4055
        // requires, and NO parameters at all, which some encoders emit. Refusing the second
        // would reject certificates that verify everywhere else, over a field carrying no
        // information either way. Anything ELSE -- a curve OID, a second element -- describes a
        // key this is not, and an earlier version never looked, so `{rsaEncryption, P-384 OID,
        // NULL}` read as RSA.
        match algorithm.take_any() {
            Ok((0x05, [])) | Err(DerError::Truncated) => {}
            _ => return Err(X509Error::Malformed),
        }
        end(&algorithm)?;

        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let mut key = Der::new(key);
        let mut rsa = key.take_sequence()?;
        // Nothing may follow RSAPublicKey inside the BIT STRING either.
        end(&key)?;
        let modulus = unsigned_integer(rsa.take_tag(tag::INTEGER)?)?;
        let exponent = unsigned_integer(rsa.take_tag(tag::INTEGER)?)?;
        end(&rsa)?;
        if !RSA_MODULUS_BYTES.contains(&modulus.len()) {
            return Err(X509Error::RsaUnusableKey);
        }
        // THE EXPONENT TOO, and an earlier version checked only the modulus. `ring` bounds the
        // exponent as well, so a key with a 40-byte exponent is one this deployment can pin and
        // never verify with.
        if !is_public_exponent(exponent) {
            return Err(X509Error::RsaUnusableKey);
        }
        return Ok(XmlSigKey::Rsa {
            modulus: modulus.to_vec(),
            exponent: exponent.to_vec(),
        });
    }

    if oid == oid::EC {
        // THE CURVE IS A PARAMETER OF THE ALGORITHM, NOT PART OF THE KEY BYTES. A reader that
        // skipped it would have a point of some length and would be guessing the curve from that
        // length -- and a certificate whose parameter says P-384 while its point is 65 bytes is
        // not a P-256 key, it is a malformed P-384 one. Pinning it as P-256 pins a key the
        // identity provider does not have.
        let curve = oid_arcs(algorithm.take_tag(tag::OID)?)?;
        end(&algorithm)?;
        let expected = if curve == oid::P256 {
            65
        } else if curve == oid::P384 {
            97
        } else {
            return Err(X509Error::UnsupportedAlgorithm);
        };
        // A COMPRESSED POINT (`0x02`/`0x03`) is refused rather than decompressed: decompression
        // is a modular square root, which is arithmetic this crate has no business doing on a
        // value somebody uploaded, and no identity provider emits one.
        //
        // THE OPERAND ORDER IS A PREFERENCE, NOT THE GUARD. Both halves are `||`, both answer
        // `Malformed`, and no input can tell which fired -- swapping them survives the suite,
        // which is the honest way to say that the earlier version's defect was its FIXTURES
        // (every compressed point was 33 bytes, so the length check answered first and the
        // prefix check was never reached) and not this line.
        if key.first() != Some(&0x04) || key.len() != expected {
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

/// The bits of a BIT STRING with no unused bits.
///
/// A key is a whole number of bytes, so a non-zero unused-bit count means the bytes after it are
/// not the key this reader thinks they are -- either a different kind of object, or an encoder
/// inventing one.
fn bit_string(contents: &[u8]) -> Result<&[u8], X509Error> {
    match contents.split_first() {
        Some((0, bits)) => Ok(bits),
        _ => Err(X509Error::Malformed),
    }
}

/// Whether these bytes are a usable RSA public exponent: ODD, and at least 3.
///
/// BOTH HALVES, AND AN EARLIER VERSION HAD ONLY ONE. It required odd, which `e = 1` satisfies --
/// and `e = 1` is the identity: "signing" leaves the message unchanged. `ring` refuses it, so it
/// would be pinned here and fail every assertion later with an error about a signature, which is
/// the exact misdirection this whole check exists to prevent.
///
/// EVEN EXPONENTS are the other half: an even `e` shares a factor with phi(n), so it has no
/// inverse and no signature ever verifies against it.
fn is_public_exponent(exponent: &[u8]) -> bool {
    // THE BYTE COUNT IS A PRE-FILTER, NOT THE RULE, and an earlier version made it the rule:
    // `1..=5` bytes admits 2^40-1 while ring's ceiling is 2^33-1, so `FF FF FF FF FF` was pinned
    // here and answered `too_large` there. Nine bytes cannot hold a value in range, so refusing
    // early is only about not folding a number that cannot fit.
    if exponent.is_empty() || exponent.len() > 8 {
        return false;
    }
    let mut value: u64 = 0;
    for byte in exponent {
        // The magnitude has had its sign padding stripped by `unsigned_integer`, so this is at
        // most eight bytes of a u64 and cannot overflow.
        value = value * 256 + u64::from(*byte);
    }
    RSA_EXPONENT.contains(&value) && value % 2 == 1
}

/// A DER INTEGER's magnitude, with the sign padding removed and a negative one refused.
///
/// DER integers are SIGNED two's complement, so a modulus whose top bit is set is written with a
/// leading `0x00` to keep it positive. That byte is PADDING, not magnitude: leaving it in makes a
/// 2048-bit modulus 257 bytes long and fails a size check that is right. A genuinely NEGATIVE
/// integer is refused -- there is no such thing as a negative modulus, and reading one as though
/// the sign were decoration is how a length check gets fooled.
fn unsigned_integer(value: &[u8]) -> Result<&[u8], X509Error> {
    match value.split_first() {
        // A leading zero is padding ONLY when the next byte needs it. `00 7f` is the non-minimal
        // encoding of 127, which DER forbids.
        Some((0, rest)) if rest.first().is_some_and(|byte| byte & 0x80 != 0) => Ok(rest),
        Some((first, _)) if first & 0x80 == 0 && *first != 0 => Ok(value),
        // Zero itself is the single byte `00`, which no key ever is.
        _ => Err(X509Error::Malformed),
    }
}

/// That a cursor is exhausted.
///
/// Called wherever the grammar says an element is complete. Content inside a length somebody
/// chose is content a second reader might interpret, and this crate's whole subject one layer up
/// is what happens when two readers see different documents in the same bytes.
fn end(cursor: &Der<'_>) -> Result<(), X509Error> {
    if cursor.is_empty() {
        Ok(())
    } else {
        Err(X509Error::Malformed)
    }
}
