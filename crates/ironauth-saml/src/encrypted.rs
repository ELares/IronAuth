// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted SAML assertions (issue #138, criterion 5).
//!
//! # The order, and why it is the whole of this module
//!
//! DECRYPT, THEN RE-VALIDATE. A decrypted assertion is attacker-supplied XML that happens to have
//! been encrypted, and being encrypted says only that the sender knew a key. It says nothing
//! about who asserted what. So the plaintext goes back through [`crate::parse`] and
//! [`crate::verify`] exactly like a document that arrived in the clear, against the same pinned
//! anchors, and this module never returns anything that has not been through them.
//!
//! The mistake this closes is the one Keycloak shipped as CVE-2026-2092 and Casdoor shipped
//! twice: treating "it decrypted" as evidence. An encrypted assertion whose signature is absent,
//! or is over a different element, or is by an unpinned key, must fail exactly as it would have
//! failed unencrypted, and the only way to be sure of that is to run the same code.
//!
//! # The key transport is a SEAM, and that is deliberate
//!
//! [`KeyTransport`] is supplied by the caller. This crate parses the `EncryptedKey`, enforces the
//! algorithm allowlist, and hands over the wrapped bytes; the unwrap itself happens wherever the
//! service provider keeps its private key, which in a real deployment is an HSM or a KMS rather
//! than a process's heap.
//!
//! It is also the only correct answer available. `ring` has no RSA decryption, and the `rsa`
//! crate's advisory exemption in `deny.toml` rests on the written claim that it "NEVER DECRYPTS".
//! Reaching for it here would have made that sentence false in the exact operation the Marvin
//! advisory is about.
//!
//! # What is refused, and the attacks behind each refusal
//!
//! * RSA-1.5 key transport. Bleichenbacher, and it is still the default in a great deal of
//!   deployed SAML. The refusal happens where the URI is read, so a caller's unwrapper is never
//!   asked to perform it and cannot become the oracle.
//! * Every CBC data-encryption mode. Jager and Somorovsky (CCS 2011) recovered plaintext from a
//!   conforming XML Encryption implementation using the XML parser's own behaviour on the
//!   decrypted bytes as an oracle, and the backwards-compatibility defences fell to the
//!   follow-up work. `ring` offers no CBC, so this refusal is structural.
//! * A `RetrievalMethod` pointing anywhere. The key must be carried INSIDE the `EncryptedData`
//!   being decrypted; a reference is a request that this crate fetch something, and it fetches
//!   nothing.
//! * More than one `EncryptedData`, or more than one `EncryptedKey` within it, for the reason
//!   every other "exactly one" in this crate exists: two is a contradiction, and choosing is
//!   choosing which half to believe.

use crate::parse::{Limits, SamlError};
use crate::verify::{TrustAnchor, VerifiedAssertion, VerifyError, verify};

/// The XML Encryption namespaces. Two, because the GCM modes live in the 1.1 revision.
const XENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";

/// How the data key was wrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTransportAlg {
    /// RSA-OAEP with MGF1-SHA1 (`http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p`).
    ///
    /// ACCEPTED DESPITE THE SHA-1, and the reason is worth stating because the instinct is to
    /// refuse anything with SHA-1 in it. The weakness that retired SHA-1 is collision resistance,
    /// and OAEP's MGF1 depends on neither collision nor second-preimage resistance: it is a mask
    /// generator. Refusing this URI would refuse most deployed identity providers to no security
    /// benefit, which is the kind of refusal that gets fixed by turning encryption off.
    RsaOaepMgf1Sha1,
    /// RSA-OAEP with an explicit MGF (`http://www.w3.org/2009/xmlenc11#rsa-oaep`).
    RsaOaep,
}

/// The seam a caller fills to unwrap a data key.
///
/// # Why this is a trait and not a key
///
/// See the module documentation: the private key belongs where the deployment keeps it. An
/// implementation is expected to be a call into an HSM, a KMS, or whatever holds the service
/// provider's decryption key.
///
/// AN IMPLEMENTATION MUST NOT REPORT WHY IT FAILED. Returning distinguishable errors for "bad
/// padding" and "wrong key" rebuilds the Bleichenbacher oracle inside the caller, which is why
/// this returns an `Option` rather than a `Result`.
pub trait KeyTransport {
    /// Unwrap `wrapped` under this deployment's private key, or answer `None`.
    fn unwrap_key(&self, algorithm: KeyTransportAlg, wrapped: &[u8]) -> Option<Vec<u8>>;
}

/// Why an encrypted assertion was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
    /// The outer document did not survive the parser.
    Malformed(SamlError),
    /// The document does not carry exactly one encrypted assertion in the expected shape.
    Shape,
    /// A named algorithm is not on the allowlist.
    AlgorithmRefused,
    /// The key could not be unwrapped, or the ciphertext did not authenticate.
    ///
    /// ONE VARIANT FOR BOTH, on purpose. Separating them is the padding oracle.
    DecryptFailed,
    /// The decrypted assertion did not verify. See [`VerifyError`].
    ///
    /// A decrypted assertion is revalidated exactly like one that arrived in the clear, so every
    /// refusal the verifier can produce reaches a caller unchanged.
    Unverified(VerifyError),
}

impl core::fmt::Display for DecryptError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(inner) => write!(formatter, "{inner}"),
            Self::Shape => formatter.write_str("the document is not one encrypted assertion"),
            Self::AlgorithmRefused => {
                formatter.write_str("the document names an algorithm this server refuses")
            }
            Self::DecryptFailed => formatter.write_str("the assertion did not decrypt"),
            Self::Unverified(inner) => write!(formatter, "{inner}"),
        }
    }
}

impl core::error::Error for DecryptError {}

/// Decrypt the one `EncryptedAssertion` in `bytes`, then verify it against `anchors`.
///
/// The return value is a [`VerifiedAssertion`] and nothing weaker: there is no way to obtain the
/// decrypted document without its signature having been checked, which is the same rule the
/// clear-text path follows and the reason both paths end in the same type.
///
/// # Errors
///
/// [`DecryptError`]. No variant carries any part of the document, the ciphertext or a key.
pub fn decrypt_and_verify(
    bytes: &[u8],
    limits: &Limits,
    anchors: &[TrustAnchor],
    transport: &dyn KeyTransport,
) -> Result<VerifiedAssertion, DecryptError> {
    let root = crate::tree::build(bytes, limits).map_err(DecryptError::Malformed)?;

    // EXACTLY ONE EncryptedAssertion, and the EncryptedData is ITS OWN DIRECT CHILD.
    //
    // The containment is the half a first draft of this got wrong: it searched the whole document
    // for an `EncryptedData` and only counted the `EncryptedAssertion`, with a comment claiming
    // the containment it did not check. A document with one of each, where the ciphertext is a
    // SIBLING of the assertion rather than inside it, would then have been decrypted -- the same
    // "the element I found is not the element that matters" shape as XML Signature Wrapping,
    // arriving one layer down.
    let encrypted = crate::verify::collect(&root, &[], crate::ASSERTION_NS, "EncryptedAssertion");
    let [encrypted] = encrypted.as_slice() else {
        return Err(DecryptError::Shape);
    };
    let encrypted =
        crate::verify::Scoped::new(encrypted, crate::verify::scope_at(&root, encrypted));
    let mut children = encrypted.children(XENC_NS, "EncryptedData");
    let (Some(data), 1) = (children.pop(), children.len() + 1) else {
        return Err(DecryptError::Shape);
    };

    check_type(&data)?;
    let algorithm = data_algorithm(&data)?;
    let key = unwrap_data_key(&data, algorithm, transport)?;

    let plaintext = ironauth_jose::xmlenc::decrypt(algorithm, &key, &cipher_value(&data)?)
        .map_err(|_| DecryptError::DecryptFailed)?;

    // AND NOW IT IS JUST A DOCUMENT. The same parser, the same verifier, the same anchors, and
    // the same limits: nothing about having been encrypted buys the plaintext any trust.
    //
    // THE SAME LIMITS, and the amplification they stop is in the SHAPE rather than the size.
    // Base64 expands by four thirds, so a ciphertext that fit the outer `max_bytes` always
    // decrypts to something smaller -- a draft of this comment claimed the opposite and the test
    // written for it could not be made to pass. What DOES amplify is structure: a `Response`
    // wrapping an `EncryptedData` is about ten elements whatever the payload, so a plaintext with
    // hundreds of elements or nested hundreds deep arrives inside a document trivially within
    // every structural bound. `max_elements` and `max_depth` are the bounds an attacker steps
    // around by encrypting, which is why they are applied again here.
    verify(
        &plaintext,
        limits,
        anchors,
        crate::ASSERTION_NS,
        "Assertion",
    )
    .map_err(DecryptError::Unverified)
}

/// The `Type` must say ELEMENT, or say nothing.
///
/// # `#Content` is a different thing wearing the same shape
///
/// XML Encryption's `Type` distinguishes `#Element` -- the ciphertext is a whole element -- from
/// `#Content`, where it is the CHILDREN of an element without the element itself. This crate
/// parses the plaintext as a document, which is only correct for the first. A `#Content`
/// ciphertext decrypting to something that happens to look well formed would be read as a
/// document it is not.
///
/// ABSENT IS ACCEPTED, and that is not laxity: the attribute is optional in the schema and a
/// great deal of deployed SAML omits it. Refusing an absent `Type` would refuse conforming
/// documents, and what the plaintext turns out to be is then decided by the parser and the
/// verifier, which is where it should be decided anyway.
fn check_type(data: &crate::verify::Scoped<'_>) -> Result<(), DecryptError> {
    match data.attribute("Type") {
        None | Some("http://www.w3.org/2001/04/xmlenc#Element") => Ok(()),
        Some(_) => Err(DecryptError::Shape),
    }
}

/// The data-encryption algorithm the `EncryptedData` names.
///
/// GCM ONLY, and the CBC URIs are named in the refusal rather than falling through an unnamed
/// default, so a reader can see that they were considered and refused.
fn data_algorithm(
    data: &crate::verify::Scoped<'_>,
) -> Result<ironauth_jose::xmlenc::XmlEncAlg, DecryptError> {
    use ironauth_jose::xmlenc::XmlEncAlg;
    let method = data
        .child(XENC_NS, "EncryptionMethod")
        .ok_or(DecryptError::Shape)?;
    match method
        .attribute("Algorithm")
        .ok_or(DecryptError::AlgorithmRefused)?
    {
        "http://www.w3.org/2009/xmlenc11#aes128-gcm" => Ok(XmlEncAlg::Aes128Gcm),
        "http://www.w3.org/2009/xmlenc11#aes256-gcm" => Ok(XmlEncAlg::Aes256Gcm),
        _ => Err(DecryptError::AlgorithmRefused),
    }
}

/// Unwrap the data key carried inside this `EncryptedData`.
///
/// # The key must be HERE, not somewhere this crate would have to go and get
///
/// A `RetrievalMethod` is a URI, and honouring one would make an unauthenticated document able to
/// choose an outbound request. This crate performs no I/O, so a document that carries a reference
/// instead of a key is refused rather than followed.
///
/// # The unwrapped length is checked against the ALGORITHM
///
/// A caller's unwrapper answers with bytes. If those bytes are the wrong length for the named
/// algorithm the answer is a refusal, not a truncation or a pad: silently adjusting a key length
/// is how an implementation ends up decrypting under something neither party chose.
fn unwrap_data_key(
    data: &crate::verify::Scoped<'_>,
    algorithm: ironauth_jose::xmlenc::XmlEncAlg,
    transport: &dyn KeyTransport,
) -> Result<Vec<u8>, DecryptError> {
    let key_info = data
        .child("http://www.w3.org/2000/09/xmldsig#", "KeyInfo")
        .ok_or(DecryptError::Shape)?;
    if key_info
        .child("http://www.w3.org/2000/09/xmldsig#", "RetrievalMethod")
        .is_some()
    {
        return Err(DecryptError::Shape);
    }
    let encrypted_key = key_info
        .child(XENC_NS, "EncryptedKey")
        .ok_or(DecryptError::Shape)?;
    let method = encrypted_key
        .child(XENC_NS, "EncryptionMethod")
        .ok_or(DecryptError::Shape)?;
    let transport_algorithm = match method
        .attribute("Algorithm")
        .ok_or(DecryptError::AlgorithmRefused)?
    {
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" => KeyTransportAlg::RsaOaepMgf1Sha1,
        "http://www.w3.org/2009/xmlenc11#rsa-oaep" => KeyTransportAlg::RsaOaep,
        // `#rsa-1_5` lands here, and that is the Bleichenbacher refusal. It is refused BEFORE the
        // caller's unwrapper is asked, so the unwrapper cannot become the oracle.
        _ => return Err(DecryptError::AlgorithmRefused),
    };
    let wrapped = cipher_value(&encrypted_key)?;
    let key = transport
        .unwrap_key(transport_algorithm, &wrapped)
        .ok_or(DecryptError::DecryptFailed)?;
    // DEFENCE IN DEPTH, not the check. `xmlenc::decrypt` refuses a wrong-length key and so does
    // `ring` beneath it, so a mutation sweep removes this with the suite still green. It earns
    // its place by refusing BEFORE the ciphertext is touched at all, which keeps a caller's
    // unwrapper from being probed for the length of what it returned.
    //
    // What `a_data_key_of_the_wrong_length_is_refused` pins is the OUTCOME -- a key of the wrong
    // length never decrypts -- rather than this line. Saying which is which is the difference
    // between a comment and a claim.
    if key.len() != algorithm.key_bytes() {
        return Err(DecryptError::DecryptFailed);
    }
    Ok(key)
}

/// The decoded `CipherValue` of an `EncryptedData` or an `EncryptedKey`.
fn cipher_value(element: &crate::verify::Scoped<'_>) -> Result<Vec<u8>, DecryptError> {
    let data = element
        .child(XENC_NS, "CipherData")
        .ok_or(DecryptError::Shape)?;
    // NOT CipherReference, which is the same outbound-request refusal as RetrievalMethod.
    if data.child(XENC_NS, "CipherReference").is_some() {
        return Err(DecryptError::Shape);
    }
    let value = data
        .child(XENC_NS, "CipherValue")
        .ok_or(DecryptError::Shape)?;
    crate::verify::decode_base64(&value.text()).ok_or(DecryptError::Shape)
}
