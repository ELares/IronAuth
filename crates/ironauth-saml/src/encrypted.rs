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
//! * A `RetrievalMethod` naming somewhere ELSE. The SAML schema allows the `EncryptedKey` to be
//!   a SIBLING of the `EncryptedData`, referenced by a same-document fragment, and that is what
//!   `OpenSAML` and Shibboleth emit -- so a fragment is accepted and must name the key actually
//!   used. Anything that is not a fragment is a request this crate will not make.
//!
//!   An earlier version refused every `RetrievalMethod` on the ground that "a reference is a
//!   request that this crate fetch something". True of an absolute URI, false of `#_ek`, and the
//!   refusal was therefore turning away conforming documents from the commonest implementation
//!   in the field.
//! * More than one `EncryptedData`, or more than one `EncryptedKey` within it, for the reason
//!   every other "exactly one" in this crate exists: two is a contradiction, and choosing is
//!   choosing which half to believe.

use crate::parse::{Limits, SamlError};
use crate::verify::{TrustAnchor, VerifiedAssertion, VerifyError, verify};

/// The XML Encryption namespace.
const XENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";

/// The XML Encryption 1.1 namespace, which is where `MGF` lives.
const XENC11_NS: &str = "http://www.w3.org/2009/xmlenc11#";

/// The XMLDSIG namespace, which is where `KeyInfo` and `RetrievalMethod` live.
const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

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

/// The OAEP hash and mask generation the `EncryptedKey` names.
///
/// # Why the seam is told, rather than left to guess
///
/// XML Encryption 1.1 section 5.5.2 parameterises RSA-OAEP with three CHILD elements of
/// `EncryptionMethod`: `ds:DigestMethod` (the OAEP hash), `xenc11:MGF` (the mask generation
/// function), and `xenc:OAEPparams` (the RFC 3447 label). The specification's own worked example
/// carries SHA-256 and MGF1-SHA256.
///
/// A first version read only the `Algorithm` attribute and discarded all three, so a conforming
/// SHA-256 document and one using the SHA-1 defaults arrived at the caller's unwrapper looking
/// identical. An unwrapper cannot decrypt without knowing which, so it would have had to guess,
/// and a guess that is wrong is indistinguishable from a wrong key -- which is the failure mode
/// this crate spends the most effort making impossible to distinguish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OaepParameters {
    /// The OAEP hash. SHA-1 when the document names none, which is the specification's default.
    ///
    /// NOT FIXED BY `#rsa-oaep-mgf1p`, and an earlier version of this very sentence said it was.
    /// XML Encryption 1.0 section 5.4.2 fixes only the mask generation function under that URI
    /// and leaves the digest an explicit parameter, so `#rsa-oaep-mgf1p` with a SHA-256
    /// `DigestMethod` is conforming and this crate accepts it.
    ///
    /// AN IMPLEMENTOR WHO BELIEVES THE OLD SENTENCE hard-codes SHA-1 whenever the algorithm is
    /// `RsaOaepMgf1Sha1` and unwraps under the wrong hash for every such document -- failing
    /// indistinguishably from a wrong key, which is the exact outcome these parameters exist to
    /// prevent. This is the only rustdoc a seam implementor sees for this field, so the
    /// correction lives here and not only beside the code.
    pub digest: OaepDigest,
    /// The mask generation function. MGF1-SHA1 when the document names none.
    pub mgf: OaepMgf,
    /// The `OAEPparams` label, if the document carries one. Decoded, never the base64.
    pub label: Option<Vec<u8>>,
}

/// An OAEP hash this crate will name to a seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OaepDigest {
    /// SHA-1, the specification's default when a document names no digest.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// A mask generation function this crate will name to a seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OaepMgf {
    /// MGF1 with SHA-1, the default.
    Mgf1Sha1,
    /// MGF1 with SHA-256.
    Mgf1Sha256,
    /// MGF1 with SHA-384.
    Mgf1Sha384,
    /// MGF1 with SHA-512.
    Mgf1Sha512,
}

/// The seam a caller fills to unwrap a data key.
///
/// # Why this is a trait and not a key
///
/// The private key belongs where the deployment keeps it, which in production is an HSM or a KMS.
/// This crate parses the `EncryptedKey`, enforces the allowlist and hands over the wrapped bytes.
///
/// It is also the only correct answer available: `ring` has no RSA decryption, and the `rsa`
/// crate's advisory exemption in `deny.toml` rests on the written claim that it "NEVER DECRYPTS",
/// which calling its decrypt here would have made false in the exact operation the Marvin
/// advisory is about.
///
/// AN IMPLEMENTATION MUST NOT REPORT WHY IT FAILED. Returning distinguishable errors for "bad
/// padding" and "wrong key" rebuilds the Bleichenbacher oracle inside the caller, which is why
/// this returns an `Option` rather than a `Result`.
pub trait KeyTransport {
    /// Unwrap `wrapped` under this deployment's private key, or answer `None`.
    ///
    /// `parameters` carries the OAEP hash, mask generation function and label the document named,
    /// with the specification's defaults filled in. An implementation that ignores them decrypts
    /// under the wrong parameters for every identity provider that does not use the SHA-1
    /// defaults.
    fn unwrap_key(
        &self,
        algorithm: KeyTransportAlg,
        parameters: &OaepParameters,
        wrapped: &[u8],
    ) -> Option<Vec<u8>>;
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

    // EXACTLY ONE EncryptedAssertion, AND NO CLEARTEXT ONE BESIDE IT.
    //
    // The second half was missing and it is a wrapping shape. Encryption uses the service
    // provider's PUBLIC key, published in its own metadata, so anyone can mint an
    // EncryptedAssertion. A Response carrying the identity provider's genuinely signed cleartext
    // assertion PLUS an attacker's encrypted one was accepted here, and `decrypt_and_verify`
    // returned the encrypted subject while `verify` on the same bytes returned the cleartext one.
    // Two entry points, one document, two different identities: the exact disagreement this crate
    // exists to make impossible.
    let encrypted = crate::verify::collect(&root, &[], crate::ASSERTION_NS, "EncryptedAssertion");
    let [encrypted] = encrypted.as_slice() else {
        return Err(DecryptError::Shape);
    };
    if !crate::verify::collect(&root, &[], crate::ASSERTION_NS, "Assertion").is_empty() {
        return Err(DecryptError::Shape);
    }
    let encrypted =
        crate::verify::Scoped::new(encrypted, crate::verify::scope_at(&root, encrypted));

    // The EncryptedData is the EncryptedAssertion's OWN direct child. A first draft searched the
    // whole document while counting only the assertion, with a comment claiming a containment it
    // did not check, so a ciphertext SIBLING of the assertion was decrypted.
    let data = exactly_one(encrypted.children(XENC_NS, "EncryptedData"))?;

    // EVERYTHING THE DOCUMENT DECIDES IS DECIDED BEFORE THE SEAM IS ASKED. That ordering is the
    // whole of the oracle defence and an earlier version got it wrong: `cipher_value(&data)` was
    // evaluated as an argument to the decrypt call, i.e. AFTER the unwrapper had run. So a
    // document with a deliberately malformed CipherData answered `Shape` when the unwrap
    // succeeded and `DecryptFailed` when it did not, and an unauthenticated party varying only
    // the EncryptedKey read one bit per request: did the private-key unwrap work. That is
    // Bleichenbacher's bit, handed over by the error taxonomy that exists to withhold it.
    check_type(&data)?;
    let algorithm = data_algorithm(&data)?;
    let wrapped = wrapped_key(&encrypted, &data)?;
    let ciphertext = cipher_value(&data)?;

    // ONLY NOW. Everything from here answers `DecryptFailed` whatever went wrong.
    let key = transport
        .unwrap_key(wrapped.algorithm, &wrapped.parameters, &wrapped.bytes)
        .ok_or(DecryptError::DecryptFailed)?;
    // DEFENCE IN DEPTH, not the check. `xmlenc::decrypt` refuses a wrong-length key and so does
    // `ring` beneath it, so a mutation sweep removes this with the suite still green.
    //
    // It earns its place by making the refusal not depend on what the backend happens to do, and
    // by keeping the error one word. An earlier version of this comment also claimed it stopped
    // a caller's unwrapper being PROBED for the length of what it returned -- it does not: the
    // seam has already run by the time this line is reached, and what actually withholds that bit
    // is that every path from here answers `DecryptFailed`.
    if key.len() != algorithm.key_bytes() {
        return Err(DecryptError::DecryptFailed);
    }
    let plaintext = ironauth_jose::xmlenc::decrypt(algorithm, &key, &ciphertext)
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
    // THE PLAINTEXT MUST BE AN ASSERTION, NOT MERELY CONTAIN ONE.
    //
    // `verify` searches by DESCENDANT, so a ciphertext decrypting to a whole `samlp:Response`
    // wrapping an assertion was accepted and returned the assertion inside it. The SAML schema
    // makes an `EncryptedAssertion`'s plaintext an `Assertion`, and OpenSAML refuses anything
    // else; accepting a wrapper is an accept-more divergence of exactly the kind `check_type`
    // refuses `#Content` to avoid. Without this, that refusal rests on a containment nothing
    // checks.
    let decrypted = crate::tree::build(&plaintext, limits)
        .map_err(|error| DecryptError::Unverified(VerifyError::Malformed(error)))?;
    if !crate::verify::Scoped::new(&decrypted, Vec::new()).is(crate::ASSERTION_NS, "Assertion") {
        return Err(DecryptError::Shape);
    }

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
        // EVERYTHING ELSE, and the CBC URIs are the ones that matter:
        // `xmlenc#aes128-cbc`, `#aes192-cbc`, `#aes256-cbc` and `#tripledes-cbc`. They are not
        // named in a match arm because there is nothing to say to them that the default does not,
        // and an earlier version of this doc claimed they were listed here when they were not.
        // `ring` offers no CBC at all, so the refusal is structural rather than a rule to keep.
        //
        // AES-192-GCM is also refused, and that IS a narrowing of a conforming algorithm: `ring`
        // has no 192-bit AES. Refusing is the honest answer; pretending would be worse.
        _ => Err(DecryptError::AlgorithmRefused),
    }
}

/// Exactly one, or a shape refusal.
///
/// # Why this is a helper rather than `Scoped::child`
///
/// `Scoped::child` answers `None` for zero matches AND for two or more, and two of the guards
/// here were written as `child(..).is_some()`. That reads as "is it present" and means "is there
/// exactly one", so a document carrying the element TWICE slipped past a refusal written to
/// reject it once -- inverting this crate's own doctrine that two is a contradiction.
fn exactly_one(
    mut found: Vec<crate::verify::Scoped<'_>>,
) -> Result<crate::verify::Scoped<'_>, DecryptError> {
    match found.len() {
        1 => found.pop().ok_or(DecryptError::Shape),
        _ => Err(DecryptError::Shape),
    }
}

/// At most one, refusing two. `None` means the document carried none.
///
/// # Why `Scoped::child` is wrong wherever ABSENT has a meaning
///
/// `child` answers `None` for zero matches AND for two or more. Where `None` means "use the
/// specification's default" that is not a shrug, it is a DOWNGRADE: writing an OAEP
/// `DigestMethod` twice made the crate tell the caller SHA-1 for a document that named SHA-512,
/// and slipped past the contradiction guard beside it. Duplication selected a weaker parameter
/// set, which is worse than the refusal-evasion this crate had already fixed once.
fn at_most_one(
    mut found: Vec<crate::verify::Scoped<'_>>,
) -> Result<Option<crate::verify::Scoped<'_>>, DecryptError> {
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => Err(DecryptError::Shape),
    }
}

/// Refuse if `element` carries ANY child that is `namespace`:`local`.
///
/// Counting rather than asking for exactly one: the guards below are refusals, so "there are two"
/// must refuse as loudly as "there is one".
fn refuse_any(
    element: &crate::verify::Scoped<'_>,
    namespace: &str,
    local: &str,
) -> Result<(), DecryptError> {
    if element.children(namespace, local).is_empty() {
        Ok(())
    } else {
        Err(DecryptError::Shape)
    }
}

/// The wrapped data key, with the parameters the document named.
struct WrappedKey {
    algorithm: KeyTransportAlg,
    parameters: OaepParameters,
    bytes: Vec<u8>,
}

/// Find the `EncryptedKey` and read everything the seam will need from it.
///
/// # BOTH placements the SAML schema allows
///
/// `saml-schema-assertion-2.0.xsd` defines `EncryptedElementType` as an `EncryptedData` followed
/// by zero or more `EncryptedKey` SIBLINGS. So the key is legally either inside the
/// `EncryptedData`'s `ds:KeyInfo`, or a sibling of the `EncryptedData` inside the
/// `EncryptedAssertion` -- and the second is what `OpenSAML` and Shibboleth emit, pointed at by a
/// `ds:RetrievalMethod` whose URI is a same-document fragment.
///
/// A first version accepted only the first placement and refused a `RetrievalMethod` outright,
/// on the stated ground that "a `RetrievalMethod` is a URI, and honouring one would make an
/// unauthenticated document able to choose an outbound request". That is true of an ABSOLUTE URI
/// and false of `#_ek`, which resolves inside the tree already parsed and drives no request. The
/// refusal is now on what it was always about: a reference this crate would have to FETCH.
fn wrapped_key(
    encrypted: &crate::verify::Scoped<'_>,
    data: &crate::verify::Scoped<'_>,
) -> Result<WrappedKey, DecryptError> {
    // AT MOST ONE KeyInfo, and two is a refusal rather than a shrug. Before the round-1 fix this
    // was `child(..).ok_or(Shape)?`, which refused two; the fix relaxed it to
    // `.map(..).unwrap_or_default()` so a missing KeyInfo would fall through to the sibling
    // placement -- and `child` still answers `None` for TWO. So two KeyInfo children produced an
    // EMPTY nested list instead of a refusal: a document holding three EncryptedKey elements was
    // accepted, and because the same `child` call gates the loop below, the absolute-URI refusal
    // was skipped entirely. That refusal is the arm that keeps the sibling placement honest.
    let key_info = at_most_one(data.children(DSIG_NS, "KeyInfo"))?;
    let inside = key_info
        .as_ref()
        .map(|info| info.children(XENC_NS, "EncryptedKey"))
        .unwrap_or_default();
    let beside = encrypted.children(XENC_NS, "EncryptedKey");

    // ONE KEY, wherever it sits. Two is the contradiction, and one in each place is two.
    let mut found = inside;
    found.extend(beside);
    let key = exactly_one(found)?;

    // A RETRIEVAL METHOD MAY NOT NAME SOMEWHERE ELSE. A same-document fragment is fine and is
    // what the sibling placement uses; anything else is a request this crate will not make.
    if let Some(info) = key_info.as_ref() {
        for method in info.children(DSIG_NS, "RetrievalMethod") {
            let uri = method.attribute("URI").ok_or(DecryptError::Shape)?;
            let Some(fragment) = uri.strip_prefix('#') else {
                return Err(DecryptError::Shape);
            };
            // AND IT MUST NAME THE KEY THAT IS USED. Checking only the leading `#` made the
            // reference decorative: a document could point at `#somewhere_else` and be decrypted
            // under whichever key happened to be found. A reference that names nothing is a
            // reference to nothing.
            if key.attribute("Id") != Some(fragment) {
                return Err(DecryptError::Shape);
            }
        }
    }

    let method = exactly_one(key.children(XENC_NS, "EncryptionMethod"))?;
    let algorithm = match method
        .attribute("Algorithm")
        .ok_or(DecryptError::AlgorithmRefused)?
    {
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" => KeyTransportAlg::RsaOaepMgf1Sha1,
        "http://www.w3.org/2009/xmlenc11#rsa-oaep" => KeyTransportAlg::RsaOaep,
        // `#rsa-1_5` lands here, and that is the Bleichenbacher refusal. It happens BEFORE the
        // caller's unwrapper is asked, so the unwrapper cannot become the oracle.
        _ => return Err(DecryptError::AlgorithmRefused),
    };

    Ok(WrappedKey {
        algorithm,
        parameters: oaep_parameters(&method, algorithm)?,
        bytes: cipher_value(&key)?,
    })
}

/// The OAEP hash, mask generation and label the `EncryptionMethod` names.
///
/// Absent means the specification's default, which is SHA-1 for both.
///
/// `#rsa-oaep-mgf1p` fixes the MASK GENERATION FUNCTION only (XML Encryption 1.0 section 5.4.2:
/// it "is always MGF1 with SHA1"), and leaves the digest an explicit parameter. So that URI with
/// a SHA-256 `DigestMethod` is conforming and common; what it may NOT carry is an explicit
/// `xenc11:MGF`, because the URI already decided that.
fn oaep_parameters(
    method: &crate::verify::Scoped<'_>,
    algorithm: KeyTransportAlg,
) -> Result<OaepParameters, DecryptError> {
    let digest = match at_most_one(method.children(DSIG_NS, "DigestMethod"))? {
        None => OaepDigest::Sha1,
        Some(named) => match named
            .attribute("Algorithm")
            .ok_or(DecryptError::AlgorithmRefused)?
        {
            "http://www.w3.org/2000/09/xmldsig#sha1" => OaepDigest::Sha1,
            "http://www.w3.org/2001/04/xmlenc#sha256" => OaepDigest::Sha256,
            // BOTH SHA-384 URIs, and the reason is that this is a different context from a
            // signature's `DigestMethod`. XML Encryption 1.1 section 5.8.3 assigns
            // `xmlenc#sha384` for use "within RSA-OAEP encryption as a hash function", and the
            // three entries around this one are all XML Encryption identifiers. RFC 4051 2.1.3
            // assigns `xmldsig-more#sha384` for the XMLDSIG registry, and implementations emit
            // it here too because that is where SHA-384 lives for signatures.
            //
            // Accepting only the XMLDSIG one refused the identifier the encryption specification
            // actually assigns. `verify.rs` refuses `xmlenc#sha384` for a SIGNATURE reference on
            // RFC 4051's authority, and that remains right: same spelling, different registry,
            // different question.
            "http://www.w3.org/2001/04/xmldsig-more#sha384"
            | "http://www.w3.org/2001/04/xmlenc#sha384" => OaepDigest::Sha384,
            "http://www.w3.org/2001/04/xmlenc#sha512" => OaepDigest::Sha512,
            _ => return Err(DecryptError::AlgorithmRefused),
        },
    };
    let mgf_named = at_most_one(method.children(XENC11_NS, "MGF"))?;
    let mgf = match &mgf_named {
        None => OaepMgf::Mgf1Sha1,
        Some(named) => match named
            .attribute("Algorithm")
            .ok_or(DecryptError::AlgorithmRefused)?
        {
            "http://www.w3.org/2009/xmlenc11#mgf1sha1" => OaepMgf::Mgf1Sha1,
            "http://www.w3.org/2009/xmlenc11#mgf1sha256" => OaepMgf::Mgf1Sha256,
            "http://www.w3.org/2009/xmlenc11#mgf1sha384" => OaepMgf::Mgf1Sha384,
            "http://www.w3.org/2009/xmlenc11#mgf1sha512" => OaepMgf::Mgf1Sha512,
            _ => return Err(DecryptError::AlgorithmRefused),
        },
    };
    // `#rsa-oaep-mgf1p` FIXES THE MASK GENERATION AND NOTHING ELSE, and an earlier version had
    // this backwards on both halves.
    //
    // XML Encryption 1.0 section 5.4.2, which DEFINES the URI, says the mask generation function
    // "is always MGF1 with SHA1" and makes the digest an explicit parameter: "a mandatory message
    // digest function ... indicated by the Algorithm attribute of a child ds:DigestMethod
    // element". So mgf1p with a SHA-256 digest is ONE algorithm, not a contradiction, and it is
    // what `xmlsec` and OpenSAML emit when configured with a SHA-256 OAEP digest on the 1.0 URI.
    // A reviewer found it in crewjam/saml's own corpus.
    //
    // The previous rule refused exactly that -- a correct-sounding reason applied to documents it
    // did not describe, which is the same defect as round 1's headline finding, reintroduced one
    // element down by the fix for it. What IS wrong under this URI is a PRESENT `xenc11:MGF`,
    // because the URI already fixed it, and that is what is refused now.
    if algorithm == KeyTransportAlg::RsaOaepMgf1Sha1 && mgf_named.is_some() {
        return Err(DecryptError::AlgorithmRefused);
    }
    let label = match at_most_one(method.children(XENC_NS, "OAEPparams"))? {
        None => None,
        Some(params) => {
            Some(crate::verify::decode_base64(&params.text()).ok_or(DecryptError::Shape)?)
        }
    };
    Ok(OaepParameters { digest, mgf, label })
}

/// The decoded `CipherValue` of an `EncryptedData` or an `EncryptedKey`.
fn cipher_value(element: &crate::verify::Scoped<'_>) -> Result<Vec<u8>, DecryptError> {
    let data = exactly_one(element.children(XENC_NS, "CipherData"))?;
    // NOT A CipherReference, which unlike a RetrievalMethod is always somewhere ELSE: XML
    // Encryption defines it as a reference to cipher data OUTSIDE the document, so honouring one
    // is a request this crate will not make.
    //
    // COUNTED, not `child(..).is_some()`. That reads as "is it present" and means "is there
    // exactly one", so a document carrying the element TWICE walked straight past a refusal
    // written to reject it once.
    refuse_any(&data, XENC_NS, "CipherReference")?;
    let value = exactly_one(data.children(XENC_NS, "CipherValue"))?;
    crate::verify::decode_base64(&value.text()).ok_or(DecryptError::Shape)
}
