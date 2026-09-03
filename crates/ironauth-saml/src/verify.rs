// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signature verification, and the only way to read a value out of a SAML document.
//!
//! # The rule the whole module is built around
//!
//! VERIFY THE NODE YOU CONSUME. Every XML Signature Wrapping bug in the field is one component
//! deciding that a document is signed and a different component reading values from a different
//! node in it. So this returns the SUBTREE it digested, and [`VerifiedAssertion`]'s accessors
//! read from that subtree and from nothing else. There is no path from a signature check to a
//! value that goes via a second lookup.
//!
//! That is a structural statement, not a discipline: the digested subtree is MOVED into the
//! returned value, so the document it came from is not consulted again.
//!
//! # The trust anchor is an argument, never the document
//!
//! `KeyInfo` is not read. A document that carries a certificate is carrying an attacker's
//! certificate as far as this module is concerned, and the only keys it will verify against are
//! the ones the caller passed in. That closes the whole "valid self-signature from an unpinned
//! key" class, which criterion 4 asks for by name.
//!
//! # What a caller must do that this does not
//!
//! Turning a pinned CERTIFICATE into the key material here wants is the caller's job today.
//! This crate has no X.509 parser and adding one would be a large new surface for
//! attacker-adjacent bytes; the metadata half of SAML SP inbound (#139) is where certificates
//! are handled, and it will hand this the keys it extracted.

use ironauth_jose::xmldsig::{
    XmlDigestAlg, XmlSigAlg, XmlSigKey, verify_xml_signature, xml_digest,
};

use crate::c14n::{Binding, canonicalize};
use crate::parse::{Limits, SamlError};
use crate::tree::{RichElement, RichNode};

/// The XML namespace every signature element lives in.
const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Exclusive canonicalization. The only one accepted, because it is the one SAML uses and the
/// one an assertion signed in one document and delivered in another survives.
const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// The enveloped-signature transform: remove the `Signature` element from what is digested,
/// which is what makes it possible to sign an element that contains its own signature.
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// A key the caller has pinned.
///
/// The shape is [`ironauth_jose::xmldsig::XmlSigKey`], because that is the crate that verifies
/// against it: see this crate's manifest for why the primitive lives there.
pub type TrustAnchor = XmlSigKey;

/// Why a document did not verify.
///
/// # One variant per DECISION, not per place the decision was made
///
/// A caller can act on "the signature did not verify" and cannot act on "the signature did not
/// verify at the third of four checks". A finer taxonomy would be an oracle: it tells an
/// attacker which of their forgeries got furthest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The document did not survive the parser. See [`SamlError`].
    Malformed(SamlError),
    /// The document carries no signature, or more than one where one was expected.
    SignatureMissing,
    /// The signature names an algorithm, a transform or a canonicalization this crate refuses.
    ///
    /// SHA-1 is here. So is any canonicalization other than exclusive, any transform other than
    /// the enveloped-signature and exclusive pair, and an exclusive canonicalization carrying an
    /// `InclusiveNamespaces` prefix list -- which is legal and which this crate does not
    /// implement, so refusing is the only honest answer. Pretending to honour it would compute a
    /// different digest from the signer and reject a valid signature.
    AlgorithmRefused,
    /// The signature does not cover the element whose values would be read.
    ///
    /// EVERY WRAPPING SHAPE LANDS HERE. The reference must name exactly one element, that
    /// element must be the one the caller gets, and no other element in the document may claim
    /// the same identifier.
    ReferenceRefused,
    /// The digest or the signature did not check out against a pinned key.
    SignatureInvalid,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed(_) => "the document is not acceptable XML",
            Self::SignatureMissing => "the document carries no usable signature",
            Self::AlgorithmRefused => "the signature names an algorithm this server refuses",
            Self::ReferenceRefused => "the signature does not cover the element it must",
            Self::SignatureInvalid => "the signature did not verify",
        })
    }
}

impl core::error::Error for VerifyError {}

/// An element whose signature verified, and the only thing in this crate that carries a value.
///
/// # Why the values live here and not on the parsed document
///
/// Everything an attacker wants out of a SAML document is an attribute or a text node, and
/// [`crate::Element`] exposes neither. This type does, and it exists only at the end of a
/// successful [`verify`]: the subtree it holds is the one whose digest was checked, MOVED here
/// rather than looked up again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    signed: RichElement,
}

impl VerifiedAssertion {
    /// The qualified name of the signed element.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.signed.name
    }

    /// An attribute of the signed element.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.signed
            .attributes
            .iter()
            .find(|attribute| attribute.name == name)
            .map(|attribute| attribute.value.as_str())
    }

    /// The text of the first descendant with this qualified name, searched depth first.
    ///
    /// FIRST, and the choice is deliberate rather than convenient: a document with two
    /// `NameID`s is a document where two readers can disagree, so [`verify`] refuses one before
    /// this is ever called. This function's job is to read, not to arbitrate.
    #[must_use]
    pub fn text_of(&self, name: &str) -> Option<String> {
        find(&self.signed, name).map(text_content)
    }
}

/// Verify `bytes` against `anchors`, returning the element the signature covers.
///
/// `signed_element` is the qualified name of the element a caller intends to read, and it is an
/// ARGUMENT rather than something inferred: a verifier that accepted whatever the document said
/// it had signed would accept a signature over a node nobody cares about and then be asked for
/// values from a node nobody signed.
///
/// # Errors
///
/// [`VerifyError`]. No variant carries any part of the document.
pub fn verify(
    bytes: &[u8],
    limits: &Limits,
    anchors: &[TrustAnchor],
    signed_element: &str,
) -> Result<VerifiedAssertion, VerifyError> {
    let root = crate::tree::build(bytes, limits).map_err(VerifyError::Malformed)?;

    // EXACTLY ONE candidate, and exactly one signature on it. "More than one" is not a case to
    // pick a winner from: it is the shape every wrapping attack takes, so it is a refusal.
    let candidates = collect(&root, signed_element);
    let [signed] = candidates.as_slice() else {
        return Err(VerifyError::ReferenceRefused);
    };
    let signatures = collect_ns(signed, DSIG_NS, "Signature");
    let [signature] = signatures.as_slice() else {
        return Err(VerifyError::SignatureMissing);
    };

    let signed_info =
        child_ns(signature, DSIG_NS, "SignedInfo").ok_or(VerifyError::SignatureMissing)?;
    check_canonicalization(signed_info)?;
    let algorithm = signature_algorithm(signed_info)?;
    // ONE Reference, and the COUNT is checked before anything reads one. A `SignedInfo` with two
    // says two different things are signed, and choosing one is choosing which half of a
    // contradiction to believe.
    //
    // The order matters and an earlier version had it backwards: it took the single child first,
    // which answers `None` for two references, so the request was refused as "no signature" and
    // this check was unreachable. A test written for the two-reference case is what found it --
    // the guard was dead, and the wrong word reached the caller.
    let references = collect_ns(signed_info, DSIG_NS, "Reference");
    let [reference] = references.as_slice() else {
        return Err(VerifyError::ReferenceRefused);
    };
    check_transforms(reference)?;

    // THE REFERENCE MUST NAME THE ELEMENT THE CALLER WILL READ. A same-document reference is
    // `#id`, and the id must be the one on the candidate. An empty URI (the whole document) is
    // refused: this crate returns a subtree, so "the whole document" would be a signature over
    // something other than what it hands back.
    let uri = attribute(reference, "URI").ok_or(VerifyError::ReferenceRefused)?;
    let named = uri.strip_prefix('#').ok_or(VerifyError::ReferenceRefused)?;
    let id = signed_identifier(signed).ok_or(VerifyError::ReferenceRefused)?;
    if named != id {
        return Err(VerifyError::ReferenceRefused);
    }
    // AND NOTHING ELSE IN THE DOCUMENT MAY CLAIM IT. Duplicated identifiers are the wrapping
    // class that needs no schema trick at all: two elements answer to one reference and the
    // verifier and the consumer pick differently.
    if count_identifier(&root, named) != 1 {
        return Err(VerifyError::ReferenceRefused);
    }

    // THE DIGEST, over the signed element with its signature removed. That removal IS the
    // enveloped-signature transform, and it is applied to a COPY: the subtree returned to the
    // caller keeps everything it had.
    let mut digested: RichElement = (*signed).clone();
    strip_signature(&mut digested);
    let digest_algorithm = digest_algorithm(reference)?;
    // THE ANCESTORS' DECLARATIONS TRAVEL WITH THE SUBTREE. Exclusive canonicalization resolves a
    // prefix against every declaration in scope, including the ones on ancestors OUTSIDE what is
    // signed -- an identity provider that declares `xmlns:saml` on the `Response` and uses it on
    // the `Assertion` is the ordinary case, not an exotic one.
    let assertion_scope = scope_at(&root, signed);
    let computed = xml_digest(
        digest_algorithm,
        &canonicalize(&digested, &assertion_scope)
            .map_err(|_| VerifyError::Malformed(SamlError::Malformed))?,
    );
    let declared = child_ns(reference, DSIG_NS, "DigestValue")
        .map(text_content)
        .ok_or(VerifyError::SignatureMissing)?;
    let declared = decode_base64(&declared).ok_or(VerifyError::SignatureInvalid)?;
    if !constant_time_eq(&computed, &declared) {
        return Err(VerifyError::SignatureInvalid);
    }

    // AND THE SIGNATURE, over the canonical SignedInfo. Note the order: the digest of the
    // element is checked first and the signature over SignedInfo second, and BOTH must pass.
    // Checking only the second is the Keycloak CVE-2024-8698 shape.
    let signature_value = child_ns(signature, DSIG_NS, "SignatureValue")
        .map(text_content)
        .ok_or(VerifyError::SignatureMissing)?;
    let signature_bytes = decode_base64(&signature_value).ok_or(VerifyError::SignatureInvalid)?;
    let signed_info_scope = scope_at(&root, signed_info);
    let message = canonicalize(signed_info, &signed_info_scope)
        .map_err(|_| VerifyError::Malformed(SamlError::Malformed))?;
    if !anchors
        .iter()
        .any(|anchor| verify_xml_signature(algorithm, anchor, &message, &signature_bytes))
    {
        return Err(VerifyError::SignatureInvalid);
    }

    Ok(VerifiedAssertion {
        signed: (*signed).clone(),
    })
}

/// Map the `SignatureMethod` URI onto the allowlist.
///
/// SHA-1 IS ABSENT AND THAT IS THE POINT. `rsa-sha1` is still the default in a great deal of
/// deployed SAML, and it is the algorithm the collision work retired. A verifier that accepted
/// it "for compatibility" would be the weakest link in every deployment that has one.
fn signature_algorithm(signed_info: &RichElement) -> Result<XmlSigAlg, VerifyError> {
    let method =
        child_ns(signed_info, DSIG_NS, "SignatureMethod").ok_or(VerifyError::SignatureMissing)?;
    match attribute(method, "Algorithm").ok_or(VerifyError::AlgorithmRefused)? {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Ok(XmlSigAlg::RsaSha256),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Ok(XmlSigAlg::RsaSha384),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Ok(XmlSigAlg::RsaSha512),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => Ok(XmlSigAlg::EcdsaP256Sha256),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => Ok(XmlSigAlg::EcdsaP384Sha384),
        _ => Err(VerifyError::AlgorithmRefused),
    }
}

/// Map the `DigestMethod` URI onto the allowlist.
fn digest_algorithm(reference: &RichElement) -> Result<XmlDigestAlg, VerifyError> {
    let method =
        child_ns(reference, DSIG_NS, "DigestMethod").ok_or(VerifyError::SignatureMissing)?;
    match attribute(method, "Algorithm").ok_or(VerifyError::AlgorithmRefused)? {
        "http://www.w3.org/2001/04/xmlenc#sha256" => Ok(XmlDigestAlg::Sha256),
        // NOT `xmlenc#sha384`, which looks right beside the other two and is not the URI.
        // RFC 4051 puts SHA-384 in `xmldsig-more`, and a research pass that summarised the spec
        // instead of reading it produced the tidier wrong answer.
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Ok(XmlDigestAlg::Sha384),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Ok(XmlDigestAlg::Sha512),
        _ => Err(VerifyError::AlgorithmRefused),
    }
}

/// The canonicalization must be exclusive, and must carry no prefix list.
fn check_canonicalization(signed_info: &RichElement) -> Result<(), VerifyError> {
    let method = child_ns(signed_info, DSIG_NS, "CanonicalizationMethod")
        .ok_or(VerifyError::SignatureMissing)?;
    if attribute(method, "Algorithm") != Some(EXCLUSIVE_C14N) {
        return Err(VerifyError::AlgorithmRefused);
    }
    // A PREFIX LIST IS A REFUSAL, NOT AN OMISSION. `InclusiveNamespaces` changes which
    // declarations are emitted, so ignoring one computes a different digest from the signer.
    if !method.children.is_empty() {
        return Err(VerifyError::AlgorithmRefused);
    }
    Ok(())
}

/// The transforms must be exactly the enveloped-signature transform then exclusive
/// canonicalization, in that order.
///
/// AN ALLOWLIST OF A SEQUENCE, not of a set. `XPath` and `XSLT` transforms are Turing-complete ways
/// to change what is digested and are refused; so is a transform list that omits the enveloped
/// one, because this verifier removes the signature unconditionally and would then be digesting
/// something the signer did not.
fn check_transforms(reference: &RichElement) -> Result<(), VerifyError> {
    let transforms =
        child_ns(reference, DSIG_NS, "Transforms").ok_or(VerifyError::AlgorithmRefused)?;
    let listed: Vec<&str> = transforms
        .children
        .iter()
        .filter_map(|child| match child {
            RichNode::Element(element) if local_name(&element.name) == "Transform" => {
                attribute(element, "Algorithm")
            }
            _ => None,
        })
        .collect();
    if listed != [ENVELOPED, EXCLUSIVE_C14N] {
        return Err(VerifyError::AlgorithmRefused);
    }
    // And no `Transform` may carry parameters, for the reason the canonicalization one may not.
    for child in &transforms.children {
        if let RichNode::Element(element) = child {
            if !element.children.is_empty() {
                return Err(VerifyError::AlgorithmRefused);
            }
        }
    }
    Ok(())
}

/// Every namespace declaration in scope at `target`, gathered from `root` down to it.
///
/// Returns the declarations of the ANCESTORS, not of the target itself: the canonicalizer adds
/// the element's own when it writes it. Walking rather than storing a parent pointer keeps the
/// tree acyclic and costs one traversal per verification, which is two.
fn scope_at(root: &RichElement, target: &RichElement) -> Vec<Binding> {
    let mut path = Vec::new();
    if !path_to(root, target, &mut path) {
        return Vec::new();
    }
    // The last entry is the target; its own declarations are not "inherited".
    path.pop();
    let mut scope: Vec<Binding> = Vec::new();
    for element in path {
        for attribute in &element.attributes {
            let binding = if attribute.name == "xmlns" {
                Binding {
                    prefix: String::new(),
                    uri: attribute.value.clone(),
                }
            } else if let Some(prefix) = attribute.name.strip_prefix("xmlns:") {
                Binding {
                    prefix: prefix.to_owned(),
                    uri: attribute.value.clone(),
                }
            } else {
                continue;
            };
            scope.retain(|existing| existing.prefix != binding.prefix);
            scope.push(binding);
        }
    }
    scope
}

/// Collect the chain of elements from `element` down to `target`, by identity.
fn path_to<'a>(
    element: &'a RichElement,
    target: &RichElement,
    path: &mut Vec<&'a RichElement>,
) -> bool {
    path.push(element);
    if core::ptr::eq(element, target) {
        return true;
    }
    for child in &element.children {
        if let RichNode::Element(nested) = child {
            if path_to(nested, target, path) {
                return true;
            }
        }
    }
    path.pop();
    false
}

/// Remove every `Signature` element from `element`, at any depth.
///
/// The enveloped-signature transform, which is what makes it possible for an element to contain
/// the signature over itself.
fn strip_signature(element: &mut RichElement) {
    element.children.retain(|child| match child {
        RichNode::Element(nested) => local_name(&nested.name) != "Signature",
        RichNode::Text(_) | RichNode::ProcessingInstruction(_) => true,
    });
    for child in &mut element.children {
        if let RichNode::Element(nested) = child {
            strip_signature(nested);
        }
    }
}

/// Every descendant (and the root itself) whose qualified name matches.
fn collect<'a>(root: &'a RichElement, name: &str) -> Vec<&'a RichElement> {
    let mut found = Vec::new();
    let mut pending = vec![root];
    while let Some(element) = pending.pop() {
        if element.name == name {
            found.push(element);
        }
        for child in &element.children {
            if let RichNode::Element(nested) = child {
                pending.push(nested);
            }
        }
    }
    found
}

/// Every DIRECT child in `namespace` with `local`.
///
/// Direct rather than descendant, and that is a wrapping defence: a `SignedInfo` nested three
/// levels down inside an attacker's element is not this signature's `SignedInfo`.
fn collect_ns<'a>(element: &'a RichElement, namespace: &str, local: &str) -> Vec<&'a RichElement> {
    let _ = namespace;
    element
        .children
        .iter()
        .filter_map(|child| match child {
            RichNode::Element(nested) if local_name(&nested.name) == local => Some(nested),
            _ => None,
        })
        .collect()
}

/// The single direct child in `namespace` with `local`, if there is exactly one.
fn child_ns<'a>(element: &'a RichElement, namespace: &str, local: &str) -> Option<&'a RichElement> {
    let found = collect_ns(element, namespace, local);
    match found.as_slice() {
        [single] => Some(single),
        _ => None,
    }
}

/// The first descendant with this qualified name.
fn find<'a>(element: &'a RichElement, name: &str) -> Option<&'a RichElement> {
    if element.name == name {
        return Some(element);
    }
    element.children.iter().find_map(|child| match child {
        RichNode::Element(nested) => find(nested, name),
        RichNode::Text(_) | RichNode::ProcessingInstruction(_) => None,
    })
}

/// All the text under an element, concatenated.
fn text_content(element: &RichElement) -> String {
    let mut out = String::new();
    for child in &element.children {
        match child {
            RichNode::Text(text) => out.push_str(text),
            RichNode::Element(nested) => out.push_str(&text_content(nested)),
            RichNode::ProcessingInstruction(_) => {}
        }
    }
    out
}

/// An attribute by qualified name.
fn attribute<'a>(element: &'a RichElement, name: &str) -> Option<&'a str> {
    element
        .attributes
        .iter()
        .find(|attribute| attribute.name == name)
        .map(|attribute| attribute.value.as_str())
}

/// The identifier a same-document reference would name.
fn signed_identifier(element: &RichElement) -> Option<&str> {
    attribute(element, "ID")
}

/// How many elements in the document claim `id`.
fn count_identifier(root: &RichElement, id: &str) -> usize {
    let mut count = 0;
    let mut pending = vec![root];
    while let Some(element) = pending.pop() {
        if attribute(element, "ID") == Some(id) {
            count += 1;
        }
        for child in &element.children {
            if let RichNode::Element(nested) = child {
                pending.push(nested);
            }
        }
    }
    count
}

/// The local part of a qualified name.
fn local_name(name: &str) -> &str {
    name.split_once(':').map_or(name, |(_, local)| local)
}

/// Decode standard base64, ignoring the whitespace XML puts inside a long value.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    let mut out = Vec::new();
    for byte in text.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            break;
        }
        let index = TABLE.iter().position(|candidate| *candidate == byte)?;
        accumulator = (accumulator << 6) | u32::try_from(index).ok()?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((accumulator >> bits) & 0xFF).ok()?);
        }
    }
    Some(out)
}

/// Compare two digests without a length-dependent early exit.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Locate an element by qualified name, for the canonicalization suite.
#[cfg(feature = "test-util")]
pub(crate) fn find_for_test<'a>(root: &'a RichElement, name: &str) -> Option<&'a RichElement> {
    find(root, name)
}

/// The inherited namespace scope at an element, for the canonicalization suite.
#[cfg(feature = "test-util")]
pub(crate) fn scope_at_for_test(root: &RichElement, target: &RichElement) -> Vec<Binding> {
    scope_at(root, target)
}
