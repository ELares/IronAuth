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
//! # Where a certificate becomes one of these keys
//!
//! An operator supplies a certificate, not a raw key, so something has to convert one.
//! [`crate::x509`] does, at the MANAGEMENT surface: it runs when a certificate is UPLOADED,
//! answers the key and the validity dates the store records, and is never reached by a response
//! arriving at the ACS endpoint. So the property this module depends on is unchanged -- no X.509
//! parsing sits between a signed assertion and the decision to trust it -- but the honest form
//! of the sentence is "not on this path", not "not in this crate".

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
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    signed: RichElement,
    /// What the ANCESTORS of the signed element declared.
    ///
    /// Kept because a prefix used inside the assertion is very often declared on the enclosing
    /// `Response`, which is outside the subtree: exclusive canonicalization resolves against
    /// every declaration in scope, and so must a reader. Without this, `text_of` could not tell
    /// `saml:NameID` in the SAML assertion namespace from an attacker's `saml:NameID` bound to
    /// something else.
    inherited: Vec<Binding>,
}

/// NOT DERIVED, AND THAT IS THE POINT.
///
/// [`VerifiedAssertion::attribute`] refuses namespace declarations because exclusive
/// canonicalization emits only the ones a subtree visibly USES: an unused `xmlns:evil="..."` on
/// the assertion is never digested, so a signature that covers the assertion does not cover it.
/// The derived `Debug` printed every attribute of the retained element, declarations included,
/// so `format!("{assertion:?}")` handed the same undigested attacker-controlled bytes straight
/// back to a caller who believes everything it can see was signed -- into a log line, an error
/// message, or a trace, which is exactly where they get read as trustworthy.
///
/// So the formatter shows what the type IS, not what it holds. A caller that wants a value asks
/// for one through an accessor that knows which values were covered.
impl core::fmt::Debug for VerifiedAssertion {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedAssertion")
            .field("name", &self.signed.name)
            .finish_non_exhaustive()
    }
}

impl VerifiedAssertion {
    /// The qualified name of the signed element.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.signed.name
    }

    /// Whether the signed element is `namespace`:`local`, RESOLVED rather than string-matched.
    ///
    /// [`Self::name`] hands back the QUALIFIED name, prefix and all, and a caller that tested it
    /// was testing a spelling. `name().ends_with("Assertion")` -- which is what the condition
    /// layer did -- is wrong on TWO axes at once, and each admits a different document:
    ///
    /// - THE LOCAL NAME. It answers true for `evil:NotAnAssertion`, because the suffix is a
    ///   suffix of that name too.
    /// - THE NAMESPACE. It never looks at one, so `evil:Assertion` bound to `urn:evil` answers
    ///   true as readily as the real thing.
    ///
    /// (It also answers TRUE, correctly, for the unprefixed `Assertion` an identity provider
    /// writes under a default `xmlns` -- so the suffix test is not simply "too strict". It is
    /// answering a different question from the one the caller meant.)
    ///
    /// This crate's own wrapping defence was once a rule about prefix spelling and it was a
    /// bypass; the same mistake one layer up is the same bypass.
    #[must_use]
    pub fn is(&self, namespace: &str, local: &str) -> bool {
        Scoped::new(&self.signed, self.inherited.clone()).is(namespace, local)
    }

    /// An attribute of the signed element.
    ///
    /// NOT A NAMESPACE DECLARATION. Canonicalization emits only the declarations a subtree
    /// VISIBLY USES, so an unused one is never digested -- and an earlier version returned it
    /// here anyway, which is undigested attacker-controlled data reaching a caller that believes
    /// everything it can see was signed.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        if name == "xmlns" || name.starts_with("xmlns:") {
            return None;
        }
        self.signed
            .attributes
            .iter()
            .find(|attribute| attribute.name == name)
            .map(|attribute| attribute.value.as_str())
    }

    /// How many DIRECT CHILDREN of the signed element are `namespace`:`local`.
    ///
    /// # Why a count, and why direct children
    ///
    /// [`Self::text_of`] answers `None` for zero matches AND for two or more, so it cannot be
    /// used to ask whether something is absent. A fuzz target tried, asserting that a verified
    /// assertion carries no `ds:SignatureValue`, and was silent on the document that carries TWO
    /// -- which is the smuggling shape it was written for.
    ///
    /// DIRECT children, because that is the question worth asking about a signature: the
    /// enveloped transform removed exactly the one `Signature` that was a child of this element,
    /// so a verified assertion has none. A `Signature` deeper inside may be perfectly
    /// legitimate: a `saml:Advice` carrying a signed assertion has one, and so does every
    /// assertion inside a Response that was itself signed.
    #[must_use]
    pub fn child_count(&self, namespace: &str, local: &str) -> usize {
        let scoped = Scoped::new(&self.signed, self.inherited.clone());
        scoped.children(namespace, local).len()
    }

    /// Every element in `namespace` with local name `local` anywhere under the signature, each
    /// as something a caller can read further values out of.
    ///
    /// # Why a caller needs the PARENT and not just the name
    ///
    /// [`Self::text_of`] searches every descendant, and for SAML that is the wrong question more often than it is the right one, because SAML reuses element names
    /// under different parents with DIFFERENT MEANINGS:
    ///
    /// - `saml:Audience` is a child of `AudienceRestriction` ("this assertion is addressed to
    ///   you") AND of `ProxyRestriction` ("somebody else may re-assert this to you"). A reader
    ///   that took either would accept an assertion addressed to nobody.
    /// - `saml:NameID` is the Subject's ("who this is") AND the `SubjectConfirmation`'s ("who may
    ///   present this"). A reader that took either could sign in the confirming party.
    ///
    /// So a caller resolves the PARENT it means, and reads within it. The scope travels with the
    /// element, which is what makes reading inside one safe: the same rule the internal
    /// scope-carrying type exists for.
    ///
    /// EVERY match is returned rather than the unique one, because "exactly one" is not always
    /// the rule: SAML permits several `AudienceRestriction` elements and requires the service
    /// provider to satisfy all of them.
    #[must_use]
    pub fn elements(&self, namespace: &str, local: &str) -> Vec<SignedElement<'_>> {
        collect_scoped(&self.signed, &self.inherited, namespace, local)
            .into_iter()
            .map(|scoped| SignedElement { scoped })
            .collect()
    }

    /// The DIRECT CHILDREN of the signed element that are `namespace`:`local`.
    ///
    /// # Why a caller almost always wants THIS rather than [`Self::elements`]
    ///
    /// SAML puts an assertion's own `Issuer`, `Subject`, `Conditions` and statements at the top
    /// level, and it ALSO permits whole nested assertions and arbitrary elements deeper down:
    /// `saml:Advice` carries advisory assertions, and `saml:AttributeValue` is `xs:anyType`, so
    /// an attribute's value may legitimately contain a `saml:Subject`, a `saml:Conditions` or a
    /// `saml:Issuer` of its own. Those are somebody else's, and they are inside the signature
    /// just as much as the real ones.
    ///
    /// A descendant search therefore finds elements that were never meant to answer the
    /// question. It is also not even ordered the way a reader expects: the walk uses a stack, so
    /// the first match returned is the LAST in document order.
    ///
    /// So the rule is: the values that decide who this is and whether it is valid are read as
    /// DIRECT CHILDREN, and "exactly one" is enforced by the caller on the result.
    #[must_use]
    pub fn children(&self, namespace: &str, local: &str) -> Vec<SignedElement<'_>> {
        Scoped::new(&self.signed, self.inherited.clone())
            .children(namespace, local)
            .into_iter()
            .map(|scoped| SignedElement { scoped })
            .collect()
    }

    /// The text of the descendant in `namespace` with local name `local`, if there is EXACTLY
    /// ONE.
    ///
    /// # An ambiguous read is no read
    ///
    /// An earlier version returned the first in document order and justified that by a duplicate
    /// refusal [`verify`] does not perform. It does not: two `NameID`s inside one signed
    /// assertion verify like any other document, and the caller was handed one of the two with
    /// nothing to say there had been a choice. Two readers picking differently is the whole
    /// defect class this crate is about, so ambiguity answers `None` and the caller decides what
    /// to do about it.
    #[must_use]
    pub fn text_of(&self, namespace: &str, local: &str) -> Option<String> {
        let found = collect(&self.signed, &self.inherited, namespace, local);
        match found.as_slice() {
            [single] => Some(text_content(single)),
            _ => None,
        }
    }
}

/// One element inside a verified signature, which a caller can read further values out of.
///
/// # Everything reachable from here was digested
///
/// Every constructor of this type -- [`VerifiedAssertion::elements`],
/// [`VerifiedAssertion::children`], and [`Self::children`] on an element already inside one --
/// walks only the subtree the signature covered, and each hands back another value of this same
/// type. So the guarantee is closed under reading further: a value read through this was signed,
/// and the namespace scope its ancestors put in force travels with it, so a qualified name
/// resolves the way the document meant.
///
/// NOT DERIVED for `Debug`, for the reason [`VerifiedAssertion`] gives: the derived one would
/// print every attribute of the retained element, namespace declarations included, and those are
/// exactly the bytes exclusive canonicalization does not digest.
#[derive(Clone)]
pub struct SignedElement<'a> {
    scoped: Scoped<'a>,
}

impl core::fmt::Debug for SignedElement<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SignedElement")
            .field("name", &self.scoped.element.name)
            .finish_non_exhaustive()
    }
}

impl<'a> SignedElement<'a> {
    /// An attribute of THIS element.
    ///
    /// NOT A NAMESPACE DECLARATION, for the reason [`VerifiedAssertion::attribute`] gives.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        if name == "xmlns" || name.starts_with("xmlns:") {
            return None;
        }
        self.scoped
            .element
            .attributes
            .iter()
            .find(|candidate| candidate.name == name)
            .map(|candidate| candidate.value.as_str())
    }

    /// The COLLAPSED text of every DIRECT CHILD in `namespace` with local name `local`, in
    /// document order.
    ///
    /// DIRECT children, which is the whole point of this type: a descendant search would find the
    /// same names under a different parent, which in SAML means something else.
    ///
    /// COLLAPSED for the reason [`Self::text_collapsed`] gives: the one list of direct-child text
    /// SAML asks a service provider to compare -- an `AudienceRestriction`'s `Audience` children
    /// -- is a list of `xsd:anyURI`, and comparing those raw refuses a pretty-printed document
    /// that says exactly the same thing.
    #[must_use]
    pub fn child_texts(&self, namespace: &str, local: &str) -> Vec<Option<String>> {
        self.scoped
            .children(namespace, local)
            .into_iter()
            .map(|scoped| SignedElement { scoped }.text_collapsed())
            .collect()
    }

    /// The text of this element.
    #[must_use]
    pub fn text(&self) -> String {
        text_content(self.scoped.element)
    }

    /// The RESOLVED `(namespace, local name)` of every direct child element, in document order.
    ///
    /// # For refusing what is not understood
    ///
    /// SAML Core 2.5 requires a service provider that cannot evaluate a `Condition` to treat the
    /// assertion as invalid, and a check written as an allowlist needs to see what is actually
    /// there.
    ///
    /// EACH NAME IS RESOLVED, NOT SPELLED. An earlier version answered LOCAL names only, on the
    /// reasoning that the caller had already resolved the parent -- which does not follow: the
    /// parent's namespace says nothing about its children's. An allowlist over local names
    /// admits `evil:OneTimeUse` bound to `urn:evil` as something this server understands, which
    /// is the identical bypass [`VerifiedAssertion::is`] exists to prevent one level up. The
    /// namespace is the empty string for a child in no namespace at all.
    #[must_use]
    pub fn element_children(&self) -> Vec<(String, String)> {
        let scope = self.scoped.scope();
        self.scoped
            .element
            .children
            .iter()
            .filter_map(|child| match child {
                RichNode::Element(nested) => {
                    let inner = scope_within(nested, &scope);
                    let namespace = resolve(&nested.name, &inner).unwrap_or_default();
                    Some((namespace, local_name(&nested.name).to_owned()))
                }
                RichNode::Text(_) | RichNode::ProcessingInstruction(_) => None,
            })
            .collect()
    }

    /// Every element child, with its RESOLVED name, as something to read further into.
    ///
    /// [`Self::element_children`] answers names alone, which is all an allowlist needs. A caller
    /// that has IDENTIFIED a child and wants what is inside it needs the child itself -- the
    /// SAML case being a `saml:NameID` inside an `AttributeValue`, where recognising it and then
    /// having no way to read the name it carries is recognising it for nothing.
    #[must_use]
    pub fn element_children_resolved(&self) -> Vec<(String, String, SignedElement<'a>)> {
        let scope = self.scoped.scope();
        self.scoped
            .element
            .children
            .iter()
            .filter_map(|child| match child {
                RichNode::Element(nested) => {
                    let inner = scope_within(nested, &scope);
                    let namespace = resolve(&nested.name, &inner).unwrap_or_default();
                    Some((
                        namespace,
                        local_name(&nested.name).to_owned(),
                        SignedElement {
                            scoped: Scoped::new(nested, scope.clone()),
                        },
                    ))
                }
                RichNode::Text(_) | RichNode::ProcessingInstruction(_) => None,
            })
            .collect()
    }

    /// This element's text, refused outright if it has ELEMENT CHILDREN.
    ///
    /// # Simple content cannot contain elements, and concatenating across them invents a value
    ///
    /// `saml:Audience` and `saml:Issuer` are `xsd:anyURI` and `saml:NameID` is `xsd:string`. All
    /// three are SIMPLE content: the schema forbids element children entirely. [`Self::text`]
    /// concatenates the text of every descendant, so
    ///
    /// ```xml
    /// <saml:Audience>https://sp.example<saml:Audience>/tenant</saml:Audience></saml:Audience>
    /// ```
    ///
    /// reads as `https://sp.example/tenant` here while a schema-validating reader rejects the
    /// document and a `firstChild.nodeValue` reader sees `https://sp.example`. Two readers
    /// picking differently is the defect class this crate exists for, and for the audience it is
    /// CVE-2026-9093 itself: the element's own text names one relying party and this crate reads
    /// another.
    ///
    /// So the answer is `None` rather than a spliced string, and every caller treats that as the
    /// refusal it is. This mirrors what the signature side already does with `has_element_child`
    /// inside `ds:Transform`.
    #[must_use]
    pub fn text_simple(&self) -> Option<String> {
        if self
            .scoped
            .element
            .children
            .iter()
            .any(|child| matches!(child, RichNode::Element(_)))
        {
            return None;
        }
        Some(self.text())
    }

    /// This element's text with XSD `whiteSpace="collapse"` applied, refused if it has ELEMENT
    /// CHILDREN for the reason [`Self::text_simple`] gives.
    ///
    /// # Why raw text is the wrong thing to compare for `saml:Audience` and `saml:Issuer`
    ///
    /// Both are `xsd:anyURI`, and XML Schema Part 2 gives `anyURI` the `collapse` whiteSpace
    /// facet: leading and trailing whitespace is stripped and internal runs become one space
    /// BEFORE any comparison, so
    ///
    /// ```xml
    /// <saml:Audience>
    ///   https://sp.example/metadata
    /// </saml:Audience>
    /// ```
    ///
    /// is the same value as the flush one, and an identity provider that pretty-prints its
    /// assertions is not sending a different audience. Comparing raw text refuses a conformant
    /// document -- and does it with "the assertion is addressed to a different service provider",
    /// which sends an operator looking for a misconfiguration that is not there.
    ///
    /// NOT FOR `saml:NameID`, whose content is `xsd:string` and preserves whitespace: collapsing
    /// there would map two distinct names onto one account.
    #[must_use]
    pub fn text_collapsed(&self) -> Option<String> {
        self.text_simple().as_deref().map(collapse)
    }

    /// The DIRECT CHILDREN in `namespace` with local name `local`, to read further into.
    #[must_use]
    pub fn children(&self, namespace: &str, local: &str) -> Vec<SignedElement<'a>> {
        self.scoped
            .children(namespace, local)
            .into_iter()
            .map(|scoped| SignedElement { scoped })
            .collect()
    }
}

/// [`collect`], keeping the scope each match was found under.
fn collect_scoped<'a>(
    root: &'a RichElement,
    inherited: &[Binding],
    namespace: &str,
    local: &str,
) -> Vec<Scoped<'a>> {
    let mut found = Vec::new();
    let mut pending = vec![Scoped::new(root, inherited.to_vec())];
    while let Some(scoped) = pending.pop() {
        if scoped.is(namespace, local) {
            found.push(scoped.clone());
        }
        let inner = scoped.scope();
        for child in &scoped.element.children {
            if let RichNode::Element(nested) = child {
                pending.push(Scoped::new(nested, inner.clone()));
            }
        }
    }
    found
}

/// Verify `bytes` against `anchors`, returning the element the signature covers.
///
/// `namespace` and `local` name the element a caller intends to read, and they are an ARGUMENT
/// rather than something inferred: a verifier that accepted whatever the document said it had
/// signed would accept a signature over a node nobody cares about and then be asked for values
/// from a node nobody signed.
///
/// # A NAMESPACE AND A LOCAL NAME, NOT A QUALIFIED NAME, AND THAT WAS A BYPASS
///
/// An earlier version took one string and compared it to `element.name` -- the raw, PREFIXED
/// name -- so the exactly-one-candidate rule, which is this crate's first wrapping defence, was
/// a rule about prefix SPELLING rather than about the document. A response holding the identity
/// provider's genuinely signed `<saml:Assertion ID="_assertion">` plus an attacker's unsigned
/// `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_forged">` was
/// reported as carrying exactly ONE assertion and verified, while the byte-identical document
/// spelling the second one `saml:` was refused. A prefix is not an identity, and two prefixes
/// bound to one URI name one thing.
///
/// It also made the crate unusable against the field: Okta emits `saml2:Assertion` and Entra
/// emits `Assertion` under a default `xmlns`, and neither could be named at all.
///
/// # Errors
///
/// [`VerifyError`]. No variant carries any part of the document.
pub fn verify(
    bytes: &[u8],
    limits: &Limits,
    anchors: &[TrustAnchor],
    namespace: &str,
    local: &str,
) -> Result<VerifiedAssertion, VerifyError> {
    let root = crate::tree::build(bytes, limits).map_err(VerifyError::Malformed)?;

    // EXACTLY ONE candidate, and exactly one signature on it. "More than one" is not a case to
    // pick a winner from: it is the shape every wrapping attack takes, so it is a refusal.
    let candidates = collect(&root, &[], namespace, local);
    let [signed] = candidates.as_slice() else {
        return Err(VerifyError::ReferenceRefused);
    };
    // THE SIGNATURE IS LOCATED BY INDEX, and its namespace is checked. Two things follow.
    //
    // The index is what lets the enveloped transform remove EXACTLY the element XMLDSIG-CORE
    // 6.6.4 says to remove -- the one `Signature` that carries this `Reference` -- rather than
    // every element whose local name happens to be `Signature`. An earlier version removed them
    // all, at any depth, in any namespace, so `<x:Signature xmlns:x="urn:evil">` buried anywhere
    // in the assertion was deleted before the digest and read after it.
    //
    // The namespace check is what makes `Signature` MEAN the signature. An earlier `collect_ns`
    // took a namespace argument and threw it away (`let _ = namespace;`), so an application
    // element that happened to be called `Signature` was one, and an attacker's element in any
    // namespace was one too.
    let scope = scope_at(&root, signed);
    let apex = Scoped::new(signed, scope);
    let signatures = apex.indexed_children(DSIG_NS, "Signature");
    let [(signature_index, signature)] = signatures.as_slice() else {
        return Err(VerifyError::SignatureMissing);
    };
    let signature_index = *signature_index;

    let signed_info = signature
        .child(DSIG_NS, "SignedInfo")
        .ok_or(VerifyError::SignatureMissing)?;
    check_canonicalization(&signed_info)?;
    let algorithm = signature_algorithm(&signed_info)?;
    // ONE Reference, and the COUNT is checked before anything reads one. A `SignedInfo` with two
    // says two different things are signed, and choosing one is choosing which half of a
    // contradiction to believe.
    //
    // The order matters and an earlier version had it backwards: it took the single child first,
    // which answers `None` for two references, so the request was refused as "no signature" and
    // this check was unreachable. A test written for the two-reference case is what found it --
    // the guard was dead, and the wrong word reached the caller.
    let references = signed_info.children(DSIG_NS, "Reference");
    let [reference] = references.as_slice() else {
        return Err(VerifyError::ReferenceRefused);
    };
    check_transforms(reference)?;

    // THE REFERENCE MUST NAME THE ELEMENT THE CALLER WILL READ. A same-document reference is
    // `#id`, and the id must be the one on the candidate.
    //
    // THE `#` IS NOT DECORATION. Without it the URI is a RELATIVE reference, which XMLDSIG-CORE
    // 4.4.3.1 makes an EXTERNAL one: a conforming verifier dereferences it and digests whatever
    // comes back. This crate does no dereferencing at all, so accepting `URI="_assertion"` would
    // digest the local element while claiming to have checked a reference to somewhere else. An
    // empty URI (the whole document) is refused for the mirror reason: this crate returns a
    // subtree, so "the whole document" would be a signature over something other than what it
    // hands back.
    let uri = reference
        .attribute("URI")
        .ok_or(VerifyError::ReferenceRefused)?;
    let named = uri.strip_prefix('#').ok_or(VerifyError::ReferenceRefused)?;
    let id = signed_identifier(signed).ok_or(VerifyError::ReferenceRefused)?;
    if named != id {
        return Err(VerifyError::ReferenceRefused);
    }
    // AND NOTHING ELSE IN THE DOCUMENT MAY CLAIM IT THROUGH AN `ID`. Duplicated identifiers are
    // the wrapping class that needs no schema trick at all: two elements answer to one reference
    // and the verifier and the consumer pick differently. The other element does NOT have to be
    // a second candidate -- a `samlp:Response` carrying the same `ID` as the assertion it wraps
    // is one element of each kind, so the exactly-one-candidate rule above never sees it.
    //
    // `ID` and not also `xml:id`: see `count_identifier` for what that leaves uncovered and why
    // it is a divergence rather than a hole.
    if count_identifier(&root, named) != 1 {
        return Err(VerifyError::ReferenceRefused);
    }

    // THE DIGEST, over the signed element with THIS signature removed. That removal is the
    // enveloped-signature transform.
    //
    // # The subtree that is digested is the subtree that is returned
    //
    // An earlier version digested a stripped COPY and handed the caller the ORIGINAL, with a
    // comment calling that the safe direction: "the subtree returned to the caller keeps
    // everything it had". It is the bug, and three independent reviews forged an assertion
    // through it. Everything inside the `Signature` is deleted before the digest and was still
    // readable afterwards, so appending one `<ds:Object>` carrying a forged
    // `<saml:Subject><saml:NameID>` to the identity provider's OWN signature left the digest and
    // the signature untouched while `text_of` -- which walks depth first, and meets the
    // signature before the subject, the order SAML's schema mandates -- returned the attacker's
    // value. Authenticate as anyone, which is the class this crate exists to close.
    //
    // So the digested subtree is what is moved into `VerifiedAssertion`. "Verify the node you
    // consume" is only true if they are the same value, and now they are one.
    let mut digested: RichElement = (*signed).clone();
    strip_enveloped_signature(&mut digested, signature_index);
    let digest_algorithm = digest_algorithm(reference)?;
    // THE ANCESTORS' DECLARATIONS TRAVEL WITH THE SUBTREE. Exclusive canonicalization resolves a
    // prefix against every declaration in scope, including the ones on ancestors OUTSIDE what is
    // signed -- an identity provider that declares `xmlns:saml` on the `Response` and uses it on
    // the `Assertion` is the ordinary case, not an exotic one.
    let computed = xml_digest(
        digest_algorithm,
        &canonicalize(&digested, &apex.inherited)
            .map_err(|_| VerifyError::Malformed(SamlError::Malformed))?,
    );
    let declared = reference
        .child(DSIG_NS, "DigestValue")
        .map(|value| value.text())
        .ok_or(VerifyError::SignatureMissing)?;
    let declared = decode_base64(&declared).ok_or(VerifyError::SignatureInvalid)?;
    if !constant_time_eq(&computed, &declared) {
        return Err(VerifyError::SignatureInvalid);
    }

    // AND THE SIGNATURE, over the canonical SignedInfo. Note the order: the digest of the
    // element is checked first and the signature over SignedInfo second, and BOTH must pass.
    // Checking only the second is the Keycloak CVE-2024-8698 shape.
    let signature_value = signature
        .child(DSIG_NS, "SignatureValue")
        .map(|value| value.text())
        .ok_or(VerifyError::SignatureMissing)?;
    let signature_bytes = decode_base64(&signature_value).ok_or(VerifyError::SignatureInvalid)?;
    let message = canonicalize(signed_info.element, &signed_info.inherited)
        .map_err(|_| VerifyError::Malformed(SamlError::Malformed))?;
    if !anchors
        .iter()
        .any(|anchor| verify_xml_signature(algorithm, anchor, &message, &signature_bytes))
    {
        return Err(VerifyError::SignatureInvalid);
    }

    Ok(VerifiedAssertion {
        signed: digested,
        inherited: apex.inherited,
    })
}

/// Map the `SignatureMethod` URI onto the allowlist.
///
/// SHA-1 IS ABSENT AND THAT IS THE POINT. `rsa-sha1` is still the default in a great deal of
/// deployed SAML, and it is the algorithm the collision work retired. A verifier that accepted
/// it "for compatibility" would be the weakest link in every deployment that has one.
fn signature_algorithm(signed_info: &Scoped<'_>) -> Result<XmlSigAlg, VerifyError> {
    let method = signed_info
        .child(DSIG_NS, "SignatureMethod")
        .ok_or(VerifyError::SignatureMissing)?;
    match method
        .attribute("Algorithm")
        .ok_or(VerifyError::AlgorithmRefused)?
    {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Ok(XmlSigAlg::RsaSha256),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Ok(XmlSigAlg::RsaSha384),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Ok(XmlSigAlg::RsaSha512),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => Ok(XmlSigAlg::EcdsaP256Sha256),
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => Ok(XmlSigAlg::EcdsaP384Sha384),
        _ => Err(VerifyError::AlgorithmRefused),
    }
}

/// Map the `DigestMethod` URI onto the allowlist.
fn digest_algorithm(reference: &Scoped<'_>) -> Result<XmlDigestAlg, VerifyError> {
    let method = reference
        .child(DSIG_NS, "DigestMethod")
        .ok_or(VerifyError::SignatureMissing)?;
    match method
        .attribute("Algorithm")
        .ok_or(VerifyError::AlgorithmRefused)?
    {
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
fn check_canonicalization(signed_info: &Scoped<'_>) -> Result<(), VerifyError> {
    let method = signed_info
        .child(DSIG_NS, "CanonicalizationMethod")
        .ok_or(VerifyError::SignatureMissing)?;
    if method.attribute("Algorithm") != Some(EXCLUSIVE_C14N) {
        return Err(VerifyError::AlgorithmRefused);
    }
    // A PREFIX LIST IS A REFUSAL, NOT AN OMISSION. `InclusiveNamespaces` changes which
    // declarations are emitted, so ignoring one computes a different digest from the signer.
    //
    // ELEMENT children, not any children: an earlier version refused whitespace, so a
    // pretty-printed `<ds:CanonicalizationMethod ...>\n</ds:CanonicalizationMethod>` was reported
    // as naming an algorithm this server refuses.
    if has_element_child(method.element) {
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
fn check_transforms(reference: &Scoped<'_>) -> Result<(), VerifyError> {
    let transforms = reference
        .child(DSIG_NS, "Transforms")
        .ok_or(VerifyError::AlgorithmRefused)?;
    // EVERY ELEMENT CHILD, then the ones that are really `ds:Transform`, and the two lists must
    // be the same length. Reading only the `ds:Transform` children would let an attacker park an
    // extra transform in another namespace between them: the allowlist below would not see it,
    // and a conforming verifier -- which applies every child of `Transforms` in order -- would.
    let element_children = transforms
        .element
        .children
        .iter()
        .filter(|child| matches!(child, RichNode::Element(_)))
        .count();
    let transform_children = transforms.children(DSIG_NS, "Transform");
    if transform_children.len() != element_children {
        return Err(VerifyError::AlgorithmRefused);
    }
    // EVERY transform must CARRY an Algorithm, and `filter_map` was the wrong combinator: it
    // silently DROPPED a `<ds:Transform/>` with no `Algorithm`, and a `<ds:Transform
    // ds:Algorithm="..."/>` whose attribute is prefixed. Both are counted on both sides of the
    // check above, so a three-transform list compared equal to the two-element allowlist and a
    // document with an undeclared transform in the middle verified. `Algorithm` is
    // `use="required"` in the XMLDSIG schema, so every other implementation refuses that
    // document -- the same accept-more asymmetry the count check was added for, moved from a
    // foreign namespace into the XMLDSIG one.
    let listed: Option<Vec<&str>> = transform_children
        .iter()
        .map(|transform| transform.attribute("Algorithm"))
        .collect();
    let listed = listed.ok_or(VerifyError::AlgorithmRefused)?;
    if listed != [ENVELOPED, EXCLUSIVE_C14N] {
        return Err(VerifyError::AlgorithmRefused);
    }
    // And no `Transform` may carry parameters, for the reason the canonicalization one may not.
    for transform in &transform_children {
        if has_element_child(transform.element) {
            return Err(VerifyError::AlgorithmRefused);
        }
    }
    Ok(())
}

/// Every namespace declaration in scope at `target`, gathered from `root` down to it.
///
/// Returns the declarations of the ANCESTORS, not of the target itself: the canonicalizer adds
/// the element's own when it writes it. Walking rather than storing a parent pointer keeps the
/// tree acyclic and costs one traversal per verification, which is two.
pub(crate) fn scope_at(root: &RichElement, target: &RichElement) -> Vec<Binding> {
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

/// Whether `element` has any ELEMENT child, ignoring whitespace and comments.
fn has_element_child(element: &RichElement) -> bool {
    element
        .children
        .iter()
        .any(|child| matches!(child, RichNode::Element(_)))
}

/// Remove EXACTLY ONE child of `element`: the signature at `index`.
///
/// # This is the enveloped-signature transform, and it removes one element
///
/// XMLDSIG-CORE 6.6.4 removes the `Signature` element that CONTAINS the `Transform` being
/// applied -- one element, identified by ancestry. An earlier version removed every element
/// whose LOCAL name was `Signature`, at any depth, in any namespace, which is a different
/// operation with two costs: an application element legitimately called `Signature` was silently
/// dropped from the digest, and an attacker's `<x:Signature xmlns:x="urn:evil">` anywhere in the
/// assertion was deleted before the digest and readable after it.
fn strip_enveloped_signature(element: &mut RichElement, index: usize) {
    if index < element.children.len() {
        element.children.remove(index);
    }
}

/// An element together with the namespace scope its ANCESTORS put in force.
///
/// # Why the scope travels WITH the element instead of beside it
///
/// A qualified name means nothing without the declarations in force where it is written, so
/// every lookup under the signature needs two things: the element to look in, and that
/// element's scope. An earlier version passed them as two arguments, and the second one was
/// wrong three times out of eight.
///
/// The scope of the `Signature` was threaded all the way down to the `Reference`'s children,
/// which are two levels deeper, so `SignedInfo`'s own declarations were skipped. It cost both
/// directions at once. A conforming signature that declares `xmlns:ds` on `ds:SignedInfo`
/// rather than on `ds:Signature` -- byte-identical canonical `SignedInfo`, same key, same
/// digest -- was refused as `AlgorithmRefused`, which tells an operator to go loosen an
/// algorithm allowlist that was never the problem. And in the other direction, rebinding a
/// prefix on `SignedInfo` to `urn:evil` left `<e:Transforms>`, `<e:DigestMethod>` and
/// `<e:DigestValue>` outside XMLDSIG entirely while this crate still read the transform list
/// and the digest algorithm out of them.
///
/// So the level is no longer something a call site can get wrong: the only way to look inside
/// an element is to ask the [`Scoped`] that FOUND it, and it computes the child scope itself.
#[derive(Clone)]
pub(crate) struct Scoped<'a> {
    pub(crate) element: &'a RichElement,
    /// What the ancestors declared. NOT this element's own declarations: those belong to its
    /// children's scope, and to the resolution of its own name.
    pub(crate) inherited: Vec<Binding>,
}

impl<'a> Scoped<'a> {
    /// The apex, with whatever its ancestors declared.
    pub(crate) fn new(element: &'a RichElement, inherited: Vec<Binding>) -> Self {
        Self { element, inherited }
    }

    /// The scope in force INSIDE this element: what it inherited, plus its own declarations.
    ///
    /// This is also the scope its own NAME resolves against, because a signer that writes
    /// `xmlns:ds` on the `ds:Signature` element itself is the ordinary case, not an exotic one.
    pub(crate) fn scope(&self) -> Vec<Binding> {
        scope_within(self.element, &self.inherited)
    }

    /// Whether this element is `namespace`:`local`, resolved rather than string-matched.
    ///
    /// The local name alone is not an element's identity. An earlier version compared only
    /// that, so an application element called `Signature`, and an attacker's element in any
    /// namespace at all, both answered to the name.
    pub(crate) fn is(&self, namespace: &str, local: &str) -> bool {
        local_name(&self.element.name) == local
            && resolve(&self.element.name, &self.scope()).as_deref() == Some(namespace)
    }

    /// Every DIRECT child that is `namespace`:`local`, with its index among ALL children.
    ///
    /// Direct rather than descendant, and that is a wrapping defence: a `SignedInfo` nested
    /// three levels down inside an attacker's element is not this signature's `SignedInfo`.
    ///
    /// The index is what the enveloped-signature transform removes by, so it must be the index
    /// in `children`, not in the filtered result.
    pub(crate) fn indexed_children(
        &self,
        namespace: &str,
        local: &str,
    ) -> Vec<(usize, Scoped<'a>)> {
        let inherited = self.scope();
        self.element
            .children
            .iter()
            .enumerate()
            .filter_map(|(index, child)| match child {
                RichNode::Element(nested) => {
                    let scoped = Scoped::new(nested, inherited.clone());
                    scoped.is(namespace, local).then_some((index, scoped))
                }
                _ => None,
            })
            .collect()
    }

    /// Every DIRECT child that is `namespace`:`local`.
    pub(crate) fn children(&self, namespace: &str, local: &str) -> Vec<Scoped<'a>> {
        self.indexed_children(namespace, local)
            .into_iter()
            .map(|(_, scoped)| scoped)
            .collect()
    }

    /// The single direct child that is `namespace`:`local`, if there is EXACTLY ONE.
    ///
    /// Two is not one. A `Signature` with two `SignatureValue` children says two different
    /// things, and picking either is picking which half of a contradiction to believe.
    pub(crate) fn child(&self, namespace: &str, local: &str) -> Option<Scoped<'a>> {
        let mut found = self.children(namespace, local);
        match found.len() {
            1 => found.pop(),
            _ => None,
        }
    }

    /// An attribute of this element by qualified name.
    pub(crate) fn attribute(&self, name: &str) -> Option<&'a str> {
        attribute(self.element, name)
    }

    /// All the text under this element, concatenated.
    pub(crate) fn text(&self) -> String {
        text_content(self.element)
    }
}

/// The namespace scope inside `element`: what it inherited, plus its own declarations.
fn scope_within(element: &RichElement, inherited: &[Binding]) -> Vec<Binding> {
    let mut scope = inherited.to_vec();
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
    scope
}

/// The namespace a qualified name resolves to, if any.
fn resolve(name: &str, scope: &[Binding]) -> Option<String> {
    let prefix = name.split_once(':').map_or("", |(prefix, _)| prefix);
    scope
        .iter()
        .find(|binding| binding.prefix == prefix)
        .map(|binding| binding.uri.clone())
        .filter(|uri| !uri.is_empty())
}

/// XSD `whiteSpace="collapse"`, over the four characters the specification names.
///
/// NOT `str::split_whitespace`, which splits on the whole Unicode whitespace property -- so a
/// NO-BREAK SPACE or an IDEOGRAPHIC SPACE inside a URI would be collapsed away and two values
/// XSD says are DIFFERENT would compare equal. XML Schema Part 2 names exactly `#x9`, `#xA`,
/// `#xD` and `#x20`, and everything else, whitespace-looking or not, is a character of the value.
fn collapse(text: &str) -> String {
    text.split(['\t', '\n', '\r', ' '])
        .filter(|piece| !piece.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The first descendant with this qualified name.
///
/// ONLY THE TEST CANONICALIZER USES THIS, which is why it is behind the feature: every reader
/// on the verification path resolves a namespace and a local name, and this one matches a
/// QUALIFIED name -- a spelling. `cargo build` without the feature warned it was dead, and
/// deleting it broke the feature build, which is the shape a `#[cfg]` says out loud.
#[cfg(feature = "test-util")]
fn find<'a>(element: &'a RichElement, name: &str) -> Option<&'a RichElement> {
    if element.name == name {
        return Some(element);
    }
    element.children.iter().find_map(|child| match child {
        RichNode::Element(nested) => find(nested, name),
        RichNode::Text(_) | RichNode::ProcessingInstruction(_) => None,
    })
}

/// Every descendant (and the root itself) whose qualified name matches.
pub(crate) fn collect<'a>(
    root: &'a RichElement,
    inherited: &[Binding],
    namespace: &str,
    local: &str,
) -> Vec<&'a RichElement> {
    let mut found = Vec::new();
    let mut pending = vec![Scoped::new(root, inherited.to_vec())];
    while let Some(scoped) = pending.pop() {
        if scoped.is(namespace, local) {
            found.push(scoped.element);
        }
        let inner = scoped.scope();
        for child in &scoped.element.children {
            if let RichNode::Element(nested) = child {
                pending.push(Scoped::new(nested, inner.clone()));
            }
        }
    }
    found
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

/// How many elements in the document claim `id` through an UNPREFIXED `ID` attribute.
///
/// # What this does not count, and why the call site says so
///
/// `xml:id` is also an ID-typed attribute by the W3C `xml:id` recommendation, and libxml2 --
/// the engine under `xmlsec` and most deployed SAML stacks -- resolves a same-document reference
/// through it. This counts only `ID`, which is what SAML assertions carry.
///
/// A document where an `xml:id` twin shadows the assertion's `ID` therefore passes this count.
/// It is not a bypass HERE, because the caller receives the subtree this crate DIGESTED and no
/// second lookup happens; it is a divergence from what another implementation would resolve, so
/// the call site claims only what this function checks.
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
pub(crate) fn decode_base64(text: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    let mut out = Vec::new();
    for byte in text.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            // AND NOTHING BUT PADDING AND WHITESPACE MAY FOLLOW. An earlier version broke out of
            // the loop here and never looked at the rest, so `<value>==QUJD` decoded to the same
            // bytes as `<value>==`. `SignatureValue` sits outside `SignedInfo`, so no digest and
            // no signature covers it: one captured response could be minted into unboundedly
            // many byte-distinct documents that all verify. That is the same "a second encoding
            // of the same signature" this crate refuses ECDSA DER for.
            return text
                .bytes()
                .skip_while(|candidate| *candidate != b'=')
                .all(|candidate| candidate == b'=' || candidate.is_ascii_whitespace())
                .then_some(out);
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
