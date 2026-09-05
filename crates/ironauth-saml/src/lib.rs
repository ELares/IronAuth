// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hostile-input SAML harness (issue #138): the only path by which SAML XML may enter
//! IronAuth.
//!
//! # Why this crate exists before any SAML feature does
//!
//! Every broad identity provider bleeds on SAML parsing, and the bleeding is always the same
//! shape: the document is parsed by one component, signed-ness is decided by a second, and the
//! values are read by a third, and the three disagree about which bytes they were talking
//! about. That is XML Signature Wrapping, and it is an authenticate-as-anyone bug every time.
//! Kanidm's answer is to refuse SAML outright.
//!
//! IronAuth's answer is that SAML is a hostile-input parser problem, so the parser comes first
//! and the feature comes later. This crate is the named precondition for SAML SP inbound
//! (#139), which is itself a precondition for the self-service portal (#140).
//!
//! # The library evaluation, and what was rejected
//!
//! ONE library handles XML, and it is [`quick_xml`]. The alternatives were read rather than
//! recalled, because a written evaluation that is wrong about what it rejected is worse than
//! none: it justifies a security-critical dependency for the life of the feature.
//!
//! * **`libxml2` / `xmlsec1` bindings** (`libxml`, `xmlsec`). What most of the field uses, and
//!   the reason most of the field has SAML CVEs. A large C surface with a long history of
//!   parser memory-safety issues, a build-time system dependency, and DTD and external-entity
//!   processing that is on unless correctly switched off. Rejected on memory safety first: a
//!   parser for attacker-controlled bytes is where a C dependency costs most.
//! * **`xml-rs`.** Pure Rust, long-lived, and better defended than an earlier draft of this
//!   paragraph gave it credit for: its config block is headed "Limits to defend from billion
//!   laughs attack" and ships `max_entity_expansion_length`, `max_entity_expansion_depth`,
//!   `max_name_length`, `max_attributes`, `max_attribute_length` and `max_data_length`, all on
//!   by default. That draft said entity-expansion bounds "become this crate's problem" under it;
//!   the opposite is true. Two of those six are bounds this crate had to add for itself
//!   (`max_name_length` and `max_attributes`); it still has no per-value or per-text bound, and
//!   bounds those only in aggregate through [`Limits::max_bytes`].
//!
//!   Neither library dominates the other: `xml-rs` has no document-size, depth or element-count
//!   bound, which this crate does have. The comparison is a trade, not a ranking, and the
//!   deciding property is below.
//! * **`roxmltree`.** Pure Rust, a pleasant tree API, and `ParsingOptions::allow_dtd` defaults
//!   to FALSE with a `nodes_limit` beside it. An earlier draft said it "handles DTD internal
//!   subsets and entity expansion", which is what it does when a caller opts in; by default it
//!   answers `Error::DtdDetected`, which is the same posture this crate presents as its own.
//! * **An existing Rust SAML crate.** None carries a signature-wrapping regression corpus, an
//!   algorithm allowlist, or a misuse-resistant API, which is the content of #138. Adopting one
//!   would move the problem and would put a third party in the position of deciding what
//!   "verified" means here.
//!
//! # So why `quick-xml`, given that two of those are also safe by default
//!
//! RETENTION. With a pull parser this crate decides what is KEPT, which is the only reason
//! [`Element`] can hold a name and nothing else. A tree library hands back a tree with every
//! attribute and every text node in it, and "there is no accessor for the value" then becomes a
//! promise about an API rather than a fact about what exists in memory. That is the property
//! criterion 6 of #138 is about, and it is the one a later reader will most want to have been
//! decided structurally.
//!
//! AN EARLIER DRAFT GAVE A DIFFERENT REASON AND IT WAS FALSE. It said XML Signature needs byte
//! ranges for the exact subtree it verifies, which is true, and that a tree library "gives a
//! tree and not a byte range", which is not: `roxmltree` has `Node::range()`,
//! `Attribute::range()`, `range_qname()` and `range_value()`, each documented as a byte range in
//! the original document, behind a `positions` feature that is ON by default. `quick-xml` has no
//! per-event span at all -- only `Reader::buffer_position()`, a single cursor a caller must keep
//! its own books against. On that axis the rejected library is BETTER equipped than the chosen
//! one, and the signature half will have to do that bookkeeping.
//!
//! So the honest summary is that `roxmltree` is a credible alternative that was not chosen, on
//! retention, and that the choice costs this crate the position bookkeeping it would have got
//! for free. If the signature half finds that bookkeeping is where its bugs live, the decision
//! is worth reopening, and this paragraph is what a reader would reopen it against.
//!
//! `quick-xml` is pure Rust, actively maintained, MIT licensed, and built here with default
//! features off. What it does NOT do is resolve entities automatically or perform any I/O: an
//! entity reference in TEXT arrives as its own event, which this crate refuses, and a `DOCTYPE`
//! arrives as an event this crate refuses outright. It does ship an internal-subset parser and
//! unescaping helpers; this crate calls neither, so calling it a parser with "no entity
//! resolution machinery" would be too strong -- what is true is that it resolves nothing on its
//! own, and this crate never asks it to.
//!
//! ONE CONSEQUENCE HAS TO BE HANDLED HERE RATHER THAN BY THE PARSER. Only references in TEXT
//! become events; an attribute value arrives inside the raw start tag and is never tokenised. So
//! `Destination="&whoami;"` would ride straight through a parser that trusted the event stream,
//! while the identical reference in a `NameID` is refused. [`parse`] applies the same rule to
//! attribute values itself, and `tests/hostile.rs` drives both halves.
//!
//! # Version 0.41, and the honest reason
//!
//! 0.41 reports an unresolved entity reference in text as `Event::GeneralRef`, so it can be
//! refused AT PARSE TIME. 0.37 reports the same reference inside the text node and surfaces it
//! only when a caller unescapes -- where it is, to be fair, also an error rather than a silent
//! truncation (measured: `unescape()` on `a&whoami;b` under 0.37.5 answers
//! `UnrecognizedEntity`). An earlier draft of this note claimed it read as `ab`, which is false.
//!
//! The reason to prefer the parse-time refusal is that THIS CRATE NEVER UNESCAPES. A refusal
//! that only fires when somebody calls a method is a refusal that depends on every future caller
//! remembering to call it.
//!
//! # The choke point has an upstream, and it is not here
//!
//! [`parse`] takes decoded bytes. The HTTP-Redirect binding delivers base64 of a DEFLATE
//! stream, and the classic SAML compression bomb lands in that inflate: [`Limits::max_bytes`]
//! measures the buffer AFTER something else produced it. Whatever performs that decode has to
//! carry its own output bound, and it is not written yet.
//!
//! # Signature verification, and the one rule the whole design turns on
//!
//! [`verify`] is now here, and the shape of its API is the answer to the wrapping bug described
//! at the top of this note. IN A NORMAL BUILD THE ONLY WAY TO READ A VALUE IS THROUGH A
//! [`VerifiedAssertion`], and that struct holds the subtree the digest was computed over -- not
//! the document, not the element the caller named, not a byte range into either. [`Document`]
//! exposes the SHAPE of what was parsed and no values: [`Element::name`] and
//! [`Element::children`], never an attribute and never a text node. An earlier draft said there
//! was "no accessor on `Document` at all", which is false -- [`Document::root`] is public, and
//! an element NAME is attacker-controlled bytes out of an unverified document. What is true is
//! the property this paragraph needs: no VALUE can be read without a signature.
//! So "the component that decides signed-ness" and "the
//! component that reads the values" cannot disagree about which bytes they meant, because there
//! is only one copy of those bytes and only one function that produced it.
//!
//! "IN A NORMAL BUILD" IS LOAD-BEARING AND AN EARLIER DRAFT OMITTED IT. [`test_util`] is behind
//! a feature this crate's own dependents never enable, and it exposes `canonicalize`, which
//! returns the canonical octets of any named element of any document with no signature check
//! anywhere on the path. That is a reader for unverified content. It exists because the
//! canonicalizer cannot be tested through the verifier -- a signer and a verifier sharing a
//! canonicalization bug agree perfectly -- and the argument for it is in [`test_util`] itself.
//! It is still a door, and a sentence that says there is no door is worse than the door.
//!
//! That is a stronger claim than it looks, and the review of this PR is why it is stated so
//! flatly: an earlier draft of [`verify`] digested a stripped copy of the assertion and then
//! handed back the ORIGINAL subtree. Every test passed. A document whose `NameID` said
//! `victim@example.test` verified and read back as `admin@corp.test`, because the attacker's
//! content sat inside the `Signature` element, which the digest removed and the returned value
//! kept. `tests/wrapping.rs` now carries that exact document.
//!
//! # What verification covers, and what it deliberately refuses
//!
//! * ONE signature, and it is a CHILD of the element being verified. A `Signature` deeper in
//!   the tree is not searched for, because "find the signature" is the search that XSW attacks:
//!   the attacker supplies a second one somewhere the finder looks and the reader does not.
//! * The enveloped-signature transform removes exactly ONE element -- the `Signature` holding
//!   the transform, identified by its POSITION among the children. Removing every element whose
//!   local name is `Signature` (the obvious implementation, and the one this crate had first)
//!   deletes a legitimately signed `<Signature>` in an unrelated namespace and any nested one,
//!   and both are now regression tests.
//! * `SignatureValue` for ECDSA is fixed-width `r||s` per RFC 4051 2.3.6, NOT ASN.1 DER. A
//!   verifier that accepts DER accepts a second encoding of the same signature.
//! * ONE assertion. A `Response` carrying several signed assertions is REFUSED rather than
//!   resolved to the first, and this is a real narrowing: such a response is conforming, and
//!   some identity providers emit one. It is refused because "the first assertion" is a choice
//!   this crate would be making on a caller's behalf about whose identity was asserted, and
//!   that choice is the one that has to be visible at the call site. The same rule applies
//!   inside an assertion: two elements of one name resolve to `None`, never to the first.
//!
//!   THE SAME RULE HAS A COST THE SP FLOW WILL HAVE TO PAY, and it is named here rather than
//!   discovered later. The ordinary bearer assertion carries TWO `saml:NameID` elements: the
//!   subject's, and one inside `saml:SubjectConfirmation` naming the confirming party, which
//!   SAML core 2.4.1.2 distinguishes by POSITION and not by name. So
//!   `text_of("saml:NameID")` answers `None` for the commonest assertion in the field. That is
//!   the right answer for a name-only accessor, and it means #139 needs a POSITIONAL one --
//!   `Subject` then `NameID`, as a path -- rather than a loosening of this rule.
//! * ECDSA is supported for the MATCHED pairs only: P-256 with SHA-256 and P-384 with SHA-384.
//!   RFC 4051 2.3.6 names the URIs by their DIGEST and takes the curve from the key, so P-384
//!   with `#ecdsa-sha256` is conforming and this crate cannot check it: `ring` offers the
//!   fixed-width `r||s` verification XMLDSIG requires only for the matched pairs. Such a
//!   document answers `SignatureInvalid`.
//!
//!   THAT NARROWING IS RECORDED HERE RATHER THAN IN THE ERROR, and the attempt to put it in the
//!   error is why. A previous revision returned `AlgorithmRefused` for the cross pairs so an
//!   operator would not read "forgery" about their own identity provider. It made two things
//!   worse at once. The error then depended on the SERVER's pinned key rather than on the
//!   document, so an unauthenticated attacker naming each of the three algorithm URIs in turn
//!   read the pinned key's kind out of which one answered differently -- the oracle
//!   [`VerifyError`] is explicitly shaped to avoid. And it relabelled the ORDINARY wrong-key
//!   case: an SP pinning RSA, sent an ECDSA-signed document, was told this server refuses an
//!   algorithm it in fact accepts.
//!
//!   So the error channel says only what the DOCUMENT decides, and the narrowing lives in this
//!   paragraph, where an operator can find it and an attacker cannot query it.
//! * Namespace declarations are NOT attributes. [`VerifiedAssertion::attribute`] refuses
//!   `xmlns` and `xmlns:*`, so a caller cannot read a URI as though the identity provider had
//!   asserted it.
//!
//! # What this crate does NOT do yet
//!
//! Metadata parsing, anchor rotation, and the SP protocol flow are #139.
//!
//! EVERY ACCEPTANCE CRITERION OF #138 IS MET, which is not the same as "everything #138 asks
//! for". Its What section also names strict schema validation before signature processing, and
//! this crate performs none: it checks well-formedness, bounds and signature structure. The SAML
//! schema constrains a protocol this crate does not implement, so `tests/owasp_checklist.rs`
//! records it as #139's, and this sentence says so rather than letting a reader infer more from
//! a criteria count.
//!
//! ENCRYPTED ASSERTIONS ARE HERE, with the key transport as a CALLER'S SEAM rather than a key
//! this crate holds. That is better architecture -- a production service provider keeps its
//! decryption key in an HSM or a KMS, not in a parsing library's heap -- and it is also the only
//! correct answer available: `ring` has no RSA decryption at all, and the `rsa` crate's advisory
//! exemption in `deny.toml` rests on the written claim that it "NEVER DECRYPTS", which calling
//! its decrypt here would have made false in the exact operation the Marvin advisory is about.
//! See [`decrypt_and_verify`].
//!
//! COMMENT TRUNCATION IS HERE, and an earlier version of this list said it was not. A value
//! split by a comment reads back whole, `tests/wrapping.rs` carries the corpus, and the note on
//! the `Event::Comment` arm in `tree.rs` records which mechanism actually does the work -- which
//! is not the one the obvious explanation would give.

#![forbid(unsafe_code)]

pub mod attributes;
mod c14n;
pub mod conditions;
mod encrypted;
mod instant;
mod parse;
mod tree;
mod verify;
pub mod x509;

pub use parse::{DEPTH_CEILING, Document, Element, Limits, SamlError, parse};

/// The SAML 2.0 assertion namespace, which is what an `Assertion` element is IN.
///
/// Exported because [`verify`] takes a namespace and a local name rather than a qualified name,
/// and every caller would otherwise write this URI out by hand. A prefix is not an identity:
/// Okta emits `saml2:Assertion`, Entra emits `Assertion` under a default declaration, and both
/// are this namespace.
pub const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// The SAML 2.0 protocol namespace, which `Response` and `AuthnRequest` are in.
pub const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub use attributes::{Ambiguous, Attribute, Value, attributes};
pub use conditions::{Accepted, ConditionError, Expectations, check};
pub use encrypted::{
    DecryptError, KeyTransport, KeyTransportAlg, OaepDigest, OaepMgf, OaepParameters,
    decrypt_and_verify,
};
pub use instant::parse_utc;
pub use verify::{SignedElement, TrustAnchor, VerifiedAssertion, VerifyError, verify};

/// Test-only access to the canonicalizer.
///
/// # Why this is exposed at all
///
/// The canonicalizer is the one component whose correctness cannot be checked through the
/// verifier: a signer and a verifier that share a canonicalization bug agree with each other
/// perfectly. So it gets its own suite, driven against the canonical forms the specification
/// prescribes rather than against anything this crate produces -- and that suite has to be able
/// to call it.
///
/// Behind a feature, so the surface does not exist in a normal build.
#[cfg(feature = "test-util")]
pub mod test_util {
    /// Re-sign a document whose assertion has been edited, so the edit is genuinely SIGNED.
    ///
    /// The ambiguity case needs a document that verifies and is ambiguous, which is not a
    /// forgery: an identity provider may legitimately sign an assertion with two `NameID`s, and
    /// the question is what a reader does with it.
    ///
    /// # Panics
    ///
    /// If the document does not parse or carries no signature to replace.
    #[must_use]
    pub fn resign(key: &ironauth_jose::xmldsig::test_util::XmlTestKey, document: &str) -> String {
        let start = document
            .find("<ds:Signature")
            .expect("a signature to replace");
        let end = document
            .find("</ds:Signature>")
            .expect("a signature to replace")
            + "</ds:Signature>".len();
        let stripped = [&document[..start], &document[end..]].concat();
        let digest = digest_of(&stripped, "saml:Assertion");
        let signed_info = signed_info_for("_assertion", &digest);
        let staged = [
            &document[..start],
            &signature_element(&signed_info, ""),
            &document[end..],
        ]
        .concat();
        let message = canonicalize(&staged, "ds:SignedInfo").expect("the staged SignedInfo parses");
        let value = base64(&key.sign(message.as_bytes()));
        [
            &document[..start],
            &signature_element(&signed_info, &value),
            &document[end..],
        ]
        .concat()
    }

    /// Re-seal a document whose SIGNATURE ELEMENT has been edited, leaving the assertion alone.
    ///
    /// # Why [`resign`] is not enough
    ///
    /// [`resign`] rebuilds the whole `SignedInfo` from one fixed template, so it can only ever
    /// produce the shape this crate's own signer produces. Half the properties worth testing are
    /// about a DIFFERENT shape: a `SignedInfo` that declares its own prefix, one that rebinds a
    /// prefix to a hostile URI, a `Reference` URI written without its fragment, a `DigestValue`
    /// that has been truncated, a base64 run broken across lines. Each of those has to remain
    /// GENUINELY SIGNED, or the test proves only that a document with a broken signature is
    /// refused, which every document is.
    ///
    /// So this takes the `SignedInfo` exactly as it now sits, canonicalises it in place, signs
    /// that, and writes the value back. `signed_info` and `signature_value` are the qualified
    /// names to look for, because the point of several of these documents is that those names
    /// are not the usual ones.
    ///
    /// # Panics
    ///
    /// If the named elements are absent or the document does not canonicalise.
    #[must_use]
    pub fn reseal(
        key: &ironauth_jose::xmldsig::test_util::XmlTestKey,
        document: &str,
        signed_info: &str,
        signature_value: &str,
    ) -> String {
        let message = canonicalize(document, signed_info).expect("the SignedInfo canonicalises");
        let value = base64(&key.sign(message.as_bytes()));
        let open = ["<", signature_value].concat();
        let close = ["</", signature_value, ">"].concat();
        let start = document.find(&open).expect("a SignatureValue to replace");
        let start = start
            + document[start..]
                .find('>')
                .expect("the SignatureValue start tag closes")
            + 1;
        let end = document.find(&close).expect("a SignatureValue to replace");
        [&document[..start], &value, &document[end..]].concat()
    }

    /// Add a RESPONSE-level enveloped signature to a document whose assertion is already signed.
    ///
    /// # The document this builds is the ordinary one, not an exotic one
    ///
    /// Okta and ADFS sign the Response AND the assertion inside it. That shape is why
    /// `VerifiedAssertion::child_count` counts DIRECT children: verifying the Response returns a
    /// subtree that still contains the assertion's signature, legitimately, because the Response
    /// signature covered it. A descendant count answers one there and a verifier that used one
    /// would refuse the commonest document in the field.
    ///
    /// Nothing in this crate could BUILD that document before, so the property was argued for in
    /// three doc comments and exercised by nothing.
    ///
    /// # Panics
    ///
    /// If the document does not parse or has no `samlp:Response` element.
    #[must_use]
    pub fn sign_response(
        key: &ironauth_jose::xmldsig::test_util::XmlTestKey,
        document: &str,
    ) -> String {
        // The digest is over the Response AS IT STANDS: the enveloped transform removes only the
        // signature carrying the transform, which is the one being added, and it is not there
        // yet. The assertion's own signature IS covered, which is the point of signing both.
        let digest = digest_of(document, "samlp:Response");
        let signed_info = signed_info_for("_response", &digest);
        let open_end = document.find('>').expect("the Response start tag closes") + 1;
        let stage = |value: &str| {
            [
                &document[..open_end],
                &signature_element(&signed_info, value),
                &document[open_end..],
            ]
            .concat()
        };
        // The Response's `SignedInfo` is FIRST in document order because the signature is spliced
        // in as the first child, so canonicalising by qualified name reaches it and not the
        // assertion's.
        let message =
            canonicalize(&stage(""), "ds:SignedInfo").expect("the staged SignedInfo parses");
        stage(&base64(&key.sign(message.as_bytes())))
    }

    /// The `SignedInfo` for one reference and digest.
    fn signed_info_for(id: &str, digest: &str) -> String {
        [
            "<ds:SignedInfo>",
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
            r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>"#,
            "<ds:Reference URI=\"#",
            id,
            "\"><ds:Transforms>",
            r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#,
            r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
            "</ds:Transforms>",
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
            "<ds:DigestValue>",
            digest,
            "</ds:DigestValue></ds:Reference></ds:SignedInfo>",
        ]
        .concat()
    }

    /// A `ds:Signature` element around a `SignedInfo` and a value.
    fn signature_element(signed_info: &str, value: &str) -> String {
        [
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            signed_info,
            "<ds:SignatureValue>",
            value,
            "</ds:SignatureValue></ds:Signature>",
        ]
        .concat()
    }

    /// Build a SAML response whose assertion carries a genuinely valid enveloped signature.
    ///
    /// # Why the corpus needs this
    ///
    /// A wrapping corpus built against an UNSIGNED document proves nothing: every entry would be
    /// refused for being unsigned, and the suite would pass against a verifier that refused
    /// everything. Each forgery has to start from a document that really verifies.
    ///
    /// # What it cannot prove
    ///
    /// This canonicalises with the crate's own canonicalizer, so a document it produces and the
    /// verifier accepts shows the two AGREE, not that either is right. That is what
    /// `tests/canonical.rs` is for, and neither suite substitutes for the other.
    ///
    /// # Panics
    ///
    /// If the document it just built does not parse, which would be a bug in this function.
    #[must_use]
    pub fn signed_response(
        key: &ironauth_jose::xmldsig::test_util::XmlTestKey,
        id: &str,
    ) -> String {
        signed_response_with(
            key,
            id,
            &[
                "<saml:Issuer>urn:idp</saml:Issuer>",
                "<saml:Subject><saml:NameID>victim@example.test</saml:NameID></saml:Subject>",
            ]
            .concat(),
        )
    }

    /// [`signed_response`] with the assertion's children supplied by the caller.
    ///
    /// # Why the conditions corpus needs this
    ///
    /// A condition check is about values INSIDE the signed assertion -- the audience, the two
    /// time bounds, the correlation, the recipient -- so a corpus for it has to vary those values
    /// while the signature stays genuinely valid over each variant. Composing the children here
    /// and signing whatever results is what makes "the audience is wrong" a document that really
    /// verifies rather than one that fails for being unsigned, which is the same argument
    /// [`signed_response`] makes about the wrapping corpus.
    ///
    /// # Panics
    ///
    /// If the document it just built does not parse, which would be a bug in this function.
    #[must_use]
    pub fn signed_response_with(
        key: &ironauth_jose::xmldsig::test_util::XmlTestKey,
        id: &str,
        children: &str,
    ) -> String {
        signed_element_with(key, "saml:Assertion", "", id, children)
    }

    /// [`signed_response_with`], for a root element that is NOT a `saml:Assertion`.
    ///
    /// `qualified` is written into the document verbatim and `declarations` is spliced into its
    /// start tag, so a caller can sign an element in a namespace of its own invention.
    ///
    /// # Why a caller needs this
    ///
    /// `verify` takes the element to read as an ARGUMENT, so what it hands back is not
    /// necessarily an assertion, and a condition check that tested the element's QUALIFIED name
    /// -- `name().ends_with("Assertion")`, which is what an earlier version did -- answers true
    /// for `evil:NotAnAssertion` in a namespace nobody trusts. That bypass is only testable if a
    /// fixture can sign such an element, and signing an assertion in a loop cannot express it.
    ///
    /// # Panics
    ///
    /// If the document it just built does not parse, which would be a bug in this function.
    #[must_use]
    pub fn signed_element_with(
        key: &ironauth_jose::xmldsig::test_util::XmlTestKey,
        qualified: &str,
        declarations: &str,
        id: &str,
        children: &str,
    ) -> String {
        let assertion = [
            "<",
            qualified,
            declarations,
            r#" ID=""#,
            id,
            r#"">"#,
            children,
            "</",
            qualified,
            ">",
        ]
        .concat();
        let unsigned = wrap(&assertion);
        let digest = digest_of(&unsigned, qualified);
        let signed_info = [
            "<ds:SignedInfo>",
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
            r#"<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>"#,
            "<ds:Reference URI=\"#",
            id,
            "\"><ds:Transforms>",
            r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#,
            r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
            "</ds:Transforms>",
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
            "<ds:DigestValue>",
            &digest,
            "</ds:DigestValue></ds:Reference></ds:SignedInfo>",
        ]
        .concat();
        let staged = wrap(&with_signature(&assertion, &signed_info, ""));
        let message = canonicalize(&staged, "ds:SignedInfo").expect("the staged SignedInfo parses");
        let value = base64(&key.sign(message.as_bytes()));
        wrap(&with_signature(&assertion, &signed_info, &value))
    }

    fn wrap(assertion: &str) -> String {
        [
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response">"#,
            assertion,
            "</samlp:Response>",
        ]
        .concat()
    }

    /// Splice a signature into an assertion, immediately after its issuer.
    ///
    /// AN ASSERTION WITH NO ISSUER IS SIGNED AS THE FIRST CHILD INSTEAD, rather than refused
    /// here. A document that names no author is exactly what a caller has to be able to compose,
    /// because it is exactly what an attacker can send -- and a fixture builder that cannot
    /// express it would make that case untestable.
    fn with_signature(assertion: &str, signed_info: &str, value: &str) -> String {
        let signature = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{value}</ds:SignatureValue></ds:Signature>"#
        );
        let marker = "</saml:Issuer>";
        let at = match assertion.find(marker) {
            Some(at) => at + marker.len(),
            None => {
                assertion
                    .find('>')
                    .expect("the assertion's own start tag is there")
                    + 1
            }
        };
        format!("{}{signature}{}", &assertion[..at], &assertion[at..])
    }

    /// The base64 digest of an element, as a `DigestValue` carries it.
    fn digest_of(document: &str, element: &str) -> String {
        let canonical = canonicalize(document, element).expect("the document parses");
        base64(&ironauth_jose::xmldsig::xml_digest(
            ironauth_jose::xmldsig::XmlDigestAlg::Sha256,
            canonical.as_bytes(),
        ))
    }

    /// Standard base64, which is what XML Signature carries.
    #[must_use]
    pub fn base64(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut buffer = [0_u8; 3];
            buffer[..chunk.len()].copy_from_slice(chunk);
            let packed =
                (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);
            for index in 0..4 {
                if index <= chunk.len() {
                    let shift = 18 - index * 6;
                    out.push(char::from(TABLE[((packed >> shift) & 0x3F) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// Canonicalise the first element named `element` in `document`, exclusively.
    ///
    /// The element is located by name and canonicalised WITH the namespace declarations its
    /// ancestors put in scope, which is what a signed subtree gets.
    ///
    /// # Errors
    ///
    /// The parse error, or a marker string if the subtree uses a prefix nothing binds.
    pub fn canonicalize(document: &str, element: &str) -> Result<String, String> {
        let limits = crate::Limits::default();
        let root = crate::tree::build(document.as_bytes(), &limits)
            .map_err(|error| format!("parse: {error}"))?;
        let target = crate::verify::find_for_test(&root, element)
            .ok_or_else(|| format!("no element named {element}"))?;
        let scope = crate::verify::scope_at_for_test(&root, target);
        let bytes =
            crate::c14n::canonicalize(target, &scope).map_err(|_| "unbound prefix".to_owned())?;
        String::from_utf8(bytes).map_err(|_| "not utf-8".to_owned())
    }
}
