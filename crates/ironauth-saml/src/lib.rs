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
//! # What this crate does NOT do yet
//!
//! Signature verification, the XSW corpus, comment-truncation handling, and encrypted
//! assertions are the rest of #138 and are not here. This crate currently gives a caller a
//! parsed document and NO way to read a value out of it, which is deliberate: see
//! [`Document`].

#![forbid(unsafe_code)]

mod c14n;
mod parse;
mod tree;
mod verify;

pub use parse::{DEPTH_CEILING, Document, Element, Limits, SamlError, parse};
pub use verify::{TrustAnchor, VerifiedAssertion, VerifyError, verify};

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
        // `xmlns:ds` sits on the `Signature`, so `SignedInfo` INHERITS it -- which exercises the
        // inherited-scope path the canonicalizer got wrong, rather than sidestepping it.
        let assertion = [
            r#"<saml:Assertion ID=""#,
            id,
            r#""><saml:Issuer>urn:idp</saml:Issuer>"#,
            "<saml:Subject><saml:NameID>victim@example.test</saml:NameID></saml:Subject>",
            "</saml:Assertion>",
        ]
        .concat();
        let unsigned = wrap(&assertion);
        // The digest is over the assertion with its signature removed, and there is none yet:
        // the enveloped transform makes those the same thing.
        let digest = digest_of(&unsigned, "saml:Assertion");

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
        // Canonicalise SignedInfo in the place it will sit, so its inherited `ds` resolves.
        let staged = wrap(&with_signature(&assertion, &signed_info, ""));
        let message = canonicalize(&staged, "ds:SignedInfo").expect("the staged SignedInfo parses");
        let value = base64(&key.sign(message.as_bytes()));
        wrap(&with_signature(&assertion, &signed_info, &value))
    }

    /// Put an assertion inside a response.
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
    fn with_signature(assertion: &str, signed_info: &str, value: &str) -> String {
        let signature = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{signed_info}<ds:SignatureValue>{value}</ds:SignatureValue></ds:Signature>"#
        );
        let marker = "</saml:Issuer>";
        let at = assertion.find(marker).expect("the issuer is there") + marker.len();
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
