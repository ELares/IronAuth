// SPDX-License-Identifier: MIT OR Apache-2.0

//! The XML Signature Wrapping corpus (issue #138, criteria 1 and 4).
//!
//! # What every one of these has in common
//!
//! The signature is GENUINELY VALID. Not one entry below tampers with the cryptography: each
//! takes a document that verifies and moves a node, so a verifier that checked only "does the
//! signature verify" answers yes to all of them. That is the whole family -- one component
//! decides the document is signed and a different component reads values from a different node,
//! and the two never compare notes.
//!
//! Every shape is traceable. The families are Somorovsky et al., "On Breaking SAML: Be Whoever
//! You Want to Be" (USENIX Security 2012); the positions match `SAMLRaider`'s `XSWHelpers` and
//! Keycloak's `SamlSignatureTest`, and the assertion-level relocation was rediscovered as
//! authentik GHSA-c3m2-jqmq-pvp3.
//!
//! # What stops all of them here
//!
//! One rule, applied in one place: the verifier returns the SUBTREE IT DIGESTED, and the caller
//! reads from that and nothing else. There is no second lookup to disagree with the first. The
//! refusals below are the earlier, cheaper guard -- a document carrying two candidates is
//! refused before any of it is digested -- but the structural property is what makes the guard
//! sufficient rather than merely helpful.
//!
//! Needs no database.

use ironauth_jose::xmldsig::test_util::XmlTestKey;
use ironauth_saml::{Limits, TrustAnchor, VerifyError, verify};

/// The XMLDSIG namespace, for the rows that name a signature element.
const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// The key, the anchor, and a document that really verifies.
struct Fixture {
    anchors: Vec<TrustAnchor>,
    document: String,
    /// Kept so a test can re-seal a signature it edited. See `test_util::reseal`.
    key: XmlTestKey,
}

impl Fixture {
    fn new() -> Self {
        let key = XmlTestKey::generate();
        let document = ironauth_saml::test_util::signed_response(&key, "_assertion");
        Self {
            anchors: vec![TrustAnchor::EcdsaP256(key.public_point())],
            document,
            key,
        }
    }

    /// Verify a document against this fixture's pinned key.
    fn verify(&self, document: &str) -> Result<ironauth_saml::VerifiedAssertion, VerifyError> {
        verify(
            document.as_bytes(),
            &Limits::default(),
            &self.anchors,
            ironauth_saml::ASSERTION_NS,
            "Assertion",
        )
    }
}

/// THE CONTROL, and the suite is worth nothing without it.
///
/// If the unmodified document did not verify, every refusal below would be a refusal of
/// something that was never acceptable, and the corpus would pass against a verifier that
/// refused everything.
#[test]
fn the_unmodified_document_verifies_and_carries_its_values() {
    let fixture = Fixture::new();
    let assertion = fixture
        .verify(&fixture.document)
        .expect("the unmodified document must verify");
    assert_eq!(assertion.name(), "saml:Assertion");
    assert_eq!(assertion.attribute("ID"), Some("_assertion"));
    assert_eq!(
        assertion
            .text_of(ironauth_saml::ASSERTION_NS, "NameID")
            .as_deref(),
        Some("victim@example.test")
    );
}

/// XSW3: a forged assertion as a PRECEDING SIBLING of the signed one.
///
/// The purest form of the family. The signature is untouched and stays enveloped in the original;
/// SAML permits several assertions in a response, so the document is schema-valid. A verifier
/// that validates the signature and then reads "the assertion" -- the first one, or
/// `getElementsByTagName(...).item(0)` -- reads the forgery.
#[test]
fn a_forged_assertion_before_the_signed_one_is_refused() {
    let fixture = Fixture::new();
    let forged = r#"<saml:Assertion ID="_forged"><saml:Issuer>urn:idp</saml:Issuer><saml:Subject><saml:NameID>attacker@evil.test</saml:NameID></saml:Subject></saml:Assertion>"#;
    let attacked = fixture.document.replacen(
        "<saml:Assertion ID=\"_assertion\"",
        &format!("{forged}<saml:Assertion ID=\"_assertion\""),
        1,
    );
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::ReferenceRefused)
    );
}

/// XSW3 variant: the forgery AFTER the signed assertion, for the verifier that takes the last.
#[test]
fn a_forged_assertion_after_the_signed_one_is_refused() {
    let fixture = Fixture::new();
    let forged = r#"<saml:Assertion ID="_forged"><saml:Issuer>urn:idp</saml:Issuer><saml:Subject><saml:NameID>attacker@evil.test</saml:NameID></saml:Subject></saml:Assertion>"#;
    let attacked = fixture.document.replacen(
        "</samlp:Response>",
        &format!("{forged}</samlp:Response>"),
        1,
    );
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::ReferenceRefused)
    );
}

/// XSW4: the signed assertion NESTED INSIDE the forged one.
///
/// This is the variant that defeats the weak rule "the Signature's parent must be an Assertion
/// and the Reference must name that parent's ID" -- that rule holds here, because the inner pair
/// is entirely legitimate. Only the choice of which assertion to consume is wrong.
#[test]
fn the_signed_assertion_nested_inside_a_forged_one_is_refused() {
    let fixture = Fixture::new();
    let opening = r#"<saml:Assertion ID="_forged"><saml:Issuer>urn:idp</saml:Issuer><saml:Subject><saml:NameID>attacker@evil.test</saml:NameID></saml:Subject>"#;
    let attacked = fixture
        .document
        .replacen(
            "<saml:Assertion ID=\"_assertion\"",
            &format!("{opening}<saml:Assertion ID=\"_assertion\""),
            1,
        )
        .replacen("</samlp:Response>", "</saml:Assertion></samlp:Response>", 1);
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::ReferenceRefused)
    );
}

/// XSW1: the signed original buried INSIDE the surviving `Signature` element.
///
/// The wrapped copy sits directly under `ds:Signature`, which the schema does not permit -- and
/// a verifier that resolves `URI="#id"` document-wide finds it anyway, digests it, and returns
/// true.
#[test]
fn the_signed_original_hidden_inside_the_signature_is_refused() {
    let fixture = Fixture::new();
    // A copy of the assertion, carrying the referenced ID, tucked inside the Signature; the
    // outer assertion is renamed and carries the attacker's subject.
    let copy = r#"<saml:Assertion ID="_assertion"><saml:Issuer>urn:idp</saml:Issuer><saml:Subject><saml:NameID>victim@example.test</saml:NameID></saml:Subject></saml:Assertion>"#;
    let attacked = fixture
        .document
        .replacen(
            "<saml:Assertion ID=\"_assertion\"",
            "<saml:Assertion ID=\"_forged\"",
            1,
        )
        .replacen("</ds:Signature>", &format!("{copy}</ds:Signature>"), 1)
        .replacen(
            "victim@example.test</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>",
            "attacker@evil.test</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>",
            1,
        );
    assert!(
        matches!(
            fixture.verify(&attacked),
            Err(VerifyError::ReferenceRefused | VerifyError::SignatureInvalid)
        ),
        "a copy hidden inside the signature must not be what gets digested"
    );
}

/// DUPLICATED IDENTIFIERS: two elements answering to one reference.
///
/// The wrapping class that needs no schema trick at all. The verifier resolves `#_assertion` to
/// one of them and the consumer picks the other.
#[test]
fn two_elements_claiming_one_identifier_are_refused() {
    let fixture = Fixture::new();
    let twin = r#"<saml:Assertion ID="_assertion"><saml:Issuer>urn:idp</saml:Issuer><saml:Subject><saml:NameID>attacker@evil.test</saml:NameID></saml:Subject></saml:Assertion>"#;
    let attacked =
        fixture
            .document
            .replacen("</samlp:Response>", &format!("{twin}</samlp:Response>"), 1);
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::ReferenceRefused)
    );
}

/// The reference must name the element the caller reads, not some other one.
#[test]
fn a_reference_naming_a_different_element_is_refused() {
    let fixture = Fixture::new();
    let attacked = fixture
        .document
        .replacen("URI=\"#_assertion\"", "URI=\"#_response\"", 1);
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::ReferenceRefused)
    );
}

/// An empty reference -- "the whole document" -- is refused.
///
/// This verifier hands back a subtree, so a signature over the whole document would be a
/// signature over something other than what it returns.
#[test]
fn a_whole_document_reference_is_refused() {
    let fixture = Fixture::new();
    let attacked = fixture
        .document
        .replacen("URI=\"#_assertion\"", "URI=\"\"", 1);
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::ReferenceRefused)
    );
}

/// TAMPERING WITH THE SIGNED CONTENT is caught by the digest.
///
/// The counterpart to the corpus above: those move nodes and leave the cryptography alone, and
/// this leaves the nodes alone and changes a value. Both must fail, and for different reasons.
#[test]
fn changing_a_signed_value_breaks_the_digest() {
    let fixture = Fixture::new();
    let attacked = fixture
        .document
        .replacen("victim@example.test", "attacker@evil.test", 1);
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::SignatureInvalid)
    );
}

/// A SIGNATURE FROM AN UNPINNED KEY IS REFUSED, however valid it is (criterion 4).
///
/// The document is signed correctly, by a key nobody pinned. `KeyInfo` is not consulted at all,
/// so a document carrying its own certificate is carrying an attacker's certificate.
#[test]
fn a_valid_signature_from_an_unpinned_key_is_refused() {
    let stranger = XmlTestKey::generate();
    let document = ironauth_saml::test_util::signed_response(&stranger, "_assertion");

    // Pinned: somebody else entirely.
    let pinned = XmlTestKey::generate();
    let anchors = vec![TrustAnchor::EcdsaP256(pinned.public_point())];
    assert_eq!(
        verify(
            document.as_bytes(),
            &Limits::default(),
            &anchors,
            ironauth_saml::ASSERTION_NS,
            "Assertion"
        ),
        Err(VerifyError::SignatureInvalid)
    );

    // AND THE CONTROL: the same document against the key that made it. Without this the
    // assertion above would pass for a verifier that refused every signature.
    let anchors = vec![TrustAnchor::EcdsaP256(stranger.public_point())];
    verify(
        document.as_bytes(),
        &Limits::default(),
        &anchors,
        ironauth_saml::ASSERTION_NS,
        "Assertion",
    )
    .expect("the signer's own key verifies it");
}

/// AN EMPTY ANCHOR LIST VERIFIES NOTHING.
#[test]
fn no_pinned_key_means_no_signature_verifies() {
    let fixture = Fixture::new();
    assert_eq!(
        verify(
            fixture.document.as_bytes(),
            &Limits::default(),
            &[],
            ironauth_saml::ASSERTION_NS,
            "Assertion"
        ),
        Err(VerifyError::SignatureInvalid)
    );
}

/// SHA-1 IS REFUSED, and so is every algorithm outside the allowlist.
#[test]
fn a_refused_algorithm_is_refused_before_anything_is_verified() {
    let fixture = Fixture::new();
    for (what, from, to) in [
        (
            "an RSA-SHA1 signature method",
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        ),
        (
            "a SHA-1 digest",
            "http://www.w3.org/2001/04/xmlenc#sha256",
            "http://www.w3.org/2000/09/xmldsig#sha1",
        ),
        (
            "inclusive canonicalization",
            "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod",
            "Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/><ds:SignatureMethod",
        ),
    ] {
        let attacked = fixture.document.replacen(from, to, 1);
        assert_ne!(
            attacked, fixture.document,
            "{what}: the fixture did not change"
        );
        assert_eq!(
            fixture.verify(&attacked),
            Err(VerifyError::AlgorithmRefused),
            "{what} was not refused"
        );
    }
}

/// A TRANSFORM LIST THAT IS NOT THE EXPECTED PAIR IS REFUSED.
///
/// Including one that omits the enveloped transform: this verifier removes the signature
/// unconditionally, so a reference that did not ask for that removal would be digesting
/// something the signer did not.
#[test]
fn an_unexpected_transform_list_is_refused() {
    let fixture = Fixture::new();
    let without_enveloped = fixture.document.replacen(
        r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#,
        "",
        1,
    );
    assert_eq!(
        fixture.verify(&without_enveloped),
        Err(VerifyError::AlgorithmRefused)
    );

    let with_xpath = fixture.document.replacen(
        r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
        r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/>"#,
        1,
    );
    assert_eq!(
        fixture.verify(&with_xpath),
        Err(VerifyError::AlgorithmRefused)
    );
}

/// A SECOND REFERENCE IS REFUSED.
///
/// A `SignedInfo` with two references says two different things are signed, and picking one is
/// picking which half of a contradiction to believe.
#[test]
fn a_second_reference_is_refused() {
    let fixture = Fixture::new();
    let attacked = fixture.document.replacen(
        "</ds:Reference>",
        "</ds:Reference><ds:Reference URI=\"#_response\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference>",
        1,
    );
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::ReferenceRefused)
    );
}

/// CONTENT SMUGGLED INSIDE THE SIGNATURE IS NOT READABLE AFTERWARDS.
///
/// # The structural gap this closes
///
/// Every case above MOVES a node, and the exactly-one-candidate rule catches all of them. Not
/// one ADDS a node in the part of the subtree the enveloped transform deletes -- and there was
/// no case at all where verification SUCCEEDS and the returned values are then checked against
/// what the signer actually signed. That missing shape, not a missing row, is what let three
/// independent reviews forge an assertion through this crate.
///
/// The attack needs nothing cryptographic. Append a `ds:Object` carrying a forged
/// `saml:Subject` to the identity provider's OWN signature: the whole signature is removed
/// before the digest, so the digest and the signature are untouched and verification succeeds --
/// and the old code handed back the UNSTRIPPED subtree, where `text_of` walks depth first and
/// meets the signature before the subject, the order SAML's schema mandates.
#[test]
fn content_added_inside_the_signature_is_not_returned() {
    let fixture = Fixture::new();
    let smuggled = r"<ds:Object><saml:Subject><saml:NameID>admin@evil.test</saml:NameID></saml:Subject></ds:Object>";
    let attacked =
        fixture
            .document
            .replacen("</ds:Signature>", &format!("{smuggled}</ds:Signature>"), 1);

    let assertion = fixture
        .verify(&attacked)
        .expect("the signature is untouched, so this still verifies");
    assert_eq!(
        assertion
            .text_of(ironauth_saml::ASSERTION_NS, "NameID")
            .as_deref(),
        Some("victim@example.test"),
        "a NameID smuggled inside the signature was returned as though it had been signed"
    );

    // AND AN ATTRIBUTE STATEMENT the same way, which is how a role is forged.
    let smuggled = r#"<ds:Object><saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></ds:Object>"#;
    let attacked =
        fixture
            .document
            .replacen("</ds:Signature>", &format!("{smuggled}</ds:Signature>"), 1);
    let assertion = fixture.verify(&attacked).expect("still verifies");
    assert_eq!(
        assertion.text_of(ironauth_saml::ASSERTION_NS, "AttributeValue"),
        None,
        "an attribute smuggled inside the signature was readable"
    );
}

/// AN ELEMENT NAMED `Signature` IN SOMEBODY ELSE'S NAMESPACE IS NOT A SIGNATURE.
///
/// The second door to the same bypass. An earlier version's enveloped transform deleted every
/// element whose LOCAL name was `Signature`, at any depth, in any namespace -- so
/// `<x:Signature xmlns:x="urn:evil">` buried inside the subject was removed before the digest
/// and read after it, with no access to the real signature needed at all.
///
/// It is now removed by INDEX: exactly the one element that carries this reference, which is
/// what XMLDSIG-CORE 6.6.4 says the transform removes.
#[test]
fn an_element_named_signature_in_another_namespace_is_not_stripped() {
    let fixture = Fixture::new();
    let smuggled = r#"<x:Signature xmlns:x="urn:evil"><saml:NameID>admin@evil.test</saml:NameID></x:Signature>"#;
    let attacked =
        fixture
            .document
            .replacen("<saml:Subject>", &format!("<saml:Subject>{smuggled}"), 1);
    // It is NOT stripped, so it changes what is digested, so the digest no longer matches.
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::SignatureInvalid),
        "an element named Signature in a foreign namespace must not be removed from the digest"
    );
}

/// A `ds:Signature` NESTED DEEPER IN THE ASSERTION IS NOT THIS SIGNATURE EITHER.
#[test]
fn a_nested_signature_is_not_stripped() {
    let fixture = Fixture::new();
    let smuggled = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><saml:NameID>admin@evil.test</saml:NameID></ds:Signature>"#;
    let attacked =
        fixture
            .document
            .replacen("<saml:Subject>", &format!("<saml:Subject>{smuggled}"), 1);
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::SignatureInvalid),
        "only the signature carrying this reference is removed from the digest"
    );
}

/// A NAMESPACE DECLARATION IS NOT AN ATTRIBUTE a caller can read.
///
/// Canonicalization emits only the declarations the subtree VISIBLY USES, so an unused one is
/// not digested -- and it was still readable through the accessor, which is undigested
/// attacker-controlled data reaching a caller that believes everything it sees was signed.
#[test]
fn a_namespace_declaration_is_not_a_readable_attribute() {
    let fixture = Fixture::new();
    let attacked = fixture.document.replacen(
        r#"<saml:Assertion ID="_assertion""#,
        r#"<saml:Assertion xmlns:evil="urn:evil" ID="_assertion""#,
        1,
    );
    let assertion = fixture
        .verify(&attacked)
        .expect("an unused declaration is not digested, so this still verifies");
    assert_eq!(
        assertion.attribute("xmlns:evil"),
        None,
        "an undigested namespace declaration was readable as an attribute"
    );
    // THE CONTROL: a real attribute is still readable.
    assert_eq!(assertion.attribute("ID"), Some("_assertion"));
}

/// AN AMBIGUOUS READ IS NO READ.
///
/// `text_of` used to return the first match and its doc justified that by a duplicate refusal
/// `verify` does not perform: two signed `NameID`s verified and the second was silently dropped,
/// so the caller got one of two answers with nothing to tell it there had been a choice.
#[test]
fn two_elements_of_one_name_are_not_silently_resolved_to_the_first() {
    let key = XmlTestKey::generate();
    let document = ironauth_saml::test_util::signed_response(&key, "_assertion");
    let anchors = vec![TrustAnchor::EcdsaP256(key.public_point())];

    // Both are SIGNED -- the digest is recomputed over the document as it stands, so this is not
    // a forgery. It is an ambiguity, and the caller must not be handed a coin flip.
    let twinned = document.replacen(
        "<saml:NameID>victim@example.test</saml:NameID>",
        "<saml:NameID>victim@example.test</saml:NameID><saml:NameID>other@example.test</saml:NameID>",
        1,
    );
    let resigned = ironauth_saml::test_util::resign(&key, &twinned);
    let assertion = verify(
        resigned.as_bytes(),
        &Limits::default(),
        &anchors,
        ironauth_saml::ASSERTION_NS,
        "Assertion",
    )
    .expect("a document with two NameIDs is signed like any other");
    assert_eq!(
        assertion.text_of(ironauth_saml::ASSERTION_NS, "NameID"),
        None,
        "two candidates must not resolve silently to the first"
    );
}

/// Two GENUINELY SIGNED assertions are refused rather than resolved to one of them.
///
/// # This one is not an attack, and that is the point
///
/// Every other entry in this suite is a forgery. This document is not: both assertions carry
/// their own valid enveloped signature from the pinned key, both would verify alone, and a
/// `Response` bearing several signed assertions is permitted by the SAML core schema. Some
/// identity providers emit one.
///
/// It is refused anyway, and the refusal is a real narrowing of what this crate accepts. The
/// reason is that "which assertion" is a question about WHOSE IDENTITY WAS ASSERTED, and the
/// answer cannot be a default buried in a verifier -- picking the first is how XSW3 pays off in
/// every implementation that does it. A caller that genuinely needs multi-assertion responses
/// has to ask for a named one, and that surface does not exist yet.
///
/// The controls below are what make the assertion mean anything: without them this would pass
/// against a verifier that refused both documents for being unsigned.
#[test]
fn two_genuinely_signed_assertions_are_refused_rather_than_resolved() {
    let key = XmlTestKey::generate();
    let anchors = vec![TrustAnchor::EcdsaP256(key.public_point())];
    let first = ironauth_saml::test_util::signed_response(&key, "_assertion");
    let second = ironauth_saml::test_util::signed_response(&key, "_second");

    let check = |document: &str| {
        verify(
            document.as_bytes(),
            &Limits::default(),
            &anchors,
            ironauth_saml::ASSERTION_NS,
            "Assertion",
        )
    };

    // CONTROL: each response verifies on its own, so neither is being refused for its own sake.
    assert!(
        check(&first).is_ok(),
        "the first response must verify alone"
    );
    assert!(
        check(&second).is_ok(),
        "the second response must verify alone"
    );

    // The second assertion, lifted out with its signature intact. Its enclosing scope is the
    // same `Response` element, so its canonical form -- and therefore its digest -- is unchanged
    // by the move: this is a document with two valid signatures, not a broken one.
    let start = second
        .find("<saml:Assertion")
        .expect("the second response has an assertion");
    let end = second
        .find("</saml:Assertion>")
        .expect("the second response has an assertion")
        + "</saml:Assertion>".len();
    let lifted = &second[start..end];

    let both = first.replacen(
        "</samlp:Response>",
        &format!("{lifted}</samlp:Response>"),
        1,
    );
    assert_eq!(check(&both), Err(VerifyError::ReferenceRefused));
}

// ---------------------------------------------------------------------------------------------
// THE GUARDS THAT HAD NO TEST.
//
// A mutation sweep over this crate removed each security check in turn and ran the whole suite.
// Nine of them could be deleted outright with all 57 tests still green. Every test below was
// written against one of those, and each was confirmed to FAIL with its guard removed -- which
// is the only evidence that a guard is doing anything at all.
//
// They are here rather than in a new file because they are the same corpus: each is a document
// that a verifier missing one check accepts, or a conforming document it refuses.
// ---------------------------------------------------------------------------------------------

/// A `Reference` URI without its `#` is refused.
///
/// # An external reference is not a same-document reference
///
/// `URI="#_assertion"` is a same-document reference. `URI="_assertion"` is a RELATIVE one, which
/// XMLDSIG-CORE 4.4.3.1 makes EXTERNAL: a conforming verifier dereferences it and digests
/// whatever comes back. This crate dereferences nothing, so accepting the second form would mean
/// digesting the local element while the signature claimed to cover something else entirely.
///
/// `a_whole_document_reference_is_refused` was named for this guard and does not reach it: its
/// `URI=""` is caught two guards later by the identifier comparison. With the `#` requirement
/// deleted, that test stayed green and this document verified.
#[test]
fn a_reference_uri_without_a_fragment_is_refused() {
    let fixture = Fixture::new();
    let attacked = ironauth_saml::test_util::reseal(
        &fixture.key,
        &fixture
            .document
            .replacen("URI=\"#_assertion\"", "URI=\"_assertion\"", 1),
        "ds:SignedInfo",
        "ds:SignatureValue",
    );
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::ReferenceRefused)
    );
}

/// A truncated or empty `DigestValue` is refused.
///
/// # The length check IS the comparison
///
/// The digest comparison folds over `left.iter().zip(right)`, and `zip` stops at the shorter
/// side. So the length equality that precedes it is not a fast path, it is the whole of the
/// check: without it the empty string is a prefix of every digest and compares EQUAL to all of
/// them. Deleting those three lines left `changing_a_signed_value_breaks_the_digest` -- the test
/// whose entire job is this comparison -- green, while a genuinely signed document carrying an
/// empty `DigestValue` verified and handed back the assertion.
///
/// This is "bound satisfied by zero" sitting in the one line that decides whether the digest
/// matched.
#[test]
fn a_digest_that_is_only_a_prefix_of_the_real_one_is_refused() {
    let fixture = Fixture::new();
    let real = fixture
        .document
        .split("<ds:DigestValue>")
        .nth(1)
        .and_then(|rest| rest.split("</ds:DigestValue>").next())
        .expect("the fixture carries a digest")
        .to_owned();

    for (what, forged) in [
        ("an empty digest", String::new()),
        ("a four character prefix", real[..4].to_owned()),
        // NOT "one character short": a 32 byte digest is 44 base64 characters of which the last
        // is padding, so dropping one still decodes to the same 32 bytes. Two is the smallest
        // edit that actually shortens the value, and finding that out is what this row records.
        ("two characters short", real[..real.len() - 2].to_owned()),
    ] {
        // Re-sealed, so the SIGNATURE over SignedInfo is valid and the only thing that can
        // refuse the document is the digest comparison itself.
        let attacked = ironauth_saml::test_util::reseal(
            &fixture.key,
            &fixture.document.replacen(
                &format!("<ds:DigestValue>{real}</ds:DigestValue>"),
                &format!("<ds:DigestValue>{forged}</ds:DigestValue>"),
                1,
            ),
            "ds:SignedInfo",
            "ds:SignatureValue",
        );
        assert_eq!(
            fixture.verify(&attacked),
            Err(VerifyError::SignatureInvalid),
            "{what} must be refused"
        );
    }
}

/// A second element claiming the reference's identifier is refused even when it is not a second
/// candidate.
///
/// # Why the exactly-one-candidate rule does not cover this
///
/// `two_elements_claiming_one_identifier_are_refused` adds a second `saml:Assertion`, so the
/// candidate count refuses it before the identifier logic runs at all. Deleting the duplicate-id
/// guard left that test green. The shape that needs it has ONE candidate: the enclosing
/// `samlp:Response` carrying `ID="_assertion"`. One assertion, one signature, two elements
/// answering `#_assertion` -- and a verifier that resolves the reference by scanning for the id
/// can land on either.
#[test]
fn an_enclosing_element_claiming_the_same_identifier_is_refused() {
    let fixture = Fixture::new();
    // The response already carries `ID="_response"`; ADDING a second `ID` is a duplicate
    // attribute and the parser refuses it as malformed long before any of this. Replacing the
    // value is the shape that reaches the guard.
    let attacked = fixture
        .document
        .replacen(r#"ID="_response""#, r#"ID="_assertion""#, 1);
    assert_ne!(
        attacked, fixture.document,
        "the identifier must actually collide"
    );
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::ReferenceRefused)
    );
}

/// An element called `Signature` in another namespace, as a DIRECT CHILD, is not the signature.
///
/// # Why the two existing tests do not cover this
///
/// `an_element_named_signature_in_another_namespace_is_not_stripped` and
/// `a_nested_signature_is_not_stripped` both splice their decoy inside `<saml:Subject>`, making
/// it a GRANDCHILD. The signature lookup only ever examines DIRECT children, so neither test
/// touches its namespace check: deleting the check left both green.
///
/// Moved up one level, the decoy is a direct child, and without the namespace check the document
/// has two signatures and is refused as having none -- an attacker-supplied denial of service on
/// every assertion, from one element that says nothing.
#[test]
fn a_foreign_signature_as_a_direct_child_is_not_a_signature() {
    let fixture = Fixture::new();
    let decoy = r#"<x:Signature xmlns:x="urn:evil"><x:SignedInfo/></x:Signature>"#;
    // RE-SIGNED. The decoy sits INSIDE the assertion, so it is inside what the digest covers:
    // splicing it into an already-signed document would break the digest and the test would pass
    // for the wrong reason. Re-signing makes it exactly what it claims to be -- ordinary content
    // the identity provider signed, which happens to be called Signature.
    let attacked = ironauth_saml::test_util::resign(
        &fixture.key,
        &fixture
            .document
            .replacen("<saml:Issuer>", &format!("{decoy}<saml:Issuer>"), 1),
    );
    // It verifies: the decoy is not a signature, so there is still exactly one, and the decoy is
    // inside the digest like any other content the identity provider signed.
    let assertion = fixture
        .verify(&attacked)
        .expect("a foreign element named Signature is ordinary content");
    assert_eq!(
        assertion
            .text_of(ironauth_saml::ASSERTION_NS, "NameID")
            .as_deref(),
        Some("victim@example.test")
    );
}

/// A prefix rebound under `SignedInfo` does not make hostile elements answer to XMLDSIG names.
///
/// # The false ACCEPT the scope bug opened
///
/// Every lookup under the signature used to resolve against the scope of the `Signature`
/// element, two levels above the `Reference`'s children. So a document could declare
/// `xmlns:e="http://www.w3.org/2000/09/xmldsig#"` on the `Signature` and REBIND `e` to
/// `urn:evil` on the `SignedInfo`, and `<e:Transforms>`, `<e:DigestMethod>` and
/// `<e:DigestValue>` -- which are then not XMLDSIG elements at all -- were still read as the
/// transform list, the digest algorithm and the digest. A conforming verifier sees a `Reference`
/// with none of those three and rejects the document.
#[test]
fn a_prefix_rebound_under_signed_info_is_not_the_signature_namespace() {
    let fixture = Fixture::new();
    let rebound = fixture
        .document
        .replacen(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            concat!(
                r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" "#,
                r#"xmlns:e="http://www.w3.org/2000/09/xmldsig#">"#
            ),
            1,
        )
        .replacen(
            "<ds:SignedInfo>",
            r#"<ds:SignedInfo xmlns:e="urn:evil">"#,
            1,
        )
        .replace("<ds:Transforms>", "<e:Transforms>")
        .replace("</ds:Transforms>", "</e:Transforms>")
        .replace("<ds:Transform ", "<e:Transform ")
        .replace("<ds:DigestMethod ", "<e:DigestMethod ")
        .replace("<ds:DigestValue>", "<e:DigestValue>")
        .replace("</ds:DigestValue>", "</e:DigestValue>");
    let attacked = ironauth_saml::test_util::reseal(
        &fixture.key,
        &rebound,
        "ds:SignedInfo",
        "ds:SignatureValue",
    );
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::AlgorithmRefused)
    );
}

/// A conforming signature that declares XMLDSIG on `SignedInfo` rather than on `Signature`
/// verifies.
///
/// # The false REJECT the same scope bug caused, and the direction that matters more
///
/// Where a declaration is WRITTEN is not part of a document's meaning: exclusive
/// canonicalization renders a visibly-used declaration on the apex whichever ancestor declared
/// it. So the two documents in this test have byte-identical canonical `SignedInfo`, the same
/// key and the same digest, and the identity provider's `SignatureValue` covers both.
///
/// One of them used to be refused as `AlgorithmRefused` -- "the signature names an algorithm
/// this server refuses" -- which is not merely wrong, it points the operator at an allowlist
/// that was never the problem, and the fix a hurried operator reaches for is to loosen it.
///
/// The assertion on canonical equality is what makes this a test of scope resolution rather than
/// of two unrelated documents.
#[test]
fn a_declaration_on_signed_info_is_in_scope_for_its_children() {
    let fixture = Fixture::new();
    let moved = fixture
        .document
        .replacen(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            r#"<dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">"#,
            1,
        )
        .replacen(
            "<ds:SignedInfo>",
            r#"<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            1,
        )
        .replacen("</ds:Signature>", "</dsig:Signature>", 1)
        .replace("<ds:SignatureValue>", "<dsig:SignatureValue>")
        .replace("</ds:SignatureValue>", "</dsig:SignatureValue>");
    // NOTHING CRYPTOGRAPHIC MOVED: same canonical SignedInfo, so the original signature value
    // still covers it. If this assertion ever fails, the test below proves nothing.
    assert_eq!(
        ironauth_saml::test_util::canonicalize(&fixture.document, "ds:SignedInfo")
            .expect("canonicalises"),
        ironauth_saml::test_util::canonicalize(&moved, "ds:SignedInfo").expect("canonicalises"),
        "the two documents must present the same signed octets"
    );
    let assertion = fixture
        .verify(&moved)
        .expect("a conforming signature must not be refused for where it declares its prefix");
    assert_eq!(
        assertion
            .text_of(ironauth_saml::ASSERTION_NS, "NameID")
            .as_deref(),
        Some("victim@example.test")
    );
}

/// A line-wrapped `SignatureValue` and `DigestValue` decode.
///
/// # The interoperability guard nothing drove
///
/// `xmlsec` and `OpenSAML` wrap base64 at 64 or 76 columns, so almost every real signature
/// arrives with newlines inside it. The decoder skips ASCII whitespace for that reason, and no
/// test fed it any: the crate's own signer emits one unbroken run. With the skip deleted the
/// whole suite stayed green while every wrapped document was refused as `SignatureInvalid`,
/// which reads as a forgery rather than as a decoder that cannot handle a newline.
#[test]
fn a_line_wrapped_base64_value_decodes() {
    let fixture = Fixture::new();
    let wrap = |document: &str, tag: &str| -> String {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = document.find(&open).expect("the tag is present") + open.len();
        let end = document.find(&close).expect("the tag is present");
        let mut wrapped = String::from("\n");
        for (index, byte) in document[start..end].chars().enumerate() {
            if index > 0 && index % 20 == 0 {
                wrapped.push_str("\r\n  ");
            }
            wrapped.push(byte);
        }
        wrapped.push('\n');
        [&document[..start], wrapped.as_str(), &document[end..]].concat()
    };
    // ORDER MATTERS. `DigestValue` lives INSIDE `SignedInfo`, so wrapping it changes the octets
    // the signature covers: it has to be re-sealed before the `SignatureValue` is wrapped in
    // turn. Doing it the other way round produces a document with a genuinely broken signature,
    // which is refused for a reason that has nothing to do with whitespace.
    let wrapped = wrap(
        &ironauth_saml::test_util::reseal(
            &fixture.key,
            &wrap(&fixture.document, "ds:DigestValue"),
            "ds:SignedInfo",
            "ds:SignatureValue",
        ),
        "ds:SignatureValue",
    );
    assert_ne!(
        wrapped, fixture.document,
        "the test must actually wrap something"
    );
    let assertion = fixture
        .verify(&wrapped)
        .expect("a wrapped base64 value is the ordinary case, not a forgery");
    assert_eq!(
        assertion
            .text_of(ironauth_saml::ASSERTION_NS, "NameID")
            .as_deref(),
        Some("victim@example.test")
    );
}

/// Two of anything the signature needs exactly one of is a refusal.
///
/// # "Exactly one" was a documented guarantee with no test
///
/// `SignatureMissing` is documented as "the document carries no signature, or MORE THAN ONE
/// where one was expected", and the child lookup as "the single direct child, if there is
/// exactly one". Both halves could be replaced with "take the first" and the whole suite stayed
/// green: no document in the corpus carried two `ds:Signature` children, two `ds:SignedInfo`,
/// two `ds:DigestValue` or two `ds:SignatureValue`.
///
/// Taking the first is choosing which half of a contradiction to believe, and an attacker who
/// can add an element chooses which half a verifier reads. `SignatureValue` matters most: it
/// sits OUTSIDE `SignedInfo`, so a second one is not covered by the digest at all.
#[test]
fn two_of_anything_the_signature_needs_one_of_is_refused() {
    let fixture = Fixture::new();
    let duplicate = |open: &str, close: &str| -> String {
        let start = fixture.document.find(open).expect("the element is present");
        let end = fixture
            .document
            .find(close)
            .expect("the element is present")
            + close.len();
        let element = &fixture.document[start..end];
        [&fixture.document[..end], element, &fixture.document[end..]].concat()
    };
    for (what, open, close) in [
        ("two signatures", "<ds:Signature ", "</ds:Signature>"),
        ("two SignedInfo", "<ds:SignedInfo>", "</ds:SignedInfo>"),
        ("two DigestValue", "<ds:DigestValue>", "</ds:DigestValue>"),
        (
            "two SignatureValue",
            "<ds:SignatureValue>",
            "</ds:SignatureValue>",
        ),
    ] {
        let attacked = duplicate(open, close);
        assert_ne!(
            attacked, fixture.document,
            "{what} must change the document"
        );
        assert!(
            matches!(
                fixture.verify(&attacked),
                Err(VerifyError::SignatureMissing | VerifyError::ReferenceRefused)
            ),
            "{what} must be refused, got {:?}",
            fixture.verify(&attacked)
        );
    }
}

/// A transform in another namespace, smuggled between the two legitimate ones, is refused.
///
/// # Reading only the elements you recognise is not reading the list
///
/// A conforming verifier applies EVERY child of `Transforms` in order. An allowlist that
/// collects only the `ds:Transform` children compares a list the document does not have: an
/// `<x:Transform xmlns:x="urn:evil">` between them is invisible to the check and visible to
/// every other implementation. So the count of element children must equal the count of real
/// transforms before the sequence is compared at all.
#[test]
fn a_foreign_element_inside_the_transform_list_is_refused() {
    let fixture = Fixture::new();
    let smuggled = fixture.document.replacen(
        "</ds:Transforms>",
        r#"<x:Transform xmlns:x="urn:evil" Algorithm="urn:evil"/></ds:Transforms>"#,
        1,
    );
    let attacked = ironauth_saml::test_util::reseal(
        &fixture.key,
        &smuggled,
        "ds:SignedInfo",
        "ds:SignatureValue",
    );
    assert_eq!(
        fixture.verify(&attacked),
        Err(VerifyError::AlgorithmRefused)
    );
}

/// The error a document gets does not depend on WHICH KEY the deployment pinned.
///
/// # An error that varies with the server's configuration is an oracle
///
/// A previous revision refused a document whose algorithm no pinned anchor could carry with
/// `AlgorithmRefused` rather than `SignatureInvalid`, so that an operator would not read
/// "forgery" about their own identity provider's genuine signature. Both reviewers who looked at
/// it found the same thing: everything ahead of that check is attacker-controlled or
/// self-computable -- the reference digest is UNKEYED, so an attacker computes it over content
/// they wrote -- so an attacker holding no key at all reached it, and three requests naming
/// `#rsa-sha256`, `#ecdsa-sha256` and `#ecdsa-sha384` in turn read the pinned key's kind
/// straight out of which one answered differently.
///
/// It was also wrong about the ORDINARY case: an SP pinning RSA, sent an ECDSA-signed document,
/// was told this server refuses an algorithm it accepts.
///
/// So the contract is the one `VerifyError`'s own doc states -- one variant per DECISION about
/// the DOCUMENT -- and this test is what holds it. The narrowing it replaced (ECDSA is supported
/// for the matched hash/curve pairs only) is recorded in the crate documentation instead, where
/// an operator can find it and an attacker cannot query it.
#[test]
fn the_error_does_not_reveal_which_key_kind_was_pinned() {
    let fixture = Fixture::new();
    let point = |len: usize| {
        let mut point = vec![0x04_u8];
        point.extend(core::iter::repeat_n(0x01_u8, len));
        point
    };
    let elsewhere = [
        ("a P-384 anchor", TrustAnchor::EcdsaP384(point(96))),
        (
            "a different P-256 anchor",
            TrustAnchor::EcdsaP256(point(64)),
        ),
        (
            "an RSA anchor",
            TrustAnchor::Rsa {
                modulus: vec![0x01; 256],
                exponent: vec![0x01, 0x00, 0x01],
            },
        ),
    ];
    for (what, anchor) in elsewhere {
        assert_eq!(
            verify(
                fixture.document.as_bytes(),
                &Limits::default(),
                &[anchor],
                ironauth_saml::ASSERTION_NS,
                "Assertion",
            ),
            Err(VerifyError::SignatureInvalid),
            "{what} must give the same answer as every other wrong key"
        );
    }
    // CONTROL: the right key still verifies, so the sameness above is not "everything fails".
    assert!(fixture.verify(&fixture.document).is_ok());
}

/// A namespace declaration the digest never covered is not visible through `Debug` either.
///
/// # Closing the accessor without closing the formatter closes nothing
///
/// Exclusive canonicalization emits only the declarations a subtree visibly USES, so an unused
/// `xmlns:evil="..."` on the assertion is not digested -- which is why the document below
/// verifies. The accessor refuses to return it. The DERIVED `Debug` printed it, so one
/// `format!("{assertion:?}")` into a log line or an error message handed the same undigested
/// attacker-controlled bytes to a reader who believes everything in a `VerifiedAssertion` was
/// signed.
#[test]
fn a_namespace_declaration_is_not_visible_through_debug() {
    let fixture = Fixture::new();
    let payload = "urn:undigested-attacker-payload";
    let attacked = fixture.document.replacen(
        r#"<saml:Assertion ID="_assertion""#,
        &format!(r#"<saml:Assertion xmlns:evil="{payload}" ID="_assertion""#),
        1,
    );
    let assertion = fixture
        .verify(&attacked)
        .expect("an unused declaration is not digested, so the document still verifies");
    assert_eq!(assertion.attribute("xmlns:evil"), None);
    let rendered = format!("{assertion:?}");
    assert!(
        !rendered.contains(payload),
        "Debug must not render an undigested declaration: {rendered}"
    );
}

// ---------------------------------------------------------------------------------------------
// THE COMMENT-TRUNCATION CORPUS (issue #138, criterion 2).
//
// CVE-2017-11427 and the batch around it (Duo's "Duo Finds SAML Vulnerabilities Affecting
// Multiple Implementations", February 2018) are all one bug with one shape. Canonicalization
// REMOVES comments, so the digest is taken over the joined text: `user@evil.com<!--x-->.
// example.com` digests as one string. The consumer then asked a DOM for the element's text and
// got only the FIRST text node, `user@evil.com`. Signature valid, identity different. It hit
// OneLogin, Clever, OmniAuth, Shibboleth and python-saml independently, because every one of
// them used a different component for each half.
//
// The answer here is two independent mechanisms, and it is worth being exact about them because
// the tidy version of this paragraph is false. Comments never become nodes, so a run split by
// one stays a single text node; AND the text accessor concatenates every text child, so it
// would join them even if they were two. MUTATION SHOWS NEITHER IS LOAD-BEARING ALONE: breaking
// either one leaves this corpus green, and only breaking BOTH makes it fail. That is defence in
// depth, not a single structural guarantee, and a reader who came here to find the one line
// that stops the attack should know there is not one.
//
// What the corpus pins is therefore the OBSERVABLE property, which is the one a caller can rely
// on: a signed value split by a comment reads back FULL and UNSPLIT.
// ---------------------------------------------------------------------------------------------

/// A comment inside a signed `NameID` does not truncate the value.
///
/// # Both directions, and the second is the one that catches a half fix
///
/// The first case is the attack as published: a document signed over `victim@example.test` with
/// a comment spliced into the middle afterwards. The digest is over the joined text either way,
/// so it still verifies -- and the value read back must be the WHOLE string, not the part before
/// the comment.
///
/// The second case is the same document RE-SIGNED with the comment in place, which is what an
/// identity provider that pretty-prints its output actually emits. A crate that refused comments
/// outright would pass the first case and break the second.
#[test]
fn a_comment_inside_a_signed_value_does_not_truncate_it() {
    let fixture = Fixture::new();
    let split = fixture.document.replacen(
        "victim@example.test",
        "victim<!-- comment -->@example.test",
        1,
    );

    // (a) SPLICED IN AFTER SIGNING. The comment is not part of the canonical form, so the
    // identity provider's digest still covers exactly the text that is read back.
    let assertion = fixture
        .verify(&split)
        .expect("a comment is not part of the digest, so the document still verifies");
    assert_eq!(
        assertion
            .text_of(ironauth_saml::ASSERTION_NS, "NameID")
            .as_deref(),
        Some("victim@example.test"),
        "the value must be the full string, not the part before the comment"
    );

    // (b) RE-SIGNED with the comment in place.
    let resigned = ironauth_saml::test_util::resign(&fixture.key, &split);
    assert_eq!(
        fixture
            .verify(&resigned)
            .expect("a re-signed document with a comment in it verifies")
            .text_of(ironauth_saml::ASSERTION_NS, "NameID")
            .as_deref(),
        Some("victim@example.test")
    );
}

/// Every place a comment can be written inside a signed value reads back whole.
///
/// # Why the positions are enumerated rather than sampled
///
/// The published exploits differ only in WHERE the comment sits, because each targeted a
/// different consumer's idea of "the first text node": before the value, in the middle, at the
/// end, several at once, and one immediately after the start tag. A crate that joined text
/// across a comment in the middle but not at the edges would pass a single-position test.
///
/// The control at the end is what makes the rest mean something: changing the text PAST the
/// comment must break the digest. Without it, a verifier that returned a constant would pass
/// every row above.
#[test]
fn a_comment_anywhere_in_a_signed_value_reads_back_whole() {
    let fixture = Fixture::new();
    for (what, spliced) in [
        ("before the value", "<!--c-->victim@example.test"),
        ("in the middle", "victim@<!--c-->example.test"),
        ("at the end", "victim@example.test<!--c-->"),
        ("twice", "vic<!--c-->tim@exam<!--c-->ple.test"),
        ("an empty comment", "victim@<!---->example.test"),
    ] {
        let document = fixture.document.replacen("victim@example.test", spliced, 1);
        let assertion = fixture
            .verify(&document)
            .unwrap_or_else(|error| panic!("{what}: {error:?}"));
        assert_eq!(
            assertion
                .text_of(ironauth_saml::ASSERTION_NS, "NameID")
                .as_deref(),
            Some("victim@example.test"),
            "{what}"
        );
    }

    // CONTROL: the digest really is covering this text.
    let tampered =
        fixture
            .document
            .replacen("victim@example.test", "victim@<!--c-->attacker.test", 1);
    assert_eq!(
        fixture.verify(&tampered),
        Err(VerifyError::SignatureInvalid),
        "changing the text past a comment must break the digest"
    );
}

/// A second assertion under a DIFFERENT PREFIX but the SAME namespace is refused.
///
/// # A prefix is not an identity, and treating it as one was a bypass
///
/// The exactly-one-candidate rule is this crate's first wrapping defence, and it used to compare
/// the RAW QUALIFIED NAME. So it was a rule about prefix SPELLING: the identity provider's
/// genuinely signed `<saml:Assertion>` plus an attacker's unsigned
/// `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">` was reported as
/// carrying exactly ONE assertion and verified, while the byte-identical document spelling the
/// second one `saml:` was refused. Two prefixes bound to one URI name one thing.
///
/// The two arms below are the same document differing ONLY in the second assertion's prefix, so
/// a verifier that still keys on spelling fails exactly one of them.
#[test]
fn a_second_assertion_under_another_prefix_is_still_a_second_assertion() {
    let fixture = Fixture::new();
    for (what, forged) in [
        (
            "the same prefix",
            concat!(
                r#"<saml:Assertion ID="_forged"><saml:Subject>"#,
                "<saml:NameID>attacker@evil.test</saml:NameID>",
                "</saml:Subject></saml:Assertion>"
            ),
        ),
        (
            "a different prefix bound to the same namespace",
            concat!(
                r#"<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" "#,
                r#"ID="_forged"><saml2:Subject>"#,
                "<saml2:NameID>attacker@evil.test</saml2:NameID>",
                "</saml2:Subject></saml2:Assertion>"
            ),
        ),
    ] {
        let attacked = fixture.document.replacen(
            "</samlp:Response>",
            &format!("{forged}</samlp:Response>"),
            1,
        );
        assert_eq!(
            fixture.verify(&attacked),
            Err(VerifyError::ReferenceRefused),
            "{what}"
        );
    }

    // AND THE OTHER HALF: an element with the same LOCAL name in a DIFFERENT namespace is not a
    // candidate at all, so it must not be refused. Without this the fix would be "refuse
    // anything called Assertion", which breaks every document carrying an unrelated element of
    // that name.
    let unrelated = r#"<x:Assertion xmlns:x="urn:unrelated" ID="_other"/>"#;
    let benign = fixture.document.replacen(
        "</samlp:Response>",
        &format!("{unrelated}</samlp:Response>"),
        1,
    );
    assert!(
        fixture.verify(&benign).is_ok(),
        "an element of the same local name in another namespace is not an assertion"
    );
}

/// An `InclusiveNamespaces` prefix list is refused, on the canonicalization method and on the
/// transform.
///
/// # Both refusals existed and neither had a test
///
/// Exclusive canonicalization with a `PrefixList` emits a DIFFERENT set of declarations, so a
/// verifier that ignores the list digests under rules the signer did not use and rejects a valid
/// signature -- or, with the tables turned, accepts one it should not. `VerifyError`'s own doc
/// names this refusal explicitly. Both places it is implemented could be deleted with the whole
/// suite still green, and each document below then verified.
///
/// Refusing is the honest answer: this crate does not implement prefix lists, and pretending to
/// honour one would compute a different digest from the signer.
#[test]
fn an_inclusive_namespaces_prefix_list_is_refused() {
    let fixture = Fixture::new();
    let list = concat!(
        r#"<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" "#,
        r#"PrefixList="saml"/>"#
    );
    for (what, before, after) in [
        (
            "on the canonicalization method",
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
            format!(
                r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">{list}</ds:CanonicalizationMethod>"#
            ),
        ),
        (
            "on the exclusive transform",
            r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
            format!(
                r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">{list}</ds:Transform>"#
            ),
        ),
    ] {
        let edited = fixture.document.replacen(before, &after, 1);
        assert_ne!(edited, fixture.document, "{what} must change the document");
        // Re-sealed, so the signature over SignedInfo is genuine and the refusal is about the
        // prefix list rather than about a signature the edit broke.
        let attacked = ironauth_saml::test_util::reseal(
            &fixture.key,
            &edited,
            "ds:SignedInfo",
            "ds:SignatureValue",
        );
        assert_eq!(
            fixture.verify(&attacked),
            Err(VerifyError::AlgorithmRefused),
            "{what}"
        );
    }
}

/// A `ds:Transform` with no `Algorithm` does not vanish from the list that is compared.
///
/// # The combinator was the bug
///
/// The allowlist is over a SEQUENCE, and it was built with `filter_map`, which silently DROPS a
/// transform carrying no unprefixed `Algorithm`. That element is a real `ds:Transform`, so it
/// was counted on both sides of the element-count guard added for the foreign-namespace case,
/// and then disappeared before the comparison: a three-transform list compared equal to the
/// two-element allowlist and the document verified.
///
/// `Algorithm` is `use="required"` in the XMLDSIG schema, so every other implementation refuses
/// these documents. That is the accept-more asymmetry the count guard was added for, moved from
/// a foreign namespace into the XMLDSIG one.
#[test]
fn a_transform_without_an_algorithm_is_refused() {
    let fixture = Fixture::new();
    let enveloped =
        r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>"#;
    for (what, extra) in [
        ("no Algorithm attribute at all", "<ds:Transform/>"),
        (
            "a PREFIXED Algorithm attribute",
            r#"<ds:Transform ds:Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/>"#,
        ),
    ] {
        let edited = fixture
            .document
            .replacen(enveloped, &format!("{enveloped}{extra}"), 1);
        assert_ne!(edited, fixture.document, "{what} must change the document");
        let attacked = ironauth_saml::test_util::reseal(
            &fixture.key,
            &edited,
            "ds:SignedInfo",
            "ds:SignatureValue",
        );
        assert_eq!(
            fixture.verify(&attacked),
            Err(VerifyError::AlgorithmRefused),
            "{what}"
        );
    }
}

/// Bytes after the base64 padding are refused.
///
/// # A second encoding of the same signature
///
/// `SignatureValue` sits OUTSIDE `SignedInfo`, so no digest and no signature covers it. The
/// decoder used to stop at the first `=` and never look at the rest, so one captured response
/// could be minted into unboundedly many byte-distinct documents that all verify. That is the
/// same property this crate refuses ECDSA DER for: a verifier that accepts a second encoding of
/// one signature accepts a document its own audit trail cannot tell apart.
///
/// Whitespace after the padding is still fine, because that is what a line-wrapped value looks
/// like.
#[test]
fn bytes_after_the_base64_padding_are_refused() {
    let fixture = Fixture::new();
    let start = fixture
        .document
        .find("<ds:SignatureValue>")
        .expect("the fixture is signed")
        + "<ds:SignatureValue>".len();
    let end = fixture
        .document
        .find("</ds:SignatureValue>")
        .expect("the fixture is signed");
    let value = &fixture.document[start..end];
    assert!(value.ends_with('='), "the fixture value must carry padding");

    for suffix in ["QUJD", "ZZZZZZZZ", "aGVsbG8"] {
        let attacked = [&fixture.document[..end], suffix, &fixture.document[end..]].concat();
        assert_eq!(
            fixture.verify(&attacked),
            Err(VerifyError::SignatureInvalid),
            "trailing {suffix} must be refused"
        );
    }

    // CONTROL: whitespace after the padding is a line-wrapped value, not a second encoding.
    let wrapped = [&fixture.document[..end], "\n  ", &fixture.document[end..]].concat();
    assert!(
        fixture.verify(&wrapped).is_ok(),
        "whitespace after the padding is the ordinary wrapped form"
    );
}

/// AN UNSIGNED ASSERTION IS REFUSED. This is the most basic control there is, and until now
/// nothing in this crate drove it.
///
/// # How a suite of 81 tests missed it
///
/// Every `verify` call site in the test tree starts from `Fixture::new()`, `signed_response`,
/// `resign` or `reseal` -- documents that ARE signed. So no test ever fed `verify` a document
/// with no signature at all, and a reviewer showed the consequence by mutating the refusal into
/// `Ok(..)`: every one of the 81 tests stayed green while an entirely unsigned response read its
/// `NameID` back as though verified. Authenticate as anyone, with no key at all.
///
/// The three arms are the three shapes of "not signed HERE", because the interesting failures
/// are the ones where a signature exists somewhere and a verifier is tempted to count it:
/// none at all, one on the enclosing `Response` instead, and one buried deeper in the assertion
/// rather than as its child.
#[test]
fn an_assertion_with_no_signature_of_its_own_is_refused() {
    let fixture = Fixture::new();
    let bare = concat!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
        r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response">"#,
        r#"<saml:Assertion ID="_assertion"><saml:Issuer>urn:idp</saml:Issuer>"#,
        "<saml:Subject><saml:NameID>attacker@evil.test</saml:NameID></saml:Subject>",
        "</saml:Assertion></samlp:Response>"
    );
    assert_eq!(
        fixture.verify(bare),
        Err(VerifyError::SignatureMissing),
        "an assertion with no signature must not verify"
    );

    // The identity provider's real signature, moved OUT of the assertion and onto the response.
    // It no longer covers the assertion, and a verifier that searches the document for "a
    // signature" rather than for THIS element's signature would count it.
    let start = fixture
        .document
        .find("<ds:Signature")
        .expect("the fixture is signed");
    let end = fixture
        .document
        .find("</ds:Signature>")
        .expect("the fixture is signed")
        + "</ds:Signature>".len();
    let signature = &fixture.document[start..end];
    let moved = [&fixture.document[..start], &fixture.document[end..]]
        .concat()
        .replacen(
            "</samlp:Response>",
            &format!("{signature}</samlp:Response>"),
            1,
        );
    assert_eq!(
        fixture.verify(&moved),
        Err(VerifyError::SignatureMissing),
        "a signature on the response is not a signature on the assertion"
    );

    // And one nested a level deeper than a child, which is where XSW puts a signature it wants a
    // verifier to find and a reader to ignore.
    let buried = [&fixture.document[..start], &fixture.document[end..]]
        .concat()
        .replacen("<saml:Subject>", &format!("<saml:Subject>{signature}"), 1);
    assert_eq!(
        fixture.verify(&buried),
        Err(VerifyError::SignatureMissing),
        "a signature nested below the assertion is not the assertion's signature"
    );
}

/// A verified assertion carries NO `ds:Signature` child, because the enveloped transform removed
/// exactly the one it had.
///
/// # The historical bug as an invariant
///
/// The authenticate-as-anyone defect this crate shipped and fixed digested a stripped copy and
/// returned the ORIGINAL subtree, which still had its `Signature` child with the attacker's
/// forged content hidden inside. Stating the invariant directly is what lets the fuzz target
/// check it on every input it reaches the accept path with.
///
/// DIRECT children, not descendants, and that distinction is load-bearing: a signature deeper in
/// the tree can be perfectly legitimate. A `saml:Advice` carrying a signed assertion has one, and
/// so does every assertion inside a Response that was itself signed. An earlier fuzz assertion
/// used a descendant search and died on the ordinary Okta document that signs both.
#[test]
fn a_verified_assertion_carries_no_signature_child() {
    let fixture = Fixture::new();
    let assertion = fixture
        .verify(&fixture.document)
        .expect("the fixture verifies");
    assert_eq!(
        assertion.child_count("http://www.w3.org/2000/09/xmldsig#", "Signature"),
        0
    );
    // AND THE COUNT IS NOT ZERO BECAUSE IT COUNTS NOTHING. The control names an element the
    // signed assertion really does have, so a `child_count` that always answered zero would fail
    // here.
    assert_eq!(
        assertion.child_count(ironauth_saml::ASSERTION_NS, "Subject"),
        1
    );
    assert_eq!(
        assertion.child_count(ironauth_saml::ASSERTION_NS, "Issuer"),
        1
    );

    // AND IT COUNTS DIRECT CHILDREN, NOT DESCENDANTS. `NameID` is inside `Subject`, so a
    // descendant walk answers 1 and this answers 0.
    //
    // This probe is the only one that separates the two implementations, and without it swapping
    // `Scoped::children` for the descendant `collect` passed every test in the crate -- while
    // bringing back the crash the whole round-2 fix was for, because the ordinary Okta document
    // that signs the Response AND the assertion has a `ds:Signature` at depth two inside the
    // verified Response.
    assert_eq!(
        assertion.child_count(ironauth_saml::ASSERTION_NS, "NameID"),
        0,
        "child_count must count DIRECT children; NameID is a grandchild"
    );

    // The mirror, so the row above cannot pass by counting nothing at that depth either.
    let subject_reachable = assertion
        .text_of(ironauth_saml::ASSERTION_NS, "NameID")
        .is_some();
    assert!(
        subject_reachable,
        "the grandchild must be reachable by a DESCENDANT accessor, or the previous assertion \
         proves only that the element is absent"
    );
}

/// THE ORDINARY OKTA AND ADFS DOCUMENT: the Response and the assertion inside it are both
/// signed, and both verify.
///
/// # The document three doc comments argued about and nothing built
///
/// It is the reason `child_count` counts DIRECT children. Verifying the Response returns a
/// subtree that still contains the assertion's whole signature -- legitimately, because the
/// Response signature covered it -- so a DESCENDANT count answers one there, and a verifier that
/// used one would refuse the commonest document in the field. A fuzz assertion did exactly that
/// and crashed on it.
///
/// Until now nothing in this crate could build one, so the property was asserted in prose and
/// measured by nothing. Both directions are checked here: each level verifies on its own terms,
/// and each returns a subtree with no signature CHILD while the Response still contains the
/// assertion's signature further down.
#[test]
fn a_response_and_its_assertion_can_both_be_signed() {
    let key = XmlTestKey::generate();
    let anchors = vec![TrustAnchor::EcdsaP256(key.public_point())];
    let inner = ironauth_saml::test_util::signed_response(&key, "_assertion");
    let both = ironauth_saml::test_util::sign_response(&key, &inner);
    let check = |namespace: &str, local: &str| {
        verify(
            both.as_bytes(),
            &Limits::default(),
            &anchors,
            namespace,
            local,
        )
    };

    let assertion = check(ironauth_saml::ASSERTION_NS, "Assertion")
        .expect("the assertion verifies under its own signature");
    assert_eq!(
        assertion
            .text_of(ironauth_saml::ASSERTION_NS, "NameID")
            .as_deref(),
        Some("victim@example.test")
    );
    assert_eq!(assertion.child_count(DSIG_NS, "Signature"), 0);

    let response = check(ironauth_saml::PROTOCOL_NS, "Response")
        .expect("the response verifies under the response signature");
    assert_eq!(response.name(), "samlp:Response");
    // ITS OWN signature is gone, and the assertion's is still there. That pair is the whole
    // point: the first is what the enveloped transform removes, the second is content the
    // response signature covered.
    assert_eq!(response.child_count(DSIG_NS, "Signature"), 0);
    assert_eq!(
        response.child_count(ironauth_saml::ASSERTION_NS, "Assertion"),
        1
    );
    assert!(
        response.text_of(DSIG_NS, "SignatureValue").is_some(),
        "the assertion's signature must still be inside the verified response"
    );

    // AND THE CONTROL: a stranger's key verifies neither level, so the two accepts above are
    // about the signature rather than about the document being well formed.
    let stranger = XmlTestKey::generate();
    let stranger_anchors = vec![TrustAnchor::EcdsaP256(stranger.public_point())];
    for (namespace, local) in [
        (ironauth_saml::ASSERTION_NS, "Assertion"),
        (ironauth_saml::PROTOCOL_NS, "Response"),
    ] {
        assert_eq!(
            verify(
                both.as_bytes(),
                &Limits::default(),
                &stranger_anchors,
                namespace,
                local
            ),
            Err(VerifyError::SignatureInvalid),
            "{local} must not verify under a key that signed nothing"
        );
    }
}

#[test]
fn the_signed_elements_own_name_answers_on_both_axes() {
    // `VerifiedAssertion::is` EXISTS BECAUSE `name()` HANDS BACK A SPELLING. A caller that tested
    // the qualified name was testing a prefix, which is the bypass this file's own wrapping tests
    // are about, one layer up: the condition layer's assertion gate was
    // `name().ends_with("Assertion")`.
    //
    // Both axes are asserted here rather than only through that gate, because the gate asks one
    // fixed question -- is this `{SAML}Assertion` -- and a version of `is` that ignored its
    // `local` argument entirely would answer it correctly every time while being wrong for every
    // other caller.
    let key = XmlTestKey::generate();
    let document = ironauth_saml::test_util::signed_element_with(
        &key,
        "evil:Assertion",
        r#" xmlns:evil="urn:evil""#,
        "_assertion",
        "<evil:Subject/>",
    );
    let anchors = [TrustAnchor::EcdsaP256(key.public_point())];
    let signed = verify(
        document.as_bytes(),
        &Limits::default(),
        &anchors,
        "urn:evil",
        "Assertion",
    )
    .expect("the fixture must verify, or this test measures nothing");

    assert!(
        signed.is("urn:evil", "Assertion"),
        "the element did not answer to its own resolved name"
    );
    // THE NAMESPACE AXIS: the same local name under the namespace this crate actually trusts.
    assert!(
        !signed.is(ironauth_saml::ASSERTION_NS, "Assertion"),
        "an element in a namespace nobody trusts answered to the SAML assertion namespace"
    );
    // THE LOCAL-NAME AXIS: the right namespace, a name it does not have.
    assert!(
        !signed.is("urn:evil", "Response"),
        "the element answered to a local name that is not its own"
    );
    // AND THE SPELLING IS NOT THE IDENTITY, which is the whole point:
    assert_eq!(signed.name(), "evil:Assertion");
}
