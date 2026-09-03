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

/// The key, the anchor, and a document that really verifies.
struct Fixture {
    anchors: Vec<TrustAnchor>,
    document: String,
}

impl Fixture {
    fn new() -> Self {
        let key = XmlTestKey::generate();
        let document = ironauth_saml::test_util::signed_response(&key, "_assertion");
        Self {
            anchors: vec![TrustAnchor::EcdsaP256(key.public_point())],
            document,
        }
    }

    /// Verify a document against this fixture's pinned key.
    fn verify(&self, document: &str) -> Result<ironauth_saml::VerifiedAssertion, VerifyError> {
        verify(
            document.as_bytes(),
            &Limits::default(),
            &self.anchors,
            "saml:Assertion",
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
        assertion.text_of("saml:NameID").as_deref(),
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
            "saml:Assertion"
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
        "saml:Assertion",
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
            "saml:Assertion"
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
        assertion.text_of("saml:NameID").as_deref(),
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
        assertion.text_of("saml:AttributeValue"),
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
        "saml:Assertion",
    )
    .expect("a document with two NameIDs is signed like any other");
    assert_eq!(
        assertion.text_of("saml:NameID"),
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
            "saml:Assertion",
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
