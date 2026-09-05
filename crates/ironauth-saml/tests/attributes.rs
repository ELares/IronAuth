// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an assertion says about the person, over documents that GENUINELY VERIFY.
//!
//! Every fixture here is signed by a pinned key and read back through the real `verify`, for the
//! reason the condition suite gives: a test whose document failed to verify would be measuring
//! nothing and would keep passing after the thing it names was deleted.
//!
//! # The shapes this file is actually about
//!
//! An `AttributeStatement` is the one part of an assertion an identity provider changes without
//! telling anybody, so the interesting cases are not malformed documents -- they are conformant
//! ones this crate has to keep reading the same way:
//!
//! - the same `Name` sent twice, which is a contradiction and not a longer list;
//! - an `AttributeValue` holding ELEMENTS, which `xs:anyType` permits and Entra emits;
//! - an attribute with NO values, which is how a directory says a field was cleared;
//! - attributes nested inside somebody else's assertion, which are inside this signature too.
//!
//! Needs no database.

use ironauth_jose::xmldsig::test_util::XmlTestKey;
use ironauth_saml::{ASSERTION_NS, Attribute, Limits, TrustAnchor, Value, attributes, verify};

const EMAIL: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
const GROUPS: &str = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups";
const BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

/// Sign these assertion children, verify, and read the attributes.
fn read(children: &str) -> Result<Vec<Attribute>, ironauth_saml::Ambiguous> {
    let key = XmlTestKey::generate();
    let document = ironauth_saml::test_util::signed_response_with(&key, "_assertion", children);
    let anchors = [TrustAnchor::EcdsaP256(key.public_point())];
    let assertion = verify(
        document.as_bytes(),
        &Limits::default(),
        &anchors,
        ASSERTION_NS,
        "Assertion",
    )
    .expect("the fixture's signature must verify, or this test measures nothing");
    attributes(&assertion)
}

/// An assertion body with `statements` after the issuer.
fn body(statements: &str) -> String {
    format!("<saml:Issuer>urn:idp</saml:Issuer>{statements}")
}

#[test]
fn an_ordinary_statement_reads_in_document_order_with_its_formats() {
    let found = read(&body(&format!(
        "<saml:AttributeStatement>\
         <saml:Attribute Name=\"{EMAIL}\" NameFormat=\"{BASIC}\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue>\
         </saml:Attribute>\
         <saml:Attribute Name=\"{GROUPS}\">\
         <saml:AttributeValue>engineering</saml:AttributeValue>\
         <saml:AttributeValue>oncall</saml:AttributeValue>\
         </saml:Attribute>\
         </saml:AttributeStatement>"
    )))
    .expect("an ordinary statement");

    assert_eq!(found.len(), 2, "an attribute was dropped or invented");
    assert_eq!(found[0].name, EMAIL, "document order was not preserved");
    assert_eq!(found[0].name_format.as_deref(), Some(BASIC));
    assert_eq!(
        found[0].values,
        vec![Value::Text("ada@globex.example".to_owned())]
    );

    assert_eq!(found[1].name, GROUPS);
    assert_eq!(
        found[1].name_format, None,
        "an absent NameFormat was defaulted, so 'the provider said unspecified' and 'the \
         provider said nothing' became the same answer"
    );
    assert_eq!(
        found[1].values,
        vec![
            Value::Text("engineering".to_owned()),
            Value::Text("oncall".to_owned())
        ],
        "the values of a multi-valued attribute lost their order or their count"
    );
}

#[test]
fn several_statements_are_one_list_and_no_statement_is_an_empty_one() {
    // SAML PERMITS SEVERAL `AttributeStatement`s, and an identity provider that assembles a
    // response from two sources emits exactly that. They are one list of attributes, not two
    // sets of them, and reading only the first would silently drop half.
    let two = read(&body(&format!(
        "<saml:AttributeStatement>\
         <saml:Attribute Name=\"{EMAIL}\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>\
         <saml:AttributeStatement>\
         <saml:Attribute Name=\"{GROUPS}\">\
         <saml:AttributeValue>engineering</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>"
    )))
    .expect("two statements");
    assert_eq!(two.len(), 2, "a second AttributeStatement was ignored");

    // AND NO STATEMENT AT ALL IS NOT AN ERROR. An assertion carrying only an `AuthnStatement` is
    // ordinary -- it is what a provider sends when the relying party asked for nothing -- so
    // refusing it would refuse a conformant sign-in for saying nothing extra.
    let none = read(&body(
        "<saml:AuthnStatement AuthnInstant=\"2026-01-01T00:00:00Z\"/>",
    ))
    .expect("an assertion with no attributes at all");
    assert!(none.is_empty(), "an empty list was not empty");
}

#[test]
fn an_attribute_with_no_values_is_not_the_same_as_an_absent_attribute() {
    // A DIRECTORY THAT CLEARS A FIELD SENDS THE ATTRIBUTE WITH NO VALUES. Collapsing that into
    // "not sent" loses the difference between "we do not know their department" and "they have
    // none", and a mapping that reuses a stored value on absence would then keep a department
    // the identity provider just removed.
    let found = read(&body(&format!(
        "<saml:AttributeStatement><saml:Attribute Name=\"{GROUPS}\"/>\
         </saml:AttributeStatement>"
    )))
    .expect("an attribute with no values");
    assert_eq!(found.len(), 1, "an empty attribute was dropped");
    assert!(found[0].values.is_empty());
}

#[test]
fn the_same_name_sent_twice_is_a_contradiction_and_not_a_longer_list() {
    // SAML CORE 2.7.3.1 PUTS AN ATTRIBUTE'S VALUES IN ONE `Attribute` ELEMENT, so a second one
    // with the same `Name` is a second CLAIM about that name. Taking either is choosing which
    // half to believe, and somebody who can append chooses for the reader -- the rule this crate
    // applies to `Conditions`, `Subject` and `Issuer` for exactly the same reason.
    //
    // The two carry DIFFERENT values, so a reader that concatenated them and one that took
    // either would each produce something, and all three answers differ.
    let refused = read(&body(&format!(
        "<saml:AttributeStatement>\
         <saml:Attribute Name=\"{EMAIL}\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue></saml:Attribute>\
         <saml:Attribute Name=\"{EMAIL}\">\
         <saml:AttributeValue>attacker@evil.example</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>"
    )));
    let Err(ambiguous) = &refused else {
        panic!("an assertion claiming two emails had one of them believed: {refused:?}");
    };
    assert_eq!(
        ambiguous.name.as_deref(),
        Some(EMAIL),
        "the refusal did not name the attribute an operator has to look at"
    );

    // ACROSS TWO STATEMENTS TOO, which is how it arrives when a provider merges two sources and
    // is the case a per-statement check would miss.
    let split = read(&body(&format!(
        "<saml:AttributeStatement><saml:Attribute Name=\"{EMAIL}\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>\
         <saml:AttributeStatement><saml:Attribute Name=\"{EMAIL}\">\
         <saml:AttributeValue>attacker@evil.example</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>"
    )));
    assert!(
        split.is_err(),
        "the same Name in two statements was read as two attributes"
    );

    // AND THE CONTROL: two DIFFERENT names in one statement are two attributes, so the refusal
    // above is about the name and not about there being two of anything.
    let distinct = read(&body(&format!(
        "<saml:AttributeStatement>\
         <saml:Attribute Name=\"{EMAIL}\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue></saml:Attribute>\
         <saml:Attribute Name=\"{GROUPS}\">\
         <saml:AttributeValue>engineering</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>"
    )));
    assert_eq!(distinct.expect("two distinct names").len(), 2);
}

#[test]
fn an_attribute_with_no_name_is_refused_rather_than_dropped() {
    // `Name` IS REQUIRED AND IS WHAT A MAPPING KEYS ON, so an attribute without one could never
    // be reached. Dropping it silently would hide a misconfiguration behind a trait that is
    // simply never populated -- and the operator would go looking at their mapping, which is
    // fine, rather than at their identity provider, which is where the fault is.
    let refused = read(&body(
        "<saml:AttributeStatement>\
         <saml:Attribute><saml:AttributeValue>x</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>",
    ));
    let Err(ambiguous) = &refused else {
        panic!("a nameless attribute was silently dropped: {refused:?}");
    };
    assert_eq!(ambiguous.name, None);
}

#[test]
fn a_value_carrying_elements_is_reported_as_structured_and_not_flattened() {
    // `AttributeValue` IS `xs:anyType`, so a conformant assertion may put a subtree in one --
    // Entra does for some claim types, and `saml:NameID` inside an `AttributeValue` is common
    // enough to have its own interoperability notes.
    //
    // CONCATENATING ITS DESCENDANTS WOULD INVENT A VALUE. `<a>x</a><b>y</b>` gives "xy", which
    // no other reader produces and which a mapping would then write into somebody's profile.
    let found = read(&body(&format!(
        "<saml:AttributeStatement><saml:Attribute Name=\"{GROUPS}\">\
         <saml:AttributeValue>engineering</saml:AttributeValue>\
         <saml:AttributeValue><saml:NameID>ada@globex.example</saml:NameID></saml:AttributeValue>\
         </saml:Attribute></saml:AttributeStatement>"
    )))
    .expect("a structured value is not a refusal");
    assert_eq!(
        found[0].values,
        vec![Value::Text("engineering".to_owned()), Value::Structured],
        "a structured value was flattened into text, or dropped so the text values shifted"
    );

    // THE POSITION MATTERS, which is why the text value is beside it: a caller skipping the
    // structured one must still see `engineering` as the FIRST value, not the only one.
    assert_eq!(found[0].values.len(), 2);
}

#[test]
fn an_attribute_statement_inside_a_value_belongs_to_whoever_wrote_it() {
    // THE DEFECT THE CONDITION LAYER PAID FOR THREE TIMES, in the one place it is easiest to
    // reach: `AttributeValue` is `xs:anyType`, so an assertion may legitimately carry an entire
    // `AttributeStatement` inside one -- and it is inside this signature just as much as the
    // real one. A descendant search collects both, and the nested attributes then arrive as
    // though the identity provider had asserted them.
    //
    // The nested statement here claims the SAME names with different values, so a descendant
    // search does not merely add attributes: it produces the ambiguity refusal, and this
    // assertion would be rejected outright.
    let found = read(&body(&format!(
        "<saml:AttributeStatement><saml:Attribute Name=\"{EMAIL}\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue>\
         </saml:Attribute>\
         <saml:Attribute Name=\"{GROUPS}\"><saml:AttributeValue>\
         <saml:AttributeStatement><saml:Attribute Name=\"{EMAIL}\">\
         <saml:AttributeValue>attacker@evil.example</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement></saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>"
    )))
    .expect("a nested statement is not this assertion's problem");

    assert_eq!(found.len(), 2, "a nested AttributeStatement was collected");
    assert_eq!(
        found[0].values,
        vec![Value::Text("ada@globex.example".to_owned())],
        "the nested email displaced the real one"
    );
    assert_eq!(
        found[1].values,
        vec![Value::Structured],
        "the nested statement was read as text rather than left alone"
    );
}

#[test]
fn an_attribute_in_a_foreign_namespace_is_not_this_assertions_attribute() {
    // THE ALLOWLIST LESSON FROM THE CONDITION LAYER: a name is a namespace AND a local name, and
    // an element called `Attribute` bound to a namespace nobody trusts is not a SAML attribute.
    // Reading it would let anything that can add an element to a signed document add a claim.
    let found = read(&body(&format!(
        "<saml:AttributeStatement xmlns:evil=\"urn:evil\">\
         <saml:Attribute Name=\"{EMAIL}\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue></saml:Attribute>\
         <evil:Attribute Name=\"{GROUPS}\">\
         <evil:AttributeValue>admins</evil:AttributeValue></evil:Attribute>\
         </saml:AttributeStatement>"
    )))
    .expect("a foreign element beside a real attribute");
    assert_eq!(
        found.len(),
        1,
        "an element merely NAMED Attribute became one of this assertion's attributes"
    );
    assert_eq!(found[0].name, EMAIL);

    // AND A FOREIGN STATEMENT WRAPPING A REAL ATTRIBUTE is not a statement either: the elements
    // inside it are conformant SAML, and what makes them somebody else's is their parent.
    let wrapped = read(&body(&format!(
        "<evil:AttributeStatement xmlns:evil=\"urn:evil\">\
         <saml:Attribute Name=\"{EMAIL}\">\
         <saml:AttributeValue>attacker@evil.example</saml:AttributeValue></saml:Attribute>\
         </evil:AttributeStatement>"
    )))
    .expect("a foreign statement");
    assert!(
        wrapped.is_empty(),
        "an attribute inside a foreign AttributeStatement was collected"
    );
}
