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
//! - the same `Name` sent twice under ONE format, which is a contradiction, against the same
//!   `Name` under TWO formats, which SAML says is two attributes;
//! - an `AttributeValue` holding ELEMENTS, which `xs:anyType` permits;
//! - an attribute with NO values, which is how a directory says a field was cleared;
//! - a `saml:EncryptedAttribute`, which is the sibling of the element being read;
//! - attributes nested inside somebody else's assertion, which are inside this signature too;
//! - a verified `samlp:Response` rather than the assertion inside it, which is the ONLY value
//!   the Response-only-signed profile yields.
//!
//! Needs no database.

use ironauth_jose::xmldsig::test_util::XmlTestKey;
use ironauth_saml::{
    ASSERTION_NS, Child, Limits, PROTOCOL_NS, Statement, TrustAnchor, Unreadable, Value,
    attributes, verify,
};

const EMAIL: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
const GROUPS: &str = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups";
const BASIC: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
const URI_FORMAT: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";

/// Sign these assertion children, verify the ASSERTION, and read the attributes.
fn read(children: &str) -> Result<Statement, Unreadable> {
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

/// One `saml:Attribute` with these values, and a `NameFormat` if given.
fn attribute(name: &str, name_format: Option<&str>, values: &[&str]) -> String {
    let format = name_format.map_or(String::new(), |f| format!(" NameFormat=\"{f}\""));
    let mut rendered = String::new();
    for value in values {
        rendered.push_str("<saml:AttributeValue>");
        rendered.push_str(value);
        rendered.push_str("</saml:AttributeValue>");
    }
    format!("<saml:Attribute Name=\"{name}\"{format}>{rendered}</saml:Attribute>")
}

/// A `saml:AttributeStatement` around these children.
fn statement(children: &str) -> String {
    format!("<saml:AttributeStatement>{children}</saml:AttributeStatement>")
}

#[test]
fn an_ordinary_statement_reads_in_document_order_with_its_formats() {
    let found = read(&body(&statement(&format!(
        "{}{}",
        attribute(EMAIL, Some(BASIC), &["ada@globex.example"]),
        attribute(GROUPS, None, &["engineering", "oncall"])
    ))))
    .expect("an ordinary statement");

    assert_eq!(
        found.attributes.len(),
        2,
        "an attribute was dropped or invented"
    );
    assert_eq!(
        found.attributes[0].name, EMAIL,
        "document order was not preserved"
    );
    assert_eq!(found.attributes[0].name_format.as_deref(), Some(BASIC));
    assert_eq!(
        found.attributes[0].values,
        vec![Value::Text("ada@globex.example".to_owned())]
    );

    assert_eq!(found.attributes[1].name, GROUPS);
    assert_eq!(
        found.attributes[1].name_format, None,
        "an absent NameFormat was defaulted, so 'the provider said unspecified' and 'the \
         provider said nothing' became the same answer"
    );
    assert_eq!(
        found.attributes[1].values,
        vec![
            Value::Text("engineering".to_owned()),
            Value::Text("oncall".to_owned())
        ],
        "the values of a multi-valued attribute lost their order or their count"
    );
}

#[test]
fn several_statements_are_one_list_in_document_order() {
    // SAML PERMITS SEVERAL `AttributeStatement`s, and a provider assembling a response from two
    // sources emits exactly that. They are ONE list, not two sets, and reading only the first
    // would silently drop half.
    //
    // THE ORDER ACROSS statements is asserted, not just the count: the API documents "in
    // document order", and a reader that walked them with a stack -- which is how the condition
    // layer's bug arrived -- would keep the count and reverse the list.
    let two = read(&body(&format!(
        "{}{}",
        statement(&attribute(EMAIL, None, &["ada@globex.example"])),
        statement(&attribute(GROUPS, None, &["engineering"]))
    )))
    .expect("two statements");
    assert_eq!(
        two.attributes.len(),
        2,
        "a second AttributeStatement was ignored"
    );
    assert_eq!(
        (
            two.attributes[0].name.as_str(),
            two.attributes[1].name.as_str()
        ),
        (EMAIL, GROUPS),
        "the statements were collected out of document order"
    );

    // AND NO STATEMENT AT ALL IS NOT AN ERROR. An assertion carrying only an `AuthnStatement` is
    // ordinary -- it is what a provider sends when the relying party asked for nothing.
    let none = read(&body(
        "<saml:AuthnStatement AuthnInstant=\"2026-01-01T00:00:00Z\"/>",
    ))
    .expect("an assertion with no attributes at all");
    assert!(none.attributes.is_empty(), "an empty list was not empty");
}

#[test]
fn an_attribute_with_no_values_is_not_the_same_as_an_absent_attribute() {
    // A DIRECTORY THAT CLEARS A FIELD SENDS THE ATTRIBUTE WITH NO VALUES. Collapsing that into
    // "not sent" loses the difference between "we do not know their department" and "they have
    // none", and a mapping that reuses a stored value on absence would then keep a department
    // the identity provider just removed.
    let found = read(&body(&statement(&format!(
        "<saml:Attribute Name=\"{GROUPS}\"/>"
    ))))
    .expect("an attribute with no values");
    assert_eq!(found.attributes.len(), 1, "an empty attribute was dropped");
    assert!(found.attributes[0].values.is_empty());
}

#[test]
fn an_empty_value_is_not_the_empty_string() {
    // THE CONNECTOR'S RULES TAKE THE FIRST SOURCE THAT RESOLVES TO A NON-NULL VALUE, so an empty
    // STRING wins a fallback that an absent value loses. A person whose department was cleared
    // would get `""` written into their profile instead of the next source's value -- which is
    // the difference between "we do not know" and "we know it is nothing", decided in favour of
    // a value nobody sent.
    let found = read(&body(&statement(&format!(
        "<saml:Attribute Name=\"{GROUPS}\">\
         <saml:AttributeValue></saml:AttributeValue>\
         <saml:AttributeValue/>\
         <saml:AttributeValue xsi:nil=\"true\" \
         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"/>\
         <saml:AttributeValue>engineering</saml:AttributeValue>\
         </saml:Attribute>"
    ))))
    .expect("empty values are not a refusal");
    assert_eq!(
        found.attributes[0].values,
        vec![
            Value::Empty,
            Value::Empty,
            Value::Empty,
            Value::Text("engineering".to_owned())
        ],
        "an empty value came back as Text(\"\"), which a mapping fallback treats as a value"
    );

    // AND WHITESPACE IS NOT EMPTY. `xsd:string` preserves it, so a value of one space is a value
    // -- collapsing it into `Empty` would be this crate deciding a provider meant nothing when
    // it sent something.
    let spaced = read(&body(&statement(&format!(
        "<saml:Attribute Name=\"{GROUPS}\"><saml:AttributeValue> </saml:AttributeValue>\
         </saml:Attribute>"
    ))))
    .expect("a whitespace value");
    assert_eq!(
        spaced.attributes[0].values,
        vec![Value::Text(" ".to_owned())]
    );
}

#[test]
fn the_same_name_under_one_format_is_a_contradiction_and_under_two_is_two_attributes() {
    // SAML CORE 2.7.3.1 IDENTIFIES AN ATTRIBUTE BY `Name` AND `NameFormat` TOGETHER. So the
    // duplicate rule compares both -- keying on `Name` alone refuses a conformant assertion that
    // sends one name in two formats, which is what a provider migrating from the basic format to
    // the URI format emits during the overlap.
    let two_formats = read(&body(&statement(&format!(
        "{}{}",
        attribute(EMAIL, Some(BASIC), &["ada@globex.example"]),
        attribute(EMAIL, Some(URI_FORMAT), &["ada@globex.example"])
    ))))
    .expect("one name in two formats is two attributes");
    assert_eq!(
        two_formats.attributes.len(),
        2,
        "a conformant pair was refused"
    );

    // UNDER ONE FORMAT IT IS A SECOND CLAIM. Taking either is choosing which half of a
    // contradiction to believe, and somebody who can append chooses for the reader. The two
    // carry DIFFERENT values, so a reader that concatenated them and one that took either would
    // each produce something, and all three answers differ.
    assert_eq!(
        read(&body(&statement(&format!(
            "{}{}",
            attribute(EMAIL, Some(BASIC), &["ada@globex.example"]),
            attribute(EMAIL, Some(BASIC), &["attacker@evil.example"])
        )))),
        Err(Unreadable::Duplicate {
            name: EMAIL.to_owned(),
            name_format: Some(BASIC.to_owned()),
        }),
        "an assertion claiming two emails in one format had one of them believed"
    );

    // ABSENT AND EXPLICIT `unspecified` ARE ONE ATTRIBUTE, which is where the round-1 fix moved
    // the defect rather than removing it. Round 1 keyed the duplicate on `Name` alone and would
    // have caught this pair; adding `NameFormat` to the key as an `Option<String>` made the
    // surface spelling the identity, so ONE OPTIONAL ATTRIBUTE whose value SAML defines as the
    // default turns a refusal into a silent choice between two emails.
    assert_eq!(
        read(&body(&statement(&format!(
            "{}{}",
            attribute(EMAIL, None, &["ada@globex.example"]),
            attribute(EMAIL, Some(UNSPECIFIED), &["attacker@evil.example"])
        )))),
        Err(Unreadable::Duplicate {
            name: EMAIL.to_owned(),
            name_format: Some(UNSPECIFIED.to_owned()),
        }),
        "an absent NameFormat and an explicit `unspecified` were read as two attributes"
    );
    // AND THE OTHER ORDER, so the rule is about the pair and not about which came first.
    assert!(matches!(
        read(&body(&statement(&format!(
            "{}{}",
            attribute(EMAIL, Some(UNSPECIFIED), &["ada@globex.example"]),
            attribute(EMAIL, None, &["attacker@evil.example"])
        )))),
        Err(Unreadable::Duplicate { .. })
    ));

    // AND WITH NO FORMAT ON EITHER, which is the shape most providers send.
    assert_eq!(
        read(&body(&statement(&format!(
            "{}{}",
            attribute(EMAIL, None, &["ada@globex.example"]),
            attribute(EMAIL, None, &["attacker@evil.example"])
        )))),
        Err(Unreadable::Duplicate {
            name: EMAIL.to_owned(),
            name_format: None,
        })
    );
}

#[test]
fn the_duplicate_rule_reaches_past_the_attribute_next_to_it() {
    // A CHECK AGAINST ONLY THE PREVIOUS ATTRIBUTE passes every adjacent fixture, and an earlier
    // version of this file had only adjacent ones. Here the pair is separated by two unrelated
    // attributes, so only a check that scans what it has already seen refuses it.
    let separated = read(&body(&statement(&format!(
        "{}{}{}{}",
        attribute(EMAIL, None, &["ada@globex.example"]),
        attribute(GROUPS, None, &["engineering"]),
        attribute("urn:example:department", None, &["platform"]),
        attribute(EMAIL, None, &["attacker@evil.example"])
    ))));
    assert!(
        matches!(separated, Err(Unreadable::Duplicate { .. })),
        "a duplicate two attributes away was not seen: {separated:?}"
    );

    // ACROSS TWO STATEMENTS TOO, which is how it arrives when a provider merges two sources and
    // is the case a per-statement check would miss. The refusal must NAME the duplicated
    // attribute: asserting only that it failed cannot tell this from any other refusal.
    assert_eq!(
        read(&body(&format!(
            "{}{}",
            statement(&attribute(EMAIL, None, &["ada@globex.example"])),
            statement(&attribute(EMAIL, None, &["attacker@evil.example"]))
        ))),
        Err(Unreadable::Duplicate {
            name: EMAIL.to_owned(),
            name_format: None,
        }),
        "the same Name in two statements was read as two attributes, or refused without saying \
         which attribute an operator has to look at"
    );

    // AND THE CONTROL: names differing only in CASE or in surrounding WHITESPACE are different
    // names. A SAML attribute Name is a URI compared as a string, so folding either would merge
    // two attributes an identity provider deliberately sent apart.
    let nearly = read(&body(&statement(&format!(
        "{}{}{}",
        attribute(EMAIL, None, &["ada@globex.example"]),
        attribute(&EMAIL.to_uppercase(), None, &["upper"]),
        attribute(&format!(" {EMAIL}"), None, &["padded"])
    ))))
    .expect("three names that differ");
    assert_eq!(
        nearly.attributes.len(),
        3,
        "two distinct names were folded into one"
    );
}

#[test]
fn an_attribute_with_no_usable_name_is_refused_rather_than_dropped() {
    // `Name` IS REQUIRED AND IS WHAT A MAPPING KEYS ON, so an attribute without one could never
    // be reached. Dropping it silently would hide a misconfiguration behind a trait that is
    // simply never populated.
    assert_eq!(
        read(&body(&statement(
            "<saml:Attribute><saml:AttributeValue>x</saml:AttributeValue></saml:Attribute>"
        ))),
        Err(Unreadable::NamelessAttribute)
    );

    // AND THE EMPTY STRING, which is the degenerate input a presence check alone does not catch:
    // `Name=""` is present, and a mapping keyed on `""` is not one anybody wrote on purpose.
    assert_eq!(
        read(&body(&statement(
            "<saml:Attribute Name=\"\"><saml:AttributeValue>x</saml:AttributeValue>\
             </saml:Attribute>"
        ))),
        Err(Unreadable::NamelessAttribute),
        "Name=\"\" satisfied the guard its own doc says it exists to catch"
    );
}

#[test]
fn an_encrypted_attribute_is_counted_beside_what_was_read_and_not_instead_of_it() {
    // `saml:EncryptedAttribute` IS THE SIBLING OF `saml:Attribute` in an `AttributeStatement`,
    // and this module reads only the second. Skipping it silently means an attribute an operator
    // configured, that the provider sent, never arrives with nothing said.
    //
    // BUT REFUSING THE WHOLE ASSERTION FOR ONE contradicts this module's opening rule -- an
    // attribute a caller cannot use is not a reason to refuse anybody -- and an earlier version
    // did exactly that, discarding every attribute the assertion carried in the clear. So both
    // halves come back and the caller decides.
    let mixed = read(&body(&statement(&format!(
        "{}<saml:EncryptedAttribute><xenc:EncryptedData \
         xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedAttribute>\
         <saml:EncryptedAttribute/>",
        attribute(EMAIL, None, &["ada@globex.example"])
    ))))
    .expect("an encrypted attribute is not a refusal");
    assert_eq!(
        mixed.encrypted, 2,
        "the encrypted attributes were not counted, or were counted once for the statement"
    );
    assert_eq!(
        mixed.attributes.len(),
        1,
        "the readable attribute was discarded because an unreadable one sat beside it"
    );
    assert_eq!(
        mixed.attributes[0].values,
        vec![Value::Text("ada@globex.example".to_owned())]
    );

    // A STATEMENT CARRYING ONLY ENCRYPTED ATTRIBUTES is the case that separates "counted" from
    // "counted only when something else was read": nothing pins the count if every fixture also
    // carries a plaintext attribute.
    let only = read(&body(&statement("<saml:EncryptedAttribute/>")))
        .expect("a statement of only encrypted attributes");
    assert_eq!(only.encrypted, 1);
    assert!(only.attributes.is_empty());

    // AND THE CONTROL: no encrypted element means a count of zero, so the field is not simply
    // always non-zero.
    let clear = read(&body(&statement(&attribute(
        EMAIL,
        None,
        &["ada@globex.example"],
    ))))
    .expect("the control");
    assert_eq!(clear.encrypted, 0);
    assert_eq!(clear.attributes.len(), 1);
}

#[test]
fn a_value_carrying_elements_reports_its_shape_and_is_not_flattened() {
    // `AttributeValue` IS `xs:anyType`, so a conformant assertion may put a subtree in one --
    // `saml:NameID` inside one is the case with published interoperability notes.
    //
    // CONCATENATING ITS DESCENDANTS WOULD INVENT A VALUE. `<a>x</a><b>y</b>` gives "xy", which
    // no other reader produces and which a mapping would then write into somebody's profile.
    // The child NAMES come back so a caller can log what it declined to map and decide whether
    // the attribute is one it should handle at all -- a payload-free marker would leave it a
    // choice between a fiction and a silence.
    let found = read(&body(&statement(&format!(
        "<saml:Attribute Name=\"{GROUPS}\">\
         <saml:AttributeValue>engineering</saml:AttributeValue>\
         <saml:AttributeValue><saml:NameID>ada@globex.example</saml:NameID>\
         <saml:SubjectConfirmation/></saml:AttributeValue>\
         </saml:Attribute>"
    ))))
    .expect("a structured value is not a refusal");
    assert_eq!(
        found.attributes[0].values,
        vec![
            Value::Text("engineering".to_owned()),
            Value::Structured(vec![
                Child {
                    namespace: ASSERTION_NS.to_owned(),
                    local: "NameID".to_owned(),
                    text: "ada@globex.example".to_owned(),
                },
                Child {
                    namespace: ASSERTION_NS.to_owned(),
                    local: "SubjectConfirmation".to_owned(),
                    text: String::new(),
                },
            ])
        ],
        "a structured value was flattened, dropped so the text values shifted, or reported \
         without the shape a caller has to act on"
    );
}

#[test]
fn an_attribute_statement_inside_a_value_belongs_to_whoever_wrote_it() {
    // THE DEFECT THE CONDITION LAYER PAID FOR THREE TIMES, in the place it is easiest to reach:
    // `AttributeValue` is `xs:anyType`, so an assertion may legitimately carry an entire
    // `AttributeStatement` inside one -- and it is inside this signature just as much as the
    // real one. A descendant search collects both.
    //
    // The nested statement claims the SAME name with a different value, so a descendant search
    // does not merely add attributes: it produces the duplicate refusal and this assertion is
    // rejected outright.
    let found = read(&body(&statement(&format!(
        "{}<saml:Attribute Name=\"{GROUPS}\"><saml:AttributeValue>{}</saml:AttributeValue>\
         </saml:Attribute>",
        attribute(EMAIL, None, &["ada@globex.example"]),
        statement(&attribute(EMAIL, None, &["attacker@evil.example"]))
    ))))
    .expect("a nested statement is not this assertion's problem");

    assert_eq!(
        found.attributes.len(),
        2,
        "a nested AttributeStatement was collected"
    );
    assert_eq!(
        found.attributes[0].values,
        vec![Value::Text("ada@globex.example".to_owned())],
        "the nested email displaced the real one"
    );
    assert_eq!(
        found.attributes[1].values,
        vec![Value::Structured(vec![Child {
            namespace: ASSERTION_NS.to_owned(),
            local: "AttributeStatement".to_owned(),
            // Its own text is empty: it has element children, so concatenating theirs is the
            // fiction this whole variant exists to refuse, one level down.
            text: String::new(),
        }])],
        "the nested statement was read as text rather than left alone"
    );
}

#[test]
fn an_element_in_a_foreign_namespace_is_not_this_assertions_attribute() {
    // A NAME IS A NAMESPACE AND A LOCAL NAME. An element called `Attribute` bound to a namespace
    // nobody trusts is not a SAML attribute, and reading it would let anything that can add an
    // element to a signed document add a claim.
    let found = read(&body(&format!(
        "<saml:AttributeStatement xmlns:evil=\"urn:evil\">{}\
         <evil:Attribute Name=\"{GROUPS}\"><evil:AttributeValue>admins</evil:AttributeValue>\
         </evil:Attribute></saml:AttributeStatement>",
        attribute(EMAIL, None, &["ada@globex.example"])
    )))
    .expect("a foreign element beside a real attribute");
    assert_eq!(
        found.attributes.len(),
        1,
        "an element merely NAMED Attribute became one of this assertion's attributes"
    );

    // A FOREIGN `AttributeValue` INSIDE A REAL ATTRIBUTE is not a value either. The real
    // attribute keeps exactly its own values, and the foreign one is not read at all -- this is
    // the one check in the module that had no fixture before.
    let inner = read(&body(&statement(&format!(
        "<saml:Attribute Name=\"{EMAIL}\" xmlns:evil=\"urn:evil\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue>\
         <evil:AttributeValue>attacker@evil.example</evil:AttributeValue></saml:Attribute>"
    ))))
    .expect("a foreign value beside a real one");
    assert_eq!(
        inner.attributes[0].values,
        vec![Value::Text("ada@globex.example".to_owned())],
        "a foreign AttributeValue became one of this attribute's values"
    );

    // AND A FOREIGN STATEMENT WRAPPING A REAL ATTRIBUTE is not a statement: the elements inside
    // it are conformant SAML, and what makes them somebody else's is their parent.
    let wrapped = read(&body(&format!(
        "<evil:AttributeStatement xmlns:evil=\"urn:evil\">{}</evil:AttributeStatement>",
        attribute(EMAIL, None, &["attacker@evil.example"])
    )))
    .expect("a foreign statement");
    assert!(
        wrapped.attributes.is_empty(),
        "an attribute inside a foreign AttributeStatement was collected"
    );

    // A FOREIGN `EncryptedAttribute` IS NOT ONE EITHER, so the refusal above cannot be triggered
    // by anything that merely spells the name.
    let foreign_encrypted = read(&body(&format!(
        "<saml:AttributeStatement xmlns:evil=\"urn:evil\">{}\
         <evil:EncryptedAttribute/></saml:AttributeStatement>",
        attribute(EMAIL, None, &["ada@globex.example"])
    )))
    .expect("a foreign EncryptedAttribute is not this assertion's");
    assert_eq!(foreign_encrypted.attributes.len(), 1);
}

#[test]
fn a_verified_response_is_not_an_assertion_and_answering_nothing_would_be_worse() {
    // `verify` TAKES THE ELEMENT TO READ AS AN ARGUMENT and hands back whatever was signed, so a
    // caller may hold a verified `samlp:Response`. The fixture below is the DOUBLY signed
    // document -- which is what `test_util::sign_response` builds and what its doc says Okta and
    // ADFS emit -- so BOTH elements verify here, and that is what makes the pair meaningful: the
    // same bytes, read at two levels, must answer differently.
    //
    // An earlier version of this comment claimed Okta and ADFS emit a Response-ONLY-signed
    // profile, which contradicts that helper's own doc. Response-only signing is a real
    // configuration and the guard does not need it.
    //
    // A `Response`'s direct children hold no `AttributeStatement`, so without the guard the
    // answer was an empty list -- which THIS MODULE DOCUMENTS AS A REAL ANSWER meaning "the
    // provider sent none". A mapping that clears traits on absence would wipe a department and a
    // group list on a document that verified, and nothing would say why.
    let key = XmlTestKey::generate();
    let inner = ironauth_saml::test_util::signed_response_with(
        &key,
        "_assertion",
        &body(&statement(&attribute(EMAIL, None, &["ada@globex.example"]))),
    );
    let both = ironauth_saml::test_util::sign_response(&key, &inner);
    let anchors = [TrustAnchor::EcdsaP256(key.public_point())];

    let response = verify(
        both.as_bytes(),
        &Limits::default(),
        &anchors,
        PROTOCOL_NS,
        "Response",
    )
    .expect("the Response is signed and verifies");
    assert_eq!(
        attributes(&response),
        Err(Unreadable::NotAnAssertion),
        "a verified Response answered 'this person has no attributes'"
    );

    // AND THE ASSERTION INSIDE THE SAME DOCUMENT READS, which is what shows the refusal is about
    // the element handed in and not about the document.
    let assertion = verify(
        both.as_bytes(),
        &Limits::default(),
        &anchors,
        ASSERTION_NS,
        "Assertion",
    )
    .expect("the assertion is signed too");
    let found = attributes(&assertion).expect("the assertion reads");
    assert_eq!(found.attributes.len(), 1);
    assert_eq!(
        found.attributes[0].values,
        vec![Value::Text("ada@globex.example".to_owned())]
    );
}

#[test]
fn the_assertion_guard_resolves_the_name_rather_than_reading_its_spelling() {
    // THE ONLY FIXTURE FOR THIS GUARD WAS A `samlp:Response`, which fails a suffix test, a
    // local-name test and a namespace test alike -- so the guard's own "resolved rather than
    // spelled" claim was unmeasured, and weakening it to any of the three left the suite green.
    //
    // `evil:Assertion` in a namespace nobody trusts has the RIGHT local name and the wrong
    // identity, so only a resolved check refuses it.
    let key = XmlTestKey::generate();
    let document = ironauth_saml::test_util::signed_element_with(
        &key,
        "evil:Assertion",
        r#" xmlns:evil="urn:evil""#,
        "_assertion",
        &body(&statement(&attribute(
            EMAIL,
            None,
            &["attacker@evil.example"],
        ))),
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
    assert_eq!(
        signed.name(),
        "evil:Assertion",
        "the fixture no longer expresses the case: its LOCAL name must be Assertion"
    );
    assert_eq!(
        attributes(&signed),
        Err(Unreadable::NotAnAssertion),
        "an element whose local name is Assertion, in a namespace nobody trusts, was read as one"
    );
}

#[test]
fn a_name_that_is_only_whitespace_is_not_a_name_and_the_one_returned_is_untouched() {
    // `Name=" "` IS PRESENT AND NON-EMPTY, so a check on emptiness alone admits it -- and a
    // mapping keyed on a space is no more usable than one keyed on the empty string, which is
    // what the guard's own doc says it exists to catch.
    for blank in [" ", "\t", "\n  "] {
        assert_eq!(
            read(&body(&statement(&format!(
                "<saml:Attribute Name=\"{blank}\">\
                 <saml:AttributeValue>x</saml:AttributeValue></saml:Attribute>"
            )))),
            Err(Unreadable::NamelessAttribute),
            "a Name of only whitespace ({blank:?}) was accepted"
        );
    }

    // AND A NAME WITH SURROUNDING WHITESPACE IS RETURNED UNTOUCHED. The check trims; the VALUE
    // does not. A `Name` is compared as a string, so trimming it here would be this crate
    // deciding two providers' attribute names are the same -- and an earlier version of the
    // case/whitespace test asserted only the COUNT, so folding at the push site survived it.
    let padded = format!(" {EMAIL} ");
    let found = read(&body(&statement(&attribute(&padded, None, &["value"]))))
        .expect("a padded name is a name");
    assert_eq!(
        found.attributes[0].name, padded,
        "the Name was trimmed on its way out, so two distinct attributes would collide"
    );
    assert_ne!(found.attributes[0].name, EMAIL);
}

#[test]
fn a_name_format_padded_with_whitespace_is_the_same_format() {
    // `NameFormat` IS AN `xsd:anyURI`, which XSD gives the `collapse` facet -- so
    // ` urn:...:unspecified ` and the flush spelling are ONE value to every schema-aware reader.
    // Comparing them raw re-opens, one space at a time, the exact hole the effective-format rule
    // was written to close: a provider that pads the attribute on one of two elements turns a
    // refusal back into a silent choice between two emails.
    assert!(
        matches!(
            read(&body(&statement(&format!(
                "{}{}",
                attribute(EMAIL, Some(BASIC), &["ada@globex.example"]),
                attribute(
                    EMAIL,
                    Some(&format!("  {BASIC} ")),
                    &["attacker@evil.example"]
                )
            )))),
            Err(Unreadable::Duplicate { .. })
        ),
        "a padded NameFormat was read as a different format"
    );

    // THE PADDING ON THE FIRST ELEMENT, which is the half a one-sided fixture cannot reach: the
    // STORED format is what gets compared against, so collapsing only the incoming one leaves
    // the rule half-applied and a provider padding its first element still slips through.
    assert!(
        matches!(
            read(&body(&statement(&format!(
                "{}{}",
                attribute(EMAIL, Some(&format!(" {BASIC}  ")), &["ada@globex.example"]),
                attribute(EMAIL, Some(BASIC), &["attacker@evil.example"])
            )))),
            Err(Unreadable::Duplicate { .. })
        ),
        "a padded NameFormat on the FIRST element was stored raw and never matched"
    );

    // AND A NO-BREAK SPACE IS NOT WHITESPACE. XML Schema names exactly `#x9`, `#xA`, `#xD` and
    // `#x20`, so `urn:a<NBSP>b` and `urn:a b` are DIFFERENT `anyURI` values -- while a collapse
    // over the whole Unicode whitespace property makes them equal, and would refuse a conformant
    // assertion as a duplicate. The pair below differs ONLY in that one character.
    let with_nbsp = format!("urn:a{NBSP}b", NBSP = '\u{a0}');
    assert_eq!(
        read(&body(&statement(&format!(
            "{}{}",
            attribute(EMAIL, Some(&with_nbsp), &["ada@globex.example"]),
            attribute(EMAIL, Some("urn:a b"), &["also-ada@globex.example"])
        ))))
        .expect("two formats differing by a NO-BREAK SPACE are two formats")
        .attributes
        .len(),
        2,
        "a NO-BREAK SPACE was folded as though XSD called it whitespace, so two conformant \
         attributes were refused as one"
    );

    // AND AN ABSENT ONE AGAINST A PADDED `unspecified`, which is the same rule crossed with the
    // defaulting rule.
    assert!(matches!(
        read(&body(&statement(&format!(
            "{}{}",
            attribute(EMAIL, None, &["ada@globex.example"]),
            attribute(
                EMAIL,
                Some(&format!(" {UNSPECIFIED}")),
                &["attacker@evil.example"]
            )
        )))),
        Err(Unreadable::Duplicate { .. })
    ));

    // THE CONTROL: two genuinely different formats are still two attributes, so collapsing has
    // not made every format equal.
    assert_eq!(
        read(&body(&statement(&format!(
            "{}{}",
            attribute(EMAIL, Some(BASIC), &["ada@globex.example"]),
            attribute(EMAIL, Some(URI_FORMAT), &["also-ada@globex.example"])
        ))))
        .expect("two formats")
        .attributes
        .len(),
        2
    );
}

#[test]
fn a_structured_value_carries_the_name_inside_it_and_not_only_its_shape() {
    // THE CASE `Value::Structured`'S OWN DOC NAMES AS THE REASON IT EXISTS is `saml:NameID`
    // inside an `AttributeValue` -- and a caller that has identified it wants the NAME inside it.
    // An earlier version answered the shape and threw the value away, so the one attribute the
    // doc called common was the one nothing could be done with.
    let found = read(&body(&statement(&format!(
        "<saml:Attribute Name=\"{GROUPS}\"><saml:AttributeValue>\
         <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">\
         ada@globex.example</saml:NameID></saml:AttributeValue></saml:Attribute>"
    ))))
    .expect("a NameID inside an AttributeValue");
    assert_eq!(
        found.attributes[0].values,
        vec![Value::Structured(vec![Child {
            namespace: ASSERTION_NS.to_owned(),
            local: "NameID".to_owned(),
            text: "ada@globex.example".to_owned(),
        }])],
        "the shape came back without the name inside it"
    );

    // AND A CHILD WITH ITS OWN ELEMENT CHILDREN ANSWERS EMPTY TEXT rather than its descendants
    // concatenated -- the same refusal one level down, for the same reason.
    let nested = read(&body(&statement(&format!(
        "<saml:Attribute Name=\"{GROUPS}\"><saml:AttributeValue>\
         <saml:Subject><saml:NameID>ada@globex.example</saml:NameID></saml:Subject>\
         </saml:AttributeValue></saml:Attribute>"
    ))))
    .expect("a nested subtree");
    assert_eq!(
        nested.attributes[0].values,
        vec![Value::Structured(vec![Child {
            namespace: ASSERTION_NS.to_owned(),
            local: "Subject".to_owned(),
            text: String::new(),
        }])],
        "a child with element children had its descendants' text concatenated"
    );
}
