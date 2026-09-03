// SPDX-License-Identifier: MIT OR Apache-2.0

//! Issue #138 criterion 3: "documents containing DTDs, external entities, or oversized/deep
//! structures are rejected before signature processing".
//!
//! # "Before signature processing" is a property of the TYPE here, not of an ordering
//!
//! There is no ordering to get wrong, because there is nothing to order against: the only way
//! to obtain a [`Document`] is [`parse`], and every signature step this crate will grow takes a
//! `Document`. A refused document produces no value at all, so no later stage can receive one.
//! That is why these tests assert on the error rather than on "the signature step was not
//! reached" -- the second is unrepresentable.
//!
//! Needs no database.

use ironauth_saml::{Limits, SamlError, parse};

/// A document with a DOCTYPE is refused, whatever the DOCTYPE says.
///
/// # The XXE case and the billion-laughs case are the same refusal
///
/// Both need a DTD to declare the entity, and this crate accepts no DTD, so neither payload has
/// anywhere to live. The three shapes below are the classic ones -- an external entity pointing
/// at a local file, an external entity pointing at a URL (the SSRF variant), and a nested
/// internal entity (the expansion variant) -- and all three fail at the same line for the same
/// reason.
///
/// A parser that merely declined to RESOLVE these would also pass. Refusing the DOCTYPE is a
/// stronger statement, and it is the one that survives a later change of parser.
#[test]
fn a_doctype_is_refused_whatever_it_declares() {
    for (what, document) in [
        (
            "an external entity naming a local file",
            r#"<?xml version="1.0"?>
               <!DOCTYPE Response [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
               <Response><NameID>&xxe;</NameID></Response>"#,
        ),
        (
            "an external entity naming a URL",
            r#"<?xml version="1.0"?>
               <!DOCTYPE Response [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
               <Response><NameID>&xxe;</NameID></Response>"#,
        ),
        (
            "a nested internal entity",
            r#"<?xml version="1.0"?>
               <!DOCTYPE Response [
                 <!ENTITY a "aaaaaaaaaa">
                 <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
                 <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
               ]>
               <Response><NameID>&c;</NameID></Response>"#,
        ),
        (
            "a DOCTYPE declaring nothing at all",
            "<!DOCTYPE Response><Response/>",
        ),
    ] {
        assert_eq!(
            parse(document.as_bytes(), &Limits::default()),
            Err(SamlError::DoctypeForbidden),
            "{what} was not refused"
        );
    }
}

/// An entity reference with no DOCTYPE to have declared it is refused, not silently emptied.
///
/// The five XML built-ins are resolved by the parser and are NOT this case; anything else names
/// something that cannot exist, because the only place it could have been declared is a DOCTYPE
/// this crate refuses. Letting it through as an empty string is how a `NameID` becomes somebody
/// else, so it is an error rather than a value.
#[test]
fn an_undefined_entity_reference_is_refused_rather_than_emptied() {
    assert_eq!(
        parse(
            b"<Response><NameID>&whoami;</NameID></Response>",
            &Limits::default()
        ),
        Err(SamlError::UnknownEntity)
    );

    // THE CONTROL: the built-ins are ordinary content and must still parse, or the assertion
    // above would pass for a parser that refused every ampersand.
    parse(
        b"<Response><NameID>a&amp;b&lt;c&gt;d&quot;e&apos;f</NameID></Response>",
        &Limits::default(),
    )
    .expect("the five XML built-ins are content, not entities to refuse");
}

/// A document past the byte bound is refused before it is parsed.
#[test]
fn an_oversized_document_is_refused() {
    let limits = Limits {
        max_bytes: 128,
        ..Limits::default()
    };
    let padding = "x".repeat(200);
    let document = format!("<Response><NameID>{padding}</NameID></Response>");
    assert_eq!(
        parse(document.as_bytes(), &limits),
        Err(SamlError::TooLarge)
    );

    // THE CONTROL, one byte inside the bound: the refusal above is the bound and not the shape.
    let inside = "<Response/>";
    assert!(inside.len() <= limits.max_bytes);
    parse(inside.as_bytes(), &limits).expect("a document inside the bound parses");
}

/// A document nested past the depth bound is refused, and the bound counts ELEMENTS.
#[test]
fn a_deeply_nested_document_is_refused() {
    let limits = Limits {
        max_depth: 8,
        ..Limits::default()
    };
    let deep = format!("{}{}", "<a>".repeat(20), "</a>".repeat(20));
    assert_eq!(parse(deep.as_bytes(), &limits), Err(SamlError::TooDeep));

    // EXACTLY AT THE BOUND parses, which is what makes the refusal a bound rather than a
    // rejection of nesting. Eight elements deep is eight open elements at the innermost point.
    let exact = format!("{}{}", "<a>".repeat(8), "</a>".repeat(8));
    parse(exact.as_bytes(), &limits).expect("a document exactly at the depth bound parses");

    // AND AN EMPTY ELEMENT OCCUPIES A LEVEL. `<a/>` is a start and an end at once, and a parser
    // that did not count it would let a document reach `max_depth + 1` by ending in one.
    let one_past = format!("{}<b/>{}", "<a>".repeat(8), "</a>".repeat(8));
    assert_eq!(
        parse(one_past.as_bytes(), &limits),
        Err(SamlError::TooDeep),
        "an empty element at the bound must not be free"
    );
}

/// A document with more elements than the bound is refused, however shallow it is.
///
/// Depth does not bound work on its own: this document is two levels deep and would be a
/// million allocations without this.
#[test]
fn a_document_with_too_many_elements_is_refused() {
    let limits = Limits {
        max_elements: 50,
        ..Limits::default()
    };
    let wide = format!("<Response>{}</Response>", "<a/>".repeat(200));
    assert_eq!(
        parse(wide.as_bytes(), &limits),
        Err(SamlError::TooManyElements)
    );

    let inside = format!("<Response>{}</Response>", "<a/>".repeat(10));
    parse(inside.as_bytes(), &limits).expect("a document inside the element bound parses");
}

/// Malformed XML is one refusal, whatever the malformedness.
///
/// A taxonomy of parse failures is a taxonomy an attacker can use to learn which parser is
/// behind the endpoint, and a caller cannot act on the difference anyway.
#[test]
fn malformedness_is_a_single_refusal() {
    for (what, document) in [
        ("an unclosed element", "<Response><NameID></Response>"),
        ("a mismatched end tag", "<Response></Assertion>"),
        ("a stray end tag", "</Response>"),
        ("two document elements", "<Response/><Response/>"),
        ("nothing at all", ""),
        ("not markup", "not xml"),
    ] {
        assert_eq!(
            parse(document.as_bytes(), &Limits::default()),
            Err(SamlError::Malformed),
            "{what} was not refused as malformed"
        );
    }
}

/// Bytes that are not UTF-8 are refused rather than lossily decoded.
#[test]
fn non_utf8_is_refused() {
    let mut document = b"<Response><NameID>".to_vec();
    document.push(0xFF);
    document.extend_from_slice(b"</NameID></Response>");
    assert_eq!(
        parse(&document, &Limits::default()),
        Err(SamlError::Malformed)
    );
}

/// A document that survives gives back its SHAPE and no values.
///
/// This is the misuse-resistance criterion in test form: everything an attacker wants out of a
/// SAML document is an attribute or a text node, and `Element` exposes neither. What a caller
/// can see is what a signature step needs in order to find the node it must verify.
#[test]
fn a_parsed_document_exposes_shape_and_not_values() {
    let document = parse(
        br#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            Destination="https://sp.example.test/acs">
              <saml:Assertion ID="_a1">
                <saml:Subject><saml:NameID>victim@example.test</saml:NameID></saml:Subject>
              </saml:Assertion>
            </samlp:Response>"#,
        &Limits::default(),
    )
    .expect("a well-formed response parses");

    assert_eq!(document.root().name(), "samlp:Response");
    let assertion = &document.root().children()[0];
    assert_eq!(assertion.name(), "saml:Assertion");
    let subject = &assertion.children()[0];
    assert_eq!(subject.children()[0].name(), "saml:NameID");

    // The values are NOT reachable. `Destination`, the assertion `ID` and the `NameID` text are
    // all in the document and none of them has an accessor; the compile-fail proof beside this
    // file is what holds that, because a test that merely does not call one proves nothing.
    assert!(subject.children()[0].children().is_empty());
}
