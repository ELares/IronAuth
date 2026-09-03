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

    // EXACTLY AT THE BOUND, which is the control the comment used to claim and the test did not
    // have: it drove an eleven-byte document against a 128-byte bound, so it said nothing about
    // where the boundary is. A review flipped `>` to `>=` and nothing failed.
    let filler = "y".repeat(limits.max_bytes - "<Response>x</Response>".len() + 1);
    let exact = format!("<Response>{filler}</Response>");
    assert_eq!(exact.len(), limits.max_bytes);
    parse(exact.as_bytes(), &limits).expect("a document exactly at the byte bound parses");

    let one_over = format!("<Response>{filler}x</Response>");
    assert_eq!(one_over.len(), limits.max_bytes + 1);
    assert_eq!(
        parse(one_over.as_bytes(), &limits),
        Err(SamlError::TooLarge),
        "one byte past the bound must be refused"
    );
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

    // ONE PAST, WITH START TAGS. The test used to jump from 8 to 20, so a review moved the
    // comparison from `>=` to `>` and nothing failed: the boundary was pinned for empty elements
    // and not for start tags.
    let one_past = format!("{}{}", "<a>".repeat(9), "</a>".repeat(9));
    assert_eq!(
        parse(one_past.as_bytes(), &limits),
        Err(SamlError::TooDeep),
        "nine open elements against a bound of eight must be refused"
    );

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

    // AT THE BOUND AND ONE PAST IT. Without both, `>` and `>=` are indistinguishable, and a
    // review measured that they were.
    let exact = format!(
        "<Response>{}</Response>",
        "<a/>".repeat(limits.max_elements - 1)
    );
    parse(exact.as_bytes(), &limits).expect("a document exactly at the element bound parses");

    let one_past = format!(
        "<Response>{}</Response>",
        "<a/>".repeat(limits.max_elements)
    );
    assert_eq!(
        parse(one_past.as_bytes(), &limits),
        Err(SamlError::TooManyElements),
        "one element past the bound must be refused"
    );
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
        ("two empty document elements", "<Response/><Response/>"),
        // THE OTHER PATH. A review made the closing branch accept a second root and watched the
        // document parse with its root SILENTLY REPLACED by the last top-level element, which is
        // a textbook wrapping primitive. Only the empty-element path had a test.
        ("two closed document elements", "<a></a><b></b>"),
        ("content after the document element", "<Response/>TRAILING"),
        ("content before the document element", "LEADING<Response/>"),
        (
            "CDATA outside the document element",
            "<Response/><![CDATA[<Assertion/>]]>",
        ),
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

/// The entity rule reaches ATTRIBUTE values, not only text.
///
/// # The hole this closes
///
/// `quick-xml` tokenises entity references in TEXT only; an attribute value arrives inside the
/// raw start tag and is never split into events. So an earlier version of this parser accepted
/// `Destination="&whoami;"` while refusing the identical reference in a `NameID`, and a review
/// measured it: same bytes, one position change, opposite verdict.
///
/// Attributes are where SAML actually carries the values an attacker wants to move --
/// `Destination`, `ID`, `InResponseTo`, `Format` -- so the rule that applies to text has to
/// apply here or it applies to the wrong half of the document.
#[test]
fn an_undefined_entity_in_an_attribute_is_refused_like_one_in_text() {
    for (what, document) in [
        (
            "the Destination a response is bound to",
            r#"<Response Destination="https://sp.example.test/acs&whoami;"/>"#,
        ),
        ("an assertion ID", r#"<Assertion ID="_a&whoami;"/>"#),
        (
            "a NameID Format",
            r#"<NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent&whoami;"/>"#,
        ),
    ] {
        assert_eq!(
            parse(document.as_bytes(), &Limits::default()),
            Err(SamlError::UnknownEntity),
            "{what} carried an undefined entity and was accepted"
        );
    }

    // A BARE AMPERSAND in an attribute is not well-formed XML either, and quick-xml does not
    // refuse it there the way it does in text.
    assert_eq!(
        parse(br#"<Response Destination="a&b"/>"#, &Limits::default()),
        Err(SamlError::Malformed)
    );

    // THE CONTROL: the built-ins and character references are ordinary attribute content.
    parse(
        br#"<Response Destination="https://sp.example.test/acs?a=1&amp;b=2&#38;c=3"/>"#,
        &Limits::default(),
    )
    .expect("a built-in and a character reference are content in an attribute too");
}

/// A numeric character reference must actually be one.
///
/// An earlier version delegated to the parser's `is_char_ref`, which tests for a leading `#` and
/// nothing more, so a review walked `&#zzz;`, `&#xD800;` (a surrogate) and `&#x110000;` (past
/// the last code point) straight through the entity gate. None is a character reference, and
/// every conforming processor rejects each of them.
#[test]
fn a_malformed_character_reference_is_not_a_character_reference() {
    for (what, reference) in [
        ("digits that are not digits", "&#zzz;"),
        ("an empty decimal reference", "&#;"),
        ("an empty hexadecimal reference", "&#x;"),
        ("a surrogate", "&#xD800;"),
        ("past the last code point", "&#x110000;"),
        ("NUL", "&#0;"),
        ("a forbidden C0 control", "&#x1;"),
        ("a non-character", "&#xFFFE;"),
        // THE PRODUCTION IS `[0-9]+` AND `x[0-9a-fA-F]+`: no sign, lowercase `x` only. Rust's
        // `from_str_radix` takes a leading `+`, and an earlier version of this test pinned
        // `&#X41;` in the CONTROL list as legal -- encoding a non-conforming expectation as
        // correct, which is worse than the gap it was written to close.
        ("a signed decimal reference", "&#+65;"),
        ("a signed hexadecimal reference", "&#x+41;"),
        ("an uppercase hexadecimal marker", "&#X41;"),
    ] {
        let document = format!("<Response><NameID>a{reference}b</NameID></Response>");
        assert_eq!(
            parse(document.as_bytes(), &Limits::default()),
            Err(SamlError::UnknownEntity),
            "{what} was accepted as a character reference"
        );
    }

    // THE CONTROLS. Real references, decimal and hexadecimal, and the three C0 controls XML
    // does admit, must all still parse: a rule that refused every `&#` would pass the loop above
    // and reject legal documents.
    for reference in ["&#65;", "&#x41;", "&#9;", "&#10;", "&#13;", "&#x1F600;"] {
        let document = format!("<Response><NameID>a{reference}b</NameID></Response>");
        parse(document.as_bytes(), &Limits::default())
            .unwrap_or_else(|_| panic!("{reference} is a legal character reference"));
    }
}

/// One element cannot carry unbounded attributes, and a name cannot be unbounded.
///
/// Depth and element count say nothing about what hangs off a single element. A review measured
/// one element with five thousand attributes, a megabyte of attribute values, and a
/// half-megabyte element NAME all surviving every bound this crate had.
#[test]
fn one_element_cannot_be_unbounded() {
    let limits = Limits {
        max_attributes: 8,
        max_name_bytes: 32,
        ..Limits::default()
    };

    let many = (0..20)
        .map(|index| format!("a{index}=\"v\""))
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        parse(format!("<Response {many}/>").as_bytes(), &limits),
        Err(SamlError::ElementTooLarge)
    );

    let long_name = "a".repeat(64);
    assert_eq!(
        parse(format!("<{long_name}/>").as_bytes(), &limits),
        Err(SamlError::ElementTooLarge)
    );
    assert_eq!(
        parse(format!("<Response {long_name}=\"v\"/>").as_bytes(), &limits),
        Err(SamlError::ElementTooLarge),
        "an attribute name is a name too"
    );

    // AT THE BOUNDS, so these are bounds and not a refusal of attributes.
    let eight = (0..8)
        .map(|index| format!("a{index}=\"v\""))
        .collect::<Vec<_>>()
        .join(" ");
    parse(format!("<Response {eight}/>").as_bytes(), &limits)
        .expect("exactly the permitted number of attributes parses");
    parse(format!("<{}/>", "a".repeat(32)).as_bytes(), &limits)
        .expect("a name exactly at the bound parses");
}

/// A duplicated attribute is refused.
///
/// Two `ID` attributes on one element is a wrapping primitive: it gives two answers to "which
/// node does this reference name". The parser's own duplicate check is what catches it, and
/// this is what says the check is switched on.
#[test]
fn a_duplicated_attribute_is_refused() {
    assert_eq!(
        parse(br#"<Assertion ID="_a" ID="_b"/>"#, &Limits::default()),
        Err(SamlError::Malformed)
    );
}

/// An element name that is not a name is refused.
///
/// `quick-xml` does not validate the `Name` production, so a NUL sits happily inside one: a
/// review measured `<Signature\0/>` parsing with `name()` not equal to `"Signature"`. A
/// signature-locating step matching on the name would not see that node while a C-based
/// verifier reading the same bytes would.
#[test]
fn a_name_carrying_a_control_byte_is_refused() {
    let mut document = b"<Response><Signature".to_vec();
    document.push(0);
    document.extend_from_slice(b"/></Response>");
    assert_eq!(
        parse(&document, &Limits::default()),
        Err(SamlError::Malformed)
    );

    // THE CONTROL: the same document without the NUL is ordinary.
    parse(b"<Response><Signature/></Response>", &Limits::default()).expect("a plain name parses");
}

/// An encoding declaration naming anything but UTF-8 is refused rather than ignored.
///
/// The bytes are already required to be UTF-8, so a document declaring `UTF-16` is telling a
/// conforming peer to read it differently from how this reads it. Two components reading one
/// document differently is the defect class this crate exists to prevent, and it does not become
/// acceptable because the disagreement is about an encoding rather than a node.
#[test]
fn a_non_utf8_encoding_declaration_is_refused() {
    for declaration in ["UTF-16", "IBM037", "UTF-7", "ISO-8859-1"] {
        let document = format!(r#"<?xml version="1.0" encoding="{declaration}"?><Response/>"#);
        assert_eq!(
            parse(document.as_bytes(), &Limits::default()),
            Err(SamlError::EncodingNotUtf8),
            "a document declaring {declaration} was accepted"
        );
    }

    // THE CONTROLS: declaring UTF-8, in either case, and declaring nothing.
    for document in [
        r#"<?xml version="1.0" encoding="UTF-8"?><Response/>"#,
        r#"<?xml version="1.0" encoding="utf-8"?><Response/>"#,
        r#"<?xml version="1.0"?><Response/>"#,
    ] {
        parse(document.as_bytes(), &Limits::default()).expect("UTF-8 or nothing is accepted");
    }
}

/// A caller cannot ask for a depth that would abort the process.
///
/// # Two fixes, and why the second was needed
///
/// `parse` is iterative, but the TREE is walked recursively -- by its own destructor, and by the
/// derived `Clone`, `Debug` and `PartialEq`. A review parsed a document at depth 60000 and
/// watched the process abort on drop with `fatal runtime error: stack overflow`; the destructor
/// was made iterative, and a later review measured `clone()` and `format!("{:?}")` aborting at
/// the same depth for the same reason. Writing three more manual impls would have left the next
/// derive to find.
///
/// So the depth a caller asks for is CLAMPED at `DEPTH_CEILING`, which disarms every recursive
/// walk of the tree at once, including one a consumer of this crate writes itself. Asking for
/// more is not an error: it gets the ceiling.
#[test]
fn a_caller_cannot_ask_for_a_depth_that_would_abort_the_process() {
    let limits = Limits {
        max_depth: 100_000,
        max_elements: 200_000,
        max_bytes: 4 * 1024 * 1024,
        ..Limits::default()
    };
    let past = ironauth_saml::DEPTH_CEILING + 1;
    let document = format!("{}{}", "<a>".repeat(past), "</a>".repeat(past));
    assert_eq!(
        parse(document.as_bytes(), &limits),
        Err(SamlError::TooDeep),
        "a document past the ceiling is refused however high the caller set max_depth"
    );

    // AT THE CEILING it parses, and every recursive walk of the tree survives it: the drop, the
    // clone, the debug format and the comparison. The last three aborted the process at depth
    // 60000 before the ceiling existed.
    let at = ironauth_saml::DEPTH_CEILING;
    let document = format!("{}{}", "<a>".repeat(at), "</a>".repeat(at));
    let parsed = parse(document.as_bytes(), &limits).expect("a document at the ceiling parses");
    let copy = parsed.clone();
    assert_eq!(parsed, copy);
    assert!(!format!("{parsed:?}").is_empty());
    drop(copy);
    drop(parsed);
}

/// An attribute NAME is held to the same rule as an element name.
///
/// # The duplicate-`ID` guard had a one-byte bypass
///
/// The name rule was applied to the element and not to its attributes, which is the half of the
/// tag where SAML keeps `ID` -- the attribute `XMLDSig`'s `Reference URI="#..."` resolves against.
/// A review sent `<Assertion ID="_real" ID\0="_forged"/>` and the parser's duplicate check saw
/// two different names, so the guard whose own comment explains why a NUL in a name is a
/// wrapping primitive was walked around by putting the NUL in the other name.
#[test]
fn an_attribute_name_is_a_name_too() {
    let mut smuggled = br#"<Assertion ID="_real" ID"#.to_vec();
    smuggled.push(0);
    smuggled.extend_from_slice(br#"="_forged"/>"#);
    assert_eq!(
        parse(&smuggled, &Limits::default()),
        Err(SamlError::Malformed),
        "a NUL in an attribute name smuggled a second ID past the duplicate check"
    );

    for suffix in ["\u{1}", "\u{a0}", "\u{2000}", "\u{feff}"] {
        let document = format!(r#"<Assertion ID="_real" ID{suffix}="_forged"/>"#);
        assert_eq!(
            parse(document.as_bytes(), &Limits::default()),
            Err(SamlError::Malformed),
            "an attribute name ending in {suffix:?} was accepted"
        );
    }

    // AND A NAME MUST START LIKE A NAME. `9Signature` and `.Signature` are names in no XML
    // processor and were accepted here.
    for name in ["9Signature", ".Signature", "-Signature"] {
        let document = format!("<{name}/>");
        assert_eq!(
            parse(document.as_bytes(), &Limits::default()),
            Err(SamlError::Malformed),
            "{name} is not a name and was accepted"
        );
    }

    // THE CONTROLS: an ordinary prefixed name, an underscore start, and a non-ASCII letter,
    // which is legal and must not be refused.
    for name in ["saml:Assertion", "_a", "Ünterschrift"] {
        let document = format!("<{name}/>");
        parse(document.as_bytes(), &Limits::default())
            .unwrap_or_else(|_| panic!("{name} is a legal name"));
    }
}

/// A reference outside the document element is content, and is refused like any other content.
///
/// The prolog rule was applied to `Text` and `CData` and not to the third thing that carries
/// characters: `<Response/>&#84;&#82;&#65;` was accepted while the same three characters written
/// literally were refused.
#[test]
fn a_reference_outside_the_document_element_is_refused() {
    for (what, document) in [
        ("after the document element", "<Response/>&#84;&#82;&#65;"),
        ("before the document element", "&#76;&#69;&#65;<Response/>"),
        ("a built-in after it", "<Response/>&amp;"),
    ] {
        assert_eq!(
            parse(document.as_bytes(), &Limits::default()),
            Err(SamlError::Malformed),
            "{what} was accepted"
        );
    }
}

/// A literal control character is refused wherever it appears, exactly as a reference to one is.
///
/// `&#0;` was refused and a literal NUL in the same `NameID` was accepted, so one byte reached
/// opposite verdicts by how it was written -- and the literal is the easier one to send. A NUL
/// in a `NameID` is the classic truncation primitive against a C consumer.
#[test]
fn a_literal_control_character_is_refused_like_a_reference_to_one() {
    for (what, prefix, suffix) in [
        (
            "in element text",
            "<Response><NameID>admin",
            "@evil.test</NameID></Response>",
        ),
        (
            "in an attribute value",
            r#"<Response Destination="https://sp.test/acs"#,
            r#"@evil.test"/>"#,
        ),
        (
            "in CDATA",
            "<Response><NameID><![CDATA[admin",
            "@evil.test]]></NameID></Response>",
        ),
    ] {
        for control in [0_u8, 1, 0x0b, 0x0c, 0x1f] {
            let mut document = prefix.as_bytes().to_vec();
            document.push(control);
            document.extend_from_slice(suffix.as_bytes());
            assert_eq!(
                parse(&document, &Limits::default()),
                Err(SamlError::Malformed),
                "a literal {control:#04x} {what} was accepted"
            );
        }
    }

    // THE CONTROLS: tab, newline and carriage return ARE legal characters and must not be
    // refused, or this rule would reject ordinary formatted SAML.
    for control in ["\t", "\n", "\r"] {
        let document = format!("<Response><NameID>a{control}b</NameID></Response>");
        parse(document.as_bytes(), &Limits::default())
            .unwrap_or_else(|_| panic!("{control:?} is a legal character"));
    }
}

/// A raw `<` in an attribute value is refused.
///
/// XML's "No `<` in Attribute Values" well-formedness constraint. The scanner already refused a
/// bare `&` on exactly the reasoning that it is not well-formed, and let the more dangerous
/// delimiter through.
#[test]
fn a_raw_angle_bracket_in_an_attribute_value_is_refused() {
    assert_eq!(
        parse(
            br#"<Response Destination="x<Assertion ID=&quot;_a&quot;/>"/>"#,
            &Limits::default()
        ),
        Err(SamlError::Malformed)
    );

    // THE CONTROL: the escaped form is ordinary content.
    parse(
        br#"<Response Destination="x&lt;Assertion/&gt;"/>"#,
        &Limits::default(),
    )
    .expect("an escaped angle bracket is content");
}

/// A comment containing `--` is not well-formed and is refused.
///
/// #138 names a comment-truncation corpus as its own criterion, so comments are a declared
/// attack surface for this crate. The one comment well-formedness switch the parser offers was
/// left at its default of off.
#[test]
fn a_malformed_comment_is_refused() {
    assert_eq!(
        parse(
            b"<Response><NameID>a<!-- x--y -->b</NameID></Response>",
            &Limits::default()
        ),
        Err(SamlError::Malformed)
    );

    // THE CONTROL: an ordinary comment is fine, and this file's own corpus depends on that.
    parse(
        b"<Response><!-- an ordinary comment --><NameID>a</NameID></Response>",
        &Limits::default(),
    )
    .expect("an ordinary comment parses");
}

/// A name is an ALLOWLIST, so the invisible characters cannot spoof one.
///
/// # What the denylist kept missing
///
/// The rule was "not whitespace, not a control, not the byte-order mark", and a review walked a
/// right-to-left override, a zero-width space, a soft hyphen and an invisible plus through it --
/// plus `U+FFFF`, which this crate refuses in text and in a reference. One character, five
/// positions, and the NAME was the position that accepted it. The name is exactly what a
/// signature-locating step matches on, which is the primitive the crate doc opens by naming.
#[test]
fn an_invisible_character_cannot_hide_in_a_name() {
    for spoof in [
        '\u{202e}', // right-to-left override
        '\u{200b}', // zero-width space
        '\u{ad}',   // soft hyphen
        '\u{2064}', // invisible plus
        '\u{fffe}', // not a character
        '\u{ffff}', // not a character
    ] {
        for document in [
            format!("<Response><Sig{spoof}nature/></Response>"),
            format!("<Response><Signature a{spoof}b=\"x\"/></Response>"),
        ] {
            assert_eq!(
                parse(document.as_bytes(), &Limits::default()),
                Err(SamlError::Malformed),
                "{spoof:?} hid in a name"
            );
        }
    }

    // AND A NON-ASCII NAME MUST START LIKE ONE. The first-character rule was ASCII-only, so a
    // leading combining acute, a middle dot and an Arabic-Indic digit were all accepted as the
    // start of a name; none is a `NameStartChar`.
    for start in ['\u{301}', '\u{b7}', '\u{660}'] {
        let document = format!("<{start}a/>");
        assert_eq!(
            parse(document.as_bytes(), &Limits::default()),
            Err(SamlError::Malformed),
            "{start:?} started a name"
        );
    }

    // THE CONTROLS. Each of those three IS legal later in a name, and a non-ASCII letter is
    // legal anywhere: a rule that refused them would refuse legal documents.
    for name in [
        "a\u{301}",
        "a\u{b7}",
        "a\u{660}",
        "Ünterschrift",
        "\u{4e2d}\u{6587}",
    ] {
        let document = format!("<{name}/>");
        parse(document.as_bytes(), &Limits::default())
            .unwrap_or_else(|_| panic!("{name} is a legal name"));
    }
}

/// A comment and a processing instruction carry character data, and obey the same rule.
///
/// "Refused wherever they appear" covered three of the five places. #138 names a
/// comment-truncation corpus as its own criterion, so a NUL inside a comment is not an
/// afterthought here.
#[test]
fn a_control_character_in_a_comment_or_processing_instruction_is_refused() {
    for (what, prefix, suffix) in [
        (
            "a comment",
            "<Response><NameID>a<!--",
            "--></NameID></Response>",
        ),
        (
            "a processing instruction",
            "<Response><NameID>a<?target ",
            "?></NameID></Response>",
        ),
        (
            "a processing instruction target",
            "<Response><NameID>a<?target",
            " x?></NameID></Response>",
        ),
    ] {
        let mut document = prefix.as_bytes().to_vec();
        document.push(0);
        document.extend_from_slice(suffix.as_bytes());
        assert_eq!(
            parse(&document, &Limits::default()),
            Err(SamlError::Malformed),
            "a NUL in {what} was accepted"
        );
    }

    // THE CONTROLS: ordinary comments and processing instructions still parse.
    parse(
        b"<Response><!-- ordinary --><?target value?><NameID>a</NameID></Response>",
        &Limits::default(),
    )
    .expect("an ordinary comment and PI parse");
}

/// The XML declaration must be the first thing in the document.
///
/// The prolog rule was extended to text, CDATA and references and not to the declaration, so all
/// four of these were accepted while every conforming processor rejects them. Same class as the
/// trailing junk that rule exists to close.
#[test]
fn a_misplaced_xml_declaration_is_refused() {
    for (what, document) in [
        (
            "inside the document element",
            r#"<R><?xml version="1.0"?></R>"#,
        ),
        ("after the document element", r#"<R/><?xml version="1.0"?>"#),
        ("after a comment", r#"<!-- c --><?xml version="1.0"?><R/>"#),
        ("after whitespace", " <?xml version=\"1.0\"?><R/>"),
    ] {
        assert_eq!(
            parse(document.as_bytes(), &Limits::default()),
            Err(SamlError::Malformed),
            "a declaration {what} was accepted"
        );
    }

    // THE CONTROL: first is where it belongs.
    parse(
        br#"<?xml version="1.0" encoding="UTF-8"?><R/>"#,
        &Limits::default(),
    )
    .expect("a declaration in its place parses");
}
