// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exclusive canonicalization, against the forms the specification prescribes.
//!
//! # Why this suite exists separately from everything else
//!
//! A signer and a verifier that share a canonicalization bug agree with each other perfectly.
//! Every test that goes through [`ironauth_saml::verify`] is therefore blind to this component:
//! it can only show the two halves match, never that either is right.
//!
//! So these expectations come from the specification, not from anything this crate produces.
//! The first version of the canonicalizer had NINE defects and none of them was visible, because
//! there was no suite here at all -- two of the nine were fatal (one rejected every conforming
//! signature, one made two genuinely different documents digest identically). Each case below
//! names the defect it would have caught.
//!
//! Needs no database.

use ironauth_saml::test_util::canonicalize;

/// A prefix declared on an ANCESTOR of the signed subtree resolves.
///
/// # The defect that rejected every real signature
///
/// Exclusive canonicalization renders only the declarations a subtree visibly uses, and it
/// resolves them against every declaration in scope -- INCLUDING ancestors outside the subtree.
/// An earlier version started the in-scope set empty, defending it as "no inherited scope". The
/// empty OUTPUT context is right; the empty in-scope set is not, and the two are different
/// things.
///
/// The measured cost was total: an identity provider that declares `xmlns:ds` on the `Response`
/// leaves `ds:SignedInfo` unable to resolve its own prefix, so the declaration was dropped and
/// no conforming signature could ever verify.
#[test]
fn a_prefix_declared_on_an_ancestor_is_rendered_on_the_apex() {
    let document = r#"<samlp:Response xmlns:samlp="urn:p" xmlns:ds="urn:ds">
        <ds:SignedInfo><ds:Reference/></ds:SignedInfo>
      </samlp:Response>"#;
    assert_eq!(
        canonicalize(document, "ds:SignedInfo").expect("canonicalises"),
        r#"<ds:SignedInfo xmlns:ds="urn:ds"><ds:Reference></ds:Reference></ds:SignedInfo>"#
    );
}

/// A prefix REDECLARED inside the subtree is rendered again.
///
/// # The defect that made two different documents digest the same
///
/// With one set doing the work of two, a descendant that rebound a prefix was invisible: it
/// resolved against the stale ancestor binding and rendered nothing. Two documents in which
/// `p:y` is genuinely in different namespaces then produced identical octets, so a signature
/// over the benign one verified over the attacker's.
#[test]
fn a_redeclared_prefix_is_rendered_again() {
    let benign = r#"<a xmlns:p="urn:1"><b p:y="2"/></a>"#;
    let hostile = r#"<a xmlns:p="urn:1"><b xmlns:p="urn:evil" p:y="2"/></a>"#;

    let benign = canonicalize(benign, "b").expect("canonicalises");
    let hostile = canonicalize(hostile, "b").expect("canonicalises");
    assert_eq!(benign, r#"<b xmlns:p="urn:1" p:y="2"></b>"#);
    assert_eq!(hostile, r#"<b xmlns:p="urn:evil" p:y="2"></b>"#);
    assert_ne!(
        benign, hostile,
        "two documents whose attribute is in different namespaces must not canonicalise alike"
    );
}

/// Attributes sort by NAMESPACE URI then local name, which is not the qualified-name order.
///
/// An earlier version sorted the qualified name and argued it was equivalent. It is not: here
/// the prefix order is `ds` before `wsu` and the URI order is the reverse, which is the
/// WS-Security-wrapped SAML shape.
#[test]
fn attributes_sort_by_namespace_uri_then_local_name() {
    let document = r#"<a xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                         xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
        <b ds:Id="1" wsu:Id="2"/>
      </a>"#;
    let canonical = canonicalize(document, "b").expect("canonicalises");
    let wsu = canonical.find("wsu:Id").expect("wsu attribute");
    let ds = canonical.find("ds:Id").expect("ds attribute");
    assert!(
        wsu < ds,
        "the wss URI sorts before the xmldsig one, so wsu:Id comes first: {canonical}"
    );

    // AND AN UNPREFIXED ATTRIBUTE IS IN NO NAMESPACE, which is lexicographically least however
    // its name sorts against a prefixed one.
    let document = r#"<a xmlns:zz="urn:z"><b zz:aaa="1" mmm="2"/></a>"#;
    let canonical = canonicalize(document, "b").expect("canonicalises");
    assert!(
        canonical.find("mmm=").expect("m") < canonical.find("zz:aaa=").expect("z"),
        "the unprefixed attribute sorts first: {canonical}"
    );
}

/// A prefix nothing binds is an ERROR, not a prefix written without its namespace.
///
/// An earlier version skipped it silently and wrote the prefix anyway, which put the namespace
/// URI outside the digest entirely -- so documents binding one prefix to different URIs produced
/// identical octets. That is how a mismatch becomes a collision.
#[test]
fn an_unbound_prefix_is_refused() {
    let document = r#"<a><b p:y="2"/></a>"#;
    assert!(
        canonicalize(document, "b").is_err(),
        "a prefix nothing binds must not canonicalise"
    );
}

/// `xmlns=""` is rendered only when there is a default namespace to undeclare.
#[test]
fn an_empty_default_declaration_is_rendered_only_to_undeclare() {
    // NOTHING TO UNDECLARE: the six bytes must not appear.
    assert_eq!(
        canonicalize(r#"<a><b xmlns=""/></a>"#, "b").expect("canonicalises"),
        "<b></b>"
    );

    // SOMETHING TO UNDECLARE: the apex renders the default, so the child must undeclare it.
    assert_eq!(
        canonicalize(r#"<a xmlns="urn:1"><b xmlns=""><c/></b></a>"#, "a").expect("canonicalises"),
        r#"<a xmlns="urn:1"><b xmlns=""><c></c></b></a>"#
    );
}

/// A processing instruction is part of the canonical form.
///
/// Only COMMENTS are removed by the algorithm this crate accepts. An earlier version dropped
/// processing instructions at parse time, so one could be added to or removed from the signed
/// subtree without changing its digest -- content inside the signature's coverage that the
/// signature did not cover.
#[test]
fn a_processing_instruction_is_kept_and_a_comment_is_not() {
    assert_eq!(
        canonicalize("<a><?target value?>text</a>", "a").expect("canonicalises"),
        "<a><?target value?>text</a>"
    );
    assert_eq!(
        canonicalize("<a><!-- gone -->text</a>", "a").expect("canonicalises"),
        "<a>text</a>"
    );
}

/// Literal whitespace in an attribute value is normalised to a space; a reference is not.
///
/// XML 1.0 section 3.3.3 makes this the processor's job, and the canonical form then escapes
/// what survived. An earlier version normalised neither, so a pretty-printed or line-wrapped
/// attribute digested differently from every conforming signer.
#[test]
fn attribute_values_are_normalised_before_they_are_escaped() {
    let document = "<a><b x=\"one\ttwo\nthree\" y=\"one&#x9;two\"/></a>";
    let canonical = canonicalize(document, "b").expect("canonicalises");
    assert!(
        canonical.contains(r#"x="one two three""#),
        "a literal tab and newline become spaces: {canonical}"
    );
    assert!(
        canonical.contains(r#"y="one&#x9;two""#),
        "a character reference survives and is escaped: {canonical}"
    );
}

/// CRLF and a lone CR become a single newline before anything is digested.
///
/// XML 1.0 section 2.11 makes this the processor's job too. Without it a document delivered with
/// CRLF line endings emits five extra bytes per line break inside a text node, and its digest
/// differs from every conforming signer's.
#[test]
fn line_endings_are_normalised() {
    let crlf = canonicalize("<a>one\r\ntwo\rthree</a>", "a").expect("canonicalises");
    let lf = canonicalize("<a>one\ntwo\nthree</a>", "a").expect("canonicalises");
    assert_eq!(crlf, lf);
    assert_eq!(crlf, "<a>one\ntwo\nthree</a>");

    // A REFERENCE IS NOT A LINE ENDING. `&#xD;` is written explicitly and survives, and the
    // canonical form escapes it -- which is the only way a carriage return can appear.
    assert_eq!(
        canonicalize("<a>one&#xD;two</a>", "a").expect("canonicalises"),
        "<a>one&#xD;two</a>"
    );
}

/// The `xml` prefix is bound by definition: it resolves, it is never rendered, and it sorts
/// under its own URI.
#[test]
fn the_xml_prefix_is_bound_without_being_declared() {
    let canonical = canonicalize(r#"<a><b xml:lang="en"/></a>"#, "b").expect("canonicalises");
    assert_eq!(canonical, r#"<b xml:lang="en"></b>"#);

    // AND IT SORTS BY ITS URI. `http://www.w3.org/XML/1998/namespace` sorts after
    // `http://docs.oasis-open.org/...`, so the `wsu` attribute comes first even though `wsu`
    // sorts after `xml` as three letters.
    let document = r#"<a xmlns:wsu="http://docs.oasis-open.org/x">
        <b xml:lang="en" wsu:Id="1"/>
      </a>"#;
    let canonical = canonicalize(document, "b").expect("canonicalises");
    assert!(
        canonical.find("wsu:Id").expect("wsu") < canonical.find("xml:lang").expect("xml"),
        "the xml prefix sorts under its own URI: {canonical}"
    );
}

/// Text escaping is the specification's set, and no more.
///
/// Escaping the apostrophe or the quote in text is a different digest from every conforming
/// implementation, so "escape everything to be safe" is precisely the wrong instinct here.
#[test]
fn text_escaping_is_exactly_the_specified_set() {
    assert_eq!(
        canonicalize("<a>&amp; &lt; &gt; ' \" x</a>", "a").expect("canonicalises"),
        "<a>&amp; &lt; &gt; ' \" x</a>"
    );
}

/// A declaration the subtree does not visibly use is NOT rendered, which is what "exclusive"
/// means and why a signed assertion survives being moved between documents.
#[test]
fn an_unused_declaration_is_not_rendered() {
    let inside = r#"<Response xmlns:unused="urn:nobody" xmlns:saml="urn:s">
        <saml:Assertion ID="_a"/>
      </Response>"#;
    let elsewhere = r#"<OtherResponse xmlns:saml="urn:s" xmlns:different="urn:x">
        <saml:Assertion ID="_a"/>
      </OtherResponse>"#;
    assert_eq!(
        canonicalize(inside, "saml:Assertion").expect("canonicalises"),
        canonicalize(elsewhere, "saml:Assertion").expect("canonicalises"),
        "an assertion signed in one document must canonicalise identically in another"
    );
}
