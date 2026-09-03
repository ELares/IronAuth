// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OWASP SAML Security Cheat Sheet, as an EXECUTABLE checklist (issue #138, criterion 6).
//!
//! # Why this is a test and not a document
//!
//! The criterion asks that "the OWASP checklist maps every item to a test or a written N/A".
//! A markdown table would satisfy the words and nothing else: it would go stale the first time a
//! test was renamed, and the failure mode of a stale checklist is the worst one available, which
//! is a reader believing a control exists because a document says so.
//!
//! So the table lives here, every [`Coverage::Test`] row names a real `#[test]` function, and
//! this file FAILS if the named function is not in the crate's test sources. Renaming a test
//! without updating its row is a red build.
//!
//! # What this cannot check, said out loud
//!
//! It checks that the named test EXISTS, not that the test proves what the row claims. That gap
//! is real and it is why every row also carries the sentence a reader would need to judge it.
//! The reason the gap is acceptable here is that the named tests are all in the same crate and
//! all mutation-verified: each was confirmed to FAIL with the guard it covers removed. A row
//! whose test exists but proves nothing is caught by that sweep, not by this file.
//!
//! Rows marked [`Coverage::NotApplicable`] carry the reason, and the reason has to be about
//! SCOPE -- something this crate structurally does not do -- rather than about difficulty. Every
//! one of them names the issue that does own the item.
//!
//! Needs no database.

/// How an item is covered.
enum Coverage {
    /// The name of a `#[test]` function in this crate, which must exist.
    Test(&'static str),
    /// Out of scope for this crate, with the reason and the issue that owns it.
    NotApplicable(&'static str),
}

/// One cheat-sheet item.
struct Item {
    /// The control, in the cheat sheet's own terms.
    control: &'static str,
    /// What this crate does about it.
    coverage: Coverage,
    /// Why that is the right answer. A row without this is a row nobody can audit.
    rationale: &'static str,
}

/// The cheat sheet, item by item.
///
/// The grouping follows the OWASP SAML Security Cheat Sheet's own headings: validate the message,
/// validate the signature, validate the protocol usage, and the deployment concerns around them.
const CHEAT_SHEET: &[Item] = &[
    Item {
        control: "Validate XML schema / reject malformed documents before anything else",
        coverage: Coverage::Test("malformedness_is_a_single_refusal"),
        rationale: "Parsing is the first and only entry point, and it refuses before any \
                    signature work. Size, DOCTYPE and structure, in that order.",
    },
    Item {
        control: "Disable DTD processing and external entity resolution (XXE)",
        coverage: Coverage::Test("a_doctype_is_refused_whatever_it_declares"),
        rationale: "A DOCTYPE is refused outright rather than merely not resolved, so the XXE, \
                    SSRF and billion-laughs payloads all lose the place they would live. A \
                    parser that only declined to RESOLVE would also pass; refusing is the \
                    stronger statement and it survives a change of parser.",
    },
    Item {
        control: "Bound entity expansion",
        coverage: Coverage::Test("an_undefined_entity_reference_is_refused_rather_than_emptied"),
        rationale: "With no DTD there is nothing to declare an entity, so an expansion bound \
                    would bound a thing that cannot exist. What remains is a reference to an \
                    entity nothing declared, and that is refused rather than silently emptied.",
    },
    Item {
        control: "Bound document size, depth and breadth",
        coverage: Coverage::Test("one_element_cannot_be_unbounded"),
        rationale: "Size, depth, element count, attributes per element and name length are each \
                    bounded, because each is a way to be expensive that the others do not \
                    cover. The fuzz target re-measures every accepted document against them.",
    },
    Item {
        control: "Validate the signature over the exact node that is consumed",
        coverage: Coverage::Test("content_added_inside_the_signature_is_not_returned"),
        rationale: "The verifier returns the subtree it DIGESTED, so there is no second lookup \
                    to disagree with the first. An earlier revision returned the original \
                    subtree instead and was an authenticate-as-anyone bug.",
    },
    Item {
        control: "Reject XML Signature Wrapping in all its published forms",
        coverage: Coverage::Test("a_forged_assertion_before_the_signed_one_is_refused"),
        rationale: "The whole of tests/wrapping.rs is the corpus, traceable to Somorovsky et \
                    al. and to SAMLRaider's positions; this row names its first entry.",
    },
    Item {
        control: "Reject duplicated element identifiers",
        coverage: Coverage::Test("an_enclosing_element_claiming_the_same_identifier_is_refused"),
        rationale: "Two elements answering one reference is the wrapping class that needs no \
                    schema trick. Counted for unprefixed ID; see count_identifier for what \
                    xml:id leaves uncovered and why that is a divergence rather than a hole.",
    },
    Item {
        control: "Do not take the trust anchor from the document (embedded certificates)",
        coverage: Coverage::Test("a_valid_signature_from_an_unpinned_key_is_refused"),
        rationale: "Anchors are a caller-supplied argument and KeyInfo is never read. The test \
                    carries a document with a genuinely valid self-signature.",
    },
    Item {
        control: "Enforce a signature algorithm allowlist and exclude SHA-1",
        coverage: Coverage::Test("a_refused_algorithm_is_refused_before_anything_is_verified"),
        rationale: "rsa-sha1 is still the deployed default in much of the field and is absent \
                    here. The refusal happens before any verification work.",
    },
    Item {
        control: "Enforce a transform allowlist (no XPath, no XSLT)",
        coverage: Coverage::Test("an_unexpected_transform_list_is_refused"),
        rationale: "An allowlist of a SEQUENCE, not of a set: exactly the enveloped-signature \
                    transform then exclusive canonicalization. Turing-complete transforms are \
                    ways to change what is digested.",
    },
    Item {
        control: "Handle comment truncation in signed values (CVE-2017-11427 and its siblings)",
        coverage: Coverage::Test("a_comment_inside_a_signed_value_does_not_truncate_it"),
        rationale: "A value split by a comment reads back whole. Two mechanisms do it and \
                    mutation shows neither is load-bearing alone, which the tree.rs note says.",
    },
    Item {
        control: "Canonicalize exactly as the signer did",
        coverage: Coverage::Test("a_prefix_declared_on_an_ancestor_is_rendered_on_the_apex"),
        rationale: "tests/canonical.rs drives the canonicalizer against the specification rather \
                    than against this crate's own signer, because a signer and a verifier \
                    sharing a bug agree with each other perfectly.",
    },
    Item {
        control: "Reject an InclusiveNamespaces prefix list rather than ignoring it",
        coverage: Coverage::Test("an_inclusive_namespaces_prefix_list_is_refused"),
        rationale: "A prefix list changes which declarations are emitted, so ignoring one \
                    digests under rules the signer did not use.",
    },
    Item {
        control: "Do not let error responses become an oracle",
        coverage: Coverage::Test("the_error_does_not_reveal_which_key_kind_was_pinned"),
        rationale: "One error variant per DECISION ABOUT THE DOCUMENT. A revision that varied \
                    the error with the SERVER's pinned key let an attacker holding no key read \
                    the key's kind out of which request answered differently.",
    },
    Item {
        control: "Validate the assertion's audience (Recipient / AudienceRestriction)",
        coverage: Coverage::NotApplicable(
            "This crate returns a verified subtree and interprets no SAML semantics: there is \
             no configured audience here to compare against. Owned by issue #139, which builds \
             the SP flow and holds the service provider's entity ID.",
        ),
        rationale: "Splitting it here would put half a check in a crate with no configuration, \
                    and half a check reads as a whole one.",
    },
    Item {
        control: "Validate NotBefore / NotOnOrAfter and bound clock skew",
        coverage: Coverage::NotApplicable(
            "There is no clock in this crate, deliberately: a verifier that took one would make \
             every test time-dependent. Owned by issue #139.",
        ),
        rationale: "The condition checks belong with the flow that has a clock and a skew \
                    setting, and issue #139 names them as its own criterion.",
    },
    Item {
        control: "Prevent assertion replay",
        coverage: Coverage::NotApplicable(
            "Replay prevention needs durable state across requests, and this crate has none and \
             touches no database. Owned by issue #139, which adds the replay table.",
        ),
        rationale: "A cache inside a pure verifier would be per-process and would therefore \
                    look like protection while providing none behind two replicas.",
    },
    Item {
        control: "Validate InResponseTo against a request this SP actually made",
        coverage: Coverage::NotApplicable(
            "The correlation is with a request this crate never made: there is no AuthnRequest \
             here. Owned by issue #139.",
        ),
        rationale: "The authoritative value lives in the flow's own state, not in the document.",
    },
    Item {
        control: "Validate the Destination against this SP's ACS URL",
        coverage: Coverage::NotApplicable(
            "No endpoint is configured here. Owned by issue #139, with the caveat recorded \
             there that when the Response is unsigned -- Okta's and Entra's default -- its \
             Destination attribute is attacker-mutable.",
        ),
        rationale: "Reading Destination off an unsigned Response is a no-op check, so the item \
                    is only meaningfully owned where the signed subtree is known.",
    },
    Item {
        control: "Decrypt encrypted assertions, then re-validate the decrypted content",
        coverage: Coverage::NotApplicable(
            "XML Encryption is not implemented yet. It is criterion 5 of this same issue \
             (#138) and is the next thing to land in this crate, not a deferral to another.",
        ),
        rationale: "Recorded as absent rather than omitted, because an item silently missing \
                    from a checklist is the failure this file exists to prevent.",
    },
    Item {
        control: "Fuzz the parser, canonicalizer and verifier continuously",
        coverage: Coverage::Test("the_corpus_covers_both_answers_and_reaches_the_verifier"),
        rationale: "Three targets live in fuzz/ and run on the scheduled lane, enforced by \
                    scripts/fuzz-matrix-freshness.sh. The named test is the stable-CI half: the \
                    scheduled lane needs nightly and does not run on a pull request, so without \
                    it nothing on the merge path looks at the corpus at all. What a fuzzer \
                    structurally cannot do is forge a signature, so it can only ever prove the \
                    accept path is UNREACHABLE; tests/wrapping.rs is where the accept path is \
                    driven, and neither substitutes for the other.",
    },
];

/// Every row that names a test names one that exists.
///
/// # What makes this able to fail
///
/// It scans the crate's test sources for `fn <name>(`. Renaming a test without updating its row
/// turns this red, which is the whole point: a checklist that cannot go stale is a checklist
/// whose rows a reader can trust.
#[test]
fn every_checklist_item_names_a_test_that_exists_or_a_reason() {
    let sources: Vec<String> = [
        "tests/hostile.rs",
        "tests/wrapping.rs",
        "tests/canonical.rs",
        "tests/owasp_checklist.rs",
    ]
    .iter()
    .map(|path| {
        std::fs::read_to_string(format!("{}/{path}", env!("CARGO_MANIFEST_DIR")))
            .unwrap_or_else(|error| panic!("{path} must be readable: {error}"))
    })
    .collect();

    let mut named = 0_usize;
    let mut excused = 0_usize;
    for item in CHEAT_SHEET {
        assert!(
            !item.rationale.trim().is_empty(),
            "{}: every row needs a rationale a reader can audit",
            item.control
        );
        match item.coverage {
            Coverage::Test(name) => {
                named += 1;
                let needle = format!("fn {name}(");
                assert!(
                    sources.iter().any(|source| source.contains(&needle)),
                    "{}: names the test `{name}`, which does not exist in this crate",
                    item.control
                );
            }
            Coverage::NotApplicable(reason) => {
                excused += 1;
                assert!(
                    reason.contains("issue #") || reason.contains("(#"),
                    "{}: an N/A must name the issue that DOES own the item, so the control has \
                     an owner rather than a shrug",
                    item.control
                );
            }
        }
    }
    // A NON-ZERO FLOOR ON BOTH SIDES. Without it an empty table, or a table that excused every
    // row, would pass a check whose whole purpose is that the rows are real.
    assert!(named >= 14, "only {named} items are covered by a test");
    assert!(excused >= 1, "only {excused} items are excused");
    assert_eq!(named + excused, CHEAT_SHEET.len());
}
