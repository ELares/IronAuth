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
//! So the table lives here, every [`Coverage::Tests`] row names real `#[test]` functions, and
//! this file FAILS if a named function is not an actual test in this crate. Renaming a test
//! without updating its row is a red build.
//!
//! # Three defects the first version of this file had, because they are the ones to watch for
//!
//! IT SCANNED A HAND-WRITTEN LIST OF FOUR FILENAMES, and the row it was written for named a test
//! in a fifth. The build was red on the commit that introduced it, and the commit message
//! claimed the whole thing had been mutation-verified -- which cannot have happened, because a
//! mutation check needs a green baseline. The scan now WALKS the directories; a list covers what
//! somebody thought of.
//!
//! IT WAS A PLAIN SUBSTRING MATCH, so `// fn foo(` in a comment, or a helper function that is
//! not a test at all, satisfied a row. It now requires a `#[test]` or `#[tokio::test]` attribute
//! within a few lines above, and refuses a commented-out line.
//!
//! ONE ROW NAMED A TEST THAT MEASURED NOTHING IT CLAIMED. "Bound document size, depth and
//! breadth" pointed at a test that only ever set an attribute-count and a name-length limit; all
//! three bound guards could be deleted from the parser with that row still green. Rows now name
//! EVERY test that carries the control, which is why [`Coverage::Tests`] takes a slice.
//!
//! # What this still cannot check, said out loud
//!
//! It checks that the named tests EXIST, not that they prove what the row claims. That gap is
//! real, and the rationale on every row is what a reader needs to judge it. The thing that
//! actually covers the gap is the mutation sweep over the crate, not this file: a row whose test
//! exists but proves nothing is caught by removing the guard and watching the suite stay green.
//!
//! It also cannot tell that a ROW WAS DELETED. A count floor is a ratchet and nothing more: it
//! catches a row going missing by accident, not a row removed on purpose, because the expected
//! value would live in the same file as the thing it bounds.
//!
//! # The source, and what "complete" means
//!
//! The rows follow the published OWASP SAML Security Cheat Sheet
//! (<https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html>) section by
//! section. An earlier version held 21 rows and silently omitted about two dozen published
//! items, which is the failure a checklist exists to prevent, so the omitted ones are all here
//! now -- most as N/A, because most of them are about a deployment or a protocol flow that this
//! crate is deliberately not.
//!
//! Needs no database.

/// How an item is covered.
enum Coverage {
    /// The names of `#[test]` functions in this crate, ALL of which must exist.
    ///
    /// A slice rather than one name, because a control is often carried by several tests and
    /// naming only one of them lets the others be deleted with the row still green.
    Tests(&'static [&'static str]),
    /// Out of scope for this crate, with the reason and the issue that owns it.
    NotApplicable(&'static str),
    /// In scope for this crate and NOT DONE, with the criterion that owns it.
    ///
    /// Separate from [`Coverage::NotApplicable`] because they are different facts and blurring
    /// them is how a gap becomes invisible: an N/A says "not ours", a gap says "ours, missing".
    Gap(&'static str),
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

/// The cheat sheet, item by item, in its own section order.
const CHEAT_SHEET: &[Item] = &[
    // -- Validate Message Confidentiality and Integrity -------------------------------------
    Item {
        control: "Exchange assertions only over secure transports (TLS 1.2 or better)",
        coverage: Coverage::NotApplicable(
            "This crate takes decoded bytes from a caller and opens no socket. Transport is the \
             SP flow's, and issue #139 owns the ACS endpoint that terminates it.",
        ),
        rationale: "A transport claim made by a component with no transport would be a claim \
                    about somebody else's code.",
    },
    Item {
        control: "Use strong encryption and signature algorithms throughout the chain",
        coverage: Coverage::Tests(&["a_refused_algorithm_is_refused_before_anything_is_verified"]),
        rationale: "The signature allowlist is exactly RSA and ECDSA over SHA-256/384/512, and \
                    the digest allowlist exactly SHA-256/384/512. Nothing else is accepted.",
    },
    Item {
        control: "Deprecate support for insecure XMLEnc algorithms",
        coverage: Coverage::Gap(
            "XML Encryption is not implemented, so there is no algorithm set to deprecate yet. \
             Criterion 5 of this issue (#138) owns it, and the allowlist has to exclude \
             RSA-1.5 (the Bleichenbacher class, Keycloak CVE-2026-2092) and CBC modes (the \
             padding-oracle class) from the first line of code rather than later.",
        ),
        rationale: "Recorded as a GAP rather than an N/A: it is this crate's work and it is \
                    missing, which is a different fact from being out of scope.",
    },
    // -- Validate Protocol Usage ------------------------------------------------------------
    Item {
        control: "Reject malformed documents before anything else happens",
        coverage: Coverage::Tests(&[
            "malformedness_is_a_single_refusal",
            "a_refused_algorithm_is_refused_before_anything_is_verified",
        ]),
        rationale: "Parsing is the only entry point and it refuses before any signature work; \
                    the second test asserts that ordering against `verify` itself rather than \
                    against a type argument, which an earlier version of this crate wrongly \
                    claimed made it structural.",
    },
    Item {
        control: "Validate against a schema, from a local trusted copy, with no network fetch",
        coverage: Coverage::NotApplicable(
            "This crate performs NO schema validation, and does not pretend to: it checks \
             well-formedness, bounds and signature structure. The SAML schema constrains a \
             protocol this crate does not implement, so issue #139 owns it. What matters for \
             the sub-bullets is that nothing here fetches anything: the parser does no I/O at \
             all and refuses a DOCTYPE, so an external schema or entity reference has nowhere \
             to resolve.",
        ),
        rationale: "Stated plainly because an earlier row claimed this control and backed it \
                    with a well-formedness test, which is a different thing wearing its name.",
    },
    Item {
        control: "Validate AuthnRequest and Response processing rules (SAML Core, Profiles 4.1.5)",
        coverage: Coverage::NotApplicable(
            "Neither message is processed here: this crate verifies a signature over an element \
             a caller names and interprets no SAML semantics. Issue #139 owns both.",
        ),
        rationale: "The processing rules are about a flow, and a flow needs state this crate \
                    has none of.",
    },
    Item {
        control: "Validate the Recipient, InResponseTo and SubjectConfirmationData",
        coverage: Coverage::NotApplicable(
            "The correlation is with a request this crate never made, and there is no \
             configured recipient here to compare against. Issue #139 owns it.",
        ),
        rationale: "Half a check in a crate with no configuration reads as a whole one.",
    },
    Item {
        control: "Validate the Destination against this service provider's ACS URL",
        coverage: Coverage::NotApplicable(
            "No endpoint is configured here. Issue #139 owns it, with the caveat recorded in \
             its plan that when the Response is unsigned -- Okta's and Entra's default -- the \
             Destination attribute is attacker-mutable, so reading it off the Response is a \
             no-op check.",
        ),
        rationale: "The item is only meaningfully owned where the signed subtree is known.",
    },
    Item {
        control: "Validate NotBefore / NotOnOrAfter and bound clock skew",
        coverage: Coverage::NotApplicable(
            "There is no clock in this crate, deliberately: a verifier that took one would make \
             every test in it time-dependent. Issue #139 owns the condition checks.",
        ),
        rationale: "The checks belong with the flow that has a clock and a skew setting.",
    },
    Item {
        control: "Prevent assertion replay",
        coverage: Coverage::NotApplicable(
            "Replay prevention needs durable state across requests and this crate touches no \
             database. Issue #139 owns the replay table.",
        ),
        rationale: "A cache inside a pure verifier would be per-process, so it would look like \
                    protection while providing none behind two replicas.",
    },
    Item {
        control: "Validate the binding implementation (HTTP Redirect 3.4, HTTP POST 3.5)",
        coverage: Coverage::NotApplicable(
            "No binding is implemented here. The crate documentation records the one thing a \
             binding will have to carry that this crate cannot: `Limits::max_bytes` measures a \
             buffer AFTER something else produced it, so the DEFLATE inflate in the Redirect \
             binding needs its own output bound. Issue #139 owns both bindings.",
        ),
        rationale: "Named rather than omitted precisely because the compression bomb lands \
                    upstream of every bound this crate has.",
    },
    Item {
        control: "Validate RelayState: bound its length, and allowlist it if it is a URL",
        coverage: Coverage::NotApplicable(
            "RelayState is a binding parameter and never reaches this crate. Issue #139 owns \
             it, and its plan names the open-redirect shape.",
        ),
        rationale: "It is a query parameter, not part of the document this crate parses.",
    },
    Item {
        control: "Prefer IP filtering where the deployment allows it",
        coverage: Coverage::NotApplicable(
            "A network control, made by whatever fronts the deployment. Nothing in this \
             repository can assert it, and issue #139 does not either.",
        ),
        rationale: "An item a library cannot implement is worth an explicit N/A rather than \
                    silence, so a reader does not go looking for it.",
    },
    // -- Validate Signatures ----------------------------------------------------------------
    Item {
        control: "Ensure each Assertion, or the entire Response, is signed",
        coverage: Coverage::Tests(&[
            "no_pinned_key_means_no_signature_verifies",
            "two_genuinely_signed_assertions_are_refused_rather_than_resolved",
        ]),
        rationale: "An element with no signature over it produces no `VerifiedAssertion` at \
                    all, so 'is it signed' is not a check a caller can forget: it is the only \
                    way to get a value. RESPONSE-level signing is the half this crate does not \
                    yet drive -- `verify` takes one element and one signature that is its \
                    CHILD, so a caller must name the Response itself. Issue #139 owns making \
                    that a single call.",
    },
    Item {
        control: "Validate the signature over the exact node that is consumed afterwards",
        coverage: Coverage::Tests(&[
            "content_added_inside_the_signature_is_not_returned",
            "the_signed_original_hidden_inside_the_signature_is_refused",
        ]),
        rationale: "The verifier returns the subtree it DIGESTED, so there is no second lookup \
                    to disagree with the first. An earlier revision returned the original \
                    subtree and was an authenticate-as-anyone bug; the first test is that \
                    document.",
    },
    Item {
        control: "Reject XML Signature Wrapping in all its published forms",
        coverage: Coverage::Tests(&[
            "a_forged_assertion_before_the_signed_one_is_refused",
            "a_forged_assertion_after_the_signed_one_is_refused",
            "the_signed_assertion_nested_inside_a_forged_one_is_refused",
            "a_second_assertion_under_another_prefix_is_still_a_second_assertion",
        ]),
        rationale: "tests/wrapping.rs is the corpus, traceable to Somorovsky et al. and to \
                    SAMLRaider's positions. The last one is this crate's own bypass: the \
                    candidate rule compared the raw PREFIXED name, so a second assertion under \
                    a different prefix in the same namespace was invisible.",
    },
    Item {
        control: "Reject duplicated element identifiers",
        coverage: Coverage::Tests(&[
            "two_elements_claiming_one_identifier_are_refused",
            "an_enclosing_element_claiming_the_same_identifier_is_refused",
        ]),
        rationale: "Two elements answering one reference is the wrapping class that needs no \
                    schema trick. Counted for unprefixed `ID`; `count_identifier` records what \
                    an `xml:id` twin leaves uncovered and why that is a divergence from \
                    libxml2 rather than a hole here.",
    },
    Item {
        control: "Never take the trust anchor from the document (embedded certificates)",
        coverage: Coverage::Tests(&[
            "a_valid_signature_from_an_unpinned_key_is_refused",
            "no_pinned_key_means_no_signature_verifies",
        ]),
        rationale: "Anchors are a caller-supplied argument and `KeyInfo` is never read. The \
                    first test carries a document with a genuinely valid self-signature.",
    },
    Item {
        control: "Enforce a signature algorithm allowlist and exclude SHA-1",
        coverage: Coverage::Tests(&[
            "a_refused_algorithm_is_refused_before_anything_is_verified",
            "the_error_does_not_reveal_which_key_kind_was_pinned",
        ]),
        rationale: "`rsa-sha1` is still the deployed default in much of the field and is absent \
                    here. The second test pins the other half: the refusal must not vary with \
                    the SERVER's pinned key, or the error is an oracle.",
    },
    Item {
        control: "Enforce a transform allowlist (no XPath, no XSLT)",
        coverage: Coverage::Tests(&[
            "an_unexpected_transform_list_is_refused",
            "a_foreign_element_inside_the_transform_list_is_refused",
            "a_transform_without_an_algorithm_is_refused",
            "an_inclusive_namespaces_prefix_list_is_refused",
        ]),
        rationale: "An allowlist of a SEQUENCE, not of a set. The last three are the ways a \
                    document can carry a transform the allowlist does not SEE: in another \
                    namespace, with no `Algorithm` at all, or as a prefix list nested inside a \
                    transform that is on the list.",
    },
    Item {
        control: "Canonicalize exactly as the signer did",
        coverage: Coverage::Tests(&[
            "a_prefix_declared_on_an_ancestor_is_rendered_on_the_apex",
            "attributes_sort_by_namespace_uri_then_local_name",
            "declarations_are_rendered_default_first_then_by_prefix",
            "a_declaration_on_signed_info_is_in_scope_for_its_children",
        ]),
        rationale: "tests/canonical.rs drives the canonicalizer against the specification \
                    rather than against this crate's own signer, because a signer and a \
                    verifier sharing a bug agree with each other perfectly.",
    },
    Item {
        control: "Handle comment truncation in signed values (CVE-2017-11427 and its siblings)",
        coverage: Coverage::Tests(&[
            "a_comment_inside_a_signed_value_does_not_truncate_it",
            "a_comment_anywhere_in_a_signed_value_reads_back_whole",
        ]),
        rationale: "A value split by a comment reads back whole. Two mechanisms do it and \
                    mutation shows neither is load-bearing alone, which the note on the \
                    `Event::Comment` arm in tree.rs records.",
    },
    // -- Validate the Message Itself --------------------------------------------------------
    Item {
        control: "Disable DTD processing and external entity resolution (XXE)",
        coverage: Coverage::Tests(&["a_doctype_is_refused_whatever_it_declares"]),
        rationale: "A DOCTYPE is refused outright rather than merely not resolved, so the XXE, \
                    SSRF and billion-laughs payloads all lose the place they would live. A \
                    parser that only declined to RESOLVE would also pass; refusing is the \
                    stronger statement and it survives a change of parser.",
    },
    Item {
        control: "Bound entity expansion",
        coverage: Coverage::Tests(&[
            "an_undefined_entity_reference_is_refused_rather_than_emptied",
        ]),
        rationale: "With no DTD there is nothing to declare an entity, so an expansion bound \
                    would bound a thing that cannot exist. What remains is a reference to an \
                    entity nothing declared, and that is refused rather than silently emptied.",
    },
    Item {
        control: "Bound document size, depth and breadth",
        coverage: Coverage::Tests(&[
            "an_oversized_document_is_refused",
            "a_deeply_nested_document_is_refused",
            "a_document_with_too_many_elements_is_refused",
            "one_element_cannot_be_unbounded",
            "a_caller_cannot_ask_for_a_depth_that_would_abort_the_process",
        ]),
        rationale: "Five separate bounds and five separate tests, because each is a way to be \
                    expensive that the others do not cover. An earlier version of this row \
                    named only the last one, which sets an attribute count and a name length \
                    and measures none of size, depth or element count: all three parser guards \
                    could be deleted with the row still green.",
    },
    Item {
        control: "Reject malformed qualified names and namespace declarations",
        coverage: Coverage::Tests(&[
            "a_malformed_qualified_name_is_refused",
            "a_namespace_declaration_is_not_a_readable_attribute",
            "a_namespace_declaration_is_not_visible_through_debug",
        ]),
        rationale: "Not a cheat-sheet row, kept because it is this crate's own finding: \
                    `xmlns:` with an empty local part was read as a DEFAULT declaration, so \
                    two different documents produced identical canonical octets. And a \
                    declaration is not an attribute: an unused one is never digested, so it \
                    must not be readable through an accessor or through `Debug`.",
    },
    // -- X.509 Certificate Considerations ---------------------------------------------------
    Item {
        control: "Certificate strength, lifetime, key usage, and CRL/OCSP revocation checking",
        coverage: Coverage::NotApplicable(
            "This crate never sees a certificate. A trust anchor here is a raw public key -- an \
             uncompressed point or an RSA modulus and exponent -- supplied by the caller, so \
             there is no chain to validate, no lifetime to bound and no revocation list to \
             consult. Issue #139 introduces certificate pinning and metadata, and owns every \
             item in this section.",
        ),
        rationale: "The raw-key shape is deliberate: it is what makes 'never take the anchor \
                    from the document' structural rather than a rule somebody has to follow.",
    },
    Item {
        control: "Protect the signing key (HSM or equivalent) and fetch metadata over trusted TLS",
        coverage: Coverage::NotApplicable(
            "This crate holds no signing key -- it only verifies -- and fetches nothing. Issue \
             #139 owns metadata retrieval.",
        ),
        rationale: "A verifier with no private key cannot mishandle one, which is worth saying \
                    rather than leaving the row absent.",
    },
    // -- Assertion and Session Management ---------------------------------------------------
    Item {
        control: "Validate session state, session management, and SAML logout criteria",
        coverage: Coverage::NotApplicable(
            "There are no sessions here. IronAuth's session and logout machinery is a different \
             subsystem entirely, and issue #139 is what connects a verified assertion to it.",
        ),
        rationale: "Named so a reader can see the boundary rather than guess at it.",
    },
    Item {
        control: "Set authorization context at an appropriate granularity, and verify identities",
        coverage: Coverage::NotApplicable(
            "This crate returns a verified subtree and asserts nothing about identity or \
             authorization. Issue #139 maps an assertion onto a user, and #98 owns the RBAC \
             model it maps into.",
        ),
        rationale: "The one thing this crate does for the item is make sure the values a mapper \
                    reads were signed, which the signature rows above carry.",
    },
    // -- Encrypted assertions ---------------------------------------------------------------
    Item {
        control: "Decrypt encrypted assertions, then re-validate the decrypted content",
        coverage: Coverage::Gap(
            "XML Encryption is not implemented. It is criterion 5 of this same issue (#138) and \
             is the next thing to land in this crate.",
        ),
        rationale: "A GAP, not an N/A: it is in this crate's scope and it is missing. An item \
                    silently absent from a checklist is the failure this file exists to \
                    prevent, and an item mislabelled as out of scope is the same failure with \
                    better manners.",
    },
    // -- Fuzzing ----------------------------------------------------------------------------
    Item {
        control: "Fuzz the parser, canonicalizer and verifier continuously",
        coverage: Coverage::Tests(&[
            "every_fuzz_target_has_a_tracked_seed_corpus",
            "every_canonicalization_seed_reaches_the_canonicalizer",
            "the_corpus_covers_both_answers_and_reaches_the_verifier",
        ]),
        rationale: "Three targets live in fuzz/ and run on the scheduled lane, enforced by \
                    scripts/fuzz-matrix-freshness.sh. The named tests are the stable-CI half: \
                    the scheduled lane needs nightly and does not run on a pull request, so \
                    without them nothing on the merge path looks at the corpus at all.",
    },
];

/// Every `#[test]` function in this crate, found by WALKING the source rather than by reading a
/// list of filenames.
///
/// # The list was the bug
///
/// The first version of this file hand-listed four paths, and the row it was written for named a
/// test in a fifth that this same commit added. The build was red the moment it landed. A walk
/// covers what is there; a list covers what somebody remembered.
///
/// Inline `#[cfg(test)]` modules under `src/` are walked too, because a test does not stop being
/// a test for living beside the code.
fn every_test_in_this_crate() -> std::collections::BTreeSet<String> {
    fn walk(directory: &std::path::Path, into: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, into);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                into.push(path);
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("tests"), &mut files);
    walk(&root.join("src"), &mut files);
    assert!(
        files.len() >= 8,
        "the walk found only {} source files, so it is not walking what it thinks it is",
        files.len()
    );

    let mut names = std::collections::BTreeSet::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a source file is readable");
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            // A COMMENTED-OUT LINE IS NOT A TEST. An earlier version matched `fn name(`
            // anywhere, so `// fn foo(` in a doc comment satisfied a row.
            if trimmed.starts_with("//") {
                continue;
            }
            let Some(rest) = trimmed
                .strip_prefix("fn ")
                .or_else(|| trimmed.strip_prefix("async fn "))
            else {
                continue;
            };
            let Some(name) = rest.split('(').next() else {
                continue;
            };
            // AND IT MUST CARRY A TEST ATTRIBUTE. A helper function is not a test, and naming
            // one in a row would claim coverage from a function nothing ever runs.
            let attributed = lines[index.saturating_sub(4)..index].iter().any(|above| {
                let above = above.trim_start();
                above.starts_with("#[test]")
                    || above.starts_with("#[tokio::test")
                    || above.starts_with("#[test_case")
            });
            if attributed {
                names.insert(name.trim().to_owned());
            }
        }
    }
    names
}

/// Every row names tests that exist, or carries a reason with an owner.
#[test]
fn every_checklist_item_names_a_test_that_exists_or_a_reason() {
    let tests = every_test_in_this_crate();
    assert!(
        tests.contains("every_checklist_item_names_a_test_that_exists_or_a_reason"),
        "the walk cannot find this very test, so it finds nothing"
    );

    let mut named = 0_usize;
    let mut excused = 0_usize;
    let mut gaps = 0_usize;
    let mut controls = std::collections::BTreeSet::new();
    for item in CHEAT_SHEET {
        assert!(
            !item.rationale.trim().is_empty(),
            "{}: every row needs a rationale a reader can audit",
            item.control
        );
        assert!(
            controls.insert(item.control),
            "{}: two rows carry the same control, so one of them covers nothing",
            item.control
        );
        match item.coverage {
            Coverage::Tests(covering) => {
                assert!(
                    !covering.is_empty(),
                    "{}: a Tests row with no names claims coverage from nothing",
                    item.control
                );
                named += 1;
                for name in covering {
                    assert!(
                        tests.contains(*name),
                        "{}: names `{name}`, which is not a #[test] in this crate",
                        item.control
                    );
                }
            }
            Coverage::NotApplicable(reason) => {
                excused += 1;
                assert!(
                    reason.contains("issue #") || reason.contains("(#") || reason.contains("#139"),
                    "{}: an N/A must name the issue that DOES own the item, or say plainly that \
                     nothing in this repository can assert it",
                    item.control
                );
            }
            Coverage::Gap(reason) => {
                gaps += 1;
                assert!(
                    reason.contains("#138"),
                    "{}: a GAP is work THIS issue owns, so it must name it",
                    item.control
                );
            }
        }
    }

    // FLOORS, and they are a ratchet rather than a proof. They catch a row or a name going
    // missing by accident; they cannot catch one removed on purpose, because the expected value
    // would live in the same file as the thing it bounds. That limit is in the module doc.
    assert!(named >= 14, "only {named} rows are covered by tests");
    assert!(
        excused >= 12,
        "only {excused} rows are excused as out of scope"
    );
    assert!(
        gaps >= 1,
        "no row is recorded as a gap; the encrypted-assertion work is one"
    );
}

/// The rows that name tests name ENOUGH of them.
///
/// # Why a separate assertion
///
/// The row that failed review named exactly one test, and that test measured none of the three
/// things the control was about. One name is where that failure lives: a control carried by
/// several guards, pinned to one test, lets every other guard be deleted with the row green.
/// This is not a proof that the names are the right ones -- nothing in this file can be -- but a
/// row whose control enumerates several properties and names one test is visible here.
#[test]
fn a_row_naming_several_properties_names_several_tests() {
    for item in CHEAT_SHEET {
        let Coverage::Tests(covering) = item.coverage else {
            continue;
        };
        let conjunctions =
            item.control.matches(',').count() + item.control.matches(" and ").count();
        if conjunctions >= 2 {
            assert!(
                covering.len() >= 2,
                "{}: the control names {} separate properties and the row names {} test(s)",
                item.control,
                conjunctions + 1,
                covering.len()
            );
        }
    }
}
