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
//! So the table lives here and every [`Coverage::Tests`] row names real `#[test]` functions.
//! THAT THEY EXIST IS CHECKED BY `scripts/saml-owasp-checklist.sh`, NOT BY THIS FILE, for the
//! reason the next section gives. Renaming a test without updating its row turns that script
//! red in CI's invariants job and in `scripts/gate.sh`.
//!
//! # THE NAME CHECK IS NOT HERE, AND THAT IS THE THIRD ATTEMPT
//!
//! Two versions of this file tried to verify that a named test EXISTS by scanning the source for
//! `fn <name>(`, and a source scan cannot decide what the compiler decided. `libtest` exposes no
//! list of the tests linked into a binary, so there was nothing sound to ask.
//!
//! The first scanned a hand-written list of four filenames, and the row it was written for named
//! a test in a fifth file the same commit added: the build was red on arrival. The second walked
//! the directories and required a `#[test]` attribute within four lines above the function --
//! which attributes a HELPER declared just after a test, misses a one-line
//! `#[test] fn foo() {}` entirely, and descends into `tests/compile-fail/`, whose files are
//! `trybuild` fixtures that are never compiled into any test binary. Both versions could report
//! a row as covered by a function nothing runs.
//!
//! `scripts/saml-owasp-checklist.sh` owns that check now. It reads
//! `cargo test -- --list`, which prints exactly the tests the compiler produced, and it runs in
//! CI's invariants job and in `scripts/gate.sh`.
//!
//! NOT "merge-blocking", which an earlier draft called it. Branch protection on `main` requires
//! one approving review and ZERO status checks, so a red invariants job does not stop a merge,
//! and the standing admin-squash authorisation makes that the normal path. A sentence telling a
//! reader the build cannot land in that state is worse than none: it is why they stop looking.
//!
//! What is left here is what a table CAN check about itself:
//! every row has a rationale, no two rows claim the same control, an N/A names an owner, and a
//! gap names the criterion it belongs to.
//!
//! # One defect that was about the ROWS rather than the mechanism
//!
//! A row named ONE test for a control about three separate bounds, and that test measured none
//! of them: all three parser guards could be deleted with the row still green. Rows now name
//! EVERY test that carries the control, which is why [`Coverage::Tests`] takes a slice, and a
//! second test refuses a row whose control enumerates several properties while naming one test.
//!
//! # What this still cannot check, said out loud
//!
//! That a named test proves what its row claims. The rationale on every row is what a reader
//! needs to judge it, and the thing that actually covers the gap is the mutation sweep over the
//! crate: a row whose test exists but proves nothing is caught by removing the guard and
//! watching the suite stay green.
//!
//! It also cannot tell that a ROW WAS DELETED. A count floor is a ratchet and nothing more, and
//! this file has already demonstrated the limit: the commit that added two dozen missing items
//! also DELETED the audience row, and no floor noticed because the total went up.
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
    ///
    /// # Currently unused, and kept on purpose
    ///
    /// Both gaps were XML Encryption and criterion 5 closed them, so nothing constructs this
    /// today. Deleting it would leave the table unable to SAY "this is ours and it is missing",
    /// and the alternative -- folding such an item into `NotApplicable` -- is exactly the
    /// blurring the paragraph above refuses.
    #[allow(
        dead_code,
        reason = "the vocabulary outlives the current gaps; see the note above"
    )]
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
        rationale: "The signature allowlist is exactly rsa-sha256/384/512 and ecdsa-sha256/384; \
                    the digest allowlist exactly SHA-256/384/512. NOT ecdsa-sha512, which an \
                    earlier version of this row claimed: `ring` offers the fixed-width \
                    verification XMLDSIG needs only for the matched hash and curve pairs, and \
                    the crate documentation is where that narrowing is recorded. A row that \
                    overstates the allowlist hides the one place it was written down.",
    },
    Item {
        control: "Deprecate support for insecure XMLEnc algorithms",
        coverage: Coverage::Tests(&["the_broken_algorithms_are_refused_before_the_seam"]),
        rationale: "There was never anything to deprecate: the allowlist excluded RSA-1.5 (the \
                    Bleichenbacher class) and every CBC mode (the Jager and Somorovsky \
                    plaintext-recovery class) from its first line. CBC is refused structurally \
                    because `ring` offers none, and RSA-1.5 is refused BEFORE the caller's \
                    unwrapper is asked, so the unwrapper cannot become the oracle.",
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
        coverage: Coverage::Tests(&[
            "a_response_naming_no_request_is_refused_when_one_was_required",
            "a_response_naming_a_different_request_is_refused",
            "an_unsolicited_response_is_admissible_only_when_it_names_no_request",
            "a_missing_recipient_is_a_refusal_and_not_a_pass",
            "an_assertion_addressed_to_another_endpoint_is_refused",
            "the_confirmations_own_expiry_is_checked_and_is_a_different_bound",
            "a_bearer_confirmation_that_is_not_yet_usable_is_refused_rather_than_used",
            "a_holder_of_key_confirmation_is_not_honoured_as_a_bearer_one",
            "two_bearer_confirmations_are_refused_rather_than_letting_one_win",
        ]),
        rationale: "`conditions::check` compares all three against an `Expectations` the caller \
                    supplies, so the configuration this row once said was missing is now the \
                    argument. ABSENCE IS A REFUSAL for the recipient and for the confirmation \
                    expiry, which is the half an earlier version of this crate got wrong: the \
                    defence disappeared exactly when an attacker omitted the attribute. The \
                    profile's one MUST NOT is covered too -- a bearer `SubjectConfirmationData` \
                    carrying a `NotBefore` is refused rather than honoured through a window \
                    nothing evaluates.",
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
        control: "Validate the assertion's audience (Recipient and AudienceRestriction)",
        coverage: Coverage::Tests(&[
            "an_assertion_for_another_service_provider_is_refused",
            "an_assertion_restricted_to_nobody_is_refused",
            "an_assertion_naming_several_audiences_is_accepted_and_every_restriction_must_hold",
            "a_proxy_restriction_naming_us_is_not_an_address_to_us",
            "a_value_spliced_across_nested_elements_is_not_the_value_it_spells",
        ]),
        rationale: "RESTORED. This row existed, and the commit that added two dozen missing \
                    items DELETED it while claiming the checklist was now complete. No count \
                    floor noticed, because the total went up. That is the limit of a ratchet \
                    stated as a fact rather than as a caveat.",
    },
    Item {
        control: "Never select security-relevant elements by tag name; use absolute paths",
        coverage: Coverage::Tests(&[
            "a_second_assertion_under_another_prefix_is_still_a_second_assertion",
            "a_foreign_signature_as_a_direct_child_is_not_a_signature",
            "a_prefix_rebound_under_signed_info_is_not_the_signature_namespace",
            "an_assertion_with_no_signature_of_its_own_is_refused",
        ]),
        rationale: "The cheat sheet's target is `getElementsByTagName`, and this crate's \
                    equivalent is `collect`. It is not a tag-name search: identity is (namespace \
                    URI, local name), resolved against the declarations in scope, which the \
                    first test exists because an earlier version got wrong. `collect` IS a \
                    descendant search, though -- so what an absolute path buys is bought one \
                    layer up instead, by every SAML value that decides identity or validity \
                    being read as a DIRECT CHILD: see `VerifiedAssertion::children` and the \
                    conditions suite's \
                    `an_assertion_nested_in_an_attribute_value_supplies_none_of_this_ones_answers`, \
                    which is there because a descendant search let a nested assertion's Issuer, \
                    Subject and Conditions answer for the real one. The last test here pins the \
                    signature half -- a signature nested below the assertion is not the \
                    assertion's.",
    },
    Item {
        control: "Prefer OneTimeUse and short lifetimes on the Response",
        coverage: Coverage::NotApplicable(
            "Both are conditions on a Response this crate does not interpret, and honouring \
             OneTimeUse needs the durable state a replay cache is. Issue #139 owns them together \
             with the replay table.",
        ),
        rationale: "Named rather than folded into the time-bounds row, because OneTimeUse is a \
                    different mechanism from an expiry and an implementation can ship one \
                    without the other.",
    },
    Item {
        control: "Refuse unsolicited responses (IdP-initiated SSO) unless deliberately enabled",
        coverage: Coverage::NotApplicable(
            "Unsolicited means there was no AuthnRequest to correlate against, and this crate \
             never made one. Issue #139 owns it, and its plan records the shape: refused by \
             default, per-connection opt-in, and with the opt-in on, a replayed assertion ID \
             rejected for the full validity window.",
        ),
        rationale: "This is login CSRF rather than a signature problem, which is why it belongs \
                    with the flow: an attacker who can post a VALID assertion for their own \
                    account signs the victim's browser into it.",
    },
    Item {
        control: "Validate NotBefore / NotOnOrAfter and bound clock skew",
        coverage: Coverage::Tests(&[
            "an_expired_assertion_and_one_not_yet_valid_are_both_refused",
            "an_assertion_with_no_expiry_is_refused_rather_than_treated_as_open",
            "an_assertion_valid_for_longer_than_this_connection_allows_is_refused",
            "the_clock_skew_is_applied_at_both_edges_and_a_smaller_one_refuses_more",
            "every_time_comparison_is_pinned_at_its_exact_boundary",
            "an_inverted_window_is_malformed_rather_than_expired",
            "a_missing_bound_says_which_one_rather_than_reporting_an_expiry",
            "a_bound_that_is_present_and_unreadable_is_not_reported_as_absent",
        ]),
        rationale: "STILL NO CLOCK: `check` takes `now_unix_secs` as an argument, so the \
                    property this row used to defer for -- every test being time-dependent -- is \
                    preserved, and the boundaries can be driven exactly. The skew is bounded \
                    below at zero and saturating; it is NOT bounded above, which \
                    `Expectations::clock_skew_secs` says out loud, because nothing here can \
                    know what too large means for a deployment.",
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
             repository can assert it: there is no issue that owns it, because there is no \
             code it could live in.",
        ),
        rationale: "An item a library cannot implement is worth an explicit N/A rather than \
                    silence, so a reader does not go looking for it.",
    },
    // -- Validate Signatures ----------------------------------------------------------------
    Item {
        control: "Ensure each Assertion, or the entire Response, is signed",
        coverage: Coverage::Tests(&[
            "an_assertion_with_no_signature_of_its_own_is_refused",
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
    Item {
        control: "Validate that the assertion was signed by an AUTHORIZED identity provider",
        coverage: Coverage::NotApplicable(
            "Distinct from never taking the anchor from the document, which this crate does \
             enforce: that is about KeyInfo, this is about WHICH pinned identity provider a \
             given connection may be served by. `verify` takes a list of anchors and asks only \
             whether one of them signed; deciding that THIS connection may be served by THAT \
             identity provider needs the connection, which is issue #139.",
        ),
        rationale: "Named separately because the two are easy to conflate and a deployment with \
                    several identity providers is exactly where conflating them lets one tenant's \
                    identity provider mint an assertion another tenant's connection accepts.",
    },
    Item {
        control: "Validate strong authentication options at the identity provider",
        coverage: Coverage::NotApplicable(
            "An identity provider concern, and IronAuth is the service provider here. The SAML \
             half of it -- reading and acting on AuthnContext -- is issue #139.",
        ),
        rationale: "A service provider can require an authentication context; it cannot make the \
                    identity provider honour one. The item is real and it is not this crate's.",
    },
    Item {
        control: "Synchronize to a common Internet time source",
        coverage: Coverage::NotApplicable(
            "A deployment concern with no code in this repository to hold it: there is no clock \
             in this crate at all, deliberately. Nothing in this repository can assert it.",
        ),
        rationale: "The consequence lands on the time-bounds check that issue #139 owns, so an \
                    operator reading that row finds this one beside it.",
    },
    Item {
        control: "Define levels of assurance for identity verification",
        coverage: Coverage::NotApplicable(
            "A policy decision expressed through AuthnContext class references, which issue #139 \
             maps. This crate returns a verified subtree and reads no semantics from it.",
        ),
        rationale: "Recorded so the mapping work inherits an entry rather than rediscovering the \
                    item.",
    },
    Item {
        control: "Prefer asymmetric identifiers over personally identifiable ones in assertions",
        coverage: Coverage::NotApplicable(
            "About what a NameID CONTAINS, which is an identity provider's choice and a JIT \
             mapping concern. Issue #139 owns the mapping; nothing here inspects the value.",
        ),
        rationale: "The one thing this crate does for it is make sure whatever the value is was \
                    signed, which the signature rows carry.",
    },
    Item {
        control: "Input validation on every value taken out of an assertion",
        coverage: Coverage::Tests(&[
            "a_malformed_qualified_name_is_refused",
            "an_undefined_entity_reference_is_refused_rather_than_emptied",
            "non_utf8_is_refused",
        ]),
        rationale: "The cheat sheet's one-line section, and the part of it this crate owns is \
                    that a value reaching a caller has already survived a hostile parser: no \
                    DOCTYPE, no unresolved entity, valid UTF-8, well formed names. What a caller \
                    then does with a NameID is issue #139's.",
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
        coverage: Coverage::Tests(&[
            "an_encrypted_assertion_decrypts_and_verifies",
            "decryption_is_not_verification",
            "the_broken_algorithms_are_refused_before_the_seam",
            "the_limits_apply_to_the_decrypted_document",
        ]),
        rationale: "Decrypt then REVALIDATE, and the second test is the one that matters: an \
                    assertion that decrypts but is signed by nobody pinned, or not signed, or \
                    edited after signing, is refused exactly as it would be in the clear. \
                    Keycloak CVE-2026-2092 and the Casdoor batch are both 'it decrypted' taken \
                    as evidence about whose identity was asserted, and the encryption key is a \
                    PUBLIC one out of the service provider's own metadata.",
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

/// Every row names tests that exist, or carries a reason with an owner.
#[test]
fn every_checklist_item_names_a_test_that_exists_or_a_reason() {
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
                // THAT THE NAMES EXIST IS scripts/saml-owasp-checklist.sh's job, because it
                // can read `cargo test -- --list` and this cannot. What is checkable here is
                // that a name is shaped like one, so a typo that produces an empty or obviously
                // wrong string fails immediately rather than at gate time.
                for name in covering {
                    assert!(
                        !name.is_empty()
                            && name.chars().all(|character| character.is_ascii_lowercase()
                                || character.is_ascii_digit()
                                || character == '_'),
                        "{}: `{name}` is not a test function name",
                        item.control
                    );
                }
            }
            Coverage::NotApplicable(reason) => {
                excused += 1;
                // BOTH ALTERNATIVES THE MESSAGE OFFERS ARE IMPLEMENTED. An earlier version
                // checked only the first while promising the second, and the one row that
                // depends on the second -- IP filtering, which no code in this repository can
                // assert -- passed by accident on a trailing clause. A check that is narrower
                // than its own error message trains a reader to distrust the message.
                // Case-insensitive, because half the rows open a sentence with "Issue #139".
                // An earlier version matched only the lowercase form and passed those rows on a
                // bare `#139` disjunct instead, which made the whole condition near-tautological.
                let lowered = reason.to_ascii_lowercase();
                let names_an_owner = lowered.contains("issue #") || lowered.contains("(#");
                let names_nobody = reason.contains("Nothing in this repository can assert it");
                assert!(
                    names_an_owner || names_nobody,
                    "{}: an N/A must name the issue that DOES own the item, or say in those \
                     words that `Nothing in this repository can assert it`",
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

    // FLOORS, and they are set at the CURRENT counts rather than comfortably below them.
    // Slack is what the previous version had and it bought nothing: with floors two rows below
    // the totals, two published items could vanish in silence, which is the failure a checklist
    // exists to prevent -- and one did, when the commit that added two dozen items also deleted
    // the audience row and no floor noticed because the total went UP.
    //
    // At exact counts a deletion is a red build that a reader has to lower deliberately, in the
    // same commit, with the removed row visible in the diff. That is the most a same-file bound
    // can do: it cannot stop a removal, only make one loud.
    assert_eq!(named, 23, "a row that names tests was added or removed");
    assert_eq!(
        excused, 19,
        "a row marked out of scope was added or removed"
    );
    // ZERO GAPS. Both were XML Encryption, and criterion 5 closed them. The assertion stays at
    // an exact count rather than being deleted: a checklist that cannot express "this is ours
    // and it is missing" has no way to record the next one.
    assert_eq!(gaps, 0, "a row marked as a gap was added or removed");
}

/// A row whose control TEXT enumerates several properties names several tests.
///
/// # A narrow guard, and the narrowness is measured rather than hoped
///
/// The row that failed review named exactly one test, and that test measured none of the three
/// things the control was about. This catches the shape where the control SAYS it covers several
/// things: "Bound document size, depth and breadth" is two conjunctions, so it needs two names.
///
/// IT REACHES FEW ROWS, AND THAT IS THE HONEST DESCRIPTION. Punctuation is a proxy for "how many
/// properties", and a control can carry four tests while reading as one phrase: "Reject XML
/// Signature Wrapping in all its published forms" scores zero, so cutting its four names to one
/// passes here. A reviewer demonstrated exactly that.
///
/// What catches THAT is `scripts/saml-owasp-checklist.sh`, which asserts the exact number of
/// names across all rows, in a different file from the table. This guard is kept for the case it
/// does catch and is described for the cases it does not, rather than left looking like more.
#[test]
fn a_row_naming_several_properties_names_several_tests() {
    for item in CHEAT_SHEET {
        let Coverage::Tests(covering) = item.coverage else {
            continue;
        };
        // SEMICOLONS COUNT. Two of the four-name rows separate their clauses with one and so
        // scored zero, which left this guard reaching three rows of seventeen: the row carrying
        // the whole published wrapping corpus could have been cut to a single test with
        // everything still green.
        let conjunctions = item.control.matches(',').count()
            + item.control.matches(';').count()
            + item.control.matches(" and ").count();
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
