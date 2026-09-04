// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz signature verification (issue #138, criterion 6).
//!
//! # The key is REAL, and the assertions are ones a CONFORMING document cannot break
//!
//! Two earlier versions of this target were wrong in opposite directions, and both are worth
//! recording because they are the two ways a fuzz assertion goes bad.
//!
//! THE FIRST ASSERTED NOTHING. It pinned anchors that had signed nothing and asserted `verify`
//! never returns `Ok`. `verify`'s only `Ok` exit sits immediately after
//! `if !anchors.iter().any(|a| verify_xml_signature(..))`, so with an empty slice the `Err` is
//! taken by construction, whatever happened upstream. A reviewer deleted the digest comparison,
//! the exactly-one-candidate refusal and the duplicate-identifier guard in turn and the target
//! stayed green on every input. It asserted that `any()` over an empty iterator is false.
//!
//! THE SECOND ASSERTED TOO MUCH, which is worse, because a fuzz target that fires on a valid
//! document reports an authentication bypass that does not exist. It checked that a verified
//! subtree carries no `ds:SignatureValue` -- false for the ordinary Okta and ADFS document that
//! signs the Response AND the assertion inside it, where verifying the Response legitimately
//! returns a subtree containing the assertion's signature. And it compared the returned `ID`
//! against the first `URI="#` found by scanning the RAW INPUT, which is not the reference the
//! verifier used: a Response-level signature, or any inserted text, sits outside the digested
//! subtree, so a document that verifies correctly aborted the target. A reviewer produced both
//! crashes with `cargo fuzz run`, and the README's triage rules would have had a maintainer
//! reading a legal SAML response as a working exploit.
//!
//! # So what is asserted is what a correct verifier CANNOT violate
//!
//! 1. THE ELEMENT RETURNED IS THE ELEMENT ASKED FOR.
//! 2. THE ENVELOPED SIGNATURE IS GONE: a verified assertion has no `ds:Signature` DIRECT CHILD,
//!    because `verify` requires exactly one and the transform removes exactly that one. Direct
//!    children only, which is what makes it survive the double-signed Response the previous
//!    version died on: the assertion's signature is a child of the assertion, not of the
//!    Response.
//! 3. AND NO OTHER KEY WOULD HAVE DONE. Whatever verified under the pinned anchor must NOT
//!    verify under a different real key. This is the only one of the three that depends on the
//!    cryptography at all.
//!
//! # WHICH MUTATIONS THIS KILLS, AND WHICH IT DOES NOT
//!
//! Stated because a reviewer measured it, and because the first two versions of this target both
//! claimed coverage they did not have. Assertions 1 and 2 are decided BEFORE the digest is
//! computed -- 1 restates the selection predicate, and 2 is settled the moment
//! `strip_enveloped_signature` runs -- so neither can notice anything the signature check does.
//!
//! KILLED: returning the un-stripped original subtree (the historical authenticate-as-anyone
//! defect, caught by 2); relaxing the exactly-one-signature rule to "take the first", which
//! leaves a second `Signature` child unstripped (2); ignoring the pinned anchors (3).
//!
//! NOT KILLED, and each is covered by a test in `tests/wrapping.rs` instead: deleting the digest
//! comparison (`changing_a_signed_value_breaks_the_digest`), the exactly-one-candidate refusal
//! (`a_forged_assertion_before_the_signed_one_is_refused`), and the duplicate-identifier guard
//! (`an_enclosing_element_claiming_the_same_identifier_is_refused`). A fuzzer cannot forge, so
//! it cannot build the document that separates a correct digest check from an absent one: that
//! needs a signature over content the attacker chose, which is exactly what it does not have.
//!
//! The value here is therefore: no panics on any input, the accept path is exercised with a real
//! key, and three invariants that no conforming document can violate. That is less than "every
//! bypass class in one assertion", which is what the first version claimed.
//!
//! Run locally: `cargo +nightly fuzz run saml_verify` from `crates/ironauth-saml/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// The XMLDSIG namespace, for the one assertion that names an element.
const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// A throwaway P-256 key, fixed so the accept path is reachable AND deterministic.
///
/// Fixed rather than generated for two reasons: `verify` must be able to answer `Ok` at all, and
/// a corpus entry that verifies in one process and not the next means nothing. It authorises
/// nothing but this target, and `crates/ironauth-saml/tests/fuzz_seeds.rs` reads this literal out
/// of this file so the signed seed and the target cannot drift apart.
const FUZZ_KEY_PKCS8: &[u8] = &[
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20, 0xc0, 0xf2, 0x5c, 0x36, 0x09, 0xc6, 0x81, 0x08, 0xab, 0x75, 0x7f, 0x7e,
    0xb4, 0x8b, 0x0d, 0x74, 0xe1, 0x5a, 0xa6, 0x5c, 0x32, 0xd5, 0x3f, 0x00, 0x09, 0xc3, 0xa4, 0x34,
    0x6f, 0x81, 0x4a, 0x35, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x56, 0x83, 0xc8, 0x11, 0xa5, 0xb3,
    0x51, 0x54, 0xf1, 0x78, 0x89, 0x34, 0xac, 0x68, 0xd1, 0x1b, 0x5e, 0xb5, 0xc5, 0xec, 0x64, 0x6a,
    0x3a, 0x9e, 0xd6, 0xe4, 0x6b, 0x08, 0x44, 0xba, 0x74, 0xa9, 0x17, 0x16, 0x2c, 0x6f, 0x5c, 0x13,
    0xde, 0xb9, 0xe0, 0x90, 0xb0, 0xb9, 0x3b, 0x92, 0xad, 0x94, 0x44, 0x16, 0xda, 0xc9, 0x75, 0x22,
    0xc3, 0x12, 0xb9, 0x88, 0xec, 0xcd, 0x2c, 0x43, 0xc4, 0x8c,
];

/// The signed fixture and the anchor that verifies it, built once.
fn pinned() -> &'static Pinned {
    static PINNED: OnceLock<Pinned> = OnceLock::new();
    PINNED.get_or_init(|| {
        let key = ironauth_jose::xmldsig::test_util::XmlTestKey::from_pkcs8(FUZZ_KEY_PKCS8)
            .expect("the embedded key loads");
        let document = ironauth_saml::test_util::signed_response(&key, "_assertion");
        let anchors = vec![ironauth_saml::TrustAnchor::EcdsaP256(key.public_point())];
        // A SECOND REAL KEY, which signed nothing. Assertion 3 needs a key that could have
        // verified something and did not: a syntactically valid point that is not on the curve
        // would be refused by the primitive rather than by the signature, which is a different
        // fact.
        let stranger = ironauth_jose::xmldsig::test_util::XmlTestKey::generate();
        let stranger_anchors =
            vec![ironauth_saml::TrustAnchor::EcdsaP256(stranger.public_point())];

        // THE CONTROL RUNS ONCE, HERE. It used to run on every iteration, and a reviewer
        // measured what that cost: 50.8 microseconds of parse, canonicalization, SHA-256 and
        // ECDSA against a CONSTANT document, which is 99.7% of an iteration that rejects its
        // input. The fixture and the anchors are both behind this `OnceLock` and cannot change,
        // so checking once gives the identical guarantee -- if the fixture ever stops verifying,
        // the target asserts nothing, and this is where it says so.
        assert!(
            ironauth_saml::verify(
                document.as_bytes(),
                &ironauth_saml::Limits::default(),
                &anchors,
                ironauth_saml::ASSERTION_NS,
                "Assertion",
            )
            .is_ok(),
            "the embedded fixture must verify, or this target asserts nothing"
        );

        Pinned {
            document: document.into_bytes(),
            anchors,
            stranger_anchors,
        }
    })
}

/// The fixture, the anchor that verifies it, and a second real key that signed nothing.
struct Pinned {
    document: Vec<u8>,
    anchors: Vec<ironauth_saml::TrustAnchor>,
    stranger_anchors: Vec<ironauth_saml::TrustAnchor>,
}

/// The local part of a qualified name.
fn local_of(name: &str) -> &str {
    name.split_once(':').map_or(name, |(_, rest)| rest)
}

fuzz_target!(|data: &[u8]| {
    let limits = ironauth_saml::Limits::default();
    let pinned = pinned();
    // The control lives in `pinned()` and runs once; see the note there.
    let _ = &pinned.document;

    for (namespace, local) in [
        (ironauth_saml::ASSERTION_NS, "Assertion"),
        (ironauth_saml::PROTOCOL_NS, "Response"),
    ] {
        let Ok(assertion) =
            ironauth_saml::verify(data, &limits, &pinned.anchors, namespace, local)
        else {
            continue;
        };
        assert_eq!(
            local_of(assertion.name()),
            local,
            "verify returned an element that is not the one it was asked for"
        );
        assert_eq!(
            assertion.child_count(DSIG_NS, "Signature"),
            0,
            "a verified {local} still carries the signature the enveloped transform removes, so \
             the caller can read content the digest did not cover"
        );
        // AND NO OTHER KEY WOULD HAVE DONE. The stranger is a real P-256 key that signed
        // nothing, so a verifier that ignores its anchors, or that accepts any well-formed one,
        // answers Ok here and a correct one cannot.
        assert!(
            ironauth_saml::verify(data, &limits, &pinned.stranger_anchors, namespace, local)
                .is_err(),
            "a document that verified under the pinned key also verified under a key that \
             signed nothing"
        );
    }
});
