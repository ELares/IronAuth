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
//! 1. THE ELEMENT RETURNED IS THE ELEMENT ASKED FOR. `verify` selects candidates by resolved
//!    namespace and local name, so the subtree it hands back must satisfy the same predicate.
//!    A wrapping bug that returned a neighbouring element breaks it.
//!
//! 2. THE ENVELOPED SIGNATURE IS GONE. `verify` requires exactly one `ds:Signature` that is a
//!    DIRECT CHILD of the candidate, and the enveloped transform removes exactly that one before
//!    the digest, so a verified assertion has zero. This is the historical
//!    authenticate-as-anyone defect stated as an invariant: that version digested a stripped
//!    copy and returned the ORIGINAL, which still had its signature child and the forged content
//!    hidden inside it. It is DIRECT children only, which is what makes it survive the
//!    double-signed Response the previous version died on: the assertion's signature is a child
//!    of the assertion, not of the Response.
//!
//! # And what a fuzzer still cannot do
//!
//! It cannot FORGE. Every `Ok` it reaches comes from a mutation that left the signature and the
//! digest intact, so this explores the accept path's edges rather than its perimeter. The
//! perimeter is `tests/wrapping.rs`, where each document is built deliberately. Neither
//! substitutes for the other.
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
fn pinned() -> &'static (Vec<u8>, Vec<ironauth_saml::TrustAnchor>) {
    static PINNED: OnceLock<(Vec<u8>, Vec<ironauth_saml::TrustAnchor>)> = OnceLock::new();
    PINNED.get_or_init(|| {
        let key = ironauth_jose::xmldsig::test_util::XmlTestKey::from_pkcs8(FUZZ_KEY_PKCS8)
            .expect("the embedded key loads");
        let document = ironauth_saml::test_util::signed_response(&key, "_assertion");
        (
            document.into_bytes(),
            vec![ironauth_saml::TrustAnchor::EcdsaP256(key.public_point())],
        )
    })
}

/// The local part of a qualified name.
fn local_of(name: &str) -> &str {
    name.split_once(':').map_or(name, |(_, rest)| rest)
}

fuzz_target!(|data: &[u8]| {
    let limits = ironauth_saml::Limits::default();
    let (fixture, anchors) = pinned();

    // THE CONTROL, EVERY RUN. If the fixture ever stops verifying, every assertion below becomes
    // vacuous in silence: the accept path would be unreachable again and the target would keep
    // reporting success. So it is checked here rather than assumed.
    assert!(
        ironauth_saml::verify(
            fixture,
            &limits,
            anchors,
            ironauth_saml::ASSERTION_NS,
            "Assertion",
        )
        .is_ok(),
        "the embedded fixture must verify, or this target asserts nothing"
    );

    for (namespace, local) in [
        (ironauth_saml::ASSERTION_NS, "Assertion"),
        (ironauth_saml::PROTOCOL_NS, "Response"),
    ] {
        let Ok(assertion) = ironauth_saml::verify(data, &limits, anchors, namespace, local) else {
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
    }
});
