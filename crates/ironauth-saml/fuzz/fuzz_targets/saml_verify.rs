// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz signature verification (issue #138, criterion 6).
//!
//! # The key is REAL, and that is the whole difference
//!
//! An earlier version of this target pinned anchors that had signed nothing -- an empty slice,
//! and a syntactically well-formed point that is not on the curve -- and asserted that `verify`
//! never returns `Ok`. The doc claimed that covered "every bypass class in one assertion".
//! It covered none of them. `verify`'s only `Ok` exit sits immediately after
//! `if !anchors.iter().any(|a| verify_xml_signature(..))`, so with either of those anchors the
//! `Err` is taken by construction, whatever happened upstream. A reviewer deleted the digest
//! comparison, the exactly-one-candidate refusal and the duplicate-identifier guard in turn and
//! the target stayed green on every input, forever. It asserted that `any()` over an empty
//! iterator is false.
//!
//! So this target carries a FIXED private key and a document that genuinely verifies under it.
//! The accept path exists, the fuzzer's mutations of that document can reach it, and the
//! assertions below are about what comes back when they do.
//!
//! Fixed rather than generated, for two reasons: `verify` must be able to answer `Ok` at all,
//! and a corpus entry that verifies in one process and not the next means nothing. The key is a
//! throwaway P-256 pair with no counterpart anywhere; it authorises nothing but this target.
//!
//! # What is asserted when the accept path IS reached
//!
//! 1. THE RETURNED SUBTREE CARRIES NO SIGNATURE. The enveloped-signature transform removes the
//!    `Signature` before the digest, so a `VerifiedAssertion` that still contains one is holding
//!    content the digest did not cover. That is exactly the authenticate-as-anyone defect this
//!    crate shipped and fixed: the verifier digested a stripped copy and returned the original,
//!    and the forged `NameID` rode inside the `Signature` element.
//!
//! 2. THE RETURNED ELEMENT IS THE ONE THE REFERENCE NAMED. Its `ID` must equal the fragment in
//!    the `Reference` URI. "Verify the node you consume" is only true if those agree.
//!
//! # And what a fuzzer still cannot do
//!
//! It cannot FORGE. Every `Ok` it reaches comes from a mutation that left the signature and the
//! digest intact, so this explores the accept path's edges rather than its perimeter. The
//! perimeter is `tests/wrapping.rs`, where each document is built deliberately. Neither
//! substitutes for the other, and an earlier draft of this note claimed one did.
//!
//! Run locally: `cargo +nightly fuzz run saml_verify` from `crates/ironauth-saml/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// A throwaway P-256 key, fixed so the accept path is reachable AND deterministic.
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

/// The fragment named by the first `Reference` URI in the document, if there is one.
fn referenced_id(bytes: &[u8]) -> Option<String> {
    let text = core::str::from_utf8(bytes).ok()?;
    let start = text.find("URI=\"#")? + "URI=\"#".len();
    let end = start + text[start..].find('"')?;
    Some(text[start..end].to_owned())
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
        // 1. No signature survives into what the caller reads.
        assert!(
            assertion
                .text_of("http://www.w3.org/2000/09/xmldsig#", "SignatureValue")
                .is_none(),
            "a verified {local} still carries a SignatureValue, so the digest did not cover it"
        );
        // 2. The element returned is the element the reference named.
        if let Some(id) = referenced_id(data) {
            assert_eq!(
                assertion.attribute("ID"),
                Some(id.as_str()),
                "a verified {local} is not the element the Reference URI named"
            );
        }
    }

    // AND WITH NO KEY, NOTHING VERIFIES. Weaker than the above and kept for one reason: it is
    // the only assertion that holds for EVERY input rather than only for the ones that reach the
    // accept path, so it is what covers the inputs the mutations never make verifiable.
    for (namespace, local) in [
        (ironauth_saml::ASSERTION_NS, "Assertion"),
        (ironauth_saml::PROTOCOL_NS, "Response"),
    ] {
        assert!(
            ironauth_saml::verify(data, &limits, &[], namespace, local).is_err(),
            "verified {local} against no pinned key at all"
        );
    }
});
