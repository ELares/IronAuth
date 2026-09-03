// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz signature verification (issue #138, criterion 6).
//!
//! # The invariant, and why it is the strongest one available to a fuzzer
//!
//! A fuzzer cannot forge a signature, so it cannot explore the accept path. What it CAN do is
//! prove the accept path is unreachable without the key: this target pins anchors that signed
//! nothing, and any `Ok` at all is a finding. That covers every bypass class in one assertion --
//! wrapping, a skipped digest comparison, an algorithm confusion, a canonicalization collision --
//! because each of them ends in an `Ok` the pinned key did not authorise.
//!
//! Both anchor shapes are driven, because the code paths differ: the EMPTY list (a caller that
//! pinned nothing trusts nothing) and a well-formed-but-wrong key (a caller that pinned the wrong
//! one). An earlier revision of this crate got the empty case wrong in the other direction, and
//! reported "no key trusts this" as "this server refuses that algorithm".
//!
//! The element name is taken from the DOCUMENT rather than fixed, so the fuzzer reaches the
//! candidate-selection path with whatever it built rather than only with `Assertion`.
//!
//! Run locally: `cargo +nightly fuzz run saml_verify` from `crates/ironauth-saml/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = ironauth_saml::Limits::default();
    // A syntactically well-formed P-256 point that signed nothing. Not a random one: a fixed
    // value keeps the target deterministic, which a corpus depends on.
    let mut point = vec![0x04_u8];
    point.extend(std::iter::repeat(0x01_u8).take(64));
    let wrong = [ironauth_saml::TrustAnchor::EcdsaP256(point)];

    for anchors in [&[][..], &wrong[..]] {
        // The names the corpus is built around, plus whatever the document itself carries.
        for (namespace, local) in [
            (ironauth_saml::ASSERTION_NS, "Assertion"),
            (ironauth_saml::PROTOCOL_NS, "Response"),
        ] {
            assert!(
                ironauth_saml::verify(data, &limits, anchors, namespace, local).is_err(),
                "verified {local} against a key that signed nothing"
            );
        }
        if let Ok(document) = ironauth_saml::parse(data, &limits) {
            let name = document.root().name().to_owned();
            let local = name.split_once(':').map_or(name.as_str(), |(_, rest)| rest);
            for namespace in ["", ironauth_saml::ASSERTION_NS, ironauth_saml::PROTOCOL_NS] {
                assert!(
                    ironauth_saml::verify(data, &limits, anchors, namespace, local).is_err(),
                    "verified the document root against a key that signed nothing"
                );
            }
        }
    }
});
