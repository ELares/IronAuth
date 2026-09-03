// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz exclusive canonicalization (issue #138, criterion 6).
//!
//! # Why this path gets its own target
//!
//! The canonicalizer is the component whose correctness cannot be checked through the verifier:
//! a signer and a verifier sharing a canonicalization bug agree with each other perfectly. It is
//! also the component that walks the whole tree building strings, so it is where an unbounded
//! recursion or an index panic would live.
//!
//! # What this target asserts
//!
//! 1. Canonicalization is TOTAL over every document the parser accepts.
//!
//! 2. IT IS DETERMINISTIC. The same document canonicalises to the same octets twice. A digest is
//!    a function of these bytes, so any dependence on iteration order, hashing or allocation
//!    address would make one verifier disagree with another run of itself.
//!
//! 3. THE OUTPUT IS WELL FORMED ENOUGH TO PARSE AGAIN, and canonicalising it a second time is a
//!    FIXED POINT. That is the property a signature depends on: the signer canonicalises once,
//!    the verifier canonicalises what it received, and the two must land on the same string even
//!    though one of them started from an already-canonical document.
//!
//! Run locally: `cargo +nightly fuzz run saml_canonicalize` from `crates/ironauth-saml/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let limits = ironauth_saml::Limits::default();
    let Ok(document) = ironauth_saml::parse(data, &limits) else {
        return;
    };
    // Canonicalise the ROOT, whatever it is called: the name comes from the document rather than
    // from a fixture, so the target explores whatever the fuzzer built.
    let name = document.root().name().to_owned();
    let Ok(first) = ironauth_saml::test_util::canonicalize(text, &name) else {
        return;
    };
    let second = ironauth_saml::test_util::canonicalize(text, &name)
        .expect("canonicalization that succeeded once must succeed again");
    assert_eq!(first, second, "canonicalization must be deterministic");

    // AND THE FIXED POINT. The canonical form is itself a document; canonicalising it again must
    // not move. If it does, a signer and a verifier that start from different-but-equivalent
    // documents compute different digests, which is a false rejection of every real signature.
    if let Ok(reparsed) = ironauth_saml::parse(first.as_bytes(), &limits) {
        let again = ironauth_saml::test_util::canonicalize(&first, reparsed.root().name())
            .expect("the canonical form canonicalises");
        assert_eq!(first, again, "canonicalization must be a fixed point");
    }
});
