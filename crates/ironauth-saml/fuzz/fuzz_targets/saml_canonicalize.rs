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
//! 1. It is DETERMINISTIC. The same document canonicalises to the same octets twice. A digest is
//!    a function of these bytes, so any dependence on iteration order, hashing or allocation
//!    address would make one verifier disagree with another run of itself.
//!
//! 2. IT IS A FIXED POINT. Canonicalising an already-canonical document must not move it. That
//!    is the property a signature depends on: the signer canonicalises once, the verifier
//!    canonicalises what it received, and the two must land on the same string even though one
//!    of them started from an already-canonical document.
//!
//! 3. A DESCENDANT canonicalises, not only the root. This is what reaches the INHERITED-SCOPE
//!    path, where the crate's worst canonicalization defect lived: a prefix declared on an
//!    ancestor OUTSIDE the signed subtree has to resolve, and an earlier version started the
//!    in-scope set empty, so no conforming signature could verify. A target that only ever
//!    canonicalised the document root never entered that code at all.
//!
//! # What it deliberately does NOT assert
//!
//! Not totality. An earlier draft of this note claimed "canonicalization is TOTAL over every
//! document the parser accepts", and the code below has always swallowed the failure -- because
//! the claim is false: a document with an unbound prefix parses and is REFUSED here, on purpose,
//! since a prefix with no namespace URI would be written into the digest with nothing to bind
//! it. Asserting totality would fail on a legal refusal.
//!
//! Run locally: `cargo +nightly fuzz run saml_canonicalize` from `crates/ironauth-saml/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;

/// A qualified name from the tree: the root, and the deepest descendant found by walking first
/// children, which is the one with the most inherited scope above it.
fn names(document: &ironauth_saml::Document) -> Vec<String> {
    let mut names = vec![document.root().name().to_owned()];
    let mut element = document.root();
    while let Some(child) = element.children().first() {
        element = child;
        names.push(element.name().to_owned());
    }
    names.dedup();
    names
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let limits = ironauth_saml::Limits::default();
    let Ok(document) = ironauth_saml::parse(data, &limits) else {
        return;
    };
    for name in names(&document) {
        // A refusal is a legal answer here; see the note above.
        let Ok(first) = ironauth_saml::test_util::canonicalize(text, &name) else {
            continue;
        };
        let second = ironauth_saml::test_util::canonicalize(text, &name)
            .expect("canonicalization that succeeded once must succeed again");
        assert_eq!(first, second, "canonicalising {name} must be deterministic");

        // THE FIXED POINT. If it moves, a signer and a verifier that start from
        // different-but-equivalent documents compute different digests, which is a false
        // rejection of every real signature.
        if let Ok(reparsed) = ironauth_saml::parse(first.as_bytes(), &limits) {
            let again = ironauth_saml::test_util::canonicalize(&first, reparsed.root().name())
                .expect("the canonical form canonicalises");
            assert_eq!(first, again, "canonicalising {name} must be a fixed point");
        }
    }
});
