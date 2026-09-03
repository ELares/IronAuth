// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the hostile-input SAML parser (issue #138, criterion 6).
//!
//! # What this target asserts
//!
//! 1. `parse` is TOTAL: arbitrary bytes are a `Document` or a `SamlError`, never a panic and
//!    never an abort. The input is a base64-decoded POST body from an unauthenticated party, so
//!    "never panics" is the difference between a rejected assertion and a downed process.
//!
//! 2. THE BOUNDS ARE REAL, not merely configured. Every accepted document is re-measured against
//!    the limits it was parsed under, so a size, depth or element-count bound that the parser
//!    checks in the wrong place fails here rather than in production. A bound that is only
//!    checked before the work it bounds is the defect class this asserts against.
//!
//! 3. DEPTH IS ASSERTED SEPARATELY FROM SIZE. A deeply nested document is small, so a size cap
//!    passes it: the recursion bound is what stops a stack overflow, and a stack overflow is an
//!    abort that no `Result` can express.
//!
//! Run locally: `cargo +nightly fuzz run saml_parse` from `crates/ironauth-saml/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = ironauth_saml::Limits::default();
    let Ok(document) = ironauth_saml::parse(data, &limits) else {
        return;
    };
    // The document was accepted, so its shape must be inside the bounds it was accepted under.
    // Measuring it here rather than trusting the parser is the point: this is the half that
    // catches a bound applied to the wrong number.
    let mut deepest = 0_usize;
    let mut elements = 0_usize;
    let mut pending = vec![(document.root(), 1_usize)];
    while let Some((element, depth)) = pending.pop() {
        elements += 1;
        deepest = deepest.max(depth);
        for child in element.children() {
            pending.push((child, depth + 1));
        }
    }
    assert!(
        deepest <= ironauth_saml::DEPTH_CEILING,
        "accepted a document {deepest} deep"
    );
    assert!(
        data.len() <= limits.max_bytes,
        "accepted {} bytes past the limit",
        data.len()
    );
    assert!(
        elements <= limits.max_elements,
        "accepted {elements} elements past the limit"
    );
});
