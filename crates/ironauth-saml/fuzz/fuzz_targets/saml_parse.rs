// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the hostile-input SAML parser (issue #138, criterion 6).
//!
//! # The limits are SMALL, and that is the fix for a target that asserted nothing
//!
//! An earlier version used `Limits::default()`: a megabyte, 64 deep, ten thousand elements.
//! libFuzzer generates 4096 bytes by default, and at four bytes minimum per element only about
//! a thousand elements fit in that -- so the size and element-count assertions could not fire
//! for ANY input the lane produces, and the depth one compared against `DEPTH_CEILING` (512)
//! rather than against the bound `parse` actually enforces, which is
//! `max_depth.min(DEPTH_CEILING)` = 64. A reviewer raised the parser's effective depth to 512
//! and the target stayed green while the parser accepted documents eight times its configured
//! bound.
//!
//! So the bounds here are sized to what a fuzzer can actually build. They are not the deployed
//! defaults and are not meant to be: the property under test is that `parse` enforces WHATEVER
//! bounds it is given, and small ones are the only ones a 4096-byte input can cross.
//!
//! # What this target asserts
//!
//! 1. `parse` is TOTAL: arbitrary bytes are a `Document` or a `SamlError`, never a panic and
//!    never an abort. The input is a base64-decoded POST body from an unauthenticated party, so
//!    "never panics" is the difference between a rejected assertion and a downed process.
//!
//! 2. EVERY BOUND THIS TARGET SETS is re-measured on the accepted document, against the SAME
//!    limits the parse used, and against the effective depth rather than the ceiling. A bound
//!    checked in the wrong place, or against the wrong number, fails here.
//!
//!    THAT IS NOT EVERY BOUND `Limits` HAS, and the difference is not an oversight. The public
//!    [`ironauth_saml::Element`] exposes only `name()` and `children()` -- the crate's whole
//!    retention argument is that it keeps nothing else -- so a target cannot see an attribute,
//!    and `max_attributes` and the attribute-name half of `max_name_bytes` are unmeasurable
//!    from out here. An earlier version SET those limits and claimed to re-measure "every"
//!    bound; they could be deleted from the parser with this target green forever. They are not
//!    set now, and `one_element_cannot_be_unbounded` in `tests/hostile.rs` is where they are
//!    covered instead.
//!
//! 3. Depth is asserted separately from size, because a deeply nested document is small: the
//!    recursion bound is what stops a stack overflow, and a stack overflow is an abort no
//!    `Result` can express.
//!
//! Run locally: `cargo +nightly fuzz run saml_parse` from `crates/ironauth-saml/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Sized so a 4096-byte input -- libFuzzer's default maximum -- can cross every one of them.
    // The attribute bounds are left at their defaults deliberately: nothing out here can measure
    // them, so setting them would be a bound this target claims and does not check.
    let limits = ironauth_saml::Limits {
        max_bytes: 2048,
        max_depth: 8,
        max_elements: 64,
        ..ironauth_saml::Limits::default()
    };
    // The bound `parse` enforces is the configured depth CLAMPED by the ceiling, not the
    // ceiling. Asserting the ceiling passes a parser that ignores the configuration entirely.
    let effective_depth = limits.max_depth.min(ironauth_saml::DEPTH_CEILING);

    let Ok(document) = ironauth_saml::parse(data, &limits) else {
        return;
    };
    let mut deepest = 0_usize;
    let mut elements = 0_usize;
    let mut longest_name = 0_usize;
    let mut pending = vec![(document.root(), 1_usize)];
    while let Some((element, depth)) = pending.pop() {
        elements += 1;
        deepest = deepest.max(depth);
        longest_name = longest_name.max(element.name().len());
        for child in element.children() {
            pending.push((child, depth + 1));
        }
    }
    assert!(
        deepest <= effective_depth,
        "accepted a document {deepest} deep past a bound of {effective_depth}"
    );
    assert!(
        data.len() <= limits.max_bytes,
        "accepted {} bytes past a bound of {}",
        data.len(),
        limits.max_bytes
    );
    assert!(
        elements <= limits.max_elements,
        "accepted {elements} elements past a bound of {}",
        limits.max_elements
    );
    assert!(
        longest_name <= limits.max_name_bytes,
        "accepted a {longest_name} byte name past a bound of {}",
        limits.max_name_bytes
    );
});
