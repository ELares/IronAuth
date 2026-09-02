// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the RFC 7644 filter parser and its evaluator (issue #135).
//!
//! # What this target asserts
//!
//! 1. `parse_filter` is TOTAL: arbitrary text is a `Filter` or a `FilterError`, never a panic.
//!    The input is a query-string parameter a provisioning client sends verbatim over the
//!    public plane, so "never panics" is the difference between a rejected filter and a
//!    downed process.
//!
//! 2. Evaluation is total too, which is the half a parser-only target would miss. A parsed
//!    filter is applied to a rendered resource by `filter_matches`, and that walk recurses
//!    through `And` / `Or` / `Not` / `ValuePath` and indexes into JSON. A filter that parses
//!    and then panics during evaluation is reachable from exactly the same request.
//!
//! 3. Parsing is IDEMPOTENT under rendering: not asserted here, because `Filter` has no
//!    renderer. Recorded so the omission is deliberate rather than forgotten.
//!
//! Run locally: `cargo +nightly fuzz run scim_filter` from `crates/ironauth-scim/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(filter) = ironauth_scim::parse_filter(text) else {
        return;
    };
    // THE SHARED resource, not a copy. `sample_user_resource` is exported by the crate and
    // the seed test measures the corpus against the same object, so a change here cannot
    // silently stop the test from describing what this target explores.
    let resource = ironauth_scim::sample_user_resource();
    let _ = ironauth_scim::filter_matches(&filter, &resource);
    // And against a resource carrying NONE of those attributes, which is the absent-attribute
    // path every operator handles differently.
    let _ = ironauth_scim::filter_matches(&filter, &serde_json::json!({}));
});
