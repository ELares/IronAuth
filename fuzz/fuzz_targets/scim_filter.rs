// SPDX-License-Identifier: MIT OR Apache-2.0

//! libFuzzer target for the SCIM filter, PATCH path, and resource path parsers (issue #135).
//!
//! The filter is the one place a SCIM server takes a whole grammar from an unauthenticated
//! shape of input, so the fuzzer's bytes go straight in: this parser's entry point IS the
//! attacker's entry point, with no carrier to build.
//!
//! Two invariants, and the second is the one worth having:
//!
//!   1. no input panics. A recursive-descent parser over attacker-shaped input is a stack
//!      overflow waiting for a deep enough nest, and the escape and number scanners index
//!      forward from a position the input chose.
//!   2. anything that PARSES round-trips as something the datastore boundary can accept:
//!      the returned tree contains no raw text, which is a property of the type rather than
//!      of this target, and the target exists to keep finding inputs that reach it.
//!
//! Run with a nightly toolchain: `cargo +nightly fuzz run scim_filter`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only well-formed UTF-8 reaches a real server: a query string that is not UTF-8 is
    // refused before the filter is ever looked at, so feeding invalid bytes here would spend
    // the fuzzer's budget on a path production cannot take.
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    // The PATCH path parser embeds the filter parser, so the same bytes reach it through a
    // second entry point with a different prefix and suffix. Fuzzing only the filter would
    // miss the bracket handling that decides which slice the filter parser even sees.
    if let Ok(patch) = ironauth_scim::parse_patch_path(input) {
        if let Some(selector) = &patch.selector {
            walk(selector);
        }
    }
    // The resource path parser: attacker-shaped input, and the one place an encoding trick
    // would show up as an ACCEPTED path rather than a crash.
    let _ = ironauth_scim::parse_resource_path(input);

    // The contract is that it RETURNS. Most inputs are refusals and that is the point.
    if let Ok(filter) = ironauth_scim::parse_filter(input) {
        // A parsed filter must survive being walked: the consumer that turns it into a query
        // walks it, and a tree that panics on traversal is a crash moved one step later.
        walk(&filter);
    }
});

/// Walk every node, as a consumer building a query would.
fn walk(filter: &ironauth_scim::Filter) {
    match filter {
        ironauth_scim::Filter::Compare { path, value, .. } => {
            let _ = (&path.urn, &path.name, &path.sub);
            if let ironauth_scim::Value::String(text) = value {
                let _ = text.len();
            }
        }
        ironauth_scim::Filter::Present { path, .. } => {
            let _ = (&path.urn, &path.name, &path.sub);
        }
        ironauth_scim::Filter::And(left, right) | ironauth_scim::Filter::Or(left, right) => {
            walk(left);
            walk(right);
        }
        ironauth_scim::Filter::Not(inner) => walk(inner),
    }
}
