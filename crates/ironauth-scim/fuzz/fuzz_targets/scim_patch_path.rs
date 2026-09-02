// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the RFC 7644 section 3.5.2 PATCH path parser (issue #135).
//!
//! # Why this is a separate target from the filter
//!
//! A PATCH path shares the filter's grammar for its value selector but is not a filter: it is
//! `attribute[selector].subAttribute`, and the two extra parts are parsed by different code.
//! `members[value eq "usr_x"]` is the shape group push sends thousands of times per sync, and
//! it is the one an attacker controls most directly: it arrives in a request BODY, so it is
//! not length-bounded by a URL.
//!
//! The target also walks the SELECTOR when there is one. The selector is a `Filter`, and a
//! path that parses while its selector panics on inspection is reachable from one request --
//! which is exactly what `selected_member` in groups.rs does to decide who to remove.
//!
//! Run locally: `cargo +nightly fuzz run scim_patch_path` from `crates/ironauth-scim/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(path) = ironauth_scim::parse_patch_path(text) else {
        return;
    };
    // Every accessor a handler calls on a parsed path, because a parse that succeeds and an
    // accessor that panics are one request apart.
    let _ = path.attribute();
    let _ = path.sub_attribute();
    if let Some(selector) = path.selector() {
        // The selector is evaluated exactly as the group remove path evaluates it.
        let member = serde_json::json!({"value": "usr_fuzz", "type": "User"});
        let _ = ironauth_scim::filter_matches(selector, &member);
    }
});
