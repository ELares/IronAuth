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
//! The target also EVALUATES the selector when there is one, which is a stronger walk than any
//! consumer performs today and is deliberately so. `selected_member` in `groups.rs` destructures
//! a selector shallowly -- it accepts only a top-level `Compare` on `value` with `eq` and
//! rejects everything else -- and `users.rs` only asks whether a selector is present. Neither
//! calls `filter_matches`. An earlier version of this comment said this mirrored
//! `selected_member`, and it does not: it covers the whole tree that one refuses to look
//! inside, which is the right thing to fuzz precisely because no consumer currently walks it
//! and a future one would.
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
        // Evaluated IN FULL, which no consumer does; see the module comment above.
        let member = serde_json::json!({"value": "usr_fuzz", "type": "User"});
        let _ = ironauth_scim::filter_matches(selector, &member);
    }
});
