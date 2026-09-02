// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fuzz the SCIM resource path parser (issue #135).
//!
//! # Why this is a target at all, when the router does the routing
//!
//! `parse_resource_path` is not what serves `/scim/v2/Users/{id}` -- axum's router does that.
//! It is reached from a BULK request body (`bulk.rs`), where an operation names its own target
//! path as a string, so the bytes here are body-shaped rather than URL-shaped and nothing has
//! percent-decoded or length-bounded them on the way in.
//!
//! It carried a target in the repository-root fuzz crate that had NEVER COMPILED: it read a
//! private field and matched non-exhaustively on `Filter`, so `cargo fuzz build` failed on it
//! and the scheduled lane could only ever have failed too. The freshness gate could not see
//! that, because it compares registration three ways and never builds anything. So this parser
//! has been listed as fuzzed and has never been fuzzed. That target is deleted and this is
//! what replaces it.
//!
//! Run locally: `cargo +nightly fuzz run scim_resource_path` from `crates/ironauth-scim/fuzz`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(reference) = ironauth_scim::parse_resource_path(text) else {
        return;
    };
    // Every accessor a caller reads off an accepted path. An encoding trick shows up here as
    // an ACCEPTED path naming something unexpected rather than as a crash, so the interesting
    // outcome is what these return, not whether they return.
    let _ = reference.resource_type();
    let _ = reference.id();
});
