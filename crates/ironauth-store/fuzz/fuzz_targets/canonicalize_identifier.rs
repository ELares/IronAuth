// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target over the identifier canonicalization seam (issue #54), the single
//! security-critical function every login-identifier comparison, uniqueness check,
//! and (future) lockout / access decision routes through.
//!
//! The input bytes become a candidate identifier string (lossily, so arbitrary and
//! invalid UTF-8 is still exercised), and each [`IdentifierType`] is canonicalized.
//! The properties the fuzzer proves, for EVERY input and EVERY kind:
//!
//! - [`canonicalize_identifier`] never panics (it is TOTAL), including on empty,
//!   all-invisible, lone-combining-mark, and control-character-soup input; and
//! - it is IDEMPOTENT: canonicalizing an already-canonical value returns it
//!   unchanged (`canonicalize(canonicalize(x)) == canonicalize(x)`), which is the
//!   property that makes "store and compare the canonical form" sound: a value read
//!   back and re-canonicalized must not drift into a different identifier.
//!
//! The same input space has stable, in-CI coverage in
//! `crates/ironauth-store/src/identifier.rs` (the adversarial and idempotence
//! property tests), so this crate is a nightly deepening, not the only coverage.
//!
//! Run locally: `cargo +nightly fuzz run canonicalize_identifier` from this directory.

#![no_main]

use ironauth_store::identifier::{IdentifierType, canonicalize_identifier};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Accept arbitrary bytes as an identifier string; lossy decoding keeps invalid
    // UTF-8 (replacement characters) in the exercised space rather than skipping it.
    let raw = String::from_utf8_lossy(data);

    for kind in [
        IdentifierType::Email,
        IdentifierType::Username,
        IdentifierType::Phone,
    ] {
        // Total: must never panic on any input.
        let once = canonicalize_identifier(kind, &raw);
        // Idempotent: a second pass over the canonical form is a fixpoint.
        let twice = canonicalize_identifier(kind, once.as_str());
        assert_eq!(
            once, twice,
            "canonicalization is not idempotent for {kind:?} on {raw:?}"
        );
    }
});
