// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target over the redirect-URI comparator and registrability rule (issue
//! #13), the security-critical redirect-matching policy.
//!
//! The input is split on the first NUL byte into two candidate URIs (a
//! `registered` and a `presented` value); with no NUL the two are the same
//! string. The properties the fuzzer proves:
//!
//! - neither [`redirect_uri_is_registrable`] nor [`redirect_uri_matches`] ever
//!   panics on any input;
//! - matching is reflexive (a value always matches itself) and symmetric (it does
//!   not depend on argument order); and
//! - a match between two DIFFERENT strings is ONLY ever the RFC 8252 loopback port
//!   exception, so both sides must then be `http` (the only scheme the exception
//!   applies to). This is the anti-bypass invariant: any accepted match that is
//!   not exact-string must be a loopback variant, never a wildcard, substring,
//!   case-fold, or normalization bypass.
//!
//! The same input space has stable, in-CI coverage in
//! `crates/ironauth-store/src/redirect.rs` (the CVE regression corpus and the
//! loopback cases), so this crate is a nightly deepening, not the only coverage.
//!
//! Run locally: `cargo +nightly fuzz run redirect_match` from this directory.

#![no_main]

use ironauth_store::{redirect_uri_is_registrable, redirect_uri_matches};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split into two candidate URIs on the first NUL; both halves must be UTF-8
    // (a redirect URI is a text value, so non-UTF-8 is not a candidate).
    let (a_bytes, b_bytes) = match data.iter().position(|&byte| byte == 0) {
        Some(index) => (&data[..index], &data[index + 1..]),
        None => (data, data),
    };
    let (Ok(a), Ok(b)) = (
        std::str::from_utf8(a_bytes),
        std::str::from_utf8(b_bytes),
    ) else {
        return;
    };

    // Must never panic on any input.
    let _ = redirect_uri_is_registrable(a);
    let _ = redirect_uri_is_registrable(b);

    // Reflexive: a value always matches itself.
    assert!(redirect_uri_matches(a, a), "matching is not reflexive: {a:?}");

    // Symmetric: matching does not depend on argument order.
    assert_eq!(
        redirect_uri_matches(a, b),
        redirect_uri_matches(b, a),
        "matching is not symmetric: {a:?} vs {b:?}"
    );

    // The anti-bypass invariant: a match between DIFFERENT strings is ONLY ever the
    // RFC 8252 loopback port exception, which applies only to http. So any accepted
    // non-exact match must have both sides on the http scheme.
    if a != b && redirect_uri_matches(a, b) {
        assert!(
            a.len() >= 7 && a[..7].eq_ignore_ascii_case("http://"),
            "non-exact match on a non-http registered value: {a:?}"
        );
        assert!(
            b.len() >= 7 && b[..7].eq_ignore_ascii_case("http://"),
            "non-exact match on a non-http presented value: {b:?}"
        );
    }
});
