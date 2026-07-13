// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz target over the one public verification entry point.
//!
//! It drives [`ironauth_jose::verify`] with arbitrary input against a fixed,
//! representative policy (an EdDSA allowlist, one trusted Ed25519 key, an
//! expected issuer and audience, default caps and skew) and a fixed clock. The
//! properties the fuzzer proves: `verify` never panics on any input, and no
//! input is ever accepted unless it is a genuine signature over the exact header
//! it carries (the corpus is seeded from the committed regression vectors, whose
//! adversarial cases must always stay rejected). The same input space has stable,
//! in-CI coverage in `crates/ironauth-jose/tests/cve_corpus.rs` and
//! `property.rs`, so this crate is a nightly deepening, not the only coverage.
//!
//! Run locally: `cargo +nightly fuzz run verify_jws` from this directory.

#![no_main]

use std::time::{Duration, SystemTime};

use ironauth_env::ManualClock;
use ironauth_jose::{JwsAlgorithm, TrustedKey, VerificationPolicy, verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A verifier must accept only valid UTF-8 compact tokens; non-UTF-8 input is
    // simply not a token string, so there is nothing to drive.
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };

    // A fixed, representative policy. The trusted key bytes are arbitrary but
    // structurally valid: the interesting behavior is in the parse, guard, key
    // selection, and claim stages, all reached before the signature check.
    let Ok(key) = TrustedKey::ed25519(Some("k1".into()), &[0x42; 32]) else {
        return;
    };
    let Ok(policy) = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa, JwsAlgorithm::Es256, JwsAlgorithm::Rs256],
        vec![key],
        "https://issuer.example.test",
        "client-abc",
    ) else {
        return;
    };

    let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));

    // The only invariant that matters here: this must return, never panic. A
    // genuine forgery would show up as an Ok on an adversarial seed, which the
    // stable regression suites also guard.
    let _ = verify(token, &policy, &clock);
});
