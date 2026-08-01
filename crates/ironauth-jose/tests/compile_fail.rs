// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile-fail proofs about what cannot be written against this crate.
//!
//! These assert, at the type level, what a runtime test cannot: that no call
//! site outside `ironauth-jose` can reach the raw signature check, the header
//! parser, or a trusted key's inner material, and so cannot assemble a second,
//! weaker verifier; and that no call site can build a verification policy
//! without saying which token profile it accepts. The `.stderr` snapshots are
//! pinned to the workspace toolchain (rust-toolchain.toml), which is what the
//! test lane runs, so the exact compiler messages are stable.

/// A verification policy that names no token profile does not compile (issue
/// #192). This is the enforcement's own proof: the runtime confusion suite can
/// only show that a STATED expectation is honored, never that a caller could not
/// have left it unstated.
#[test]
fn a_policy_cannot_omit_its_expected_media_type() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/policy_requires_expected_typ.rs");
}

#[test]
fn primitives_are_unreachable_from_outside() {
    let t = trybuild::TestCases::new();
    // The one signature primitive lives in a private module.
    t.compile_fail("tests/compile-fail/reach_crypto_primitive.rs");
    // The header parser and its trust guards live in a private module.
    t.compile_fail("tests/compile-fail/reach_header_parser.rs");
    // A trusted key's inner material is not reachable; keys are opaque.
    t.compile_fail("tests/compile-fail/trusted_key_material_is_private.rs");
}
