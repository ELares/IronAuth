// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile-fail proofs that the verification primitives are unreachable from
//! outside the crate.
//!
//! These assert, at the type level, what a runtime test cannot: that no call
//! site outside `ironauth-jose` can reach the raw signature check, the header
//! parser, or a trusted key's inner material, and so cannot assemble a second,
//! weaker verifier. The `.stderr` snapshots are pinned to the workspace
//! toolchain (rust-toolchain.toml), which is what the test lane runs, so the
//! exact compiler messages are stable.

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
