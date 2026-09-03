// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile-fail proofs about what cannot be written against this crate.
//!
//! Following `ironauth-jose`, whose pattern this crate replicates: a runtime test can show that
//! a call site did not do something, and only a compile-fail proof can show that no call site
//! could. The `.stderr` snapshots are pinned to the workspace toolchain, which is what the test
//! lane runs, so the compiler messages are stable.

/// A value cannot be read out of an unverified document (issue #138).
///
/// EVERYTHING AN ATTACKER WANTS is an attribute value or a text node: the `NameID`, the
/// attribute statements, the `Destination`, the `InResponseTo`. `Element` exposes a name and
/// its children and nothing else, so a caller holding a parsed-but-unverified document cannot
/// reach any of it. The verified type that does carry values arrives with the signature half of
/// this issue, and it is a different type on purpose.
#[test]
fn a_value_cannot_be_read_from_an_unverified_document() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/read_a_value_from_an_unverified_document.rs");
}
