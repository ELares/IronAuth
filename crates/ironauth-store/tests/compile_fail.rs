// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile-fail proofs that the isolation model cannot be misused.
//!
//! These assert, at the type level, the two guarantees a runtime test cannot:
//! that a repository cannot be built without a scope, and that a scoped handle
//! exposes no way to reach another tenant. The `.stderr` snapshots are pinned
//! to the workspace toolchain (rust-toolchain.toml), which is what both the
//! local gate and CI run, so the exact compiler messages are stable.

#[test]
fn isolation_types_reject_misuse_at_compile_time() {
    let t = trybuild::TestCases::new();
    // (a) A repository cannot be constructed without a scope.
    t.compile_fail("tests/compile-fail/repo_requires_scope.rs");
    // (b) A scoped handle cannot query another tenant: no such API exists.
    t.compile_fail("tests/compile-fail/no_cross_tenant_query.rs");
}
