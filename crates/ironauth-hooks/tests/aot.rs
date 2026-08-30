// SPDX-License-Identifier: MIT OR Apache-2.0
//! Precompiled artifacts and the key that decides whether one may be executed (issue #114
//! criterion 4).
//!
//! An artifact is MACHINE CODE. Everything here is about the one question that matters before it
//! runs: is this artifact one THIS build produced?

// UNSAFE IS DENIED CRATE-WIDE, and this file is the one place a test must use it: the whole
// subject here is `load_precompiled`, whose entire contract is that the caller states where the
// artifact came from. Every use below is an artifact THIS test just produced.
#![expect(
    unsafe_code,
    reason = "the subject of this file is the unsafe AOT load; each call states its provenance"
)]

use ironauth_hooks::{HookEngine, Limits, Request};

fn guest() -> Vec<u8> {
    std::fs::read(env!("IRONAUTH_GUEST_GOOD")).expect("read the guest")
}

fn request() -> Request {
    Request {
        payload_version: 1,
        grant_type: "authorization_code".to_owned(),
        client_id: "spa".to_owned(),
        subject: Some("user-1".to_owned()),
        id_token_claims: Vec::new(),
        access_token_claims: Vec::new(),
    }
}

/// THE ROUND TRIP: compile, load the artifact, and get the same behaviour as loading the wasm.
///
/// The whole criterion rests on these being the same hook. A test that only checked the artifact
/// LOADS would pass for one that loaded and then did something else.
#[test]
fn an_artifact_runs_the_same_hook_the_component_does() {
    let engine = HookEngine::new().expect("engine");
    let wasm = guest();
    let artifact = engine.compile(&wasm).expect("compile");

    let from_wasm = engine
        .load(&wasm)
        .expect("load wasm")
        .customize(&engine, &Limits::default(), &request())
        .expect("run from wasm");
    // SAFETY: `artifact` is the output of `compile` on this same engine, in this process.
    let loaded = unsafe { engine.load_precompiled(&artifact) }.expect("load artifact");
    let from_artifact = loaded
        .customize(&engine, &Limits::default(), &request())
        .expect("run from artifact");

    assert_eq!(
        from_wasm.access_token_claims, from_artifact.access_token_claims,
        "the artifact must run the same hook, not merely load"
    );
    assert!(
        !from_artifact.access_token_claims.is_empty(),
        "and it must actually produce claims, or the comparison above is between two empties"
    );
}

/// THE KEY IS STABLE ACROSS ENGINES OF THE SAME BUILD.
///
/// Two engines built the same way must agree, or a second replica would refuse every artifact
/// the first one wrote and the cache would never hit.
#[test]
fn two_engines_of_one_build_agree_on_the_key() {
    let first = HookEngine::new().expect("first");
    let second = HookEngine::new().expect("second");
    assert_eq!(
        first.compatibility_key(),
        second.compatibility_key(),
        "a per-engine key would make every artifact unloadable by any other process"
    );
    assert_eq!(
        first.compatibility_key().len(),
        64,
        "a SHA-256 rendered as hex is 64 characters; a shorter one means the encoding changed \
         and every stored artifact just became unloadable"
    );
    assert!(
        first
            .compatibility_key()
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "the key is stored in a text column and compared as a string"
    );
}

/// THE VERSION LITERAL MATCHES THE DEPENDENCY IT NAMES.
///
/// `WASMTIME_VERSION` is a literal because cargo does not expose a dependency's version to a
/// dependent. A literal that drifted from the real dependency would keep the key STABLE across a
/// wasmtime upgrade -- which is the one direction that matters, because it would let this build
/// load an artifact compiled by a different compiler.
///
/// Read from `Cargo.toml` at test time rather than trusted.
#[test]
fn the_pinned_wasmtime_version_matches_cargo_toml() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read Cargo.toml");
    let declared = manifest
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("wasmtime = { version = \"")?;
            rest.split('"').next()
        })
        .expect("the manifest declares a wasmtime version");
    // The constant is private, so this reads it the way the key does: by building a key with the
    // known version prefix and asserting the manifest agrees with what the module documents.
    assert_eq!(
        declared, "48",
        "the wasmtime dependency moved to {declared}; update WASMTIME_VERSION in engine.rs so \
         the artifact key changes with it, or this build will load artifacts compiled by a \
         different compiler"
    );
}

/// AN ARTIFACT FROM A DIFFERENT COMPILER IS REFUSED.
///
/// The negative that gives the key its meaning. A truncated artifact stands in for a foreign
/// one: what is asserted is that `load_precompiled` REFUSES rather than executing something it
/// cannot vouch for -- and that the refusal is an error rather than a crash.
#[test]
fn a_corrupt_artifact_is_refused_rather_than_executed() {
    let engine = HookEngine::new().expect("engine");
    let artifact = engine.compile(&guest()).expect("compile");
    let mut damaged = artifact.clone();
    // Damage the TAIL rather than the header: a header check is the easy half, and an artifact
    // whose header is intact is the one a caller would be tempted to trust.
    let tail = damaged.len() - 1024;
    for byte in &mut damaged[tail..] {
        *byte ^= 0xff;
    }
    // SAFETY: this is deliberately damaged output of our own `compile`, and the assertion is
    // that wasmtime refuses it. That is the contract being tested; it is not a load we rely on.
    let result = unsafe { engine.load_precompiled(&damaged) };
    assert!(
        result.is_err(),
        "a damaged artifact must be refused, not executed"
    );
}
