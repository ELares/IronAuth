// SPDX-License-Identifier: MIT OR Apache-2.0
//! The TypeScript half of issue #114 criterion 1.
//!
//! > A Rust hook and a TypeScript hook each customize token claims through `token.customize`
//! > under sandbox limits in the integration suite.
//!
//! The Rust half is `tests/sandbox.rs`, which runs fourteen Rust components. This file runs the
//! ONE TypeScript component, and it exists as its own file for a reason worth stating: a
//! JavaScript hook carries a JavaScript engine, so compiling it costs seconds in a release
//! build and around two minutes in a debug one. Every test here therefore shares a single
//! compiled hook through a `OnceLock`, which is why the module is arranged around
//! [`typescript_hook`] rather than loading per test.
//!
//! # What "under sandbox limits" is made to mean here
//!
//! Every test runs with [`Limits::claim_shaping`] UNMODIFIED except where the test is about a
//! limit. That is deliberate. Relaxing the fuel or the memory cap "so the TypeScript one fits"
//! would answer a question nobody asked: the claim in criterion 1 is that a TypeScript hook
//! works under the bounds the product actually ships, and a test that raises them first cannot
//! make it. The measured margins are recorded in
//! [`the_typescript_hook_fits_the_shipped_limits_with_margin`], so a future change that eats
//! the headroom is visible as a number rather than as a mysterious failure.

use std::sync::OnceLock;

use ironauth_hooks::{AbortKind, HookEngine, HookError, Limits, LoadedHook, Request};

/// The mode claim the sample reads, mirrored from `guests-ts/src/token-customize.ts`.
///
/// One TypeScript component serves the happy path, the fuel abort and the decline, because
/// four of them would be forty-four megabytes of JavaScript engine in the repository. The
/// sample selects its behaviour from an ordinary input claim, and strips that claim from what
/// it returns.
const MODE_CLAIM: &str = "ironauth_ts_hook_mode";

/// The claim the sample adds. Its VALUE is derived from three request fields.
const SAMPLE_CLAIM: &str = "ts_hook_tier";

/// The committed component, read from disk rather than embedded.
///
/// `tests/sandbox.rs` reads its fixtures the same way, and here it matters more: embedding
/// eleven megabytes with `include_bytes!` would put a copy of a JavaScript engine in this test
/// binary for no gain, since it is read once.
///
/// The env var is set by `build.rs`, and honours an override so `scripts/ts-hook-freshness.sh`
/// can point these same tests at a component it just rebuilt from the TypeScript source. That
/// is what keeps the committed artifact honest: the freshness check compares BEHAVIOUR against
/// this file, not bytes.
fn component() -> Vec<u8> {
    let path = std::env::var("IRONAUTH_GUEST_TS_TOKEN_CUSTOMIZE_OVERRIDE")
        .unwrap_or_else(|_| env!("IRONAUTH_GUEST_TS_TOKEN_CUSTOMIZE").to_owned());
    std::fs::read(&path).unwrap_or_else(|error| panic!("reading {path}: {error}"))
}

/// The one compiled TypeScript hook, shared by every test in this file.
fn typescript_hook() -> &'static (HookEngine, LoadedHook) {
    static HOOK: OnceLock<(HookEngine, LoadedHook)> = OnceLock::new();
    HOOK.get_or_init(|| {
        let engine = HookEngine::new().expect("engine");
        let hook = engine
            .load(&component())
            .expect("the committed TypeScript component must load");
        (engine, hook)
    })
}

/// A request with BOTH claim sets populated and a subject present.
///
/// Both sets, for the reason `tests/sandbox.rs` gives: an empty one makes that half of the
/// contract unobservable, so a transport that dropped it would pass. A subject, because the
/// sample branches on its presence and the no-subject shape is covered separately in
/// [`a_typescript_hook_sees_a_grant_with_no_subject`].
fn request(mode: Option<&str>) -> Request {
    let mut id_token_claims = vec![("email".to_owned(), "\"user@example.test\"".to_owned())];
    if let Some(mode) = mode {
        id_token_claims.push((MODE_CLAIM.to_owned(), format!("\"{mode}\"")));
    }
    Request {
        payload_version: 1,
        grant_type: "authorization_code".to_owned(),
        client_id: "spa".to_owned(),
        subject: Some("user-1".to_owned()),
        id_token_claims,
        access_token_claims: vec![("sub".to_owned(), "\"user-1\"".to_owned())],
    }
}

fn claim<'a>(claims: &'a [(String, String)], name: &str) -> Option<&'a str> {
    claims
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// CRITERION 1, the TypeScript half: a TypeScript hook customizes claims under sandbox limits.
///
/// First, and every other test in this file depends on it: if the TypeScript component cannot
/// run at all, an abort test below still passes, because an abort is what it asserts.
#[test]
fn a_typescript_hook_customizes_claims_under_the_shipped_limits() {
    let (engine, hook) = typescript_hook();
    let outcome = hook
        .customize(engine, &Limits::claim_shaping(), &request(None))
        .expect("the TypeScript hook runs under the shipped limits");

    // The claim the hook ADDED, and its value is derived from the grant type and the client, so
    // this one assertion also proves those two request fields crossed the boundary intact.
    assert_eq!(
        claim(&outcome.id_token_claims, SAMPLE_CLAIM),
        Some("\"authorization_code:spa\""),
        "the TypeScript hook's claim, derived from the request it was handed: {:?}",
        outcome.id_token_claims
    );
    // The claim it was given and echoed. Without this a hook that returned ONLY its own claim
    // would pass, and the WIT contract is a replace: dropping the rest is a real defect that
    // reaches the token.
    assert_eq!(
        claim(&outcome.id_token_claims, "email"),
        Some("\"user@example.test\""),
        "the input claim must survive"
    );
    // The OTHER list. `sandbox.rs` learned this one the hard way: a transport that handled the
    // ID-token half and dropped the access-token half looks correct from the ID token alone.
    assert_eq!(
        claim(&outcome.access_token_claims, "sub"),
        Some("\"user-1\""),
        "the access-token claim set must survive too: {:?}",
        outcome.access_token_claims
    );
    // And the mode claim is absent because it was never sent, not because the hook strips it.
    // The stripping is asserted where a mode IS sent, below.
    assert_eq!(claim(&outcome.id_token_claims, MODE_CLAIM), None);
}

/// The subject is optional in the WIT record, and `option<string>` is where a transport bug
/// hides: a hook that received `Some("")` for an absent subject would produce a different tier
/// and nothing else here would notice.
#[test]
fn a_typescript_hook_sees_a_grant_with_no_subject() {
    let (engine, hook) = typescript_hook();
    let mut req = request(None);
    req.subject = None;
    let outcome = hook
        .customize(engine, &Limits::claim_shaping(), &req)
        .expect("runs");
    assert_eq!(
        claim(&outcome.id_token_claims, SAMPLE_CLAIM),
        Some("\"service:spa\""),
        "an absent subject must reach the guest as absent, not as an empty string"
    );
}

/// The mode claim is CONSUMED, which is what makes one component able to serve every test here
/// without the sample path carrying a stray claim into a token.
#[test]
fn the_mode_claim_does_not_reach_the_output() {
    let (engine, hook) = typescript_hook();
    let outcome = hook
        .customize(
            engine,
            &Limits::claim_shaping(),
            &request(Some("unknown-mode")),
        )
        .expect("an unrecognised mode falls through to the sample path");
    assert_eq!(
        claim(&outcome.id_token_claims, MODE_CLAIM),
        None,
        "the mode claim must be stripped: {:?}",
        outcome.id_token_claims
    );
    assert_eq!(
        claim(&outcome.id_token_claims, SAMPLE_CLAIM),
        Some("\"authorization_code:spa\""),
        "and an unrecognised mode must still customize"
    );
}

/// CRITERION 3, in JavaScript. Fuel bounds a guest that spins, whatever language it was
/// written in.
///
/// This is not a duplicate of `sandbox.rs`'s `fuel_bomb`. Fuel counts wasm instructions, and a
/// JavaScript `for(;;){}` is an interpreter loop rather than a wasm loop: the instructions
/// being counted belong to `SpiderMonkey`, not to the hook author's own code. That the bound
/// still fires is the thing worth pinning.
#[test]
fn a_spinning_typescript_hook_runs_out_of_fuel() {
    let (engine, hook) = typescript_hook();
    let error = hook
        .customize(engine, &Limits::claim_shaping(), &request(Some("spin")))
        .expect_err("an endless loop must not return a customization");
    assert_eq!(
        error.abort_kind(),
        Some(AbortKind::OutOfFuel),
        "a spinning JavaScript hook must abort on FUEL, not on some other fault: {error}"
    );
}

/// A deliberate decline is the `err` arm of the WIT result, and it is not a trap.
///
/// The distinction is what the per-hook failure policy is applied to: a decline carries the
/// author's own reason, an abort has none because the guest never finished. jco lowers the
/// error arm to a thrown value, so this also pins that a TypeScript author's `throw` of a
/// string arrives as a decline rather than as a crash.
#[test]
fn a_declining_typescript_hook_is_a_decline_and_not_an_abort() {
    let (engine, hook) = typescript_hook();
    let error = hook
        .customize(engine, &Limits::claim_shaping(), &request(Some("decline")))
        .expect_err("a decline is not a customization");
    assert_eq!(
        error.abort_kind(),
        None,
        "a decline must not be classified as an abort: {error}"
    );
    let HookError::Declined(reason) = &error else {
        panic!("expected a decline, got {error:?}");
    };
    assert!(
        reason.contains("declined on purpose"),
        "the author's own reason must survive: {reason}"
    );
}

/// The margins, recorded as numbers rather than as a passing test with nothing to read.
///
/// A JavaScript hook is the worst case for every bound the product ships, so these are the
/// figures that say whether [`Limits::claim_shaping`] is sized for the languages criterion 1
/// promises. They are asserted loosely -- the point is to FAIL when a margin disappears, and to
/// print what it was when it does, not to freeze a measurement that legitimately moves.
#[test]
fn the_typescript_hook_fits_the_shipped_limits_with_margin() {
    let (engine, hook) = typescript_hook();
    let shipped = Limits::claim_shaping();

    // MEMORY. The engine's heap has to fit under the same 16 MiB a Rust hook gets. Halving the
    // cap is the probe: if the hook still runs at 8 MiB, the shipped cap has at least 2x of
    // room, and if it does not, the margin is thinner than that and this test says so.
    let halved = Limits {
        memory_bytes: shipped.memory_bytes / 2,
        ..shipped
    };
    assert!(
        hook.customize(engine, &halved, &request(None)).is_ok(),
        "the TypeScript hook needs more than half of the shipped {} MiB memory cap, so the \
         shipped cap has under 2x of headroom for a JavaScript guest",
        shipped.memory_bytes >> 20
    );

    // FUEL. Same probe: run at a quarter of the shipped budget and report if it does not fit.
    // A JavaScript engine's startup dominates this number, so it is the one most likely to
    // creep when componentize-js is upgraded.
    let quartered = Limits {
        fuel: shipped.fuel / 4,
        ..shipped
    };
    let fuel_result = hook.customize(engine, &quartered, &request(None));
    assert!(
        fuel_result.is_ok(),
        "the TypeScript hook needs more than a quarter of the shipped {} fuel budget, so the \
         shipped budget has under 4x of headroom for a JavaScript guest: {:?}",
        shipped.fuel,
        fuel_result.err()
    );
}
