// SPDX-License-Identifier: MIT OR Apache-2.0
//! The adversarial sandbox harness (issue #114, criteria 2 and 3).
//!
//! Every test here runs a REAL component built from `guests/`, not a mock. A mocked hook would
//! be testing this crate's opinion of what a hook does, and the failures these tests exist to
//! catch are all failures of the boundary itself.

use ironauth_hooks::{AbortKind, HookEngine, HookError, Limits, Request};

fn guest(bytes: &'static str) -> Vec<u8> {
    std::fs::read(bytes).unwrap_or_else(|error| panic!("reading guest {bytes}: {error}"))
}

const GOOD: &str = env!("IRONAUTH_GUEST_GOOD");
const FUEL_BOMB: &str = env!("IRONAUTH_GUEST_FUEL_BOMB");
const MEMORY_BOMB: &str = env!("IRONAUTH_GUEST_MEMORY_BOMB");
const NET_ESCAPE: &str = env!("IRONAUTH_GUEST_NET_ESCAPE");
const WALL_CLOCK_ESCAPE: &str = env!("IRONAUTH_GUEST_WALL_CLOCK_ESCAPE");
const MONOTONIC_READER: &str = env!("IRONAUTH_GUEST_MONOTONIC_READER");
const DECLINER: &str = env!("IRONAUTH_GUEST_DECLINER");

fn request() -> Request {
    Request {
        payload_version: 1,
        grant_type: "authorization_code".to_owned(),
        client_id: "spa".to_owned(),
        subject: Some("user-1".to_owned()),
        // BOTH claim sets are populated. An empty one would make the whole ID-token half of
        // the contract unobservable: a transport that dropped it would pass every test.
        id_token_claims: vec![("email".to_owned(), "\"user@example.test\"".to_owned())],
        access_token_claims: vec![("sub".to_owned(), "\"user-1\"".to_owned())],
    }
}

/// The control: a healthy hook runs, and its claim arrives.
///
/// First because every other test in this file is an assertion that something FAILS, and a
/// harness where nothing can succeed would pass all of them. If this test breaks, none of the
/// others below mean what they say.
#[test]
fn a_healthy_hook_runs_and_its_claims_come_back() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(GOOD)).expect("load");
    let outcome = hook
        .customize(&engine, &Limits::claim_shaping(), &request())
        .expect("a healthy hook must run to completion");
    assert!(
        outcome
            .access_token_claims
            .iter()
            .any(|(name, value)| name == "tier" && value == "\"gold\""),
        "the hook's claim did not come back: {:?}",
        outcome.access_token_claims
    );
    assert!(
        outcome
            .access_token_claims
            .iter()
            .any(|(name, _)| name == "sub"),
        "the claims the host sent must survive the round trip"
    );
    assert_eq!(
        outcome.id_token_claims,
        vec![("email".to_owned(), "\"user@example.test\"".to_owned())],
        "the ID token claims must cross the boundary in both directions"
    );
}

/// A hook that opens a socket cannot start.
///
/// Criterion 2, and the mechanism matters as much as the outcome: this is not a connection
/// that gets refused, it is an instantiation that fails because the linker offers no
/// `wasi:sockets`. The guest's own code never runs.
#[test]
fn a_guest_that_opens_a_socket_cannot_start() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(NET_ESCAPE)).expect("it compiles fine");
    let error = hook
        .customize(&engine, &Limits::claim_shaping(), &request())
        .expect_err("a hook that imports sockets must not instantiate");
    assert_eq!(
        error.abort_kind(),
        Some(AbortKind::Unlinkable),
        "it must fail at LINK time, before guest code runs: {error}"
    );
    assert!(
        error.to_string().contains("sockets"),
        "the refusal must name the capability it refused: {error}"
    );
}

/// A hook that reads the wall clock cannot start.
///
/// `wasi:clocks/wall-clock` is not linked, for the sandbox and because this workspace routes
/// all wall-clock time through `ironauth-env`. A hook reaching around that seam would be a
/// determinism hole opened from inside the guest, where `scripts/invariant-lints.sh` cannot
/// see it.
#[test]
fn a_guest_that_reads_the_wall_clock_cannot_start() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(WALL_CLOCK_ESCAPE)).expect("compiles");
    let error = hook
        .customize(&engine, &Limits::claim_shaping(), &request())
        .expect_err("a hook that imports wall-clock must not instantiate");
    assert_eq!(
        error.abort_kind(),
        Some(AbortKind::Unlinkable),
        "it must fail at LINK time: {error}"
    );
    assert!(
        error.to_string().contains("wall-clock"),
        "the refusal must name what it refused: {error}"
    );
}

/// The monotonic clock is present and frozen.
///
/// The one capability absence cannot deliver, because std imports it whether or not a hook uses
/// it. So it is bound to a constant, and this is the guest that proves the constant is what a
/// hook actually sees: it reads the clock, does half a million additions, reads it again, and
/// must observe no time passing.
#[test]
fn the_monotonic_clock_is_present_and_tells_a_hook_nothing() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(MONOTONIC_READER)).expect("load");
    let outcome = hook
        .customize(&engine, &Limits::claim_shaping(), &request())
        .expect("the clock is present, so this hook must run");
    let elapsed = outcome
        .access_token_claims
        .iter()
        .find(|(name, _)| name == "elapsed_ns")
        .map(|(_, value)| value.clone())
        .expect("the guest reports what it measured");
    assert_eq!(
        elapsed, "0",
        "the clock must not advance across real work, or it is not frozen"
    );
}

/// A hook that spins is aborted by fuel.
#[test]
fn a_hook_that_spins_is_aborted_by_fuel() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(FUEL_BOMB)).expect("load");
    let limits = Limits {
        fuel: 5_000_000,
        ..Limits::claim_shaping()
    };
    let error = hook
        .customize(&engine, &limits, &request())
        .expect_err("an infinite loop must not return");
    assert_eq!(
        error.abort_kind(),
        Some(AbortKind::OutOfFuel),
        "fuel must be what stopped it, not something else: {error}"
    );
}

/// The memory cap is what decides, shown by moving only the cap.
///
/// The same guest allocating the same 32 MiB is run twice: under an 8 MiB cap it aborts, under
/// a 128 MiB cap it completes. Asserting only that it failed would not distinguish the cap from
/// fuel, from a trap, or from the guest simply being broken; running it on both sides of the
/// bound is what makes the cap the cause rather than a coincidence.
///
/// Fuel is enormous in both runs, so fuel cannot be what stopped either one. That is the point
/// the two bounds being non-redundant rests on: allocating is cheap in instructions, so a hook
/// can take a gigabyte while barely moving the fuel counter.
#[test]
fn the_memory_cap_is_what_stops_a_hungry_hook() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(MEMORY_BOMB)).expect("load");
    let generous_fuel = 100_000_000_000;

    let error = hook
        .customize(
            &engine,
            &Limits {
                fuel: generous_fuel,
                memory_bytes: 8 << 20,
                ..Limits::claim_shaping()
            },
            &request(),
        )
        .expect_err("32 MiB must not fit under an 8 MiB cap");
    assert_ne!(
        error.abort_kind(),
        Some(AbortKind::OutOfFuel),
        "fuel must not be what stopped it, or this is not a memory test: {error}"
    );

    let outcome = hook
        .customize(
            &engine,
            &Limits {
                fuel: generous_fuel,
                memory_bytes: 128 << 20,
                ..Limits::claim_shaping()
            },
            &request(),
        )
        .expect("the same guest must complete when the cap allows it");
    assert!(
        outcome
            .access_token_claims
            .iter()
            .any(|(name, _)| name == "allocated"),
        "the completing run must be the same guest doing the same work"
    );
}

/// An untouched epoch never interrupts a healthy hook.
///
/// The footgun this exists for: `epoch_interruption(true)` traps EVERY call unless the store
/// also carries a deadline, so a deployment that enables the deadline and forgets the driver
/// gets its failure policy fired on every token issuance rather than on a runaway one. The
/// exhaustion test below cannot see that, because it passes either way.
#[test]
fn an_untouched_epoch_never_interrupts_a_healthy_hook() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(GOOD)).expect("load");
    for _ in 0..50 {
        hook.customize(&engine, &Limits::claim_shaping(), &request())
            .expect("a healthy hook must not be interrupted by an epoch nobody advanced");
    }
}

/// A hook past its deadline is aborted.
#[test]
fn a_hook_past_its_deadline_is_aborted() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(FUEL_BOMB)).expect("load");
    // Enough fuel that fuel cannot be what stops it, so the deadline is what the test measures.
    let limits = Limits {
        fuel: u64::MAX,
        epoch_deadline: 1,
        ..Limits::claim_shaping()
    };
    let engine_for_tick = engine.clone();
    let ticker = std::thread::spawn(move || {
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            engine_for_tick.tick();
        }
    });
    let error = hook
        .customize(&engine, &limits, &request())
        .expect_err("a hook past its deadline must not return");
    ticker.join().expect("ticker");
    assert_eq!(
        error.abort_kind(),
        Some(AbortKind::DeadlineExceeded),
        "the deadline must be what stopped it, not fuel or a trap: {error}"
    );
}

/// A hook that declines is not a hook that trapped.
#[test]
fn a_hook_that_declines_is_distinguished_from_one_that_trapped() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(DECLINER)).expect("load");
    let error = hook
        .customize(&engine, &Limits::claim_shaping(), &request())
        .expect_err("this hook declines");
    assert_eq!(
        error.abort_kind(),
        None,
        "a deliberate decline must not read as an abort: {error}"
    );
    match error {
        HookError::Declined(reason) => assert!(
            reason.contains("not eligible"),
            "the hook's own reason must survive: {reason}"
        ),
        HookError::Aborted { source, .. } => {
            panic!("a deliberate decline must not read as a trap: {source}")
        }
    }
}

/// A precompiled artifact loads, and produces the same result as compiling.
#[test]
fn a_precompiled_hook_behaves_the_same_as_a_compiled_one() {
    let engine = HookEngine::new().expect("engine");
    let wasm = guest(GOOD);
    let compiled = engine
        .load(&wasm)
        .expect("load")
        .customize(&engine, &Limits::claim_shaping(), &request())
        .expect("compiled path");

    let artifact = engine.compile(&wasm).expect("precompile");
    // SAFETY: `artifact` is the output of `engine.compile` two lines above, on this same
    // engine, in this process. It is exactly the provenance `load_precompiled` requires: it
    // did not come from a hook author, from storage, or off a network.
    #[expect(
        unsafe_code,
        reason = "the AOT path cannot be tested without exercising it; the provenance the \
                  contract requires is satisfied two lines above"
    )]
    let precompiled = unsafe { engine.load_precompiled(&artifact) }
        .expect("load precompiled")
        .customize(&engine, &Limits::claim_shaping(), &request())
        .expect("precompiled path");

    assert_eq!(
        compiled, precompiled,
        "AOT must change the latency and nothing else"
    );
}
