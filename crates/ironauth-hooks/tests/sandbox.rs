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
const SLEEPER: &str = env!("IRONAUTH_GUEST_SLEEPER");
const RANDOM_ESCAPE: &str = env!("IRONAUTH_GUEST_RANDOM_ESCAPE");
const FS_ESCAPE: &str = env!("IRONAUTH_GUEST_FS_ESCAPE");
const ECHO_REQUEST: &str = env!("IRONAUTH_GUEST_ECHO_REQUEST");

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

/// A hook that reads randomness cannot start.
///
/// The guest does nothing exotic: it builds a `HashMap`. std's default hasher is randomly
/// seeded, so an ordinary hook imports `wasi:random/insecure-seed` without its author knowing
/// randomness is involved at all.
///
/// This is deny-by-default working as specified, and it is also a real cost to hook authors,
/// which is why it is a tested fixture rather than a footnote. Randomness is absent for the
/// same reason the wall clock is: this workspace routes entropy through `ironauth-env`, and a
/// hook drawing its own would be a determinism hole opened inside the guest. Granting it is a
/// capability decision that belongs with the work that implements capability grants.
#[test]
fn a_guest_that_draws_randomness_cannot_start() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(RANDOM_ESCAPE)).expect("compiles");
    let error = hook
        .customize(&engine, &Limits::claim_shaping(), &request())
        .expect_err("a hook that imports randomness must not instantiate");
    assert_eq!(error.abort_kind(), Some(AbortKind::Unlinkable));
    assert!(
        error.to_string().contains("random"),
        "the refusal must name what it refused: {error}"
    );
}

/// A hook that opens a file cannot start.
#[test]
fn a_guest_that_opens_a_file_cannot_start() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(FS_ESCAPE)).expect("compiles");
    let error = hook
        .customize(&engine, &Limits::claim_shaping(), &request())
        .expect_err("a hook that imports the filesystem must not instantiate");
    assert_eq!(error.abort_kind(), Some(AbortKind::Unlinkable));
    assert!(
        error.to_string().contains("filesystem") || error.to_string().contains("wall-clock"),
        "the refusal must name what it refused: {error}"
    );
}

/// Every scalar field of the request arrives where it belongs.
///
/// `grant_type` and `client_id` are both strings, so a transport that swapped them would
/// compile and would pass every other test here while handing a hook that gates on the grant
/// type the client id instead.
#[test]
fn every_request_field_crosses_the_boundary_intact() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(ECHO_REQUEST)).expect("load");
    let mut req = request();
    req.payload_version = 7;
    req.grant_type = "refresh_token".to_owned();
    req.client_id = "cli_distinct".to_owned();
    req.subject = Some("usr_distinct".to_owned());

    let outcome = hook
        .customize(&engine, &Limits::claim_shaping(), &req)
        .expect("echo hook runs");
    let field = |name: &str| {
        outcome
            .access_token_claims
            .iter()
            .chain(outcome.id_token_claims.iter())
            .find(|(claim, _)| claim == name)
            .map_or_else(|| panic!("{name} not echoed"), |(_, value)| value.clone())
    };
    assert_eq!(field("echo_grant_type"), "\"refresh_token\"");
    assert_eq!(field("echo_client_id"), "\"cli_distinct\"");
    assert_eq!(field("echo_payload_version"), "7");
    assert_eq!(field("echo_subject"), "\"usr_distinct\"");
}

/// Bytes that are not a hook are reported as unloadable, not as a capability escape.
///
/// The distinction is what an audit log says about an operator who mistyped an upload: "asked
/// for a capability it was not granted" is an accusation, and a parse error is not.
#[test]
fn bytes_that_are_not_a_hook_are_reported_as_invalid() {
    let engine = HookEngine::new().expect("engine");
    for bytes in [
        b"this is not wasm".as_slice(),
        b"".as_slice(),
        b"\0asm-truncated",
    ] {
        let error = engine.load(bytes).expect_err("not a component");
        assert_eq!(
            error.abort_kind(),
            Some(AbortKind::Invalid),
            "unloadable bytes must not read as a capability escape: {error}"
        );
        let compile_error = engine.compile(bytes).expect_err("not a component");
        assert_eq!(compile_error.abort_kind(), Some(AbortKind::Invalid));
    }
}

/// A forged precompiled artifact is refused, and is reported as unloadable.
#[test]
fn a_forged_precompiled_artifact_is_refused() {
    let engine = HookEngine::new().expect("engine");
    // SAFETY: the contract is that the artifact came from this deployment's own `compile`.
    // It deliberately did NOT here, which is the case under test; wasmtime's header check is
    // what refuses it, and the point of this test is that the refusal is CLASSIFIED honestly.
    // Nothing is executed: the header check fails before any code is mapped.
    #[expect(
        unsafe_code,
        reason = "the refusal of a forged artifact cannot be tested without offering one"
    )]
    let error = unsafe { engine.load_precompiled(b"\0wasm-artifact-forged") }
        .expect_err("a foreign artifact must be refused");
    assert_eq!(error.abort_kind(), Some(AbortKind::Invalid));
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
    let claim = |name: &str| {
        outcome
            .access_token_claims
            .iter()
            .find(|(claim, _)| claim == name)
            .map_or_else(|| panic!("{name} not reported"), |(_, value)| value.clone())
    };
    assert_eq!(
        claim("elapsed_ns"),
        "0",
        "the clock must not advance across real work, or it is not frozen"
    );
    // Two claims returned, two claims asserted. A resolution of zero is a value a guest could
    // divide by, and the guest already reports it.
    assert_eq!(
        claim("resolution_ns"),
        ironauth_hooks::FROZEN_RESOLUTION_NS.to_string(),
        "the resolution must stay fine-grained rather than becoming another way to say zero"
    );
}

/// A hook cannot WAIT, which is the one thing none of the three bounds can catch.
///
/// The guest's body is `std::thread::sleep(Duration::from_secs(30))` in plain std, needing no
/// knowledge of WASI. Against `wasmtime_wasi`'s own monotonic clock it holds this thread for
/// the full thirty seconds: it executes no instructions, so fuel never moves; it allocates
/// nothing, so the memory cap is irrelevant; and the epoch deadline is only checked while wasm
/// code runs, so it fires when the host call returns rather than while it is blocked. On a
/// login path that is a denial of service a hook author can write by accident.
///
/// The bound is wall-clock here, deliberately, and it is not a flake risk in the direction that
/// matters: the assertion is that thirty seconds of sleep took under five, so it fails only if
/// waiting genuinely happened. A slow machine makes a passing run slower, not a failing one.
#[test]
fn a_hook_cannot_wait() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(SLEEPER)).expect("load");
    let started = std::time::Instant::now(); // invariant-allow: time-via-env -- a TIMING harness: the assertion is that a 30-second sleep did NOT take 30 seconds, which is a claim about real elapsed time and cannot be made against a frozen seam
    hook.customize(&engine, &Limits::claim_shaping(), &request())
        .expect("the wait is answered immediately, so the hook completes");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "a hook asked to sleep for 30s held the thread for {elapsed:?}"
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

    // The two arms bracket the MEASURED threshold, not the guest's nominal appetite. Sweeping
    // the cap from 31 to 128 MiB, this guest traps at 31, 32 and 33 MiB and completes from 34
    // MiB up: its 32 MiB buffer plus the module's own memory, stack and allocator overhead.
    // Bracketing at 33 and 34 pins the cap to within one megabyte of where it actually bites.
    //
    // Tightness is the point. A loose low arm is satisfied by caps so small the guest never
    // executes at all, which reports that the memory cap stopped a hungry hook when in fact
    // instantiation was refused; and a loose pair would let a limiter that multiplied the
    // configured number satisfy both.
    let error = hook
        .customize(
            &engine,
            &Limits {
                fuel: generous_fuel,
                memory_bytes: 33 << 20,
                ..Limits::claim_shaping()
            },
            &request(),
        )
        .expect_err("this guest must not fit under a 33 MiB cap");
    assert_eq!(
        error.abort_kind(),
        Some(AbortKind::Trapped),
        "the guest must have RUN and its own allocator failed, not been refused at          instantiation: {error}"
    );

    // One megabyte above the measured threshold. Together with the 33 MiB arm, a limiter that
    // silently multiplied or ignored the configured number could not satisfy both.
    let outcome = hook
        .customize(
            &engine,
            &Limits {
                fuel: generous_fuel,
                memory_bytes: 34 << 20,
                ..Limits::claim_shaping()
            },
            &request(),
        )
        .expect("the same guest must complete when the cap allows it");
    let touched = outcome
        .access_token_claims
        .iter()
        .find(|(name, _)| name == "pages_touched")
        .map(|(_, value)| value.clone())
        .expect("the completing run must be the same guest doing the same work");
    assert_eq!(
        touched,
        (32 * 1024 / 4).to_string(),
        "the guest must have written every page, not merely reserved them"
    );
}

/// The shipped defaults actually bite.
///
/// `Limits::claim_shaping()` is what a deployment gets when it does not tune anything, and
/// every one of its three numbers could be raised to infinity with nothing turning red: the
/// other tests all pass their own `Limits`. Pinned behaviourally rather than by re-asserting
/// the literals, because asserting `fuel == 50_000_000` says only that somebody typed a number,
/// not that the number stops anything.
#[test]
fn the_default_limits_bound_a_runaway_hook() {
    let engine = HookEngine::new().expect("engine");
    let defaults = Limits::claim_shaping();

    let spinner = engine.load(&guest(FUEL_BOMB)).expect("load");
    let error = spinner
        .customize(&engine, &defaults, &request())
        .expect_err("the DEFAULT fuel must stop an infinite loop");
    assert_eq!(
        error.abort_kind(),
        Some(AbortKind::OutOfFuel),
        "default fuel must be finite and small enough to bite: {error}"
    );

    let hungry = engine.load(&guest(MEMORY_BOMB)).expect("load");
    let error = hungry
        .customize(&engine, &defaults, &request())
        .expect_err("the DEFAULT memory cap must stop a 32 MiB appetite");
    assert_ne!(
        error.abort_kind(),
        Some(AbortKind::OutOfFuel),
        "the default memory cap, not fuel, must be what stopped it: {error}"
    );

    // The default deadline must be reachable. `u64::MAX` would make the epoch backstop
    // unreachable for every deployment, and nothing else here would notice.
    assert!(
        defaults.epoch_deadline <= 16,
        "a default deadline of {} ticks is not a backstop anybody reaches",
        defaults.epoch_deadline
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
    // Large but FINITE fuel. With `u64::MAX` a regression in the deadline mechanism makes this
    // test HANG rather than fail: the spinner runs forever and nothing bounds it. At this
    // budget the deadline still wins by a wide margin under normal operation, and a broken
    // deadline surfaces within seconds as an OutOfFuel abort instead of a hung suite.
    let limits = Limits {
        fuel: 10_000_000_000,
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
