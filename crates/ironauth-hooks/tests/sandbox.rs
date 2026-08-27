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
const INSTANT_WAITER: &str = env!("IRONAUTH_GUEST_INSTANT_WAITER");
const POLLABLE_LEAK: &str = env!("IRONAUTH_GUEST_POLLABLE_LEAK");
const POLL_BOMB: &str = env!("IRONAUTH_GUEST_POLL_BOMB");

/// Run a hook on its own thread with a deadline, so a regression FAILS rather than hangs.
///
/// The wait tests assert that a call returned promptly. If the mechanism they guard regresses so
/// that the call never returns, measuring elapsed time inside the call cannot report it: the
/// test hangs and CI reports a job timeout rather than the one-line failure. This bounds the
/// call itself.
fn bounded_customize(
    hook: &ironauth_hooks::LoadedHook,
    engine: &HookEngine,
    limits: &Limits,
    request: &Request,
) -> Result<Result<ironauth_hooks::Customization, HookError>, &'static str> {
    std::thread::scope(|scope| {
        let (sender, receiver) = std::sync::mpsc::channel();
        scope.spawn(move || {
            let _ = sender.send(hook.customize(engine, limits, request));
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .map_err(|_| "the hook did not return within 10s")
    })
}

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
/// Criterion 2, and the mechanism matters as much as the outcome: this is not a connection that
/// gets refused, it is IMPORT RESOLUTION that fails because the host surface offers no
/// `wasi:sockets`. The guest's own code never runs.
///
/// It now fails at LOAD rather than at the first call. Resolving a component's imports moved to
/// `HookEngine::load` when the warm path stopped rebuilding its linker per invocation, and the
/// refusal moved with it. That is the better place for it: a hook asking for a capability the
/// sandbox does not grant is a property of the ARTIFACT, not of any particular request, so an
/// operator learns it when the component is first loaded instead of on somebody's login.
#[test]
fn a_guest_that_opens_a_socket_cannot_start() {
    let engine = HookEngine::new().expect("engine");
    // REFUSED AT LOAD, not at call. `HookEngine::load` resolves the component's
    // imports against the host surface now, so a guest asking for a capability the
    // sandbox does not offer never becomes a `LoadedHook` at all.
    let error = engine
        .load(&guest(NET_ESCAPE))
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
    // REFUSED AT LOAD, not at call. `HookEngine::load` resolves the component's
    // imports against the host surface now, so a guest asking for a capability the
    // sandbox does not offer never becomes a `LoadedHook` at all.
    let error = engine
        .load(&guest(RANDOM_ESCAPE))
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
    // REFUSED AT LOAD, not at call. `HookEngine::load` resolves the component's
    // imports against the host surface now, so a guest asking for a capability the
    // sandbox does not offer never becomes a `LoadedHook` at all.
    let error = engine
        .load(&guest(FS_ESCAPE))
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
    // REFUSED AT LOAD; see the socket case.
    let error = engine
        .load(&guest(WALL_CLOCK_ESCAPE))
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
    // The PROPERTY, not the constant. Comparing the reported value to the constant moves with
    // it: setting FROZEN_RESOLUTION_NS to 0 satisfied that equality while every guest computing
    // `elapsed / resolution` divided by zero and trapped on every invocation.
    // The absolute reading, not only the delta: a clock stuck at ANY constant gives a zero
    // delta, so this is what distinguishes frozen-at-zero from frozen-at-12.3-seconds.
    assert_eq!(
        claim("now_ns"),
        "0",
        "the clock must read zero, not merely fail to advance"
    );
    let resolution: u64 = claim("resolution_ns").parse().expect("a number");
    assert!(
        resolution > 0,
        "a guest is free to divide by the resolution, so it must never be zero"
    );
    assert!(
        resolution <= 1_000,
        "the clock must stay fine-grained, not {resolution}ns"
    );
    assert_eq!(
        resolution,
        ironauth_hooks::FROZEN_RESOLUTION_NS,
        "the reported resolution must be the one the sandbox documents"
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
    let outcome = hook
        .customize(&engine, &Limits::claim_shaping(), &request())
        .expect("the wait is answered immediately, so the hook completes");
    let elapsed = started.elapsed();
    // The bound is DERIVED from what the fixture asked for, not hard-coded. With a fixed five
    // seconds, deleting the sleep from the guest leaves this test green -- and it then passes
    // against a sandbox where waiting still works, which is the one thing it exists to catch.
    // The HOST's observation, not the guest's report. Deriving the threshold from a number the
    // guest prints is not a guard: deleting the sleep while keeping the report left the whole
    // suite green against a sandbox with a live thirty-second hold. `longest_requested_wait_ns`
    // is recorded on the host side of the boundary when the guest calls subscribe, so it says
    // the wait was ATTEMPTED whatever the guest chooses to say about itself.
    let requested_ns = outcome.observed.longest_requested_wait_ns;
    assert!(
        requested_ns >= 10_000_000_000,
        "the host must have SEEN a long wait requested; it saw {requested_ns}ns, so this test \
         is no longer exercising the sandbox"
    );
    assert!(
        elapsed.as_nanos() * 6 < u128::from(requested_ns),
        "a hook asked to wait {requested_ns}ns and the call took {elapsed:?}"
    );
}

/// A hook cannot make the HOST allocate an unbounded poll list.
///
/// The fourth multiplier, and the other three cannot see it. The resource table bounds DISTINCT
/// resources; a poll list is a list of handles and nothing stopped the same handle appearing a
/// million times. Measured before this bound: 11.5 MiB of host heap per call, completing
/// normally under a 16 MiB guest cap, reaching 739 MiB after sixty-four invocations.
#[test]
fn a_hook_cannot_poll_an_unbounded_list() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(POLL_BOMB)).expect("load");
    let error = bounded_customize(&hook, &engine, &Limits::claim_shaping(), &request())
        .expect("the call must not hang")
        .expect_err("a million-entry poll list must be refused");
    assert_ne!(
        error.abort_kind(),
        Some(AbortKind::Unlinkable),
        "the guest must have RUN and been refused: {error}"
    );
}

/// A hook cannot wait on an INSTANT either.
///
/// `subscribe-instant` is the clock's other waiting function, and it is a separate code path
/// from `subscribe-duration`. Reintroducing a real timer on this one alone held the host thread
/// for twenty seconds with every other test in this file green.
#[test]
fn a_hook_cannot_wait_on_an_instant() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(INSTANT_WAITER)).expect("load");
    let started = std::time::Instant::now(); // invariant-allow: time-via-env -- a TIMING harness: the assertion is that a wait until the end of time returned promptly, which is a claim about real elapsed time
    hook.customize(&engine, &Limits::claim_shaping(), &request())
        .expect("a wait on an instant is answered immediately");
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "a hook waiting until u64::MAX held the thread for {elapsed:?}"
    );
}

/// A hook cannot exhaust the HOST's heap through the resource table.
///
/// The bound that matters here is not the memory cap. `StoreLimits` governs core-wasm memories,
/// tables and instances; a pollable is none of those, so a guest that leaks them grows the
/// HOST's component resource table instead. Measured before this was capped: 100 MiB of host
/// heap under a 16 MiB guest ceiling, unchanged by every `StoreLimits` knob.
#[test]
fn a_hook_cannot_exhaust_the_host_resource_table() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(POLLABLE_LEAK)).expect("load");
    let started = std::time::Instant::now(); // invariant-allow: time-via-env -- a TIMING harness: an unbounded table would make this run until the host is out of memory, so the bound is a real elapsed one
    // The CAP is what decides, shown by moving only the cap. The guest asks for 3000
    // pollables: under a cap of 512 it must be refused, under 8192 it must succeed. Asserting
    // only that something stopped it would not distinguish the cap from fuel -- an unbounded
    // leak is stopped by fuel too, which is why removing the cap entirely left the first
    // version of this test green.
    let error = hook
        .customize(
            &engine,
            &Limits {
                max_host_resources: 512,
                ..Limits::claim_shaping()
            },
            &request(),
        )
        .expect_err("3000 pollables must not fit under a cap of 512");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the leak must be refused promptly, not after exhausting the host"
    );
    assert_ne!(
        error.abort_kind(),
        Some(AbortKind::Unlinkable),
        "the guest must have RUN and been refused a resource: {error}"
    );

    let outcome = hook
        .customize(
            &engine,
            &Limits {
                max_host_resources: 8192,
                ..Limits::claim_shaping()
            },
            &request(),
        )
        .expect("the same guest must complete when the cap allows it");
    assert_eq!(
        outcome
            .access_token_claims
            .iter()
            .find(|(name, _)| name == "pollables_created")
            .map(|(_, value)| value.as_str()),
        Some("3000"),
        "the completing run must be the same guest doing the same work"
    );

    // And the SHIPPED default must be a real bound, not an inherited million.
    assert!(
        Limits::claim_shaping().max_host_resources <= 8192,
        "the default host-resource cap is too high to bound anything"
    );
}

/// A deadline that expires during INSTANTIATION is not reported as a capability refusal.
///
/// `from_instantiate` is reached for both, and binning a trap by its call site would tell a
/// failure policy that a hook asked for something it was not granted -- which is unfixable by
/// the operator it is reported to, and wrong.
#[test]
fn a_deadline_that_expires_during_instantiation_is_not_a_capability_refusal() {
    let engine = HookEngine::new().expect("engine");
    let hook = engine.load(&guest(GOOD)).expect("load");
    // A deadline of ZERO ticks is already reached the moment it is set, so the interrupt fires
    // at the first epoch check, which happens while the component is being instantiated. That
    // is deterministic, where racing a ticker against instantiation is not.
    let error = hook
        .customize(
            &engine,
            &Limits {
                epoch_deadline: 0,
                ..Limits::claim_shaping()
            },
            &request(),
        )
        .expect_err("a deadline of zero ticks must abort");
    assert_eq!(
        error.abort_kind(),
        Some(AbortKind::DeadlineExceeded),
        "a deadline that fired during instantiation must not read as Unlinkable: {error}"
    );
}

/// Calling `customize` from a tokio worker thread PANICS, and this is the executable form of
/// that warning.
///
/// The sandbox links `wasmtime-wasi`'s sync bindings, and every one enters the host through
/// `in_tokio`, which panics when it is already on a worker. IronAuth's server is async, so a
/// dispatch that calls this straight from a request handler panics the host mid-login.
///
/// The doc on `customize` used to say a `#[test]` fn could not observe this. That was wrong: a
/// test can build its own runtime, and this one does. Written as a test rather than only a
/// comment because if someone later swaps the sandbox to the async bindings, this goes red and
/// the doc gets corrected with it, where a prose warning would simply become false.
#[test]
fn calling_a_hook_from_a_tokio_worker_panics_rather_than_working() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let joined = runtime.block_on(async {
        tokio::task::spawn(async {
            let engine = HookEngine::new().expect("engine");
            let hook = engine.load(&guest(SLEEPER)).expect("load");
            hook.customize(&engine, &Limits::claim_shaping(), &request())
                .map(|_| ())
        })
        .await
    });
    let error = joined.expect_err("a hook that polls must not survive a worker thread");
    assert!(
        error.is_panic(),
        "the failure must be the in_tokio panic the doc warns about, not an ordinary error"
    );

    // And the same hook under spawn_blocking is fine, which is what the doc tells a caller to do.
    let ok = runtime.block_on(async {
        tokio::task::spawn_blocking(|| {
            let engine = HookEngine::new().expect("engine");
            let hook = engine.load(&guest(SLEEPER)).expect("load");
            hook.customize(&engine, &Limits::claim_shaping(), &request())
                .map(|_| ())
        })
        .await
        .expect("spawn_blocking must not panic")
    });
    assert!(ok.is_ok(), "under spawn_blocking the same hook completes");
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

    // The deadline is pinned BEHAVIOURALLY, by driving it. A range check (`<= 16`) passes for
    // any value in the range, so raising the default from 1 to 16 -- a 16x weaker backstop --
    // left it green. Ticking exactly `epoch_deadline` times must abort a spinner, whatever that
    // number is, which is the property "the default is reachable" actually means.
    // Exactly ONE tick, and the default must be reachable by it. Ticking
    // `defaults.epoch_deadline` times instead would pass for any value, so raising the default
    // from 1 to 16 -- a 16x weaker backstop -- left the first version of this green.
    assert_eq!(
        defaults.epoch_deadline, 1,
        "the default deadline must be one tick, so a deployment's tick interval IS its timeout"
    );
    let ticker_engine = engine.clone();
    let ticker = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        ticker_engine.tick();
    });
    let error = spinner
        .customize(
            &engine,
            &Limits {
                // Enough that fuel cannot be what stops it within the tick window, but finite,
                // so a broken deadline fails this test instead of hanging it.
                fuel: 100_000_000_000,
                ..defaults
            },
            &request(),
        )
        .expect_err("the DEFAULT deadline must stop a spinner once it is driven");
    ticker.join().expect("ticker");
    assert_eq!(
        error.abort_kind(),
        Some(AbortKind::DeadlineExceeded),
        "one tick must reach the default deadline: {error}"
    );
}

/// The default fuel is small enough to bite quickly, not merely finite.
///
/// A 1000x raise leaves every other test green while taking the default runaway abort from
/// milliseconds to seconds, which on a login path is the difference between a bounded hook and
/// a stalled one.
#[test]
fn the_default_fuel_stops_a_runaway_quickly() {
    let engine = HookEngine::new().expect("engine");
    let spinner = engine.load(&guest(FUEL_BOMB)).expect("load");
    let started = std::time::Instant::now(); // invariant-allow: time-via-env -- a TIMING harness: the claim is that the DEFAULT budget aborts a runaway in a bounded wall-clock time, which is what makes it a usable default
    let error = spinner
        .customize(&engine, &Limits::claim_shaping(), &request())
        .expect_err("the default fuel must stop an infinite loop");
    let elapsed = started.elapsed();
    assert_eq!(error.abort_kind(), Some(AbortKind::OutOfFuel));
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "the default fuel took {elapsed:?} to stop a spinner, which is too long for a login path"
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

/// TWO ENGINES BUILT THE SAME WAY AGREE, and an artifact from one loads in the other.
///
/// This is the property the whole AOT design rests on. Storing machine code in a table every
/// node reads is undefined behaviour if the loading engine differs from the producing one, so
/// the artifact travels with a KEY and is only deserialized when the key matches. If two
/// identically-configured engines disagreed, every node would recompile forever and the stored
/// artifact would be dead weight; if the key matched across engines that were NOT compatible,
/// it would be worse than dead weight.
///
/// wasmtime's own guarantee is the one being leaned on: "If this Hash matches between two
/// Engines then binaries from one are guaranteed to deserialize in the other." This asserts the
/// key agrees AND that a real artifact actually crosses, because the guarantee is only useful
/// if both halves hold in this configuration.
#[test]
fn an_artifact_crosses_between_two_engines_that_report_the_same_key() {
    let producer = HookEngine::new().expect("engine");
    let consumer = HookEngine::new().expect("engine");
    assert_eq!(
        producer.compatibility_key(),
        consumer.compatibility_key(),
        "two engines built by `HookEngine::new` are configured identically, so they must agree"
    );

    let artifact = producer.compile(&guest(GOOD)).expect("precompile");
    // SAFETY: the artifact is the output of `compile` on an engine whose compatibility key
    // equals this one's, asserted immediately above. That is exactly the provenance
    // `load_precompiled` requires, and it is the same check the dispatch makes before it calls
    // this in production.
    #[expect(
        unsafe_code,
        reason = "the AOT path is the subject: the property under test is that an artifact \
                  crosses between key-equal engines, which cannot be shown without loading one"
    )]
    let hook = unsafe { consumer.load_precompiled(&artifact) }
        .expect("an artifact from a key-equal engine loads");

    let customization = hook
        .customize(&consumer, &Limits::claim_shaping(), &request())
        .expect("and it runs");
    assert!(
        customization
            .access_token_claims
            .iter()
            .any(|(name, _)| name == "tier"),
        "the hook that crossed is the hook that ran: {:?}",
        customization.access_token_claims
    );
}

/// The key is STABLE within a process, so reading it twice cannot invalidate stored artifacts.
///
/// Cheap, and it guards a real hazard: a key derived from anything incidental -- an address, an
/// allocation order, a timestamp -- would differ between the deploy-time write and the
/// request-time comparison, and every artifact would be recompiled on every load while the
/// mechanism looked correct.
#[test]
fn the_compatibility_key_is_stable_across_reads() {
    let engine = HookEngine::new().expect("engine");
    assert_eq!(engine.compatibility_key(), engine.compatibility_key());
}
