// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cold and warm hook invocation latency (issue #114, criterion 4).
//!
//! Emits one JSON object on stdout so a gate script can compare it against the bounds in
//! `bench-config.toml` and against the committed baseline. A benchmark whose output only a human
//! reads cannot fail a build.
//!
//! # What "cold" means here, and why it changed
//!
//! Cold is `Component::new + instantiate + call`, measured fresh each iteration: the component
//! COMPILED, a store built, and the hook run once. That is what a deployment pays the first time
//! a process sees a given hook, and it is the number the criterion bounds at 1 ms.
//!
//! # This measurement has moved twice, and both moves were the same rule
//!
//! THE RULE: time the sequence the server makes, whatever that currently is.
//!
//! It began as `deserialize + instantiate + call` over a precompiled artifact and reported 128
//! microseconds -- for a path nothing ran. The dispatch that shipped with issue #114 used
//! `HookEngine::load`, and `compile`/`load_precompiled` had ZERO production callers, so the
//! benchmark was passing a gate on a sequence the server never executed while the real one
//! compiled at 33 ms. So cold became the compile, and the gate was raised to 250 ms to match a
//! truth nobody liked.
//!
//! It is the artifact load AGAIN, and the reason is not that the earlier move was wrong: it is
//! that the fact it rested on has changed. Deploys now precompile and store the artifact, and the
//! dispatch loads it when its key matches this build -- so `load_precompiled` has production
//! callers and this sequence is the one a login makes on a cache miss. The cold gate drops from
//! 250 ms to the criterion's 1 ms with it.
//!
//! WHAT THIS DOES NOT MEASURE, said plainly: a row with NO artifact still compiles, and that is
//! milliseconds. Three things produce one -- a deployment whose admin process has no hook
//! runtime, a build without `wasm-hooks`, and a rollback, which deliberately stores none. Those
//! logins pay a compile, and this number is not about them. It is the AOT cold start the
//! criterion names, on the rows a normal deploy writes.
//!
//! Warm is a repeated call on an already-LOADED hook. It is not a repeated call on a shared
//! instance, and the difference is worth stating because it makes the number look worse than a
//! naive benchmark would: `LoadedHook::customize` builds a fresh `Store` every call, on purpose.
//! A store carries one invocation's fuel, deadline and memory, so sharing one across two token
//! issuances would let one hook's consumption bound the other -- a cross-tenant coupling
//! disguised as an optimization. What is reused is the COMPILED component, which is the
//! expensive part; what is rebuilt is the per-invocation state, which is the isolation.
//!
//! So "warm" here means: compilation and AOT loading already paid, everything else fresh. That
//! is what the second and subsequent invocations of a hook actually cost in this design.

use ironauth_hooks::{HookEngine, Limits, Request};

/// How many cold iterations to take. Each one builds and tears down a store, so this is the
/// expensive loop; enough for a stable p95 without making the job slow.
const COLD_ITERATIONS: usize = 200;

/// How many warm iterations to take. Cheap, so more of them.
const WARM_ITERATIONS: usize = 5_000;

/// One sample's elapsed nanoseconds, as a number the JSON line can carry exactly.
///
/// `Instant::elapsed().as_nanos()` is a `u128`, and casting one to `f64` loses precision above
/// 2^53 nanoseconds -- about 104 days.
///
/// The first version guarded that with a `debug_assert!`. `cargo bench` builds on the bench
/// profile, which inherits release, and the target is `test = false`, so the assertion could not
/// execute anywhere -- and the `#[expect]` beside it cited a guard that never runs. A bound
/// nothing evaluates is not a bound, so the value is CLAMPED instead: a sample past the exactly
/// representable range is reported at that range rather than silently rounded, and the reported
/// number stays one the JSON line carries exactly.
///
/// In practice the clamp is unreachable -- an invocation is bounded by an epoch deadline
/// measured in milliseconds -- but "unreachable" is the claim the first version made and could
/// not support.
const EXACT_NANOS: u128 = 1 << 53;

fn micros(nanos: u128) -> f64 {
    let bounded = nanos.min(EXACT_NANOS);
    // Every value reaching this point is at most 2^53, which `f64` represents exactly.
    #[expect(
        clippy::cast_precision_loss,
        reason = "clamped to 2^53 on the line above, which is exactly representable"
    )]
    let nanos = bounded as f64;
    nanos / 1000.0
}

fn p95(mut samples: Vec<u128>) -> u128 {
    samples.sort_unstable();
    // The 95th percentile by nearest-rank, which needs no interpolation and cannot pick an
    // index past the end.
    let rank = (samples.len() * 95).div_ceil(100).max(1) - 1;
    samples[rank]
}

fn request() -> Request {
    Request {
        payload_version: 1,
        grant_type: "authorization_code".to_owned(),
        client_id: "cli_bench".to_owned(),
        subject: Some("usr_bench".to_owned()),
        id_token_claims: vec![("email".to_owned(), "\"user@example.test\"".to_owned())],
        access_token_claims: vec![("sub".to_owned(), "\"usr_bench\"".to_owned())],
    }
}

fn main() {
    let engine = HookEngine::new().expect("engine");
    let wasm = std::fs::read(env!("IRONAUTH_GUEST_GOOD")).expect("the benchmark guest");
    let limits = Limits::claim_shaping();
    let request = request();

    // THE ARTIFACT, compiled once OUTSIDE the measurement -- because the deploy pays that, not
    // the login. Measuring the compile here would time the control plane's work and report it as
    // the request path's, which is precisely the mistake this file's header records.
    let artifact = engine.compile(&wasm).expect("precompile");

    let mut cold_samples = Vec::with_capacity(COLD_ITERATIONS);
    for _ in 0..COLD_ITERATIONS {
        let started = std::time::Instant::now(); // invariant-allow: time-via-env -- THE measurement: elapsed time is this benchmark's entire output, and a bench target is not protocol logic (it is not compiled into the server), which is what the rule protects
        // `load_precompiled + instantiate + call`: the SAME sequence the dispatch makes on a
        // cache miss for a row whose artifact key matches this build.
        //
        // SAFETY: `artifact` is the output of `compile` on this same engine, in this process --
        // the strongest provenance the unsafe contract can have.
        #[expect(
            unsafe_code,
            reason = "the AOT load is the measured path; the artifact was produced by this \
                      engine in this process, which is the provenance the contract requires"
        )]
        let hook = unsafe { engine.load_precompiled(&artifact) }.expect("load the artifact");
        hook.customize(&engine, &limits, &request).expect("call");
        cold_samples.push(started.elapsed().as_nanos());
    }

    let hook = engine.load(&wasm).expect("load");
    // One call outside the measurement so the warm number is not the first call.
    hook.customize(&engine, &limits, &request).expect("warm up");
    let mut warm_samples = Vec::with_capacity(WARM_ITERATIONS);
    for _ in 0..WARM_ITERATIONS {
        let started = std::time::Instant::now(); // invariant-allow: time-via-env -- the warm half of the same measurement; same reasoning as the cold loop above
        hook.customize(&engine, &limits, &request).expect("call");
        warm_samples.push(started.elapsed().as_nanos());
    }

    let (cold_taken, warm_taken) = (cold_samples.len(), warm_samples.len());
    let cold_p95_ns = p95(cold_samples);
    let warm_p95_ns = p95(warm_samples);
    println!(
        "{{\"cold_p95_micros\":{:.3},\"warm_p95_micros\":{:.3},\"artifact_bytes\":{},\"cold_iterations\":{},\"warm_iterations\":{}}}",
        micros(cold_p95_ns),
        micros(warm_p95_ns),
        wasm.len(),
        // The LENGTHS, not the constants. They agree today because the constants are the loop
        // bounds, but the gate's sample floor would then be reading a claim about the data
        // rather than the data -- and a loop that broke early would report the count it meant
        // to take.
        cold_taken,
        warm_taken
    );
}
