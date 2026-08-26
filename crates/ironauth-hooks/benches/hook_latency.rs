// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cold and warm hook invocation latency (issue #114, criterion 4).
//!
//! Emits one JSON object on stdout so a gate script can compare it against the bounds in
//! `bench-config.toml` and against the committed baseline. A benchmark whose output only a human
//! reads cannot fail a build.
//!
//! # What "cold" means here, and why it is the whole invocation
//!
//! Cold is `deserialize + instantiate + call`, measured fresh each iteration: a precompiled
//! artifact loaded, a store built, and the hook run once. That is what a deployment pays for the
//! first invocation of a hook it has not run recently, and it is the number the criterion bounds
//! at 1 ms. Measuring only `deserialize` would report a smaller number for a thing nobody
//! experiences.
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
/// 2^53 nanoseconds -- about 104 days. Every sample here is a single hook invocation bounded by
/// an epoch deadline measured in milliseconds, so the value is representable exactly; the
/// conversion is done once, here, with that reasoning attached, rather than at the print site
/// where it reads as an unexamined cast.
fn micros(nanos: u128) -> f64 {
    debug_assert!(
        nanos < (1_u128 << 53),
        "a single hook invocation cannot take 104 days; the exactness argument for this cast \
         rests on that"
    );
    #[expect(
        clippy::cast_precision_loss,
        reason = "bounded above by the debug assertion: a hook invocation is microsecond-scale"
    )]
    let nanos = nanos as f64;
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
    // AOT, because that is what the criterion measures: a deployment compiles at deploy time and
    // the request path only ever deserializes.
    let artifact = engine.compile(&wasm).expect("precompile");
    let limits = Limits::claim_shaping();
    let request = request();

    let mut cold_samples = Vec::with_capacity(COLD_ITERATIONS);
    for _ in 0..COLD_ITERATIONS {
        let started = std::time::Instant::now(); // invariant-allow: time-via-env -- THE measurement: this benchmark's entire output is real elapsed time, and the Clock seam is a frozen ManualClock, so routing it through the seam would report zero
        // SAFETY: `artifact` is the output of `engine.compile` above, in this process, on this
        // engine. That is exactly the provenance `load_precompiled` requires.
        #[expect(
            unsafe_code,
            reason = "the AOT path is what criterion 4 measures; it cannot be benchmarked \
                      without exercising it, and the provenance is satisfied above"
        )]
        let hook = unsafe { engine.load_precompiled(&artifact) }.expect("load");
        hook.customize(&engine, &limits, &request).expect("call");
        cold_samples.push(started.elapsed().as_nanos());
    }

    #[expect(
        unsafe_code,
        reason = "same provenance as the cold loop; the warm loop needs one loaded hook"
    )]
    let hook = unsafe { engine.load_precompiled(&artifact) }.expect("load");
    // One call outside the measurement so the warm number is not the first call.
    hook.customize(&engine, &limits, &request).expect("warm up");
    let mut warm_samples = Vec::with_capacity(WARM_ITERATIONS);
    for _ in 0..WARM_ITERATIONS {
        let started = std::time::Instant::now(); // invariant-allow: time-via-env -- the warm half of the same measurement; same reasoning as the cold loop above
        hook.customize(&engine, &limits, &request).expect("call");
        warm_samples.push(started.elapsed().as_nanos());
    }

    let cold_p95_ns = p95(cold_samples);
    let warm_p95_ns = p95(warm_samples);
    println!(
        "{{\"cold_p95_micros\":{:.3},\"warm_p95_micros\":{:.3},\"artifact_bytes\":{},\"cold_iterations\":{},\"warm_iterations\":{}}}",
        micros(cold_p95_ns),
        micros(warm_p95_ns),
        artifact.len(),
        COLD_ITERATIONS,
        WARM_ITERATIONS
    );
}
