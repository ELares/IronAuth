// SPDX-License-Identifier: MIT OR Apache-2.0
//! A custom factor that never returns, in EVERY one of its three calls (issue #114 criteria 3
//! and 6).
//!
//! The bounds a sandboxed guest runs under are fuel, the memory cap and the epoch deadline, and
//! they are applied per STORE. `challenge.rs` builds a store in one shared helper so that all
//! three entry points get them, but a helper that quietly stopped setting fuel would leave every
//! test in `custom_challenge.rs` green: none of those calls is expensive enough to notice.
//!
//! So this exists to notice. Each export spins forever, and a host that bounded the call aborts
//! it; one that did not hangs, which the test's own timeout turns into a failure rather than a
//! stuck suite.
//!
//! ALL THREE EXPORTS, not just one. The three are three separate invocations with three separate
//! stores, and a helper applied to two of them would be a hole exactly the size of the third.

wit_bindgen::generate!({ path: "../../wit", world: "custom-challenge-hook" });

use exports::ironauth::hooks::custom_challenge::{
    Answer, ChallengeSpec, Context, Decision, Guest,
};

struct Runaway;

/// Spin until something outside stops us.
///
/// `black_box` on the accumulator so the optimizer cannot decide the loop is dead and delete it.
/// A fixture that got optimized away would report "no abort" and read exactly like a missing
/// bound.
fn spin() -> ! {
    let mut counter: u64 = 0;
    loop {
        counter = counter.wrapping_add(1);
        std::hint::black_box(counter);
    }
}

impl Guest for Runaway {
    fn define(_ctx: Context) -> Result<Decision, String> {
        spin()
    }

    fn create(_ctx: Context) -> Result<ChallengeSpec, String> {
        spin()
    }

    fn verify(_ctx: Context, _private_params: String, _answers: Vec<Answer>) -> Result<bool, String> {
        spin()
    }
}

export!(Runaway);
