// SPDX-License-Identifier: MIT OR Apache-2.0
//! The three bounds a hook runs under, and why there are three rather than one.
//!
//! Criterion 3 asks that "fuel exhaustion and epoch deadline both abort a hook cleanly". They
//! are not redundant, and neither one subsumes the other:
//!
//! - **Fuel** counts executed instructions. It is deterministic: the same hook on the same
//!   input consumes the same fuel on every machine, so a fuel limit is reproducible and can be
//!   set from a measurement rather than from a guess. It cannot bound a hook that blocks,
//!   because blocking executes no instructions.
//! - **The epoch deadline** is wall-clock-shaped and bounds exactly what fuel cannot: time
//!   spent not executing. It is not deterministic, so it is a backstop rather than a budget.
//! - **The memory cap** bounds neither time nor instructions. A hook can allocate a gigabyte
//!   in very few instructions, so fuel does not see it coming.
//!
//! A deployment that sets only one of the three has a hole shaped like the other two.

/// How much a hook may consume before it is aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Instructions the hook may execute.
    ///
    /// Deterministic, so this number is a measurement rather than a guess: run the hook, read
    /// the fuel it consumed, and set the limit above it with margin.
    pub fuel: u64,
    /// How many epoch ticks the hook may span before it is interrupted.
    ///
    /// The tick interval belongs to whoever drives the epoch, not to this struct: a deadline of
    /// 1 means "one tick", and only the driver knows how long a tick is. See
    /// [`crate::engine::HookEngine::tick`].
    pub epoch_deadline: u64,
    /// The ceiling on linear memory, in bytes.
    pub memory_bytes: usize,
    /// The most HOST resources one invocation may hold at once.
    ///
    /// A fourth bound, and it is not covered by the other three. `StoreLimits` governs
    /// core-wasm memories, tables and instances; a pollable is none of those, so it lands in the
    /// host's component resource table instead. A guest looping on `subscribe_duration` and
    /// leaking the handles drove 100 MiB of HOST heap under a 16 MiB guest cap, with every
    /// other bound irrelevant to it.
    pub max_host_resources: usize,
}

impl Limits {
    /// Bounds sized for a claim-shaping hook.
    ///
    /// Every number here is a starting point an operator is expected to tune, not a law. They
    /// are set from the measurement recorded on issue #114: a real component-model hook that
    /// decodes a payload, walks a claim list and re-encodes runs a warm call at a p95 of
    /// roughly one microsecond, so these are generous by orders of magnitude on purpose. A
    /// limit that trips during ordinary work teaches operators to raise it without reading it,
    /// which is worse than no limit at all.
    #[must_use]
    pub const fn claim_shaping() -> Self {
        Self {
            // Enough for a hook to walk a large claim set and re-encode it many times over,
            // and far too little to spin.
            fuel: 50_000_000,
            // ONE TICK, and this value is only correct for a caller that drives the epoch
            // DELIBERATELY -- the sandbox suite ticks by hand, so one tick means one tick.
            //
            // Against a FREE-RUNNING ticker it is a lottery. wasmtime sets the deadline to
            // `current_epoch + delta`, and a store created at an arbitrary point inside a tick
            // inherits only what remains of it, so a delta of 1 grants a uniform slice of
            // (0, T]. Measured on a 10 ms ticker: a guest doing 78 microseconds of work
            // trapped on 0.40% of invocations. A server that fails an issuance on a trap gets a
            // random 500 on roughly one hooked login in a hundred.
            //
            // A caller with a running driver must set its own, and must size it for the worst
            // SCHEDULING delay rather than the work, because this bound counts wall clock while
            // `fuel` counts instructions. `ironauth_oidc::token_hook::EPOCH_TICKS_PER_HOOK` is
            // that number for the server and carries the reasoning.
            epoch_deadline: 1,
            // 16 MiB. A claim set that needs more than this is not a claim set.
            memory_bytes: 16 << 20,
            // Far more than a claim-shaping hook needs (the shipped fixtures use single
            // digits), and small enough that exhausting it costs kilobytes rather than
            // gigabytes.
            max_host_resources: 4096,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::claim_shaping()
    }
}
