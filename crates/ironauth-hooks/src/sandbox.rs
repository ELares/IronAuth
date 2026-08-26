// SPDX-License-Identifier: MIT OR Apache-2.0
//! The host surface a hook can reach, which is as close to nothing as a std guest permits.
//!
//! Criterion 2 asks for a deny-by-default capability sandbox and, unusually for a security
//! requirement, it specifies the mechanism: "enforced by the component linker, not policy
//! checks". The component model delivers that, and the measurement recorded on issue #114 is
//! why it can be trusted rather than assumed: **a guest imports an interface only if it uses
//! one**, so the import list is the capability manifest. A guest that opens a socket carries a
//! `wasi:sockets` import, and against a linker that does not offer one it fails to instantiate:
//!
//! ```text
//! component imports instance `wasi:sockets/tcp@0.2.9`, but a matching
//! implementation was not found in the linker
//! ```
//!
//! That is stronger than a runtime refusal. The hook does not try the connection and get
//! denied; the hook never starts, because the function it wanted was never in the room. There
//! is no escape to attempt, so there is nothing to get wrong at a call site later.
//!
//! # What is deliberately absent
//!
//! [`Sandbox::link`] adds thirteen WASI interfaces by hand rather than calling
//! `wasmtime_wasi::p2::add_to_linker_sync`, and the reason is everything that call would have
//! added. Absent, and absent on purpose:
//!
//! | absent | a guest that touches it |
//! |---|---|
//! | `wasi:sockets/*` (5 interfaces) | fails to instantiate |
//! | `wasi:filesystem/*` (2 interfaces) | fails to instantiate |
//! | `wasi:random/*` (3 interfaces) | fails to instantiate |
//! | `wasi:clocks/wall-clock` | fails to instantiate |
//!
//! `wasi:random` and `wasi:clocks/wall-clock` are absent for a second reason beyond the
//! sandbox: this workspace routes all entropy and all wall-clock time through
//! `ironauth-env`, enforced by `scripts/invariant-lints.sh`. A hook reaching around that seam
//! would be a determinism hole opened from inside the guest, where the lint cannot see it.
//!
//! # The one thing that is present, and the honest limit on it
//!
//! `wasi:clocks/monotonic-clock` IS linked, and this is the exception worth stating plainly
//! rather than letting the criterion read as fully satisfied. A `wasm32-wasip2` guest built
//! with the Rust standard library imports it whether or not it ever reads a clock; std pulls it
//! in unconditionally. Leaving it out would not produce a hook with no clock, it would produce
//! a hook that cannot start.
//!
//! So the name is bound to [`FrozenClock`], which always reads zero and never advances. The
//! guarantee that gives is not "the hook cannot call it" but "calling it tells the hook
//! nothing", and those are different strengths:
//!
//! | capability | mechanism | a guest using it |
//! |---|---|---|
//! | sockets, filesystem, random, wall clock | import absent from the linker | fails to instantiate |
//! | monotonic clock | import present, bound to a constant | starts, and learns nothing |
//!
//! A frozen clock is chosen over a trapping stub, which is what I proposed on the issue before
//! building it. A trap would abort std guests at unpredictable points inside code the hook
//! author did not write, turning a capability decision into a mysterious crash. A constant
//! keeps the hook running, denies the timing side channel just as completely, and has the
//! side benefit of matching the determinism seam: two runs of the same hook on the same input
//! cannot diverge on time, because there is no time.
//!
//! # Granting capabilities
//!
//! Nothing here grants anything, and there is deliberately no API to. Criterion 2's grantable
//! HTTP capability, its request budget, and the KV cache arrive with the work that implements
//! them; an `allow_http` flag that no linker consults would be a control that reads as
//! enforcement and is not. When a grant does arrive it belongs here, as an interface this
//! function conditionally adds, so that the enforcement stays where the mechanism is.

use wasmtime::component::{HasData, Linker, ResourceTable};
use wasmtime_wasi::cli::{WasiCli, WasiCliView as _};
use wasmtime_wasi::clocks::{WasiClocks, WasiClocksView as _};
use wasmtime_wasi::p2::bindings::sync;
use wasmtime_wasi::{HostMonotonicClock, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Marker giving the `wasi:io` interfaces access to the resource table.
///
/// `wasmtime-wasi` keeps its own private equivalent; this is the same three lines, needed
/// here because [`Sandbox::link`] adds those interfaces itself rather than through the
/// all-or-nothing helper.
struct HasTable;

impl HasData for HasTable {
    type Data<'a> = &'a mut ResourceTable;
}

/// A monotonic clock that never advances.
///
/// See the module header: this is what `wasi:clocks/monotonic-clock` is bound to, because a
/// std guest imports that interface unconditionally and cannot start without it.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrozenClock;

impl HostMonotonicClock for FrozenClock {
    fn resolution(&self) -> u64 {
        // One nanosecond, the finest the interface can express. Reporting a coarse resolution
        // would be a second, redundant story about why time is useless here; the honest
        // statement is that the clock is fine-grained and simply never moves.
        1
    }

    fn now(&self) -> u64 {
        0
    }
}

/// The host state a hook instance runs against.
pub struct Sandbox {
    ctx: WasiCtx,
    table: ResourceTable,
    limits: wasmtime::StoreLimits,
}

impl Sandbox {
    /// Build the host state for one hook invocation.
    ///
    /// The [`WasiCtx`] is constructed with no grants at all: no environment variables, no
    /// standard streams, no preopened directories, no network. Those defaults matter less than
    /// they look, because most of what they would grant is not linked in the first place, but
    /// they are the second line and cost nothing.
    #[must_use]
    pub fn new(limits: &crate::Limits) -> Self {
        let mut builder = WasiCtxBuilder::new();
        builder.monotonic_clock(FrozenClock);
        Self {
            ctx: builder.build(),
            table: ResourceTable::new(),
            limits: wasmtime::StoreLimitsBuilder::new()
                .memory_size(limits.memory_bytes)
                .build(),
        }
    }

    /// Access the store limiter, for `Store::limiter`.
    ///
    /// Returned as the trait object `Store::limiter` wants, so the memory cap is applied by
    /// the same mechanism wasmtime uses for every other resource rather than by a check here.
    pub fn limits(&mut self) -> &mut dyn wasmtime::ResourceLimiter {
        &mut self.limits
    }

    /// Add exactly the host interfaces a hook may reach.
    ///
    /// Thirteen `add_to_linker` calls, one per interface, rather than one call to
    /// `add_to_linker_sync`. The list is written out so that adding a capability is an edit
    /// somebody has to make and review, and so that the absence of sockets and filesystem is
    /// visible in the source rather than implied by a helper's contents.
    ///
    /// # Errors
    ///
    /// If an interface cannot be added to the linker, which means two definitions collided.
    /// Returned as wasmtime's own error rather than a [`crate::HookError`] so that the caller
    /// classifies it; there is deliberately no blanket `From<wasmtime::Error>`, because one
    /// would let an unclassified error reach a failure policy that has to match on the kind.
    pub fn link(linker: &mut Linker<Self>) -> Result<(), wasmtime::Error> {
        // io: the resource plumbing std's startup requires. Streams that lead nowhere,
        // because no stdio was granted above.
        wasmtime_wasi_io::bindings::wasi::io::error::add_to_linker::<Self, HasTable>(
            linker,
            |s: &mut Self| &mut s.table,
        )?;
        sync::io::poll::add_to_linker::<Self, HasTable>(linker, |s: &mut Self| &mut s.table)?;
        sync::io::streams::add_to_linker::<Self, HasTable>(linker, |s: &mut Self| &mut s.table)?;

        // The single clock, frozen. wall-clock is NOT added.
        sync::clocks::monotonic_clock::add_to_linker::<Self, WasiClocks>(linker, Self::clocks)?;

        // cli: exit, the environment (empty), the three standard streams (all closed), and
        // the terminal probes std calls during startup. None of them reaches anything.
        sync::cli::exit::add_to_linker::<Self, WasiCli>(linker, Self::cli)?;
        sync::cli::environment::add_to_linker::<Self, WasiCli>(linker, Self::cli)?;
        sync::cli::stdin::add_to_linker::<Self, WasiCli>(linker, Self::cli)?;
        sync::cli::stdout::add_to_linker::<Self, WasiCli>(linker, Self::cli)?;
        sync::cli::stderr::add_to_linker::<Self, WasiCli>(linker, Self::cli)?;
        sync::cli::terminal_input::add_to_linker::<Self, WasiCli>(linker, Self::cli)?;
        sync::cli::terminal_output::add_to_linker::<Self, WasiCli>(linker, Self::cli)?;
        sync::cli::terminal_stdin::add_to_linker::<Self, WasiCli>(linker, Self::cli)?;
        sync::cli::terminal_stdout::add_to_linker::<Self, WasiCli>(linker, Self::cli)?;
        sync::cli::terminal_stderr::add_to_linker::<Self, WasiCli>(linker, Self::cli)?;

        Ok(())
    }
}

impl WasiView for Sandbox {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}
