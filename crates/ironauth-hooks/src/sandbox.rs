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
//! [`Sandbox::link`] adds fourteen WASI interfaces by hand rather than calling
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

use wasmtime::component::{HasData, Linker, Resource, ResourceTable};
use wasmtime_wasi::cli::{WasiCli, WasiCliView as _};
use wasmtime_wasi::p2::bindings::sync;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_io::poll::{DynPollable, Pollable, subscribe};

/// Marker giving the `wasi:io` interfaces access to the resource table.
///
/// `wasmtime-wasi` keeps its own private equivalent; this is the same three lines, needed
/// here because [`Sandbox::link`] adds those interfaces itself rather than through the
/// all-or-nothing helper.
struct HasTable;

impl HasData for HasTable {
    type Data<'a> = &'a mut ResourceTable;
}

/// What one outbound request returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOutcome {
    /// The HTTP status.
    pub status: u16,
    /// The body as text.
    pub body: String,
}

/// How the host actually performs an outbound request.
///
/// Supplied by the CALLER so this crate owns no network code. That is not tidiness: the sandbox
/// is the thing that must be auditable as a list of capabilities NOT granted, and a crate that
/// linked an HTTP client would have one more thing to argue about. The caller routes through
/// whatever hardened path it already has.
pub type FetchTransport = Box<dyn Fn(&str) -> Result<FetchOutcome, String> + Send + Sync>;

/// An outbound HTTP grant: how many requests, how many spent, and how to make one.
struct FetchGrant {
    budget: u32,
    spent: u32,
    transport: FetchTransport,
}

/// The marker for the one interface this product defines itself.
///
/// `ironauth:hooks/secrets` is implemented on the store state directly rather than on a view of
/// one field, because the whole implementation is a lookup in a map the state owns.
pub struct HasSandbox;

impl HasData for HasSandbox {
    type Data<'a> = &'a mut Sandbox;
}

/// The resolution the frozen clock reports, in nanoseconds.
///
/// One nanosecond, the finest the interface can express. Reporting a coarse resolution would be
/// a second, redundant story about why time is useless here; the honest statement is that the
/// clock is fine-grained and simply never moves. It is deliberately NOT zero: a guest is free
/// to divide by a resolution.
pub const FROZEN_RESOLUTION_NS: u64 = 1;

/// A compile-time floor on the resolution.
///
/// Zero is the one value that is worse than a wrong one: the doc above says a guest is free to
/// divide by the resolution, and a guest that does so against zero traps on every invocation.
/// Asserted here rather than only in a test, because a test that compares the reported value to
/// this constant moves with it.
const _: () = assert!(FROZEN_RESOLUTION_NS > 0);

/// A pollable that is ready the moment it is asked.
///
/// This is what makes the frozen clock a real bound rather than a cosmetic one, and it closes
/// what was a denial of service on the login path.
///
/// `wasi:clocks/monotonic-clock` has four functions, not two. `now` and `resolution` return
/// numbers, and freezing those is easy. `subscribe-instant` and `subscribe-duration` return a
/// POLLABLE, and `wasi:io/poll` blocks on it. Binding only the two number functions to a frozen
/// clock leaves the other two backed by the host's real timer, and a guest whose body is
/// `std::thread::sleep(Duration::from_secs(30))` then holds an IronAuth request thread for
/// thirty seconds. None of the three bounds can stop it: fuel counts instructions and a
/// sleeping guest executes none, the memory cap is irrelevant, and the epoch deadline is
/// checked when wasm code runs, so it fires only once the host call returns, which is thirty
/// seconds too late. A guest can do worse: `subscribe-duration(u64::MAX)` maps to a future that
/// is never ready at all.
///
/// So the sandbox does not implement waiting. Both subscribe functions return this, and a hook
/// that asks to wait is answered immediately. A guest that then busy-loops is executing
/// instructions, which is precisely the thing fuel does bound.
///
/// The general rule this is one instance of: **no host function the sandbox links may block.**
/// A blocking host function is invisible to all three limits, because all three are measured
/// against a guest that is running.
struct AlwaysReady;

#[wasmtime_wasi::async_trait]
impl Pollable for AlwaysReady {
    async fn ready(&mut self) {}
}

/// The host state backing the frozen `wasi:clocks/monotonic-clock`.
struct FrozenClockView<'a> {
    table: &'a mut ResourceTable,
    observed: &'a mut Observed,
}

/// Marker giving the frozen clock access to the resource table.
struct FrozenClocks;

impl HasData for FrozenClocks {
    type Data<'a> = FrozenClockView<'a>;
}

impl sync::clocks::monotonic_clock::Host for FrozenClockView<'_> {
    fn now(&mut self) -> wasmtime::Result<u64> {
        Ok(0)
    }

    fn resolution(&mut self) -> wasmtime::Result<u64> {
        Ok(FROZEN_RESOLUTION_NS)
    }

    fn subscribe_instant(&mut self, when: u64) -> wasmtime::Result<Resource<DynPollable>> {
        // The clock reads zero, so an absolute instant IS the duration from now.
        self.observed.longest_requested_wait_ns = self.observed.longest_requested_wait_ns.max(when);
        self.observed.host_resources_created += 1;
        let handle = self.table.push(AlwaysReady)?;
        subscribe(self.table, handle)
    }

    fn subscribe_duration(&mut self, duration: u64) -> wasmtime::Result<Resource<DynPollable>> {
        self.observed.longest_requested_wait_ns =
            self.observed.longest_requested_wait_ns.max(duration);
        self.observed.host_resources_created += 1;
        let handle = self.table.push(AlwaysReady)?;
        subscribe(self.table, handle)
    }
}

/// A `wasi:io/poll` whose list length is bounded.
///
/// The fourth host-cost multiplier, and none of the other bounds sees it. `poll` takes a LIST of
/// pollable handles, and nothing stops the same handle appearing a million times: the resource
/// table cap bounds distinct resources, not repeats. Measured before this: a guest holding one
/// pollable and polling a list of a million references grew host RSS by 11.5 MiB per call and
/// ran to completion under the shipped 16 MiB guest cap; sixty-four invocations took the host to
/// 739 MiB, permanently.
///
/// Bounded by the same number that bounds the table, because a list longer than the number of
/// resources a guest may hold is necessarily repeats, and a guest has no legitimate reason to
/// wait on the same handle twice in one call.
struct BoundedPoll<'a> {
    table: &'a mut ResourceTable,
    max_entries: usize,
}

/// Marker giving the bounded poll access to the table and the limit.
struct BoundedPollData;

impl HasData for BoundedPollData {
    type Data<'a> = BoundedPoll<'a>;
}

impl sync::io::poll::Host for BoundedPoll<'_> {
    fn poll(&mut self, pollables: Vec<Resource<DynPollable>>) -> wasmtime::Result<Vec<u32>> {
        if pollables.len() > self.max_entries {
            return Err(wasmtime::Error::msg(format!(
                "a hook polled {} handles at once, over the {} limit",
                pollables.len(),
                self.max_entries
            )));
        }
        sync::io::poll::Host::poll(self.table, pollables)
    }
}

impl sync::io::poll::HostPollable for BoundedPoll<'_> {
    fn ready(&mut self, pollable: Resource<DynPollable>) -> wasmtime::Result<bool> {
        sync::io::poll::HostPollable::ready(self.table, pollable)
    }

    fn block(&mut self, pollable: Resource<DynPollable>) -> wasmtime::Result<()> {
        sync::io::poll::HostPollable::block(self.table, pollable)
    }

    fn drop(&mut self, pollable: Resource<DynPollable>) -> wasmtime::Result<()> {
        sync::io::poll::HostPollable::drop(self.table, pollable)
    }
}

/// What the HOST observed a hook do, as opposed to what the hook reported.
///
/// A guest's own account of itself is not evidence: a test that asserts a hook did not wait,
/// using a number the hook printed, passes when the hook stops waiting AND when the sandbox
/// stops preventing it. These are recorded on the host side of the boundary, so they say what
/// happened rather than what was claimed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Observed {
    /// The longest wait, in nanoseconds, the hook ASKED for.
    ///
    /// Not the wait it got: the sandbox answers every wait immediately. This is the request,
    /// which is what distinguishes a hook that tried to sleep for thirty seconds from one that
    /// never tried at all.
    pub longest_requested_wait_ns: u64,
    /// How many host resources the hook created.
    pub host_resources_created: usize,
}

/// The host state a hook instance runs against.
pub struct Sandbox {
    ctx: WasiCtx,
    table: ResourceTable,
    limits: wasmtime::StoreLimits,
    max_host_resources: usize,
    observed: Observed,
    /// The secrets this hook was GRANTED, resolved before it started.
    ///
    /// RESOLVED UP FRONT, and that is a safety property rather than a performance one. Every
    /// resource limit here -- fuel, the memory cap, the epoch deadline -- is measured against a
    /// guest that is RUNNING, so a host function that waited on a database would sit outside
    /// all three and a hook could hold a request thread open through it. Answering from a map
    /// filled before instantiation means `secrets.get` performs no I/O and cannot block.
    ///
    /// EMPTY IS THE DEFAULT and it is the common case: a hook granted nothing gets `none` for
    /// every name, which is the deny-by-default this sandbox applies to everything else.
    secrets: std::collections::BTreeMap<String, String>,
    /// The outbound HTTP capability, absent unless this hook was granted it.
    ///
    /// [`None`] is deny-by-default and it is what an ordinary hook has: `fetch.get` answers
    /// "not granted" without reaching any transport at all.
    fetch: Option<FetchGrant>,
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
        // Nothing is granted: no environment, no standard streams, no preopened directories,
        // no network. The clock is not configured here either, because the sandbox's clock is
        // not this context's clock: see `FrozenClockView`.
        // The host resource table is capped, and this is the bound that actually holds.
        //
        // `StoreLimits` governs core-wasm memories, tables and instances. A POLLABLE is none of
        // those: it lives in the component resource table, whose only ceiling is wasmtime's own
        // default of a million entries. A hook looping on `subscribe_duration` and leaking the
        // handles drove 100 MiB of HOST heap under a 16 MiB guest cap, and every StoreLimits
        // knob was irrelevant to it -- deleting all four changed the number by a megabyte.
        //
        // 4096 is far more than a claim-shaping hook needs (the shipped fixtures use single
        // digits) and small enough that exhausting it costs kilobytes. A guest that exceeds it
        // gets an error from the host function, which surfaces as an ordinary trap.
        let mut table = ResourceTable::new();
        table.set_max_capacity(limits.max_host_resources);

        Self {
            ctx: WasiCtxBuilder::new().build(),
            table,
            max_host_resources: limits.max_host_resources,
            observed: Observed::default(),
            secrets: std::collections::BTreeMap::new(),
            fetch: None,
            // The memory cap alone bounds one linear memory, and a guest can multiply what it
            // costs the HOST without ever exceeding it: many memories, a growing table, or a
            // resource handle per host call. A measured example drove 137 MB of host heap under
            // a 16 MiB ceiling by leaking pollables in a loop. Bounding the multipliers costs a
            // single-module Rust hook nothing, because it needs exactly one of each.
            limits: wasmtime::StoreLimitsBuilder::new()
                .memory_size(limits.memory_bytes)
                // COUNTS are compilation details, not hook-facing limits: one component is
                // several core instances and more than one table, so a count of 1 refuses an
                // ordinary hook before it runs (measured: "table count too high at 2"). They
                // are bounded generously, to stop a pathological module rather than to tune a
                // hook. The SIZES below them are the levers that matter.
                .memories(4)
                .tables(8)
                .table_elements(100_000)
                .instances(64)
                .build(),
        }
    }

    /// What the host saw this hook do.
    #[must_use]
    pub fn observed(&self) -> Observed {
        self.observed
    }

    /// Grant this sandbox the secrets its hook may read.
    ///
    /// Called with values the CALLER has already resolved, because resolving them is a database
    /// read and this type must never perform one: see the field's own doc for why a blocking
    /// host call would sit outside every resource limit the sandbox has.
    #[must_use]
    pub fn with_secrets(mut self, secrets: std::collections::BTreeMap<String, String>) -> Self {
        self.secrets = secrets;
        self
    }

    /// Grant this hook the outbound HTTP capability, bounded by `budget` requests.
    ///
    /// `transport` is supplied by the CALLER, and this crate deliberately owns no network code:
    /// what the sandbox owns is the BUDGET, which is the part the criterion asks to be
    /// deterministic. Keeping them apart is also what lets the budget be tested with no network
    /// at all -- a fake transport that counts calls proves the arithmetic, where a real one
    /// would prove the arithmetic and the internet.
    #[must_use]
    pub fn with_fetch(mut self, budget: u32, transport: FetchTransport) -> Self {
        self.fetch = Some(FetchGrant {
            budget,
            spent: 0,
            transport,
        });
        self
    }

    /// Perform one outbound request, or say why not.
    ///
    /// TWO REFUSALS, and they are deliberately distinguishable. "Not granted" and "budget
    /// exhausted" are different facts about a hook, and an author debugging one should not be
    /// shown the other -- the first means an operator has to grant the capability, the second
    /// means the hook is asking for more than it was given.
    ///
    /// A REFUSAL RETURNS RATHER THAN CALLING OUT. The check is an early return, so an attempt
    /// past the budget reaches no transport at all -- a host that called out and discarded the
    /// answer would already have done the thing it refused.
    ///
    /// AND THE BUDGET IS SPENT WHETHER OR NOT THE REQUEST SUCCEEDS. It bounds what a hook may
    /// make the server DO; a request that failed still travelled, and refunding failures would
    /// let a hook with a budget of one make unbounded attempts against a host that refuses it.
    /// The increment therefore precedes the call, though on this arrangement the ORDER is not
    /// what holds the bound -- the early return above is. What the order buys is that a
    /// transport which panics has still spent its request.
    ///
    /// # Errors
    ///
    /// The refusal text the guest sees. Two of them come from here -- "not granted" when the
    /// hook holds no capability, and "request budget exhausted" when it has spent one -- and any
    /// other is the transport's own, passed through unchanged so a hook author reads what the
    /// remote end or the fetcher said rather than a message this layer invented.
    pub fn fetch(&mut self, url: &str) -> Result<FetchOutcome, String> {
        let Some(grant) = self.fetch.as_mut() else {
            return Err("fetch is not granted to this hook".to_owned());
        };
        if grant.spent >= grant.budget {
            return Err(format!(
                "request budget exhausted: {} of {} used",
                grant.spent, grant.budget
            ));
        }
        grant.spent = grant.spent.saturating_add(1);
        (grant.transport)(url)
    }

    /// The value of a granted secret, or [`None`] when this hook may not read it.
    ///
    /// The whole of what the `secrets` import can do. A map lookup and nothing else -- see the
    /// field's doc for why this must never become a read.
    #[must_use]
    pub fn secret(&self, name: &str) -> Option<String> {
        self.secrets.get(name).cloned()
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
    /// Fourteen `add_to_linker` calls, one per interface, rather than one call to
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
        sync::io::poll::add_to_linker::<Self, BoundedPollData>(linker, |s: &mut Self| {
            BoundedPoll {
                table: &mut s.table,
                max_entries: s.max_host_resources,
            }
        })?;
        sync::io::streams::add_to_linker::<Self, HasTable>(linker, |s: &mut Self| &mut s.table)?;

        // The single clock, frozen in all FOUR of its functions. wall-clock is NOT added.
        //
        // Implemented here rather than routed to `wasmtime_wasi`'s, because that one builds its
        // pollables from `tokio::time::Instant` and consults the configured
        // `HostMonotonicClock` only for `now` and `resolution`. Handing it a frozen clock
        // freezes the two functions that return numbers and leaves the two that return a
        // pollable backed by real time, which is a sleep primitive. See `AlwaysReady`.
        sync::clocks::monotonic_clock::add_to_linker::<Self, FrozenClocks>(
            linker,
            |s: &mut Self| FrozenClockView {
                table: &mut s.table,
                observed: &mut s.observed,
            },
        )?;

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
