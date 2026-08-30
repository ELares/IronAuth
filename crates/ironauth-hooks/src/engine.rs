// SPDX-License-Identifier: MIT OR Apache-2.0
//! Compiling a hook, loading it, and running it under bounds.
//!
//! # AOT is a security boundary, not only a latency one
//!
//! Criterion 4 wants AOT precompilation for its cold-start budget, and the numbers recorded on
//! issue #114 say it delivers: a real component-model hook deserializes, instantiates and runs
//! at a p95 of 0.127 ms against a 1 ms gate. That is the reason the criterion asks for it.
//!
//! It is not the most important reason to be careful with it. **A precompiled artifact is
//! machine code.** [`HookEngine::load_precompiled`] maps it and jumps into it, and wasmtime's
//! own documentation is explicit that the header check it performs is a version guard, not a
//! defence against a hostile artifact. So the rule this module exists to enforce is:
//!
//! > A precompiled artifact is only ever loaded if THIS deployment produced it from a `.wasm`
//! > it validated. A hook author uploads WebAssembly, never machine code.
//!
//! That is why the two directions are asymmetric. [`HookEngine::compile`] takes untrusted
//! bytes and is safe: wasmtime validates the module, and a malformed one is an error, not a
//! jump. [`HookEngine::load_precompiled`] takes bytes that must already be trusted and is
//! `unsafe`, so that every caller has to write down where its artifact came from. If those two
//! were symmetric, the shortest path from "hook upload" to "running" would run straight
//! through arbitrary code execution, and nothing in the type system would object.
//!
//! # Why the engine is shared and the store is not
//!
//! One [`HookEngine`] holds compiled code and is cheap to clone across threads. A `Store` holds
//! one invocation's fuel, deadline, and memory, so it is created per call and dropped after.
//! Sharing a store between two token issuances would let one hook's consumption bound the
//! other's, which is a cross-tenant coupling disguised as an optimization.

use wasmtime::component::{Component, InstancePre, Linker};
use wasmtime::{Config, Engine, Store};

use crate::sandbox::HasSandbox;
use crate::{HookError, Limits, Sandbox};

wasmtime::component::bindgen!({
    path: "wit",
    world: "token-customize-hook",
});

// Aliased so the generated path is written once. The generated namespace repeats the WIT
// interface name, and `scripts/dormant-module-scan.sh` counts a bare `name::` anywhere in
// `crates/` as a reference to a MODULE of that name -- so spelling the full path at each use
// site made `ironauth-store`'s unrelated `token_customize` module look wired. One alias keeps
// the collision to a single line that a reader can see for what it is.
use exports::ironauth::hooks::token_customize as wit_hook;

/// The host side of the `secrets` import, answered from what the caller resolved.
///
/// NO I/O HERE, and the whole design of per-hook secrets rests on it: every resource limit a
/// sandboxed guest runs under -- fuel, the memory cap, the epoch deadline -- is measured against
/// a guest that is RUNNING, so a host function that waited on a database would sit outside all
/// three. A hook could then hold a request thread open through this call while executing no
/// instructions, which is precisely the shape a previous review found in `wasi:clocks`'
/// subscription functions. The values are resolved before instantiation and this is a map
/// lookup.
///
/// DENY BY DEFAULT: a name this hook was not granted answers `none`, and a hook granted nothing
/// gets `none` for every name. There is no `list`, so a hook cannot enumerate the secret
/// namespace -- knowing WHICH secrets an operator has configured is disclosure even where the
/// values are refused.
impl ironauth::hooks::secrets::Host for Sandbox {
    fn get(&mut self, name: String) -> Option<String> {
        self.secret(&name)
    }
}

/// A compiled-code cache, the configuration every hook runs under, and the linked host surface.
///
/// # The linker is built ONCE, and that is the warm-path budget
///
/// `Sandbox::link` registers the whole host surface a guest may import: the io resource
/// plumbing, the bounded poll, the streams, and the frozen monotonic clock in all four of its
/// functions. That is dozens of host function registrations and it does not depend on the guest.
///
/// It used to run inside `customize`, so EVERY invocation rebuilt the entire linker before
/// instantiating. Criterion 4 bounds a warm invocation at 100 microseconds and CI measured 83.7,
/// 135.8, 169.9 and 168.2 across four runs -- a bound the system passed one run in four. Most of
/// that was this.
#[derive(Clone)]
pub struct HookEngine {
    engine: Engine,
    /// Shared because `HookEngine` is `Clone` and a `Linker` is not cheap to duplicate. It is
    /// immutable after construction: nothing adds to the host surface at runtime, which is what
    /// makes sharing it safe and what makes `deny by default` a property of this type rather
    /// than of each call.
    linker: std::sync::Arc<Linker<Sandbox>>,
}

impl HookEngine {
    /// Build an engine configured for hooks.
    ///
    /// # Errors
    ///
    /// If wasmtime rejects the configuration, which on a supported platform means the build
    /// lacks a feature this asks for.
    pub fn new() -> Result<Self, HookError> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        // Both bounds are enabled at the ENGINE, and both are then set per store. Enabling
        // them here costs a little throughput on every hook whether or not a given deployment
        // uses them, and that is the right trade: a config flag that decides whether runaway
        // hooks can be stopped is not something to leave to a deployment to remember.
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(HookError::from_engine)?;
        let mut linker: Linker<Sandbox> = Linker::new(&engine);
        // NOT `from_instantiate`. That classifier answers "a hook asked for a capability it was
        // not granted", which is a statement about a GUEST -- and there is no guest here. This
        // is the host failing to register its own surface, which is a broken build or a
        // wasmtime version skew, and reporting it as a capability refusal would send an
        // operator looking at a hook that does not exist yet.
        Sandbox::link(&mut linker).map_err(HookError::from_engine)?;
        // THE ONE INTERFACE THIS PRODUCT DEFINES, beside the fourteen WASI ones `link` adds.
        // Registered here rather than inside `Sandbox::link` because that function's contract
        // is "exactly the WASI host interfaces a hook may reach", and this is not WASI: it is
        // `ironauth:hooks/secrets`, whose whole implementation is a lookup in this store's own
        // state. Keeping the two lists apart is what makes the WASI surface auditable as a
        // list of things NOT granted.
        ironauth::hooks::secrets::add_to_linker::<Sandbox, HasSandbox>(&mut linker, |s| s)
            .map_err(HookError::from_engine)?;
        Ok(Self {
            engine,
            linker: std::sync::Arc::new(linker),
        })
    }

    /// Compile a hook from WebAssembly to a precompiled artifact.
    ///
    /// This is the deploy-time half. It is safe to call on bytes a hook author uploaded:
    /// wasmtime validates the component and refuses a malformed one.
    ///
    /// # Errors
    ///
    /// If the bytes are not a valid component, or if compilation fails.
    pub fn compile(&self, wasm: &[u8]) -> Result<Vec<u8>, HookError> {
        self.engine
            .precompile_component(wasm)
            .map_err(HookError::from_load)
    }

    /// Load a hook straight from WebAssembly, compiling it now.
    ///
    /// The convenience path for tests and for a first invocation that has no artifact yet.
    /// The request path should not use it: compilation is milliseconds where loading a
    /// precompiled artifact is microseconds, and criterion 4's budget is written for the
    /// latter.
    ///
    /// # Errors
    ///
    /// If the bytes are not a valid component, or if compilation fails -- and now also if the
    /// component imports something the host surface does not offer, which is
    /// [`AbortKind::Unlinkable`](crate::AbortKind::Unlinkable) and used to surface at the first
    /// invocation instead. That is a DEPLOY-time property of the artifact, so it belongs here;
    /// a caller that caches loaded hooks should cache this refusal too, or it recompiles an
    /// unloadable component on every request.
    pub fn load(&self, wasm: &[u8]) -> Result<LoadedHook, HookError> {
        let component = Component::new(&self.engine, wasm).map_err(HookError::from_load)?;
        self.prepare(&component)
    }

    /// Resolve a compiled component's imports against the host surface.
    ///
    /// The shared half of [`Self::load`] and [`Self::load_precompiled`], so both produce a hook
    /// whose imports are already matched and neither can accidentally skip it.
    ///
    /// # Errors
    ///
    /// If the component imports something the sandbox does not offer. That is a DEPLOY-time
    /// error now, where it used to surface on the first login that ran the hook.
    fn prepare(&self, component: &Component) -> Result<LoadedHook, HookError> {
        Ok(LoadedHook {
            pre: self
                .linker
                .instantiate_pre(component)
                .map_err(HookError::from_instantiate)?,
        })
    }

    /// Load a hook from an artifact this deployment previously produced with [`Self::compile`].
    ///
    /// # Safety
    ///
    /// The bytes MUST be the unmodified output of [`Self::compile`] from an engine with the
    /// same wasmtime version and configuration. They are machine code and will be executed.
    /// Loading an artifact that arrived over the network, that a hook author supplied, or that
    /// any component outside this deployment produced is arbitrary code execution, and the
    /// version header wasmtime checks does not make it otherwise.
    ///
    /// # Errors
    ///
    /// If the artifact was produced by a different wasmtime version or configuration, insofar
    /// as the header records that. An `Ok` here is not evidence the artifact was trustworthy.
    #[expect(
        unsafe_code,
        reason = "AOT loading is inherently unsafe: the artifact is machine code. The whole \
                  point of this function is to be the one place that is written down, so \
                  callers must state where their artifact came from. See the module header."
    )]
    pub unsafe fn load_precompiled(&self, artifact: &[u8]) -> Result<LoadedHook, HookError> {
        // SAFETY: delegated to this function's own contract, which the caller accepted.
        let component = unsafe { Component::deserialize(&self.engine, artifact) }
            .map_err(HookError::from_load)?;
        self.prepare(&component)
    }

    /// Advance the epoch by one tick.
    ///
    /// A hook's [`Limits::epoch_deadline`] counts ticks, and this is what makes one pass. The
    /// deployment that calls this decides what a tick is worth in milliseconds; nothing here
    /// can know that, and a hard-coded interval would be a timeout nobody could tune.
    ///
    /// A deployment that never calls this has hooks bounded only by fuel and memory. That is a
    /// real gap, not a theoretical one, and it is the reason
    /// `an_untouched_epoch_never_interrupts_a_healthy_hook` exists: the failure it guards
    /// against is a deployment that enables the deadline and forgets the driver, at which
    /// point the deadline never arrives and the backstop is quietly gone.
    pub fn tick(&self) {
        self.engine.increment_epoch();
    }

    /// The underlying engine, for building a linker.
    pub(crate) fn inner(&self) -> &Engine {
        &self.engine
    }
}

/// A hook that has been compiled AND had its imports resolved, ready to instantiate.
///
/// `Debug` is HAND-WRITTEN, not derived: `InstancePre` has none, and the fact worth printing is
/// not its contents (resolved import pointers) but that the hook reached the resolved state at
/// all. A `LoadedHook` that exists has passed import resolution by construction. Tests still
/// `expect_err` on a load, which is how the unloadable and unlinkable paths are covered.
pub struct LoadedHook {
    /// The guest's imports already resolved against the host surface.
    ///
    /// `Linker::instantiate_pre` does the matching of what the component imports to what the
    /// host offers, once, at load time. `customize` then only has to build a `Store` and
    /// instantiate, which is the irreducible per-invocation work: a store is per-call state
    /// (its fuel, its epoch deadline, its resource table) and cannot be shared.
    ///
    /// This also moves a whole class of failure from the request path to the deploy path. A
    /// component importing something the sandbox does not grant now fails when it is LOADED,
    /// with a clear error, rather than on the first login that reaches it.
    pre: InstancePre<Sandbox>,
}

/// Hand-written because `InstancePre` has no `Debug`, and because the fact worth printing is
/// not its contents (resolved import pointers) but that the hook reached the resolved state at
/// all. A `LoadedHook` that exists has passed import resolution by construction.
impl std::fmt::Debug for LoadedHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedHook")
            .field("imports", &"resolved")
            .finish()
    }
}

/// What one hook invocation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Customization {
    /// The claims the hook wants in the ID token.
    pub id_token_claims: Vec<(String, String)>,
    /// The claims the hook wants in the access token.
    pub access_token_claims: Vec<(String, String)>,
    /// What the HOST saw the hook do, as opposed to what the hook said about itself.
    ///
    /// Carried out of the invocation because a guest's own account of itself is not evidence: a
    /// hook that reports it asked to sleep for thirty seconds and a hook that never asked are
    /// indistinguishable from the claims alone. A failure policy that wants to disable a hook
    /// which repeatedly tries to wait needs the host's number, not the guest's.
    pub observed: crate::Observed,
}

impl LoadedHook {
    /// Run the hook's `customize` export under `limits`.
    ///
    /// # This is SYNCHRONOUS and must not be called from an async runtime worker thread
    ///
    /// The sandbox links `wasmtime-wasi`'s SYNC bindings, and every one of them enters the
    /// host through `in_tokio`, which PANICS when it is already on a tokio worker. IronAuth's
    /// server is async, so calling this directly from a request handler panics the host process
    /// the first time a guest polls or reads a stream: not an error, not a trap, a panic in the
    /// middle of a login.
    ///
    /// Measured: the same hook that returns in 1.16 ms under `spawn_blocking` panics at
    /// `wasmtime-wasi/src/runtime.rs` when invoked from a multi-thread runtime. It is not only
    /// written here: `calling_a_hook_from_a_tokio_worker_panics_rather_than_working` builds a
    /// runtime and asserts both halves, so this warning has an executable form that goes red if
    /// the sandbox ever moves to the async bindings.
    ///
    /// **Call this from `tokio::task::spawn_blocking`** (or any thread with no ambient
    /// runtime). The dispatch that wires hooks into the token mint has to do that, and this is
    /// the note it needs to have read.
    ///
    /// The returned claims have NOT been fenced. Every name here came from guest code and is
    /// a request, not a decision. `filter_hook_claims`, in `ironauth-oidc`'s claims-mapping module, is what
    /// turns it into one, and it refuses a reserved name, an untrimmed one, an over-long one,
    /// and anything past its claim bound. Keeping the fence out of this crate is deliberate: it
    /// makes filtering a step visible in the caller rather than something this function is
    /// trusted to have done.
    ///
    /// # Errors
    ///
    /// [`HookError::Aborted`] if the hook exhausted fuel, passed its deadline, exceeded its
    /// memory cap, or trapped. [`HookError::Declined`] if the hook returned an error of its
    /// own, which is a different thing: the hook ran and said no.
    pub fn customize(
        &self,
        engine: &HookEngine,
        limits: &Limits,
        request: &Request,
    ) -> Result<Customization, HookError> {
        self.customize_with_secrets(engine, limits, request, std::collections::BTreeMap::new())
    }

    /// [`Self::customize`], granting the hook the secrets it may read (issue #114 criterion 5).
    ///
    /// A SEPARATE ENTRY POINT rather than a parameter on `customize`, so that the callers who
    /// grant nothing keep saying nothing about secrets -- which is most of them, and which is
    /// the deny-by-default this sandbox applies to every other capability.
    ///
    /// `secrets` carries VALUES the caller has already resolved. This crate must not resolve
    /// them: it has no store, and more importantly a host function that read one would sit
    /// outside every bound a running guest is measured against. See `Sandbox::secrets`.
    ///
    /// # Errors
    ///
    /// As [`Self::customize`].
    pub fn customize_with_secrets(
        &self,
        engine: &HookEngine,
        limits: &Limits,
        request: &Request,
        secrets: std::collections::BTreeMap<String, String>,
    ) -> Result<Customization, HookError> {
        // A STORE and nothing else. The linker was built when the engine was, and this hook's
        // imports were resolved against it when the hook was loaded; what is left is the state
        // that genuinely cannot be shared between two concurrent invocations -- this call's
        // fuel, its epoch deadline, and its resource table.
        // THE SECRETS ARE ALREADY RESOLVED, and they have to be: this call is where the guest
        // starts running, and every bound it runs under is measured against a RUNNING guest, so
        // a host function that fetched a value would sit outside all of them.
        let sandbox = Sandbox::new(limits).with_secrets(secrets);
        let mut store = Store::new(engine.inner(), sandbox);
        store.limiter(|s: &mut Sandbox| s.limits());
        store.set_fuel(limits.fuel).map_err(HookError::from_call)?;
        store.set_epoch_deadline(limits.epoch_deadline);

        let instance = self
            .pre
            .instantiate(&mut store)
            .map_err(HookError::from_instantiate)?;
        let hook =
            TokenCustomizeHook::new(&mut store, &instance).map_err(HookError::from_instantiate)?;
        let wit_request = wit_hook::Request {
            payload_version: request.payload_version,
            grant_type: request.grant_type.clone(),
            client_id: request.client_id.clone(),
            subject: request.subject.clone(),
            id_token_claims: to_wit(&request.id_token_claims),
            access_token_claims: to_wit(&request.access_token_claims),
        };

        let returned = hook
            .ironauth_hooks_token_customize()
            .call_customize(&mut store, &wit_request)
            .map_err(HookError::from_call)?;

        match returned {
            Ok(response) => Ok(Customization {
                id_token_claims: from_wit(response.id_token_claims),
                access_token_claims: from_wit(response.access_token_claims),
                observed: store.data().observed(),
            }),
            Err(reason) => Err(HookError::Declined(reason)),
        }
    }
}

/// What the host hands a hook, in host types.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request {
    /// Issue #113's payload version.
    pub payload_version: u32,
    /// The wire `grant_type`.
    pub grant_type: String,
    /// The client the tokens are for.
    pub client_id: String,
    /// The subject, absent for a grant with no user.
    pub subject: Option<String>,
    /// ID-token claims, as name and JSON text.
    pub id_token_claims: Vec<(String, String)>,
    /// Access-token claims, as name and JSON text.
    pub access_token_claims: Vec<(String, String)>,
}

fn to_wit(claims: &[(String, String)]) -> Vec<ironauth::hooks::types::Claim> {
    claims
        .iter()
        .map(|(name, value)| ironauth::hooks::types::Claim {
            name: name.clone(),
            value_json: value.clone(),
        })
        .collect()
}

fn from_wit(claims: Vec<ironauth::hooks::types::Claim>) -> Vec<(String, String)> {
    claims
        .into_iter()
        .map(|claim| (claim.name, claim.value_json))
        .collect()
}
