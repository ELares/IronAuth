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

use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

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

/// A compiled-code cache and the configuration every hook runs under.
#[derive(Clone)]
pub struct HookEngine {
    engine: Engine,
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
        Ok(Self {
            engine: Engine::new(&config).map_err(HookError::from_engine)?,
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
    /// If the bytes are not a valid component, or if compilation fails.
    pub fn load(&self, wasm: &[u8]) -> Result<LoadedHook, HookError> {
        Ok(LoadedHook {
            component: Component::new(&self.engine, wasm).map_err(HookError::from_load)?,
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
        Ok(LoadedHook { component })
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

/// A hook that has been compiled and is ready to instantiate.
///
/// `Debug` is derived rather than omitted so a test can `expect_err` on a load, which is how
/// the unloadable-bytes paths are covered at all. The component's own `Debug` is opaque, so
/// this leaks nothing about a hook's contents.
#[derive(Debug)]
pub struct LoadedHook {
    component: Component,
}

/// What one hook invocation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Customization {
    /// The claims the hook wants in the ID token.
    pub id_token_claims: Vec<(String, String)>,
    /// The claims the hook wants in the access token.
    pub access_token_claims: Vec<(String, String)>,
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
    /// `wasmtime-wasi/src/runtime.rs` and exits 101 when invoked from a `#[tokio::main]`
    /// multi-thread main. A `#[test]` fn has no ambient runtime, so the suite in this crate
    /// cannot see it, which is exactly why it is written here.
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
        let mut linker: Linker<Sandbox> = Linker::new(engine.inner());
        Sandbox::link(&mut linker).map_err(HookError::from_instantiate)?;

        let sandbox = Sandbox::new(limits);
        let mut store = Store::new(engine.inner(), sandbox);
        store.limiter(|s: &mut Sandbox| s.limits());
        store.set_fuel(limits.fuel).map_err(HookError::from_call)?;
        store.set_epoch_deadline(limits.epoch_deadline);

        let hook = TokenCustomizeHook::instantiate(&mut store, &self.component, &linker)
            .map_err(HookError::from_instantiate)?;
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
