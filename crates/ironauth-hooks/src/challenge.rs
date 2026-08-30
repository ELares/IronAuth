// SPDX-License-Identifier: MIT OR Apache-2.0

//! The custom challenge triad (issue #114 criterion 6): `define`, `create`, `verify`.
//!
//! Cognito's custom auth challenge model, as one WASM component. What the host does with the
//! three answers is the flow engine's business; what this module owns is that each of the three
//! is a SEPARATE sandboxed invocation with its own fuel, its own memory cap and its own epoch
//! deadline.
//!
//! # Three invocations, not one, and the bounds are the reason
//!
//! It would be cheaper to instantiate once and call all three exports against one store. It
//! would also mean a component could spend the whole factor's fuel inside `define` and leave
//! `verify` unable to run -- so a factor could be made to fail closed by exhausting a budget in
//! a call that decides nothing. Each call gets its own store, so each is bounded on its own and
//! one cannot starve another.
//!
//! # These three do NOT return `Observed`, and that is deliberate
//!
//! [`crate::Customization`] carries an [`crate::Observed`] -- the longest wait a guest ASKED
//! for, and how many host resources it created -- and the triad drops it. That asymmetry is
//! recorded here rather than left silent, because it looks like an oversight and is not.
//!
//! Nothing outside this crate reads `Observed` today: `customize` fills it, the tests assert it,
//! and no dispatch consults it. Adding a second unread channel would be building another layer
//! with no caller, which is worse than the asymmetry. When a consumer arrives -- a metric on
//! hooks that try to sleep, say -- it needs BOTH worlds, and this note is where the second one
//! is written down so it is not forgotten.
//!
//! It also means no state survives between them. That is deliberate: everything `verify` needs
//! is what `create` put in `private-params`, which the host held, so the component is a pure
//! function of what it is handed. A component that stashed the expected answer in a global
//! would find it gone, which is the correct outcome rather than an inconvenience -- two logins
//! running concurrently in one process must not be able to see each other's challenge.

use wasmtime::Store;

use crate::sandbox::FetchTransport;
use crate::{HookEngine, HookError, Limits, LoadedHook, Sandbox};

mod bindings {
    //! The generated bindings for the second world.
    //!
    //! `with` REUSES the first world's generated import types rather than generating a second
    //! set. Both worlds import the same `secrets` and `fetch`, and generating them twice would
    //! define the `Host` traits twice -- so `Sandbox` could not implement both, and the linker
    //! built for one world could not resolve a component of the other. Sharing them is what
    //! lets ONE linker, ONE `HookEngine` and ONE `LoadedHook` serve both worlds.
    wasmtime::component::bindgen!({
        path: "wit",
        world: "custom-challenge-hook",
        with: {
            "ironauth:hooks/secrets": crate::engine::ironauth::hooks::secrets,
            "ironauth:hooks/fetch": crate::engine::ironauth::hooks::fetch,
        },
    });
}

use bindings::CustomChallengeHook;
use bindings::exports::ironauth::hooks::custom_challenge as wit;

/// What every call in the triad is told about the flow it is running in.
///
/// NO SESSION, NO TOKENS, NO CREDENTIALS, which is the point rather than an omission: a
/// challenge component decides whether a user can prove something, and is never given the means
/// to act as them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChallengeContext {
    /// The payload version, explicit in every invocation.
    pub payload_version: u32,
    /// The pseudonymous subject being challenged, when the flow has established one.
    pub subject: Option<String>,
    /// The client this login is for.
    pub client_id: String,
    /// How many rounds of this factor have already COMPLETED, starting at zero.
    pub round: u32,
    /// Whether the previous round's answer was accepted; [`None`] on the first round.
    pub previous_passed: Option<bool>,
}

/// What `define` decided happens next.
///
/// The host owns no state machine of its own for a custom factor: it asks, and it does this.
/// That is what keeps a new factor out of the flow engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeDecision {
    /// Issue (another) challenge. The host calls [`LoadedHook::create_challenge`] next.
    Challenge,
    /// The factor is satisfied; the flow advances.
    Succeed,
    /// The factor has failed for good, with a reason for the audit trail.
    ///
    /// NOT rendered to the user. A factor that wants to tell the user something says it through
    /// a further round's prompt; this string is for the operator reading why a login was refused.
    Fail(String),
}

/// One input a challenge asks the user for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeField {
    /// The submission key the answer arrives under.
    pub name: String,
    /// The label to render, or a localization key for one.
    pub label: String,
    /// Whether to mask the value on screen and keep it out of logs.
    pub secret: bool,
}

/// One challenge to put in front of the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeSpec {
    /// What to tell the user.
    pub prompt: String,
    /// The inputs to render, in the order the component gave them.
    pub fields: Vec<ChallengeField>,
    /// What `verify` will need, JSON-encoded. NEVER rendered and never sent to the client.
    pub private_params: String,
    /// What the client may see alongside the fields, JSON-encoded.
    pub public_params: String,
}

/// One answer coming back from the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeAnswer {
    /// The field name this answers.
    pub name: String,
    /// What the user submitted.
    pub value: String,
}

/// What a caller grants ONE invocation of the triad.
///
/// The same shape `token.customize` takes, and grouped into a struct for the same reason: three
/// entry points that each took `secrets` and `fetch` positionally would be three chances to pass
/// one factor's secrets to another factor's call.
pub struct ChallengeGrants {
    /// The resolved secret values this component may read, by name.
    pub secrets: std::collections::BTreeMap<String, String>,
    /// The outbound request budget and its transport, absent when not granted.
    pub fetch: Option<(u32, FetchTransport)>,
}

impl std::fmt::Debug for ChallengeGrants {
    /// The secret NAMES and whether a transport is present. Never a value, and never the
    /// transport itself, which is a closure with nothing printable.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeGrants")
            .field("secret_names", &self.secrets.keys().collect::<Vec<_>>())
            .field(
                "fetch_budget",
                &self.fetch.as_ref().map(|(budget, _)| budget),
            )
            .finish()
    }
}

impl ChallengeGrants {
    /// Grant nothing: no secrets, no outbound access.
    ///
    /// The deny-by-default starting point, and what a draft run uses.
    #[must_use]
    pub fn none() -> Self {
        Self {
            secrets: std::collections::BTreeMap::new(),
            fetch: None,
        }
    }
}

/// Build a store for ONE invocation, with this call's own fuel and deadline.
///
/// Private and shared by all three entry points, so none of them can accidentally skip a bound.
/// A missing `set_fuel` here would be invisible in a passing test suite: the guest would simply
/// run, and only a fuel bomb would notice.
fn store_for(
    engine: &HookEngine,
    limits: &Limits,
    grants: ChallengeGrants,
) -> Result<Store<Sandbox>, HookError> {
    let sandbox = Sandbox::new(limits).with_secrets(grants.secrets);
    let sandbox = match grants.fetch {
        Some((budget, transport)) => sandbox.with_fetch(budget, transport),
        None => sandbox,
    };
    let mut store = Store::new(engine.inner(), sandbox);
    store.limiter(|s: &mut Sandbox| s.limits());
    store.set_fuel(limits.fuel).map_err(HookError::from_call)?;
    store.set_epoch_deadline(limits.epoch_deadline);
    Ok(store)
}

fn to_wit_context(ctx: &ChallengeContext) -> wit::Context {
    wit::Context {
        payload_version: ctx.payload_version,
        subject: ctx.subject.clone(),
        client_id: ctx.client_id.clone(),
        round: ctx.round,
        previous_passed: ctx.previous_passed,
    }
}

impl LoadedHook {
    /// Ask the component what happens next for this factor (issue #114 criterion 6).
    ///
    /// # This is SYNCHRONOUS and must not be called from an async runtime worker thread
    ///
    /// The same constraint [`LoadedHook::customize`] documents, for the same reason: the sandbox
    /// links wasmtime-wasi's SYNC bindings, which panic when entered from a tokio worker. Call
    /// it from `spawn_blocking`.
    ///
    /// # Errors
    ///
    /// [`HookError`] when the component traps, exhausts fuel, hits the deadline, or fails to
    /// instantiate. A component that DECLINES deliberately returns
    /// [`ChallengeDecision::Fail`], which is not an error: a factor refusing a login is a
    /// decision, and it must not be confused with the component being broken.
    pub fn define_challenge(
        &self,
        engine: &HookEngine,
        limits: &Limits,
        ctx: &ChallengeContext,
        grants: ChallengeGrants,
    ) -> Result<ChallengeDecision, HookError> {
        let mut store = store_for(engine, limits, grants)?;
        let instance = self
            .pre()
            .instantiate(&mut store)
            .map_err(HookError::from_instantiate)?;
        let hook =
            CustomChallengeHook::new(&mut store, &instance).map_err(HookError::from_instantiate)?;
        let returned = hook
            .ironauth_hooks_custom_challenge()
            .call_define(&mut store, &to_wit_context(ctx))
            .map_err(HookError::from_call)?;
        match returned {
            Ok(wit::Decision::Challenge) => Ok(ChallengeDecision::Challenge),
            Ok(wit::Decision::Succeed) => Ok(ChallengeDecision::Succeed),
            Ok(wit::Decision::Fail(reason)) => Ok(ChallengeDecision::Fail(reason)),
            Err(reason) => Err(HookError::Declined(reason)),
        }
    }

    /// Ask the component to build the challenge to render.
    ///
    /// # Errors
    ///
    /// As [`Self::define_challenge`].
    pub fn create_challenge(
        &self,
        engine: &HookEngine,
        limits: &Limits,
        ctx: &ChallengeContext,
        grants: ChallengeGrants,
    ) -> Result<ChallengeSpec, HookError> {
        let mut store = store_for(engine, limits, grants)?;
        let instance = self
            .pre()
            .instantiate(&mut store)
            .map_err(HookError::from_instantiate)?;
        let hook =
            CustomChallengeHook::new(&mut store, &instance).map_err(HookError::from_instantiate)?;
        let returned = hook
            .ironauth_hooks_custom_challenge()
            .call_create(&mut store, &to_wit_context(ctx))
            .map_err(HookError::from_call)?;
        match returned {
            Ok(spec) => Ok(ChallengeSpec {
                prompt: spec.prompt,
                fields: spec
                    .fields
                    .into_iter()
                    .map(|field| ChallengeField {
                        name: field.name,
                        label: field.label,
                        secret: field.secret,
                    })
                    .collect(),
                private_params: spec.private_params,
                public_params: spec.public_params,
            }),
            Err(reason) => Err(HookError::Declined(reason)),
        }
    }

    /// Ask the component whether the answer was right.
    ///
    /// `private_params` is what THIS round's [`Self::create_challenge`] produced. Handing back a
    /// different round's is how a replay would succeed, so the caller owns keeping them together.
    ///
    /// # Errors
    ///
    /// As [`Self::define_challenge`]. A WRONG ANSWER IS `Ok(false)`, not an error: the error
    /// case is the component failing to decide at all, which gets the per-hook failure policy,
    /// while a wrong answer is a normal outcome the factor's own `define` then rules on.
    pub fn verify_challenge(
        &self,
        engine: &HookEngine,
        limits: &Limits,
        ctx: &ChallengeContext,
        private_params: &str,
        answers: &[ChallengeAnswer],
        grants: ChallengeGrants,
    ) -> Result<bool, HookError> {
        let mut store = store_for(engine, limits, grants)?;
        let instance = self
            .pre()
            .instantiate(&mut store)
            .map_err(HookError::from_instantiate)?;
        let hook =
            CustomChallengeHook::new(&mut store, &instance).map_err(HookError::from_instantiate)?;
        let wit_answers: Vec<wit::Answer> = answers
            .iter()
            .map(|answer| wit::Answer {
                name: answer.name.clone(),
                value: answer.value.clone(),
            })
            .collect();
        let returned = hook
            .ironauth_hooks_custom_challenge()
            .call_verify(
                &mut store,
                &to_wit_context(ctx),
                private_params,
                &wit_answers,
            )
            .map_err(HookError::from_call)?;
        returned.map_err(HookError::Declined)
    }
}
