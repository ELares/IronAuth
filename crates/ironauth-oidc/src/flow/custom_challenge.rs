// SPDX-License-Identifier: MIT OR Apache-2.0

//! A CUSTOM FACTOR, driven from the flow engine (issue #114 criterion 6).
//!
//! > The custom challenge define/create/verify sample adds a working custom factor without
//! > modifications to the flow engine.
//!
//! This module is what makes the second half of that true. It is the ONE place the engine knows
//! about custom factors, and everything it knows is the triad: ask the component what happens
//! next, render the fields it names, hold its opaque parameters, ask it whether the answer was
//! right. Adding a SECOND custom factor after this is a component and a journey step, with no
//! Rust change anywhere.
//!
//! # What the engine deliberately does not know
//!
//! It never reads `private_params` or `public_params`. It does not know what the challenge asks,
//! how many rounds a factor wants, or what makes an answer correct. A factor that wanted to check
//! a hardware token, a shared word or an upstream's verdict is the same code path here.
//!
//! # Where the round's state lives, and why it is server-side
//!
//! `private_params` and the round counter ride the flow's PERSISTED STATE, which is server-side
//! and never rendered. That is the whole reason the triad can be stateless across its three
//! invocations: the component is a pure function of what it is handed, so two concurrent logins
//! cannot see each other's challenge, and a component that stashed an expected answer in a global
//! would find it gone.
//!
//! It also means a REPLAY has to beat the parameters rather than the component: an answer is
//! checked against the parameters of the round it was issued for, and the flow row holds exactly
//! one round's worth.
//!
//! # The failure policy is fail-closed and is not configurable here
//!
//! A component that traps, exhausts its fuel, hits its deadline, or is not deployed leaves the
//! flow unable to decide whether the user proved anything. The only safe answer is that they did
//! not. A per-factor policy would be a knob whose fail-open setting is a bypass of the factor it
//! configures, which is different from a token hook's fail-open (that shapes claims on a token
//! the login already earned).

use std::collections::BTreeMap;

use ironauth_store::{Scope, Store};

use super::FlowError;
use super::message::{self, Message, MessageContext};
use super::model::{InputType, Node, NodeAttributes, NodeGroup, Transport};

/// What one drive of a custom factor decided.
///
/// Mirrors the component's own `decision` plus the two outcomes only the host can produce: the
/// render, and the refusal it turns a fault into.
pub(super) enum FactorStep {
    /// Render this challenge and hold the flow here.
    Render {
        /// The nodes to render.
        nodes: Vec<Node>,
        /// The opaque parameters `verify` will need, to be persisted server-side.
        private_params: String,
    },
    /// The factor is satisfied; the flow advances.
    Satisfied,
    /// The factor refused, or could not decide. The flow holds on a uniform refusal.
    Refused,
}

/// Load the component a step names, resolve its grants, and run one call of the triad.
///
/// # Errors
///
/// [`FlowError::Store`] on a persistence fault reading the component. Every other failure --
/// a component that is not deployed, does not load, traps, or declines -- is
/// [`FactorStep::Refused`] rather than an error, because those are all "the user did not prove
/// anything" and the flow's answer to that is uniform.
#[cfg(feature = "wasm-hooks")]
pub(super) async fn drive(
    state: &crate::state::OidcState,
    scope: Scope,
    factor: &str,
    transport: Transport,
    flow_id: &str,
    context: ironauth_hooks::ChallengeContext,
    call: Call<'_>,
) -> Result<FactorStep, FlowError> {
    let Some(runtime) = state.hook_engine() else {
        // NO RUNTIME IS A REFUSAL, not a skip. A deployment that compiled without hooks, or
        // booted without installing the runtime, cannot run the factor a journey names -- and
        // treating that as "the factor passed" would turn a build flag into an authentication
        // bypass.
        tracing::warn!(
            target: "ironauth.hooks",
            tenant = %scope.tenant(),
            factor,
            "a journey names a custom factor but this deployment has no hook runtime",
        );
        return Ok(FactorStep::Refused);
    };

    let record = match state
        .store()
        .scoped(scope)
        .challenge_components()
        .get(factor)
        .await
    {
        Ok(Some(record)) => record,
        Ok(None) => {
            // NOT DEPLOYED. The journey validated against its own document, which is why this is
            // reachable at all: a journey is meant to be promotable into an environment its
            // components have not reached yet. That is a configuration error an operator fixes,
            // and until they do the factor refuses.
            tracing::warn!(
                target: "ironauth.hooks",
                tenant = %scope.tenant(),
                factor,
                "a journey names a custom factor that is not deployed in this environment",
            );
            return Ok(FactorStep::Refused);
        }
        Err(_) => return Err(FlowError::Store),
    };

    let secrets = resolve_secrets(state.store(), scope, &record).await;
    // THE ARTIFACT TRAVELS WITH THE RECORD (issue #114 criterion 4). The runtime compares its
    // key against this engine's before deserializing anything, so a row written by another build
    // simply compiles.
    let loaded = match runtime
        .loaded(scope, factor, &record.component, record.aot.clone())
        .await
    {
        Ok(loaded) => loaded,
        Err(error) => {
            tracing::error!(
                target: "ironauth.hooks",
                tenant = %scope.tenant(),
                factor,
                error = %error,
                "a custom factor component could not be loaded",
            );
            return Ok(FactorStep::Refused);
        }
    };

    // THE BUDGET IS PER CALL, matching what the column's comment says: the triad is three
    // separate invocations with three separate sandboxes, so each gets the granted budget and
    // one cannot starve another.
    let fetch = u32::try_from(record.fetch_budget)
        .ok()
        .filter(|budget| *budget > 0)
        .map(|budget| {
            (
                budget,
                crate::token_hook::hook_transport(runtime.fetcher().cloned()),
            )
        });
    let grants = ironauth_hooks::ChallengeGrants { secrets, fetch };

    let engine = std::sync::Arc::clone(runtime.engine());
    let limits = crate::token_hook::limits();
    let call = call.into_owned();
    // SPAWN_BLOCKING, for the reason `token_hook::invoke` documents: the sandbox links
    // wasmtime-wasi's SYNC bindings, which PANIC when entered from a tokio worker.
    let outcome = tokio::task::spawn_blocking(move || match call {
        OwnedCall::Define => loaded
            .define_challenge(&engine, &limits, &context, grants)
            .map(Outcome::Decided),
        OwnedCall::Create => loaded
            .create_challenge(&engine, &limits, &context, grants)
            .map(Outcome::Created),
        OwnedCall::Verify {
            private_params,
            answers,
        } => loaded
            .verify_challenge(
                &engine,
                &limits,
                &context,
                &private_params,
                &answers,
                grants,
            )
            .map(Outcome::Verified),
    })
    .await
    .unwrap_or_else(|join| {
        // A PANIC IN THE BLOCKING POOL is not a hook outcome, and it must not be reported as one.
        Err(ironauth_hooks::HookError::Declined(format!(
            "the factor's worker did not complete: {join}"
        )))
    });

    Ok(interpret(outcome, scope, factor, transport, flow_id))
}

/// Turn one triad call's return into the step the flow takes.
///
/// Split out of [`drive`] so that function reads as what it is -- resolve, grant, load, invoke --
/// rather than as those four steps plus a match on every way a component can answer. Every arm
/// here that reaches [`FactorStep::Refused`] logs its own reason first, because those are very
/// different facts for an operator and must be one fact for whoever is at the keyboard.
#[cfg(feature = "wasm-hooks")]
fn interpret(
    outcome: Result<Outcome, ironauth_hooks::HookError>,
    scope: Scope,
    factor: &str,
    transport: Transport,
    flow_id: &str,
) -> FactorStep {
    match outcome {
        Ok(Outcome::Decided(decision)) => match decision {
            ironauth_hooks::ChallengeDecision::Succeed => FactorStep::Satisfied,
            ironauth_hooks::ChallengeDecision::Challenge => FactorStep::Render {
                // A `define` that says CHALLENGE names no challenge: the caller runs `create`
                // next. An empty render here would be a blank form, so the caller never uses
                // this arm's nodes -- see `enter_nodes`, which sequences the two calls.
                nodes: Vec::new(),
                private_params: String::new(),
            },
            ironauth_hooks::ChallengeDecision::Fail(reason) => {
                // THE REASON IS FOR THE OPERATOR, never for the browser. A component's own words
                // about why it refused would be an oracle if rendered.
                tracing::info!(
                    target: "ironauth.hooks",
                    tenant = %scope.tenant(),
                    factor,
                    reason,
                    "a custom factor refused a login",
                );
                FactorStep::Refused
            }
        },
        Ok(Outcome::Created(spec)) => FactorStep::Render {
            nodes: challenge_nodes(transport, flow_id, &spec, false),
            private_params: spec.private_params,
        },
        Ok(Outcome::Verified(passed)) => {
            if passed {
                FactorStep::Satisfied
            } else {
                FactorStep::Refused
            }
        }
        Err(error) => {
            tracing::warn!(
                target: "ironauth.hooks",
                tenant = %scope.tenant(),
                factor,
                error = %error,
                "a custom factor did not complete; failing closed",
            );
            FactorStep::Refused
        }
    }
}

/// Which call of the triad to make, borrowing the caller's answers.
pub(super) enum Call<'a> {
    /// Ask what happens next.
    Define,
    /// Build the challenge.
    Create,
    /// Check an answer against the parameters this round was issued with.
    Verify {
        /// The parameters `create` produced for THIS round.
        private_params: &'a str,
        /// The answers the submission carried.
        answers: &'a [ironauth_hooks::ChallengeAnswer],
    },
}

/// The same call, owned, so it can cross into `spawn_blocking`.
enum OwnedCall {
    Define,
    Create,
    Verify {
        private_params: String,
        answers: Vec<ironauth_hooks::ChallengeAnswer>,
    },
}

impl Call<'_> {
    fn into_owned(self) -> OwnedCall {
        match self {
            Call::Define => OwnedCall::Define,
            Call::Create => OwnedCall::Create,
            Call::Verify {
                private_params,
                answers,
            } => OwnedCall::Verify {
                private_params: private_params.to_owned(),
                answers: answers.to_vec(),
            },
        }
    }
}

/// What one triad call returned.
enum Outcome {
    Decided(ironauth_hooks::ChallengeDecision),
    Created(ironauth_hooks::ChallengeSpec),
    Verified(bool),
}

/// Resolve the VALUES of the secrets a component was granted, just before it runs.
///
/// The same two-step shape `token_hook::resolve_secrets` uses, and for the same reasons: the
/// GRANTS say which names, the environment secret store holds the values, and a value that is not
/// valid UTF-8 is SKIPPED rather than lossily converted -- a key mangled by replacement
/// characters is worse than an absent one, because the component would use it.
#[cfg(feature = "wasm-hooks")]
async fn resolve_secrets(
    store: &Store,
    scope: Scope,
    record: &ironauth_store::ChallengeComponentRecord,
) -> BTreeMap<String, String> {
    let mut resolved = BTreeMap::new();
    if record.granted_secrets.is_empty() {
        return resolved;
    }
    let scoped = store.scoped(scope);
    for name in &record.granted_secrets {
        match scoped
            .environment_secrets()
            .open_value_under_platform_key_at_uniform_cost(name)
            .await
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
        {
            Some(value) => {
                resolved.insert(name.clone(), value);
            }
            None => {
                tracing::warn!(
                    target: "ironauth.hooks",
                    tenant = %scope.tenant(),
                    factor = %record.name,
                    secret = %name,
                    "a granted secret could not be read; the factor sees it as absent",
                );
            }
        }
    }
    resolved
}

/// The nodes for one round of a custom factor's challenge.
///
/// EVERY FIELD THE COMPONENT NAMED, in the order it named them, in one group. The engine does not
/// interpret them: a component asking for a word, a code and a checkbox gets three inputs.
///
/// THE GROUP IS `Default`, not a per-factor one. Node groups are a CLOSED vocabulary the client
/// renders against, so a custom factor cannot mint one -- and putting a factor's fields in an
/// existing method's group (`Totp`, say) would tell a client they are that method's, which they
/// are not.
#[cfg(feature = "wasm-hooks")]
fn challenge_nodes(
    transport: Transport,
    flow_id: &str,
    spec: &ironauth_hooks::ChallengeSpec,
    incorrect: bool,
) -> Vec<Node> {
    let mut nodes = Vec::new();
    nodes.push(Node {
        group: NodeGroup::Default,
        attributes: NodeAttributes::Text {
            message: Message::with_context(
                message::CUSTOM_FACTOR_PROMPT,
                MessageContext::one("prompt", &spec.prompt),
            ),
        },
        label: None,
        messages: Vec::new(),
        sequence: 0,
    });
    for (index, field) in spec.fields.iter().enumerate() {
        // THE SEQUENCE PRESERVES THE COMPONENT'S ORDER. Node order is a total function of
        // (group rank, sequence), so without this every field would tie at zero and the rendered
        // order would depend on a sort that was never asked to be stable.
        let sequence = u16::try_from(index + 1).unwrap_or(u16::MAX);
        let mut node = Node::input(
            NodeGroup::Default,
            sequence,
            NodeAttributes::Input {
                name: field.name.clone(),
                // MASKED WHEN THE COMPONENT SAYS SO. It is the only party that knows whether what
                // it is asking for is a secret.
                input_type: if field.secret {
                    InputType::Password
                } else {
                    InputType::Text
                },
                value: None,
                required: true,
                // NO AUTOCOMPLETE HINT. The browser vocabulary describes known credential kinds,
                // and a custom factor is by construction not one of them; claiming `one-time-code`
                // for an arbitrary field would make a password manager offer the wrong thing.
                autocomplete: None,
                disabled: false,
                constraints: None,
            },
            Some(Message::with_context(
                message::CUSTOM_FACTOR_FIELD_LABEL,
                MessageContext::one("label", &field.label),
            )),
        );
        if incorrect && index == 0 {
            node.messages
                .push(Message::of(message::CUSTOM_FACTOR_INCORRECT));
        }
        nodes.push(node);
    }
    nodes.push(Node::input(
        NodeGroup::Submit,
        0,
        NodeAttributes::Input {
            name: "method".to_owned(),
            input_type: InputType::Submit,
            value: Some("custom_factor".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::CUSTOM_FACTOR_SUBMIT_LABEL)),
    ));
    push_flow_hidden(&mut nodes, transport, flow_id);
    nodes
}

/// The uniform refusal render: a message and no inputs.
///
/// NO FIELDS, deliberately. A refusal that still rendered the challenge would invite the user to
/// keep answering something the factor has already ended, and a factor that ends a login must
/// look the same whether it ended because the answer was wrong, because the component was not
/// deployed, or because it trapped. Those are very different facts for the OPERATOR, which is why
/// each is logged separately, and they must be one fact for whoever is at the keyboard.
///
/// The flow HOLDS here and never mints, which is the `RegistrationAck` posture: a terminal-looking
/// render that discloses nothing while the flow stays open.
pub(super) fn refused_nodes(transport: Transport, flow_id: &str) -> Vec<Node> {
    let mut nodes = vec![Node {
        group: NodeGroup::Default,
        attributes: NodeAttributes::Text {
            message: Message::of(message::CUSTOM_FACTOR_REFUSED),
        },
        label: None,
        messages: Vec::new(),
        sequence: 0,
    }];
    push_flow_hidden(&mut nodes, transport, flow_id);
    nodes
}

/// Push the browser-only hidden `flow` node carrying the flow id back on the form post.
///
/// A per-module copy, as `mfa.rs` and `recovery.rs` each keep: the helper is four lines and
/// private to each renderer, and hoisting it would put a rendering detail in a shared module
/// only so three call sites could share a `Vec::push`.
#[cfg(feature = "wasm-hooks")]
fn push_flow_hidden(nodes: &mut Vec<Node>, transport: Transport, flow_id: &str) {
    if matches!(transport, Transport::Browser) {
        nodes.push(Node::input(
            NodeGroup::Default,
            5,
            NodeAttributes::Input {
                name: "flow".to_owned(),
                input_type: InputType::Hidden,
                value: Some(flow_id.to_owned()),
                required: true,
                autocomplete: None,
                disabled: false,
                constraints: None,
            },
            None,
        ));
    }
}
