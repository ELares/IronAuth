// SPDX-License-Identifier: MIT OR Apache-2.0

//! Progressive profiling on a later login (issue #87, PR 3): the client form's LATER-LOGIN
//! signup fields collected on a SUBSEQUENT login as a HELD login step, injected where a
//! successful primary (plus any second factor) login would otherwise mint the session.
//!
//! Like the MFA challenge/enrollment states, this is a held step on the LOGIN plan: the driver
//! transitions into [`FlowStateTag::ProgressiveProfiling`](super::model::FlowStateTag::ProgressiveProfiling)
//! WITHOUT minting or consuming the flow, carrying the authenticated subject and the honest
//! primary (plus second factor) method tokens on the persisted state, and mints once, at the
//! profiling completion, with the SAME [`AuthenticationEvent::from_methods`](crate::authn::AuthenticationEvent)
//! amr the login already earned. Collection reuses the PR 2 [`signup_fields`] builders and the
//! trait-authoritative [`signup_fields::validate_signup_submission`].
//!
//! ## The one new behavior: PROMPT-ON-NEXT-LOGIN-NEVER-BLOCK
//!
//! A missing REQUIRED later-login field is PROMPTED but never blocks the login: the step is
//! always SKIPPABLE, so the user can always proceed to the mint. That relaxation is a ONE-flag
//! change: [`plan`] clones each missing required later-login field with `required = false` into
//! the [`ProfilingPlan::relaxed_config`]. The SAME `required` flag feeds BOTH the node builder
//! (the rendered `required` attribute) AND the validator (the required check), so the relaxed
//! copy renders non-blocking AND makes a BLANK submit a SKIP (the value coerces to none and,
//! with `required = false`, is not a failure and is not collected) rather than a REQUIRED
//! failure. A NON-EMPTY value still validates TRAIT AUTHORITATIVELY, so an invalid non-empty
//! value re-prompts (the escape hatch is to clear the field and skip). No PR 2 signature
//! changes: the trigger picks fields on the ORIGINAL `required`; the relaxed copy is only ever
//! used for the render and the validate.
//!
//! ## Persistence: merge, never delete
//!
//! A collected value is DEEP-MERGED into the identity's existing trait document and the WHOLE
//! document is written through [`ActingUserRepo::set_traits`](ironauth_store::ActingUserRepo::set_traits)
//! (which re-validates against the active schema, seals at rest, and audits, in one
//! transaction). The merge only ever ADDS or OVERWRITES the collected pointers, so removing a
//! field from the form NEVER deletes an already-collected trait. A pre-existing document that
//! no longer validates against the now-active schema cannot be rewritten here; rather than trap
//! the user out of a genuine login, the mint proceeds WITHOUT persisting (the step is
//! skippable, so a failed profile update must never block the login).

use serde_json::{Map, Value};

use ironauth_store::{
    CorrelationId, FlowRecord, Scope, SignupFormConfig, SignupFormField, SignupStep, StoreError,
    TraitSchema, UserId,
};

use super::message::{self, Message};
use super::model::{InputType, Node, NodeAttributes, NodeGroup, Transport};
use super::signup_fields::{self, SignupValidation};
use super::{FlowError, Submission};
use crate::interaction;
use crate::state::OidcState;

/// The live plan for a progressive profiling step (issue #87): the missing required later-login
/// fields RELAXED to non-required (so the step is skippable) and the compiled active trait schema
/// to validate against. The active schema version is NOT carried: the persist re-derives and
/// re-stamps the active version itself, so there is nothing here for a caller to stamp.
pub(super) struct ProfilingPlan {
    /// The missing required later-login fields, each cloned with `required = false` so the step
    /// renders non-blocking and a blank submit skips rather than fails.
    relaxed_config: SignupFormConfig,
    /// The compiled active trait schema (the trait-authoritative validation source).
    schema: TraitSchema,
}

/// The outcome of one progressive profiling transition (issue #87).
pub(super) enum ProfilingStep {
    /// Stay on the profiling state and re-render (a non-empty value failed trait-authoritative
    /// validation). The nodes already carry their node-level errors and the flow stays OPEN
    /// (never consumed), so a re-render is never a completion oracle.
    Render {
        /// The nodes to render (already carrying their node-level messages).
        nodes: Vec<Node>,
        /// The flow-level messages.
        messages: Vec<Message>,
    },
    /// The step is done: either a valid value was collected and persisted, or the step was
    /// SKIPPED (an all-empty submit), or there is nothing left to collect. The driver consumes
    /// the single-use latch and mints the session with the honest amr the login already earned.
    Complete,
}

/// Plan the progressive profiling step for a subsequent login (issue #87): load the LIVE active
/// signup form and trait schema for the flow's client, read the subject's existing traits, and
/// pick the REQUIRED later-login fields whose value is still missing. Returns [`None`] when the
/// flow has no client form, there is no active schema, a read faults, or every required
/// later-login field is already filled (so a login with nothing to collect mints directly with
/// no profiling state). The picked fields are RELAXED to non-required in the returned plan (see
/// the module docs), which is the ONE change that makes the step skippable.
pub(super) async fn plan(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    return_to: Option<&str>,
) -> Option<ProfilingPlan> {
    let (config, schema, _version) =
        signup_fields::load_active_signup_form(state, scope, return_to).await?;
    // The subject's existing trait document (an absent document is an empty object: every
    // later-login field is then still missing). A read fault degrades to collecting nothing (a
    // form is a pure additive collection, never a hard block on the login).
    let existing = match state.store().scoped(scope).users().traits(subject).await {
        Ok(Some((_, doc))) => doc,
        Ok(None) => Value::Object(Map::new()),
        Err(_) => return None,
    };
    // Trigger on the ORIGINAL `required` flag; clone each missing field with `required = false`
    // so the render and the validate treat the step as skippable.
    let missing: Vec<SignupFormField> = config
        .fields
        .iter()
        .filter(|field| field.step == SignupStep::LaterLogin && field.required)
        .filter(|field| value_missing_at(&existing, &field.trait_pointer))
        .map(|field| SignupFormField {
            required: false,
            ..field.clone()
        })
        .collect();
    if missing.is_empty() {
        return None;
    }
    Some(ProfilingPlan {
        relaxed_config: SignupFormConfig { fields: missing },
        schema,
    })
}

/// Whether the existing trait document has NO value at `pointer` (an absent pointer or an
/// explicit null both count as missing, so a cleared trait re-prompts).
fn value_missing_at(existing: &Value, pointer: &str) -> bool {
    matches!(existing.pointer(pointer), None | Some(Value::Null))
}

/// Build the profiling nodes for the driver's transition INTO the profiling state (issue #87):
/// the leading prompt copy, the relaxed later-login field inputs, the submit control, and (on
/// the browser transport) the hidden `flow` node.
#[must_use]
pub(super) fn start_nodes(transport: Transport, flow_id: &str, plan: &ProfilingPlan) -> Vec<Node> {
    profiling_nodes(transport, flow_id, plan, &[])
}

/// Build the profiling nodes with per-field validation messages attached (issue #87): identical
/// to [`start_nodes`], but each field whose pointer appears in `failures` also carries the
/// generic error message on its node, exactly as the registration path attaches signup field
/// errors, so the same failure attaches to the SAME node on both transports.
fn profiling_nodes(
    transport: Transport,
    flow_id: &str,
    plan: &ProfilingPlan,
    failures: &[signup_fields::FieldFailure],
) -> Vec<Node> {
    let mut nodes = Vec::new();
    // The leading prompt copy (informational): the fields can be completed now or skipped.
    nodes.push(Node {
        group: NodeGroup::Default,
        attributes: NodeAttributes::Text {
            message: Message::of(message::PROGRESSIVE_PROFILING_PROMPT),
        },
        label: None,
        messages: Vec::new(),
        sequence: 0,
    });
    // The relaxed later-login field inputs (Profile group, rank 80, so they render after the
    // prompt and before the submit regardless of append order).
    nodes.extend(signup_fields::signup_field_nodes_with_messages(
        &plan.relaxed_config,
        &plan.schema,
        SignupStep::LaterLogin,
        failures,
    ));
    // The submit control (Submit group, rank 90): a skip (an empty submit) still mints.
    nodes.push(Node::input(
        NodeGroup::Submit,
        0,
        NodeAttributes::Input {
            name: "method".to_owned(),
            input_type: InputType::Submit,
            value: Some("profile".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::PROGRESSIVE_PROFILING_SUBMIT_LABEL)),
    ));
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
    nodes
}

/// Advance the progressive profiling step one transition (issue #87): recompute the plan LIVE
/// (a management write or a concurrent profile update may have changed which required
/// later-login fields are still missing), validate the submission TRAIT AUTHORITATIVELY against
/// the relaxed config, and either re-render a non-empty invalid value, or complete (a skip, a
/// valid collection, or nothing left to collect). A valid non-empty document is deep-merged
/// into the existing traits and persisted; the driver mints on [`ProfilingStep::Complete`].
pub(super) async fn advance(
    state: &OidcState,
    scope: Scope,
    record: &FlowRecord,
    subject: &UserId,
    submission: &Submission,
) -> Result<ProfilingStep, FlowError> {
    let transport = transport_of(record);
    let flow_id = record.id.as_str();
    // Recompute the plan against the LIVE form and the subject's current traits. When nothing
    // is left to collect (the form changed, or the fields were filled concurrently), mint
    // without persisting anything.
    let Some(plan) = plan(state, scope, subject, record.return_to.as_deref()).await else {
        return Ok(ProfilingStep::Complete);
    };

    let document = match signup_fields::validate_signup_submission(
        &plan.relaxed_config,
        &plan.schema,
        SignupStep::LaterLogin,
        &submission.node_values,
    ) {
        // A non-empty value failed trait-authoritative validation: re-render with the field
        // error, flow OPEN (the escape hatch is to clear the field and skip).
        SignupValidation::Invalid(failures) => {
            return Ok(ProfilingStep::Render {
                nodes: profiling_nodes(transport, flow_id, &plan, &failures),
                messages: Vec::new(),
            });
        }
        SignupValidation::Valid(document) => document,
    };

    // An all-empty (skipped) submission collects nothing: mint, persist nothing.
    let Some(collected) = document.as_object().filter(|map| !map.is_empty()) else {
        return Ok(ProfilingStep::Complete);
    };

    // Deep-merge the collected fields into the subject's existing traits and persist the WHOLE
    // document. Removing a field from the form never deletes an existing trait: the merge only
    // ever adds or overwrites the collected pointers.
    let mut merged = match state.store().scoped(scope).users().traits(subject).await {
        Ok(Some((_, existing))) => existing,
        Ok(None) => Value::Object(Map::new()),
        Err(_) => return Err(FlowError::Store),
    };
    deep_merge(&mut merged, Value::Object(collected.clone()));
    let Ok(traits_json) = serde_json::to_string(&merged) else {
        return Err(FlowError::Store);
    };
    let actor = interaction::user_actor(subject);
    let write = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .set_traits(state.env(), subject, &traits_json)
        .await;
    match write {
        Ok(_) => Ok(ProfilingStep::Complete),
        // Never-block: a PRE-EXISTING document that violates the now-active schema (or a missing
        // active schema, a race against the plan) cannot be rewritten here. Mint WITHOUT
        // persisting rather than trap a genuine login behind a skippable profile update.
        Err(StoreError::TraitsInvalid(_) | StoreError::NoActiveTraitSchema) => {
            Ok(ProfilingStep::Complete)
        }
        // A database or encryption fault is the neutral store error (the flow is NOT consumed, so
        // a resubmit retries), never a 500 to the client.
        Err(_) => Err(FlowError::Store),
    }
}

/// Deep-merge `overlay` into `base` (issue #87): object values merge recursively key-by-key; a
/// scalar or array value (and an object overlaid on a non-object) overwrites. The collected
/// document arrives already shaped at its RFC 6901 pointers, so nested profile fields merge into
/// the matching nested objects without disturbing sibling keys.
fn deep_merge(base: &mut Value, overlay: Value) {
    match overlay {
        Value::Object(overlay_map) => {
            if let Value::Object(base_map) = base {
                for (key, value) in overlay_map {
                    match base_map.get_mut(&key) {
                        Some(slot) => deep_merge(slot, value),
                        None => {
                            base_map.insert(key, value);
                        }
                    }
                }
            } else {
                *base = Value::Object(overlay_map);
            }
        }
        other => *base = other,
    }
}

/// The transport a loaded flow row was created on.
fn transport_of(record: &FlowRecord) -> Transport {
    if record.transport == Transport::Api.as_str() {
        Transport::Api
    } else {
        Transport::Browser
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn schema() -> TraitSchema {
        TraitSchema::compile(
            &json!({
                "type": "object",
                "properties": {
                    "email": {"type": "string", "x-ironauth": {"verification": "email"}},
                    "nickname": {"type": "string", "minLength": 3, "maxLength": 20},
                    "age": {"type": "integer", "minimum": 0, "maximum": 130},
                    "address": {
                        "type": "object",
                        "properties": {"zip": {"type": "string", "maxLength": 10}}
                    }
                }
            })
            .to_string(),
        )
        .expect("schema compiles")
    }

    fn field(pointer: &str, required: bool, step: SignupStep) -> SignupFormField {
        SignupFormField {
            trait_pointer: pointer.to_owned(),
            required,
            order: 0,
            step,
            rules: json!({}),
            label_message_id: message::SIGNUP_FIELD_LABEL.0,
        }
    }

    // The pure trigger and relaxation core, exercised WITHOUT a store: `compute_plan` is the
    // same field-picking + relaxation `plan` runs after the (async) form and traits reads.
    fn compute_plan(config: &SignupFormConfig, existing: &Value) -> Option<Vec<SignupFormField>> {
        let missing: Vec<SignupFormField> = config
            .fields
            .iter()
            .filter(|field| field.step == SignupStep::LaterLogin && field.required)
            .filter(|field| value_missing_at(existing, &field.trait_pointer))
            .map(|field| SignupFormField {
                required: false,
                ..field.clone()
            })
            .collect();
        (!missing.is_empty()).then_some(missing)
    }

    #[test]
    fn a_missing_required_later_login_field_triggers_and_is_relaxed() {
        let config = SignupFormConfig {
            fields: vec![field("/nickname", true, SignupStep::LaterLogin)],
        };
        let picked = compute_plan(&config, &json!({})).expect("a missing field triggers");
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].trait_pointer, "/nickname");
        // THE CRUX: the picked copy is relaxed to non-required.
        assert!(
            !picked[0].required,
            "the picked field is relaxed to non-required"
        );
    }

    #[test]
    fn an_already_filled_field_does_not_trigger() {
        let config = SignupFormConfig {
            fields: vec![field("/nickname", true, SignupStep::LaterLogin)],
        };
        assert!(
            compute_plan(&config, &json!({"nickname": "zeke"})).is_none(),
            "a filled required field collects nothing"
        );
        // An explicit null still counts as missing (a cleared trait re-prompts).
        assert!(
            compute_plan(&config, &json!({"nickname": null})).is_some(),
            "an explicit null re-prompts"
        );
    }

    #[test]
    fn an_optional_or_signup_step_field_does_not_trigger() {
        // An OPTIONAL later-login field does not trigger (only required fields prompt).
        let optional = SignupFormConfig {
            fields: vec![field("/nickname", false, SignupStep::LaterLogin)],
        };
        assert!(compute_plan(&optional, &json!({})).is_none());
        // A SIGNUP-step field is not a later-login field (it is collected at registration).
        let signup = SignupFormConfig {
            fields: vec![field("/nickname", true, SignupStep::Signup)],
        };
        assert!(compute_plan(&signup, &json!({})).is_none());
    }

    #[test]
    fn a_relaxed_blank_submit_skips_and_a_valid_value_is_collected() {
        // The relaxation feeds the validator: with `required = false`, a BLANK submit is a SKIP
        // (no failure, nothing collected), a VALID value is collected, and a NON-EMPTY invalid
        // value is an Invalid re-prompt.
        let relaxed = SignupFormConfig {
            fields: compute_plan(
                &SignupFormConfig {
                    fields: vec![field("/nickname", true, SignupStep::LaterLogin)],
                },
                &json!({}),
            )
            .expect("triggers"),
        };

        // Blank submit: skipped (Valid with an empty document).
        let mut blank = BTreeMap::new();
        blank.insert("nickname".to_owned(), json!(""));
        assert_eq!(
            signup_fields::validate_signup_submission(
                &relaxed,
                &schema(),
                SignupStep::LaterLogin,
                &blank
            ),
            SignupValidation::Valid(json!({})),
            "a blank relaxed field is a skip, not a required failure"
        );

        // A non-empty invalid value (below the trait minLength 3) still re-prompts.
        let mut short = BTreeMap::new();
        short.insert("nickname".to_owned(), json!("ab"));
        assert!(
            matches!(
                signup_fields::validate_signup_submission(
                    &relaxed,
                    &schema(),
                    SignupStep::LaterLogin,
                    &short
                ),
                SignupValidation::Invalid(_)
            ),
            "a non-empty invalid value re-prompts trait-authoritatively"
        );

        // A valid value is collected into the document.
        let mut ok = BTreeMap::new();
        ok.insert("nickname".to_owned(), json!("zeke"));
        assert_eq!(
            signup_fields::validate_signup_submission(
                &relaxed,
                &schema(),
                SignupStep::LaterLogin,
                &ok
            ),
            SignupValidation::Valid(json!({"nickname": "zeke"}))
        );
    }

    #[test]
    fn deep_merge_preserves_existing_sibling_keys() {
        let mut base = json!({"email": "user@example.test", "address": {"zip": "94107"}});
        deep_merge(
            &mut base,
            json!({"nickname": "zeke", "address": {"city": "SF"}}),
        );
        assert_eq!(
            base,
            json!({
                "email": "user@example.test",
                "nickname": "zeke",
                "address": {"zip": "94107", "city": "SF"}
            }),
            "the merge adds new keys and merges nested objects without dropping siblings"
        );
        // A scalar overlay overwrites.
        deep_merge(&mut base, json!({"nickname": "z"}));
        assert_eq!(base["nickname"], json!("z"));
    }

    #[test]
    fn start_nodes_render_the_relaxed_fields_the_prompt_and_a_skippable_submit() {
        // The rendered node set: the prompt, the relaxed later-login field (required = false, so
        // it renders non-blocking), and the submit control. The browser transport adds a hidden
        // `flow` node; the API transport does not.
        let picked = compute_plan(
            &SignupFormConfig {
                fields: vec![field("/nickname", true, SignupStep::LaterLogin)],
            },
            &json!({}),
        )
        .expect("triggers");
        let plan = ProfilingPlan {
            relaxed_config: SignupFormConfig { fields: picked },
            schema: schema(),
        };
        let names = |nodes: &[Node]| -> Vec<String> {
            nodes
                .iter()
                .map(|node| match &node.attributes {
                    NodeAttributes::Input { name, .. } => name.clone(),
                    NodeAttributes::Text { .. } => "text".to_owned(),
                })
                .collect()
        };
        let browser = start_nodes(Transport::Browser, "flw_x", &plan);
        assert_eq!(names(&browser), vec!["text", "nickname", "method", "flow"]);
        // The relaxed field renders non-blocking.
        let nickname = browser
            .iter()
            .find(|node| {
                matches!(&node.attributes, NodeAttributes::Input { name, .. } if name == "nickname")
            })
            .expect("nickname node");
        match &nickname.attributes {
            NodeAttributes::Input { required, .. } => {
                assert!(!required, "the field is non-blocking");
            }
            NodeAttributes::Text { .. } => panic!("nickname is an input"),
        }
        // The API transport renders the SAME set minus the browser-only hidden flow node.
        let api = start_nodes(Transport::Api, "flw_x", &plan);
        assert_eq!(names(&api), vec!["text", "nickname", "method"]);
    }
}
