// SPDX-License-Identifier: MIT OR Apache-2.0

//! The load-time journey validator (issue #92, PR 1): the one deterministic, pure check that
//! refuses a malformed artifact BEFORE it is stored, imported, or compiled. Every failure is
//! OPERATOR-SAFE and VALUE-FREE, carrying an RFC 6901 JSON Pointer into the artifact document
//! and a stable config identifier (a step id, a kind name, a node-group name, a version),
//! never end-user data, mirroring `SignupFormError` and
//! `ironauth_store::trait_schema::ValidationFailure`.
//!
//! PR 1 validates the artifact STRUCTURE: the step id set, the closed step-kind and node-group
//! vocabularies, transition and subflow reference targets, routing determinism, reachability,
//! and engine compatibility. PR 2 extends the same pass with predicate TYPE checking (see
//! [`crate::eval::typecheck_predicate`]): a guard or decision predicate whose comparison cannot
//! type-unify is a load-time [`JourneyError::PredicateType`], so the evaluator only ever runs
//! type-safe predicates. The compile-to-table executor is PR 4.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::artifact::{DecisionSpec, JOURNEY_ENGINE_VERSION, Journey, Step, StepKind};
use crate::eval::{PredicateTypeError, typecheck_predicate};

/// The node-group vocabulary a journey step may render under (issue #92, fork F6): custom
/// journeys are constrained to the EXISTING node-group set, so the rendered flow contract
/// stays fixed. This mirrors the `NodeGroup` enum's `snake_case` wire forms in the
/// `ironauth-oidc` flow model; PR 1 keeps it as a const (the pure journey crate does not
/// depend on the flow engine), and a later PR that unifies the two engines makes it the one
/// source. Any `node_group` outside this set is refused with
/// [`JourneyError::UnknownNodeGroup`].
pub const NODE_GROUPS: [&str; 12] = [
    "default",
    "password",
    "passkey",
    "totp",
    "email_otp",
    "sms_otp",
    "recovery_code",
    "oidc",
    "profile",
    "client_identity",
    "scope",
    "submit",
];

/// Why a journey artifact is not well formed (issue #92). Every variant is OPERATOR-SAFE and
/// VALUE-FREE: it names an RFC 6901 pointer into the document and a stable config identifier,
/// never end-user data, so a rejection carries no PII.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JourneyError {
    /// A step declares a kind outside the closed built-in vocabulary.
    UnknownStepKind {
        /// The RFC 6901 pointer to the offending `kind`.
        pointer: String,
        /// The unrecognized kind name.
        kind: String,
    },
    /// A step names a node group outside the existing node-group vocabulary
    /// ([`NODE_GROUPS`], fork F6).
    UnknownNodeGroup {
        /// The RFC 6901 pointer to the offending `node_group`.
        pointer: String,
        /// The unrecognized node-group name.
        group: String,
    },
    /// A transition names a step id that no step declares. The `pointer` locates the offending
    /// endpoint (`from` or `to`) and `to` carries the unknown id.
    DanglingTransition {
        /// The RFC 6901 pointer to the offending transition endpoint.
        pointer: String,
        /// The unknown step id the endpoint references.
        to: String,
    },
    /// A step references a subflow id that the journey's `subflows` list does not declare.
    DanglingSubflowRef {
        /// The RFC 6901 pointer to the offending `subflow`.
        pointer: String,
        /// The unknown subflow id.
        subflow: String,
    },
    /// A step is unreachable from the entry step by any transition.
    UnreachableStep {
        /// The RFC 6901 pointer to the unreachable step.
        pointer: String,
        /// The unreachable step id.
        step: String,
    },
    /// A reachable, non-terminal step has no outgoing transition, so the engine routes into it
    /// and can neither advance nor complete (a dead end). Covers the entry step too, with a
    /// proper `/steps/<index>` pointer.
    DeadEndStep {
        /// The RFC 6901 pointer to the dead-end step.
        pointer: String,
        /// The dead-end step id.
        step: String,
    },
    /// A step requires an attachment its kind depends on but does not carry it: a `subflow_call`
    /// with no `subflow` to call, or a `decision` with no `decision` to route on.
    MissingStepAttachment {
        /// The RFC 6901 pointer to the step missing the attachment.
        pointer: String,
        /// The step id.
        step: String,
        /// The kind that requires the missing attachment (`subflow_call` or `decision`).
        kind: String,
    },
    /// A step carries an attachment its kind does not use: a `subflow` on a step that is not a
    /// `subflow_call`, or a `decision` on a step that is not a `decision`.
    UnexpectedStepAttachment {
        /// The RFC 6901 pointer to the offending attachment.
        pointer: String,
        /// The step id.
        step: String,
    },
    /// A terminal step has an outgoing transition, but a terminal completes and never routes
    /// onward. The pointer names the offending transition.
    TerminalHasTransition {
        /// The RFC 6901 pointer to the offending transition.
        pointer: String,
        /// The terminal step id the transition leaves.
        step: String,
    },
    /// The artifact declares an engine version newer than this build supports.
    EngineIncompatible {
        /// The RFC 6901 pointer to `engine_version`.
        pointer: String,
        /// The version the artifact declares.
        declared: u32,
        /// The newest version this build supports ([`JOURNEY_ENGINE_VERSION`]).
        supported: u32,
    },
    /// Two or more UNGUARDED transitions leave the same step, so routing is ambiguous.
    NonDeterministicTransition {
        /// The RFC 6901 pointer to the transition that makes routing ambiguous.
        pointer: String,
    },
    /// Two steps declare the same id, so a reference cannot resolve unambiguously.
    DuplicateStepId {
        /// The RFC 6901 pointer to the duplicate step's `id`.
        pointer: String,
        /// The duplicated step id.
        id: String,
    },
    /// The `entry` names a step id that no step declares.
    UnknownEntry {
        /// The RFC 6901 pointer to `entry`.
        pointer: String,
    },
    /// A guard or decision predicate is not type-safe: a comparison whose field source or type
    /// cannot unify, so the evaluator only ever runs type-checked predicates (issue #92, PR 2).
    /// The wrapped [`PredicateTypeError`] carries the precise RFC 6901 pointer into the artifact.
    PredicateType(PredicateTypeError),
}

impl fmt::Display for JourneyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JourneyError::UnknownStepKind { pointer, kind } => {
                write!(f, "unknown step kind {kind} at {pointer}")
            }
            JourneyError::UnknownNodeGroup { pointer, group } => {
                write!(f, "unknown node group {group} at {pointer}")
            }
            JourneyError::DanglingTransition { pointer, to } => {
                write!(f, "transition at {pointer} references unknown step {to}")
            }
            JourneyError::DanglingSubflowRef { pointer, subflow } => {
                write!(f, "step at {pointer} references unknown subflow {subflow}")
            }
            JourneyError::UnreachableStep { pointer, step } => {
                write!(f, "step {step} at {pointer} is unreachable from the entry")
            }
            JourneyError::DeadEndStep { pointer, step } => {
                write!(
                    f,
                    "step {step} at {pointer} is a non-terminal dead end with no outgoing transition"
                )
            }
            JourneyError::MissingStepAttachment {
                pointer,
                step,
                kind,
            } => write!(
                f,
                "step {step} at {pointer} of kind {kind} is missing its required attachment"
            ),
            JourneyError::UnexpectedStepAttachment { pointer, step } => {
                write!(
                    f,
                    "step {step} carries an attachment its kind does not use at {pointer}"
                )
            }
            JourneyError::TerminalHasTransition { pointer, step } => {
                write!(
                    f,
                    "terminal step {step} has an outgoing transition at {pointer}"
                )
            }
            JourneyError::EngineIncompatible {
                pointer,
                declared,
                supported,
            } => write!(
                f,
                "engine version {declared} at {pointer} exceeds the supported version {supported}"
            ),
            JourneyError::NonDeterministicTransition { pointer } => {
                write!(f, "ambiguous unguarded routing at {pointer}")
            }
            JourneyError::DuplicateStepId { pointer, id } => {
                write!(f, "duplicate step id {id} at {pointer}")
            }
            JourneyError::UnknownEntry { pointer } => {
                write!(f, "entry at {pointer} names no declared step")
            }
            JourneyError::PredicateType(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for JourneyError {}

/// Validate a journey artifact at load time (issue #92), returning EVERY structural failure in
/// deterministic document order. An empty result means the artifact is well formed against the
/// PR 1 vocabulary; a later PR extends the same entry point with predicate type unification (PR
/// 2) and the compiled transition table (PR 4).
///
/// The checks, in order, are: engine compatibility; duplicate step ids; per-step unknown kind,
/// unknown node group, dangling subflow reference, and kind-attachment coherence; an unknown
/// entry; dangling transition endpoints; ambiguous unguarded routing; a transition leaving a
/// terminal step; unreachable steps; reachable non-terminal dead ends; and guard and decision
/// predicate type safety (PR 2). Pure and deterministic: it only reads the document.
///
/// # Errors
///
/// A non-empty [`Vec`] of [`JourneyError`], one per structural failure, in document order.
pub fn validate(doc: &Journey) -> Result<(), Vec<JourneyError>> {
    // PR4: LIVENESS (a reachable completion exists and there is no exit-less cycle a journey can
    // never leave) is validated at COMPILE time in PR 4, not here, because judging whether a
    // journey can ever complete needs the executor's completion semantics: a step may complete
    // internally (mint a session) rather than only by reaching a kind=terminal step. PR 1
    // validates topology structure; the compile pass adds liveness. This is a documented
    // deferral, not a lost check.
    let mut errors = Vec::new();

    if doc.engine_version > JOURNEY_ENGINE_VERSION {
        errors.push(JourneyError::EngineIncompatible {
            pointer: "/engine_version".to_owned(),
            declared: doc.engine_version,
            supported: JOURNEY_ENGINE_VERSION,
        });
    }

    let ids = collect_step_ids(doc, &mut errors);
    check_steps(doc, &mut errors);

    let entry_known = ids.contains(doc.entry.as_str());
    if !entry_known {
        errors.push(JourneyError::UnknownEntry {
            pointer: "/entry".to_owned(),
        });
    }

    check_transitions(doc, &ids, &mut errors);
    if entry_known {
        check_reachability(doc, &ids, &mut errors);
    }
    check_predicates(doc, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// The declared step id set, flagging a [`JourneyError::DuplicateStepId`] at each repeat's
/// document position.
fn collect_step_ids<'a>(doc: &'a Journey, errors: &mut Vec<JourneyError>) -> BTreeSet<&'a str> {
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for (index, step) in doc.steps.iter().enumerate() {
        if !ids.insert(step.id.as_str()) {
            errors.push(JourneyError::DuplicateStepId {
                pointer: format!("/steps/{index}/id"),
                id: step.id.clone(),
            });
        }
    }
    ids
}

/// The per-step structural checks: an unknown kind, an unknown node group, a dangling subflow
/// reference, and kind-attachment coherence, in document order.
fn check_steps(doc: &Journey, errors: &mut Vec<JourneyError>) {
    let declared_subflows = declared_subflow_ids(doc);
    for (index, step) in doc.steps.iter().enumerate() {
        if !step.kind.is_known() {
            errors.push(JourneyError::UnknownStepKind {
                pointer: format!("/steps/{index}/kind"),
                kind: step.kind.as_wire().to_owned(),
            });
        }
        // A match guard rather than a nested `if let ... { if ... }`, so no let chain is needed
        // (MSRV 1.85), mirroring the trait-schema validator's structural checks.
        match &step.node_group {
            Some(group) if !NODE_GROUPS.contains(&group.as_str()) => {
                errors.push(JourneyError::UnknownNodeGroup {
                    pointer: format!("/steps/{index}/node_group"),
                    group: group.clone(),
                });
            }
            _ => {}
        }
        match &step.subflow {
            Some(subflow) if !declared_subflows.contains(subflow.as_str()) => {
                errors.push(JourneyError::DanglingSubflowRef {
                    pointer: format!("/steps/{index}/subflow"),
                    subflow: subflow.clone(),
                });
            }
            _ => {}
        }
        check_attachment_coherence(step, index, errors);
    }
}

/// The per-transition structural checks: a dangling endpoint, ambiguous unguarded routing, and a
/// transition leaving a terminal step, in document order.
fn check_transitions(doc: &Journey, ids: &BTreeSet<&str>, errors: &mut Vec<JourneyError>) {
    let terminal_ids = terminal_step_ids(doc);
    // A second (or later) unguarded transition from a step already left by an unguarded one:
    // `insert` returns false once the source has been seen unguarded.
    let mut seen_unguarded: BTreeSet<&str> = BTreeSet::new();
    for (index, transition) in doc.transitions.iter().enumerate() {
        if !ids.contains(transition.from.as_str()) {
            errors.push(JourneyError::DanglingTransition {
                pointer: format!("/transitions/{index}/from"),
                to: transition.from.clone(),
            });
        }
        if !ids.contains(transition.to.as_str()) {
            errors.push(JourneyError::DanglingTransition {
                pointer: format!("/transitions/{index}/to"),
                to: transition.to.clone(),
            });
        }
        if transition.guard.is_none() && !seen_unguarded.insert(transition.from.as_str()) {
            errors.push(JourneyError::NonDeterministicTransition {
                pointer: format!("/transitions/{index}"),
            });
        }
        if terminal_ids.contains(transition.from.as_str()) {
            errors.push(JourneyError::TerminalHasTransition {
                pointer: format!("/transitions/{index}"),
                step: transition.from.clone(),
            });
        }
    }
}

/// The reachability checks (a known entry is required to walk from): an unreachable step, and a
/// reachable non-terminal dead end with no outgoing transition (which covers the entry step,
/// reported with its own `/steps/<index>` pointer).
fn check_reachability(doc: &Journey, ids: &BTreeSet<&str>, errors: &mut Vec<JourneyError>) {
    let reachable = reachable_steps(doc, ids);
    let sources: BTreeSet<&str> = doc
        .transitions
        .iter()
        .map(|transition| transition.from.as_str())
        .collect();
    for (index, step) in doc.steps.iter().enumerate() {
        if !reachable.contains(step.id.as_str()) {
            errors.push(JourneyError::UnreachableStep {
                pointer: format!("/steps/{index}"),
                step: step.id.clone(),
            });
        }
    }
    for (index, step) in doc.steps.iter().enumerate() {
        let dead = reachable.contains(step.id.as_str())
            && !step.kind.is_terminal()
            && !sources.contains(step.id.as_str());
        if dead {
            errors.push(JourneyError::DeadEndStep {
                pointer: format!("/steps/{index}"),
                step: step.id.clone(),
            });
        }
    }
}

/// Type-check every guard and decision predicate in the artifact (issue #92, PR 2), appending a
/// [`JourneyError::PredicateType`] per failure in document order (all transition guards, then all
/// step decisions). A statically-decidable type mismatch (an ordering operator on a boolean
/// signal, a literal that cannot unify with its field, a membership over a mismatched set, a set
/// used in a comparison) is a LOAD-TIME error, so the evaluator only ever runs type-safe
/// predicates. Each error carries the precise RFC 6901 pointer into the predicate.
fn check_predicates(doc: &Journey, errors: &mut Vec<JourneyError>) {
    for (index, transition) in doc.transitions.iter().enumerate() {
        if let Some(guard) = &transition.guard {
            let base = format!("/transitions/{index}/guard");
            collect_predicate_errors(guard, &base, errors);
        }
    }
    for (index, step) in doc.steps.iter().enumerate() {
        if let Some(DecisionSpec::Predicate { predicate }) = &step.decision {
            let base = format!("/steps/{index}/decision/predicate");
            collect_predicate_errors(predicate, &base, errors);
        }
    }
}

/// Type-check one predicate rooted at `base`, wrapping each [`PredicateTypeError`] as a
/// [`JourneyError`].
fn collect_predicate_errors(
    predicate: &crate::artifact::Predicate,
    base: &str,
    errors: &mut Vec<JourneyError>,
) {
    let mut type_errors: Vec<PredicateTypeError> = Vec::new();
    typecheck_predicate(predicate, base, &mut type_errors);
    errors.extend(type_errors.into_iter().map(JourneyError::PredicateType));
}

/// The set of subflow ids the journey declares in its `subflows` list.
fn declared_subflow_ids(doc: &Journey) -> BTreeSet<&str> {
    doc.subflows
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|subflow| subflow.id.as_str())
        .collect()
}

/// The set of step ids reachable from the entry by following transitions whose endpoints both
/// name a declared step. An iterative walk, so a cyclic or deep graph cannot exhaust the stack.
fn reachable_steps<'a>(doc: &'a Journey, ids: &BTreeSet<&'a str>) -> BTreeSet<&'a str> {
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for transition in &doc.transitions {
        if ids.contains(transition.from.as_str()) && ids.contains(transition.to.as_str()) {
            adjacency
                .entry(transition.from.as_str())
                .or_default()
                .push(transition.to.as_str());
        }
    }
    let mut reached: BTreeSet<&str> = BTreeSet::new();
    let mut stack = vec![doc.entry.as_str()];
    while let Some(node) = stack.pop() {
        if !reached.insert(node) {
            continue;
        }
        if let Some(next) = adjacency.get(node) {
            stack.extend(next.iter().copied());
        }
    }
    reached
}

/// The set of step ids whose kind is terminal.
fn terminal_step_ids(doc: &Journey) -> BTreeSet<&str> {
    doc.steps
        .iter()
        .filter(|step| step.kind.is_terminal())
        .map(|step| step.id.as_str())
        .collect()
}

/// Check that a step carries exactly the attachments its kind uses: a `subflow_call` names a
/// subflow to call, a `decision` carries a decision to route on, and neither attachment appears
/// on a kind that does not use it. Only known kinds are checked; an unknown kind is already
/// flagged by [`JourneyError::UnknownStepKind`].
fn check_attachment_coherence(step: &Step, index: usize, errors: &mut Vec<JourneyError>) {
    match &step.kind {
        StepKind::SubflowCall if step.subflow.is_none() => {
            errors.push(JourneyError::MissingStepAttachment {
                pointer: format!("/steps/{index}"),
                step: step.id.clone(),
                kind: "subflow_call".to_owned(),
            });
        }
        StepKind::Decision if step.decision.is_none() => {
            errors.push(JourneyError::MissingStepAttachment {
                pointer: format!("/steps/{index}"),
                step: step.id.clone(),
                kind: "decision".to_owned(),
            });
        }
        _ => {}
    }
    // A stray `subflow` on a step that is not a `subflow_call`.
    if step.subflow.is_some() && !matches!(step.kind, StepKind::SubflowCall) && step.kind.is_known()
    {
        errors.push(JourneyError::UnexpectedStepAttachment {
            pointer: format!("/steps/{index}/subflow"),
            step: step.id.clone(),
        });
    }
    // A stray `decision` on a step that is not a `decision`.
    if step.decision.is_some() && !matches!(step.kind, StepKind::Decision) && step.kind.is_known() {
        errors.push(JourneyError::UnexpectedStepAttachment {
            pointer: format!("/steps/{index}/decision"),
            step: step.id.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{
        CmpOp, DecisionSpec, FieldRef, FieldSource, JOURNEY_SCHEMA_VERSION, Literal, Predicate,
        Step, StepKind, SubflowRef, SubflowSource, Transition,
    };
    use crate::eval::PredicateTypeError;

    fn step(id: &str, kind: StepKind, node_group: Option<&str>) -> Step {
        Step {
            id: id.to_owned(),
            kind,
            node_group: node_group.map(str::to_owned),
            subflow: None,
            decision: None,
            comment: None,
        }
    }

    fn guarded(from: &str, to: &str) -> Transition {
        Transition {
            from: from.to_owned(),
            to: to.to_owned(),
            guard: Some(Predicate::Cmp {
                field: FieldRef {
                    source: FieldSource::Signals,
                    pointer: "/mfa_required".to_owned(),
                },
                op: CmpOp::Eq,
                value: Literal::Bool(true),
            }),
            comment: None,
        }
    }

    fn unguarded(from: &str, to: &str) -> Transition {
        Transition {
            from: from.to_owned(),
            to: to.to_owned(),
            guard: None,
            comment: None,
        }
    }

    /// A realistic identifier-first-with-conditional-MFA journey that validates clean.
    fn valid_journey() -> Journey {
        Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: Some("Identifier plus password, then MFA only when required.".to_owned()),
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("mfa", StepKind::MfaChallenge, Some("totp")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![
                guarded("primary", "mfa"),
                Transition {
                    from: "primary".to_owned(),
                    to: "done".to_owned(),
                    guard: Some(Predicate::Cmp {
                        field: FieldRef {
                            source: FieldSource::Signals,
                            pointer: "/mfa_required".to_owned(),
                        },
                        op: CmpOp::Eq,
                        value: Literal::Bool(false),
                    }),
                    comment: None,
                },
                unguarded("mfa", "done"),
            ],
            subflows: None,
        }
    }

    #[test]
    fn a_realistic_conditional_mfa_journey_validates() {
        assert_eq!(validate(&valid_journey()), Ok(()));
    }

    #[test]
    fn an_unknown_step_kind_is_rejected_with_a_pointer() {
        let mut doc = valid_journey();
        doc.steps[1].kind = StepKind::from_wire("teleport");
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::UnknownStepKind {
                pointer: "/steps/1/kind".to_owned(),
                kind: "teleport".to_owned(),
            }])
        );
    }

    #[test]
    fn an_unknown_node_group_is_rejected_with_a_pointer() {
        let mut doc = valid_journey();
        doc.steps[0].node_group = Some("wizardry".to_owned());
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::UnknownNodeGroup {
                pointer: "/steps/0/node_group".to_owned(),
                group: "wizardry".to_owned(),
            }])
        );
    }

    #[test]
    fn a_dangling_transition_target_is_rejected() {
        let mut doc = valid_journey();
        doc.transitions.push(guarded("mfa", "nowhere"));
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::DanglingTransition {
                pointer: "/transitions/3/to".to_owned(),
                to: "nowhere".to_owned(),
            }])
        );
    }

    #[test]
    fn a_dangling_subflow_reference_is_rejected() {
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                Step {
                    subflow: Some("ghost".to_owned()),
                    ..step("call", StepKind::SubflowCall, None)
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "call"), unguarded("call", "done")],
            subflows: Some(vec![SubflowRef {
                id: "mfa_step_up".to_owned(),
                source: SubflowSource::Builtin {
                    name: "mfa_step_up".to_owned(),
                },
            }]),
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::DanglingSubflowRef {
                pointer: "/steps/1/subflow".to_owned(),
                subflow: "ghost".to_owned(),
            }])
        );
    }

    #[test]
    fn an_unreachable_step_is_rejected() {
        let mut doc = valid_journey();
        doc.steps.push(step("orphan", StepKind::Terminal, None));
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::UnreachableStep {
                pointer: "/steps/3".to_owned(),
                step: "orphan".to_owned(),
            }])
        );
    }

    #[test]
    fn an_entry_with_no_outgoing_transition_is_a_dead_end() {
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![step(
                "primary",
                StepKind::IdentifierPassword,
                Some("password"),
            )],
            transitions: vec![],
            subflows: None,
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::DeadEndStep {
                pointer: "/steps/0".to_owned(),
                step: "primary".to_owned(),
            }])
        );
    }

    #[test]
    fn an_interior_non_terminal_dead_end_is_rejected() {
        // The entry advances into `trap`, but `trap` is non-terminal with no outgoing transition,
        // so the engine can neither advance from it nor complete: a dead end.
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("trap", StepKind::MfaChallenge, Some("totp")),
            ],
            transitions: vec![unguarded("primary", "trap")],
            subflows: None,
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::DeadEndStep {
                pointer: "/steps/1".to_owned(),
                step: "trap".to_owned(),
            }])
        );
    }

    #[test]
    fn a_subflow_call_with_no_subflow_is_rejected() {
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("call", StepKind::SubflowCall, None),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "call"), unguarded("call", "done")],
            subflows: None,
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::MissingStepAttachment {
                pointer: "/steps/1".to_owned(),
                step: "call".to_owned(),
                kind: "subflow_call".to_owned(),
            }])
        );
    }

    #[test]
    fn a_decision_step_with_no_decision_is_rejected() {
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("branch", StepKind::Decision, None),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "branch"), unguarded("branch", "done")],
            subflows: None,
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::MissingStepAttachment {
                pointer: "/steps/1".to_owned(),
                step: "branch".to_owned(),
                kind: "decision".to_owned(),
            }])
        );
    }

    #[test]
    fn a_subflow_attachment_on_a_non_subflow_call_step_is_rejected() {
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                Step {
                    // A stray subflow on an identifier_password step; the subflow id is declared,
                    // so this is the coherence rejection, not a dangling reference.
                    subflow: Some("mfa_step_up".to_owned()),
                    ..step("primary", StepKind::IdentifierPassword, Some("password"))
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "done")],
            subflows: Some(vec![SubflowRef {
                id: "mfa_step_up".to_owned(),
                source: SubflowSource::Builtin {
                    name: "mfa_step_up".to_owned(),
                },
            }]),
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::UnexpectedStepAttachment {
                pointer: "/steps/0/subflow".to_owned(),
                step: "primary".to_owned(),
            }])
        );
    }

    #[test]
    fn a_decision_attachment_on_a_non_decision_step_is_rejected() {
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                Step {
                    decision: Some(DecisionSpec::Predicate {
                        predicate: Predicate::Always,
                    }),
                    ..step("primary", StepKind::IdentifierPassword, Some("password"))
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "done")],
            subflows: None,
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::UnexpectedStepAttachment {
                pointer: "/steps/0/decision".to_owned(),
                step: "primary".to_owned(),
            }])
        );
    }

    #[test]
    fn a_terminal_step_with_an_outgoing_transition_is_rejected() {
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "done"), unguarded("done", "primary")],
            subflows: None,
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::TerminalHasTransition {
                pointer: "/transitions/1".to_owned(),
                step: "done".to_owned(),
            }])
        );
    }

    #[test]
    fn an_engine_version_newer_than_supported_is_rejected() {
        let mut doc = valid_journey();
        doc.engine_version = JOURNEY_ENGINE_VERSION + 1;
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::EngineIncompatible {
                pointer: "/engine_version".to_owned(),
                declared: JOURNEY_ENGINE_VERSION + 1,
                supported: JOURNEY_ENGINE_VERSION,
            }])
        );
    }

    #[test]
    fn two_unguarded_transitions_from_one_step_are_rejected() {
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("a", StepKind::Terminal, None),
                step("b", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "a"), unguarded("primary", "b")],
            subflows: None,
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::NonDeterministicTransition {
                pointer: "/transitions/1".to_owned(),
            }])
        );
    }

    #[test]
    fn a_duplicate_step_id_is_rejected() {
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "a".to_owned(),
            comment: None,
            steps: vec![
                step("a", StepKind::IdentifierPassword, Some("password")),
                step("a", StepKind::IdentifierPassword, Some("password")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("a", "done")],
            subflows: None,
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::DuplicateStepId {
                pointer: "/steps/1/id".to_owned(),
                id: "a".to_owned(),
            }])
        );
    }

    #[test]
    fn an_unknown_entry_is_rejected() {
        let mut doc = valid_journey();
        doc.entry = "ghost".to_owned();
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::UnknownEntry {
                pointer: "/entry".to_owned(),
            }])
        );
    }

    #[test]
    fn a_well_typed_guard_predicate_passes_validation() {
        // The realistic conditional-MFA journey's guards are all well typed (boolean signal
        // equalities), so predicate type checking adds no error.
        assert_eq!(validate(&valid_journey()), Ok(()));
    }

    #[test]
    fn an_ill_typed_guard_predicate_fails_validation_with_a_pointer() {
        // An ordering operator on a boolean signal is a statically-decidable type error at the
        // guard's precise pointer; the journey is otherwise valid.
        let mut doc = valid_journey();
        doc.transitions[0].guard = Some(Predicate::Cmp {
            field: FieldRef {
                source: FieldSource::Signals,
                pointer: "/mfa_required".to_owned(),
            },
            op: CmpOp::Lt,
            value: Literal::Bool(true),
        });
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::PredicateType(
                PredicateTypeError::OrderingUndefined {
                    pointer: "/transitions/0/guard/op".to_owned(),
                }
            )])
        );
    }

    #[test]
    fn an_ill_typed_decision_predicate_fails_validation_with_a_pointer() {
        // A Member over a numeric field (not a string set) is a static mismatch, located at the
        // decision predicate's pointer.
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                Step {
                    decision: Some(DecisionSpec::Predicate {
                        predicate: Predicate::Member {
                            field: FieldRef {
                                source: FieldSource::Risk,
                                pointer: "/score".to_owned(),
                            },
                            set: crate::artifact::MemberSet::Group {
                                name: "staff".to_owned(),
                            },
                        },
                    }),
                    ..step("branch", StepKind::Decision, None)
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "branch"), unguarded("branch", "done")],
            subflows: None,
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::PredicateType(
                PredicateTypeError::MemberSetMismatch {
                    pointer: "/steps/1/decision/predicate/field".to_owned(),
                }
            )])
        );
    }
}
