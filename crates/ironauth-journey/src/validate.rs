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

use crate::artifact::{DecisionSpec, JOURNEY_ENGINE_VERSION, Journey, Step, StepKind, Transition};
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
    /// A CUSTOM-authored artifact declares a BUILT-IN-ONLY step kind (issue #92, PR 8a): one of the
    /// mint-family kinds ([`StepKind::Registration`], [`StepKind::RecoveryStart`],
    /// [`StepKind::RecoveryVerify`]) that CREATE accounts or MINT sessions through fixed built-in
    /// ceremonies. A custom author must not be able to name these (see [`StepKind::is_builtin_only`]),
    /// so [`validate`] refuses one here while [`crate::compile_builtin`] admits them for the embedded
    /// built-in journeys.
    BuiltinOnlyStepKind {
        /// The RFC 6901 pointer to the offending `kind`.
        pointer: String,
        /// The built-in-only kind name a custom artifact may not use.
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
    /// A step whose kind READS an already-established subject ([`StepKind::requires_subject`]) is
    /// reachable from the entry by at least one path that has not first passed a
    /// subject-establishing step ([`StepKind::establishes_subject`]), so the flow would render a
    /// form no submission can satisfy (issue #351). Flagged at LOAD, fail-closed. The check itself
    /// walks the TOP-LEVEL graph and does not descend into `subflow_call` targets (a subflow is
    /// validated as an isolated fragment that cannot know its call-site subject state). This is NOT
    /// a subflow escape hatch: composition (`compose_inner`) INLINES every subflow and re-runs this
    /// check on the flattened graph before a routable table is built (see `compile_inner`), so a
    /// subflow that injects a subject-less subject-requiring step at a subject-less call site is
    /// still caught at compile time. Only a standalone `validate()` (which never yields a routable
    /// table) leaves a subflow interior unwalked.
    SubjectStepNotEstablished {
        /// The RFC 6901 pointer to the subject-requiring step.
        pointer: String,
        /// The subject-requiring step id.
        step: String,
    },
    /// A step requires an attachment its kind depends on but does not carry it: a `subflow_call`
    /// with no `subflow` to call. (A `decision` step's `decision` attachment is OPTIONAL as of issue
    /// #351, so a spec-less decision never raises this.)
    MissingStepAttachment {
        /// The RFC 6901 pointer to the step missing the attachment.
        pointer: String,
        /// The step id.
        step: String,
        /// The kind that requires the missing attachment (`subflow_call`).
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
    /// A [`SubflowSource::Builtin`] reference names a built-in subflow this build does not provide
    /// (issue #92, PR 3).
    UnknownBuiltinSubflow {
        /// The RFC 6901 pointer to the offending subflow reference `source`.
        pointer: String,
        /// The unrecognized built-in subflow name.
        name: String,
    },
    /// A [`SubflowSource::Inline`] reference names an inline subflow definition the artifact's
    /// `subflow_definitions` does not carry (issue #92, PR 3).
    UnknownSubflowDefinition {
        /// The RFC 6901 pointer to the offending subflow reference `source`.
        pointer: String,
        /// The unresolved inline subflow definition id.
        subflow: String,
    },
    /// Two inline subflow definitions declare the same id, or a definition collides with a
    /// built-in subflow name, so a reference cannot resolve unambiguously (issue #92, PR 3).
    DuplicateSubflowDefinition {
        /// The RFC 6901 pointer to the offending definition's `id`.
        pointer: String,
        /// The duplicated subflow definition id.
        id: String,
    },
    /// A subflow references itself directly or transitively, so composition would never terminate
    /// (issue #92, PR 3). Rejected at LOAD, never at flow time.
    SubflowCycle {
        /// The RFC 6901 pointer to the subflow definition that closes the cycle.
        pointer: String,
        /// The subflow definition id that closes the cycle.
        subflow: String,
    },
    /// A subflow declares a [`StepKind::Terminal`] step. A subflow never mints a session; it
    /// returns to its caller, so it declares return `exits`, never a terminal (issue #92, PR 3).
    SubflowTerminalStep {
        /// The RFC 6901 pointer to the offending terminal step.
        pointer: String,
        /// The offending step id.
        step: String,
    },
    /// A subflow declares no return `exits`, so composition has no point to return to the caller
    /// from (issue #92, PR 3).
    SubflowNoExit {
        /// The RFC 6901 pointer to the subflow definition's `exits`.
        pointer: String,
        /// The subflow definition id.
        subflow: String,
    },
    /// A subflow's `exits` list names a step id the subflow does not declare (issue #92, PR 3).
    UnknownSubflowExit {
        /// The RFC 6901 pointer to the offending `exits` entry.
        pointer: String,
        /// The unknown exit step id.
        exit: String,
    },
    /// A subflow exit has an outgoing transition, but an exit is a return leaf: it returns to the
    /// caller, it does not route onward within the subflow (issue #92, PR 3).
    SubflowExitNotLeaf {
        /// The RFC 6901 pointer to the offending transition that leaves the exit.
        pointer: String,
        /// The exit step id the transition leaves.
        exit: String,
    },
    /// A template invocation names a template id this build does not provide (issue #92, PR 3).
    UnknownTemplate {
        /// The RFC 6901 pointer to the offending `template`.
        pointer: String,
        /// The unrecognized template id.
        template: String,
    },
    /// A template invocation omits a required parameter (issue #92, PR 3).
    MissingTemplateParam {
        /// The RFC 6901 pointer to the invocation's `params`.
        pointer: String,
        /// The missing parameter name.
        param: String,
    },
    /// A template invocation supplies a parameter of the wrong type (issue #92, PR 3).
    TemplateParamType {
        /// The RFC 6901 pointer to the offending parameter.
        pointer: String,
        /// The parameter name.
        param: String,
    },
    /// An author-provided step id contains the reserved `::` sequence (issue #92, PR 3). The `::`
    /// sequence is reserved as the composition namespace separator (`<call_id>::<step_id>`), so an
    /// author step id may not use it, otherwise a hand-written id could collide with a namespaced
    /// subflow step and produce a duplicate step id after composition.
    ReservedStepIdSeparator {
        /// The RFC 6901 pointer to the offending step `id`.
        pointer: String,
        /// The offending step id.
        id: String,
    },
    /// Two entries in the `subflows` reference list declare the same alias id, so a
    /// [`StepKind::SubflowCall`] step's reference cannot resolve unambiguously (issue #92, PR 3).
    DuplicateSubflowRef {
        /// The RFC 6901 pointer to the duplicate reference's `id`.
        pointer: String,
        /// The duplicated alias id.
        id: String,
    },
    /// Composing the journey would splice more steps than the composed-size ceiling admits (issue
    /// #92, PR 3). An acyclic fan-out of subflow references can expand exponentially, so the splice
    /// fails LOAD at a generous bound rather than exhausting memory. Rejected during composition,
    /// never at flow time.
    ComposedTooLarge {
        /// The composed step ceiling this build admits.
        limit: usize,
    },
    /// The journey has no completion reachable from the entry (issue #92, PR 4): a journey
    /// completes by routing into a [`StepKind::Terminal`] step, and no such step is reachable (an
    /// exit-less cycle, or a graph that reaches no terminal). This LIVENESS failure is deferred
    /// from load-time structural validation to compile time ([`crate::compile`]), because judging
    /// completion needs the executor's semantics. Refused at compile, never at flow time.
    NoReachableCompletion,
}

impl fmt::Display for JourneyError {
    // One arm per error variant: a flat match is the clearest form and the line count only reflects
    // the number of variants, not any real complexity.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JourneyError::UnknownStepKind { pointer, kind } => {
                write!(f, "unknown step kind {kind} at {pointer}")
            }
            JourneyError::BuiltinOnlyStepKind { pointer, kind } => {
                write!(
                    f,
                    "built-in-only step kind {kind} at {pointer} is not allowed in a custom journey"
                )
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
            JourneyError::SubjectStepNotEstablished { pointer, step } => write!(
                f,
                "step {step} at {pointer} requires an authenticated subject but is reachable from the entry with no preceding subject-establishing step (identifier_password)"
            ),
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
            JourneyError::UnknownBuiltinSubflow { pointer, name } => {
                write!(f, "unknown built-in subflow {name} at {pointer}")
            }
            JourneyError::UnknownSubflowDefinition { pointer, subflow } => {
                write!(
                    f,
                    "reference at {pointer} names no inline subflow definition {subflow}"
                )
            }
            JourneyError::DuplicateSubflowDefinition { pointer, id } => {
                write!(f, "duplicate subflow definition id {id} at {pointer}")
            }
            JourneyError::SubflowCycle { pointer, subflow } => {
                write!(f, "subflow {subflow} at {pointer} references itself")
            }
            JourneyError::SubflowTerminalStep { pointer, step } => {
                write!(
                    f,
                    "subflow step {step} at {pointer} is a terminal, but a subflow returns via its exits"
                )
            }
            JourneyError::SubflowNoExit { pointer, subflow } => {
                write!(f, "subflow {subflow} at {pointer} declares no return exits")
            }
            JourneyError::UnknownSubflowExit { pointer, exit } => {
                write!(f, "exit at {pointer} names no declared step {exit}")
            }
            JourneyError::SubflowExitNotLeaf { pointer, exit } => {
                write!(
                    f,
                    "subflow exit {exit} has an outgoing transition at {pointer}"
                )
            }
            JourneyError::UnknownTemplate { pointer, template } => {
                write!(f, "unknown template {template} at {pointer}")
            }
            JourneyError::MissingTemplateParam { pointer, param } => {
                write!(
                    f,
                    "missing required template parameter {param} at {pointer}"
                )
            }
            JourneyError::TemplateParamType { pointer, param } => {
                write!(
                    f,
                    "template parameter {param} at {pointer} has the wrong type"
                )
            }
            JourneyError::ReservedStepIdSeparator { pointer, id } => {
                write!(
                    f,
                    "step id {id} at {pointer} uses the reserved namespace separator"
                )
            }
            JourneyError::DuplicateSubflowRef { pointer, id } => {
                write!(f, "duplicate subflow reference alias {id} at {pointer}")
            }
            JourneyError::ComposedTooLarge { limit } => {
                write!(f, "composition exceeds the step ceiling of {limit}")
            }
            JourneyError::NoReachableCompletion => {
                write!(f, "no completion is reachable from the entry step")
            }
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
/// terminal step; unreachable steps; reachable non-terminal dead ends; guard and decision
/// predicate type safety (PR 2); and, for PR 3, subflow reference resolution, inline subflow
/// definition well-formedness, and subflow reference acyclicity. Pure and deterministic: it only
/// reads the document.
///
/// # Errors
///
/// A non-empty [`Vec`] of [`JourneyError`], one per structural failure, in document order.
pub fn validate(doc: &Journey) -> Result<(), Vec<JourneyError>> {
    validate_inner(doc, RESERVED_IDS_REJECTED, BUILTIN_ONLY_REJECTED)
}

/// Validate a journey artifact in the EMBEDDED BUILT-IN context (issue #92, PR 8a): identical to
/// [`validate`] except that the BUILT-IN-ONLY mint-family step kinds
/// ([`StepKind::is_builtin_only`]) are ADMITTED. The embedded built-in journeys that converge onto
/// the compiled table (login/mfa/profiling/registration/recovery) declare these kinds; a
/// custom-authored artifact must not, so the public [`validate`] refuses them.
///
/// # Errors
///
/// A non-empty [`Vec`] of [`JourneyError`], one per structural failure, in document order (the same
/// checks [`validate`] runs, minus the built-in-only rejection).
pub fn validate_builtin(doc: &Journey) -> Result<(), Vec<JourneyError>> {
    validate_inner(doc, RESERVED_IDS_REJECTED, BUILTIN_ONLY_ADMITTED)
}

/// Reject an author step id that uses the reserved namespace separator (the public [`validate`]
/// entry point uses this).
pub(crate) const RESERVED_IDS_REJECTED: bool = true;

/// Admit the reserved namespace separator in step ids (the post-composition re-validation uses this,
/// because composition itself mints the only legitimate `::` ids).
pub(crate) const RESERVED_IDS_ADMITTED: bool = false;

/// Reject a BUILT-IN-ONLY step kind (issue #92, PR 8a): the CUSTOM validation context (the public
/// [`validate`]) refuses the mint-family kinds a custom author must not name.
pub(crate) const BUILTIN_ONLY_REJECTED: bool = false;

/// Admit a BUILT-IN-ONLY step kind (issue #92, PR 8a): the EMBEDDED built-in context
/// ([`validate_builtin`] / [`crate::compile_builtin`]) permits the mint-family kinds.
pub(crate) const BUILTIN_ONLY_ADMITTED: bool = true;

/// Validate a journey artifact (issue #92), with `reject_reserved` controlling whether an author
/// step id that uses the reserved `::` namespace separator is refused, and `admit_builtin_only`
/// controlling whether the BUILT-IN-ONLY mint-family step kinds ([`StepKind::is_builtin_only`]) are
/// permitted. The public [`validate`] refuses the reserved separator and the built-in-only kinds;
/// the post-composition re-validation admits the reserved separator (composition mints those ids);
/// [`validate_builtin`] admits the built-in-only kinds.
pub(crate) fn validate_inner(
    doc: &Journey,
    reject_reserved: bool,
    admit_builtin_only: bool,
) -> Result<(), Vec<JourneyError>> {
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

    let ids = collect_step_ids(&doc.steps, "", &mut errors);

    // A journey `subflow_call` step names a subflow ALIAS declared in the `subflows` reference
    // list; a dangling alias is rejected here (the alias-to-source resolution is checked by
    // `crate::subflow::validate_subflows`).
    let declared = declared_subflow_ids(doc);
    for (index, step) in doc.steps.iter().enumerate() {
        let step_ptr = format!("/steps/{index}");
        check_kind_and_node_group(step, &step_ptr, admit_builtin_only, &mut errors);
        if reject_reserved && step.id.contains(crate::subflow::NAMESPACE_SEPARATOR) {
            errors.push(JourneyError::ReservedStepIdSeparator {
                pointer: format!("/steps/{index}/id"),
                id: step.id.clone(),
            });
        }
        match &step.subflow {
            Some(alias) if !declared.contains(alias.as_str()) => {
                errors.push(JourneyError::DanglingSubflowRef {
                    pointer: format!("/steps/{index}/subflow"),
                    subflow: alias.clone(),
                });
            }
            _ => {}
        }
        check_attachment_coherence(step, &step_ptr, &mut errors);
    }

    let entry_known = ids.contains(doc.entry.as_str());
    if !entry_known {
        errors.push(JourneyError::UnknownEntry {
            pointer: "/entry".to_owned(),
        });
    }

    check_transition_endpoints(&ids, &doc.transitions, "", &mut errors);
    // A journey's completion role is played by its `terminal`-kind steps: a transition may not
    // leave one.
    let terminals: BTreeSet<&str> = doc
        .steps
        .iter()
        .filter(|step| step.kind.is_terminal())
        .map(|step| step.id.as_str())
        .collect();
    for (index, transition) in doc.transitions.iter().enumerate() {
        if terminals.contains(transition.from.as_str()) {
            errors.push(JourneyError::TerminalHasTransition {
                pointer: format!("/transitions/{index}"),
                step: transition.from.clone(),
            });
        }
    }
    if entry_known {
        check_reachability_and_dead_ends(
            &doc.entry,
            &doc.steps,
            &doc.transitions,
            &ids,
            &terminals,
            "",
            &mut errors,
        );
        check_subject_establishment(
            &doc.entry,
            &doc.steps,
            &doc.transitions,
            &ids,
            "",
            &mut errors,
        );
    }
    check_predicates(&doc.steps, &doc.transitions, "", &mut errors);

    // PR 3: resolve subflow references, validate inline subflow definitions as fragments, and
    // reject reference cycles. All load-time, never at flow time. The built-in-only gate threads
    // through so a mint-family kind smuggled into an inline subflow definition is refused in a
    // custom artifact just as it is at journey level.
    crate::subflow::validate_subflows(doc, admit_builtin_only, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// The declared step id set for a step slice, flagging a [`JourneyError::DuplicateStepId`] at each
/// repeat's document position. `base` is the RFC 6901 pointer prefix (empty for a journey, the
/// definition pointer for a subflow), so the error locates the step in whichever document carries
/// it.
pub(crate) fn collect_step_ids<'a>(
    steps: &'a [Step],
    base: &str,
    errors: &mut Vec<JourneyError>,
) -> BTreeSet<&'a str> {
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    for (index, step) in steps.iter().enumerate() {
        if !ids.insert(step.id.as_str()) {
            errors.push(JourneyError::DuplicateStepId {
                pointer: format!("{base}/steps/{index}/id"),
                id: step.id.clone(),
            });
        }
    }
    ids
}

/// The per-step vocabulary checks shared by a journey and a subflow: an unknown step kind, a
/// BUILT-IN-ONLY step kind used in a custom context (issue #92, PR 8a), and an unknown node group.
/// `step_ptr` is the RFC 6901 pointer to the step (for example `/steps/2` or
/// `/subflow_definitions/1/steps/2`). When `admit_builtin_only` is set (the embedded built-in
/// context), a mint-family kind is permitted; otherwise a custom artifact naming one is refused
/// with [`JourneyError::BuiltinOnlyStepKind`].
pub(crate) fn check_kind_and_node_group(
    step: &Step,
    step_ptr: &str,
    admit_builtin_only: bool,
    errors: &mut Vec<JourneyError>,
) {
    if !step.kind.is_known() {
        errors.push(JourneyError::UnknownStepKind {
            pointer: format!("{step_ptr}/kind"),
            kind: step.kind.as_wire().to_owned(),
        });
    } else if step.kind.is_builtin_only() && !admit_builtin_only {
        errors.push(JourneyError::BuiltinOnlyStepKind {
            pointer: format!("{step_ptr}/kind"),
            kind: step.kind.as_wire().to_owned(),
        });
    }
    // A match guard rather than a nested `if let ... { if ... }`, so no let chain is needed
    // (MSRV 1.85), mirroring the trait-schema validator's structural checks.
    match &step.node_group {
        Some(group) if !NODE_GROUPS.contains(&group.as_str()) => {
            errors.push(JourneyError::UnknownNodeGroup {
                pointer: format!("{step_ptr}/node_group"),
                group: group.clone(),
            });
        }
        _ => {}
    }
}

/// The per-transition endpoint checks shared by a journey and a subflow: a dangling endpoint and
/// ambiguous unguarded routing, in document order. `base` is the RFC 6901 pointer prefix.
pub(crate) fn check_transition_endpoints(
    ids: &BTreeSet<&str>,
    transitions: &[Transition],
    base: &str,
    errors: &mut Vec<JourneyError>,
) {
    // A second (or later) unguarded transition from a step already left by an unguarded one:
    // `insert` returns false once the source has been seen unguarded.
    let mut seen_unguarded: BTreeSet<&str> = BTreeSet::new();
    for (index, transition) in transitions.iter().enumerate() {
        if !ids.contains(transition.from.as_str()) {
            errors.push(JourneyError::DanglingTransition {
                pointer: format!("{base}/transitions/{index}/from"),
                to: transition.from.clone(),
            });
        }
        if !ids.contains(transition.to.as_str()) {
            errors.push(JourneyError::DanglingTransition {
                pointer: format!("{base}/transitions/{index}/to"),
                to: transition.to.clone(),
            });
        }
        if transition.guard.is_none() && !seen_unguarded.insert(transition.from.as_str()) {
            errors.push(JourneyError::NonDeterministicTransition {
                pointer: format!("{base}/transitions/{index}"),
            });
        }
    }
}

/// The reachability checks shared by a journey and a subflow (a known entry is required to walk
/// from): an unreachable step, and a reachable dead end with no outgoing transition that does not
/// play the completion role (a journey terminal, or a subflow exit). `role_terminals` names the
/// steps that legitimately have no successor; `base` is the RFC 6901 pointer prefix.
pub(crate) fn check_reachability_and_dead_ends(
    entry: &str,
    steps: &[Step],
    transitions: &[Transition],
    ids: &BTreeSet<&str>,
    role_terminals: &BTreeSet<&str>,
    base: &str,
    errors: &mut Vec<JourneyError>,
) {
    let reachable = reachable_steps(entry, transitions, ids);
    let sources: BTreeSet<&str> = transitions
        .iter()
        .map(|transition| transition.from.as_str())
        .collect();
    for (index, step) in steps.iter().enumerate() {
        if !reachable.contains(step.id.as_str()) {
            errors.push(JourneyError::UnreachableStep {
                pointer: format!("{base}/steps/{index}"),
                step: step.id.clone(),
            });
        }
    }
    for (index, step) in steps.iter().enumerate() {
        let dead = reachable.contains(step.id.as_str())
            && !role_terminals.contains(step.id.as_str())
            && !sources.contains(step.id.as_str());
        if dead {
            errors.push(JourneyError::DeadEndStep {
                pointer: format!("{base}/steps/{index}"),
                step: step.id.clone(),
            });
        }
    }
}

/// Type-check every guard and decision predicate in a step and transition slice (issue #92, PR 2),
/// appending a [`JourneyError::PredicateType`] per failure in document order (all transition
/// guards, then all step decisions). A statically-decidable type mismatch (an ordering operator on
/// a boolean signal, a literal that cannot unify with its field, a membership over a mismatched
/// set, a set used in a comparison) is a LOAD-TIME error, so the evaluator only ever runs type-safe
/// predicates. Each error carries the precise RFC 6901 pointer into the predicate, prefixed by
/// `base`.
pub(crate) fn check_predicates(
    steps: &[Step],
    transitions: &[Transition],
    base: &str,
    errors: &mut Vec<JourneyError>,
) {
    for (index, transition) in transitions.iter().enumerate() {
        if let Some(guard) = &transition.guard {
            let predicate_base = format!("{base}/transitions/{index}/guard");
            collect_predicate_errors(guard, &predicate_base, errors);
        }
    }
    for (index, step) in steps.iter().enumerate() {
        if let Some(DecisionSpec::Predicate { predicate }) = &step.decision {
            let predicate_base = format!("{base}/steps/{index}/decision/predicate");
            collect_predicate_errors(predicate, &predicate_base, errors);
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

/// The set of subflow aliases the journey declares in its `subflows` reference list.
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
pub(crate) fn reachable_steps<'a>(
    entry: &'a str,
    transitions: &'a [Transition],
    ids: &BTreeSet<&'a str>,
) -> BTreeSet<&'a str> {
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for transition in transitions {
        if ids.contains(transition.from.as_str()) && ids.contains(transition.to.as_str()) {
            adjacency
                .entry(transition.from.as_str())
                .or_default()
                .push(transition.to.as_str());
        }
    }
    let mut reached: BTreeSet<&str> = BTreeSet::new();
    let mut stack = vec![entry];
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

/// Refuse a journey that routes into a subject-REQUIRING step ([`StepKind::requires_subject`]) by
/// any path that has not first passed a subject-ESTABLISHING step ([`StepKind::establishes_subject`])
/// (issue #351). Modeled on [`reachable_steps`] (an iterative walk, no recursion), but the walk does
/// NOT expand the successors of an establishing step: an establishing step satisfies the requirement
/// for everything downstream of it, so pruning its outgoing edges leaves exactly the set of nodes
/// reachable from the entry by at least one still-subject-less path. Any `requires_subject` step in
/// that set is reachable subject-less by SOME path and is flagged (the rule is that EVERY path to it
/// must first establish, so any subject-less path is a violation, which this pruned walk captures on
/// cyclic and diamond graphs alike).
///
/// Scope: this walk sees the TOP-LEVEL journey graph only. A `subflow_call` step is neither
/// establishing nor requiring here, and the walk does not descend into subflow targets (subflows are
/// validated as isolated fragments by [`crate::subflow::validate_subflows`], and a fragment cannot
/// know its call-site subject state). That is NOT a subflow escape hatch: composition
/// ([`crate::subflow::compose_inner`]) inlines every subflow and re-runs this check on the flattened
/// graph before any routable table is built (see [`crate::compile`]), so a subflow that injects a
/// subject-less subject-requiring step at a subject-less call site is still caught at compile time.
/// The subflow interior is unwalked only on a standalone [`crate::validate`] pass, which never yields
/// a routable table. `base` is the RFC 6901 pointer prefix.
pub(crate) fn check_subject_establishment(
    entry: &str,
    steps: &[Step],
    transitions: &[Transition],
    ids: &BTreeSet<&str>,
    base: &str,
    errors: &mut Vec<JourneyError>,
) {
    let mut kind_by_id: BTreeMap<&str, &StepKind> = BTreeMap::new();
    for step in steps {
        kind_by_id.entry(step.id.as_str()).or_insert(&step.kind);
    }
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for transition in transitions {
        if ids.contains(transition.from.as_str()) && ids.contains(transition.to.as_str()) {
            adjacency
                .entry(transition.from.as_str())
                .or_default()
                .push(transition.to.as_str());
        }
    }
    // Every node reachable from the entry by at least one path that has not yet passed an
    // establishing step. An establishing step is included as a boundary node, but its successors are
    // NOT walked through this set.
    let mut reachable_before_establishment: BTreeSet<&str> = BTreeSet::new();
    let mut stack = vec![entry];
    while let Some(node) = stack.pop() {
        if !reachable_before_establishment.insert(node) {
            continue;
        }
        // Prune: an establishing step satisfies the requirement downstream, so its successors are
        // not reachable subject-less through it.
        if kind_by_id
            .get(node)
            .is_some_and(|kind| kind.establishes_subject())
        {
            continue;
        }
        if let Some(next) = adjacency.get(node) {
            stack.extend(next.iter().copied());
        }
    }
    for (index, step) in steps.iter().enumerate() {
        if step.kind.requires_subject() && reachable_before_establishment.contains(step.id.as_str())
        {
            errors.push(JourneyError::SubjectStepNotEstablished {
                pointer: format!("{base}/steps/{index}"),
                step: step.id.clone(),
            });
        }
    }
}

/// Check that a step carries only the attachments its kind may use: a `subflow_call` names a
/// subflow to call, a `decision` attachment appears only on a `decision` step (but is OPTIONAL
/// there, issue #351), and a `subflow` attachment appears only on a `subflow_call` step. Only known
/// kinds are checked; an unknown kind is already flagged by [`JourneyError::UnknownStepKind`].
/// `step_ptr` is the RFC 6901 pointer to the step.
pub(crate) fn check_attachment_coherence(
    step: &Step,
    step_ptr: &str,
    errors: &mut Vec<JourneyError>,
) {
    match &step.kind {
        StepKind::SubflowCall if step.subflow.is_none() => {
            errors.push(JourneyError::MissingStepAttachment {
                pointer: step_ptr.to_owned(),
                step: step.id.clone(),
                kind: "subflow_call".to_owned(),
            });
        }
        // A `decision` step with no `DecisionSpec` is VALID (issue #351): the attachment is optional
        // (a reserved M11 outcome-routing slot), so a spec-less decision is a pure edge-guard routing
        // hub. An edge-less spec-less decision is still caught as a `DeadEndStep`.
        _ => {}
    }
    // A stray `subflow` on a step that is not a `subflow_call`.
    if step.subflow.is_some() && !matches!(step.kind, StepKind::SubflowCall) && step.kind.is_known()
    {
        errors.push(JourneyError::UnexpectedStepAttachment {
            pointer: format!("{step_ptr}/subflow"),
            step: step.id.clone(),
        });
    }
    // A stray `decision` on a step that is not a `decision`.
    if step.decision.is_some() && !matches!(step.kind, StepKind::Decision) && step.kind.is_known() {
        errors.push(JourneyError::UnexpectedStepAttachment {
            pointer: format!("{step_ptr}/decision"),
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
            subflow_definitions: None,
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
            subflow_definitions: None,
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
            subflow_definitions: None,
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
            subflow_definitions: None,
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
            subflow_definitions: None,
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
    fn a_decision_step_with_no_decision_now_compiles() {
        // Issue #351: the `decision` attachment is OPTIONAL. A spec-less decision step is a pure
        // edge-guard routing hub (previously rejected with MissingStepAttachment), so it now
        // validates clean.
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
            subflow_definitions: None,
        };
        assert_eq!(validate(&doc), Ok(()));
    }

    /// Build a single-hop journey `entry_kind -> terminal` for the subject-establishment tests.
    fn one_hop(entry_kind: StepKind) -> Journey {
        Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "entry".to_owned(),
            comment: None,
            steps: vec![
                step("entry", entry_kind, None),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("entry", "done")],
            subflows: None,
            subflow_definitions: None,
        }
    }

    #[test]
    fn an_entry_mfa_challenge_with_no_establishing_step_is_rejected() {
        // Issue #351: a subject-requiring entry (mfa_challenge) with no preceding
        // subject-establishing step is refused at load, fail-closed.
        assert_eq!(
            validate(&one_hop(StepKind::MfaChallenge)),
            Err(vec![JourneyError::SubjectStepNotEstablished {
                pointer: "/steps/0".to_owned(),
                step: "entry".to_owned(),
            }])
        );
    }

    #[test]
    fn mfa_enroll_and_progressive_profiling_entries_are_each_rejected() {
        // Issue #351: every subject-requiring kind is flagged the same way at the entry position.
        for kind in [StepKind::MfaEnroll, StepKind::ProgressiveProfiling] {
            assert_eq!(
                validate(&one_hop(kind.clone())),
                Err(vec![JourneyError::SubjectStepNotEstablished {
                    pointer: "/steps/0".to_owned(),
                    step: "entry".to_owned(),
                }]),
                "{} must require an establishing step",
                kind.as_wire()
            );
        }
    }

    #[test]
    fn establishment_before_a_subject_step_validates() {
        // identifier_password -> mfa_challenge -> terminal: the primary factor establishes the
        // subject before the second factor reads it, so the journey is well formed.
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("mfa", StepKind::MfaChallenge, Some("totp")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "mfa"), unguarded("mfa", "done")],
            subflows: None,
            subflow_definitions: None,
        };
        assert_eq!(validate(&doc), Ok(()));
    }

    #[test]
    fn a_subject_step_reachable_by_one_establishment_free_path_is_rejected() {
        // A diamond: `start` branches to an establishing path (`a_pw` -> `mfa`) and a
        // establishment-free path (`b_dec` -> `mfa`) that both reach the SAME mfa_challenge. The
        // rule is that EVERY path must first establish, so the establishment-free path is a
        // violation even though another path establishes.
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "start".to_owned(),
            comment: None,
            steps: vec![
                step("start", StepKind::Decision, None),
                step("a_pw", StepKind::IdentifierPassword, Some("password")),
                step("b_dec", StepKind::Decision, None),
                step("mfa", StepKind::MfaChallenge, Some("totp")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![
                guarded("start", "a_pw"),
                guarded("start", "b_dec"),
                unguarded("a_pw", "mfa"),
                unguarded("b_dec", "mfa"),
                unguarded("mfa", "done"),
            ],
            subflows: None,
            subflow_definitions: None,
        };
        assert_eq!(
            validate(&doc),
            Err(vec![JourneyError::SubjectStepNotEstablished {
                pointer: "/steps/3".to_owned(),
                step: "mfa".to_owned(),
            }])
        );
    }

    #[test]
    fn a_decision_hub_between_establishment_and_a_subject_step_validates() {
        // identifier_password -> decision -> mfa_challenge: the establishing step prunes the walk,
        // so a Decision hub after it does not reset establishment. Well formed.
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("branch", StepKind::Decision, None),
                step("mfa", StepKind::MfaChallenge, Some("totp")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![
                unguarded("primary", "branch"),
                unguarded("branch", "mfa"),
                unguarded("mfa", "done"),
            ],
            subflows: None,
            subflow_definitions: None,
        };
        assert_eq!(validate(&doc), Ok(()));
    }

    #[test]
    fn recovery_verify_establishes_a_subject_for_a_downstream_profiling_step() {
        // A built-in fragment: recovery_verify mints a session (establishes the subject), so a
        // progressive_profiling step after it is well formed under validate_builtin (the mint-family
        // kind is admitted only in the embedded built-in context).
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "recovery".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "verify".to_owned(),
            comment: None,
            steps: vec![
                step("verify", StepKind::RecoveryVerify, Some("email_otp")),
                step("profiling", StepKind::ProgressiveProfiling, Some("profile")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![
                unguarded("verify", "profiling"),
                unguarded("profiling", "done"),
            ],
            subflows: None,
            subflow_definitions: None,
        };
        assert_eq!(validate_builtin(&doc), Ok(()));
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
            subflow_definitions: None,
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
            subflow_definitions: None,
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
            subflow_definitions: None,
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
            subflow_definitions: None,
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
            subflow_definitions: None,
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

    /// A structurally valid journey whose entry is a BUILT-IN-ONLY mint-family step (issue #92,
    /// PR 8a): `registration` details routing to a terminal. Well formed in every respect except
    /// the custom-context built-in-only gate.
    fn registration_journey() -> Journey {
        Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "registration".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "details".to_owned(),
            comment: None,
            steps: vec![
                step("details", StepKind::Registration, Some("password")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("details", "done")],
            subflows: None,
            subflow_definitions: None,
        }
    }

    #[test]
    fn a_custom_artifact_using_a_builtin_only_kind_is_rejected() {
        // The public `validate` is the CUSTOM context: a mint-family kind an author must not name
        // is refused with a precise pointer, never silently admitted.
        assert_eq!(
            validate(&registration_journey()),
            Err(vec![JourneyError::BuiltinOnlyStepKind {
                pointer: "/steps/0/kind".to_owned(),
                kind: "registration".to_owned(),
            }])
        );
        // Each of the three mint-family kinds is gated the same way at the entry position.
        for kind in [
            StepKind::Registration,
            StepKind::RecoveryStart,
            StepKind::RecoveryVerify,
        ] {
            let mut doc = registration_journey();
            doc.steps[0].kind = kind.clone();
            assert_eq!(
                validate(&doc),
                Err(vec![JourneyError::BuiltinOnlyStepKind {
                    pointer: "/steps/0/kind".to_owned(),
                    kind: kind.as_wire().to_owned(),
                }])
            );
        }
    }

    #[test]
    fn an_embedded_builtin_artifact_admits_builtin_only_kinds() {
        // The embedded built-in context admits the mint-family kinds, so a built-in journey that
        // uses `registration` validates clean.
        assert_eq!(validate_builtin(&registration_journey()), Ok(()));
    }

    #[test]
    fn a_builtin_only_kind_smuggled_into_an_inline_subflow_is_rejected_in_a_custom_artifact() {
        // The gate threads into inline subflow definitions too, so a custom author cannot bypass
        // it by hiding a mint-family kind in a called fragment.
        let definition = crate::artifact::Subflow {
            id: "smuggle".to_owned(),
            entry: "mint".to_owned(),
            exits: vec!["mint".to_owned()],
            comment: None,
            steps: vec![step("mint", StepKind::Registration, Some("password"))],
            transitions: vec![],
        };
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "custom".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                Step {
                    subflow: Some("smuggle".to_owned()),
                    ..step("call", StepKind::SubflowCall, None)
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "call"), unguarded("call", "done")],
            subflows: Some(vec![SubflowRef {
                id: "smuggle".to_owned(),
                source: SubflowSource::Inline {
                    subflow_id: "smuggle".to_owned(),
                },
            }]),
            subflow_definitions: Some(vec![definition]),
        };
        let errors = validate(&doc).expect_err("a smuggled built-in-only kind is rejected");
        assert!(
            errors.iter().any(|error| matches!(
                error,
                JourneyError::BuiltinOnlyStepKind { kind, .. } if kind == "registration"
            )),
            "expected a BuiltinOnlyStepKind, got {errors:?}"
        );
    }

    #[test]
    fn an_ill_typed_decision_predicate_fails_validation_with_a_pointer() {
        // A Member whose field reads a LIVE but non-matching source (a signal, not the group set)
        // is a static mismatch, located at the decision predicate's pointer. The source is live so
        // the reject is the set-kind mismatch rather than the issue #355 source-not-live gate.
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
                                source: FieldSource::Signals,
                                pointer: "/mfa_required".to_owned(),
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
            subflow_definitions: None,
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

    #[test]
    fn a_guard_on_a_source_the_engine_does_not_populate_fails_validation() {
        // Issue #355: a decision predicate that reads a NOT-LIVE source (a subject group set, a
        // subject scope set, or the risk score) is refused at LOAD time (fail-closed at authoring)
        // rather than silently misrouting to the default branch at runtime.
        let mismatched_source = |predicate: Predicate| Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                Step {
                    decision: Some(DecisionSpec::Predicate { predicate }),
                    ..step("branch", StepKind::Decision, None)
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "branch"), unguarded("branch", "done")],
            subflows: None,
            subflow_definitions: None,
        };
        let group_member = Predicate::Member {
            field: FieldRef {
                source: FieldSource::SubjectGroups,
                pointer: String::new(),
            },
            set: crate::artifact::MemberSet::Group {
                name: "staff".to_owned(),
            },
        };
        assert_eq!(
            validate(&mismatched_source(group_member)),
            Err(vec![JourneyError::PredicateType(
                PredicateTypeError::SourceNotLive {
                    pointer: "/steps/1/decision/predicate/field".to_owned(),
                    source: FieldSource::SubjectGroups,
                }
            )])
        );
        let scope_member = Predicate::Member {
            field: FieldRef {
                source: FieldSource::SubjectScopes,
                pointer: String::new(),
            },
            set: crate::artifact::MemberSet::Scope {
                name: "read".to_owned(),
            },
        };
        assert_eq!(
            validate(&mismatched_source(scope_member)),
            Err(vec![JourneyError::PredicateType(
                PredicateTypeError::SourceNotLive {
                    pointer: "/steps/1/decision/predicate/field".to_owned(),
                    source: FieldSource::SubjectScopes,
                }
            )])
        );
        let score_cmp = Predicate::Cmp {
            field: FieldRef {
                source: FieldSource::Risk,
                pointer: "/score".to_owned(),
            },
            op: crate::artifact::CmpOp::Lt,
            value: crate::artifact::Literal::Number(serde_json::Number::from(50)),
        };
        assert_eq!(
            validate(&mismatched_source(score_cmp)),
            Err(vec![JourneyError::PredicateType(
                PredicateTypeError::SourceNotLive {
                    pointer: "/steps/1/decision/predicate/field".to_owned(),
                    source: FieldSource::Risk,
                }
            )])
        );
    }

    #[test]
    fn a_guard_on_the_live_risk_level_passes_validation() {
        // Issue #355: the risk `/level` IS engine-live, so a guard reading it is accepted.
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
                        predicate: Predicate::Cmp {
                            field: FieldRef {
                                source: FieldSource::Risk,
                                pointer: "/level".to_owned(),
                            },
                            op: crate::artifact::CmpOp::Eq,
                            value: crate::artifact::Literal::String("high".to_owned()),
                        },
                    }),
                    ..step("branch", StepKind::Decision, None)
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![unguarded("primary", "branch"), unguarded("branch", "done")],
            subflows: None,
            subflow_definitions: None,
        };
        assert_eq!(validate(&doc), Ok(()));
    }
}
