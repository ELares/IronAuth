// SPDX-License-Identifier: MIT OR Apache-2.0

//! The compile-to-table lowering (issue #92, PR 4): the pure step that turns a validated,
//! composed, materialized [`Journey`] into the engine's transition table, plus the DEFERRED
//! LIVENESS check the load-time validator could not make.
//!
//! ## Why a table, and why here
//!
//! The load-time validator ([`crate::validate`]) checks artifact STRUCTURE (vocabulary,
//! reachability, dead ends, routing determinism, predicate types) but deliberately DEFERS
//! liveness (does a journey have a reachable completion) to compile time, because judging
//! completion needs the executor's semantics: a journey completes by ROUTING into a
//! [`StepKind::Terminal`] step, which the pure validator cannot assert reaches a mint. This
//! module makes that judgement, so a journey with no reachable completion (an exit-less cycle,
//! or a graph that never reaches a terminal) is refused with
//! [`JourneyError::NoReachableCompletion`] BEFORE the engine ever drives it.
//!
//! ## Purity discipline
//!
//! Like the rest of this crate, [`compile`] is a PURE value function: no clock, no entropy, no
//! I/O. It composes (which re-validates the source and its inlined result), builds the table,
//! and runs the liveness walk. The engine binds the table to real flow state in the OIDC crate;
//! none of that lands here.

use std::collections::{BTreeMap, BTreeSet};

use crate::artifact::{DecisionSpec, Journey, Predicate, StepId, StepKind};
use crate::eval::{EvalContext, evaluate};
use crate::validate::JourneyError;

/// One compiled step (issue #92, PR 4): the built-in executor kind, the node group it renders
/// under (when it renders), and the decision it evaluates (for a [`StepKind::Decision`] step).
/// The document-local step id is the [`CompiledJourney::steps`] key, so it is not repeated here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledStep {
    /// The built-in executor kind that runs this step.
    pub kind: StepKind,
    /// The node group this step renders under, or [`None`] for a step that renders nothing (a
    /// decision or a terminal).
    pub node_group: Option<String>,
    /// The decision this step evaluates, for a [`StepKind::Decision`] step.
    pub decision: Option<DecisionSpec>,
}

/// One guarded outgoing edge (issue #92, PR 4): the target step id and the guard predicate that
/// must hold for the edge to be taken. An UNGUARDED edge (`guard` of [`None`]) always applies.
/// The engine walks a step's edges in DOCUMENT ORDER and takes the first whose guard is absent or
/// evaluates true, so the compiled order is load-bearing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedEdge {
    /// The target step id.
    pub to: StepId,
    /// The guard predicate, or [`None`] for an unguarded (always-applicable) edge.
    pub guard: Option<Predicate>,
}

/// The compiled transition table (issue #92, PR 4): the engine's runtime shape for a journey.
/// The entry step, the steps keyed by id, the ordered guarded edges keyed by source step, and
/// the precomputed reachable set. Built by [`compile`] from a validated, composed journey with
/// no remaining `subflow_call` step (composition inlines every subflow first), so every step is a
/// concrete executor kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledJourney {
    /// The entry step id: where the journey starts.
    pub entry: StepId,
    /// The steps keyed by document-local id.
    pub steps: BTreeMap<StepId, CompiledStep>,
    /// The ordered guarded edges keyed by source step id. A step with no outgoing edge (a
    /// terminal) has no entry here.
    pub transitions: BTreeMap<StepId, Vec<GuardedEdge>>,
    /// The set of step ids reachable from the entry (precomputed once at compile time).
    reachable: BTreeSet<StepId>,
}

impl CompiledJourney {
    /// The set of step ids reachable from the entry (issue #92, PR 4). The anti-drift gate uses
    /// this as a custom journey's PLAN: the reachable set is exactly the states the compiled
    /// engine can occupy, mirroring how a built-in journey's [`plan`] lists its states.
    #[must_use]
    pub fn reachable(&self) -> &BTreeSet<StepId> {
        &self.reachable
    }

    /// The compiled step for an id, or [`None`] when the id names no step.
    #[must_use]
    pub fn step(&self, id: &str) -> Option<&CompiledStep> {
        self.steps.get(id)
    }

    /// The ordered guarded edges leaving a step (empty for a terminal or an unknown step).
    #[must_use]
    pub fn edges(&self, id: &str) -> &[GuardedEdge] {
        self.transitions.get(id).map_or(&[], Vec::as_slice)
    }

    /// Choose the first guarded edge that applies from `from` (issue #92, PR 4): document order,
    /// first whose guard is absent or evaluates true. This is the ONE routing primitive both the
    /// engine's `drive_via_table` walk and the replay harness's `route_hop` walk share (issue
    /// #355 item 2), so the drift-detection harness cannot itself drift from the engine.
    ///
    /// An evaluation error (only the depth guard, which a type-checked predicate never hits) is
    /// treated as a non-match, never fail-open. SAFETY INVARIANT for a built-in artifact: a
    /// POSITIVE guard whose false skips a security requirement (for example `/mfa_required` gating
    /// the challenge edge) must never be able to error, or "false on error" would relax that
    /// requirement. Today the built-in login guards are depth 1 Cmp predicates that only ever error
    /// on `MAX_PREDICATE_DEPTH`, which they cannot hit, so this holds; a future built-in guard must
    /// preserve it (issue #359).
    #[must_use]
    pub fn choose_edge(&self, from: &str, ctx: &EvalContext) -> Option<StepId> {
        for edge in self.edges(from) {
            // An eval error counts as "guard did not match" so a corrupt guard cannot force a route.
            let taken = match &edge.guard {
                None => true,
                Some(guard) => evaluate(guard, ctx).unwrap_or(false),
            };
            if taken {
                return Some(edge.to.clone());
            }
        }
        None
    }
}

/// Compile a journey artifact into the engine's transition table (issue #92, PR 4): a PURE,
/// load-time lowering. The journey is COMPOSED first ([`crate::compose`], which validates the
/// source, its subflow references, and its acyclicity, inlines every subflow, and re-validates
/// the flattened result), so the table always sees fully-resolved topology with no
/// `subflow_call` step. The flattened steps and transitions are indexed into the table, the
/// reachable set is precomputed, and the DEFERRED LIVENESS check runs: a journey MUST have a
/// [`StepKind::Terminal`] step reachable from the entry, otherwise it can never complete and is
/// refused with [`JourneyError::NoReachableCompletion`].
///
/// A template invocation is materialized into a concrete [`Journey`] by [`crate::materialize`]
/// BEFORE compilation, so this function always receives a concrete journey.
///
/// # Errors
///
/// Every load-time failure [`compose`](crate::compose) reports (the source's own validation
/// failures, an unresolved or cyclic subflow reference, or [`JourneyError::ComposedTooLarge`]),
/// plus [`JourneyError::NoReachableCompletion`] when no terminal step is reachable from the entry.
pub fn compile(doc: &Journey) -> Result<CompiledJourney, Vec<JourneyError>> {
    compile_inner(doc, crate::validate::BUILTIN_ONLY_REJECTED)
}

/// Compile an EMBEDDED BUILT-IN journey artifact into the engine's transition table (issue #92,
/// PR 8a): identical to [`compile`] except that the BUILT-IN-ONLY mint-family step kinds
/// ([`StepKind::is_builtin_only`]) are ADMITTED, so the built-in login/registration/recovery
/// journeys that converge onto the compiled table lower cleanly. A custom-authored artifact still
/// uses [`compile`], which refuses those kinds with [`JourneyError::BuiltinOnlyStepKind`].
///
/// # Errors
///
/// The same failures [`compile`] reports, minus the built-in-only rejection.
pub fn compile_builtin(doc: &Journey) -> Result<CompiledJourney, Vec<JourneyError>> {
    compile_inner(doc, crate::validate::BUILTIN_ONLY_ADMITTED)
}

/// Compile a journey into the engine's transition table (issue #92), with `admit_builtin_only`
/// selecting the custom ([`compile`]) or embedded built-in ([`compile_builtin`]) validation
/// context.
fn compile_inner(
    doc: &Journey,
    admit_builtin_only: bool,
) -> Result<CompiledJourney, Vec<JourneyError>> {
    // Compose validates the source (structure, references, acyclicity), inlines every subflow,
    // and re-validates the flattened result, so the table is built from a validate-clean journey
    // with no remaining subflow_call step. This subsumes a standalone validate pass.
    let flat = crate::subflow::compose_inner(doc, admit_builtin_only)?;

    let mut steps: BTreeMap<StepId, CompiledStep> = BTreeMap::new();
    for step in &flat.steps {
        steps.insert(
            step.id.clone(),
            CompiledStep {
                kind: step.kind.clone(),
                node_group: step.node_group.clone(),
                decision: step.decision.clone(),
            },
        );
    }

    let mut transitions: BTreeMap<StepId, Vec<GuardedEdge>> = BTreeMap::new();
    for transition in &flat.transitions {
        transitions
            .entry(transition.from.clone())
            .or_default()
            .push(GuardedEdge {
                to: transition.to.clone(),
                guard: transition.guard.clone(),
            });
    }

    // The reachable set over the flattened graph, reusing the validator's iterative walk so a
    // cyclic or deep graph cannot exhaust the stack.
    let ids: BTreeSet<&str> = flat.steps.iter().map(|step| step.id.as_str()).collect();
    let reachable: BTreeSet<StepId> =
        crate::validate::reachable_steps(&flat.entry, &flat.transitions, &ids)
            .into_iter()
            .map(str::to_owned)
            .collect();

    // LIVENESS (the deferred check): a journey completes by routing into a terminal step, so at
    // least one terminal must be reachable from the entry. A graph that only cycles, or that
    // reaches no terminal, can never complete and is refused here rather than at flow time.
    let has_reachable_completion = flat
        .steps
        .iter()
        .any(|step| step.kind.is_terminal() && reachable.contains(step.id.as_str()));
    if !has_reachable_completion {
        return Err(vec![JourneyError::NoReachableCompletion]);
    }

    Ok(CompiledJourney {
        entry: flat.entry.clone(),
        steps,
        transitions,
        reachable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{
        CmpOp, FieldRef, FieldSource, JOURNEY_ENGINE_VERSION, JOURNEY_SCHEMA_VERSION, Literal,
        Step, Transition,
    };
    use crate::artifact::{SubflowRef, SubflowSource};

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

    fn mfa_required_guard(value: bool) -> Predicate {
        Predicate::Cmp {
            field: FieldRef {
                source: FieldSource::Signals,
                pointer: "/mfa_required".to_owned(),
            },
            op: CmpOp::Eq,
            value: Literal::Bool(value),
        }
    }

    /// The AC1 identifier-first-conditional-MFA journey (mirrors the validator fixture).
    fn conditional_mfa_journey() -> Journey {
        Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "login_conditional_mfa".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("mfa", StepKind::MfaChallenge, Some("totp")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![
                Transition {
                    from: "primary".to_owned(),
                    to: "mfa".to_owned(),
                    guard: Some(mfa_required_guard(true)),
                    comment: None,
                },
                Transition {
                    from: "primary".to_owned(),
                    to: "done".to_owned(),
                    guard: Some(mfa_required_guard(false)),
                    comment: None,
                },
                Transition {
                    from: "mfa".to_owned(),
                    to: "done".to_owned(),
                    guard: None,
                    comment: None,
                },
            ],
            subflows: None,
            subflow_definitions: None,
        }
    }

    #[test]
    fn compile_lowers_entry_steps_and_ordered_transitions() {
        let compiled = compile(&conditional_mfa_journey()).expect("compiles");
        assert_eq!(compiled.entry, "primary");
        assert_eq!(compiled.steps.len(), 3);
        assert_eq!(
            compiled.step("primary").map(|s| s.kind.clone()),
            Some(StepKind::IdentifierPassword)
        );
        assert_eq!(
            compiled.step("primary").and_then(|s| s.node_group.clone()),
            Some("password".to_owned())
        );
        assert!(compiled.step("done").is_some_and(|s| s.kind.is_terminal()));
        // The two guarded edges from `primary` are kept in document order (mfa first, done
        // second), so the engine's first-true-guard walk is deterministic.
        let edges = compiled.edges("primary");
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0].to, "mfa");
        assert_eq!(edges[1].to, "done");
        assert_eq!(edges[0].guard, Some(mfa_required_guard(true)));
        // A terminal has no outgoing edge.
        assert!(compiled.edges("done").is_empty());
        // Every step is reachable, and a completion is reachable.
        assert_eq!(compiled.reachable().len(), 3);
    }

    #[test]
    fn compile_reachable_is_the_reachable_step_set() {
        let compiled = compile(&conditional_mfa_journey()).expect("compiles");
        let reachable = compiled.reachable();
        for id in ["primary", "mfa", "done"] {
            assert!(reachable.contains(id), "{id} is reachable");
        }
    }

    #[test]
    fn a_subflow_call_is_gone_after_composition() {
        // A journey that calls the built-in mfa_step_up subflow: after compile, the compiled
        // table has NO subflow_call step (composition inlined it), and the spliced steps carry
        // the namespaced ids.
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                Step {
                    subflow: Some("mfa_step_up".to_owned()),
                    ..step("call", StepKind::SubflowCall, None)
                },
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![
                Transition {
                    from: "primary".to_owned(),
                    to: "call".to_owned(),
                    guard: None,
                    comment: None,
                },
                Transition {
                    from: "call".to_owned(),
                    to: "done".to_owned(),
                    guard: None,
                    comment: None,
                },
            ],
            subflows: Some(vec![SubflowRef {
                id: "mfa_step_up".to_owned(),
                source: SubflowSource::Builtin {
                    name: "mfa_step_up".to_owned(),
                },
            }]),
            subflow_definitions: None,
        };
        let compiled = compile(&doc).expect("compiles");
        assert!(
            compiled
                .steps
                .values()
                .all(|s| !matches!(s.kind, StepKind::SubflowCall)),
            "composition inlined every subflow_call"
        );
        assert!(compiled.reachable().contains("done"));
    }

    #[test]
    fn a_journey_with_no_reachable_completion_is_refused() {
        // Two steps that route into each other with no terminal: reachable, dead-end-free by the
        // structural rules, but no completion is reachable. Liveness refuses it at compile.
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "j".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "a".to_owned(),
            comment: None,
            steps: vec![
                step("a", StepKind::IdentifierPassword, Some("password")),
                step("b", StepKind::MfaChallenge, Some("totp")),
            ],
            transitions: vec![
                Transition {
                    from: "a".to_owned(),
                    to: "b".to_owned(),
                    guard: None,
                    comment: None,
                },
                Transition {
                    from: "b".to_owned(),
                    to: "a".to_owned(),
                    guard: None,
                    comment: None,
                },
            ],
            subflows: None,
            subflow_definitions: None,
        };
        assert_eq!(
            compile(&doc),
            Err(vec![JourneyError::NoReachableCompletion])
        );
    }

    #[test]
    fn compile_rejects_a_builtin_only_kind_but_compile_builtin_admits_it() {
        // A journey whose entry is a mint-family kind: the custom `compile` refuses it (a custom
        // author cannot mint accounts / sessions), while `compile_builtin` lowers it for the
        // embedded built-in journeys.
        let doc = Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "registration".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "details".to_owned(),
            comment: None,
            steps: vec![
                step("details", StepKind::Registration, Some("password")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![Transition {
                from: "details".to_owned(),
                to: "done".to_owned(),
                guard: None,
                comment: None,
            }],
            subflows: None,
            subflow_definitions: None,
        };
        let errors = compile(&doc).expect_err("the custom compile refuses a built-in-only kind");
        assert!(
            errors.iter().any(|e| matches!(
                e,
                JourneyError::BuiltinOnlyStepKind { kind, .. } if kind == "registration"
            )),
            "expected a BuiltinOnlyStepKind, got {errors:?}"
        );
        // The embedded built-in compile lowers it, and the mint-family step survives to the table.
        let compiled = compile_builtin(&doc).expect("compile_builtin admits the mint-family kind");
        assert_eq!(
            compiled.step("details").map(|s| s.kind.clone()),
            Some(StepKind::Registration)
        );
        assert!(compiled.reachable().contains("done"));
    }

    #[test]
    fn choose_edge_takes_the_first_document_order_guard_that_holds() {
        use crate::eval::{EvalContext, OutcomeSignal, SignalSet};

        let compiled = compile(&conditional_mfa_journey()).expect("compiles");

        // A context in which the signal `/mfa_required` is asserted, and one in which it is not.
        let ctx_mfa = EvalContext {
            flow: crate::eval::FlowContext {
                signals: SignalSet::new().with(OutcomeSignal::MfaRequired, true),
                ..crate::eval::FlowContext::default()
            },
            ..EvalContext::default()
        };
        let ctx_no_mfa = EvalContext::default();

        // `primary` has two guarded edges in document order: mfa (guard mfa_required == true) then
        // done (guard mfa_required == false). The first whose guard holds wins.
        assert_eq!(
            compiled.choose_edge("primary", &ctx_mfa).as_deref(),
            Some("mfa")
        );
        assert_eq!(
            compiled.choose_edge("primary", &ctx_no_mfa).as_deref(),
            Some("done")
        );

        // `mfa` has a single unguarded edge to done, taken under any context.
        assert_eq!(
            compiled.choose_edge("mfa", &ctx_mfa).as_deref(),
            Some("done")
        );
        assert_eq!(
            compiled.choose_edge("mfa", &ctx_no_mfa).as_deref(),
            Some("done")
        );

        // A terminal (no outgoing edge) and an unknown step both route nowhere.
        assert_eq!(compiled.choose_edge("done", &ctx_mfa), None);
        assert_eq!(compiled.choose_edge("nope", &ctx_mfa), None);
    }

    #[test]
    fn a_structurally_invalid_journey_fails_to_compile() {
        // An unknown step kind fails composition's validate, so compile surfaces it.
        let mut doc = conditional_mfa_journey();
        doc.steps[1].kind = StepKind::from_wire("teleport");
        let errors = compile(&doc).expect_err("does not compile");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, JourneyError::UnknownStepKind { .. }))
        );
    }
}
